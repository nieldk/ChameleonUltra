/*
 * mode_zigbee.c
 *
 * Standalone mode: passive IEEE 802.15.4 (Zigbee) receive, one channel or hopping
 * over 11..26. Receive only; nothing is transmitted. Frames are counted by type
 * (`standalone status`) and appended to a RAM log that the host drains with
 * `standalone zigbee get-result`. RX runs in chained SoftDevice timeslots, so frames
 * between slots are missed (see zb_radio.c).
 *
 * Config, v1 (4 bytes): u8 version=1, u8 channel (0 = hop all 11..26, else a
 * single 11..26; default 11), u16 dwell_ms LE (hop dwell per channel,
 * 50..60000, default 500). A 2-byte blob (version, channel) is accepted too.
 *
 * Config, v2 (6 bytes): u8 version=2, u8 reserved0=0, u16 dwell_ms LE,
 * u16 chan_mask LE (bit i = channel 11+i; hop only over the set channels).
 * A zero mask is rejected (falls back to the default single channel) --
 * same "bad config, use the default" rule as v1's out-of-range channel.
 *
 * Log record: u8 channel, u8 lqi_raw, u8 len, u8 data[len] (MPDU without FCS).
 * Draining (get-result/scan/devices/dump) advances the read cursor but does not
 * free space; only `standalone clear-result` does that -- same convention as
 * every other mode. The log is persisted to flash on disarm (and on clear) and
 * reloaded on re-arm or on a disarmed `get-result`/`ls`, so results survive a
 * disarm or reset; a power loss while armed can lose records added since the
 * last flush. When full, new frames are counted in `log overflow` and dropped.
 */

#include "app_standalone.h"
#include "zb_radio.h"

#include <string.h>
#include "nrf_log.h"

#define DEFAULT_CHANNEL 11
#define DEFAULT_DWELL   500
#define REC_HDR         3

/* The framework persists at most STANDALONE_RESULT_PERSIST_MAX - 4 = 2080 bytes
 * per mode. m_log must be word-aligned for fds_write_sync(). */
#define LOG_SZ          2048
_Static_assert(LOG_SZ + 4 <= STANDALONE_RESULT_PERSIST_MAX,
               "zigbee log must fit the framework's persisted result record");

static uint8_t  m_channel  = DEFAULT_CHANNEL;   /* 0 = hop (mask has >1 bit) */
static uint16_t m_chan_mask = (uint16_t)(1u << (DEFAULT_CHANNEL - 11));  /* bit i = ch 11+i */
static uint16_t m_dwell   = DEFAULT_DWELL;
static uint8_t  m_cur     = DEFAULT_CHANNEL;
static uint32_t m_hop_at;
static bool     m_hop_init;
static uint32_t m_type[4];                  /* beacon, data, ack, command */
static uint32_t m_other;
static uint32_t m_chan_rx[16];
static uint8_t  m_last_len;

static int mask_popcount(uint16_t m) {
    int n = 0;
    for (; m; m >>= 1) n += m & 1;
    return n;
}

/* Lowest channel set in mask, or DEFAULT_CHANNEL if mask is somehow 0
 * (shouldn't happen -- cfg_parse never leaves m_chan_mask at 0). */
static uint8_t mask_first_channel(uint16_t m) {
    for (int i = 0; i < 16; i++) if (m & (1u << i)) return (uint8_t)(11 + i);
    return DEFAULT_CHANNEL;
}

/* Next channel in mask after `cur`, wrapping 26 -> 11. Assumes mask != 0. */
static uint8_t mask_next_channel(uint16_t m, uint8_t cur) {
    uint8_t next = cur;
    for (int i = 0; i < 16; i++) {
        next = (next >= 26) ? 11 : (uint8_t)(next + 1);
        if (m & (1u << (next - 11))) return next;
    }
    return cur;   /* unreachable if mask != 0 */
}

static uint32_t m_log_words[(LOG_SZ + 3) / 4];
#define m_log ((uint8_t *)m_log_words)
static size_t   m_used, m_cursor;
static uint32_t m_overflow;
static bool     m_loaded, m_dirty;

static void cfg_parse(const uint8_t *cfg, size_t cfg_len) {
    m_channel   = DEFAULT_CHANNEL;
    m_chan_mask = (uint16_t)(1u << (DEFAULT_CHANNEL - 11));
    m_dwell     = DEFAULT_DWELL;
    if (cfg == NULL || cfg_len < 2) return;
    if (cfg[0] == 1) {
        if (cfg[1] == 0) {
            m_channel   = 0;
            m_chan_mask = 0xFFFFU;
        } else if (cfg[1] >= 11 && cfg[1] <= 26) {
            m_channel   = cfg[1];
            m_chan_mask = (uint16_t)(1u << (cfg[1] - 11));
        }
        if (cfg_len >= 4) {
            uint16_t d = (uint16_t)(cfg[2] | (cfg[3] << 8));
            if (d >= 50 && d <= 60000) m_dwell = d;
        }
    } else if (cfg[0] == 2 && cfg_len >= 6) {
        uint16_t mask = (uint16_t)(cfg[4] | (cfg[5] << 8));
        if (mask != 0) {
            m_chan_mask = mask;
            m_channel   = (mask_popcount(mask) == 1) ? mask_first_channel(mask) : 0;
        }
        uint16_t d = (uint16_t)(cfg[2] | (cfg[3] << 8));
        if (d >= 50 && d <= 60000) m_dwell = d;
    }
}

static void on_config(const uint8_t *cfg, size_t cfg_len) {
    cfg_parse(cfg, cfg_len);
    /* Apply immediately if already armed: `set-mode <same mode>` + `trigger`
     * does NOT call on_enter() (app_standalone_set_mode only disarms on an
     * actual mode change; app_standalone_trigger only (re-)arms from
     * DISARMED), so without this a config change while armed in this same
     * mode would silently never take effect until an explicit disarm+trigger. */
    if (zb_radio_running()) {
        m_hop_init = false;
        m_cur = mask_first_channel(m_chan_mask);
        zb_radio_set_channel(m_cur);
    }
}

/* Walk the log and return the length of the longest run of whole records --
 * drops a torn trailing record (e.g. from a power loss mid-flush). */
static size_t log_validate(size_t n) {
    size_t i = 0;
    while (i + REC_HDR <= n) {
        size_t need = REC_HDR + m_log[i + 2];
        if (i + need > n) break;
        i += need;
    }
    return i;
}

/* Loads the persisted log into RAM at most once (per boot or after a
 * clear_result load-cache reset isn't needed: clear_result updates m_used
 * directly). Called lazily so a disarmed `standalone zigbee get-result` or
 * `standalone ls` still sees prior captures, same pattern as nfc_canary. */
static void log_ensure_loaded(void) {
    if (m_loaded) return;
    m_loaded = true;
    size_t n = 0;
    if (app_standalone_load_result_buf(STANDALONE_MODE_ZIGBEE, m_log_words,
                                       LOG_SZ, &n) != STANDALONE_RC_OK) {
        n = 0;
    }
    m_used   = log_validate(n);
    m_cursor = 0;
    NRF_LOG_INFO("zigbee: loaded %u log byte(s)", (unsigned)m_used);
}

static void log_flush(void) {
    if (!m_dirty) return;
    app_standalone_save_result_buf(STANDALONE_MODE_ZIGBEE, m_log_words, m_used);
    m_dirty = false;
}

static standalone_rc_t on_enter(const uint8_t *cfg, size_t cfg_len) {
    cfg_parse(cfg, cfg_len);
    m_other = m_last_len = 0;
    m_overflow = 0;
    log_ensure_loaded();   /* keep any unread/uncleared capture from before */
    m_hop_init = false;
    memset(m_chan_rx, 0, sizeof(m_chan_rx));
    for (int i = 0; i < 4; i++) m_type[i] = 0;
    m_cur = mask_first_channel(m_chan_mask);
    if (!zb_radio_start(m_cur)) return STANDALONE_RC_INTERNAL;
    NRF_LOG_INFO("zigbee: rx %s channel %u", (mask_popcount(m_chan_mask) > 1) ? "hop from" : "on", m_cur);
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_exit(void) {
    zb_radio_stop();
    log_flush();   /* disarm persists whatever is in the log, same as other modes */
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_button(standalone_button_evt_t evt) {
    (void)evt;
    return STANDALONE_RC_OK;
}

static void log_add(const zb_frame_t *f) {
    size_t need = REC_HDR + f->len;
    if (m_used + need > LOG_SZ) { m_overflow++; return; }
    m_log[m_used]     = f->channel;
    m_log[m_used + 1] = f->lqi;
    m_log[m_used + 2] = f->len;
    memcpy(&m_log[m_used + REC_HDR], f->data, f->len);
    m_used += need;
    m_dirty = true;
}

/* Count frames by type (frame control bits 0-2), log them, and hop. */
static standalone_rc_t on_tick(uint32_t now_ms) {
    zb_frame_t f;
    zb_radio_poll();
    while (zb_radio_pop(&f)) {
        uint8_t type = f.data[0] & 7;
        if (type < 4) m_type[type]++;
        else m_other++;
        m_last_len = f.len;
        if (f.channel >= 11 && f.channel <= 26) m_chan_rx[f.channel - 11]++;
        log_add(&f);
    }
    if (mask_popcount(m_chan_mask) > 1) {
        if (!m_hop_init) { m_hop_init = true; m_hop_at = now_ms; }
        else if ((uint32_t)(now_ms - m_hop_at) >= m_dwell) {
            m_hop_at = now_ms;
            m_cur = mask_next_channel(m_chan_mask, m_cur);
            zb_radio_set_channel(m_cur);
        }
    }
    return STANDALONE_RC_OK;
}

static size_t get_result_size(void) {
    log_ensure_loaded();
    return m_used - m_cursor;
}

/* Returns whole records only. Unread tail only -- already-read bytes are NOT
 * freed here; only clear_result() (standalone clear-result) frees the buffer,
 * same as every other mode. A long capture without an intervening clear-result
 * will fill the log and then drop new frames into `overflow`, even if
 * everything read so far was drained. */
static standalone_rc_t read_result(uint8_t *out, size_t out_max, size_t *out_len) {
    if (out == NULL || out_len == NULL) return STANDALONE_RC_INVALID_CFG;
    log_ensure_loaded();
    *out_len = 0;
    if (m_cursor >= m_used) {
        return STANDALONE_RC_NO_RESULT;
    }
    size_t take = 0;
    while (m_cursor + take < m_used) {
        size_t rl = REC_HDR + m_log[m_cursor + take + 2];
        if (take + rl > out_max) break;
        take += rl;
    }
    if (take == 0) return STANDALONE_RC_NO_RESULT;
    memcpy(out, &m_log[m_cursor], take);
    m_cursor += take;
    *out_len = take;
    return STANDALONE_RC_OK;
}

static void clear_result(void) {
    log_ensure_loaded();
    m_used = m_cursor = 0;
    m_overflow = 0;
    m_dirty = true;
    log_flush();   /* clear takes effect in flash immediately, not just RAM */
}

/* Keep short: the whole `standalone status` reply is built in a 512-byte buffer. */
static size_t get_status(char *out, size_t out_max) {
    size_t len = 0;
    zb_stats_t s;
    zb_radio_get_stats(&s);
    STATUS_KV(out, out_max, len, "radio=%s ch=%u%s dwell=%u\n", zb_radio_running() ? "rx" : "off",
              m_cur, (mask_popcount(m_chan_mask) > 1) ? " hop" : "", m_dwell);
    STATUS_KV(out, out_max, len, "slots=%lu blocked=%lu canceled=%lu us=%lu\n",
              (unsigned long)s.slots, (unsigned long)s.blocked, (unsigned long)s.canceled,
              (unsigned long)s.slot_us);
    STATUS_KV(out, out_max, len, "diag cb=%lu/%lu/%lu rxen=%lu/%lu ed=%lu/%lu st=%u/%u pw=%u rc=%lu fs=%lu\n",
              (unsigned long)s.sig_radio, (unsigned long)s.sig_timer0, (unsigned long)s.idle,
              (unsigned long)s.ready_ok, (unsigned long)s.ready_timeout,
              (unsigned long)s.ed_ok, (unsigned long)s.ed_timeout,
              (unsigned)s.state_after, (unsigned)s.state_end, (unsigned)s.power_was,
              (unsigned long)s.last_rc, (unsigned long)s.framestart);
    STATUS_KV(out, out_max, len, "frames ok=%lu bad_fcs=%lu dropped=%lu\n",
              (unsigned long)s.rx_ok, (unsigned long)s.rx_crc, (unsigned long)s.dropped);
    /* Expect mode=15 pcnf0=06000008 crccnf=00000202 sfd=a7 freq=5*(ch-10) --
     * anything else means the write didn't stick, not a demod/RF problem. */
    STATUS_KV(out, out_max, len, "rb mode=%lu pcnf0=%08lx crccnf=%08lx sfd=%02x freq=%lu\n",
              (unsigned long)s.rb_mode, (unsigned long)s.rb_pcnf0, (unsigned long)s.rb_crccnf,
              (unsigned)s.rb_sfd, (unsigned long)s.rb_freq);
    STATUS_KV(out, out_max, len, "types bcn=%lu data=%lu ack=%lu cmd=%lu oth=%lu\n",
              (unsigned long)m_type[0], (unsigned long)m_type[1], (unsigned long)m_type[2],
              (unsigned long)m_type[3], (unsigned long)m_other);
    STATUS_KV(out, out_max, len, "log pending=%u overflow=%lu\n", (unsigned)(m_used - m_cursor),
              (unsigned long)m_overflow);
    /* Host's standalone_get_status() keeps only "key=value" lines (it does
     * line.partition('=') and drops anything with no '='), so these must use
     * '=' too, not ':' -- a colon-only line is silently swallowed on the host
     * side and never reaches the printed table. */
    if (mask_popcount(m_chan_mask) > 1) {
        if (m_chan_mask != 0xFFFFU) {
            STATUS_KV(out, out_max, len, "chanset=");
            bool first = true;
            for (int i = 0; i < 16; i++) {
                if (m_chan_mask & (1u << i)) {
                    STATUS_KV(out, out_max, len, "%s%u", first ? "" : ",", 11 + i);
                    first = false;
                }
            }
            STATUS_KV(out, out_max, len, "\n");
        }
        STATUS_KV(out, out_max, len, "rx11-26=");
        for (int i = 0; i < 16; i++) STATUS_KV(out, out_max, len, "%s%lu", i ? "," : "", (unsigned long)m_chan_rx[i]);
        STATUS_KV(out, out_max, len, "\ned11-26=");
        for (int i = 0; i < 16; i++) STATUS_KV(out, out_max, len, "%s%u", i ? "," : "", (unsigned)s.ed_max[i]);
        STATUS_KV(out, out_max, len, "\n");
    } else if (m_cur >= 11 && m_cur <= 26) {
        STATUS_KV(out, out_max, len, "ed=%u\n", (unsigned)s.ed_max[m_cur - 11]);
    }
    STATUS_KV(out, out_max, len, "last len=%u lqi_raw=%u\n", m_last_len, (unsigned)s.last_lqi);
    return len;
}

const standalone_mode_iface_t mode_zigbee_iface = {
    .id               = STANDALONE_MODE_ZIGBEE,
    .name             = "zigbee",
    .writes_tag       = false,
    .writes_slot      = false,
    .wants_tick       = true,
    .tick_interval_ms = 20,
    .on_enter         = on_enter,
    .on_exit          = on_exit,
    .on_button        = on_button,
    .on_tick          = on_tick,
    .get_result_size  = get_result_size,
    .read_result      = read_result,
    .clear_result     = clear_result,
    .ensure_loaded    = log_ensure_loaded,
    .get_status       = get_status,
    .on_config        = on_config,
};
