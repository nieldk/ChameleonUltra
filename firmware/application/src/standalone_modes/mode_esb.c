/*
 * mode_esb.c
 *
 * Standalone mode: passive Nordic proprietary-PHY (Enhanced ShockBurst
 * framing) receive, matching one known 5-byte address -- e.g. a paired
 * Logitech Unifying receiver's address. One fixed channel (0..100, direct
 * MHz offset from 2400) or hopping across the whole range. Receive only;
 * nothing is transmitted, nothing is injected. Frames are appended to a RAM
 * log that the host drains with `standalone esb get-result`. RX runs in
 * chained SoftDevice timeslots, so frames between slots are missed, same as
 * zigbee/spectrum (see esb_radio.c).
 *
 * Config (10 bytes): u8 version=1, u8 addr[5] (addr[0]=prefix byte,
 * addr[1..4]=base address, in the order these are normally written/paired
 * with -- see esb_radio.h), u8 channel (0..100 direct, 0xFF = hop over the
 * whole range; default 5), u8 bitrate (0 = Nrf_1Mbit, 1 = Nrf_2Mbit;
 * default 1), u16 dwell_ms LE (hop dwell per channel, 50..60000,
 * default 500). on_enter refuses an all-zero/unset address.
 *
 * Log record: u8 channel, u8 len, u8 data[len] (payload, ESB's own CRC
 * already stripped by the radio). Draining (get-result) advances the read
 * cursor but does not free space; only `standalone clear-result` does that
 * -- same convention as every other mode. The log is persisted to flash on
 * disarm (and on clear) and reloaded on re-arm or a disarmed get-result/ls,
 * same as zigbee. When full, new frames are counted in `log overflow` and
 * dropped.
 */

#include "app_standalone.h"
#include "esb_radio.h"

#include <string.h>
#include "nrf_log.h"

#define DEFAULT_CHANNEL 5
#define DEFAULT_BITRATE 1       /* Nrf_2Mbit */
#define DEFAULT_DWELL   500
#define HOP_CHANNEL     0xFFu
#define REC_HDR         2

/* Same persisted-size budget as zigbee/spectrum; see app_standalone.h. */
#define LOG_SZ          2048
_Static_assert(LOG_SZ + 4 <= STANDALONE_RESULT_PERSIST_MAX,
               "esb log must fit the framework's persisted result record");

static uint8_t  m_addr[5];
static uint8_t  m_channel = DEFAULT_CHANNEL;   /* 0xFF = hop */
static uint8_t  m_bitrate  = DEFAULT_BITRATE;
static uint16_t m_dwell    = DEFAULT_DWELL;
static uint8_t  m_cur      = DEFAULT_CHANNEL;
static uint32_t m_hop_at;
static bool     m_hop_init;
static bool     m_have_addr;
static uint32_t m_chan_rx[101];
static uint8_t  m_last_len;

static uint32_t m_log_words[(LOG_SZ + 3) / 4];
#define m_log ((uint8_t *)m_log_words)
static size_t   m_used, m_cursor;
static uint32_t m_overflow;
static bool     m_loaded, m_dirty;

static bool addr_is_set(const uint8_t a[5]) {
    for (int i = 0; i < 5; i++) if (a[i] != 0) return true;
    return false;
}

static void cfg_parse(const uint8_t *cfg, size_t cfg_len) {
    memset(m_addr, 0, sizeof(m_addr));
    m_channel = DEFAULT_CHANNEL;
    m_bitrate = DEFAULT_BITRATE;
    m_dwell   = DEFAULT_DWELL;
    m_have_addr = false;
    if (cfg == NULL || cfg_len < 6 || cfg[0] != 1) return;
    memcpy(m_addr, &cfg[1], 5);
    m_have_addr = addr_is_set(m_addr);
    if (cfg_len >= 7 && (cfg[6] <= 100 || cfg[6] == HOP_CHANNEL)) m_channel = cfg[6];
    if (cfg_len >= 8 && (cfg[7] == 0 || cfg[7] == 1)) m_bitrate = cfg[7];
    if (cfg_len >= 10) {
        uint16_t d = (uint16_t)(cfg[8] | (cfg[9] << 8));
        if (d >= 50 && d <= 60000) m_dwell = d;
    }
}

static void on_config(const uint8_t *cfg, size_t cfg_len) {
    cfg_parse(cfg, cfg_len);
    /* Apply immediately if already armed -- same reasoning as mode_zigbee.c:
     * set-mode + trigger doesn't call on_enter() on an unchanged mode. */
    if (esb_radio_running() && m_have_addr) {
        m_hop_init = false;
        m_cur = (m_channel == HOP_CHANNEL) ? 0 : m_channel;
        esb_radio_set_channel(m_cur);
    }
}

/* Drops a torn trailing record, same as mode_zigbee.c's log_validate(). */
static size_t log_validate(size_t n) {
    size_t i = 0;
    while (i + REC_HDR <= n) {
        size_t need = REC_HDR + m_log[i + 1];
        if (i + need > n) break;
        i += need;
    }
    return i;
}

static void log_ensure_loaded(void) {
    if (m_loaded) return;
    m_loaded = true;
    size_t n = 0;
    if (app_standalone_load_result_buf(STANDALONE_MODE_ESB, m_log_words,
                                       LOG_SZ, &n) != STANDALONE_RC_OK) {
        n = 0;
    }
    m_used   = log_validate(n);
    m_cursor = 0;
    NRF_LOG_INFO("esb: loaded %u log byte(s)", (unsigned)m_used);
}

static void log_flush(void) {
    if (!m_dirty) return;
    app_standalone_save_result_buf(STANDALONE_MODE_ESB, m_log_words, m_used);
    m_dirty = false;
}

static standalone_rc_t on_enter(const uint8_t *cfg, size_t cfg_len) {
    cfg_parse(cfg, cfg_len);
    if (!m_have_addr) return STANDALONE_RC_INVALID_CFG;   /* refuse an unset address */
    m_last_len = 0;
    m_overflow = 0;
    log_ensure_loaded();
    m_hop_init = false;
    memset(m_chan_rx, 0, sizeof(m_chan_rx));
    m_cur = (m_channel == HOP_CHANNEL) ? 0 : m_channel;
    if (!esb_radio_start(m_addr, m_cur, m_bitrate != 0)) return STANDALONE_RC_INTERNAL;
    NRF_LOG_INFO("esb: rx %s channel %u", m_channel == HOP_CHANNEL ? "hop from" : "on", m_cur);
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_exit(void) {
    esb_radio_stop();
    log_flush();
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_button(standalone_button_evt_t evt) {
    (void)evt;
    return STANDALONE_RC_OK;
}

static void log_add(const esb_frame_t *f) {
    size_t need = REC_HDR + f->len;
    if (m_used + need > LOG_SZ) { m_overflow++; return; }
    m_log[m_used]     = f->channel;
    m_log[m_used + 1] = f->len;
    memcpy(&m_log[m_used + REC_HDR], f->data, f->len);
    m_used += need;
    m_dirty = true;
}

static standalone_rc_t on_tick(uint32_t now_ms) {
    esb_frame_t f;
    esb_radio_poll();
    while (esb_radio_pop(&f)) {
        m_last_len = f.len;
        if (f.channel <= 100) m_chan_rx[f.channel]++;
        log_add(&f);
    }
    if (m_channel == HOP_CHANNEL) {
        if (!m_hop_init) { m_hop_init = true; m_hop_at = now_ms; }
        else if ((uint32_t)(now_ms - m_hop_at) >= m_dwell) {
            m_hop_at = now_ms;
            m_cur = (m_cur >= 100) ? 0 : (uint8_t)(m_cur + 1);
            esb_radio_set_channel(m_cur);
        }
    }
    return STANDALONE_RC_OK;
}

static size_t get_result_size(void) {
    log_ensure_loaded();
    return m_used - m_cursor;
}

static standalone_rc_t read_result(uint8_t *out, size_t out_max, size_t *out_len) {
    if (out == NULL || out_len == NULL) return STANDALONE_RC_INVALID_CFG;
    log_ensure_loaded();
    *out_len = 0;
    if (m_cursor >= m_used) return STANDALONE_RC_NO_RESULT;
    size_t take = 0;
    while (m_cursor + take < m_used) {
        size_t rl = REC_HDR + m_log[m_cursor + take + 1];
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
    log_flush();
}

/* Keep short: the whole `standalone status` reply is built in a 512-byte buffer. */
static size_t get_status(char *out, size_t out_max) {
    size_t len = 0;
    esb_stats_t s;
    esb_radio_get_stats(&s);
    STATUS_KV(out, out_max, len, "radio=%s ch=%u%s bitrate=%s dwell=%u\n",
              esb_radio_running() ? "rx" : "off", m_cur,
              m_channel == HOP_CHANNEL ? " hop" : "", m_bitrate ? "2M" : "1M", m_dwell);
    STATUS_KV(out, out_max, len, "addr=%02x:%02x:%02x:%02x:%02x\n",
              m_addr[0], m_addr[1], m_addr[2], m_addr[3], m_addr[4]);
    STATUS_KV(out, out_max, len, "slots=%lu blocked=%lu canceled=%lu us=%lu\n",
              (unsigned long)s.slots, (unsigned long)s.blocked, (unsigned long)s.canceled,
              (unsigned long)s.slot_us);
    STATUS_KV(out, out_max, len, "diag radio=%lu timer0=%lu idle=%lu rxen=%lu/%lu addr_evt=%lu rc=%lu\n",
              (unsigned long)s.sig_radio, (unsigned long)s.sig_timer0, (unsigned long)s.idle,
              (unsigned long)s.ready_ok, (unsigned long)s.ready_timeout,
              (unsigned long)s.address_evt, (unsigned long)s.last_rc);
    STATUS_KV(out, out_max, len, "frames ok=%lu bad_crc=%lu dropped=%lu\n",
              (unsigned long)s.rx_ok, (unsigned long)s.rx_crc, (unsigned long)s.dropped);
    STATUS_KV(out, out_max, len, "log pending=%u overflow=%lu\n", (unsigned)(m_used - m_cursor),
              (unsigned long)m_overflow);
    STATUS_KV(out, out_max, len, "last len=%u\n", m_last_len);
    return len;
}

const standalone_mode_iface_t mode_esb_iface = {
    .id               = STANDALONE_MODE_ESB,
    .name             = "esb",
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
