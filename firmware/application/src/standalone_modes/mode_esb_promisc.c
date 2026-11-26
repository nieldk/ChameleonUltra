/*
 * mode_esb_promisc.c
 *
 * Standalone mode: ESB sniff for an UNKNOWN address (e.g. finding a Logitech
 * Unifying device with no prior knowledge of it) -- see esb_promisc_radio.h.
 * The radio runs LOGITacker's illegal BALEN=1 match on all 8 pipes at once, so
 * noise still triggers EVENTS_END regularly; CRC is off on-chip (there's
 * nothing to validate an unknown address against there either), so this file
 * runs its own CRC-16 check (esb_crc_valid/esb_unifying_strict_ok, below) on
 * every popped frame in on_tick() BEFORE logging it -- only CRC-valid frames
 * ever reach the log/host, noise is counted in m_filtered and dropped. cli_esb
 * on the host re-runs the same check on what's logged (belt and suspenders,
 * not load-bearing); `standalone esb-promisc status` shows hits (radio-level
 * matches) vs. filtered (dropped here) vs. logged, which is the number that
 * actually matters when nothing shows up in get-result.
 *
 * Config (4-5 bytes): u8 version=1, u8 channel (0-100; the fixed channel when
 * not hopping, else the sweep's start), u8 prefix_lo, u8 prefix_hi (both kept
 * for config-blob compatibility only -- the fixed 8-pipe scheme below has no
 * guess range left to select), and an optional u8 flags: bit0 = hop the
 * Unifying channel set (a device hops, so a fixed channel catches it rarely),
 * bit1 = strict (only log Unifying-shaped frames, len 5/10/22, whose vendor
 * checksum is valid -- tighter than the CRC-only filter already applied).
 *
 * Log record: u8 channel, u8 pipe (0..7, which fixed pipe matched), u8
 * pipe_prefix (that pipe's fixed prefix byte), u8 len, u8 raw[len] (len is
 * always ESB_PROMISC_CAP_LEN here; stored explicitly so the host-side format
 * doesn't silently break if that constant ever changes). Same drain/persist
 * conventions as every other mode.
 */

#include "app_standalone.h"
#include "esb_promisc_radio.h"

#include <string.h>
#include "nrf_log.h"

#define DEFAULT_CHANNEL    5
#define DEFAULT_PREFIX_LO  0x00
#define DEFAULT_PREFIX_HI  0x07
#define REC_HDR            4

#define CFG_FLAG_HOP       (1u << 0)
#define CFG_FLAG_STRICT    (1u << 1)
#define HOP_DWELL_TICKS    5          /* ticks per channel; tick is 20ms -> ~100ms dwell */

/* Logitech Unifying hop set (MHz offsets from 2400), from nRF ESB
 * nrf_esb_update_channel_frequency_table_unifying (mame82). */
static const uint8_t UNIFYING_CH[] = {
    5, 8, 11, 14, 17, 20, 23, 26, 29, 32, 35, 38, 41,
    44, 47, 50, 53, 56, 59, 62, 65, 68, 71, 74, 77,
};
#define UNIFYING_CH_N  (sizeof(UNIFYING_CH) / sizeof(UNIFYING_CH[0]))

#define LOG_SZ          2048
_Static_assert(LOG_SZ + 4 <= STANDALONE_RESULT_PERSIST_MAX,
               "esb-promisc log must fit the framework's persisted result record");
_Static_assert(REC_HDR + ESB_PROMISC_CAP_LEN <= LOG_SZ,
               "esb-promisc log must fit at least one full-size record");

static uint8_t m_channel   = DEFAULT_CHANNEL;
static uint8_t m_prefix_lo = DEFAULT_PREFIX_LO;
static uint8_t m_prefix_hi = DEFAULT_PREFIX_HI;
static bool    m_hop;                  /* sweep the Unifying channel set */
static bool    m_strict;               /* only log checksum-valid Unifying frames */
static uint8_t m_hop_idx;              /* index into UNIFYING_CH when hopping */
static uint8_t m_hop_tick;             /* ticks spent on the current channel */

static uint32_t m_log_words[(LOG_SZ + 3) / 4];
#define m_log ((uint8_t *)m_log_words)
static size_t   m_used, m_cursor;
static uint32_t m_overflow;
static uint32_t m_filtered;      /* radio-level pipe matches dropped: no valid ESB CRC */
static bool     m_loaded, m_dirty;

/* ESB 2-byte CRC-16/CCITT-FALSE check, mirroring cli_esb's host validation so
 * only real frames reach the log. The capture starts at the address, so the
 * CRC covers address(5) + PCF(9 bits) + payload with the 16-bit CRC after it.
 * The nRF52 RADIO stores payload bits LSBit-first, the reverse of the on-air
 * order the CRC runs over, so the bytes are tried as captured and bit-reversed.
 * Main context only (called from on_tick), not the radio callback. */
static uint16_t crc16_over_bits(const uint8_t *b, int nbits) {
    uint16_t crc = 0xFFFF;
    for (int i = 0; i < nbits; i++) {
        uint16_t bit = (b[i >> 3] >> (7 - (i & 7))) & 1u;
        crc ^= bit << 15;
        crc = (crc & 0x8000u) ? (uint16_t)((crc << 1) ^ 0x1021u) : (uint16_t)(crc << 1);
    }
    return crc;
}

static bool esb_crc_valid(const uint8_t *raw, size_t len) {
    uint8_t rev[ESB_PROMISC_CAP_LEN];
    for (size_t i = 0; i < len; i++) {
        uint8_t x = raw[i], r = 0;
        for (int j = 0; j < 8; j++) r = (uint8_t)(r | (((x >> j) & 1u) << (7 - j)));
        rev[i] = r;
    }
    const uint8_t *variants[2] = { raw, rev };
    const int total = (int)(len * 8);
    const int hdr = 5 * 8 + 9;                      /* address + 9-bit PCF */
    for (int v = 0; v < 2; v++) {
        const uint8_t *b = variants[v];
        for (int plen = 0; plen <= 23; plen++) {
            int k = hdr + 8 * plen;
            if (k + 16 > total) break;
            uint16_t got = 0;
            for (int i = 0; i < 16; i++)
                got = (uint16_t)((got << 1) | ((b[(k + i) >> 3] >> (7 - ((k + i) & 7))) & 1u));
            if (crc16_over_bits(b, k) == got) return true;
        }
    }
    return false;
}

/* Strict Unifying filter: a frame passes only if a CRC-valid boundary also
 * yields a Unifying-shaped payload (len 0/5/10/22) whose vendor checksum is
 * valid. Mirrors mame82's LOGITECH_FILTER (nrf_esb_validate_promiscuous_frame
 * + logiteacker_unifying_payload_validate_checksum): length 0 (keepalives,
 * emitted every ~8ms and the clearest live-device signal) passes on CRC alone;
 * for a payload, the last byte must equal the Logitech checksum or its
 * even-masked value (the low bit is sometimes wrong). Same bit-order sweep as
 * esb_crc_valid. */
static bool esb_unifying_strict_ok(const uint8_t *raw, size_t len) {
    uint8_t rev[ESB_PROMISC_CAP_LEN];
    for (size_t i = 0; i < len; i++) {
        uint8_t x = raw[i], r = 0;
        for (int j = 0; j < 8; j++) r = (uint8_t)(r | (((x >> j) & 1u) << (7 - j)));
        rev[i] = r;
    }
    const uint8_t *variants[2] = { raw, rev };
    const int total = (int)(len * 8);
    const int hdr = 5 * 8 + 9;
    const int shapes[4] = { 0, 5, 10, 22 };
    for (int v = 0; v < 2; v++) {
        const uint8_t *b = variants[v];
        for (int s = 0; s < 4; s++) {
            int plen = shapes[s];
            int k = hdr + 8 * plen;
            if (k + 16 > total) continue;
            uint16_t got = 0;
            for (int i = 0; i < 16; i++)
                got = (uint16_t)((got << 1) | ((b[(k + i) >> 3] >> (7 - ((k + i) & 7))) & 1u));
            if (crc16_over_bits(b, k) != got) continue;
            if (plen == 0) return true;                 /* keepalive: CRC-valid, no checksum */
            uint8_t pay[22];
            for (int j = 0; j < plen; j++) {
                uint8_t pb = 0;
                for (int i = 0; i < 8; i++) {
                    int bit = hdr + j * 8 + i;
                    pb = (uint8_t)((pb << 1) | ((b[bit >> 3] >> (7 - (bit & 7))) & 1u));
                }
                pay[j] = pb;
            }
            uint8_t chk = 0;                            /* Logitech checksum over the first plen-1 bytes */
            for (int j = 0; j < plen - 1; j++) chk = (uint8_t)(chk - pay[j]);
            if (pay[plen - 1] == chk || pay[plen - 1] == (uint8_t)(chk & 0xFE)) return true;
        }
    }
    return false;
}

static void cfg_parse(const uint8_t *cfg, size_t cfg_len) {
    m_channel   = DEFAULT_CHANNEL;
    m_prefix_lo = DEFAULT_PREFIX_LO;
    m_prefix_hi = DEFAULT_PREFIX_HI;
    m_hop = false;
    m_strict = false;
    if (cfg == NULL || cfg_len < 2 || cfg[0] != 1) return;
    if (cfg[1] <= 100) m_channel = cfg[1];
    if (cfg_len >= 4 && cfg[2] <= cfg[3]) {
        m_prefix_lo = cfg[2];
        m_prefix_hi = cfg[3];
    }
    if (cfg_len >= 5) {
        m_hop    = (cfg[4] & CFG_FLAG_HOP) != 0;
        m_strict = (cfg[4] & CFG_FLAG_STRICT) != 0;
    }
}

static void on_config(const uint8_t *cfg, size_t cfg_len) {
    cfg_parse(cfg, cfg_len);
    /* Unlike zigbee/esb's set_channel, changing the guess range mid-sweep
     * needs a full restart (the radio driver has no "re-range" entry
     * point) -- simplest to require disarm+trigger, so just don't apply
     * live here. */
}

static size_t log_validate(size_t n) {
    size_t i = 0;
    while (i + REC_HDR <= n) {
        size_t need = REC_HDR + m_log[i + 3];
        if (i + need > n) break;
        i += need;
    }
    return i;
}

static void log_ensure_loaded(void) {
    if (m_loaded) return;
    m_loaded = true;
    size_t n = 0;
    if (app_standalone_load_result_buf(STANDALONE_MODE_ESB_PROMISC, m_log_words,
                                       LOG_SZ, &n) != STANDALONE_RC_OK) {
        n = 0;
    }
    m_used   = log_validate(n);
    m_cursor = 0;
    NRF_LOG_INFO("esb-promisc: loaded %u log byte(s)", (unsigned)m_used);
}

static void log_flush(void) {
    if (!m_dirty) return;
    app_standalone_save_result_buf(STANDALONE_MODE_ESB_PROMISC, m_log_words, m_used);
    m_dirty = false;
}

static standalone_rc_t on_enter(const uint8_t *cfg, size_t cfg_len) {
    cfg_parse(cfg, cfg_len);
    m_overflow = 0;
    m_filtered = 0;
    m_hop_idx  = 0;
    m_hop_tick = 0;
    uint8_t start_ch = m_hop ? UNIFYING_CH[0] : m_channel;
    /* m_prefix_lo/m_prefix_hi are passed through for config-blob compat only;
     * esb_promisc_radio_start() ignores them now (fixed 8-pipe scheme). */
    if (!esb_promisc_radio_start(start_ch, m_prefix_lo, m_prefix_hi)) return STANDALONE_RC_INTERNAL;
    log_ensure_loaded();
    NRF_LOG_INFO("esb-promisc: 8-pipe BALEN=1 sync ch=%u hop=%u strict=%u", start_ch, m_hop, m_strict);
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_exit(void) {
    esb_promisc_radio_stop();
    log_flush();
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_button(standalone_button_evt_t evt) {
    (void)evt;
    return STANDALONE_RC_OK;
}

static void log_add(const esb_promisc_frame_t *f) {
    size_t need = REC_HDR + ESB_PROMISC_CAP_LEN;
    if (m_used + need > LOG_SZ) { m_overflow++; return; }
    m_log[m_used]     = f->channel;
    m_log[m_used + 1] = f->prefix_guess;
    m_log[m_used + 2] = f->base_guess;
    m_log[m_used + 3] = ESB_PROMISC_CAP_LEN;
    memcpy(&m_log[m_used + REC_HDR], f->raw, ESB_PROMISC_CAP_LEN);
    m_used += need;
    m_dirty = true;
}

static standalone_rc_t on_tick(uint32_t now_ms) {
    (void)now_ms;
    esb_promisc_frame_t f;
    esb_promisc_radio_poll();
    while (esb_promisc_radio_pop(&f)) {
        bool keep = m_strict ? esb_unifying_strict_ok(f.raw, ESB_PROMISC_CAP_LEN)
                             : esb_crc_valid(f.raw, ESB_PROMISC_CAP_LEN);
        if (keep) log_add(&f);
        else m_filtered++;        /* noise or non-Unifying (strict): never logged */
    }
    if (m_hop && ++m_hop_tick >= HOP_DWELL_TICKS) {
        m_hop_tick = 0;
        m_hop_idx = (uint8_t)((m_hop_idx + 1u) % UNIFYING_CH_N);
        esb_promisc_radio_set_channel(UNIFYING_CH[m_hop_idx]);
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
        size_t rl = REC_HDR + m_log[m_cursor + take + 3];
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

static size_t get_status(char *out, size_t out_max) {
    size_t len = 0;
    esb_promisc_stats_t s;
    esb_promisc_radio_get_stats(&s);
    uint8_t cur_ch = m_hop ? UNIFYING_CH[m_hop_idx] : m_channel;
    /* No single preamble byte anymore (8 fixed pipes matched at once), so
     * there's nothing meaningful to print there -- see hits/filtered below
     * for what actually indicates traffic. */
    STATUS_KV(out, out_max, len, "radio=%s ch=%u pipes=8 hop=%u strict=%u\n",
              esb_promisc_radio_running() ? "rx" : "off", cur_ch, m_hop, m_strict);
    STATUS_KV(out, out_max, len, "slots=%lu blocked=%lu canceled=%lu us=%lu\n",
              (unsigned long)s.slots, (unsigned long)s.blocked, (unsigned long)s.canceled,
              (unsigned long)s.slot_us);
    STATUS_KV(out, out_max, len, "diag radio=%lu timer0=%lu idle=%lu rxen=%lu/%lu rc=%lu\n",
              (unsigned long)s.sig_radio, (unsigned long)s.sig_timer0, (unsigned long)s.idle,
              (unsigned long)s.ready_ok, (unsigned long)s.ready_timeout, (unsigned long)s.last_rc);
    STATUS_KV(out, out_max, len, "hits=%lu dropped=%lu\n", (unsigned long)s.hits, (unsigned long)s.dropped);
    STATUS_KV(out, out_max, len, "filtered=%lu (noise, not logged)\n", (unsigned long)m_filtered);
    STATUS_KV(out, out_max, len, "log pending=%u overflow=%lu\n", (unsigned)(m_used - m_cursor),
              (unsigned long)m_overflow);
    return len;
}

const standalone_mode_iface_t mode_esb_promisc_iface = {
    .id               = STANDALONE_MODE_ESB_PROMISC,
    .name             = "esb-promisc",
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
