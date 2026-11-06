/*
 * mode_esb_promisc.c
 *
 * Standalone mode: brute-force partial-address ESB sniff for an UNKNOWN
 * address (e.g. finding a Logitech Unifying dongle's address with no prior
 * knowledge of it) -- see esb_promisc_radio.h for exactly what's grounded
 * vs. a genuinely unverified port of a technique built for a different
 * chip generation. Every capture here is a CANDIDATE, not a confirmed
 * frame: CRC is off in this mode (there's nothing to validate an unknown
 * address against), so hits include noise. A sustained hit rate at one
 * (prefix, base-byte) guess is the signal to trust, not an isolated hit.
 *
 * Config (4 bytes): u8 version=1, u8 channel (0-100, no hop -- point this
 * at a channel you already suspect is active, e.g. via the spectrum mode),
 * u8 prefix_lo, u8 prefix_hi (inclusive device-ID guess range, default
 * 0..7 -- Unifying's documented device-ID space is small, not the full
 * 0-255 a fully generic ESB target would need).
 *
 * Log record: u8 channel, u8 prefix_guess, u8 base_guess, u8 len,
 * u8 raw[len] (len is always ESB_PROMISC_CAP_LEN here; stored explicitly
 * so the host-side format doesn't silently break if that constant ever
 * changes). Same drain/persist conventions as every other mode.
 */

#include "app_standalone.h"
#include "esb_promisc_radio.h"

#include <string.h>
#include "nrf_log.h"

#define DEFAULT_CHANNEL    5
#define DEFAULT_PREFIX_LO  0x00
#define DEFAULT_PREFIX_HI  0x07
#define REC_HDR            4

#define LOG_SZ          2048
_Static_assert(LOG_SZ + 4 <= STANDALONE_RESULT_PERSIST_MAX,
               "esb-promisc log must fit the framework's persisted result record");
_Static_assert(REC_HDR + ESB_PROMISC_CAP_LEN <= LOG_SZ,
               "esb-promisc log must fit at least one full-size record");

static uint8_t m_channel   = DEFAULT_CHANNEL;
static uint8_t m_prefix_lo = DEFAULT_PREFIX_LO;
static uint8_t m_prefix_hi = DEFAULT_PREFIX_HI;

static uint32_t m_log_words[(LOG_SZ + 3) / 4];
#define m_log ((uint8_t *)m_log_words)
static size_t   m_used, m_cursor;
static uint32_t m_overflow;
static bool     m_loaded, m_dirty;

static void cfg_parse(const uint8_t *cfg, size_t cfg_len) {
    m_channel   = DEFAULT_CHANNEL;
    m_prefix_lo = DEFAULT_PREFIX_LO;
    m_prefix_hi = DEFAULT_PREFIX_HI;
    if (cfg == NULL || cfg_len < 2 || cfg[0] != 1) return;
    if (cfg[1] <= 100) m_channel = cfg[1];
    if (cfg_len >= 4 && cfg[2] <= cfg[3]) {
        m_prefix_lo = cfg[2];
        m_prefix_hi = cfg[3];
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
    log_ensure_loaded();
    if (!esb_promisc_radio_start(m_channel, m_prefix_lo, m_prefix_hi)) return STANDALONE_RC_INTERNAL;
    NRF_LOG_INFO("esb-promisc: guessing ch=%u prefix=%u..%u", m_channel, m_prefix_lo, m_prefix_hi);
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
    while (esb_promisc_radio_pop(&f)) log_add(&f);
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
    STATUS_KV(out, out_max, len, "radio=%s ch=%u prefix=%u-%u\n",
              esb_promisc_radio_running() ? "rx" : "off", m_channel, m_prefix_lo, m_prefix_hi);
    STATUS_KV(out, out_max, len, "slots=%lu blocked=%lu canceled=%lu us=%lu guesses=%lu\n",
              (unsigned long)s.slots, (unsigned long)s.blocked, (unsigned long)s.canceled,
              (unsigned long)s.slot_us, (unsigned long)s.guesses_tried);
    STATUS_KV(out, out_max, len, "diag radio=%lu timer0=%lu idle=%lu rxen=%lu/%lu rc=%lu\n",
              (unsigned long)s.sig_radio, (unsigned long)s.sig_timer0, (unsigned long)s.idle,
              (unsigned long)s.ready_ok, (unsigned long)s.ready_timeout, (unsigned long)s.last_rc);
    STATUS_KV(out, out_max, len, "hits=%lu dropped=%lu\n", (unsigned long)s.hits, (unsigned long)s.dropped);
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
