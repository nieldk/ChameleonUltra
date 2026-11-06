/*
 * mode_spectrum.c
 *
 * Standalone mode: one-shot 2.4 GHz ISM energy-detect sweep (1 MHz steps,
 * default full 2400-2483 MHz / 84 points -- see sa_radio.c). Idle while
 * armed; `standalone trigger` (or the button) starts one sweep. The host
 * plots the result (`standalone spectrum plot`).
 *
 * Config (4 bytes): u8 version=1, u16 start_mhz LE (2400-2483, default 2400),
 * u8 count (1-84, default 84, clamped so start+count <= 2484). Applies to the
 * next triggered sweep; like zigbee's channel config, also re-applied live to
 * a sweep already in progress isn't attempted here (there's nothing sensible
 * to do mid-sweep), only to the next trigger.
 *
 * Result (persisted, up to 87 bytes): u8 version=2, u16 start_mhz LE, u8
 * count, then `count` raw EDSAMPLE bytes, point i == (start_mhz + i) MHz.
 * Self-describing so the host doesn't have to assume a fixed range. Draining
 * (get-result/plot) advances the read cursor but does not free space; only
 * `standalone clear-result` does -- same convention as every other mode.
 */

#include "app_standalone.h"
#include "sa_radio.h"

#include <string.h>

#define REC_HDR     4                        /* version, start_mhz lo/hi, count */
#define REC_LEN_MAX (REC_HDR + SA_POINT_COUNT)
#define DEFAULT_START_MHZ (SA_START_MHZ)
#define DEFAULT_COUNT     (SA_POINT_COUNT)

static uint32_t m_buf_words[(REC_LEN_MAX + 3) / 4];
#define m_buf ((uint8_t *)m_buf_words)
static size_t   m_used, m_cursor;
static bool     m_loaded, m_dirty;
static bool     m_harvested;   /* true once this sweep's result has been copied into
                                 * m_buf -- without this, sa_radio_done() stays true
                                 * forever after a sweep and on_tick() would re-copy
                                 * and reset m_cursor on every 20ms tick, forever,
                                 * which stomps on any in-progress host drain. */

static uint16_t m_cfg_start_mhz = DEFAULT_START_MHZ;
static uint8_t  m_cfg_count     = DEFAULT_COUNT;

static void cfg_parse(const uint8_t *cfg, size_t cfg_len) {
    m_cfg_start_mhz = DEFAULT_START_MHZ;
    m_cfg_count     = DEFAULT_COUNT;
    if (cfg == NULL || cfg_len < 4 || cfg[0] != 1) return;
    uint16_t start = (uint16_t)(cfg[1] | (cfg[2] << 8));
    uint8_t  count = cfg[3];
    if (count == 0 || count > SA_POINT_COUNT) return;
    if (start < SA_START_MHZ || start + count > SA_START_MHZ + SA_POINT_COUNT) return;
    m_cfg_start_mhz = start;
    m_cfg_count     = count;
}

static void on_config(const uint8_t *cfg, size_t cfg_len) {
    cfg_parse(cfg, cfg_len);
}

static void ensure_loaded(void) {
    if (m_loaded) return;
    m_loaded = true;
    size_t n = 0;
    if (app_standalone_load_result_buf(STANDALONE_MODE_SPECTRUM, m_buf_words,
                                       REC_LEN_MAX, &n) != STANDALONE_RC_OK ||
        n < REC_HDR || m_buf[0] != 2 || n != (size_t)REC_HDR + m_buf[3]) {
        n = 0;
    }
    m_used   = n;
    m_cursor = 0;
}

static void flush_result(void) {
    if (!m_dirty) return;
    app_standalone_save_result_buf(STANDALONE_MODE_SPECTRUM, m_buf_words, m_used);
    m_dirty = false;
}

static standalone_rc_t on_enter(const uint8_t *cfg, size_t cfg_len) {
    (void)cfg; (void)cfg_len;
    ensure_loaded();   /* keep any unread/uncleared sweep from before */
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_exit(void) {
    flush_result();
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_button(standalone_button_evt_t evt) {
    if (evt != STANDALONE_BTN_BOTH_SHORT) return STANDALONE_RC_OK;
    if (sa_radio_busy()) return STANDALONE_RC_BUSY;
    uint16_t start_offset = (uint16_t)(m_cfg_start_mhz - SA_START_MHZ);
    if (!sa_radio_sweep_start(start_offset, m_cfg_count)) return STANDALONE_RC_INTERNAL;
    m_harvested = false;
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_tick(uint32_t now_ms) {
    (void)now_ms;
    sa_radio_poll();
    /* sa_radio_done() stays true from the moment a sweep finishes until the
     * *next* sweep starts, and on_tick() fires every 20ms regardless -- so
     * this must be edge-triggered on m_harvested, not on sa_radio_done()
     * alone, or m_cursor gets reset to 0 on every idle tick and the host's
     * drain (get-result) never sees the result go to zero. */
    if (sa_radio_done() && !m_harvested) {
        size_t   n = 0;
        uint16_t start_offset, count;
        sa_radio_get_range(&start_offset, &count);
        m_buf[0] = 2;   /* version */
        m_buf[1] = (uint8_t)((SA_START_MHZ + start_offset));
        m_buf[2] = (uint8_t)((SA_START_MHZ + start_offset) >> 8);
        sa_radio_get_result(&m_buf[REC_HDR], REC_LEN_MAX - REC_HDR, &n);
        m_buf[3]    = (uint8_t)n;   /* count -- sa_radio clamps to <= SA_POINT_COUNT (255) */
        m_used      = REC_HDR + n;
        m_cursor    = 0;
        m_dirty     = true;
        m_harvested = true;
        flush_result();
    }
    return STANDALONE_RC_OK;
}

static size_t get_result_size(void) {
    ensure_loaded();
    return m_used - m_cursor;
}

static standalone_rc_t read_result(uint8_t *out, size_t out_max, size_t *out_len) {
    if (out == NULL || out_len == NULL) return STANDALONE_RC_INVALID_CFG;
    ensure_loaded();
    *out_len = 0;
    if (m_cursor >= m_used) return STANDALONE_RC_NO_RESULT;
    size_t take = m_used - m_cursor;
    if (take > out_max) take = out_max;
    if (take == 0) return STANDALONE_RC_NO_RESULT;
    memcpy(out, &m_buf[m_cursor], take);
    m_cursor += take;
    *out_len = take;
    return STANDALONE_RC_OK;
}

static void clear_result(void) {
    ensure_loaded();
    m_used = m_cursor = 0;
    m_dirty = true;
    flush_result();
}

static size_t get_status(char *out, size_t out_max) {
    size_t len = 0;
    sa_stats_t s;
    sa_radio_get_stats(&s);
    STATUS_KV(out, out_max, len,
              "sweep=%s range=%u-%u points=%u/%u slots=%lu blocked=%lu canceled=%lu\n",
              sa_radio_busy() ? "running" : (sa_radio_done() ? "done" : "idle"),
              (unsigned)m_cfg_start_mhz, (unsigned)(m_cfg_start_mhz + m_cfg_count - 1),
              (unsigned)s.points_done, (unsigned)m_cfg_count,
              (unsigned long)s.slots, (unsigned long)s.blocked, (unsigned long)s.canceled);
    return len;
}

const standalone_mode_iface_t mode_spectrum_iface = {
    .id               = STANDALONE_MODE_SPECTRUM,
    .name             = "spectrum",
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
    .ensure_loaded    = ensure_loaded,
    .get_status       = get_status,
    .on_config        = on_config,
};
