/*
 * mode_esb_enum.c
 *
 * Standalone mode: active enumeration of a Unifying dongle. For a 4-byte base
 * address (from a captured frame -- split addr into base+prefix), ping every
 * prefix and use the ESB ACK as the detector; prefixes the dongle listens on
 * are its paired device addresses. mame82's active_enum, see esb_enum_radio.c.
 *
 * Config (8 bytes): u8 version=1, u8 base[4], u8 flags (bit0 = 1Mbit PHY),
 * u8 prefix_lo, u8 prefix_hi (inclusive sweep; 0x00..0xFF for all, prefix 0x00
 * is the dongle's own address). Sweeps the full Unifying channel set.
 *
 * Result: u8 base[4], u8 count, u8 prefixes[count]. Each base+prefix is a
 * device address to feed esb-inject or pairing-sniff.
 */

#include "app_standalone.h"
#include "esb_enum_radio.h"

#include <string.h>
#include "nrf_log.h"

#define CFG_FLAG_1MBIT   (1u << 0)

static const uint8_t UNIFYING_CH[] = {
    5, 8, 11, 14, 17, 20, 23, 26, 29, 32, 35, 38, 41,
    44, 47, 50, 53, 56, 59, 62, 65, 68, 71, 74, 77,
};
#define UNIFYING_CH_N  (sizeof(UNIFYING_CH) / sizeof(UNIFYING_CH[0]))

static uint8_t  m_base[4];
static bool     m_2mbit = true;
static uint8_t  m_plo, m_phi = 0xFF;
static bool     m_scanning;

static uint8_t  m_result[5 + 256];     /* base(4) + count(1) + prefixes */
static size_t   m_rlen, m_rcursor;
static bool     m_have_result;

static void cfg_parse(const uint8_t *cfg, size_t cfg_len) {
    memset(m_base, 0, 4);
    m_2mbit = true;
    m_plo = 0x00;
    m_phi = 0xFF;
    if (cfg == NULL || cfg_len < 8 || cfg[0] != 1) return;
    memcpy(m_base, &cfg[1], 4);
    m_2mbit = (cfg[5] & CFG_FLAG_1MBIT) == 0;
    m_plo = cfg[6];
    m_phi = cfg[7];
    if (m_plo > m_phi) { m_plo = 0x00; m_phi = 0xFF; }
}

static void build_result(void) {
    uint8_t found[32];
    esb_enum_radio_get_found(found);
    memcpy(m_result, m_base, 4);
    size_t n = 0;
    for (int p = 0; p < 256; p++) {
        if (found[p >> 3] & (1u << (p & 7))) m_result[5 + n++] = (uint8_t)p;
    }
    m_result[4] = (uint8_t)n;
    m_rlen = 5 + n;
    m_rcursor = 0;
    m_have_result = true;
    NRF_LOG_INFO("esb-enum: %u device prefix(es) found", (unsigned)n);
}

static standalone_rc_t on_enter(const uint8_t *cfg, size_t cfg_len) {
    cfg_parse(cfg, cfg_len);
    m_have_result = false;
    m_rlen = m_rcursor = 0;
    if (!esb_enum_radio_start(m_base, UNIFYING_CH, UNIFYING_CH_N, m_2mbit, m_plo, m_phi))
        return STANDALONE_RC_INTERNAL;
    m_scanning = true;
    NRF_LOG_INFO("esb-enum: base %02x%02x%02x%02x prefixes %02x..%02x",
                 m_base[0], m_base[1], m_base[2], m_base[3], m_plo, m_phi);
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_exit(void) {
    esb_enum_radio_stop();
    m_scanning = false;
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_button(standalone_button_evt_t evt) {
    (void)evt;
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_tick(uint32_t now_ms) {
    (void)now_ms;
    if (!m_scanning) return STANDALONE_RC_OK;
    esb_enum_radio_poll();
    if (esb_enum_radio_done()) {
        build_result();
        esb_enum_radio_stop();
        m_scanning = false;
    }
    return STANDALONE_RC_OK;
}

static size_t get_result_size(void) {
    return m_have_result ? (m_rlen - m_rcursor) : 0;
}

static standalone_rc_t read_result(uint8_t *out, size_t out_max, size_t *out_len) {
    if (out == NULL || out_len == NULL) return STANDALONE_RC_INVALID_CFG;
    *out_len = 0;
    if (!m_have_result || m_rcursor >= m_rlen) return STANDALONE_RC_NO_RESULT;
    size_t take = m_rlen - m_rcursor;
    if (take > out_max) take = out_max;
    memcpy(out, &m_result[m_rcursor], take);
    m_rcursor += take;
    *out_len = take;
    return STANDALONE_RC_OK;
}

static void clear_result(void) {
    m_have_result = false;
    m_rlen = m_rcursor = 0;
}

static size_t get_status(char *out, size_t out_max) {
    size_t len = 0;
    esb_enum_stats_t s;
    esb_enum_radio_get_stats(&s);
    STATUS_KV(out, out_max, len, "base=%02x%02x%02x%02x bitrate=%s prefixes=%02x..%02x\n",
              m_base[0], m_base[1], m_base[2], m_base[3], m_2mbit ? "2m" : "1m", m_plo, m_phi);
    STATUS_KV(out, out_max, len, "state=%s done=%u/%u found=%u\n",
              m_scanning ? "scan" : (m_have_result ? "done" : "idle"),
              (unsigned)s.prefixes_done, (unsigned)(m_phi - m_plo + 1), (unsigned)s.found_count);
    STATUS_KV(out, out_max, len, "pings=%lu acks=%lu tx_timeout=%lu slots=%lu\n",
              (unsigned long)s.pings, (unsigned long)s.acks,
              (unsigned long)s.tx_timeout, (unsigned long)s.slots);
    return len;
}

const standalone_mode_iface_t mode_esb_enum_iface = {
    .id               = STANDALONE_MODE_ESB_ENUM,
    .name             = "esb-enum",
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
    .ensure_loaded    = NULL,
    .get_status       = get_status,
    .on_config        = NULL,
};
