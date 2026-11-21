/*
 * mode_zb_tx.c
 *
 * Standalone mode: transmit one raw IEEE 802.15.4 frame (built host-side) on a
 * Zigbee channel, N times. Used to inject a NWK-secured Leave command that
 * forces a device to re-pair, so the rejoin's Transport-Key can be captured and
 * the network key recovered (cli_zigbee). The frame fits the config blob, so no
 * separate load command is needed; the trigger transmits.
 *
 * Config (>=5 bytes): u8 version=1, u8 channel (11..26), u8 repeat, u8 gap_ms,
 * u8 frame_len, u8 frame[frame_len] (MAC bytes, no FCS -- the radio adds it).
 */

#include "app_standalone.h"
#include "zb_tx_radio.h"

#include <string.h>
#include "nrf_log.h"

static uint8_t  m_channel = 11;
static uint8_t  m_repeat = 1;
static uint8_t  m_gap_ms = 10;
static uint8_t  m_frame[ZB_TX_MAX_PSDU];
static uint8_t  m_flen;
static bool     m_injecting;

static void cfg_parse(const uint8_t *cfg, size_t cfg_len) {
    m_channel = 11;
    m_repeat = 1;
    m_gap_ms = 10;
    m_flen = 0;
    if (cfg == NULL || cfg_len < 5 || cfg[0] != 1) return;
    if (cfg[1] >= 11 && cfg[1] <= 26) m_channel = cfg[1];
    m_repeat = cfg[2] ? cfg[2] : 1;
    m_gap_ms = cfg[3] ? cfg[3] : 10;
    uint8_t flen = cfg[4];
    if (flen > 0 && flen <= ZB_TX_MAX_PSDU && (size_t)(5 + flen) <= cfg_len) {
        memcpy(m_frame, &cfg[5], flen);
        m_flen = flen;
    }
}

static standalone_rc_t on_enter(const uint8_t *cfg, size_t cfg_len) {
    cfg_parse(cfg, cfg_len);
    m_injecting = false;
    NRF_LOG_INFO("zb-tx: armed ch=%u len=%u repeat=%u", m_channel, m_flen, m_repeat);
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_exit(void) {
    if (m_injecting) { zb_tx_radio_stop(); m_injecting = false; }
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_button(standalone_button_evt_t evt) {
    if (evt != STANDALONE_BTN_BOTH_SHORT) return STANDALONE_RC_OK;
    if (m_flen == 0) return STANDALONE_RC_INVALID_STATE;
    if (m_injecting || zb_tx_radio_running()) return STANDALONE_RC_BUSY;
    if (!zb_tx_radio_start(m_channel, m_frame, m_flen, m_repeat, m_gap_ms))
        return STANDALONE_RC_INTERNAL;
    m_injecting = true;
    NRF_LOG_INFO("zb-tx: transmitting %u byte frame x%u on ch %u", m_flen, m_repeat, m_channel);
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_tick(uint32_t now_ms) {
    (void)now_ms;
    if (!m_injecting) return STANDALONE_RC_OK;
    zb_tx_radio_poll();
    if (zb_tx_radio_done()) {
        zb_tx_radio_stop();
        m_injecting = false;
        NRF_LOG_INFO("zb-tx: done");
    }
    return STANDALONE_RC_OK;
}

static size_t get_result_size(void) { return 0; }

static standalone_rc_t read_result(uint8_t *out, size_t out_max, size_t *out_len) {
    (void)out; (void)out_max;
    if (out_len) *out_len = 0;
    return STANDALONE_RC_NO_RESULT;
}

static void clear_result(void) { }

static size_t get_status(char *out, size_t out_max) {
    size_t len = 0;
    zb_tx_stats_t s;
    zb_tx_radio_get_stats(&s);
    STATUS_KV(out, out_max, len, "ch=%u len=%u repeat=%u gap=%ums state=%s\n",
              m_channel, m_flen, m_repeat, m_gap_ms,
              m_injecting ? "tx" : (zb_tx_radio_running() ? "tx" : "idle"));
    STATUS_KV(out, out_max, len, "tx attempts=%lu done=%lu timeout=%lu sent=%lu slots=%lu\n",
              (unsigned long)s.tx_attempts, (unsigned long)s.tx_done,
              (unsigned long)s.tx_timeout, (unsigned long)s.sent, (unsigned long)s.slots);
    return len;
}

const standalone_mode_iface_t mode_zb_tx_iface = {
    .id               = STANDALONE_MODE_ZB_TX,
    .name             = "zb-tx",
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
