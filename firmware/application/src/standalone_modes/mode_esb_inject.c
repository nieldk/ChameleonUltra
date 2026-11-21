/*
 * mode_esb_inject.c
 *
 * Standalone mode: transmit (inject) host-built ESB frames on a known 5-byte
 * address -- e.g. Logitech Unifying keystrokes built by cli_esb
 * (esb_build_keyboard_frames). The frames are built and verified host-side
 * (single source of truth, layouts included) and streamed into this mode's RAM
 * with DATA_CMD_STANDALONE_ESB_INJECT_LOAD; the trigger starts the transmit.
 * The radio work is esb_tx_radio.c (PTX, Unifying channel sweep).
 *
 * Config (>=7 bytes): u8 version=1, u8 addr[5] (prefix byte first), u8 flags
 * (bit0 = 1Mbit PHY instead of 2Mbit), optional u8 gap_ms (per-frame gap,
 * default 8), optional u8 repeat (whole-job repeats, default 1). Frames are
 * always swept across the full Unifying channel set so they land wherever the
 * receiver is hopping.
 *
 * LOAD wire format: u8 op (0 = reset buffer, 1 = append), then for append a
 * sequence of records [u8 len][u8 payload[len]]. Host streams in chunks.
 *
 * Produces no capture: the result interface is stubbed.
 */

#include "app_standalone.h"
#include "esb_tx_radio.h"

#include <string.h>
#include "nrf_log.h"

#define CFG_FLAG_1MBIT   (1u << 0)
#define DEFAULT_GAP_MS   8
#define DEFAULT_REPEAT   1

/* Logitech Unifying hop set (MHz offsets from 2400); frames are swept across
 * all of these so one lands wherever the receiver currently listens. */
static const uint8_t UNIFYING_CH[] = {
    5, 8, 11, 14, 17, 20, 23, 26, 29, 32, 35, 38, 41,
    44, 47, 50, 53, 56, 59, 62, 65, 68, 71, 74, 77,
};
#define UNIFYING_CH_N  (sizeof(UNIFYING_CH) / sizeof(UNIFYING_CH[0]))

static uint8_t  m_addr[5];
static bool     m_2mbit = true;
static uint8_t  m_gap_ms = DEFAULT_GAP_MS;
static uint8_t  m_repeat = DEFAULT_REPEAT;

static uint8_t  m_job[ESB_TX_MAX_FRAMES * ESB_MAX_PAYLOAD];
static uint16_t m_job_lens[ESB_TX_MAX_FRAMES];
static uint8_t  m_job_count;
static size_t   m_job_bytes;
static bool     m_injecting;

/* Called from the host command handler (DATA_CMD_STANDALONE_ESB_INJECT_LOAD).
 * op 0 resets the buffer; op 1 appends length-prefixed frame records. Returns
 * a standalone_rc_t. */
standalone_rc_t mode_esb_inject_load(const uint8_t *data, size_t len) {
    if (data == NULL || len < 1) return STANDALONE_RC_INVALID_CFG;
    uint8_t op = data[0];
    if (op == 0) {                       /* reset */
        m_job_count = 0;
        m_job_bytes = 0;
        return STANDALONE_RC_OK;
    }
    if (op != 1) return STANDALONE_RC_INVALID_CFG;

    size_t i = 1;
    while (i < len) {
        uint8_t fl = data[i++];
        if (fl == 0 || fl > ESB_MAX_PAYLOAD) return STANDALONE_RC_INVALID_CFG;
        if (i + fl > len) return STANDALONE_RC_INVALID_CFG;
        if (m_job_count >= ESB_TX_MAX_FRAMES) return STANDALONE_RC_BUFFER_FULL;
        if (m_job_bytes + fl > sizeof(m_job)) return STANDALONE_RC_BUFFER_FULL;
        memcpy(&m_job[m_job_bytes], &data[i], fl);
        m_job_lens[m_job_count++] = fl;
        m_job_bytes += fl;
        i += fl;
    }
    return STANDALONE_RC_OK;
}

static void cfg_parse(const uint8_t *cfg, size_t cfg_len) {
    memset(m_addr, 0, 5);
    m_2mbit  = true;
    m_gap_ms = DEFAULT_GAP_MS;
    m_repeat = DEFAULT_REPEAT;
    if (cfg == NULL || cfg_len < 7 || cfg[0] != 1) return;
    memcpy(m_addr, &cfg[1], 5);
    m_2mbit = (cfg[6] & CFG_FLAG_1MBIT) == 0;
    if (cfg_len >= 8 && cfg[7]) m_gap_ms = cfg[7];
    if (cfg_len >= 9 && cfg[8]) m_repeat = cfg[8];
}

static standalone_rc_t on_enter(const uint8_t *cfg, size_t cfg_len) {
    cfg_parse(cfg, cfg_len);
    m_injecting = false;
    NRF_LOG_INFO("esb-inject: armed addr %02x%02x%02x%02x%02x frames=%u",
                 m_addr[0], m_addr[1], m_addr[2], m_addr[3], m_addr[4], m_job_count);
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_exit(void) {
    if (m_injecting) { esb_tx_radio_stop(); m_injecting = false; }
    return STANDALONE_RC_OK;
}

/* Trigger (host STANDALONE_TRIGGER / button short): start the transmit. */
static standalone_rc_t on_button(standalone_button_evt_t evt) {
    if (evt != STANDALONE_BTN_BOTH_SHORT) return STANDALONE_RC_OK;
    if (m_job_count == 0) return STANDALONE_RC_INVALID_STATE;
    if (m_injecting || esb_tx_radio_running()) return STANDALONE_RC_BUSY;
    if (!esb_tx_radio_start(m_addr, m_job, m_job_lens, m_job_count,
                            UNIFYING_CH, UNIFYING_CH_N, m_2mbit, m_gap_ms, m_repeat)) {
        return STANDALONE_RC_INTERNAL;
    }
    m_injecting = true;
    NRF_LOG_INFO("esb-inject: transmitting %u frame(s)", m_job_count);
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_tick(uint32_t now_ms) {
    (void)now_ms;
    if (!m_injecting) return STANDALONE_RC_OK;
    esb_tx_radio_poll();
    if (esb_tx_radio_done()) {
        esb_tx_radio_stop();
        m_injecting = false;
        NRF_LOG_INFO("esb-inject: done");
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
    esb_tx_stats_t s;
    esb_tx_radio_get_stats(&s);
    STATUS_KV(out, out_max, len, "addr=%02x%02x%02x%02x%02x bitrate=%s gap=%ums repeat=%u\n",
              m_addr[0], m_addr[1], m_addr[2], m_addr[3], m_addr[4],
              m_2mbit ? "2m" : "1m", m_gap_ms, m_repeat);
    STATUS_KV(out, out_max, len, "frames=%u state=%s\n",
              m_job_count, m_injecting ? "tx" : (esb_tx_radio_running() ? "tx" : "idle"));
    STATUS_KV(out, out_max, len, "tx attempts=%lu done=%lu timeout=%lu\n",
              (unsigned long)s.tx_attempts, (unsigned long)s.tx_done, (unsigned long)s.tx_timeout);
    STATUS_KV(out, out_max, len, "sweeps=%lu frames_sent=%lu slots=%lu blocked=%lu\n",
              (unsigned long)s.sweeps, (unsigned long)s.frames_sent,
              (unsigned long)s.slots, (unsigned long)s.blocked);
    return len;
}

const standalone_mode_iface_t mode_esb_inject_iface = {
    .id               = STANDALONE_MODE_ESB_INJECT,
    .name             = "esb-inject",
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
