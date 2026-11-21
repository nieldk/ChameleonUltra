/*
 * mode_esb_prx.c
 *
 * Standalone mode: emulate a Logitech Unifying receiver (sink). Listens on a
 * target address, decrypts the encrypted-keyboard frames with the shared device
 * key, and logs the typed text -- so a second CU running this validates
 * esb-inject (and a real device) end to end, with no dongle needed.
 *
 * This v1 is receive + decrypt only; it does NOT auto-ACK, so it does not yet
 * answer esb-enum (that needs the hardware TIFS RX->TX turnaround). esb-inject
 * transmits blind (it does not read the ACK), so injection is fully testable
 * here: inject on CU-A, read the text on CU-B.
 *
 * Config (>=22 bytes): u8 version=1, u8 addr[5] (base-first), u8 key[16],
 * u8 flags (bit0 = 1Mbit PHY, bit1 = hop the Unifying set), optional u8
 * channel (default 5; used when not hopping). esb-inject sweeps every channel,
 * so a fixed channel here still catches each injected frame.
 *
 * Result: the decrypted typed text (down-transitions only).
 */

#include "app_standalone.h"
#include "esb_prx_radio.h"
#include "esb_unifying.h"

#include <string.h>
#include "nrf_log.h"

#define CFG_FLAG_1MBIT   (1u << 0)
#define CFG_FLAG_HOP     (1u << 1)
#define CFG_FLAG_NOACK   (1u << 2)   /* set to disable the ESB ACK (RX only) */
#define HOP_DWELL_TICKS  5
#define TEXT_MAX         512

static const uint8_t UNIFYING_CH[] = {
    5, 8, 11, 14, 17, 20, 23, 26, 29, 32, 35, 38, 41,
    44, 47, 50, 53, 56, 59, 62, 65, 68, 71, 74, 77,
};
#define UNIFYING_CH_N  (sizeof(UNIFYING_CH) / sizeof(UNIFYING_CH[0]))

static uint8_t  m_addr[5];
static uint8_t  m_key[16];
static bool     m_2mbit = true;
static bool     m_hop;
static bool     m_ack = true;        /* ACK received frames (emulate a real receiver) */
static uint8_t  m_channel = 5;
static uint8_t  m_hop_idx, m_hop_tick;

static uint8_t  m_prev[6];            /* keycodes held in the previous report */
static char     m_text[TEXT_MAX];
static size_t   m_tlen, m_tcursor;
static uint32_t m_rx, m_kbd;

static void cfg_parse(const uint8_t *cfg, size_t cfg_len) {
    memset(m_addr, 0, 5);
    memset(m_key, 0, 16);
    m_2mbit = true;
    m_hop = false;
    m_ack = true;
    m_channel = 5;
    if (cfg == NULL || cfg_len < 22 || cfg[0] != 1) return;
    memcpy(m_addr, &cfg[1], 5);
    memcpy(m_key, &cfg[6], 16);
    m_2mbit = (cfg[22] & CFG_FLAG_1MBIT) == 0;
    m_hop   = (cfg[22] & CFG_FLAG_HOP) != 0;
    m_ack   = (cfg[22] & CFG_FLAG_NOACK) == 0;
    if (cfg_len >= 24 && cfg[23] <= 100) m_channel = cfg[23];
}

static standalone_rc_t on_enter(const uint8_t *cfg, size_t cfg_len) {
    cfg_parse(cfg, cfg_len);
    m_tlen = m_tcursor = 0;
    m_rx = m_kbd = 0;
    m_hop_idx = m_hop_tick = 0;
    memset(m_prev, 0, 6);
    uint8_t ch = m_hop ? UNIFYING_CH[0] : m_channel;
    if (!esb_prx_radio_start(m_addr, ch, m_2mbit, m_ack)) return STANDALONE_RC_INTERNAL;
    NRF_LOG_INFO("esb-prx: receiver on %02x%02x%02x%02x%02x ch=%u hop=%u ack=%u",
                 m_addr[0], m_addr[1], m_addr[2], m_addr[3], m_addr[4], ch, m_hop, m_ack);
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_exit(void) {
    esb_prx_radio_stop();
    return STANDALONE_RC_OK;
}

/* Receiver starts in on_enter (on arm); trigger just needs to succeed. */
static standalone_rc_t on_button(standalone_button_evt_t evt) {
    (void)evt;
    return STANDALONE_RC_OK;
}

static void ingest(const esb_frame_t *f) {
    uint8_t rep[8];
    if (!esb_unifying_decrypt_keyboard(m_key, f->data, f->len, rep)) return;
    m_kbd++;
    uint8_t mod = rep[0];
    for (int i = 2; i < 7; i++) {                 /* [7] is the 0xC9 sentinel */
        uint8_t k = rep[i];
        if (k <= 0x03) continue;
        bool was = false;
        for (int j = 0; j < 6; j++) if (m_prev[j] == k) was = true;
        if (!was) {
            char c = esb_unifying_keycode_char(k, mod);
            if (c && m_tlen < TEXT_MAX) m_text[m_tlen++] = c;
        }
    }
    memset(m_prev, 0, 6);
    int n = 0;
    for (int i = 2; i < 7 && n < 6; i++) if (rep[i] > 0x03) m_prev[n++] = rep[i];
}

static standalone_rc_t on_tick(uint32_t now_ms) {
    (void)now_ms;
    esb_frame_t f;
    esb_prx_radio_poll();
    while (esb_prx_radio_pop(&f)) { m_rx++; ingest(&f); }
    if (m_hop && ++m_hop_tick >= HOP_DWELL_TICKS) {
        m_hop_tick = 0;
        m_hop_idx = (uint8_t)((m_hop_idx + 1u) % UNIFYING_CH_N);
        esb_prx_radio_set_channel(UNIFYING_CH[m_hop_idx]);
    }
    return STANDALONE_RC_OK;
}

static size_t get_result_size(void) { return m_tlen - m_tcursor; }

static standalone_rc_t read_result(uint8_t *out, size_t out_max, size_t *out_len) {
    if (out == NULL || out_len == NULL) return STANDALONE_RC_INVALID_CFG;
    *out_len = 0;
    if (m_tcursor >= m_tlen) return STANDALONE_RC_NO_RESULT;
    size_t take = m_tlen - m_tcursor;
    if (take > out_max) take = out_max;
    memcpy(out, &m_text[m_tcursor], take);
    m_tcursor += take;
    *out_len = take;
    return STANDALONE_RC_OK;
}

static void clear_result(void) {
    m_tlen = m_tcursor = 0;
    memset(m_prev, 0, 6);
}

static size_t get_status(char *out, size_t out_max) {
    size_t len = 0;
    esb_prx_stats_t s;
    esb_prx_radio_get_stats(&s);
    uint8_t cur_ch = m_hop ? UNIFYING_CH[m_hop_idx] : m_channel;
    STATUS_KV(out, out_max, len, "addr=%02x%02x%02x%02x%02x bitrate=%s ch=%u hop=%u ack=%u\n",
              m_addr[0], m_addr[1], m_addr[2], m_addr[3], m_addr[4],
              m_2mbit ? "2m" : "1m", cur_ch, m_hop, m_ack);
    STATUS_KV(out, out_max, len, "rx=%lu keyboard=%lu chars=%u acks=%lu\n",
              (unsigned long)m_rx, (unsigned long)m_kbd, (unsigned)m_tlen,
              (unsigned long)s.acks);
    return len;
}

const standalone_mode_iface_t mode_esb_prx_iface = {
    .id               = STANDALONE_MODE_ESB_PRX,
    .name             = "esb-prx",
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
