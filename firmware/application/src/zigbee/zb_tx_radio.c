/*
 * zb_tx_radio.c - transmit a raw IEEE 802.15.4 frame in chained SoftDevice
 * timeslots. The TX counterpart of zb_radio.c; PHY config is identical
 * (Ieee802154_250Kbit, PLEN 32-bit zero, SFD 0xA7, CRC 16-bit 0x11021/0,
 * CRCINC so the PHR length includes the 2-byte FCS the radio computes). Timeslot
 * mechanics match esb_tx_radio.c.
 *
 * This is a straight inject: no CSMA/CCA back-off before TX. For the Zigbee
 * re-pair trigger the frame is a NWK-secured Leave built host-side; this code
 * just puts the bytes on the air `repeat` times. UNBUILT/untested here.
 */

#include "zb_tx_radio.h"

#include <string.h>

#include "nrf.h"
#include "nrf_sdh_soc.h"
#include "nrf_soc.h"

#define PSDU_MAX       127u
#define SLOT_US        50000u
#define TIMEOUT_US     200000u
#define STOP_GUARD_US  2000u
#define TX_SPIN_MAX    20000u

static nrf_radio_request_t                      m_req;
static nrf_radio_signal_callback_return_param_t m_ret;
static volatile bool    m_run;
static volatile bool    m_open;
static volatile bool    m_done;

static uint8_t  m_channel = 11;
static uint8_t  m_repeat = 1;
static uint8_t  m_gap_ms = 10;
static uint8_t  m_rep;                          /* repeats done */
static uint8_t  m_pkt[1 + PSDU_MAX];            /* [PHR length][PSDU] */
static uint8_t  m_flen;                         /* MAC frame length (no FCS) */

static volatile zb_tx_stats_t m_st;
static volatile bool     m_rereq;
static volatile uint32_t m_slot_us = SLOT_US;

static void fill_request(void) {
    m_req.request_type               = NRF_RADIO_REQ_TYPE_EARLIEST;
    m_req.params.earliest.hfclk      = NRF_RADIO_HFCLK_CFG_XTAL_GUARANTEED;
    m_req.params.earliest.priority   = NRF_RADIO_PRIORITY_NORMAL;
    m_req.params.earliest.length_us  = m_slot_us;
    m_req.params.earliest.timeout_us = TIMEOUT_US;
}

static void radio_cfg(void) {
    NRF_RADIO->POWER   = 1;
    NRF_RADIO->MODE    = RADIO_MODE_MODE_Ieee802154_250Kbit << RADIO_MODE_MODE_Pos;
    NRF_RADIO->PCNF0   = (8UL << RADIO_PCNF0_LFLEN_Pos) |
                         (RADIO_PCNF0_PLEN_32bitZero << RADIO_PCNF0_PLEN_Pos) |
                         (RADIO_PCNF0_CRCINC_Include << RADIO_PCNF0_CRCINC_Pos);
    NRF_RADIO->PCNF1   = (PSDU_MAX << RADIO_PCNF1_MAXLEN_Pos);
    NRF_RADIO->CRCCNF  = (RADIO_CRCCNF_LEN_Two << RADIO_CRCCNF_LEN_Pos) |
                         (RADIO_CRCCNF_SKIPADDR_Ieee802154 << RADIO_CRCCNF_SKIPADDR_Pos);
    NRF_RADIO->CRCPOLY = 0x11021UL;
    NRF_RADIO->CRCINIT = 0;
    NRF_RADIO->SFD     = 0xA7UL;
    NRF_RADIO->FREQUENCY = 5UL * (m_channel - 10u);     /* 2405 MHz + 5*(ch-11) */
    NRF_RADIO->TXPOWER   = RADIO_TXPOWER_TXPOWER_Pos8dBm << RADIO_TXPOWER_TXPOWER_Pos;
    NRF_RADIO->SHORTS    = RADIO_SHORTS_TXREADY_START_Msk | RADIO_SHORTS_END_DISABLE_Msk;
    NRF_RADIO->INTENCLR  = 0xFFFFFFFFUL;
}

static void tx_one(void) {
    m_pkt[0] = (uint8_t)(m_flen + 2);               /* PHR: PSDU incl FCS */
    NRF_RADIO->PACKETPTR = (uint32_t)m_pkt;
    NRF_RADIO->EVENTS_END      = 0;
    NRF_RADIO->EVENTS_DISABLED = 0;
    m_st.tx_attempts++;
    NRF_RADIO->TASKS_TXEN = 1;
    uint32_t i = 0;
    while (!NRF_RADIO->EVENTS_END && i < TX_SPIN_MAX) { __NOP(); i++; }
    if (NRF_RADIO->EVENTS_END) m_st.tx_done++; else m_st.tx_timeout++;
    NRF_RADIO->EVENTS_END = 0;
}

static void radio_off(void) {
    NRF_TIMER0->INTENCLR          = TIMER_INTENCLR_COMPARE0_Msk | TIMER_INTENCLR_COMPARE1_Msk;
    NRF_TIMER0->EVENTS_COMPARE[0] = 0;
    NRF_TIMER0->EVENTS_COMPARE[1] = 0;
    NRF_RADIO->SHORTS             = 0;
    NRF_RADIO->EVENTS_DISABLED    = 0;
    NRF_RADIO->TASKS_DISABLE      = 1;
    for (uint32_t i = 0; i < 2000 && !NRF_RADIO->EVENTS_DISABLED; i++) __NOP();
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->EVENTS_END      = 0;
}

static void arm_step(uint32_t us) {
    uint32_t cc = m_req.params.earliest.length_us - STOP_GUARD_US;
    uint32_t t  = NRF_TIMER0->CC[1] + us;
    if (t >= cc) t = cc - 1;
    NRF_TIMER0->CC[1]             = t;
    NRF_TIMER0->EVENTS_COMPARE[1] = 0;
    NRF_TIMER0->INTENSET          = TIMER_INTENSET_COMPARE1_Msk;
}

static nrf_radio_signal_callback_return_param_t *radio_cb(uint8_t sig) {
    m_ret.callback_action = NRF_RADIO_SIGNAL_CALLBACK_ACTION_NONE;
    switch (sig) {
        case NRF_RADIO_CALLBACK_SIGNAL_TYPE_START:
            m_st.slots++;
            radio_cfg();
            NRF_TIMER0->CC[0]             = m_req.params.earliest.length_us - STOP_GUARD_US;
            NRF_TIMER0->CC[1]             = 0;
            NRF_TIMER0->EVENTS_COMPARE[0] = 0;
            NRF_TIMER0->EVENTS_COMPARE[1] = 0;
            NRF_TIMER0->INTENSET          = TIMER_INTENSET_COMPARE0_Msk;
            NVIC_ClearPendingIRQ(TIMER0_IRQn);
            NVIC_EnableIRQ(TIMER0_IRQn);
            if (!m_done) arm_step(1000u);
            break;
        case NRF_RADIO_CALLBACK_SIGNAL_TYPE_TIMER0:
            if (NRF_TIMER0->EVENTS_COMPARE[1]) {
                NRF_TIMER0->EVENTS_COMPARE[1] = 0;
                if (!m_done) {
                    tx_one();
                    m_st.sent++;
                    if (++m_rep >= m_repeat) { m_done = true; m_run = false; }
                    else                     { arm_step((uint32_t)m_gap_ms * 1000u); }
                }
            }
            if (NRF_TIMER0->EVENTS_COMPARE[0]) {
                NRF_TIMER0->EVENTS_COMPARE[0] = 0;
                radio_off();
                if (m_run && !m_done) {
                    fill_request();
                    m_ret.params.request.p_next = &m_req;
                    m_ret.callback_action       = NRF_RADIO_SIGNAL_CALLBACK_ACTION_REQUEST_AND_END;
                } else {
                    m_ret.callback_action = NRF_RADIO_SIGNAL_CALLBACK_ACTION_END;
                }
            }
            break;
        default:
            break;
    }
    return &m_ret;
}

static void soc_evt(uint32_t evt, void *ctx) {
    (void)ctx;
    if (!m_open) return;
    switch (evt) {
        case NRF_EVT_RADIO_BLOCKED:
        case NRF_EVT_RADIO_CANCELED:
            if (evt == NRF_EVT_RADIO_BLOCKED) m_st.blocked++; else m_st.canceled++;
            m_rereq = true;
            break;
        case NRF_EVT_RADIO_SESSION_IDLE:
            m_st.idle++;
            if (!m_run) (void)sd_radio_session_close();
            break;
        case NRF_EVT_RADIO_SESSION_CLOSED:
            m_open = false;
            break;
        default:
            break;
    }
}
NRF_SDH_SOC_OBSERVER(m_zb_tx_obs, 0, soc_evt, NULL);

void zb_tx_radio_poll(void) {
    if (!m_rereq) return;
    m_rereq = false;
    if (!m_run || !m_open) return;
    fill_request();
    m_st.last_rc = sd_radio_request(&m_req);
}

bool zb_tx_radio_start(uint8_t channel, const uint8_t *frame, uint8_t frame_len,
                       uint8_t repeat, uint8_t gap_ms) {
    if (m_open || frame == NULL) return false;
    if (channel < 11 || channel > 26) return false;
    if (frame_len == 0 || frame_len > ZB_TX_MAX_PSDU) return false;
    memset((void *)&m_st, 0, sizeof(m_st));
    memcpy(&m_pkt[1], frame, frame_len);
    m_flen   = frame_len;
    m_channel = channel;
    m_repeat = repeat ? repeat : 1;
    m_gap_ms = gap_ms ? gap_ms : 10;
    m_rep = 0;
    m_done = false;
    m_slot_us = SLOT_US;
    m_run = true;
    if (sd_radio_session_open(radio_cb) != NRF_SUCCESS) { m_run = false; return false; }
    m_open = true;
    fill_request();
    if (sd_radio_request(&m_req) != NRF_SUCCESS) {
        m_run = false;
        (void)sd_radio_session_close();
        return false;
    }
    return true;
}

bool zb_tx_radio_running(void) { return m_run; }
bool zb_tx_radio_done(void)    { return m_done; }

void zb_tx_radio_stop(void) {
    m_run = false;
    if (m_open) (void)sd_radio_session_close();
}

void zb_tx_radio_get_stats(zb_tx_stats_t *out) {
    *out = *(const zb_tx_stats_t *)&m_st;
    out->slot_us = m_slot_us;
}
