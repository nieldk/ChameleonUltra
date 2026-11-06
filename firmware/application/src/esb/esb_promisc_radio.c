/*
 * esb_promisc_radio.c - brute-force partial-address ESB/proprietary-PHY
 * sniffer for an unknown address. See esb_promisc_radio.h for what's
 * grounded vs. unverified here; this is a genuinely different radio config
 * from esb_radio.c's known-address path, not a variant of it.
 *
 * Timeslot/session plumbing is identical to esb_radio.c/zb_radio.c; only
 * radio_rx_begin() differs (PCNF0=0 no length field, BALEN=1, CRC off) and
 * there's a guess counter advanced once per slot instead of a hop timer.
 */

#include "esb_promisc_radio.h"

#include <string.h>

#include "nrf.h"
#include "nrf_sdh_soc.h"
#include "nrf_soc.h"

#define SLOT_US        30000u
#define SLOT_MIN_US    5000u
#define TIMEOUT_US     200000u
#define STOP_GUARD_US  2000u
#define RING_SZ        16u

static nrf_radio_request_t                      m_req;
static nrf_radio_signal_callback_return_param_t m_ret;
static volatile bool    m_run;
static volatile bool    m_open;
static uint8_t           m_channel;
static uint8_t           m_prefix_lo, m_prefix_hi;
static uint8_t           m_cur_prefix;
static uint8_t           m_cur_base;        /* single guessed BASE byte */
static uint8_t           m_pkt[ESB_PROMISC_CAP_LEN];
static esb_promisc_frame_t m_ring[RING_SZ];
static volatile uint8_t  m_head, m_tail;
static volatile bool     m_rereq;
static volatile uint32_t m_slot_us = SLOT_US;
static volatile esb_promisc_stats_t m_st;

static void fill_request(void) {
    m_req.request_type               = NRF_RADIO_REQ_TYPE_EARLIEST;
    m_req.params.earliest.hfclk      = NRF_RADIO_HFCLK_CFG_XTAL_GUARANTEED;
    m_req.params.earliest.priority   = NRF_RADIO_PRIORITY_NORMAL;
    m_req.params.earliest.length_us  = m_slot_us;
    m_req.params.earliest.timeout_us = TIMEOUT_US;
}

/* Same bit-reverse-then-byte-reverse conversion esb_radio.c uses for the
 * known-address path (Zephyr esb.c's addr_conv()) -- applied here to a
 * single guessed byte so it lands in the same hardware convention. */
static uint32_t addr_conv(uint32_t inp) {
    inp = (inp & 0xF0F0F0F0UL) >> 4 | (inp & 0x0F0F0F0FUL) << 4;
    inp = (inp & 0xCCCCCCCCUL) >> 2 | (inp & 0x33333333UL) << 2;
    inp = (inp & 0xAAAAAAAAUL) >> 1 | (inp & 0x55555555UL) << 1;
    return __REV(inp);
}

static void advance_guess(void) {
    m_st.guesses_tried++;
    if (m_cur_base < 0xFFu) {
        m_cur_base++;
        return;
    }
    m_cur_base = 0;
    m_cur_prefix = (m_cur_prefix >= m_prefix_hi) ? m_prefix_lo : (uint8_t)(m_cur_prefix + 1);
}

static void radio_rx_begin(void) {
    NRF_RADIO->POWER = 1;
    NRF_RADIO->MODE  = RADIO_MODE_MODE_Nrf_2Mbit << RADIO_MODE_MODE_Pos;

    /* No length field at all -- PCNF0=0, matching POC||GTFO #17's
     * Micro:bit BLE-sniffer config. Everything after the matched address
     * bytes is raw, fixed-length capture, not a parsed ESB payload. */
    NRF_RADIO->PCNF0 = 0;
    NRF_RADIO->PCNF1 = (RADIO_PCNF1_WHITEEN_Disabled << RADIO_PCNF1_WHITEEN_Pos) |
                       (RADIO_PCNF1_ENDIAN_Big        << RADIO_PCNF1_ENDIAN_Pos) |
                       (1UL                           << RADIO_PCNF1_BALEN_Pos) |   /* short match: prefix + 1 base byte */
                       (ESB_PROMISC_CAP_LEN           << RADIO_PCNF1_STATLEN_Pos) |
                       (ESB_PROMISC_CAP_LEN           << RADIO_PCNF1_MAXLEN_Pos);
    NRF_RADIO->CRCCNF = RADIO_CRCCNF_LEN_Disabled << RADIO_CRCCNF_LEN_Pos;   /* no way to validate an unknown frame */

    NRF_RADIO->BASE0   = addr_conv((uint32_t)m_cur_base);
    NRF_RADIO->PREFIX0 = addr_conv((uint32_t)m_cur_prefix);
    NRF_RADIO->RXADDRESSES = RADIO_RXADDRESSES_ADDR0_Enabled << RADIO_RXADDRESSES_ADDR0_Pos;

    NRF_RADIO->FREQUENCY = m_channel;
    NRF_RADIO->PACKETPTR = (uint32_t)m_pkt;
    NRF_RADIO->SHORTS    = RADIO_SHORTS_RXREADY_START_Msk;
    NRF_RADIO->EVENTS_END     = 0;
    NRF_RADIO->EVENTS_READY   = 0;
    NRF_RADIO->INTENSET      = RADIO_INTENSET_END_Msk;

    NRF_TIMER0->CC[0]             = m_slot_us - STOP_GUARD_US;
    NRF_TIMER0->EVENTS_COMPARE[0] = 0;
    NRF_TIMER0->INTENSET          = TIMER_INTENSET_COMPARE0_Msk;

    NVIC_ClearPendingIRQ(RADIO_IRQn);
    NVIC_ClearPendingIRQ(TIMER0_IRQn);
    NVIC_EnableIRQ(RADIO_IRQn);
    NVIC_EnableIRQ(TIMER0_IRQn);

    NRF_RADIO->TASKS_RXEN = 1;
    for (uint32_t i = 0; i < 4000 && !NRF_RADIO->EVENTS_READY; i++) {
        __NOP();
    }
    if (NRF_RADIO->EVENTS_READY) m_st.ready_ok++; else m_st.ready_timeout++;
}

static void radio_off(void) {
    NRF_TIMER0->INTENCLR = TIMER_INTENCLR_COMPARE0_Msk;
    NRF_TIMER0->EVENTS_COMPARE[0] = 0;
    NRF_RADIO->SHORTS    = 0;
    NRF_RADIO->INTENCLR  = RADIO_INTENCLR_END_Msk;
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->TASKS_DISABLE   = 1;
    for (uint32_t i = 0; i < 2000 && !NRF_RADIO->EVENTS_DISABLED; i++) {
        __NOP();
    }
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->EVENTS_END      = 0;
}

static void radio_hit(void) {
    NRF_RADIO->EVENTS_END = 0;
    uint8_t next = (uint8_t)((m_head + 1u) % RING_SZ);
    if (next == m_tail) {
        m_st.dropped++;
    } else {
        esb_promisc_frame_t *f = &m_ring[m_head];
        f->channel      = m_channel;
        f->prefix_guess  = m_cur_prefix;
        f->base_guess    = m_cur_base;
        memcpy(f->raw, m_pkt, ESB_PROMISC_CAP_LEN);
        m_head = next;
        m_st.hits++;
    }
}

static nrf_radio_signal_callback_return_param_t *radio_cb(uint8_t sig) {
    m_ret.callback_action = NRF_RADIO_SIGNAL_CALLBACK_ACTION_NONE;
    switch (sig) {
        case NRF_RADIO_CALLBACK_SIGNAL_TYPE_START:
            m_st.slots++;
            radio_rx_begin();
            break;
        case NRF_RADIO_CALLBACK_SIGNAL_TYPE_RADIO:
            m_st.sig_radio++;
            if (NRF_RADIO->EVENTS_END) radio_hit();
            break;
        case NRF_RADIO_CALLBACK_SIGNAL_TYPE_TIMER0:
            m_st.sig_timer0++;
            radio_off();
            advance_guess();
            if (m_run) {
                fill_request();
                m_ret.params.request.p_next = &m_req;
                m_ret.callback_action       = NRF_RADIO_SIGNAL_CALLBACK_ACTION_REQUEST_AND_END;
            } else {
                m_ret.callback_action = NRF_RADIO_SIGNAL_CALLBACK_ACTION_END;
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
NRF_SDH_SOC_OBSERVER(m_esb_promisc_obs, 0, soc_evt, NULL);

void esb_promisc_radio_poll(void) {
    if (!m_rereq) return;
    m_rereq = false;
    if (!m_run || !m_open) return;
    fill_request();
    m_st.last_rc = sd_radio_request(&m_req);
}

bool esb_promisc_radio_start(uint8_t channel, uint8_t prefix_lo, uint8_t prefix_hi) {
    if (m_open || channel > 100 || prefix_lo > prefix_hi) return false;
    memset((void *)&m_st, 0, sizeof(m_st));
    m_slot_us = SLOT_US;
    m_head = m_tail = 0;
    m_channel   = channel;
    m_prefix_lo = prefix_lo;
    m_prefix_hi = prefix_hi;
    m_cur_prefix = prefix_lo;
    m_cur_base   = 0;
    m_run = true;
    if (sd_radio_session_open(radio_cb) != NRF_SUCCESS) {
        m_run = false;
        return false;
    }
    m_open = true;
    fill_request();
    if (sd_radio_request(&m_req) != NRF_SUCCESS) {
        m_run = false;
        (void)sd_radio_session_close();
        return false;
    }
    return true;
}

void esb_promisc_radio_stop(void) {
    m_run = false;
    if (m_open) (void)sd_radio_session_close();
}

bool esb_promisc_radio_running(void) {
    return m_run;
}

bool esb_promisc_radio_pop(esb_promisc_frame_t *out) {
    if (m_tail == m_head) return false;
    *out = m_ring[m_tail];
    m_tail = (uint8_t)((m_tail + 1u) % RING_SZ);
    return true;
}

void esb_promisc_radio_get_stats(esb_promisc_stats_t *out) {
    *out = *(const esb_promisc_stats_t *)&m_st;
    out->slot_us = m_slot_us;
}
