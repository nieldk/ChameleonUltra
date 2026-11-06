/*
 * zb_radio.c - passive IEEE 802.15.4 receive in chained SoftDevice timeslots.
 *
 * The SoftDevice owns NRF_RADIO, so RX only runs inside timeslots. Each slot is
 * up to SLOT_US long (shorter after cancels); shortly before it ends the radio is stopped and the next slot is
 * requested from the callback. Between slots frames are missed.
 * The callback runs at SoftDevice priority 0 and may not call sd_*: copy the frame,
 * nothing else.
 *
 * Radio setup and RAM layout follow the nRF52840 PS, RADIO "IEEE 802.15.4 operation":
 * PHR first, then PHR-2 bytes, the FCS is not written, one LQI byte follows.
 */

#include "zb_radio.h"

#include <string.h>

#include "nrf.h"
#include "nrf_sdh_soc.h"
#include "nrf_soc.h"

#define SLOT_US        50000u       /* longest slot */
#define SLOT_MIN_US    5000u        /* shortest slot after repeated cancels */
#define SLOT_GROW_US   5000u
#define TIMEOUT_US     200000u      /* give up on a request after 200 ms: BLOCKED */
#define GROW_EVERY     16u          /* granted slots before trying a longer one */
#define STOP_GUARD_US  2000u        /* radio off this long before the slot ends */
#define RING_SZ        8u
#define PSDU_MAX       127u

static nrf_radio_request_t                      m_req;
static nrf_radio_signal_callback_return_param_t m_ret;
static volatile bool    m_run;                  /* wanted */
static volatile bool    m_open;                 /* session open */
static volatile uint8_t m_channel = 11;        /* wanted */
static uint8_t          m_slot_ch = 11;         /* in use this slot */
static uint8_t          m_pkt[1 + PSDU_MAX];    /* PHR + PSDU */
static zb_frame_t       m_ring[RING_SZ];
static volatile uint8_t m_head, m_tail;
static volatile bool     m_rereq;               /* main context re-requests (rate limited) */
static volatile uint32_t m_slot_us = SLOT_US;    /* length asked for next */
static uint32_t         m_cur_us  = SLOT_US;    /* length of the running slot */
static volatile zb_stats_t m_st;

static void fill_request(void) {
    m_req.request_type               = NRF_RADIO_REQ_TYPE_EARLIEST;
    m_req.params.earliest.hfclk      = NRF_RADIO_HFCLK_CFG_XTAL_GUARANTEED;
    m_req.params.earliest.priority   = NRF_RADIO_PRIORITY_NORMAL;
    m_req.params.earliest.length_us  = m_slot_us;
    m_req.params.earliest.timeout_us = TIMEOUT_US;
}

static void radio_rx_begin(void) {
    m_st.power_was = (uint8_t)NRF_RADIO->POWER;
    NRF_RADIO->POWER = 1;
    NRF_RADIO->MODE      = RADIO_MODE_MODE_Ieee802154_250Kbit << RADIO_MODE_MODE_Pos;
    NRF_RADIO->PCNF0     = (8UL << RADIO_PCNF0_LFLEN_Pos) |
                           (RADIO_PCNF0_PLEN_32bitZero << RADIO_PCNF0_PLEN_Pos) |
                           (RADIO_PCNF0_CRCINC_Include << RADIO_PCNF0_CRCINC_Pos);
    NRF_RADIO->PCNF1     = (PSDU_MAX << RADIO_PCNF1_MAXLEN_Pos);
    NRF_RADIO->CRCCNF    = (RADIO_CRCCNF_LEN_Two << RADIO_CRCCNF_LEN_Pos) |
                           (RADIO_CRCCNF_SKIPADDR_Ieee802154 << RADIO_CRCCNF_SKIPADDR_Pos);
    NRF_RADIO->CRCPOLY   = 0x11021UL;
    NRF_RADIO->CRCINIT   = 0;
    NRF_RADIO->SFD       = 0xA7UL;   /* IEEE 802.15.4 start-of-frame delimiter; demod
                                       * only raises FRAMESTART on a match against this.
                                       * Never set before -- worth it even if it's already
                                       * the reset default, since leaving it unset is the
                                       * difference between "definitely right" and "assumed". */
    m_slot_ch            = m_channel;
    NRF_RADIO->FREQUENCY = 5UL * (m_slot_ch - 10u);      /* 2405 MHz + 5 * (ch - 11) */
    NRF_RADIO->PACKETPTR = (uint32_t)m_pkt;
    /* MODECNF0 intentionally left at its reset value (RU_Default, DTX=Center).
     * RU_Fast was tried here and reverted: Nordic's own MODECNF0.RU docs say fast
     * ramp-up disables hardware-enforced TIFS and hands that control to software,
     * which this code never took over. Matches the regression signature exactly --
     * ready_ok/ed_ok stayed healthy (state-machine and RSSI, unaffected by RU) while
     * FRAMESTART never fired even with confirmed real traffic on-channel. */
    NRF_RADIO->SHORTS    = RADIO_SHORTS_RXREADY_START_Msk;   /* END->START is not allowed in this mode */
    NRF_RADIO->EVENTS_END = 0;
    NRF_RADIO->EVENTS_FRAMESTART = 0;
    NRF_RADIO->EVENTS_READY = 0;
    NRF_RADIO->INTENSET   = RADIO_INTENSET_END_Msk | RADIO_INTENSET_FRAMESTART_Msk;

    NRF_TIMER0->CC[0]             = m_cur_us - STOP_GUARD_US;   /* TIMER0 runs at 1 MHz in a slot */
    NRF_TIMER0->EVENTS_COMPARE[0] = 0;
    NRF_TIMER0->INTENSET          = TIMER_INTENSET_COMPARE0_Msk;

    /* The slot signals only arrive with these IRQs enabled (Nordic timeslot guide).
     * Armed before TASKS_RXEN: previously this was armed after the EVENTS_READY
     * busy-wait below, which left a window -- from TASKS_RXEN until NVIC_EnableIRQ --
     * where the shortcut could already auto-start RX and a FRAMESTART/END landing in
     * that window would set its EVENTS bit but never reach radio_cb(RADIO). Too narrow
     * to explain a 100% miss rate by itself, but it was a real gap and is now closed. */
    NVIC_ClearPendingIRQ(RADIO_IRQn);
    NVIC_ClearPendingIRQ(TIMER0_IRQn);
    NVIC_EnableIRQ(RADIO_IRQn);
    NVIC_EnableIRQ(TIMER0_IRQn);

    NRF_RADIO->TASKS_RXEN = 1;
    for (uint32_t i = 0; i < 4000 && !NRF_RADIO->EVENTS_READY; i++) {
        __NOP();
    }
    if (NRF_RADIO->EVENTS_READY) m_st.ready_ok++; else m_st.ready_timeout++;
    m_st.state_after = (uint8_t)NRF_RADIO->STATE;
}

/* One energy-detect sample (Nordic PS, IEEE 802.15.4 ED); bounded wait, raw value. */
static void ed_sample(void) {
    m_st.state_end = (uint8_t)NRF_RADIO->STATE;
    NRF_RADIO->EVENTS_EDEND = 0;
    NRF_RADIO->TASKS_EDSTART = 1;
    for (uint32_t i = 0; i < 20000 && !NRF_RADIO->EVENTS_EDEND; i++) {
        __NOP();
    }
    if (NRF_RADIO->EVENTS_EDEND) {
        m_st.ed_ok++;
        uint8_t v = (uint8_t)NRF_RADIO->EDSAMPLE;
        uint8_t i = (uint8_t)(m_slot_ch - 11u);
        if (v > m_st.ed_max[i]) m_st.ed_max[i] = v;
    } else {
        m_st.ed_timeout++;
        NRF_RADIO->TASKS_EDSTOP = 1;
    }
    NRF_RADIO->EVENTS_EDEND = 0;
}

static void radio_off(void) {
    NRF_TIMER0->INTENCLR = TIMER_INTENCLR_COMPARE0_Msk;
    NRF_TIMER0->EVENTS_COMPARE[0] = 0;
    NRF_RADIO->SHORTS    = 0;
    NRF_RADIO->INTENCLR  = RADIO_INTENCLR_END_Msk | RADIO_INTENCLR_FRAMESTART_Msk;
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->TASKS_DISABLE   = 1;
    for (uint32_t i = 0; i < 2000 && !NRF_RADIO->EVENTS_DISABLED; i++) {
        __NOP();
    }
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->EVENTS_END      = 0;
}

/* RAM: [PHR][MPDU: PHR-2 bytes][LQI]; the radio stays in RXIDLE after END. */
static void radio_frame(void) {
    NRF_RADIO->EVENTS_END = 0;
    uint8_t phr = m_pkt[0] & 0x7F;
    bool    ok  = NRF_RADIO->CRCSTATUS == RADIO_CRCSTATUS_CRCSTATUS_CRCOk;

    if (!ok) {
        m_st.rx_crc++;
    } else if (phr >= 3) {                              /* LQI is valid from 3 octets */
        uint8_t len  = (uint8_t)(phr - 2u);
        uint8_t next = (uint8_t)((m_head + 1u) % RING_SZ);
        if (next == m_tail) {
            m_st.dropped++;
        } else {
            zb_frame_t *f = &m_ring[m_head];
            f->channel = m_slot_ch;
            f->len = len;
            f->lqi = m_pkt[1 + len];
            memcpy(f->data, &m_pkt[1], len);
            m_head = next;
            m_st.rx_ok++;
            m_st.last_lqi = f->lqi;
        }
    }
    NRF_RADIO->PACKETPTR = (uint32_t)m_pkt;
    NRF_RADIO->TASKS_START = 1;
}

static nrf_radio_signal_callback_return_param_t *radio_cb(uint8_t sig) {
    m_ret.callback_action = NRF_RADIO_SIGNAL_CALLBACK_ACTION_NONE;
    switch (sig) {
        case NRF_RADIO_CALLBACK_SIGNAL_TYPE_START:
            m_st.slots++;
            m_cur_us = m_req.params.earliest.length_us;
            if (m_st.slots % GROW_EVERY == 0 && m_slot_us < SLOT_US) m_slot_us += SLOT_GROW_US;
            radio_rx_begin();
            break;
        case NRF_RADIO_CALLBACK_SIGNAL_TYPE_RADIO:
            m_st.sig_radio++;
            if (NRF_RADIO->EVENTS_FRAMESTART) {
                NRF_RADIO->EVENTS_FRAMESTART = 0;
                m_st.framestart++;
            }
            if (NRF_RADIO->EVENTS_END) radio_frame();
            break;
        case NRF_RADIO_CALLBACK_SIGNAL_TYPE_TIMER0:
            m_st.sig_timer0++;
            ed_sample();
            radio_off();
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

/* Main context: SoftDevice system events. */
static void soc_evt(uint32_t evt, void *ctx) {
    (void)ctx;
    if (!m_open) return;
    switch (evt) {
        case NRF_EVT_RADIO_BLOCKED:
        case NRF_EVT_RADIO_CANCELED:
            if (evt == NRF_EVT_RADIO_BLOCKED) m_st.blocked++; else m_st.canceled++;
            if (m_slot_us > SLOT_MIN_US) m_slot_us = (m_slot_us / 2 > SLOT_MIN_US) ? m_slot_us / 2 : SLOT_MIN_US;
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
NRF_SDH_SOC_OBSERVER(m_zb_obs, 0, soc_evt, NULL);

/* Main context, called from the mode tick: at most one re-request per tick. */
void zb_radio_poll(void) {
    if (!m_rereq) return;
    m_rereq = false;
    if (!m_run || !m_open) return;
    fill_request();
    m_st.last_rc = sd_radio_request(&m_req);
}

bool zb_radio_start(uint8_t channel) {
    if (m_open || channel < 11 || channel > 26) return false;
    memset((void *)&m_st, 0, sizeof(m_st));
    m_slot_us = SLOT_US;
    m_head = m_tail = 0;
    m_channel = channel;
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

void zb_radio_set_channel(uint8_t channel) {
    if (channel >= 11 && channel <= 26) m_channel = channel;
}

void zb_radio_stop(void) {
    m_run = false;
    if (m_open) (void)sd_radio_session_close();   /* BUSY inside a slot: closed on SESSION_IDLE */
}

bool zb_radio_running(void) {
    return m_run;
}

bool zb_radio_pop(zb_frame_t *out) {
    if (m_tail == m_head) return false;
    *out = m_ring[m_tail];
    m_tail = (uint8_t)((m_tail + 1u) % RING_SZ);
    return true;
}

void zb_radio_get_stats(zb_stats_t *out) {
    *out = *(const zb_stats_t *)&m_st;
    out->slot_us = m_slot_us;
}
