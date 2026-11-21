/*
 * esb_prx_radio.c - emulate an ESB PRX (receiver): address-matched RX in
 * chained SoftDevice timeslots, plus an ESB ACK transmitted after each
 * good-CRC frame. The receive half is esb_radio.c verbatim (same framing,
 * address byte-order, ring); the ACK half is the Nordic ESB PRX turnaround
 * (nrf_esb_illegalmod on_radio_disabled_rx): disable, TXEN a len-0 ACK, ramp
 * back to RX. Both sides use the default ~130us ramp, so the ACK lands in the
 * PTX's wait window without an explicit TIFS.
 *
 * The ACK here is done with bounded spins in the radio callback rather than
 * pure PPI/SHORTS chaining -- simpler to follow, and the TX ramp dominates the
 * timing. If a bench shows the ACK arriving too late for esb-enum, this spin
 * turnaround is the thing to replace with a SHORTS/TIFS one; ack_enable=false
 * falls back to pure RX in the meantime. UNBUILT/untested here.
 *
 * See esb_radio.c for the register-config provenance (it is identical).
 */

#include "esb_prx_radio.h"

#include <string.h>

#include "nrf.h"
#include "nrf_sdh_soc.h"
#include "nrf_soc.h"

#define SLOT_US        50000u
#define SLOT_MIN_US    5000u
#define TIMEOUT_US     200000u
#define STOP_GUARD_US  2000u
#define RING_SZ        8u
#define ACK_TX_SPIN    6000u        /* bounded wait for the ACK TX END */
#define RAMP_SPIN      4000u        /* bounded wait for a ramp (READY/DISABLED) */

static nrf_radio_request_t                      m_req;
static nrf_radio_signal_callback_return_param_t m_ret;
static volatile bool    m_run;
static volatile bool    m_open;
static volatile uint8_t m_channel = 5;
static uint8_t          m_slot_ch = 5;
static uint8_t          m_addr[5];
static bool             m_2mbit = true;
static bool             m_ack_enable = true;

static uint8_t          m_pkt[1 + ESB_MAX_PAYLOAD];   /* [LENGTH][payload] */
static uint8_t          m_ack[1] = { 0 };             /* len-0 ACK, S1 excluded from RAM */
static esb_frame_t      m_ring[RING_SZ];
static volatile uint8_t m_head, m_tail;
static volatile bool    m_rereq;
static volatile uint32_t m_slot_us = SLOT_US;
static volatile esb_prx_stats_t m_st;

static void fill_request(void) {
    m_req.request_type               = NRF_RADIO_REQ_TYPE_EARLIEST;
    m_req.params.earliest.hfclk      = NRF_RADIO_HFCLK_CFG_XTAL_GUARANTEED;
    m_req.params.earliest.priority   = NRF_RADIO_PRIORITY_NORMAL;
    m_req.params.earliest.length_us  = m_slot_us;
    m_req.params.earliest.timeout_us = TIMEOUT_US;
}

static uint32_t addr_conv(uint32_t inp) {
    inp = (inp & 0xF0F0F0F0UL) >> 4 | (inp & 0x0F0F0F0FUL) << 4;
    inp = (inp & 0xCCCCCCCCUL) >> 2 | (inp & 0x33333333UL) << 2;
    inp = (inp & 0xAAAAAAAAUL) >> 1 | (inp & 0x55555555UL) << 1;
    return __REV(inp);
}

static void radio_cfg_common(void) {
    NRF_RADIO->POWER = 1;
    NRF_RADIO->MODE  = (m_2mbit ? RADIO_MODE_MODE_Nrf_2Mbit : RADIO_MODE_MODE_Nrf_1Mbit)
                        << RADIO_MODE_MODE_Pos;
    NRF_RADIO->PCNF0 = (0UL << RADIO_PCNF0_S0LEN_Pos) |
                       (6UL << RADIO_PCNF0_LFLEN_Pos) |
                       (3UL << RADIO_PCNF0_S1LEN_Pos);
    NRF_RADIO->PCNF1 = (RADIO_PCNF1_WHITEEN_Disabled << RADIO_PCNF1_WHITEEN_Pos) |
                       (RADIO_PCNF1_ENDIAN_Big        << RADIO_PCNF1_ENDIAN_Pos) |
                       (4UL                           << RADIO_PCNF1_BALEN_Pos) |
                       (0UL                           << RADIO_PCNF1_STATLEN_Pos) |
                       (ESB_MAX_PAYLOAD               << RADIO_PCNF1_MAXLEN_Pos);
    NRF_RADIO->CRCCNF  = RADIO_CRCCNF_LEN_Two << RADIO_CRCCNF_LEN_Pos;
    NRF_RADIO->CRCPOLY = 0x11021UL;
    NRF_RADIO->CRCINIT = 0xFFFFUL;
    NRF_RADIO->BASE0   = addr_conv(((uint32_t)m_addr[0] << 24) | ((uint32_t)m_addr[1] << 16) |
                                    ((uint32_t)m_addr[2] << 8)  |  (uint32_t)m_addr[3]);
    /* addr_conv()'s __REV() is only correct for a 4-byte value (BASE0); for
     * a lone prefix byte it lands in bits[31:24] instead of AP0's bits[7:0].
     * Shift back down -- see esb_radio.c for the full explanation. */
    NRF_RADIO->PREFIX0 = addr_conv((uint32_t)m_addr[4]) >> 24;
    NRF_RADIO->RXADDRESSES = RADIO_RXADDRESSES_ADDR0_Enabled << RADIO_RXADDRESSES_ADDR0_Pos;
    NRF_RADIO->TXADDRESS   = 0;
    NRF_RADIO->TXPOWER     = RADIO_TXPOWER_TXPOWER_Pos8dBm << RADIO_TXPOWER_TXPOWER_Pos;
}

static void radio_rx_begin(void) {
    radio_cfg_common();
    m_slot_ch            = m_channel;
    NRF_RADIO->FREQUENCY = m_slot_ch;
    NRF_RADIO->PACKETPTR = (uint32_t)m_pkt;
    NRF_RADIO->SHORTS    = RADIO_SHORTS_RXREADY_START_Msk;
    NRF_RADIO->EVENTS_END     = 0;
    NRF_RADIO->EVENTS_ADDRESS = 0;
    NRF_RADIO->EVENTS_READY   = 0;
    NRF_RADIO->INTENSET       = RADIO_INTENSET_END_Msk;

    NRF_TIMER0->CC[0]             = m_req.params.earliest.length_us - STOP_GUARD_US;
    NRF_TIMER0->EVENTS_COMPARE[0] = 0;
    NRF_TIMER0->INTENSET          = TIMER_INTENSET_COMPARE0_Msk;
    NVIC_ClearPendingIRQ(RADIO_IRQn);
    NVIC_ClearPendingIRQ(TIMER0_IRQn);
    NVIC_EnableIRQ(RADIO_IRQn);
    NVIC_EnableIRQ(TIMER0_IRQn);

    NRF_RADIO->TASKS_RXEN = 1;
    for (uint32_t i = 0; i < RAMP_SPIN && !NRF_RADIO->EVENTS_READY; i++) __NOP();
}

/* Transmit the len-0 ACK and ramp back to RX. Blocking (bounded). */
static void send_ack(void) {
    NRF_RADIO->SHORTS          = 0;
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->TASKS_DISABLE   = 1;
    for (uint32_t i = 0; i < RAMP_SPIN && !NRF_RADIO->EVENTS_DISABLED; i++) __NOP();

    NRF_RADIO->PACKETPTR = (uint32_t)m_ack;
    NRF_RADIO->SHORTS    = RADIO_SHORTS_READY_START_Msk | RADIO_SHORTS_END_DISABLE_Msk;
    NRF_RADIO->EVENTS_END      = 0;
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->TASKS_TXEN      = 1;
    for (uint32_t i = 0; i < ACK_TX_SPIN && !NRF_RADIO->EVENTS_END; i++) __NOP();
    NRF_RADIO->EVENTS_END = 0;
    for (uint32_t i = 0; i < RAMP_SPIN && !NRF_RADIO->EVENTS_DISABLED; i++) __NOP();
    NRF_RADIO->EVENTS_DISABLED = 0;
    m_st.acks++;

    /* back to RX */
    NRF_RADIO->PACKETPTR = (uint32_t)m_pkt;
    NRF_RADIO->SHORTS    = RADIO_SHORTS_RXREADY_START_Msk;
    NRF_RADIO->EVENTS_READY = 0;
    NRF_RADIO->TASKS_RXEN   = 1;
    for (uint32_t i = 0; i < RAMP_SPIN && !NRF_RADIO->EVENTS_READY; i++) __NOP();
}

static void radio_frame(void) {
    NRF_RADIO->EVENTS_END = 0;
    bool    ok  = NRF_RADIO->CRCSTATUS == RADIO_CRCSTATUS_CRCSTATUS_CRCOk;
    uint8_t len = m_pkt[0] & 0x3FUL;
    if (!ok) {
        m_st.rx_crc++;
    } else {
        if (len > 0 && len <= ESB_MAX_PAYLOAD) {
            uint8_t next = (uint8_t)((m_head + 1u) % RING_SZ);
            if (next == m_tail) {
                m_st.dropped++;
            } else {
                esb_frame_t *f = &m_ring[m_head];
                f->channel = m_slot_ch;
                f->len = len;
                memcpy(f->data, &m_pkt[1], len);
                m_head = next;
                m_st.rx_ok++;
            }
        }
    }
    if (ok && m_ack_enable) {
        send_ack();                 /* leaves the radio back in RX */
    } else {
        NRF_RADIO->PACKETPTR = (uint32_t)m_pkt;
        NRF_RADIO->TASKS_START = 1;
    }
}

static void radio_off(void) {
    NRF_TIMER0->INTENCLR = TIMER_INTENCLR_COMPARE0_Msk;
    NRF_TIMER0->EVENTS_COMPARE[0] = 0;
    NRF_RADIO->SHORTS    = 0;
    NRF_RADIO->INTENCLR  = RADIO_INTENCLR_END_Msk;
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->TASKS_DISABLE   = 1;
    for (uint32_t i = 0; i < 2000 && !NRF_RADIO->EVENTS_DISABLED; i++) __NOP();
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->EVENTS_END      = 0;
}

static nrf_radio_signal_callback_return_param_t *radio_cb(uint8_t sig) {
    m_ret.callback_action = NRF_RADIO_SIGNAL_CALLBACK_ACTION_NONE;
    switch (sig) {
        case NRF_RADIO_CALLBACK_SIGNAL_TYPE_START:
            m_st.slots++;
            radio_rx_begin();
            break;
        case NRF_RADIO_CALLBACK_SIGNAL_TYPE_RADIO:
            if (NRF_RADIO->EVENTS_END) radio_frame();
            break;
        case NRF_RADIO_CALLBACK_SIGNAL_TYPE_TIMER0:
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
NRF_SDH_SOC_OBSERVER(m_esb_prx_obs, 0, soc_evt, NULL);

void esb_prx_radio_poll(void) {
    if (!m_rereq) return;
    m_rereq = false;
    if (!m_run || !m_open) return;
    fill_request();
    m_st.last_rc = sd_radio_request(&m_req);
}

bool esb_prx_radio_pop(esb_frame_t *out) {
    if (m_tail == m_head) return false;
    *out = m_ring[m_tail];
    m_tail = (uint8_t)((m_tail + 1u) % RING_SZ);
    return true;
}

bool esb_prx_radio_start(const uint8_t addr[5], uint8_t channel,
                         bool bitrate_2mbit, bool ack_enable) {
    if (m_open || addr == NULL || channel > 100) return false;
    memset((void *)&m_st, 0, sizeof(m_st));
    memcpy(m_addr, addr, 5);
    m_channel = channel;
    m_slot_ch = channel;
    m_2mbit = bitrate_2mbit;
    m_ack_enable = ack_enable;
    m_head = m_tail = 0;
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

void esb_prx_radio_set_channel(uint8_t channel) {
    if (channel <= 100) m_channel = channel;
}

void esb_prx_radio_stop(void) {
    m_run = false;
    if (m_open) (void)sd_radio_session_close();
}

bool esb_prx_radio_running(void) { return m_run; }

void esb_prx_radio_get_stats(esb_prx_stats_t *out) {
    *out = *(const esb_prx_stats_t *)&m_st;
    out->slot_us = m_slot_us;
}
