/*
 * esb_enum_radio.c - active enumeration of a Unifying dongle: ping each prefix
 * on a fixed base address and use the ESB ACK as the detector. The PTX-with-ACK
 * counterpart used by mame82's active_enum, under SoftDevice timeslots.
 *
 * Timeslot mechanics and the register/address config match esb_radio.c /
 * esb_tx_radio.c. The ACK turnaround is carried from Nordic's ESB PTX
 * (nrf_esb_illegalmod on_radio_disabled_tx*): SHORTS READY_START | END_DISABLE
 * | DISABLED_RXEN, so after TXEN the radio sends, END-disables and ramps to RX;
 * a CRCOK RX inside the retransmit window is the ACK. Here the sequence is
 * polled (bounded spins) rather than PPI/ISR-chained, so it is simpler but the
 * ACK-window spin length is a bring-up constant, not a verified value.
 *
 * Each slot pings prefixes against a time budget, resuming the sweep across
 * slots. A prefix is tried on each channel until one ACKs (the dongle hops).
 */

#include "esb_enum_radio.h"

#include <string.h>

#include "nrf.h"
#include "nrf_sdh_soc.h"
#include "nrf_soc.h"

#define SLOT_US        50000u
#define TIMEOUT_US     200000u
#define STOP_GUARD_US  3000u
#define TX_SPIN_MAX    20000u       /* bounded wait for the TX END (deterministic, fast) */
/* ACK wait, in real microseconds off the 1MHz timeslot TIMER0. From Nordic ESB
 * (nrf_esb_illegalmod): RX wait-for-ack is 50us at 2Mbit, 73us at 1Mbit, timed
 * from RX-ready; their retransmit_delay-130 implies a ~130us RX ramp. We wait
 * ramp + window from the TX END. */
#define RX_RAMP_US     140u
#define ACK_WAIT_US_2M 50u
#define ACK_WAIT_US_1M 73u

static nrf_radio_request_t                      m_req;
static nrf_radio_signal_callback_return_param_t m_ret;
static volatile bool    m_run;
static volatile bool    m_open;
static volatile bool    m_done;

static uint8_t  m_base[4];
static bool     m_2mbit = true;
static uint8_t  m_channels[ESB_ENUM_MAX_CHANNELS];
static uint8_t  m_nch;
static uint8_t  m_plo, m_phi;

static uint16_t m_prefix;           /* current prefix (0..256; 256 = done) */
static uint8_t  m_ch_idx;           /* channel index for the current prefix */
static uint8_t  m_found[32];        /* bit p = prefix p ACKed */

static uint8_t  m_ping[2 + 1];      /* [LENGTH=1][S1][payload 0x00] */
static volatile esb_enum_stats_t m_st;
static volatile bool     m_rereq;
static volatile uint32_t m_slot_us = SLOT_US;

static void fill_request(void) {
    m_req.request_type               = NRF_RADIO_REQ_TYPE_EARLIEST;
    m_req.params.earliest.hfclk      = NRF_RADIO_HFCLK_CFG_XTAL_GUARANTEED;
    m_req.params.earliest.priority   = NRF_RADIO_PRIORITY_NORMAL;
    m_req.params.earliest.length_us  = m_slot_us;
    m_req.params.earliest.timeout_us = TIMEOUT_US;
}

static uint32_t elapsed_us(void);   /* defined below; microseconds since slot start */

static uint32_t addr_conv(uint32_t inp) {
    inp = (inp & 0xF0F0F0F0UL) >> 4 | (inp & 0x0F0F0F0FUL) << 4;
    inp = (inp & 0xCCCCCCCCUL) >> 2 | (inp & 0x33333333UL) << 2;
    inp = (inp & 0xAAAAAAAAUL) >> 1 | (inp & 0x55555555UL) << 1;
    return __REV(inp);
}

/* Static framing config for the slot. Address and channel are set per ping. */
static void radio_cfg(void) {
    NRF_RADIO->POWER = 1;
    NRF_RADIO->MODE  = (m_2mbit ? RADIO_MODE_MODE_Nrf_2Mbit : RADIO_MODE_MODE_Nrf_1Mbit)
                        << RADIO_MODE_MODE_Pos;
    NRF_RADIO->PCNF0 = (0UL << RADIO_PCNF0_S0LEN_Pos) |
                       (6UL << RADIO_PCNF0_LFLEN_Pos) |
                       (3UL << RADIO_PCNF0_S1LEN_Pos) |
                       (RADIO_PCNF0_S1INCL_Include << RADIO_PCNF0_S1INCL_Pos);
    NRF_RADIO->PCNF1 = (RADIO_PCNF1_WHITEEN_Disabled << RADIO_PCNF1_WHITEEN_Pos) |
                       (RADIO_PCNF1_ENDIAN_Big        << RADIO_PCNF1_ENDIAN_Pos) |
                       (4UL                           << RADIO_PCNF1_BALEN_Pos) |
                       (0UL                           << RADIO_PCNF1_STATLEN_Pos) |
                       (ESB_MAX_PAYLOAD               << RADIO_PCNF1_MAXLEN_Pos);
    NRF_RADIO->CRCCNF  = RADIO_CRCCNF_LEN_Two << RADIO_CRCCNF_LEN_Pos;
    NRF_RADIO->CRCPOLY = 0x11021UL;
    NRF_RADIO->CRCINIT = 0xFFFFUL;
    NRF_RADIO->BASE0   = addr_conv(((uint32_t)m_base[0] << 24) | ((uint32_t)m_base[1] << 16) |
                                    ((uint32_t)m_base[2] << 8)  |  (uint32_t)m_base[3]);
    NRF_RADIO->TXADDRESS   = 0;
    NRF_RADIO->RXADDRESSES = RADIO_RXADDRESSES_ADDR0_Enabled << RADIO_RXADDRESSES_ADDR0_Pos;
    NRF_RADIO->TXPOWER     = RADIO_TXPOWER_TXPOWER_Pos8dBm << RADIO_TXPOWER_TXPOWER_Pos;
    NRF_RADIO->INTENCLR    = 0xFFFFFFFFUL;
}

/* Ping base+prefix on ch, return true if an ACK (CRCOK) came back. */
static bool ping_ack(uint8_t prefix, uint8_t ch) {
    /* addr_conv()'s __REV() is only correct for a 4-byte value (BASE0); for
     * a lone prefix byte it lands in bits[31:24] instead of AP0's bits[7:0].
     * Shift back down -- see esb_radio.c for the full explanation. */
    NRF_RADIO->PREFIX0   = addr_conv((uint32_t)prefix) >> 24;
    NRF_RADIO->FREQUENCY = ch;
    m_ping[0] = 1;                       /* LENGTH */
    m_ping[1] = (uint8_t)((prefix & 0x03u) << 1);   /* S1: PID, no_ack=0 */
    m_ping[2] = 0x00;
    NRF_RADIO->PACKETPTR = (uint32_t)m_ping;
    NRF_RADIO->SHORTS    = RADIO_SHORTS_READY_START_Msk | RADIO_SHORTS_END_DISABLE_Msk |
                           RADIO_SHORTS_DISABLED_RXEN_Msk;
    NRF_RADIO->EVENTS_END      = 0;
    NRF_RADIO->EVENTS_DISABLED = 0;

    bool ack = false;   /* real bug, not just the warning: `goto off` below skipped this
                         * declaration, so a TX timeout returned an uninitialized value */
    m_st.pings++;
    NRF_RADIO->TASKS_TXEN = 1;
    uint32_t i = 0;
    while (!NRF_RADIO->EVENTS_END && i < TX_SPIN_MAX) { __NOP(); i++; }
    if (!NRF_RADIO->EVENTS_END) { m_st.tx_timeout++; goto off; }
    NRF_RADIO->EVENTS_END = 0;
    /* TX END has disabled and DISABLED_RXEN has ramped to RX. Drop the
     * turnaround short so the ACK RX stops after it, then wait its END for the
     * RX ramp plus the bitrate's ack window (real us off TIMER0). */
    NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk | RADIO_SHORTS_END_DISABLE_Msk;
    uint32_t deadline = elapsed_us() + RX_RAMP_US + (m_2mbit ? ACK_WAIT_US_2M : ACK_WAIT_US_1M);
    while (!NRF_RADIO->EVENTS_END && elapsed_us() < deadline) { __NOP(); }
    ack = NRF_RADIO->EVENTS_END &&
          (NRF_RADIO->CRCSTATUS == RADIO_CRCSTATUS_CRCSTATUS_CRCOk);
    if (ack) m_st.acks++;
off:
    NRF_RADIO->SHORTS          = 0;
    NRF_RADIO->EVENTS_END      = 0;
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->TASKS_DISABLE   = 1;
    for (uint32_t j = 0; j < 2000 && !NRF_RADIO->EVENTS_DISABLED; j++) __NOP();
    NRF_RADIO->EVENTS_DISABLED = 0;
    return ack;
}

/* Advance to the next prefix after one ACK/decision. */
static void next_prefix(void) {
    m_ch_idx = 0;
    m_st.prefixes_done++;
    if (m_prefix >= m_phi) { m_prefix = 256; m_done = true; m_run = false; return; }
    m_prefix++;
}

static uint32_t elapsed_us(void) {
    NRF_TIMER0->TASKS_CAPTURE[1] = 1;
    return NRF_TIMER0->CC[1];
}

static void radio_off(void) {
    NRF_RADIO->SHORTS    = 0;
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->TASKS_DISABLE   = 1;
    for (uint32_t i = 0; i < 2000 && !NRF_RADIO->EVENTS_DISABLED; i++) __NOP();
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->EVENTS_END      = 0;
}

static nrf_radio_signal_callback_return_param_t *radio_cb(uint8_t sig) {
    m_ret.callback_action = NRF_RADIO_SIGNAL_CALLBACK_ACTION_NONE;
    switch (sig) {
        case NRF_RADIO_CALLBACK_SIGNAL_TYPE_START: {
            m_st.slots++;
            radio_cfg();
            uint32_t budget = m_req.params.earliest.length_us - STOP_GUARD_US;
            while (!m_done && elapsed_us() < budget) {
                if (ping_ack((uint8_t)m_prefix, m_channels[m_ch_idx])) {
                    m_found[m_prefix >> 3] |= (uint8_t)(1u << (m_prefix & 7));
                    m_st.found_count++;
                    next_prefix();
                } else if (++m_ch_idx >= m_nch) {
                    next_prefix();                /* no channel ACKed: prefix absent */
                }
            }
            radio_off();
            if (m_run && !m_done) {
                fill_request();
                m_ret.params.request.p_next = &m_req;
                m_ret.callback_action       = NRF_RADIO_SIGNAL_CALLBACK_ACTION_REQUEST_AND_END;
            } else {
                m_ret.callback_action = NRF_RADIO_SIGNAL_CALLBACK_ACTION_END;
            }
            break;
        }
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
NRF_SDH_SOC_OBSERVER(m_esb_enum_obs, 0, soc_evt, NULL);

void esb_enum_radio_poll(void) {
    if (!m_rereq) return;
    m_rereq = false;
    if (!m_run || !m_open) return;
    fill_request();
    m_st.last_rc = sd_radio_request(&m_req);
}

bool esb_enum_radio_start(const uint8_t base[4],
                          const uint8_t *channels, uint8_t n_ch,
                          bool bitrate_2mbit, uint8_t prefix_lo, uint8_t prefix_hi) {
    if (m_open || base == NULL || channels == NULL) return false;
    if (n_ch == 0 || n_ch > ESB_ENUM_MAX_CHANNELS || prefix_lo > prefix_hi) return false;
    memset((void *)&m_st, 0, sizeof(m_st));
    memset(m_found, 0, sizeof(m_found));
    memcpy(m_base, base, 4);
    m_2mbit = bitrate_2mbit;
    for (uint8_t i = 0; i < n_ch; i++) {
        if (channels[i] > 100) return false;
        m_channels[i] = channels[i];
    }
    m_nch   = n_ch;
    m_plo   = prefix_lo;
    m_phi   = prefix_hi;
    m_prefix = prefix_lo;
    m_ch_idx = 0;
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

bool esb_enum_radio_running(void) { return m_run; }
bool esb_enum_radio_done(void)    { return m_done; }

void esb_enum_radio_stop(void) {
    m_run = false;
    if (m_open) (void)sd_radio_session_close();
}

void esb_enum_radio_get_stats(esb_enum_stats_t *out) {
    *out = *(const esb_enum_stats_t *)&m_st;
    out->slot_us = m_slot_us;
}

void esb_enum_radio_get_found(uint8_t bitmap[32]) {
    memcpy(bitmap, m_found, 32);
}
