/*
 * esb_tx_radio.c - transmit (inject) Nordic proprietary-PHY (Enhanced
 * ShockBurst framed) packets as a PTX on a known 5-byte address, in chained
 * SoftDevice timeslots. The transmit counterpart of esb_radio.c.
 *
 * Timeslot mechanics (session, chained slots, TIMER0 slot-end guard, re-request
 * on BLOCKED/CANCELED) are identical to esb_radio.c / zb_radio.c -- see those
 * files. PCNF0/PCNF1/CRCCNF and addr_conv are carried over unchanged from
 * esb_radio.c, which took them from Nordic's own ESB source (nrf_esb.c /
 * Zephyr esb.c). Only the differences for TX are commented here:
 *
 *   - PCNF0 adds S1INCL=Include so the 3-bit S1 field (2-bit PID + 1-bit
 *     no_ack) is read from RAM. esb_radio.c's RX path leaves S1INCL at the
 *     default (exclude) because it discards PCF on receive; to TRANSMIT a
 *     correct PCF the PID/no_ack must come from RAM, so the TX RAM layout is
 *     [LENGTH][S1][payload] (one extra byte versus the RX [LENGTH][payload]).
 *   - PID increments per logical frame (not per channel repeat), so a receiver
 *     dedupes the sweep repeats of one frame but still processes the next
 *     distinct frame. no_ack=0: the receiver ACKs and processes the frame.
 *   - TXADDRESS=0, SHORTS = TXREADY_START | END_DISABLE (ramp up, auto-start,
 *     send, auto-disable). We do not turn around to RX for the ACK in this v1;
 *     a frame is injected redundantly across every channel in the sweep so it
 *     lands wherever the receiver is hopping. ACK-confirmed early-stop is a
 *     documented follow-up (needs DISABLED_RXEN + a CRCOK check within the
 *     ~250 us retransmit window).
 *
 * UNVERIFIED on hardware here (no nRF build/flash in this environment, same
 * caveat esb_radio.c carries): the TX ramp/one-shot timing, that S1INCL frames
 * the PCF the Logitech receiver expects, and the per-channel/per-frame pacing.
 * Stats below are deliberately fine-grained so a bench log shows which step
 * works. Bitrate, channel set, gap and TX power are runtime config, not facts.
 */

#include "esb_tx_radio.h"

#include <string.h>

#include "nrf.h"
#include "nrf_sdh_soc.h"
#include "nrf_soc.h"

#define SLOT_US        50000u
#define SLOT_MIN_US    5000u
#define TIMEOUT_US     200000u
#define STOP_GUARD_US  2000u
#define TX_SPIN_MAX    20000u       /* bounded wait for EVENTS_END after TXEN */
#define PER_CH_US      600u         /* gap between channels of one frame's sweep */

static nrf_radio_request_t                      m_req;
static nrf_radio_signal_callback_return_param_t m_ret;
static volatile bool    m_run;
static volatile bool    m_open;
static volatile bool    m_done;

static uint8_t  m_addr[5];
static bool     m_2mbit = true;
static uint8_t  m_gap_ms = 8;
static uint8_t  m_repeat = 1;

static uint8_t  m_channels[ESB_TX_MAX_CHANNELS];
static uint8_t  m_nch;

static uint8_t  m_frames[ESB_TX_MAX_FRAMES][ESB_MAX_PAYLOAD];
static uint8_t  m_flen[ESB_TX_MAX_FRAMES];
static uint8_t  m_fcount;

/* progress cursors: current repeat, frame, channel-in-sweep */
static uint8_t  m_rep, m_fi, m_ci;

static uint8_t  m_txpkt[2 + ESB_MAX_PAYLOAD];   /* [LENGTH][S1][payload] */
static volatile esb_tx_stats_t m_st;
static volatile bool     m_rereq;
static volatile uint32_t m_slot_us = SLOT_US;

static void fill_request(void) {
    m_req.request_type               = NRF_RADIO_REQ_TYPE_EARLIEST;
    m_req.params.earliest.hfclk      = NRF_RADIO_HFCLK_CFG_XTAL_GUARANTEED;
    m_req.params.earliest.priority   = NRF_RADIO_PRIORITY_NORMAL;
    m_req.params.earliest.length_us  = m_slot_us;
    m_req.params.earliest.timeout_us = TIMEOUT_US;
}

/* Identical to esb_radio.c addr_conv: bit-reverse each byte, then reverse byte
 * order, for BASE0/PREFIX0. */
static uint32_t addr_conv(uint32_t inp) {
    inp = (inp & 0xF0F0F0F0UL) >> 4 | (inp & 0x0F0F0F0FUL) << 4;
    inp = (inp & 0xCCCCCCCCUL) >> 2 | (inp & 0x33333333UL) << 2;
    inp = (inp & 0xAAAAAAAAUL) >> 1 | (inp & 0x55555555UL) << 1;
    return __REV(inp);
}

/* Static radio config for the slot (address, framing, CRC). Frequency and
 * payload are set per frame in tx_one(). */
static void radio_tx_config(void) {
    NRF_RADIO->POWER = 1;
    NRF_RADIO->MODE  = (m_2mbit ? RADIO_MODE_MODE_Nrf_2Mbit : RADIO_MODE_MODE_Nrf_1Mbit)
                        << RADIO_MODE_MODE_Pos;
    NRF_RADIO->PCNF0 = (0UL << RADIO_PCNF0_S0LEN_Pos) |
                       (6UL << RADIO_PCNF0_LFLEN_Pos) |
                       (3UL << RADIO_PCNF0_S1LEN_Pos) |
                       (RADIO_PCNF0_S1INCL_Include << RADIO_PCNF0_S1INCL_Pos);  /* drive PID/no_ack from RAM */
    NRF_RADIO->PCNF1 = (RADIO_PCNF1_WHITEEN_Disabled << RADIO_PCNF1_WHITEEN_Pos) |
                       (RADIO_PCNF1_ENDIAN_Big        << RADIO_PCNF1_ENDIAN_Pos) |
                       (4UL                           << RADIO_PCNF1_BALEN_Pos) |
                       (0UL                           << RADIO_PCNF1_STATLEN_Pos) |
                       (ESB_MAX_PAYLOAD               << RADIO_PCNF1_MAXLEN_Pos);
    NRF_RADIO->CRCCNF  = RADIO_CRCCNF_LEN_Two << RADIO_CRCCNF_LEN_Pos;
    NRF_RADIO->CRCPOLY = 0x11021UL;
    NRF_RADIO->CRCINIT = 0xFFFFUL;

    /* addr is base-first [base0..3, prefix], the order a capture shows it. */
    NRF_RADIO->BASE0   = addr_conv(((uint32_t)m_addr[0] << 24) | ((uint32_t)m_addr[1] << 16) |
                                    ((uint32_t)m_addr[2] << 8)  |  (uint32_t)m_addr[3]);
    /* addr_conv()'s __REV() is only correct for a 4-byte value (BASE0); for
     * a lone prefix byte it lands in bits[31:24] instead of AP0's bits[7:0].
     * Shift back down -- see esb_radio.c for the full explanation. */
    NRF_RADIO->PREFIX0 = addr_conv((uint32_t)m_addr[4]) >> 24;
    NRF_RADIO->TXADDRESS   = 0;                     /* transmit on pipe 0 */
    NRF_RADIO->TXPOWER     = RADIO_TXPOWER_TXPOWER_Pos8dBm << RADIO_TXPOWER_TXPOWER_Pos;
    NRF_RADIO->SHORTS      = RADIO_SHORTS_TXREADY_START_Msk | RADIO_SHORTS_END_DISABLE_Msk;
    NRF_RADIO->INTENCLR    = 0xFFFFFFFFUL;          /* polled, not IRQ-driven */
}

/* Stage one logical frame into m_txpkt with its PID, then transmit it on the
 * current channel and spin (bounded) for END. */
static void tx_one(uint8_t fi, uint8_t ch) {
    uint8_t pid = fi & 0x03u;                       /* 2-bit PID, per logical frame */
    m_txpkt[0] = m_flen[fi];                         /* LENGTH (6-bit field) */
    m_txpkt[1] = (uint8_t)(pid << 1);               /* S1: PID<<1 | no_ack(0) */
    memcpy(&m_txpkt[2], m_frames[fi], m_flen[fi]);

    NRF_RADIO->FREQUENCY = ch;
    NRF_RADIO->PACKETPTR = (uint32_t)m_txpkt;
    NRF_RADIO->EVENTS_END      = 0;
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->EVENTS_READY    = 0;

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

/* Advance (repeat, frame, channel) after one TX. Returns the next inter-step
 * gap in microseconds, or 0 when the whole job is done. */
static uint32_t advance(void) {
    m_ci++;
    if (m_ci < m_nch) return PER_CH_US;             /* same frame, next channel */
    m_ci = 0;
    m_st.frames_sent++;
    m_fi++;
    if (m_fi < m_fcount) return (uint32_t)m_gap_ms * 1000u;   /* next frame */
    m_fi = 0;
    m_st.sweeps++;
    m_rep++;
    if (m_rep < m_repeat) return (uint32_t)m_gap_ms * 1000u;  /* repeat the job */
    return 0;                                        /* done */
}

static void arm_step(uint32_t us) {
    uint32_t cc = m_req.params.earliest.length_us - STOP_GUARD_US;
    uint32_t t  = NRF_TIMER0->CC[1] + us;           /* schedule off the running slot timer */
    if (t >= cc) t = cc - 1;                        /* never past the slot-end guard */
    NRF_TIMER0->CC[1]             = t;
    NRF_TIMER0->EVENTS_COMPARE[1] = 0;
    NRF_TIMER0->INTENSET          = TIMER_INTENSET_COMPARE1_Msk;
}

static nrf_radio_signal_callback_return_param_t *radio_cb(uint8_t sig) {
    m_ret.callback_action = NRF_RADIO_SIGNAL_CALLBACK_ACTION_NONE;
    switch (sig) {
        case NRF_RADIO_CALLBACK_SIGNAL_TYPE_START:
            m_st.slots++;
            radio_tx_config();
            NRF_TIMER0->CC[0]             = m_req.params.earliest.length_us - STOP_GUARD_US;
            NRF_TIMER0->CC[1]             = 0;
            NRF_TIMER0->EVENTS_COMPARE[0] = 0;
            NRF_TIMER0->EVENTS_COMPARE[1] = 0;
            NRF_TIMER0->INTENSET          = TIMER_INTENSET_COMPARE0_Msk;
            NVIC_ClearPendingIRQ(TIMER0_IRQn);
            NVIC_EnableIRQ(TIMER0_IRQn);
            if (!m_done) arm_step(PER_CH_US);        /* first TX shortly after slot start */
            break;
        case NRF_RADIO_CALLBACK_SIGNAL_TYPE_TIMER0:
            if (NRF_TIMER0->EVENTS_COMPARE[1]) {
                NRF_TIMER0->EVENTS_COMPARE[1] = 0;
                if (!m_done) {
                    tx_one(m_fi, m_channels[m_ci]);
                    uint32_t gap = advance();
                    if (gap == 0) { m_done = true; m_run = false; }
                    else          { arm_step(gap); }
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
NRF_SDH_SOC_OBSERVER(m_esb_tx_obs, 0, soc_evt, NULL);

void esb_tx_radio_poll(void) {
    if (!m_rereq) return;
    m_rereq = false;
    if (!m_run || !m_open) return;
    fill_request();
    m_st.last_rc = sd_radio_request(&m_req);
}

bool esb_tx_radio_start(const uint8_t addr[5],
                        const uint8_t *frames, const uint16_t *lens, uint8_t count,
                        const uint8_t *channels, uint8_t n_ch,
                        bool bitrate_2mbit, uint8_t per_frame_gap_ms, uint8_t repeat) {
    if (m_open || addr == NULL || frames == NULL || lens == NULL || channels == NULL) return false;
    if (count == 0 || count > ESB_TX_MAX_FRAMES || n_ch == 0 || n_ch > ESB_TX_MAX_CHANNELS) return false;

    memset((void *)&m_st, 0, sizeof(m_st));
    memcpy(m_addr, addr, 5);
    m_2mbit  = bitrate_2mbit;
    m_gap_ms = per_frame_gap_ms ? per_frame_gap_ms : 8;
    m_repeat = repeat ? repeat : 1;

    size_t off = 0;
    for (uint8_t i = 0; i < count; i++) {
        uint16_t l = lens[i];
        if (l == 0 || l > ESB_MAX_PAYLOAD) return false;
        memcpy(m_frames[i], &frames[off], l);
        m_flen[i] = (uint8_t)l;
        off += l;
    }
    m_fcount = count;

    for (uint8_t i = 0; i < n_ch; i++) {
        if (channels[i] > 100) return false;
        m_channels[i] = channels[i];
    }
    m_nch = n_ch;

    m_rep = m_fi = m_ci = 0;
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

bool esb_tx_radio_running(void) { return m_run; }
bool esb_tx_radio_done(void)    { return m_done; }

void esb_tx_radio_stop(void) {
    m_run = false;
    if (m_open) (void)sd_radio_session_close();
}

void esb_tx_radio_get_stats(esb_tx_stats_t *out) {
    *out = *(const esb_tx_stats_t *)&m_st;
    out->slot_us = m_slot_us;
}
