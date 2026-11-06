/*
 * sa_radio.c - one-shot 2.4 GHz ISM energy-detect sweep (1 MHz steps, caller
 * picks the start/count within 2400-2483 MHz) in chained SoftDevice timeslots.
 *
 * Unlike zb_radio.c this never receives a packet -- each point is just
 * RXEN + one or more energy-detect samples at a directly-set RADIO->FREQUENCY
 * (no 802.15.4 channel numbering, no PACKETPTR). PCNF0/1/CRCCNF/SFD/MODECNF0
 * are still set every point, matching zb_radio.c's proven-working ED config --
 * see sample_point(). That means a whole batch of points can be swept
 * synchronously inside the timeslot START callback itself and the result
 * returned immediately (REQUEST_AND_END or END) -- no RADIO/TIMER0 signal
 * handling needed at all.
 *
 * Nordic's IEEE 802.15.4 ED value (EDSAMPLE) is used as a raw, uncalibrated
 * busy/quiet indicator across the whole band; see zb_radio.c's status docs
 * for the same caveat (not dBm, not temperature-compensated).
 *
 * A single ED sample is one brief fixed-duration measurement -- a default
 * full-band sweep (84 points, repeat=1) completes in well under 50ms total,
 * so it's effectively an instantaneous snapshot and can miss anything
 * intermittent (WiFi beacon interval, hopping BT, bursty traffic) that just
 * isn't transmitting during that instant. sa_radio_set_repeat() trades sweep
 * time for a peak-hold over several ED cycles per point, improving the odds
 * of catching a burst at the cost of a slower sweep; points_per_slot() keeps
 * each timeslot's total busy time under budget as repeat grows.
 */

#include "sa_radio.h"

#include <string.h>

#include "nrf.h"
#include "nrf_delay.h"
#include "nrf_sdh_soc.h"
#include "nrf_soc.h"

#define SLOT_US         50000u
#define SLOT_MIN_US     5000u
#define TIMEOUT_US      200000u
#define POINTS_PER_SLOT  12u    /* safe point budget per timeslot at repeat=1 */
#define ED_CYCLE_US      150u   /* ~one EDSTART->EDEND round trip (8-symbol ED window) */
#define POINT_FIXED_US   400u   /* ramp + settle + disable, excluding ED cycles */
#define SLOT_BUDGET_US   30000u /* stay well under SLOT_US with margin for scheduling jitter */

static uint8_t m_repeat = 1;    /* ED samples per point, peak-hold -- see sa_radio_set_repeat() */

/* Points-per-slot shrinks as repeat grows so a slot with many ED cycles per
 * point still finishes comfortably inside SLOT_US; the sample loop below has
 * no mid-slot time check, so this has to hold up front. Capped at the old
 * fixed budget for repeat=1 -- unchanged behavior there. */
static uint16_t points_per_slot(void) {
    uint32_t per_point = POINT_FIXED_US + (uint32_t)m_repeat * ED_CYCLE_US;
    uint32_t n = SLOT_BUDGET_US / per_point;
    if (n < 1) n = 1;
    if (n > POINTS_PER_SLOT) n = POINTS_PER_SLOT;
    return (uint16_t)n;
}

static nrf_radio_request_t                      m_req;
static nrf_radio_signal_callback_return_param_t m_ret;
static volatile bool     m_run;
static volatile bool     m_open;
static volatile uint32_t m_slot_us = SLOT_US;
static uint8_t           m_result[SA_POINT_COUNT];
static volatile uint16_t m_idx;         /* next point to sample, absolute (0-83) */
static volatile uint16_t m_start;       /* first point of this sweep, absolute */
static volatile uint16_t m_end;         /* one past the last point, absolute */
static volatile bool     m_done;
static volatile bool     m_rereq;
static volatile sa_stats_t m_st;

static void fill_request(void) {
    m_req.request_type               = NRF_RADIO_REQ_TYPE_EARLIEST;
    m_req.params.earliest.hfclk      = NRF_RADIO_HFCLK_CFG_XTAL_GUARANTEED;
    m_req.params.earliest.priority   = NRF_RADIO_PRIORITY_NORMAL;
    m_req.params.earliest.length_us  = m_slot_us;
    m_req.params.earliest.timeout_us = TIMEOUT_US;
}

/* One point: tune, ramp up, energy-detect, record. Busy-waits (bounded) --
 * runs in the timeslot signal callback, same pattern as zb_radio.c. */
static void sample_point(uint16_t i) {
    NRF_RADIO->POWER     = 1;
    NRF_RADIO->MODE      = RADIO_MODE_MODE_Ieee802154_250Kbit << RADIO_MODE_MODE_Pos;
    /* Not used for anything (no packet is ever received here, no PACKETPTR,
     * no SHORTS past RXIDLE) -- but zb_radio.c, the only other ED user on
     * this hardware, sets exactly this before RXEN and reads real nonzero
     * EDSAMPLE values; this file set none of it and read 0 on every point,
     * busy-waits included, across the whole band. No documented reason ED
     * should care about packet format, but matching the known-good
     * configuration is the fastest way to find out. */
    NRF_RADIO->PCNF0     = (8UL << RADIO_PCNF0_LFLEN_Pos) |
                           (RADIO_PCNF0_PLEN_32bitZero << RADIO_PCNF0_PLEN_Pos) |
                           (RADIO_PCNF0_CRCINC_Include << RADIO_PCNF0_CRCINC_Pos);
    NRF_RADIO->PCNF1     = (127UL << RADIO_PCNF1_MAXLEN_Pos);
    NRF_RADIO->CRCCNF    = (RADIO_CRCCNF_LEN_Two << RADIO_CRCCNF_LEN_Pos) |
                           (RADIO_CRCCNF_SKIPADDR_Ieee802154 << RADIO_CRCCNF_SKIPADDR_Pos);
    NRF_RADIO->CRCPOLY   = 0x11021UL;
    NRF_RADIO->CRCINIT   = 0;
    NRF_RADIO->SFD       = 0xA7UL;
    NRF_RADIO->MODECNF0  = (RADIO_MODECNF0_RU_Fast << RADIO_MODECNF0_RU_Pos) |
                           (RADIO_MODECNF0_DTX_Center << RADIO_MODECNF0_DTX_Pos);
    NRF_RADIO->FREQUENCY = i;                 /* FREQUENCY reg == MHz above 2400 */
    NRF_RADIO->EVENTS_READY = 0;
    NRF_RADIO->TASKS_RXEN = 1;
    for (uint32_t w = 0; w < 4000 && !NRF_RADIO->EVENTS_READY; w++) __NOP();
    if (NRF_RADIO->EVENTS_READY) m_st.ready_ok++; else m_st.ready_timeout++;

    /* zb_radio.c's ED always runs after the radio has already been actively
     * receiving for most of a (5-50ms) slot; this fires EDSTART within
     * microseconds of READY, with no settle time for AGC/DC-offset
     * correction to converge. Untested hypothesis, cheap to try: give the
     * front end some time to settle before trusting the reading. */
    nrf_delay_us(250);

    /* Peak-hold over m_repeat EDSTART/EDEND cycles (default 1 == old behavior).
     * A single ED sample is a brief, fixed-duration hardware measurement -- an
     * intermittent emitter (WiFi beacon interval, hopping BT, bursty sensor)
     * can easily sit between samples on a one-shot sweep. Repeating here and
     * keeping the max catches a burst that happens any time during the dwell
     * instead of only the instant of a single sample. Stays in RXIDLE between
     * cycles (EDEND returns there), no re-ramp needed. */
    uint8_t v = 0;
    for (uint8_t r = 0; r < m_repeat; r++) {
        NRF_RADIO->EVENTS_EDEND = 0;
        NRF_RADIO->TASKS_EDSTART = 1;
        for (uint32_t w = 0; w < 20000 && !NRF_RADIO->EVENTS_EDEND; w++) __NOP();
        if (NRF_RADIO->EVENTS_EDEND) {
            m_st.ed_ok++;
            uint8_t sample = (uint8_t)NRF_RADIO->EDSAMPLE;
            if (sample > v) v = sample;
        } else {
            m_st.ed_timeout++;
            NRF_RADIO->TASKS_EDSTOP = 1;
        }
        NRF_RADIO->EVENTS_EDEND = 0;
    }
    m_result[i] = v;

    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->TASKS_DISABLE = 1;
    for (uint32_t w = 0; w < 2000 && !NRF_RADIO->EVENTS_DISABLED; w++) __NOP();
    NRF_RADIO->EVENTS_DISABLED = 0;
}

static nrf_radio_signal_callback_return_param_t *radio_cb(uint8_t sig) {
    m_ret.callback_action = NRF_RADIO_SIGNAL_CALLBACK_ACTION_NONE;
    if (sig != NRF_RADIO_CALLBACK_SIGNAL_TYPE_START) return &m_ret;

    m_st.slots++;
    uint16_t end = m_idx + points_per_slot();
    if (end > m_end) end = m_end;
    for (uint16_t i = m_idx; i < end; i++) sample_point(i);
    m_idx = end;
    m_st.points_done = m_idx - m_start;

    if (m_idx >= m_end || !m_run) {
        m_done = (m_idx >= m_end);
        m_run = false;
        m_ret.callback_action = NRF_RADIO_SIGNAL_CALLBACK_ACTION_END;
    } else {
        fill_request();
        m_ret.params.request.p_next = &m_req;
        m_ret.callback_action       = NRF_RADIO_SIGNAL_CALLBACK_ACTION_REQUEST_AND_END;
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
            if (m_slot_us > SLOT_MIN_US) m_slot_us /= 2;
            m_rereq = true;
            break;
        case NRF_EVT_RADIO_SESSION_IDLE:
            if (!m_run) (void)sd_radio_session_close();
            break;
        case NRF_EVT_RADIO_SESSION_CLOSED:
            m_open = false;
            break;
        default:
            break;
    }
}
NRF_SDH_SOC_OBSERVER(m_sa_obs, 0, soc_evt, NULL);

void sa_radio_poll(void) {
    if (!m_rereq) return;
    m_rereq = false;
    if (!m_run || !m_open) return;
    fill_request();
    m_st.last_rc = sd_radio_request(&m_req);
}

bool sa_radio_sweep_start(uint16_t start_offset, uint16_t count) {
    if (m_open) {
        m_run = false;   /* let the in-progress session close; caller can retry */
        return false;
    }
    if (count == 0 || count > SA_POINT_COUNT || start_offset + count > SA_POINT_COUNT) {
        return false;
    }
    memset((void *)&m_st, 0, sizeof(m_st));
    memset(m_result, 0, sizeof(m_result));
    m_slot_us = SLOT_US;
    m_start = start_offset;
    m_end   = start_offset + count;
    m_idx   = m_start;
    m_done  = false;
    m_run   = true;
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

void sa_radio_set_repeat(uint8_t n) {
    if (n < 1) n = 1;
    if (n > 32) n = 32;
    m_repeat = n;
}

bool sa_radio_busy(void) { return m_run || m_open; }
bool sa_radio_done(void) { return m_done; }

void sa_radio_get_result(uint8_t *out, size_t out_max, size_t *count) {
    size_t n = m_idx - m_start;
    if (n > out_max) n = out_max;
    if (n > SA_POINT_COUNT) n = SA_POINT_COUNT;
    memcpy(out, &m_result[m_start], n);
    *count = n;
}

void sa_radio_get_range(uint16_t *start_offset, uint16_t *count) {
    *start_offset = m_start;
    *count        = m_end - m_start;
}

void sa_radio_get_stats(sa_stats_t *out) {
    *out = *(const sa_stats_t *)&m_st;
}
