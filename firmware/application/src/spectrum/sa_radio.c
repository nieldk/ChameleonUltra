/*
 * sa_radio.c - one-shot 2.4 GHz ISM energy-detect sweep (1 MHz steps, caller
 * picks the start/count within 2400-2483 MHz) in chained SoftDevice timeslots.
 *
 * Unlike zb_radio.c this never receives a packet -- each point is just
 * RXEN + one energy-detect sample at a directly-set RADIO->FREQUENCY (no
 * 802.15.4 channel numbering, no PCNF0/1/CRCCNF, no PACKETPTR). That means a
 * whole batch of points can be swept synchronously inside the timeslot
 * START callback itself and the result returned immediately
 * (REQUEST_AND_END or END) -- no RADIO/TIMER0 signal handling needed at all.
 *
 * Nordic's IEEE 802.15.4 ED value (EDSAMPLE) is used as a raw, uncalibrated
 * busy/quiet indicator across the whole band; see zb_radio.c's status docs
 * for the same caveat (not dBm, not temperature-compensated).
 */

#include "sa_radio.h"

#include <string.h>

#include "nrf.h"
#include "nrf_sdh_soc.h"
#include "nrf_soc.h"

#define SLOT_US         50000u
#define SLOT_MIN_US     5000u
#define TIMEOUT_US      200000u
#define POINTS_PER_SLOT 12u     /* budget per timeslot; see module doc for the estimate */

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
    NRF_RADIO->FREQUENCY = i;                 /* FREQUENCY reg == MHz above 2400 */
    NRF_RADIO->EVENTS_READY = 0;
    NRF_RADIO->TASKS_RXEN = 1;
    for (uint32_t w = 0; w < 4000 && !NRF_RADIO->EVENTS_READY; w++) __NOP();

    NRF_RADIO->EVENTS_EDEND = 0;
    NRF_RADIO->TASKS_EDSTART = 1;
    uint8_t v = 0;
    for (uint32_t w = 0; w < 20000 && !NRF_RADIO->EVENTS_EDEND; w++) __NOP();
    if (NRF_RADIO->EVENTS_EDEND) {
        v = (uint8_t)NRF_RADIO->EDSAMPLE;
    } else {
        NRF_RADIO->TASKS_EDSTOP = 1;
    }
    NRF_RADIO->EVENTS_EDEND = 0;
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
    uint16_t end = m_idx + POINTS_PER_SLOT;
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
