#include "lf_rdr_ia.h"

#include <string.h>

#include "ble_main.h"
#include "bsp_delay.h"
#include "bsp_time.h"
#include "hw_connect.h"
#include "lf_125khz_radio.h"
#include "nrf_gpio.h"
#include "nrf_saadc.h"
#include "nrfx_saadc.h"
#include "timeslot.h"

#define NRF_LOG_MODULE_NAME lf_rdr_ia
#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();

#define SKIP_FC  (40u)  // carrier periods after the command, while the field recovers from the last gap

// Capture into the shared LF SAADC buffer (lf_adc_claim() uninits the SAADC,
// so it is idle for the whole transaction) instead of a buffer of our own.
static int16_t *m_cap;
static size_t m_cap_n;
static uint16_t m_runs[LF_RDR_MAX_RUNS];
static size_t m_runs_n;

static const lf_rdr_link_t *m_link;
static const uint8_t *m_tx;
static size_t m_tx_n;
static uint32_t m_power_up_us;
static volatile bool m_sent;

// The PWM's stop leaves LF_ANT_DRIVER to the GPIO, so the field is cut by driving the pin low (as lf_gap.c does).
static void field_off(void) {
    nrfx_pwm_stop(&m_pwm, true);
    nrf_gpio_cfg_output(LF_ANT_DRIVER);
    nrf_gpio_pin_clear(LF_ANT_DRIVER);
}

static void field_on(void) {
    nrf_gpio_pin_set(LF_ANT_DRIVER);
    start_lf_125khz_radio();
}

void lf_rdr_field(bool on) {
    if (on) {
        start_lf_125khz_radio();
    } else {
        stop_lf_125khz_radio();
    }
}

static void gap(uint32_t us) {
    field_off();
    const bool damp = (m_link->eof_gap & LF_RDR_DAMP_GAPS) != 0;
    if (damp) {
        nrf_gpio_pin_set(LF_MOD);
    }
    bsp_delay_us(us);
    if (damp) {
        nrf_gpio_pin_clear(LF_MOD);
    }
    field_on();
}

// Runs inside the timeslot: the command, then the capture's start.
static void send_cb(void) {
    const lf_rdr_link_t *l = m_link;
    if (l->eof_gap & LF_RDR_CAPTURE_COMMAND) {
        lf_125khz_radio_sample_link(true);
    }
    if (m_power_up_us) {
        field_on();
        bsp_delay_us(m_power_up_us);
    }
    for (size_t i = 0; i < m_tx_n; i++) {
        const uint32_t period = lf_ia_bit_get(m_tx, i) ? l->bit1_us : l->bit0_us;
        gap(l->gap_us);
        bsp_delay_us(period - l->gap_us);
    }
    if (l->eof_gap & 1u) {
        gap(l->gap_us);
    }
    bsp_delay_us(l->stop_us);
    if (!(l->eof_gap & LF_RDR_CAPTURE_COMMAND)) {
        lf_125khz_radio_sample_link(true);
    }
    m_sent = true;
}

static void adc_arm(size_t n) {
    lf_adc_claim();
    size_t cap = 0;
    m_cap = lf_adc_capture_buffer(&cap);
    nrf_saadc_int_disable(NRF_SAADC_INT_ALL);
    nrf_saadc_resolution_set(NRF_SAADC_RESOLUTION_14BIT);
    nrf_saadc_oversample_set(NRF_SAADC_OVERSAMPLE_DISABLED);
    nrf_saadc_continuous_mode_disable();
    nrf_saadc_channel_config_t ch = NRFX_SAADC_DEFAULT_CHANNEL_CONFIG_SE(NRF_SAADC_INPUT_AIN5);
    ch.acq_time = NRF_SAADC_ACQTIME_5US;
    nrf_saadc_channel_init(0, &ch);
    nrf_saadc_enable();
    nrf_saadc_buffer_init(m_cap, n);
    nrf_saadc_event_clear(NRF_SAADC_EVENT_STARTED);
    nrf_saadc_event_clear(NRF_SAADC_EVENT_END);
    nrf_saadc_task_trigger(NRF_SAADC_TASK_START);
    while (!nrf_saadc_event_check(NRF_SAADC_EVENT_STARTED)) {
    }
}

static void adc_release(void) {
    lf_125khz_radio_sample_link(false);
    nrf_saadc_event_clear(NRF_SAADC_EVENT_STOPPED);
    nrf_saadc_task_trigger(NRF_SAADC_TASK_STOP);
    for (int i = 0; i < 1000 && !nrf_saadc_event_check(NRF_SAADC_EVENT_STOPPED); i++) {
    }
    nrf_saadc_disable();
    lf_adc_release();
}

bool lf_rdr_transact(const lf_rdr_link_t *link, const uint8_t *tx, size_t n_tx, uint32_t power_up_us,
                     lf_rdr_reply_t *rx) {
    memset(rx, 0, sizeof(*rx));
    const size_t n = link->capture_n;
    if (n_tx > LF_RDR_MAX_TX_BITS || n < 64 || n > LF_RDR_CAPTURE_MAX || link->bit_fc < 2 ||
        link->gap_us >= link->bit0_us || link->gap_us >= link->bit1_us) {
        return false;
    }

    // Each gap's PWM stop and restart adds about 14 µs to its bit, so a long command overran a slot sized from the
    // nominal periods. When the slot ran out during the stop, the SoftDevice's return disturbed the field, and a tag
    // read two extra bits after a 32-bit command. Budget 40 µs a bit, and a larger margin.
    uint32_t slot_us = power_up_us + link->stop_us + link->gap_us + 1000u;
    for (size_t i = 0; i < n_tx; i++) {
        slot_us += (lf_ia_bit_get(tx, i) ? link->bit1_us : link->bit0_us) + 40u;
    }

    adc_arm(n);
    m_link = link;
    m_tx = tx;
    m_tx_n = n_tx;
    m_power_up_us = power_up_us;
    m_sent = false;
    request_timeslot(slot_us, send_cb);

    // The capture runs one sample per carrier period from the command's end.
    bool done = false;
    autotimer *p_at = bsp_obtain_timer(0);
    while (NO_TIMEOUT_1MS(p_at, 50u + (uint32_t)(slot_us / 1000u) + (uint32_t)(n * 8u / 1000u))) {
        if (m_sent && nrf_saadc_event_check(NRF_SAADC_EVENT_END)) {
            done = true;
            break;
        }
    }
    bsp_return_timer(p_at);
    m_cap_n = done ? n : 0;
    adc_release();
    if (!done) {
        return false;
    }

    const uint16_t half = link->bit_fc / 2u;
    const size_t window = link->window_us / 8u;
    m_runs_n = lf_ia_envelope_runs(m_cap, n, SKIP_FC, window > SKIP_FC ? window : SKIP_FC + 1u, link->min_depth,
                                   link->slice_pct ? link->slice_pct : 50u,
                                   half, (uint16_t)(3u * half), m_runs, LF_RDR_MAX_RUNS, &rx->env);
    rx->n_runs = m_runs_n;
    rx->n_bits = lf_ia_decode_runs_ex(m_runs, m_runs_n, (lf_ia_coding_t)link->coding, link->bit_fc,
                                      link->coding_flags, rx->bits, LF_RDR_MAX_RX_BITS, &rx->clean);
    return true;
}

const int16_t *lf_rdr_capture(size_t *n) {
    *n = m_cap_n;
    return m_cap;
}

const uint16_t *lf_rdr_runs(size_t *n) {
    *n = m_runs_n;
    return m_runs;
}
