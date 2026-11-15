#include "lf_xtal_counter.h"

#include "nrf_soc.h"
#include "timer1_lock.h"

static bool m_running = false;
static bool m_hfclk_lapsed = false;

static void latch_sample(lf_xtal_sample_t *out) {
    NRF_TIMER1->TASKS_CAPTURE[0] = 1;
    out->raw_ticks = NRF_TIMER1->CC[0];
    out->running = m_running;

    uint32_t hfclk_running = 0;
    sd_clock_hfclk_is_running(&hfclk_running);
    if (!hfclk_running) {
        m_hfclk_lapsed = true;
    }
    out->hfclk_lapsed = m_hfclk_lapsed;
}

lf_xtal_status_t lf_xtal_counter_start(void) {
    if (m_running) {
        return LF_XTAL_OK; // already running, idempotent restart is a no-op
    }
    if (!timer1_lock_try_acquire()) {
        return LF_XTAL_BUSY;
    }

    m_hfclk_lapsed = false;

    // Same request/poll pattern as lf_tag_em.c's lf_sense_enable(): SD
    // reference-counts HFXO requests, so holding ours here keeps the
    // crystal running for the whole measurement regardless of what else
    // the device does with HFXO in the meantime.
    sd_clock_hfclk_request();
    uint32_t hfclk_running = 0;
    while (!hfclk_running) {
        sd_clock_hfclk_is_running(&hfclk_running);
    }

    // Free-running 32-bit counter at the undivided 16 MHz PCLK16M (itself
    // derived from HFCLK) -- no PRESCALER division, for the finest tick
    // resolution. Wraps every ~268 s; callers must read more often than
    // that (see lf_xtal_counter.h).
    NRF_TIMER1->TASKS_STOP  = 1;
    NRF_TIMER1->MODE        = TIMER_MODE_MODE_Timer;
    NRF_TIMER1->BITMODE     = TIMER_BITMODE_BITMODE_32Bit;
    NRF_TIMER1->PRESCALER   = 0;
    NRF_TIMER1->TASKS_CLEAR = 1;
    NRF_TIMER1->TASKS_START = 1;

    m_running = true;
    return LF_XTAL_OK;
}

lf_xtal_status_t lf_xtal_counter_read(lf_xtal_sample_t *out) {
    if (!m_running) {
        return LF_XTAL_NOT_RUNNING;
    }
    latch_sample(out);
    return LF_XTAL_OK;
}

lf_xtal_status_t lf_xtal_counter_stop(lf_xtal_sample_t *out) {
    if (!m_running) {
        return LF_XTAL_NOT_RUNNING;
    }
    latch_sample(out); // final sample, taken before teardown
    NRF_TIMER1->TASKS_STOP = 1;
    sd_clock_hfclk_release();
    timer1_lock_release();
    m_running = false;
    out->running = false;
    return LF_XTAL_OK;
}
