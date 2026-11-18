// The interactive LF engine: downlink capture (C1), uplink modulation (C2), turnaround (C3) and the exchange loop
// (C6).
//
// Hardware it owns while a module is active:
// - SAADC on the field line (AIN0) at 100 kHz into a ring buffer. LF_MOD holds the load on while listening, because
//   with the load off the field line rails and a reader's gaps do not show. PPI restarts the buffer at its END, so
//   sampling never waits for an interrupt, and a TIMER3 compare starts it, so sample k is at exactly start + 10k µs
//   (the ADC's sample timer and TIMER3 both divide the 16 MHz clock). A TIMER3 tick reads the samples written so far.
// - TIMER3 at 1 MHz, free running: the time base.
// - PWM0 on LF_MOD at the 125 kHz base clock: one period per load run. A TIMER3 compare starts it through PPI, so the
//   answer's start does not depend on interrupt latency.
//
// The PWM and TIMER3 interrupts share one priority, so their handlers never preempt each other. The SAADC interrupt
// stays off.

#include <string.h>

#include "app_util_platform.h"
#include "ble_main.h"
#include "hw_connect.h"
#include "lf_ia.h"
#include "lf_ia_debug.h"
#include "lf_ia_trace.h"
#include "lf_tag_em.h"
#include "nrf_gpio.h"
#include "nrfx_lpcomp.h"
#include "nrfx_ppi.h"
#include "nrfx_pwm.h"
#include "nrf_saadc.h"
#include "nrfx_saadc.h"
#include "nrfx_timer.h"

#define NRF_LOG_MODULE_NAME lf_ia
#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();

#define SAMPLE_US     (10u)
#define SAADC_CC      (160u)  // 16 MHz / 160: 100 kHz
#define RING_N        (512u)  // 5.12 ms of samples: the longest a tick may be late before samples are overwritten
#define TICK_US       (160u)  // the step in which the engine sees a command's end
#define CONV_US       (20u)   // a sample is in RAM well within this after its time
#define SMOOTH_LAG_US (15)    // the 4-sample mean lags the field by 1.5 samples
#define FIELD_MIN     (200)   // ADC counts after smoothing: a field-on level at least this
#define RECHECK_US    (2000u) // with the load off, the field line's detector drains in about 2 ms
#define MAX_RUNS      (2u * LF_IA_MAX_RESPONSE_BITS)
#define PWM_TOP_MIN   (3u)    // the PWM's smallest counter top
#define SETTLE_MIN_US (40u)   // the 4-sample mean needs 3 samples of history before it means anything

#define CC_TX       NRF_TIMER_CC_CHANNEL0  // compare: starts the answer through PPI
#define CC_ADC_GO   NRF_TIMER_CC_CHANNEL0  // compare: the first ADC sample, through PPI, while listening
#define CC_TICK     NRF_TIMER_CC_CHANNEL1  // compare, with interrupt: the listen tick, or the field recheck
#define CC_ADC_END  NRF_TIMER_CC_CHANNEL2  // capture: each ADC ring wrap, to check the sample times
#define CC_TX_START NRF_TIMER_CC_CHANNEL3  // capture: the answer's first PWM period
#define CC_TX_END   NRF_TIMER_CC_CHANNEL4  // capture: the PWM's stop
#define CC_NOW      NRF_TIMER_CC_CHANNEL5  // capture: software reads of the time

typedef enum {
    ST_OFF,      // sense disabled
    ST_IDLE,     // waiting for the wake comparator
    ST_LISTEN,   // capturing a command
    ST_ANSWER,   // an answer is armed or playing
    ST_REST,     // holding the load off after an answer, so the reader sees the frame end, before listening
    ST_RECHECK,  // a gap ran past lost_us: waiting to check the field with the load off
} state_t;

static const nrfx_pwm_t m_ia_pwm = NRFX_PWM_INSTANCE(0);
static const nrfx_timer_t m_ia_timer = NRFX_TIMER_INSTANCE(3);

static const lf_ia_module_t *m_module;
static volatile state_t m_state = ST_OFF;
static bool m_ended;  // the module returned LF_IA_END: listen only for the field to drop
static lf_ia_trace_rec_t *m_off_rec;  // the FIELD_OFF record of the session that just ended, if it had one
static bool m_adc_on;

static nrf_ppi_channel_t m_ppi_adc_end, m_ppi_adc_restart, m_ppi_adc_go, m_ppi_tx, m_ppi_tx_start, m_ppi_tx_end;

static nrf_saadc_value_t m_ring[RING_N];
static nrf_pwm_values_wave_form_t m_pwm_vals[MAX_RUNS];
static nrf_pwm_sequence_t m_pwm_seq;
static uint16_t m_runs[MAX_RUNS];
static lf_ia_gap_t m_gaps[LF_IA_MAX_GAPS];
static uint32_t m_intervals[LF_IA_MAX_GAPS];
static uint8_t m_bits[LF_IA_MAX_BITS / 8];
static lf_ia_response_t m_rsp;

static lf_ia_tuning_t m_tuning = {
    // mfcarroll measured 2026-11-18: after the load comes back on, the field line is within 10% of its level
    // 45 to 121 us later and never dips, so 200 us is enough and frees 100 us of the reader's wait window.
    .settle_us = 200,
    .lost_us = 1500,
    .min_gap_us = 20,
    // 50 assumes a gap dips below half the field-on level. On this board's LF_RSSI coupling, a real reader's gaps
    // only reach ~72-79% of it, confirmed from an envelope capture; 85 catches them with headroom.
    .thr_pct = 85,
    .quiet_after_cmd = 1,
    .tx_lead_us = 0,
    .eof_us = 0,
    .rsp_delay_us = 0,
};

// The gap detector's state for one listen.
static struct {
    int32_t h1, h2, h3;  // the three raw samples before the current one
    int32_t prev_s;
    uint32_t prev_t;
    int32_t level;       // the tracked field-on level
    uint32_t settle_until;
    bool in_gap;
    uint32_t gap_start;
    uint32_t last_end;
    size_t n_gaps;
    bool dropped;
    uint16_t noise;
    uint32_t t0;         // the time of sample 0
    uint32_t k_done;     // samples processed
    uint32_t last_wrap;  // the ADC END capture last checked
} m_det;

static struct {
    int16_t s[LF_IA_ENV_SAMPLES];
    uint32_t head;  // samples written
    uint32_t last_us;
    bool armed;
    bool frozen;
} m_env;

static uint32_t now_us(void) {
    return nrfx_timer_capture(&m_ia_timer, CC_NOW);
}

static void load_set(bool on) {
    if (on) {
        nrf_gpio_pin_set(LF_MOD);
    } else {
        nrf_gpio_pin_clear(LF_MOD);
    }
}

static uint32_t eof_us(void) {
    return m_tuning.eof_us ? m_tuning.eof_us : m_module->eof_us;
}

// ---- C1: downlink capture -------------------------------------------------------------------------------------

static void det_reset(void) {
    memset(&m_det, 0, sizeof(m_det));
}

static void adc_listen_start(uint32_t settle_us) {
    nrf_saadc_int_disable(NRF_SAADC_INT_ALL);
    nrf_saadc_resolution_set(NRF_SAADC_RESOLUTION_14BIT);
    nrf_saadc_oversample_set(NRF_SAADC_OVERSAMPLE_DISABLED);
    nrf_saadc_channel_config_t ch = NRFX_SAADC_DEFAULT_CHANNEL_CONFIG_SE(NRF_SAADC_INPUT_AIN0);
    ch.acq_time = NRF_SAADC_ACQTIME_5US;
    nrf_saadc_channel_init(0, &ch);
    nrf_saadc_enable();
    nrf_saadc_buffer_init(m_ring, RING_N);
    nrf_saadc_continuous_mode_enable(SAADC_CC);
    nrf_saadc_event_clear(NRF_SAADC_EVENT_STARTED);
    nrf_saadc_event_clear(NRF_SAADC_EVENT_END);
    nrf_saadc_task_trigger(NRF_SAADC_TASK_START);
    while (!nrf_saadc_event_check(NRF_SAADC_EVENT_STARTED)) {
    }
    APP_ERROR_CHECK(nrfx_ppi_channel_enable(m_ppi_adc_restart));

    det_reset();
    const uint32_t go = now_us() + 20u;
    m_det.t0 = go;
    m_det.last_wrap = nrfx_timer_capture_get(&m_ia_timer, CC_ADC_END);
    m_det.settle_until = go + (settle_us < SETTLE_MIN_US ? SETTLE_MIN_US : settle_us);
    nrf_timer_event_clear(m_ia_timer.p_reg, nrf_timer_compare_event_get(CC_ADC_GO));
    nrfx_timer_compare(&m_ia_timer, CC_ADC_GO, go, false);
    APP_ERROR_CHECK(nrfx_ppi_channel_enable(m_ppi_adc_go));
    nrfx_timer_compare(&m_ia_timer, CC_TICK, go + TICK_US, true);
    m_adc_on = true;
}

static void adc_listen_stop(void) {
    if (m_adc_on) {
        nrfx_timer_compare_int_disable(&m_ia_timer, CC_TICK);
        nrfx_ppi_channel_disable(m_ppi_adc_go);
        nrfx_ppi_channel_disable(m_ppi_adc_restart);
        nrf_saadc_continuous_mode_disable();
        nrf_saadc_event_clear(NRF_SAADC_EVENT_STOPPED);
        nrf_saadc_task_trigger(NRF_SAADC_TASK_STOP);
        for (int i = 0; i < 1000 && !nrf_saadc_event_check(NRF_SAADC_EVENT_STOPPED); i++) {
        }
        nrf_saadc_disable();
        m_adc_on = false;
    }
}

static void env_push(int32_t s, uint32_t t) {
    if (!m_env.frozen) {
        m_env.s[m_env.head % LF_IA_ENV_SAMPLES] = (int16_t)s;
        m_env.head++;
        m_env.last_us = t;
    }
}

// The time a straight line from (t0, s0) to (t1, s1) crosses thr.
static uint32_t cross_time(int32_t s0, int32_t s1, uint32_t t0, uint32_t t1, int32_t thr) {
    if (s0 == s1) {
        return t1;
    }
    return t0 + (uint32_t)((thr - s0) * (int32_t)(t1 - t0) / (s1 - s0));
}

// Feeds one sample taken at time t. Returns false if a gap has lasted past lost_us, which means the field has gone.
static bool det_sample(int32_t x, uint32_t t) {
    const int32_t s = (x + m_det.h1 + m_det.h2 + m_det.h3) / 4;
    m_det.h3 = m_det.h2;
    m_det.h2 = m_det.h1;
    m_det.h1 = x;
    env_push(s, t);

    if ((int32_t)(t - m_det.settle_until) < 0) {
        m_det.level = s;
        m_det.prev_s = s;
        m_det.prev_t = t;
        return true;
    }

    int32_t thr = m_det.level * m_tuning.thr_pct / 100;
    if (thr < FIELD_MIN / 2) {
        thr = FIELD_MIN / 2;
    }

    if (!m_det.in_gap) {
        if (s < thr) {
            m_det.in_gap = true;
            m_det.gap_start = cross_time(m_det.prev_s, s, m_det.prev_t, t, thr);
        } else {
            // Follow slow drift in the field-on level, for example as the CU moves.
            m_det.level += (s - m_det.level) / 32;
        }
    } else if (s >= thr) {
        m_det.in_gap = false;
        const uint32_t end = cross_time(m_det.prev_s, s, m_det.prev_t, t, thr);
        const uint32_t w = end - m_det.gap_start;
        if (w < m_tuning.min_gap_us) {
            m_det.noise++;
        } else {
            if (m_det.n_gaps < LF_IA_MAX_GAPS) {
                m_gaps[m_det.n_gaps].start_us = m_det.gap_start;
                m_gaps[m_det.n_gaps].width_us = (uint16_t)(w > UINT16_MAX ? UINT16_MAX : w);
                m_det.n_gaps++;
            } else {
                m_det.dropped = true;
            }
            m_det.last_end = end;
        }
    } else if (t - m_det.gap_start >= m_tuning.lost_us) {
        return false;
    }

    m_det.prev_s = s;
    m_det.prev_t = t;
    return true;
}

// ---- C3 and C6: the exchange --------------------------------------------------------------------------------------

static void listen(uint32_t settle_us) {
    load_set(true);
    m_state = ST_LISTEN;
    adc_listen_start(settle_us);
}

static void session_start(void) {
    m_ended = false;
    lf_ia_trace_session_start(now_us());
    if (m_module->field_on) {
        m_module->field_on(m_module->ctx);
    }
    listen(m_tuning.settle_us);
}

static void field_gone(uint32_t t) {
    adc_listen_stop();
    load_set(false);
    if (m_module->field_off) {
        m_module->field_off(m_module->ctx);
    }
    m_off_rec = lf_ia_trace_session_end(t, (uint16_t)m_det.level);

    m_state = ST_RECHECK;
    nrfx_timer_compare(&m_ia_timer, CC_TICK, now_us() + RECHECK_US, true);
}

// Builds the PWM sequence for the answer and arms TIMER3 to start it at end_us + delay_us. Returns false if the
// answer cannot be sent.
static bool arm_answer(const lf_ia_response_t *rsp, uint32_t end_us, lf_ia_trace_rec_t *r) {
    const size_t n = lf_ia_encode_runs(rsp->bits, rsp->n_bits, rsp->coding, rsp->bit_fc, rsp->coding_flags, m_runs,
                                       MAX_RUNS);
    r->n_runs = (uint16_t)n;
    r->n_tx_bits = (uint16_t)rsp->n_bits;
    memcpy(r->tx_bits, rsp->bits, sizeof(r->tx_bits) < sizeof(rsp->bits) ? sizeof(r->tx_bits) : sizeof(rsp->bits));
    if (n == 0) {
        r->flags |= LF_IA_TRF_ENCODE_FAILED;
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        const uint16_t len = LF_IA_RUN_LEN(m_runs[i]);
        if (len < PWM_TOP_MIN) {
            r->flags |= LF_IA_TRF_ENCODE_FAILED;
            return false;
        }
        // With bit 15 set the output is high from the period's start until the compare value, so a compare of len
        // holds the load for the whole run and 0 holds it off.
        m_pwm_vals[i].channel_0 = (uint16_t)(0x8000u | (LF_IA_RUN_IS_LOAD(m_runs[i]) ? len : 0u));
        m_pwm_vals[i].channel_1 = 0;
        m_pwm_vals[i].channel_2 = 0;
        m_pwm_vals[i].counter_top = len;
    }
    m_pwm_seq.values.p_wave_form = m_pwm_vals;
    m_pwm_seq.length = (uint16_t)(n * 4u);
    m_pwm_seq.repeats = 0;
    m_pwm_seq.end_delay = 0;

    // A count of 1 starts on SEQ1 and stops after it (nrfx plays odd counts from SEQ1).
    const uint32_t task = nrfx_pwm_simple_playback(&m_ia_pwm, &m_pwm_seq, 1,
                                                   NRFX_PWM_FLAG_STOP | NRFX_PWM_FLAG_START_VIA_TASK);
    APP_ERROR_CHECK(nrfx_ppi_channel_assign(m_ppi_tx, nrfx_timer_compare_event_address_get(&m_ia_timer, CC_TX), task));

    const uint32_t due = end_us + rsp->delay_us;
    const uint32_t fire = due - (uint32_t)(int32_t)m_tuning.tx_lead_us;
    nrf_timer_event_clear(m_ia_timer.p_reg, nrf_timer_compare_event_get(CC_TX));
    nrfx_timer_compare(&m_ia_timer, CC_TX, fire, false);
    APP_ERROR_CHECK(nrfx_ppi_channel_enable(m_ppi_tx));

    const uint32_t now = now_us();
    r->t_ready_us = now;
    r->t_due_us = due;
    // If the compare time has already passed, TIMER3 will not reach it for another 71 minutes: start now instead.
    if ((int32_t)(fire - now) <= 1 && !nrf_timer_event_check(m_ia_timer.p_reg, nrf_timer_compare_event_get(CC_TX))) {
        nrfx_ppi_channel_disable(m_ppi_tx);
        *(volatile uint32_t *)task = 1;
    }
    if ((int32_t)(due - now) < 0) {
        r->flags |= LF_IA_TRF_LATE;
        lf_ia_trace_stats()->late++;
    }
    return true;
}

static void command_end(uint32_t t_detect) {
    adc_listen_stop();
    if (m_env.armed) {
        m_env.frozen = true;
        m_env.armed = false;
    }

    const size_t n = m_det.n_gaps;
    if (m_ended) {
        listen(0);
        return;
    }
    if (m_tuning.quiet_after_cmd) {
        load_set(false);
    }
    m_state = ST_ANSWER;
    lf_ia_trace_stats()->commands++;

    lf_ia_trace_rec_t *r = lf_ia_trace_begin(LF_IA_TR_COMMAND);
    r->t_us = m_det.last_end;
    r->t_detect_us = t_detect;
    r->n_gaps = (uint16_t)n;
    r->level = (uint16_t)m_det.level;
    r->n_noise = m_det.noise;
    if (m_det.dropped) {
        r->flags |= LF_IA_TRF_GAPS_DROPPED;
    }
    for (size_t i = 0; i < n && i < LF_IA_TRACE_GAPS; i++) {
        r->gaps[i].start_us = (uint16_t)(m_gaps[i].start_us - m_gaps[0].start_us);
        r->gaps[i].width_us = m_gaps[i].width_us;
    }

    lf_ia_command_t cmd = {
        .gaps = m_gaps,
        .n_gaps = n,
        .end_us = m_det.last_end,
        .decode_status = LF_IA_DECODE_TOO_FEW,
        .bits = m_bits,
        .n_bits = 0,
    };
    uint32_t split = 0;
    if (m_module->want_decode && n >= 2) {
        for (size_t i = 0; i + 1 < n; i++) {
            m_intervals[i] = m_gaps[i + 1].start_us - m_gaps[i].start_us;
        }
        memset(m_bits, 0, sizeof(m_bits));
        cmd.decode_status = lf_ia_decode_intervals(m_intervals, n - 1, &m_module->decode, m_bits, LF_IA_MAX_BITS,
                                                   &cmd.n_bits, &split);
    }
    r->split = split;
    r->decode_status = (uint8_t)cmd.decode_status;
    r->n_bits = (uint16_t)cmd.n_bits;
    memcpy(r->bits, m_bits, sizeof(r->bits));

    memset(&m_rsp, 0, sizeof(m_rsp));
    const lf_ia_verdict_t v = m_module->on_command(m_module->ctx, &cmd, &m_rsp);
    r->verdict = (uint8_t)v;

    if (m_tuning.rsp_delay_us) {
        m_rsp.delay_us = m_tuning.rsp_delay_us;
    }
    const bool armed = v == LF_IA_RESPOND && arm_answer(&m_rsp, cmd.end_us, r);
    lf_ia_trace_commit();
    if (v == LF_IA_END) {
        m_ended = true;
    }
    if (!armed) {
        listen(m_tuning.settle_us);
    }
}

// Processes the samples written since the last tick, then checks for a command's end.
static void listen_tick(void) {
    const uint32_t t_in = now_us();
    nrfx_timer_compare(&m_ia_timer, CC_TICK, t_in + TICK_US, true);
    if (m_det.k_done == 0) {
        nrfx_ppi_channel_disable(m_ppi_adc_go);
    }

    // Each ring wrap's END should land one sample period after a multiple of RING_N samples. If not, the ring
    // restarted late and the sample times are off.
    const uint32_t wrap = nrfx_timer_capture_get(&m_ia_timer, CC_ADC_END);
    if (wrap != m_det.last_wrap) {
        m_det.last_wrap = wrap;
        const uint32_t r = (wrap - m_det.t0 + SAMPLE_US) % (RING_N * SAMPLE_US);
        if (r > CONV_US && r < RING_N * SAMPLE_US - CONV_US) {
            lf_ia_trace_stats()->buffer_slips++;
        }
    }

    const int32_t ready = (int32_t)(t_in - m_det.t0 - CONV_US);
    if (ready < 0) {
        return;
    }
    uint32_t k_end = (uint32_t)ready / SAMPLE_US + 1u;
    if (k_end - m_det.k_done > RING_N - TICK_US / SAMPLE_US) {
        lf_ia_trace_stats()->buffer_slips++;  // the tick was too late: skip what the ring has already overwritten
        m_det.k_done = k_end - (RING_N - TICK_US / SAMPLE_US);
    }
    lf_ia_trace_stats()->buffers++;

    for (uint32_t k = m_det.k_done; k < k_end; k++) {
        const uint32_t t = m_det.t0 + k * SAMPLE_US - SMOOTH_LAG_US;
        if (!det_sample(m_ring[k % RING_N], t)) {
            field_gone(t);
            return;
        }
    }
    m_det.k_done = k_end;

    const uint32_t t_last = m_det.t0 + (k_end - 1u) * SAMPLE_US - SMOOTH_LAG_US;
    if (m_det.n_gaps > 0 && !m_det.in_gap && t_last - m_det.last_end >= eof_us()) {
        command_end(t_in);
    }

    const uint32_t spent = now_us() - t_in;
    if (spent > lf_ia_trace_stats()->max_handler_us) {
        lf_ia_trace_stats()->max_handler_us = spent;
    }
}

// ---- C2: the answer's end -------------------------------------------------------------------------------------

static void pwm_handler(nrfx_pwm_evt_type_t ev) {
    if (ev != NRFX_PWM_EVT_STOPPED) {
        return;
    }
    nrfx_ppi_channel_disable(m_ppi_tx);
    lf_ia_trace_rec_t *r = lf_ia_trace_last();
    if (r && r->type == LF_IA_TR_COMMAND) {
        r->t_tx_us = nrfx_timer_capture_get(&m_ia_timer, CC_TX_START);
        r->t_tx_end_us = nrfx_timer_capture_get(&m_ia_timer, CC_TX_END);
    }
    lf_ia_trace_stats()->responses++;
    if (m_state == ST_ANSWER) {
        // Rest with the load off before listening, so the reader sees the frame end rather than taking the load's
        // immediate return for another bit (the cu-cu "no read" case). The rest is the module's rest_fc, else one bit.
        load_set(false);
        m_state = ST_REST;
        const uint32_t rest_fc = m_module->rest_fc ? m_module->rest_fc : m_rsp.bit_fc;
        nrfx_timer_compare(&m_ia_timer, CC_TICK, now_us() + rest_fc * LF_IA_US_PER_FC, true);
    }
}

static void timer_handler(nrf_timer_event_t ev, void *ctx) {
    if (ev != NRF_TIMER_EVENT_COMPARE1) {
        return;
    }
    if (m_state == ST_LISTEN) {
        listen_tick();
        return;
    }
    if (m_state == ST_REST) {
        // Rest done: the frame end has registered, resume listening with the load on.
        listen(m_tuning.settle_us);
        return;
    }
    nrfx_timer_compare_int_disable(&m_ia_timer, CC_TICK);
    if (m_state != ST_RECHECK) {
        return;
    }
    if (is_lf_field_exists()) {
        // The field came back, or never left: a reader that drops its field this long has reset the tag.
        if (m_off_rec) {
            m_off_rec->flags |= LF_IA_TRF_FIELD_BACK;
        }
        nrfx_lpcomp_disable();
        session_start();
        return;
    }
    m_state = ST_IDLE;
    lf_adc_release();
    lf_tag_em_ia_field_lost();
}

// ---- Set-up ---------------------------------------------------------------------------------------------------------

void lf_ia_set_module(const lf_ia_module_t *module) {
    m_module = module;
}

const lf_ia_module_t *lf_ia_get_module(void) {
    return m_module;
}

static void ppi_link(nrf_ppi_channel_t *ch, uint32_t event, uint32_t task) {
    APP_ERROR_CHECK(nrfx_ppi_channel_alloc(ch));
    if (event) {
        APP_ERROR_CHECK(nrfx_ppi_channel_assign(*ch, event, task));
        APP_ERROR_CHECK(nrfx_ppi_channel_enable(*ch));
    }
}

void lf_ia_sense_enable(void) {
    nrfx_timer_config_t tcfg = NRFX_TIMER_DEFAULT_CONFIG;
    tcfg.frequency = NRF_TIMER_FREQ_1MHz;
    tcfg.bit_width = NRF_TIMER_BIT_WIDTH_32;
    tcfg.mode = NRF_TIMER_MODE_TIMER;
    APP_ERROR_CHECK(nrfx_timer_init(&m_ia_timer, &tcfg, timer_handler));
    nrfx_timer_enable(&m_ia_timer);

    nrfx_pwm_config_t pcfg = NRFX_PWM_DEFAULT_CONFIG;
    pcfg.output_pins[0] = LF_MOD;
    for (uint8_t i = 1; i < NRF_PWM_CHANNEL_COUNT; i++) {
        pcfg.output_pins[i] = NRFX_PWM_PIN_NOT_USED;
    }
    pcfg.irq_priority = APP_IRQ_PRIORITY_LOW;
    pcfg.base_clock = NRF_PWM_CLK_125kHz;
    pcfg.count_mode = NRF_PWM_MODE_UP;
    pcfg.load_mode = NRF_PWM_LOAD_WAVE_FORM;
    pcfg.step_mode = NRF_PWM_STEP_AUTO;
    APP_ERROR_CHECK(nrfx_pwm_init(&m_ia_pwm, &pcfg, pwm_handler));

    ppi_link(&m_ppi_adc_end, nrf_saadc_event_address_get(NRF_SAADC_EVENT_END),
             nrfx_timer_capture_task_address_get(&m_ia_timer, CC_ADC_END));
    ppi_link(&m_ppi_tx_start, nrf_pwm_event_address_get(m_ia_pwm.p_registers, NRF_PWM_EVENT_SEQSTARTED1),
             nrfx_timer_capture_task_address_get(&m_ia_timer, CC_TX_START));
    ppi_link(&m_ppi_tx_end, nrf_pwm_event_address_get(m_ia_pwm.p_registers, NRF_PWM_EVENT_STOPPED),
             nrfx_timer_capture_task_address_get(&m_ia_timer, CC_TX_END));
    ppi_link(&m_ppi_adc_restart, nrf_saadc_event_address_get(NRF_SAADC_EVENT_END),
             nrf_saadc_task_address_get(NRF_SAADC_TASK_START));
    nrfx_ppi_channel_disable(m_ppi_adc_restart);
    ppi_link(&m_ppi_adc_go, nrfx_timer_compare_event_address_get(&m_ia_timer, CC_ADC_GO),
             nrf_saadc_task_address_get(NRF_SAADC_TASK_SAMPLE));
    nrfx_ppi_channel_disable(m_ppi_adc_go);
    ppi_link(&m_ppi_tx, 0, 0);  // assigned per answer

    load_set(false);
    m_state = ST_IDLE;
}

void lf_ia_sense_disable(void) {
    if (m_state == ST_OFF) {
        return;
    }
    const bool claimed = m_state != ST_IDLE;
    m_state = ST_OFF;
    adc_listen_stop();
    if (claimed) {
        lf_adc_release();
    }
    nrfx_pwm_uninit(&m_ia_pwm);
    nrfx_ppi_channel_free(m_ppi_adc_end);
    nrfx_ppi_channel_free(m_ppi_adc_restart);
    nrfx_ppi_channel_free(m_ppi_adc_go);
    nrfx_ppi_channel_free(m_ppi_tx);
    nrfx_ppi_channel_free(m_ppi_tx_start);
    nrfx_ppi_channel_free(m_ppi_tx_end);
    nrfx_timer_uninit(&m_ia_timer);
    load_set(false);
}

void lf_ia_field_detected(void) {
    if (m_state != ST_IDLE || m_module == NULL) {
        return;
    }
    lf_adc_claim();
    session_start();
}

// ---- Instrumentation ------------------------------------------------------------------------------------------------

lf_ia_tuning_t *lf_ia_tuning(void) {
    return &m_tuning;
}

const lf_ia_stats_t *lf_ia_stats(void) {
    return lf_ia_trace_stats();
}

void lf_ia_env_arm(void) {
    CRITICAL_REGION_ENTER();
    m_env.head = 0;
    m_env.frozen = false;
    m_env.armed = true;
    CRITICAL_REGION_EXIT();
}

size_t lf_ia_env_read(size_t offset, int16_t *out, size_t max, uint32_t *last_us, uint8_t *frozen) {
    size_t n = 0;
    CRITICAL_REGION_ENTER();
    const uint32_t kept = m_env.head < LF_IA_ENV_SAMPLES ? m_env.head : LF_IA_ENV_SAMPLES;
    const uint32_t oldest = m_env.head - kept;
    for (size_t i = offset; i < kept && n < max; i++, n++) {
        out[n] = m_env.s[(oldest + i) % LF_IA_ENV_SAMPLES];
    }
    *last_us = m_env.last_us;
    *frozen = m_env.frozen;
    CRITICAL_REGION_EXIT();
    return n;
}
