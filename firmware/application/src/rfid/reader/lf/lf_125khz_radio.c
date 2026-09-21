#include "lf_125khz_radio.h"

#include "lf_reader_data.h"
#include "nrf_gpio.h"
#include "nrfx_clock.h"
#include "nrfx_gpiote.h"
#include "nrfx_ppi.h"
#include "nrfx_pwm.h"
#include "nrfx_saadc.h"
#include "nrfx_timer.h"
#include "rfid_main.h"

static bool m_reader_inited = false;

/* Active carrier configuration; defaults to 125 kHz. */
static nrf_pwm_clk_t m_base_clock = (nrf_pwm_clk_t)NRF_PWM_CLK_500kHz;
static uint16_t m_top_value = 4;
nrfx_pwm_t m_pwm = NRFX_PWM_INSTANCE(0);
nrfx_timer_t m_pwm_timer_counter = NRFX_TIMER_INSTANCE(2);
nrf_ppi_channel_t m_pwm_saadc_sample_ppi_channel;
nrf_ppi_channel_t m_pwm_timer_count_ppi_channel;

// At present, only channel 1 is used, so only one channel can be configured
static nrf_pwm_values_individual_t m_lf_125khz_pwm_seq_val[] = {
    {2, 0, 0, 0},
};

nrf_pwm_sequence_t const m_lf_125khz_pwm_seq_obj = {
    .values.p_individual = m_lf_125khz_pwm_seq_val,
    .length = NRF_PWM_VALUES_LENGTH(m_lf_125khz_pwm_seq_val),
    .repeats = 0,
    .end_delay = 0
};

/**
 * LF reading card decrease along the trigger collection event
 */
static void lf_125khz_gpio_handler(nrfx_gpiote_pin_t pin, nrf_gpiote_polarity_t action) {
    // Directly transfer to the event
    gpio_int0_irq_handler();
}

// The LF collection decline is interrupted, and the GPIO is pulled down
// by default. The trigger method is triggering
static void gpiote_init(void) {
    nrfx_err_t err_code;

    nrfx_gpiote_in_config_t cfg = NRFX_GPIOTE_CONFIG_IN_SENSE_LOTOHI(false);
    err_code = nrfx_gpiote_in_init(LF_OA_OUT, &cfg, lf_125khz_gpio_handler);
    APP_ERROR_CHECK(err_code);
}

/**
 * Start the 125kHz broadcast
 */
void start_lf_125khz_radio(void) {
    nrfx_pwm_simple_playback(&m_pwm, &m_lf_125khz_pwm_seq_obj, 1, NRFX_PWM_FLAG_LOOP);
    TAG_FIELD_LED_ON();
}

/**
 * Close 125kHz RF broadcast
 */
void stop_lf_125khz_radio(void) {
    nrfx_pwm_stop(&m_pwm, true);
    TAG_FIELD_LED_OFF();
}

static void pwm_init(void) {
    nrfx_pwm_config_t config = NRFX_PWM_DEFAULT_CONFIG;
    config.output_pins[0] = LF_ANT_DRIVER | NRFX_PWM_PIN_INVERTED;
    for (uint8_t i = 1; i < NRF_PWM_CHANNEL_COUNT; i++) {
        config.output_pins[i] = NRFX_PWM_PIN_NOT_USED;
    }
    config.irq_priority = APP_IRQ_PRIORITY_LOW;
    config.base_clock = m_base_clock;
    config.count_mode = (nrf_pwm_mode_t)NRF_PWM_MODE_UP;
    config.top_value = m_top_value;
    config.load_mode = (nrf_pwm_dec_load_t)NRF_PWM_LOAD_INDIVIDUAL;
    config.step_mode = (nrf_pwm_dec_step_t)NRF_PWM_STEP_AUTO;

    nrfx_err_t err_code = nrfx_pwm_init(&m_pwm, &config, NULL);
    APP_ERROR_CHECK(err_code);
}

static void pwm_timer_counter_init(void) {
    nrfx_err_t err_code;

    nrfx_timer_config_t timer_cfg = NRFX_TIMER_DEFAULT_CONFIG;
    timer_cfg.mode = NRF_TIMER_MODE_COUNTER;

    err_code = nrfx_timer_init(&m_pwm_timer_counter, &timer_cfg, NULL);
    APP_ERROR_CHECK(err_code);
}

// trigger timer count task from pwm
static void pwm_timer_count_ppi_init(void) {
    nrfx_err_t err_code;

    err_code = nrfx_ppi_channel_alloc(&m_pwm_timer_count_ppi_channel);
    APP_ERROR_CHECK(err_code);

    err_code = nrfx_ppi_channel_assign(
                   m_pwm_timer_count_ppi_channel,
                   nrfx_pwm_event_address_get(&m_pwm, NRF_PWM_EVENT_PWMPERIODEND),
                   nrfx_timer_task_address_get(&m_pwm_timer_counter, NRF_TIMER_TASK_COUNT));
    APP_ERROR_CHECK(err_code);
}

// trigger saadc sample task from pwm
static void pwm_saadc_sample_ppi_init(void) {
    nrfx_err_t err_code;

    err_code = nrfx_ppi_channel_alloc(&m_pwm_saadc_sample_ppi_channel);
    APP_ERROR_CHECK(err_code);

    err_code = nrfx_ppi_channel_assign(
                   m_pwm_saadc_sample_ppi_channel,
                   nrfx_pwm_event_address_get(&m_pwm, NRF_PWM_EVENT_PWMPERIODEND),
                   nrf_saadc_task_address_get(NRF_SAADC_TASK_SAMPLE));
    APP_ERROR_CHECK(err_code);
}

void lf_125khz_radio_saadc_enable(lf_adc_callback_t cb) {
    register_lf_adc_callback(cb);

    nrfx_err_t err_code;
    err_code = nrfx_ppi_channel_enable(m_pwm_saadc_sample_ppi_channel);
    APP_ERROR_CHECK(err_code);
}

void lf_125khz_radio_saadc_disable(void) {
    nrfx_err_t err_code;
    err_code = nrfx_ppi_channel_disable(m_pwm_saadc_sample_ppi_channel);
    APP_ERROR_CHECK(err_code);

    unregister_lf_adc_callback();
}

/* --- 166.67 kHz SAADC capture (TIMER3-triggered, decoupled from the carrier) ---
 * Real Indala is PSK1 fc/2: the 125 kHz CARRIER phase is flipped per data bit
 * (the tuned LF antenna filters out the 62.5 kHz subcarrier). Sampling at
 * 166.667 kHz (16 MHz / 96) aliases the carrier to 41.67 kHz = DFT bin 2, which
 * psk166_correlate_iq() reads to recover per-bit phase. The normal reader path
 * samples at the 125 kHz carrier rate (PWM-PERIOD-END PPI), where fc/2 sits at
 * Nyquist and cannot be demodulated — hence this separate sample clock.
 * TIMER3 is otherwise unused; sdk_config has NRFX_TIMER3_ENABLED=1. */
static nrfx_timer_t      m_psk166_timer = NRFX_TIMER_INSTANCE(3);
static nrf_ppi_channel_t m_psk166_saadc_ppi;
static bool              m_psk166_inited = false;

static void psk166_capture_init(void) {
    if (m_psk166_inited) return;
    nrfx_err_t err_code;

    nrfx_timer_config_t cfg = NRFX_TIMER_DEFAULT_CONFIG;
    cfg.frequency = NRF_TIMER_FREQ_16MHz;
    cfg.mode      = NRF_TIMER_MODE_TIMER;
    cfg.bit_width = NRF_TIMER_BIT_WIDTH_16;
    err_code = nrfx_timer_init(&m_psk166_timer, &cfg, NULL);
    APP_ERROR_CHECK(err_code);

    /* 16 MHz / 96 = 166.667 kHz, auto-clear on compare. */
    nrfx_timer_extended_compare(&m_psk166_timer, NRF_TIMER_CC_CHANNEL0, 96,
                                NRF_TIMER_SHORT_COMPARE0_CLEAR_MASK, false);

    err_code = nrfx_ppi_channel_alloc(&m_psk166_saadc_ppi);
    APP_ERROR_CHECK(err_code);
    err_code = nrfx_ppi_channel_assign(
                   m_psk166_saadc_ppi,
                   nrfx_timer_event_address_get(&m_psk166_timer, NRF_TIMER_EVENT_COMPARE0),
                   nrf_saadc_task_address_get(NRF_SAADC_TASK_SAMPLE));
    APP_ERROR_CHECK(err_code);

    m_psk166_inited = true;
}

/* Enable 166.67 kHz sampling. The carrier PWM's own SAADC PPI stays disabled
 * (we never enable it on this path), so SAADC is triggered only by TIMER3. */
void lf_125khz_radio_saadc166_enable(lf_adc_callback_t cb) {
    register_lf_adc_callback(cb);
    psk166_capture_init();
    nrfx_err_t err_code = nrfx_ppi_channel_enable(m_psk166_saadc_ppi);
    APP_ERROR_CHECK(err_code);
    nrfx_timer_enable(&m_psk166_timer);
}

void lf_125khz_radio_saadc166_disable(void) {
    nrfx_timer_disable(&m_psk166_timer);
    nrfx_err_t err_code = nrfx_ppi_channel_disable(m_psk166_saadc_ppi);
    APP_ERROR_CHECK(err_code);
    unregister_lf_adc_callback();
}

void lf_125khz_radio_gpiote_enable(void) {
    nrfx_err_t err_code;
    err_code = nrfx_ppi_channel_enable(m_pwm_timer_count_ppi_channel);
    APP_ERROR_CHECK(err_code);

    gpiote_init();
    nrfx_timer_enable(&m_pwm_timer_counter);
    nrfx_gpiote_in_event_enable(LF_OA_OUT, true);
}

void lf_125khz_radio_gpiote_disable(void) {
    nrfx_gpiote_in_event_disable(LF_OA_OUT);
    nrfx_gpiote_in_uninit(LF_OA_OUT);
    nrfx_timer_disable(&m_pwm_timer_counter);

    nrfx_err_t err_code;
    err_code = nrfx_ppi_channel_disable(m_pwm_timer_count_ppi_channel);
    APP_ERROR_CHECK(err_code);
}

// init 125kHz signal PWM modulation (use gpiote for ASK & saadc for FSK)
void lf_125khz_radio_init(void) {
    if (!m_reader_inited) {
        pwm_init();
        pwm_timer_counter_init();
        pwm_timer_count_ppi_init();
        pwm_saadc_sample_ppi_init();
        m_reader_inited = true;
    }
}

// uninitialize
void lf_125khz_radio_uninit(void) {
    if (m_reader_inited) {
        nrfx_ppi_channel_free(m_pwm_saadc_sample_ppi_channel);
        nrfx_ppi_channel_free(m_pwm_timer_count_ppi_channel);
        nrfx_timer_uninit(&m_pwm_timer_counter);
        nrfx_pwm_uninit(&m_pwm);
        m_reader_inited = false;
    }
}

void lf_radio_set_carrier(lf_carrier_t carrier) {
    switch (carrier) {
        case LF_CARRIER_134KHZ:
            m_base_clock = (nrf_pwm_clk_t)NRF_PWM_CLK_16MHz;
            m_top_value = 119;
            m_lf_125khz_pwm_seq_val[0].channel_0 = 60;  /* ~50% duty */
            break;
        case LF_CARRIER_125KHZ:
        default:
            m_base_clock = (nrf_pwm_clk_t)NRF_PWM_CLK_500kHz;
            m_top_value = 4;
            m_lf_125khz_pwm_seq_val[0].channel_0 = 2;
            break;
    }
    if (m_reader_inited) {
        nrfx_pwm_uninit(&m_pwm);
        pwm_init();
    }
}
