/*
 * Edge logic analyser.
 * GPIOTE IN event -> PPI -> TIMER4 CAPTURE stamps each edge in hardware;
 * the GPIOTE handler only stores the stamp and the pin level.
 */
#include "logic_analyzer.h"

#if defined(PROJECT_CHAMELEON_ULTRA)

#include "hw_connect.h"
#include "nrf_gpio.h"
#include "nrfx_gpiote.h"
#include "nrfx_ppi.h"

static uint32_t m_ts[LOGIC_MAX_EVENTS];
static uint8_t  m_ev[LOGIC_MAX_EVENTS];
static volatile uint16_t m_count;
static volatile bool     m_overflow;
static volatile uint16_t m_calls;
static uint32_t          m_cc[LOGIC_MAX_CHANNELS];
static bool              m_running;
static uint8_t           m_nch;
static uint8_t           m_init_levels;
static uint32_t          m_pin[LOGIC_MAX_CHANNELS];
static uint32_t          m_saved_cnf[LOGIC_MAX_CHANNELS];
static nrf_ppi_channel_t m_ppi[LOGIC_MAX_CHANNELS];
static uint8_t           m_stage[LOGIC_MAX_CHANNELS]; /* 0 none, 1 gpiote, 2 +ppi, 3 hook */
static uint8_t           m_hook_ch[2];
static uint16_t          m_merge;
volatile uint8_t         g_logic_hook_mask;

static bool is_hook_src(uint8_t src) {
    return src == LOGIC_SRC_HF_CS || src == LOGIC_SRC_FIELD_LED;
}

static uint32_t hook_pin(uint8_t src) {
    return src == LOGIC_SRC_HF_CS ? HF_SPI_SELECT : LED_FIELD;
}

static bool resolve_pin(uint8_t src, uint32_t *pin) {
    if (is_hook_src(src)) {
        *pin = hook_pin(src);
        return true;
    }
    if ((src & 0xC0) == LOGIC_SRC_RAW) {
        uint32_t p = src & 0x3F;
        if (nrf_gpio_pin_present_check(p)) {
            *pin = p;
            return true;
        }
    }
    return false;
}

static NRF_GPIO_Type *pin_port(uint32_t pin, uint32_t *idx) {
    *idx = pin;
    return nrf_gpio_pin_port_decode(idx);
}

static void store_event(uint8_t ch, uint32_t ts, uint8_t level) {
    uint16_t idx = __atomic_fetch_add(&m_count, 1, __ATOMIC_RELAXED);
    if (idx >= LOGIC_MAX_EVENTS) {
        m_count = LOGIC_MAX_EVENTS;
        m_overflow = true;
        return;
    }
    m_ts[idx] = ts;
    m_ev[idx] = (uint8_t)(ch | (level ? 0x80 : 0));
}

void logic_hook_slow(uint8_t src, uint8_t level) {
    uint8_t ch = m_hook_ch[src];
    m_calls++;
    NRF_TIMER4->TASKS_CAPTURE[ch] = 1;
    uint32_t ts = NRF_TIMER4->CC[ch];
    uint16_t n = m_count;
    /* fall within merge ticks of the last rise: drop both, line stays low */
    if (m_merge && !level && n && n <= LOGIC_MAX_EVENTS &&
        m_ev[n - 1] == (uint8_t)(ch | 0x80) && (ts - m_ts[n - 1]) < m_merge) {
        __atomic_fetch_sub(&m_count, 1, __ATOMIC_RELAXED);
        return;
    }
    store_event(ch, ts, level);
}

static void logic_evt(nrfx_gpiote_pin_t pin, nrf_gpiote_polarity_t action) {
    m_calls++;
    for (uint8_t i = 0; i < m_nch; i++) {
        if (m_stage[i] == 2 && m_pin[i] == pin) {
            store_event(i, NRF_TIMER4->CC[i], nrf_gpio_pin_read(pin));
            return;
        }
    }
}

void logic_stop(void) {
    if (m_running) {
        for (uint8_t i = 0; i < m_nch; i++) {
            m_cc[i] = NRF_TIMER4->CC[i];
        }
    }
    for (uint8_t i = 0; i < m_nch; i++) {
        if (m_stage[i] == 0) {
            continue;
        }
        if (m_stage[i] == 3) {
            g_logic_hook_mask = 0;
            m_stage[i] = 0;
            continue;
        }
        if (m_stage[i] == 2) {
            nrfx_gpiote_in_event_disable(m_pin[i]);
            nrfx_ppi_channel_disable(m_ppi[i]);
            nrfx_ppi_channel_free(m_ppi[i]);
        }
        nrfx_gpiote_in_uninit(m_pin[i]);
        /* uninit resets the pin to default; restore the owner's config */
        uint32_t idx;
        NRF_GPIO_Type *port = pin_port(m_pin[i], &idx);
        port->PIN_CNF[idx] = m_saved_cnf[i];
        m_stage[i] = 0;
    }
    NRF_TIMER4->TASKS_STOP = 1;
    m_running = false;
}

int logic_start(const uint8_t *src, uint8_t n, uint8_t prescaler, uint16_t merge_ticks) {
    if (m_running) {
        return LOGIC_ERR_BUSY;
    }
    if (n == 0 || n > LOGIC_MAX_CHANNELS || prescaler > 9) {
        return LOGIC_ERR_PARAM;
    }
    uint32_t pins[LOGIC_MAX_CHANNELS];
    for (uint8_t i = 0; i < n; i++) {
        if (!resolve_pin(src[i], &pins[i])) {
            return LOGIC_ERR_PARAM;
        }
    }

    m_nch = n;
    g_logic_hook_mask = 0;
    m_merge = merge_ticks;
    m_count = 0;
    m_calls = 0;
    m_overflow = false;
    m_init_levels = 0;
    for (uint8_t i = 0; i < n; i++) {
        m_cc[i] = 0;
        NRF_TIMER4->CC[i] = 0;
        m_pin[i] = pins[i];
        m_stage[i] = 0;
    }

    NRF_TIMER4->TASKS_STOP  = 1;
    NRF_TIMER4->MODE        = TIMER_MODE_MODE_Timer;
    NRF_TIMER4->BITMODE     = TIMER_BITMODE_BITMODE_32Bit;
    NRF_TIMER4->PRESCALER   = prescaler;
    NRF_TIMER4->TASKS_CLEAR = 1;

    nrfx_gpiote_in_config_t cfg = NRFX_GPIOTE_CONFIG_IN_SENSE_TOGGLE(true);
    cfg.is_watcher = true;

    for (uint8_t i = 0; i < n; i++) {
        if (is_hook_src(src[i])) {
            m_hook_ch[src[i]] = i;
            m_stage[i] = 3;
            g_logic_hook_mask |= (uint8_t)(1u << src[i]);
            /* output pin, input buffer off: read the output latch */
            if (nrf_gpio_pin_out_read(m_pin[i])) {
                m_init_levels |= (uint8_t)(1u << i);
            }
            continue;
        }
        uint32_t idx;
        NRF_GPIO_Type *port = pin_port(m_pin[i], &idx);
        uint32_t saved = port->PIN_CNF[idx];

        if (nrfx_gpiote_in_init(m_pin[i], &cfg, logic_evt) != NRFX_SUCCESS) {
            goto fail;
        }
        m_saved_cnf[i] = saved;
        m_stage[i] = 1;

        if (nrfx_ppi_channel_alloc(&m_ppi[i]) != NRFX_SUCCESS) {
            goto fail;
        }
        if (nrfx_ppi_channel_assign(m_ppi[i], nrfx_gpiote_in_event_addr_get(m_pin[i]),
                                    (uint32_t)&NRF_TIMER4->TASKS_CAPTURE[i]) != NRFX_SUCCESS) {
            nrfx_ppi_channel_free(m_ppi[i]);
            goto fail;
        }
        nrfx_ppi_channel_enable(m_ppi[i]);
        m_stage[i] = 2;
        nrfx_gpiote_in_event_enable(m_pin[i], true);
        if (nrf_gpio_pin_read(m_pin[i])) {
            m_init_levels |= (uint8_t)(1u << i);
        }
    }

    NRF_TIMER4->TASKS_START = 1;
    m_running = true;
    return LOGIC_OK;

fail:
    logic_stop();
    return LOGIC_ERR_NORES;
}

void logic_get_info(logic_info_t *info) {
    info->running     = m_running;
    info->overflow    = m_overflow;
    info->init_levels = m_init_levels;
    info->count       = m_count;
    info->calls       = m_calls;
    for (uint8_t i = 0; i < LOGIC_MAX_CHANNELS; i++) {
        info->cc[i] = m_cc[i];
    }
}

uint16_t logic_read(uint16_t offset, uint16_t max_events, uint8_t *out) {
    uint16_t total = m_count;
    if (offset >= total) {
        return 0;
    }
    uint16_t n = total - offset;
    if (n > max_events) {
        n = max_events;
    }
    for (uint16_t i = 0; i < n; i++) {
        uint32_t ts = m_ts[offset + i];
        out[0] = (uint8_t)(ts >> 24);
        out[1] = (uint8_t)(ts >> 16);
        out[2] = (uint8_t)(ts >> 8);
        out[3] = (uint8_t)ts;
        out[4] = m_ev[offset + i];
        out += LOGIC_EV_BYTES;
    }
    return n;
}

#endif /* PROJECT_CHAMELEON_ULTRA */
