#include "hitag2_tag.h"

#include <string.h>

#include "ble_main.h"
#include "bsp_delay.h"
#include "hw_connect.h"
#include "lf_125khz_radio.h"
#include "lf_tag_em.h"
#include "nrf_gpio.h"

#define NRF_LOG_MODULE_NAME hitag2_tag
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
NRF_LOG_MODULE_REGISTER();

/* -----------------------------------------------------------------------
 * Password-mode Hitag2 tag emulation: decode the external reader's own
 * BPLM downlink and answer with a Manchester reply, load-modulated on
 * LF_MOD exactly like every other protocol's broadcast output in this
 * file -- just one precisely-timed burst per command instead of a looped
 * waveform, since the reply content depends on what the reader asked.
 *
 * TX framing/polarity/SOF length is taken from RfidResearchGroup/proxmark3's
 * own working Hitag2 simulator (armsrc/hitag_common.c
 * hitag_tag_send_frame_mc4k_sync(), armsrc/hitag2.c SimulateHitag2()):
 *   - 6-bit SOF (not 5, despite the datasheet -- PM3's own comment there
 *     documents a real Paxton reader rejecting a 5-bit SOF answer).
 *   - Manchester, RF/32 (16 Tc half-period, 32 Tc full period): bit 1 =
 *     modulate the FIRST half of the period, bit 0 = modulate the SECOND
 *     half.
 * TX polarity confirmed against this board's own schematic (Chameleon_nrf52_LF.SchDoc):
 * LF_MOD gates Q3, which loads the antenna node when high -- "modulating =
 * LF_MOD high" matches ANT_NO_MOD()'s own idle-low convention, same as the
 * working viking.c RF/32 tag emulation on this same pin.
 *
 * RX, 2nd design: ADC slope detection on LF_OA_OUT, not a GPIOTE level
 * threshold.
 *
 * The first design used NRFX_GPIOTE_CONFIG_IN_SENSE_LOTOHI on LF_OA_OUT --
 * a fixed digital-level threshold crossing. PM3's own SimulateHitag2()
 * (armsrc/hitag2.c) documents hitting exactly this failure mode on their
 * hardware for this exact scenario (a tag decoding an external reader's
 * field with no self-driven carrier to reference against): a level
 * threshold needs the envelope back over it before it reports the next
 * gap, and on a run of BPLM zero bits it never gets there, so several bits
 * merge into one interval -- measured there as total failure, not partial
 * (two Proxmarks 1cm apart: start_auth=0 answers=0). Their fix was slope
 * detection in their FPGA: compare each sample to one ~32us earlier, call
 * an edge on the difference, not the absolute level. That isn't portable
 * (no FPGA here), but the principle is.
 *
 * This reuses lf_125khz_radio.c's existing TIMER3/PPI-triggered SAADC
 * capture (same 166.67kHz rate already proven for reader-mode Indala
 * fc/2 decode, AIN5 = LF_OA_OUT), routed through its own short-buffer
 * registration (ble_main.c's HITAG2_ADC_BUF_LEN) since Hitag2 must reply
 * within ~1.8ms of the reader going quiet and the 2048-sample buffers
 * used for Indala are ~12ms/buffer -- far too slow here.
 *
 * HT2_SLOPE_THRESH is a starting value, not a measured one -- needs real
 * hardware to tune against this board's actual field-on/field-off ADC
 * swing. Session start/end logs the raw sample min/max seen so that value
 * can be set from real numbers instead of guessed twice.
 * --------------------------------------------------------------------- */

#define HT2_SOF_BITS        6
#define HT2_HALF_PERIOD_US  (HITAG_T_TAG_HALF_PERIOD * 8)   // 128 us
#define HT2_FULL_PERIOD_US  (HITAG_T_TAG_FULL_PERIOD * 8)   // 256 us

#define HITAG_T_TAG_HALF_PERIOD 16
#define HITAG_T_TAG_FULL_PERIOD 32

#define HT2_T_WAIT_RESP_US   (227u * 8u)  // HITAG2_T_WAIT_RESP, see lf_hitag2_data.c

// Downlink (reader -> tag) bit-period classification, same constants as
// lf_hitag2_data.c's reader-mode TX (verified against PM3): T_0=20 Tc,
// T_1=30 Tc. Classify by the time between consecutive slope-detected edges
// (each marks the field coming back on after one bit's low pulse).
#define HT2_RX_T0_US   (20u * 8u)
#define HT2_RX_T1_US   (30u * 8u)
#define HT2_RX_JIT_US  48u  // +/- window around each threshold

// No new edge within this long -> the reader's frame is done.
#define HT2_RX_FRAME_GAP_US  400u

// LF_OA_OUT's op-amp stages need READER_POWER (LF_AMP_PWR) on; give them
// time to settle before trusting samples. Not a measured value -- a
// conservative guess pending a scope check.
#define HT2_RX_AMP_SETTLE_US  1000u

// ADC sample period: TIMER3/PPI drives SAADC at 16MHz/96 = 166.667kHz
// (lf_125khz_radio.c psk166_capture_init()).
#define HT2_SAMPLE_PERIOD_US  6u

// Slope window: compare each sample to one this many samples back. Sized to
// HT2_RX's own T_LOW (~48us = 8 samples at 6us/sample), not PM3's ~32us --
// their sample rate differs, the principle (span the low-pulse duration) is
// what carries over, not the constant.
#define HT2_SLOPE_LOOKBACK_SAMPLES 8

// Starting guess, needs real-hardware tuning -- see header comment.
#define HT2_SLOPE_THRESH 200

// Minimum samples between accepted edges, so one envelope ramp (several
// samples each showing delta > threshold while climbing) counts once, not
// several times. Shorter than the smallest valid inter-edge gap (T0, 160us).
#define HT2_SLOPE_HOLDOFF_SAMPLES 10

static uint8_t m_pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE];

static volatile uint32_t m_rx_bits[64 / 32 + 1];
static volatile uint8_t  m_rx_nbits;
static volatile uint32_t m_rx_last_edge_us;
static volatile bool     m_rx_have_edge;
static volatile uint32_t m_rx_total_samples;
static volatile bool     m_rx_frame_ready_flag;

// Slope-detector state, persists across ADC callback invocations.
static int16_t  m_hist[HT2_SLOPE_LOOKBACK_SAMPLES];
static uint8_t  m_hist_pos;
static uint8_t  m_hist_filled;
static uint32_t m_holdoff_left;

// Diagnostic only, for tuning HT2_SLOPE_THRESH against real hardware.
static int16_t m_dbg_min;
static int16_t m_dbg_max;

void hitag2_tag_load(const uint8_t pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE]) {
    memcpy(m_pages, pages, sizeof(m_pages));
}

static void hitag2_rx_push_bit(bool bit) {
    uint8_t word = m_rx_nbits / 32;
    uint8_t off  = m_rx_nbits % 32;
    if (word >= (sizeof(m_rx_bits) / sizeof(m_rx_bits[0]))) {
        return;  // frame longer than anything this protocol sends; drop
    }
    if (bit) {
        m_rx_bits[word] |= (1u << (31 - off));
    } else {
        m_rx_bits[word] &= ~(1u << (31 - off));
    }
    m_rx_nbits++;
}

// Slope-detected edge: field just came back on after one bit's low pulse.
// The bit value is carried by the time since the PREVIOUS edge, not by this
// pulse's own width (BPLM: the low pulse itself, T_LOW, is the same ~6 Tc
// for both bit values).
static void hitag2_rx_edge(uint32_t sample_idx) {
    uint32_t now_us = sample_idx * HT2_SAMPLE_PERIOD_US;
    if (m_rx_have_edge) {
        uint32_t period = now_us - m_rx_last_edge_us;
        bool is_one = (period >= (HT2_RX_T1_US - HT2_RX_JIT_US) && period <= (HT2_RX_T1_US + HT2_RX_JIT_US));
        bool is_zero = (period >= (HT2_RX_T0_US - HT2_RX_JIT_US) && period <= (HT2_RX_T0_US + HT2_RX_JIT_US));
        if (is_one) {
            hitag2_rx_push_bit(true);
        } else if (is_zero) {
            hitag2_rx_push_bit(false);
        }
        // else: out-of-window gap -- most likely the reader's own
        // frame-start/stop guard, not a data bit; ignore it rather than
        // guess, and let the frame-gap timeout close the frame.
    }
    m_rx_last_edge_us = now_us;
    m_rx_have_edge = true;
}

// SAADC DONE callback (lf_adc_callback_t), runs in interrupt context via
// lf_125khz_radio_saadc166_enable_hitag2(). Slope-detects edges in this
// buffer, pushes them through the same classifier as the pin-interrupt
// design did, then checks whether the frame has gone quiet.
static void hitag2_adc_callback(nrf_saadc_value_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        int16_t sample = (int16_t)buf[i];
        if (sample < m_dbg_min) m_dbg_min = sample;
        if (sample > m_dbg_max) m_dbg_max = sample;

        int32_t delayed = (m_hist_filled >= HT2_SLOPE_LOOKBACK_SAMPLES) ? m_hist[m_hist_pos] : sample;
        int32_t delta = (int32_t)sample - delayed;

        m_hist[m_hist_pos] = sample;
        m_hist_pos = (uint8_t)((m_hist_pos + 1) % HT2_SLOPE_LOOKBACK_SAMPLES);
        if (m_hist_filled < HT2_SLOPE_LOOKBACK_SAMPLES) {
            m_hist_filled++;
        }

        if (m_holdoff_left > 0) {
            m_holdoff_left--;
        } else if (delta > HT2_SLOPE_THRESH) {
            hitag2_rx_edge(m_rx_total_samples + i);
            m_holdoff_left = HT2_SLOPE_HOLDOFF_SAMPLES;
        }
    }
    m_rx_total_samples += (uint32_t)len;

    // Checked here, not just in hitag2_tag_tick(), so frame-gap detection
    // is bounded by one buffer period (HITAG2_ADC_BUF_LEN samples) rather
    // than also waiting on the next main-loop pass.
    if (m_rx_have_edge && m_rx_nbits > 0) {
        uint32_t since = (m_rx_total_samples * HT2_SAMPLE_PERIOD_US) - m_rx_last_edge_us;
        if (since >= HT2_RX_FRAME_GAP_US) {
            m_rx_frame_ready_flag = true;
        }
    }
}

// LF_OA_OUT's op-amp stages are unpowered during normal tag emulation
// (tag_mode_enter() clears READER_POWER). Powered once for the whole
// session (hitag2_tag_tick()), not per-reply -- hitag2_reply() only
// pauses the ADC capture around our own TX, it does not need the amp
// re-settled each time.
static void hitag2_amp_power_on(void) {
    nrf_gpio_cfg_output(READER_POWER);
    nrf_gpio_pin_set(READER_POWER);
    bsp_delay_us(HT2_RX_AMP_SETTLE_US);
}

static void hitag2_amp_power_off(void) {
    nrf_gpio_pin_clear(READER_POWER);
}

static void hitag2_rx_start(void) {
    memset((void *)m_rx_bits, 0, sizeof(m_rx_bits));
    m_rx_nbits = 0;
    m_rx_have_edge = false;
    m_rx_total_samples = 0;
    m_rx_frame_ready_flag = false;
    memset(m_hist, 0, sizeof(m_hist));
    m_hist_pos = 0;
    m_hist_filled = 0;
    m_holdoff_left = 0;
    m_dbg_min = 32767;   // INT16_MAX: first sample updates it
    m_dbg_max = -32768;  // INT16_MIN: first sample updates it

    lf_125khz_radio_saadc166_enable_hitag2(hitag2_adc_callback);
}

static void hitag2_rx_stop(void) {
    lf_125khz_radio_saadc166_disable_hitag2();
    NRF_LOG_INFO("hitag2 rx adc range: min=%d max=%d (tune HT2_SLOPE_THRESH against this)",
                 m_dbg_min, m_dbg_max);
}

// Non-blocking: true if a frame looks complete (reader has gone quiet for
// HT2_RX_FRAME_GAP_US after at least one decoded bit). The actual check
// runs in hitag2_adc_callback(); this just reads the flag it sets.
static bool hitag2_rx_frame_ready(void) {
    return m_rx_frame_ready_flag;
}

static uint32_t hitag2_rx_value(uint8_t nbits) {
    // MSB-first, matches how lf_hitag2_data.c's reader side both sends
    // and (per the page-frame formula) expects these frames.
    uint32_t v = 0;
    for (uint8_t i = 0; i < nbits; i++) {
        uint8_t word = i / 32;
        uint8_t off  = i % 32;
        bool bit = (m_rx_bits[word] >> (31 - off)) & 1;
        v = (v << 1) | (bit ? 1 : 0);
    }
    return v;
}

static void ht2_mod_on(void)  { nrf_gpio_pin_set(LF_MOD); }
static void ht2_mod_off(void) { nrf_gpio_pin_clear(LF_MOD); }

static void hitag2_tx_bit(bool bit) {
    if (bit) {
        ht2_mod_on();
        bsp_delay_us(HT2_HALF_PERIOD_US);
        ht2_mod_off();
        bsp_delay_us(HT2_HALF_PERIOD_US);
    } else {
        ht2_mod_off();
        bsp_delay_us(HT2_HALF_PERIOD_US);
        ht2_mod_on();
        bsp_delay_us(HT2_HALF_PERIOD_US);
    }
}

// Sends 6-bit SOF (all 1s) + the low `nbits` of `value`, MSB first, then
// releases the antenna. ADC RX must already be stopped by the caller --
// our own modulation would otherwise feed back into the slope detector.
static void hitag2_tx_frame(uint32_t value, uint8_t nbits) {
    for (uint8_t i = 0; i < HT2_SOF_BITS; i++) {
        hitag2_tx_bit(true);
    }
    for (int8_t i = (int8_t)(nbits - 1); i >= 0; i--) {
        hitag2_tx_bit((value >> i) & 1);
    }
    ht2_mod_off();
}

static void hitag2_reply(uint32_t value, uint8_t nbits) {
    hitag2_rx_stop();
    bsp_delay_us(HT2_T_WAIT_RESP_US);
    hitag2_tx_frame(value, nbits);
    hitag2_rx_start();
}

static uint16_t hitag2_page_frame_expect(uint8_t opcode, uint8_t page) {
    uint8_t page3 = page & 0x7;
    uint8_t comp  = (page3 ^ 0x7) & 0x7;
    uint8_t tx0   = opcode | (page3 << 3) | (comp >> 2);
    return ((uint16_t)tx0 << 2) | (comp & 0x3);
}

// One password-mode session's worth of state. Reset on every fresh
// START_AUTH (rather than tracked across the whole field-present window)
// since a reader may retry START_AUTH at any point and that always
// resets the tag's own state per the datasheet.
static bool m_authed;

static uint32_t page_u32(uint8_t page) {
    return ((uint32_t)m_pages[page][0] << 24) | ((uint32_t)m_pages[page][1] << 16) |
           ((uint32_t)m_pages[page][2] << 8)  | (uint32_t)m_pages[page][3];
}

// Handles one decoded reader frame. Mirrors PM3's own
// hitag2_handle_reader_command() dispatch by frame length (armsrc/hitag2.c):
// 5 bits = START_AUTH, 32 bits = password (or write data, not implemented --
// WRITE_PAGE needs a two-frame exchange this first cut does not do), 10
// bits = READ_PAGE/READ_PAGE_INVERTED.
static void hitag2_handle_frame(uint8_t nbits, uint32_t value) {
    NRF_LOG_INFO("hitag2 rx frame: %d bits, value 0x%08X", nbits, value);
    if (nbits == 5) {
        m_authed = false;
        hitag2_reply(page_u32(HITAG2_PAGE_UID), 32);
        return;
    }
    if (nbits == 32 && !m_authed) {
        bool crypto_mode = (m_pages[HITAG2_PAGE_CONFIG][0] & HITAG2_CONFIG_CRYPTO_BIT) != 0;
        if (crypto_mode) {
            return;  // out of scope: real tag would start Nr/Ar exchange here
        }
        if (value == page_u32(HITAG2_PAGE_PWD)) {
            m_authed = true;
            hitag2_reply(page_u32(HITAG2_PAGE_CONFIG), 32);
        }
        // mismatch -> stay silent, same as a real tag
        return;
    }
    if (nbits == 10) {
        for (uint8_t page = 0; page < HITAG2_NUM_PAGES; page++) {
            if (hitag2_page_frame_expect(HITAG2_READ_PAGE, page) == value ||
                    hitag2_page_frame_expect(HITAG2_READ_PAGE_INV, page) == value) {
                hitag2_reply(page_u32(page), 32);
                return;
            }
        }
    }
    // Anything else (e.g. a 64-bit crypto challenge) is out of scope.
}

static bool m_session_armed;

void hitag2_tag_session_start(void) {
    // Called from lf_tag_em.c's LPCOMP ISR -- must return immediately.
    // Only arms the flag; hitag2_tag_tick() does the actual work (which
    // includes powering the LF_OA_OUT amp chain) from thread context.
    m_authed = false;
    m_session_armed = true;
}

bool hitag2_tag_tick(void) {
    static bool rx_running = false;

    if (!m_session_armed) {
        return false;
    }

    if (!rx_running) {
        hitag2_amp_power_on();
        hitag2_rx_start();
        rx_running = true;
        return true;
    }

    if (!is_lf_field_exists()) {
        hitag2_rx_stop();
        hitag2_amp_power_off();
        rx_running = false;
        m_session_armed = false;
        // Without this, m_is_lf_emulating (lf_tag_em.c) stayed stuck true
        // past the end of the session, so no later reader approach this
        // boot ever re-triggered the LPCOMP ISR -- only a slot change or
        // reboot would.
        lf_tag_em_hitag2_field_lost();
        return false;
    }

    if (hitag2_rx_frame_ready()) {
        m_rx_frame_ready_flag = false;
        uint8_t nbits = m_rx_nbits;
        uint32_t value = hitag2_rx_value(nbits);
        m_rx_nbits = 0;
        m_rx_have_edge = false;
        // hitag2_reply() (called from here, for a match) stops and
        // restarts RX itself around the TX burst; harmless no-op otherwise.
        hitag2_handle_frame(nbits, value);
    }
    return true;
}

int lf_tag_hitag2_data_savecb(tag_specific_type_t type, tag_data_buffer_t *buffer) {
    (void)buffer;
    return type == TAG_TYPE_HITAG2 ? LF_HITAG2_TAG_ID_SIZE : 0;
}

// lf_tag_hitag2_data_factory() lives in lf_tag_em.c, not here -- it needs
// lf_tag_data_factory(), which is internal to that file (same pattern as
// every other LF protocol's *_data_factory).
