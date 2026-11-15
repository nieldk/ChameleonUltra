#include "hitag2_tag.h"

#include <string.h>

#include "bsp_delay.h"
#include "hw_connect.h"
#include "lf_tag_em.h"
#include "nrf_gpio.h"
#include "nrfx_gpiote.h"
#include "nrfx_timer.h"

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
 * RX tap, 2nd attempt: LF_RSSI_PIN via GPIOTE, not LF_OA_OUT.
 *
 * First attempt used LF_OA_OUT (reader-mode's own decode pin). Many
 * captures across two PM3 units never produced a clean multi-edge BPLM
 * frame, down to zero or one short edge burst per reader attempt, while a
 * passive EM410x read at the same position worked fine. LF_OA_OUT's path
 * is behind two op-amp filter stages (READER_POWER/LF_AMP_PWR) sized for
 * reader mode's own strong self-generated field, not confirmed to resolve
 * an external reader's shallower modulation depth -- no scope here to
 * check that margin.
 *
 * LF_RSSI_PIN is the plain rectified-envelope tap already used for
 * field-presence sensing (is_lf_field_exists()), no amp stage, no settle
 * delay. Its documented ~2ms time constant is nominally too slow for a
 * 160-240us bit period, but that estimate was never confirmed against real
 * hardware either, and it has not been tried. Worth ruling in or out before
 * assuming the RX side needs a scope.
 *
 * LF_RSSI_PIN is also LPCOMP's input for field sensing, so GPIOTE and
 * LPCOMP would fight over the same pin if both ran at once. Avoided here by
 * never re-enabling LPCOMP for the length of a Hitag2 session: LPCOMP is
 * already disabled on session start (lpcomp_event_handler()), and this file
 * no longer calls is_lf_field_exists() itself -- field loss is instead
 * inferred from RX inactivity (see HT2_SESSION_IDLE_US), and reported back
 * through lf_tag_em_hitag2_field_lost() so LPCOMP gets re-armed for the
 * next reader approach.
 * --------------------------------------------------------------------- */

#define HT2_SOF_BITS        6
#define HT2_HALF_PERIOD_US  (HITAG_T_TAG_HALF_PERIOD * 8)   // 128 us
#define HT2_FULL_PERIOD_US  (HITAG_T_TAG_FULL_PERIOD * 8)   // 256 us

#define HITAG_T_TAG_HALF_PERIOD 16
#define HITAG_T_TAG_FULL_PERIOD 32

#define HT2_T_WAIT_RESP_US   (227u * 8u)  // HITAG2_T_WAIT_RESP, see lf_hitag2_data.c

// Downlink (reader -> tag) bit-period classification, same constants as
// lf_hitag2_data.c's reader-mode TX (verified against PM3): T_0=20 Tc,
// T_1=30 Tc. Classify by the gap between consecutive rising edges on
// LF_RSSI_PIN (each marks the field coming back on after one bit's low
// pulse -- see header comment for why rising, not falling).
#define HT2_RX_T0_US   (20u * 8u)
#define HT2_RX_T1_US   (30u * 8u)
#define HT2_RX_JIT_US  48u  // +/- window around each threshold

// No new rising edge within this long -> the reader's frame is done.
#define HT2_RX_FRAME_GAP_US  400u

// No RX edge at all for this long -> treat the reader as gone. Well past
// PM3's own 2s client-side retry window, so a real in-progress exchange
// never gets cut off; loose because this is inactivity-based field-loss,
// not a per-frame timeout.
#define HT2_SESSION_IDLE_US  3000000u

static uint8_t m_pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE];

static nrfx_timer_t m_ht_timer = NRFX_TIMER_INSTANCE(3);

static volatile uint32_t m_rx_bits[64 / 32 + 1];
static volatile uint8_t  m_rx_nbits;
static volatile uint32_t m_rx_last_edge_us;
static volatile bool     m_rx_have_edge;

// Diagnostic only: every edge's raw period (not just the ones that passed
// classification), so a frame that decodes short can be told apart from
// "no more edges arrived" vs "edges arrived outside the T0/T1 windows".
#define HT2_RX_DEBUG_PERIODS 16
static volatile uint32_t m_rx_dbg_periods[HT2_RX_DEBUG_PERIODS];
static volatile uint8_t  m_rx_dbg_nperiods;

// Diagnostic only: plain polled reads of LF_RSSI_PIN's digital level,
// main-loop rate, independent of GPIOTE. Tells apart "GPIOTE is missing
// real edges" (poll would see the pin move) from "the pin genuinely isn't
// moving" (poll stays flat too).
static bool     m_rx_dbg_poll_level;
static bool     m_rx_dbg_poll_level_valid;
static uint16_t m_rx_dbg_poll_transitions;
static bool     m_rx_dbg_poll_last_seen_high;
static bool     m_rx_dbg_poll_last_seen_low;

// Last RX activity (any edge, classified or not). Session idle-timeout is
// measured from this, not from is_lf_field_exists() -- see header comment.
static uint32_t m_last_activity_us;

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

// GPIOTE rising-edge handler on LF_RSSI_PIN: field just came back on after
// one bit's low pulse. The bit value is carried by the period since the
// PREVIOUS rising edge, not by this pulse's own width (BPLM: the low
// pulse itself, T_LOW, is the same ~6 Tc for both bit values).
static void hitag2_rx_edge_cb(nrfx_gpiote_pin_t pin, nrf_gpiote_polarity_t action) {
    (void)pin;
    (void)action;
    uint32_t now = nrfx_timer_capture(&m_ht_timer, NRF_TIMER_CC_CHANNEL0);
    if (m_rx_have_edge) {
        uint32_t period = now - m_rx_last_edge_us;
        if (m_rx_dbg_nperiods < HT2_RX_DEBUG_PERIODS) {
            m_rx_dbg_periods[m_rx_dbg_nperiods++] = period;
        }
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
    m_rx_last_edge_us = now;
    m_rx_have_edge = true;
    m_last_activity_us = now;
}

// LF_RSSI_PIN needs no amp power and no settle delay (see header comment).
// Same timer/GPIOTE setup pattern as the LF_OA_OUT attempt, just a
// different pin.
static void hitag2_rx_start(void) {
    memset((void *)m_rx_bits, 0, sizeof(m_rx_bits));
    m_rx_nbits = 0;
    m_rx_have_edge = false;
    m_rx_dbg_nperiods = 0;
    m_rx_dbg_poll_level_valid = false;
    m_rx_dbg_poll_transitions = 0;
    m_rx_dbg_poll_last_seen_high = false;
    m_rx_dbg_poll_last_seen_low = false;

    nrfx_timer_config_t tcfg = NRFX_TIMER_DEFAULT_CONFIG;
    tcfg.frequency = NRF_TIMER_FREQ_1MHz;
    tcfg.mode = NRF_TIMER_MODE_TIMER;
    tcfg.bit_width = NRF_TIMER_BIT_WIDTH_32;
    nrfx_timer_init(&m_ht_timer, &tcfg, NULL);
    nrfx_timer_enable(&m_ht_timer);
    m_last_activity_us = nrfx_timer_capture(&m_ht_timer, NRF_TIMER_CC_CHANNEL0);

    nrfx_gpiote_in_config_t cfg = NRFX_GPIOTE_CONFIG_IN_SENSE_LOTOHI(false);
    nrfx_gpiote_in_init(LF_RSSI_PIN, &cfg, hitag2_rx_edge_cb);
    nrfx_gpiote_in_event_enable(LF_RSSI_PIN, true);
}

static void hitag2_rx_stop(void) {
    nrfx_gpiote_in_event_disable(LF_RSSI_PIN);
    nrfx_gpiote_in_uninit(LF_RSSI_PIN);
    nrfx_timer_disable(&m_ht_timer);
    nrfx_timer_uninit(&m_ht_timer);
}

// Non-blocking: true if a frame looks complete (reader has gone quiet for
// HT2_RX_FRAME_GAP_US since the last edge, classified or not). Called from
// hitag2_tag_tick(), main-loop context, every iteration -- not a wait loop.
static bool hitag2_rx_frame_ready(void) {
    // Only require an edge to have been seen at all, not a classified bit --
    // gating on m_rx_nbits meant unclassified (out-of-window) edges never
    // timed out, so a run of noise could sit open indefinitely and only
    // close once a later edge happened to fall inside a T0/T1 window.
    if (!m_rx_have_edge) {
        return false;
    }
    uint32_t since = nrfx_timer_capture(&m_ht_timer, NRF_TIMER_CC_CHANNEL0) - m_rx_last_edge_us;
    return since >= HT2_RX_FRAME_GAP_US;
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
// releases the antenna. GPIOTE RX must already be stopped by the caller --
// our own modulation would otherwise retrigger hitag2_rx_edge_cb.
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
    // Only arms the flag; hitag2_tag_tick() does the actual work from
    // thread context.
    m_authed = false;
    m_session_armed = true;
}

bool hitag2_tag_tick(void) {
    static bool rx_running = false;

    if (!m_session_armed) {
        return false;
    }

    if (!rx_running) {
        hitag2_rx_start();
        rx_running = true;
        return true;
    }

    // No is_lf_field_exists() here: that call drives LPCOMP, which shares
    // LF_RSSI_PIN with this file's own GPIOTE use, and LPCOMP is already
    // disabled for the session (lpcomp_event_handler()). Field loss is
    // inferred from RX inactivity instead, and reported through
    // lf_tag_em_hitag2_field_lost() so LPCOMP gets re-armed afterward --
    // without that call, m_is_lf_emulating stayed stuck true and no later
    // reader approach this boot ever re-triggered the LPCOMP ISR.
    uint32_t now_us = nrfx_timer_capture(&m_ht_timer, NRF_TIMER_CC_CHANNEL0);
    if ((now_us - m_last_activity_us) >= HT2_SESSION_IDLE_US) {
        // Diagnostics below normally only print when a frame completes
        // (hitag2_rx_frame_ready()), so a session with zero edges ever
        // would otherwise close silently -- print what the poll saw here
        // too, since "no edge, ever" vs "edges, never classified" is
        // exactly the question an all-silent timeout can't answer.
        NRF_LOG_INFO("hitag2 session idle: %d raw periods captured, %d poll transitions, saw high=%d low=%d",
                     m_rx_dbg_nperiods, m_rx_dbg_poll_transitions,
                     m_rx_dbg_poll_last_seen_high, m_rx_dbg_poll_last_seen_low);
        hitag2_rx_stop();
        rx_running = false;
        m_session_armed = false;
        lf_tag_em_hitag2_field_lost();
        return false;
    }

    // Plain polled read of the same pin GPIOTE is watching, main-loop rate.
    // Independent evidence of whether the pin is moving at all.
    bool level = nrf_gpio_pin_read(LF_RSSI_PIN) != 0;
    if (!m_rx_dbg_poll_level_valid) {
        m_rx_dbg_poll_level = level;
        m_rx_dbg_poll_level_valid = true;
    } else if (level != m_rx_dbg_poll_level) {
        m_rx_dbg_poll_transitions++;
        m_rx_dbg_poll_level = level;
    }
    if (level) {
        m_rx_dbg_poll_last_seen_high = true;
    } else {
        m_rx_dbg_poll_last_seen_low = true;
    }

    if (hitag2_rx_frame_ready()) {
        uint8_t nbits = m_rx_nbits;
        uint32_t value = hitag2_rx_value(nbits);
        m_rx_nbits = 0;
        m_rx_have_edge = false;

        uint8_t nperiods = m_rx_dbg_nperiods;
        uint32_t periods[HT2_RX_DEBUG_PERIODS];
        for (uint8_t i = 0; i < nperiods; i++) {
            periods[i] = m_rx_dbg_periods[i];
        }
        m_rx_dbg_nperiods = 0;
        NRF_LOG_INFO("hitag2 rx edges: %d raw periods (us):", nperiods);
        for (uint8_t i = 0; i < nperiods; i++) {
            NRF_LOG_INFO("  [%d] %d", i, periods[i]);
        }
        NRF_LOG_INFO("hitag2 rx poll: %d transitions, saw high=%d low=%d",
                     m_rx_dbg_poll_transitions, m_rx_dbg_poll_last_seen_high,
                     m_rx_dbg_poll_last_seen_low);
        m_rx_dbg_poll_transitions = 0;
        m_rx_dbg_poll_last_seen_high = false;
        m_rx_dbg_poll_last_seen_low = false;

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
