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
 * First real-hardware test of the slope detector: dozens of bogus 1-3 bit
 * "frames" per field session, no valid 5/32/10 bit frame ever decoded.
 * Raw min/max logged -116..14328 against HT2_SLOPE_THRESH=200 -- ~1.4% of
 * the swing, so the 125kHz carrier's own ripple on LF_OA_OUT (6us/sample
 * vs the carrier's 8us period is close to aliasing it, not oversampling
 * it) was crossing threshold every few samples on its own. Added a 4-tap
 * moving-average pre-filter (kills ripple, too fast to smear a real
 * 160-240us-period transition) and raised the threshold; m_dbg_max_delta
 * now logs the largest delta actually seen so the next round tunes from a
 * measured number instead of another guess.
 *
 * Second real-hardware test: garbage dropped a lot, but password frames
 * (key 00000000, value 0x00000000 -- a strong tell) landed as 26-29 bits
 * instead of 32, always right after our own reply. Cause: hitag2_reply()
 * was pausing/resuming RX via hitag2_rx_stop()/hitag2_rx_start(), which do
 * a full SAADC uninit()+init()+channel_init() -- that driver re-init
 * latency, repeated around every single TX, was clipping the first several
 * bits of the reader's actual response. Fixed by pausing/resuming only the
 * TIMER3/PPI sample trigger for a reply (hitag2_rx_pause_for_tx()/
 * _resume_after_tx()), leaving the SAADC channel live; the full init/uninit
 * is now only done once, at session start/end.
 *
 * Third real-hardware test: deficit shrank but didn't close -- 28-31 bits
 * of 32, still always right after our own reply. RfidResearchGroup/
 * proxmark3's own ReaderHitag() (armsrc/hitag2.c) documents the identical
 * physical mechanism from their side: a tag's (or tag-simulator's) own
 * reply disturbs its own LF front end, and decoding too soon into the
 * recovery ramp loses an edge partway through a 32-bit frame -- their fix
 * was to simply wait longer (t_wait_2) before trusting the line again.
 * Same fix here: hitag2_rx_resume_after_tx() now mutes the edge decision
 * (not the moving-average/history bookkeeping, which stays warm) for
 * HT2_RX_POST_TX_MUTE_US after resuming, so our own ringdown can't
 * misalign the T0/T1 reference for the bits that follow it.
 *
 * Fourth real-hardware test: no improvement, deficit if anything slightly
 * worse (as low as 24 of 32 bits, where the worst before muting was 26).
 * That direction fits a different explanation better: the mute only makes
 * our total reply-to-listening latency longer, and if the reader starts
 * its next frame on a schedule of its own rather than reacting to our
 * modulation actually stopping, a longer blind window after our TX can
 * only cost more of the reader's frame, not less. HT2_RX_POST_TX_MUTE_US
 * is disabled (0) pending real evidence either way. Added instead: each
 * decoded frame now also logs its edge-to-edge span in us and how many
 * inter-edge gaps were classified as neither T0 nor T1 and dropped
 * (hitag2_rx_edge()'s m_rx_dropped_gaps) -- dropped>0 means bits are being
 * lost mid-frame (jitter/noise), dropped==0 with a short span means the
 * frame was simply picked up late. One tells us to chase noise rejection
 * further, the other tells us to chase reply timing; guessing at another
 * constant without that distinction is how the last two rounds went.
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

// Disabled (0) -- see header comment's 4th-test note. Set to 1200 for one
// round on the theory that our own TX ringing was corrupting the first
// edge after resume; the next test's deficit didn't shrink and plausibly
// grew, which fits "this mute only shortens our listening window" better
// than "this fixes a ringing artifact". Left in place, not deleted, since
// the frame-span/dropped-gap log added alongside it is what should decide
// whether a (smaller, re-measured) mute is worth reviving.
#define HT2_RX_POST_TX_MUTE_US  0u

// Engaging LF_MOD for the antenna-load RX trick below is itself a step on
// LF_OA_OUT -- mute the slope detector for this long right after turning
// it on so that step isn't read as a bit edge. Not measured; first guess,
// same length as the slope-detector's own lookback window (8 samples * 6us).
#define HT2_RX_MOD_ENGAGE_MUTE_US  48u

// ADC sample period: TIMER3/PPI drives SAADC at 16MHz/96 = 166.667kHz
// (lf_125khz_radio.c psk166_capture_init()).
#define HT2_SAMPLE_PERIOD_US  6u

// Slope window: compare each sample to one this many samples back. Sized to
// HT2_RX's own T_LOW (~48us = 8 samples at 6us/sample), not PM3's ~32us --
// their sample rate differs, the principle (span the low-pulse duration) is
// what carries over, not the constant.
#define HT2_SLOPE_LOOKBACK_SAMPLES 8

// Moving-average width applied before slope detection (see the callback
// comment). ~24us at 6us/sample: several 125kHz carrier cycles, so it
// averages out carrier ripple, but well under one bit period (160-240us)
// so a real transition still shows up sharply.
#define HT2_AVG_TAPS 4

// Raised from 200 after the first real-hardware test -- see header
// comment. Still a guess, not a measurement; m_dbg_max_delta below is
// there so the next test replaces it with a real number.
#define HT2_SLOPE_THRESH 1500

// Minimum samples between accepted edges, so one envelope ramp (several
// samples each showing delta > threshold while climbing) counts once, not
// several times. Shorter than the smallest valid inter-edge gap (T0, 160us).
#define HT2_SLOPE_HOLDOFF_SAMPLES 10

static uint8_t m_pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE];

static volatile uint32_t m_rx_bits[64 / 32 + 1];
static volatile uint8_t  m_rx_nbits;
static volatile uint32_t m_rx_last_edge_us;
static volatile uint32_t m_rx_first_edge_us;
static volatile uint32_t m_rx_dropped_gaps;
static volatile bool     m_rx_have_edge;
static volatile uint32_t m_rx_total_samples;
static volatile bool     m_rx_frame_ready_flag;
static volatile uint32_t m_rx_mute_samples_left;

// Slope-detector state, persists across ADC callback invocations.
static int16_t  m_hist[HT2_SLOPE_LOOKBACK_SAMPLES];
static uint8_t  m_hist_pos;
static uint8_t  m_hist_filled;
static uint32_t m_holdoff_left;

// Moving-average pre-filter state, persists across ADC callback invocations.
static int16_t m_avg_buf[HT2_AVG_TAPS];
static int32_t m_avg_sum;
static uint8_t m_avg_pos;

// Diagnostic only, for tuning HT2_SLOPE_THRESH against real hardware.
static int16_t m_dbg_min;
static int16_t m_dbg_max;
static int32_t m_dbg_max_delta;

// Defined below with the TX bit-framing code; forward-declared here so the
// RX session functions can hold the antenna loaded while listening.
static void ht2_mod_on(void);
static void ht2_mod_off(void);

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
        } else {
            // Out-of-window gap -- most likely the reader's own
            // frame-start/stop guard, not a data bit; ignore it rather
            // than guess, and let the frame-gap timeout close the frame.
            // Counted (not just ignored) so the per-frame log can show
            // whether a short frame lost bits mid-stream (this count > 0)
            // or simply started late (count == 0, elapsed time short).
            // Logged with its actual duration: short (<HT2_RX_T0_US) means
            // a spurious edge slipped past the averaging filter; long
            // (>HT2_RX_T1_US) means a real transition was missed and two
            // bit periods merged into one gap. Different problems, same
            // symptom from nbits alone -- this is what tells them apart.
            NRF_LOG_INFO("hitag2 rx dropped gap: %u us", period);
            m_rx_dropped_gaps++;
        }
    } else {
        m_rx_first_edge_us = now_us;
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

        // Average before slope detection: raw samples carry visible
        // 125kHz carrier ripple (6us/sample is close to aliasing the
        // carrier's own 8us period, not safely oversampling it), and on
        // real hardware that ripple alone crossed HT2_SLOPE_THRESH every
        // few samples -- see header comment.
        m_avg_sum -= m_avg_buf[m_avg_pos];
        m_avg_buf[m_avg_pos] = sample;
        m_avg_sum += sample;
        m_avg_pos = (uint8_t)((m_avg_pos + 1) % HT2_AVG_TAPS);
        int16_t filtered = (int16_t)(m_avg_sum / HT2_AVG_TAPS);

        int32_t delayed = (m_hist_filled >= HT2_SLOPE_LOOKBACK_SAMPLES) ? m_hist[m_hist_pos] : filtered;
        int32_t delta = (int32_t)filtered - delayed;

        m_hist[m_hist_pos] = filtered;
        m_hist_pos = (uint8_t)((m_hist_pos + 1) % HT2_SLOPE_LOOKBACK_SAMPLES);
        if (m_hist_filled < HT2_SLOPE_LOOKBACK_SAMPLES) {
            m_hist_filled++;
        }

        if (m_rx_mute_samples_left > 0) {
            // Our own TX disturbs our own front end the same way PM3's
            // reader-mode code found simulating a tag disturbs theirs
            // (armsrc/hitag2.c ReaderHitag(), t_wait_2 comment): on real
            // hardware the ringdown right after resuming RX was corrupting
            // the first edge or two, which then misaligned the T0/T1
            // reference for several genuine bits after it -- 32-bit
            // password frames (key 00000000) were landing as 28-31 bits,
            // every time. Average/history above stays warm through this;
            // only the edge decision is held off.
            m_rx_mute_samples_left--;
            continue;
        }

        if (delta > m_dbg_max_delta) m_dbg_max_delta = delta;

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

// Clears decoded-bit and slope-detector state for a fresh frame. Shared by
// the full session start/resume paths below -- neither should carry over
// a partial bit/history from whatever was happening before.
static void hitag2_rx_reset_decode_state(void) {
    memset((void *)m_rx_bits, 0, sizeof(m_rx_bits));
    m_rx_nbits = 0;
    m_rx_have_edge = false;
    m_rx_total_samples = 0;
    m_rx_frame_ready_flag = false;
    memset(m_hist, 0, sizeof(m_hist));
    m_hist_pos = 0;
    m_hist_filled = 0;
    m_holdoff_left = 0;
    memset(m_avg_buf, 0, sizeof(m_avg_buf));
    m_avg_sum = 0;
    m_avg_pos = 0;
    m_rx_mute_samples_left = 0;  // resume_after_tx() below sets this for real
    m_rx_dropped_gaps = 0;
}

static void hitag2_rx_reset_dbg(void) {
    m_dbg_min = 32767;   // INT16_MAX: first sample updates it
    m_dbg_max = -32768;  // INT16_MIN: first sample updates it
    m_dbg_max_delta = 0;
}

static void hitag2_rx_log_dbg(void) {
    NRF_LOG_INFO("hitag2 rx adc range: min=%d max=%d max_delta=%d (tune HT2_SLOPE_THRESH against this)",
                 m_dbg_min, m_dbg_max, m_dbg_max_delta);
}

// Reported hardware finding (parallel work on a generic two-way LF link on
// this same board): an unloaded antenna rings enough that a tag reading a
// reader's BPLM gaps sees them smoothed at the field detector; holding
// LF_MOD on while listening damps that ringing and sharpens the gaps.
// First attempt (34d3131) turned it on with no settle time, right where
// decode state resets -- every frame in the next real-hardware log capped
// at 1-7 bits, including the very first one, which fits "the engage step
// itself is poisoning the start of every frame" better than "this doesn't
// help": a scattered-noise explanation wouldn't hit every single frame
// that hard. HT2_RX_MOD_ENGAGE_MUTE_US below holds off the edge decision
// (not the average/history, same as the TX mute) just past that step.
// Must be OFF before hitag2_tx_frame() starts: it needs a real off-to-on
// transition on its first SOF bit, not a continuation of an already-on
// line, so hitag2_rx_pause_for_tx() releases it and hitag2_rx_resume_after_tx()
// re-applies it (with its own settle mute) once our own TX is done.

// Session start/end: the only places that touch the SAADC channel itself
// (full driver init/uninit, non-trivial latency -- see hitag2_reply()'s
// pause/resume below for why that latency matters and is avoided there).
static void hitag2_rx_start(void) {
    hitag2_rx_reset_decode_state();
    hitag2_rx_reset_dbg();
    lf_125khz_radio_saadc166_enable_hitag2(hitag2_adc_callback);
    ht2_mod_on();
    m_rx_mute_samples_left = HT2_RX_MOD_ENGAGE_MUTE_US / HT2_SAMPLE_PERIOD_US;
}

static void hitag2_rx_stop(void) {
    ht2_mod_off();
    lf_125khz_radio_saadc166_disable_hitag2();
    hitag2_rx_log_dbg();
}

// Per-reply RX turnaround (around our own TX burst). Pauses/resumes only
// the TIMER3/PPI sample trigger, not the SAADC channel -- hitag2_rx_start()/
// _stop() do a full nrfx_saadc_uninit()+init()+channel_init() each time,
// which was fine once per session but far too slow called around every
// single TX: on real hardware this was the actual cause of 32-bit password
// frames (key 00000000 -- hence the telltale value 0x00000000) landing as
// 26-29 bits instead of 32, always right after a reply. The driver re-init
// latency was eating the first several bits of the reader's real response.
static void hitag2_rx_pause_for_tx(void) {
    ht2_mod_off();
    lf_125khz_radio_saadc166_pause_hitag2();
    hitag2_rx_log_dbg();
}

static void hitag2_rx_resume_after_tx(void) {
    hitag2_rx_reset_decode_state();
    hitag2_rx_reset_dbg();
    lf_125khz_radio_saadc166_resume_hitag2();
    ht2_mod_on();
    // Post-TX-ringing mute (HT2_RX_POST_TX_MUTE_US) and this engage-step
    // mute are different theories about different transients; tried
    // separately so a real-hardware log can tell them apart. Longer wins
    // if both are ever nonzero at once.
    uint32_t tx_mute  = HT2_RX_POST_TX_MUTE_US    / HT2_SAMPLE_PERIOD_US;
    uint32_t mod_mute = HT2_RX_MOD_ENGAGE_MUTE_US / HT2_SAMPLE_PERIOD_US;
    m_rx_mute_samples_left = (tx_mute > mod_mute) ? tx_mute : mod_mute;
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
    hitag2_rx_pause_for_tx();
    bsp_delay_us(HT2_T_WAIT_RESP_US);
    hitag2_tx_frame(value, nbits);
    hitag2_rx_resume_after_tx();
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
        // Span from this frame's first accepted edge to its last, and how
        // many inter-edge gaps fell outside both T0/T1 windows and got
        // dropped rather than counted as a bit -- decides between "started
        // late" (dropped==0, span roughly matches nbits*160-240us) and
        // "lost bits mid-frame" (dropped>0) for a short frame.
        uint32_t span_us = m_rx_have_edge ? (m_rx_last_edge_us - m_rx_first_edge_us) : 0;
        uint32_t dropped = m_rx_dropped_gaps;
        m_rx_nbits = 0;
        m_rx_have_edge = false;
        m_rx_dropped_gaps = 0;
        NRF_LOG_INFO("hitag2 rx frame span: %u us, dropped_gaps=%u", span_us, dropped);
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
