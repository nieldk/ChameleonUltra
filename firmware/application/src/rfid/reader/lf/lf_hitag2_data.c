#include "lf_hitag2_data.h"

#include <string.h>

#include "app_status.h"
#include "app_timer.h"
#include "bsp_delay.h"
#include "bsp_time.h"
#include "circular_buffer.h"
#include "hitag2_crypto.h"
#include "lf_125khz_radio.h"
#include "lf_reader_data.h"
#include "nrf_soc.h"
#include "timeslot.h"

#include "lf_ia_codec.h"

#define NRF_LOG_MODULE_NAME lf_hitag2
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
NRF_LOG_MODULE_REGISTER();

/* -----------------------------------------------------------------------
 * Protocol constants, verified against RfidResearchGroup/proxmark3
 * (armsrc/hitag2.c, include/protocols.h) -- see header comment.
 * All *_TC constants are in carrier periods (Tc = 1/125000 s = 8 us).
 * --------------------------------------------------------------------- */

/* HITAG2_START_AUTH/READ_PAGE/READ_PAGE_INV/WRITE_PAGE moved to
 * lf_hitag2_data.h -- hitag2_tag.c (tag emulation) needs them too. */

#define HITAG2_T_LOW_TC    6    /* field-off pulse per bit, 4..10 Tc range */
#define HITAG2_T_0_TC      20   /* total bit-0 duration, 18..22 Tc range */
#define HITAG2_T_1_TC      30   /* total bit-1 duration, 26..32 Tc range */
#define HITAG2_T_STOP_TC   36   /* EOF stop condition after the last bit, T_EOF should be > 36 Tc */

#define HITAG2_T_WAIT_POWERUP_TC        313  /* tag internal powerup, 312.5 Tc */
#define HITAG2_T_WAIT_START_AUTH_MAX_TC 232  /* tag gives up waiting for START_AUTH after this */
#define HITAG2_T_WAIT_RESP_TC           227  /* measured: tag's first answer edge, from reader's last edge */

/* Reply (tag -> reader) bit rate: RF/32 Manchester, matching lf_ia_hitag2.c's
 * HT2_BIT_FC on the emulation side -- same protocol, same carrier, so the
 * same Tc-per-bit value. Kept as a separate constant here, same as this
 * file's own HITAG2_T_0_TC/HITAG2_T_1_TC already duplicate the emulator's
 * HT2_T0_US/HT2_T1_US: the two sides don't share headers. */
#define HITAG2_BIT_FC   32u

#define HITAG2_RESP_TIMEOUT_TC   600   /* generous window to catch the ~227 Tc answer */
#define HITAG2_CB_SIZE           64
#define HITAG2_MAX_RUNS          140  /* >= 2 * max frame bits (64); merged runs mean fewer in practice */

static circular_buffer g_cb;

/* Pushes one run (level + length, Tc units) per GPIOTE edge on LF_OA_OUT,
 * for lf_ia_decode_runs() -- requires lf_125khz_radio_gpiote_enable(true)
 * (both edges), unlike every other LF protocol's rising-edge-only capture.
 * The level is the run that just ENDED, i.e. the one before this edge: a
 * rising edge means that run was low, a falling edge means it was high.
 * Which physical level the comparator calls "load" is not yet confirmed on
 * real hardware -- if replies decode inverted, flip LF_IA_INVERT in
 * hitag2_receive_frame() rather than this guess. */
static void hitag2_edge_cb(void) {
    uint32_t cnt = get_lf_counter_value();
    uint16_t len = (cnt > LF_IA_RUN_LEN_MAX) ? LF_IA_RUN_LEN_MAX : (uint16_t)cnt;
    bool completed_run_was_load = !lf_125khz_radio_last_edge_was_rising();
    uint16_t run = LF_IA_RUN(completed_run_was_load, len);
    cb_push_back(&g_cb, &run);
    clear_lf_counter_value();
}

/* Each BPLM bit toggles stop/start_lf_125khz_radio(), and that PWM driver
 * makes its own HFCLK request/release around each toggle -- so across a
 * whole TX burst it churns the SoftDevice's HFCLK reference count to zero
 * and back repeatedly, never letting the crystal (HFXO startup is ~0.36ms,
 * longer than the gap between toggles) actually settle. Confirmed on real
 * hardware: sd_clock_hfclk_is_running() read false during TX every time.
 *
 * Fix is the same one lf_xtal_counter.c already uses for TIMER1: hold our
 * own HFCLK request for the whole field session. The SoftDevice reference-
 * counts requests, so our hold keeps the crystal up regardless of how often
 * the PWM driver's own request/release toggles underneath it. */
static void hitag2_hfclk_hold(void) {
    sd_clock_hfclk_request();
    uint32_t running = 0;
    while (!running) {
        sd_clock_hfclk_is_running(&running);
    }
}

static void hitag2_hfclk_release(void) {
    sd_clock_hfclk_release();
}

/* -----------------------------------------------------------------------
 * Transmit side (reader -> tag), Binary Pulse Length Modulation.
 *
 * Per bit: drop the field for T_LOW, restore it, then hold it for the
 * remainder of the bit period (T_0 or T_1 minus T_LOW). This is the exact
 * sequence of armsrc/hitag2.c's hitag2_reader_send_bit(), just expressed
 * with this codebase's stop/start_lf_125khz_radio() primitives (the same
 * primitives lf_em4x05_data.c's send_em4305_bit() uses for its own gap
 * encoding).
 * --------------------------------------------------------------------- */

static void hitag2_send_bit(bool bit) {
    stop_lf_125khz_radio();
    bsp_delay_us(HITAG2_T_LOW_TC * 8);
    start_lf_125khz_radio();
    if (bit) {
        bsp_delay_us((HITAG2_T_1_TC - HITAG2_T_LOW_TC) * 8);
    } else {
        bsp_delay_us((HITAG2_T_0_TC - HITAG2_T_LOW_TC) * 8);
    }
}

/* EOF: one more T_LOW drop, then hold the field through T_STOP. Same shape
 * as hitag2_send_bit(), just with a fixed stop-condition hold instead of a
 * data-dependent one -- matches armsrc/hitag2.c's hitag2_reader_send_frame()
 * exactly, which every frame sender there appends after its bit loop.
 *
 * Without this, a gap-interval receiver (this codebase's own tag-emulation
 * engine, lf_ia_engine.c) has no edge to measure the last bit's duration
 * against and silently drops it -- confirmed on real hardware: a 5-bit
 * START_AUTH decoded as 4 bits by CU's own emulator reading CU's own
 * reader. A receiver with a fixed decode window (a real tag's analog
 * front end) may equally rely on this EOF to recognize the command is
 * complete rather than still waiting for more bits. */
static void hitag2_send_eof(void) {
    stop_lf_125khz_radio();
    bsp_delay_us(HITAG2_T_LOW_TC * 8);
    start_lf_125khz_radio();
    bsp_delay_us(HITAG2_T_STOP_TC * 8);
}

/* Sends the low `nbits` bits of `value`, MSB first, followed by the EOF. */
static void hitag2_send_bits(uint32_t value, uint8_t nbits) {
    for (int8_t i = (int8_t)(nbits - 1); i >= 0; i--) {
        hitag2_send_bit((value >> i) & 1);
    }
    hitag2_send_eof();
}

/* Sends `nbits` bits from a byte array, MSB first, followed by the EOF --
 * same framing as hitag2_send_bits, just for frames wider than 32 bits (the
 * 64-bit Nr/Ar crypto-mode challenge). Bit i is bit (7 - i%8) of byte i/8,
 * matching how hitag2_receive_frame packs a received frame. */
static void hitag2_send_bits_bytes(const uint8_t *bytes, uint8_t nbits) {
    for (uint8_t i = 0; i < nbits; i++) {
        hitag2_send_bit((bytes[i / 8] >> (7 - (i % 8))) & 1);
    }
    hitag2_send_eof();
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* 10-bit READ_PAGE/WRITE_PAGE/READ_PAGE_INVERTED frame.
 *
 * tx0 = opcode | (page << 3) | (complement >> 2), where complement = page ^ 7
 * (3 bits); the remaining 2 low bits of complement are the frame's last 2
 * bits. Derived from -- and verified bit-for-bit self-consistent with --
 * armsrc/hitag2.c's own sector decode:
 *   sector = ~(((rx[0]<<2)&0x04) | ((rx[1]>>6)&0x03)) & 0x07
 * and its own command encode:
 *   tx[0] = OPCODE | (blocknr << 3) | ((blocknr ^ 7) >> 2)
 */
static uint16_t hitag2_page_frame(uint8_t opcode, uint8_t page) {
    uint8_t page3 = page & 0x7;
    uint8_t comp  = (page3 ^ 0x7) & 0x7;
    uint8_t tx0   = opcode | (page3 << 3) | (comp >> 2);
    return ((uint16_t)tx0 << 2) | (comp & 0x3);
}

/* -----------------------------------------------------------------------
 * Receive side (tag -> reader): plain Manchester, no preamble, no SOF --
 * the tag's reply is exactly `nbits` data bits starting at its first edge.
 * Arms the GPIOTE edge counter right after the reader's last transmitted
 * edge and decodes until `nbits` bits are collected or the window times
 * out.
 * --------------------------------------------------------------------- */

/* How many leading runs to try dropping before decoding, and in which load
 * polarity: neither is known at compile time. A leading run can be the
 * arm-to-first-edge gap (clear_lf_counter_value() firing before the tag's
 * reply starts) or a short comparator glitch (lf hitag2 raw has shown both,
 * on real hardware, in the same capture) -- either misaligns every half-bit
 * after it by one run if not dropped, or if wrongly dropped. Rather than
 * guess which applies, try a handful of offsets; Manchester's own coding
 * check (lf_ia_decode_runs() stops at the first bit that breaks it) makes a
 * wrong offset or polarity fail outright, not decode plausible-looking
 * garbage, so whichever combination reaches nbits clean bits first is the
 * real one. */
#define HITAG2_RX_MAX_SKIP   4

static bool hitag2_receive_frame(uint8_t *out, uint8_t nbits, uint32_t timeout_ms) {
    cb_init(&g_cb, HITAG2_CB_SIZE, sizeof(uint16_t));
    register_rio_callback(hitag2_edge_cb);
    lf_125khz_radio_gpiote_enable(true);
    clear_lf_counter_value();

    uint16_t runs[HITAG2_MAX_RUNS];
    size_t n_runs = 0;
    uint8_t bits_buf[(64 + 7) / 8] = {0};
    bool ok = false;

    autotimer *p_at = bsp_obtain_timer(0);
    while (!ok && NO_TIMEOUT_1MS(p_at, timeout_ms)) {
        uint16_t run = 0;
        if (!cb_pop_front(&g_cb, &run)) {
            continue;
        }
        if (n_runs < HITAG2_MAX_RUNS) {
            runs[n_runs++] = run;
        }
        for (uint8_t skip = 0; !ok && skip < HITAG2_RX_MAX_SKIP && skip < n_runs; skip++) {
            static const uint32_t flags_try[] = {0, LF_IA_INVERT};
            for (uint8_t f = 0; !ok && f < ARRAY_SIZE(flags_try); f++) {
                if (lf_ia_decode_runs(runs + skip, n_runs - skip, LF_IA_CODING_MANCHESTER,
                                       HITAG2_BIT_FC, flags_try[f], bits_buf, nbits) >= nbits) {
                    ok = true;
                }
            }
        }
    }
    bsp_return_timer(p_at);
    lf_125khz_radio_gpiote_disable();
    unregister_rio_callback();
    cb_free(&g_cb);

    if (!ok) {
        return false;
    }
    memcpy(out, bits_buf, (size_t)(nbits + 7) / 8);
    return true;
}

/* -----------------------------------------------------------------------
 * Command helpers -- each is one request_timeslot() transmit followed by
 * one receive window, mirroring lf_em4x05_data.c's per-command structure.
 * --------------------------------------------------------------------- */

static uint32_t g_send_value;
static uint8_t  g_send_nbits;
static volatile bool g_timeslot_done = false;

/* app_timer tick (RTC1, APP_TIMER_CONFIG_RTC_FREQUENCY=1 -> 16384 Hz, ~61us/tick)
 * at the instant the last TX bit's edge finishes, for measuring the gap to
 * when RX actually arms -- see hitag2_reader_raw_capture(). */
static volatile uint32_t g_tx_done_tick;

/* request_timeslot()'s configure_next_event_earliest() (timeslot.c) asks for
 * NRF_RADIO_HFCLK_CFG_NO_GUARANTEE, so the SoftDevice may still be on the RC
 * oscillator when the callback runs -- it only promises the crystal for
 * NRF_RADIO_HFCLK_CFG_XTAL_GUARANTEED. Latched right before the PWM bit-bang
 * so hitag2_reader_raw_capture() can report whether the crystal was actually
 * up for this particular TX burst. */
static volatile bool g_hfclk_running_at_tx;

static void hitag2_send_timeslot_cb(void) {
    uint32_t hfclk_running = 0;
    sd_clock_hfclk_is_running(&hfclk_running);
    g_hfclk_running_at_tx = (hfclk_running != 0);
    hitag2_send_bits(g_send_value, g_send_nbits);
    g_tx_done_tick = app_timer_cnt_get();
    g_timeslot_done = true;
}

static bool hitag2_tx_rx(uint32_t tx_value, uint8_t tx_nbits,
                          uint8_t *rx_out, uint8_t rx_nbits,
                          uint32_t powerup_wait_us, uint32_t timeout_ms) {
    g_send_value    = tx_value;
    g_send_nbits    = tx_nbits;
    g_timeslot_done = false;

    /* Timeslot must cover: optional powerup wait + worst-case bit time
     * (T_1) per bit, with margin. */
    uint32_t slot_us = powerup_wait_us + ((uint32_t)tx_nbits * HITAG2_T_1_TC * 8) + 2000;
    request_timeslot(slot_us, hitag2_send_timeslot_cb);

    autotimer *p_wait = bsp_obtain_timer(0);
    while (!g_timeslot_done && NO_TIMEOUT_1MS(p_wait, 20)) {}
    bsp_return_timer(p_wait);

    if (!g_timeslot_done) {
        return false;
    }
    return hitag2_receive_frame(rx_out, rx_nbits, timeout_ms);
}

/* Byte-buffer send path, additive alongside hitag2_tx_rx above: only the
 * 64-bit Nr/Ar crypto challenge needs more than 32 bits, and the existing
 * uint32-based path (hardware-verified for password mode) is left alone. */
static uint8_t g_send8_buf[8];
static uint8_t g_send8_nbits;

static void hitag2_send8_timeslot_cb(void) {
    hitag2_send_bits_bytes(g_send8_buf, g_send8_nbits);
    g_timeslot_done = true;
}

static bool hitag2_tx_rx_bytes(const uint8_t *tx_bytes, uint8_t tx_nbits,
                                uint8_t *rx_out, uint8_t rx_nbits,
                                uint32_t powerup_wait_us, uint32_t timeout_ms) {
    memcpy(g_send8_buf, tx_bytes, (size_t)(tx_nbits + 7) / 8);
    g_send8_nbits   = tx_nbits;
    g_timeslot_done = false;

    uint32_t slot_us = powerup_wait_us + ((uint32_t)tx_nbits * HITAG2_T_1_TC * 8) + 2000;
    request_timeslot(slot_us, hitag2_send8_timeslot_cb);

    autotimer *p_wait = bsp_obtain_timer(0);
    while (!g_timeslot_done && NO_TIMEOUT_1MS(p_wait, 20)) {}
    bsp_return_timer(p_wait);

    if (!g_timeslot_done) {
        return false;
    }
    return hitag2_receive_frame(rx_out, rx_nbits, timeout_ms);
}

/* Debug aid: send START_AUTH and dump the raw rising-to-rising GPIOTE edge
 * intervals on LF_OA_OUT (Tc units, truncated to 0xff) in place of decoding
 * them -- for seeing what the comparator actually produces on real silicon,
 * separately from hitag2_receive_frame()'s own (both-edge) capture.
 *
 * Also reports rx_arm_gap_ticks: the app_timer (RTC1, ~61us/tick) gap
 * between the last TX edge finishing (timestamped inside the timeslot
 * callback) and RX actually arming here, after request_timeslot() has torn
 * its SD radio session down. Hitag2's reply window is only ~199-206 T0
 * (~1.6-1.65ms) after the reader's last edge -- unlike EM4x05/T55xx, whose
 * much longer windows this TX-then-arm structure was proven against -- so if
 * that teardown alone is in the same ballpark, RX would arm after the tag
 * has already answered and nothing would ever be seen.
 *
 * Also reports hfclk_running_out: whether the crystal (not the RC
 * oscillator) was the HFCLK source at the instant the TX burst ran, per
 * NRF_RADIO_HFCLK_CFG_NO_GUARANTEE above -- a false here means the bit
 * timing just sent was off nominal 16 MHz by whatever the RC oscillator's
 * tolerance is, not the values the classifier and the tag both expect. */
bool hitag2_reader_raw_capture(uint8_t *intervals, uint8_t max_n, uint8_t *n_out,
                                uint32_t *rx_arm_gap_ticks_out, bool *hfclk_running_out,
                                uint32_t timeout_ms) {
    *n_out = 0;
    *rx_arm_gap_ticks_out = 0;
    *hfclk_running_out = false;
    hitag2_hfclk_hold();
    start_lf_125khz_radio();
    bsp_delay_us(HITAG2_T_WAIT_POWERUP_TC * 8);

    g_send_value    = 0x18;  /* START_AUTH, 5 bits -- see hitag2_reader_get_uid */
    g_send_nbits    = 5;
    g_timeslot_done = false;
    uint32_t slot_us = ((uint32_t)5 * HITAG2_T_1_TC * 8) + 2000;
    request_timeslot(slot_us, hitag2_send_timeslot_cb);

    autotimer *p_wait = bsp_obtain_timer(0);
    while (!g_timeslot_done && NO_TIMEOUT_1MS(p_wait, 20)) {}
    bsp_return_timer(p_wait);

    if (!g_timeslot_done) {
        stop_lf_125khz_radio();
        hitag2_hfclk_release();
        return false;
    }

    *hfclk_running_out = g_hfclk_running_at_tx;
    uint32_t rx_arm_tick_pre = app_timer_cnt_get();
    cb_init(&g_cb, HITAG2_CB_SIZE, sizeof(uint16_t));
    register_rio_callback(hitag2_edge_cb);
    lf_125khz_radio_gpiote_enable(false);  /* rising-only: unchanged raw dump, not the run decode */
    clear_lf_counter_value();
    *rx_arm_gap_ticks_out = (rx_arm_tick_pre - g_tx_done_tick) & 0xFFFFFFu;

    uint8_t n = 0;
    autotimer *p_at = bsp_obtain_timer(0);
    while (n < max_n && NO_TIMEOUT_1MS(p_at, timeout_ms)) {
        uint16_t run = 0;
        if (!cb_pop_front(&g_cb, &run)) {
            continue;
        }
        /* Rising-only capture: hitag2_edge_cb()'s level bit is always 0
         * here, so this is the same rising-to-rising interval as before,
         * just truncated instead of clamped above 255 (unchanged in
         * practice -- real runs never get near that). */
        intervals[n++] = (uint8_t)run;
    }
    bsp_return_timer(p_at);
    lf_125khz_radio_gpiote_disable();
    unregister_rio_callback();
    cb_free(&g_cb);

    stop_lf_125khz_radio();
    hitag2_hfclk_release();
    *n_out = n;
    return n > 0;
}

bool hitag2_reader_get_uid(uint8_t uid[HITAG2_PAGE_SIZE], uint32_t timeout_ms) {
    /* START_AUTH is 5 bits, top-aligned in the frame: value 0x18 (binary
     * 11000) sent as the low 5 bits -- see HITAG2_START_AUTH's own comment
     * in protocols.h ("left 5 bits only"); hitag2_send_bits sends the low
     * `nbits` bits MSB-first, so passing 0x18/5 here reproduces "11000". */
    hitag2_hfclk_hold();
    start_lf_125khz_radio();
    bsp_delay_us(HITAG2_T_WAIT_POWERUP_TC * 8);
    bool ok = hitag2_tx_rx(0x18, 5, uid, 32, 0, timeout_ms);
    return ok;
}

bool hitag2_reader_read(const uint8_t password[HITAG2_PAGE_SIZE],
                         uint8_t pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE],
                         uint32_t timeout_ms) {
    memset(pages, 0, HITAG2_NUM_PAGES * HITAG2_PAGE_SIZE);

    /* hitag2_reader_get_uid() turns the field on unconditionally; this
     * function owns the field for the whole session and must turn it back
     * off on every exit (matches lf_em4x05_data.c's own reader functions --
     * leaving the field on across a failed attempt denies the tag the fresh
     * power-up its next START_AUTH needs). */
    if (!hitag2_reader_get_uid(pages[HITAG2_PAGE_UID], timeout_ms)) {
        stop_lf_125khz_radio();
        hitag2_hfclk_release();
        return false;
    }

    uint32_t pwd_val = ((uint32_t)password[0] << 24) | ((uint32_t)password[1] << 16) |
                        ((uint32_t)password[2] << 8)  | (uint32_t)password[3];
    uint8_t reply[4];
    if (!hitag2_tx_rx(pwd_val, 32, reply, 32, 0, timeout_ms)) {
        /* Tag may have ignored this (wrong password, or crypto mode) --
         * either way there is nothing more we can read without the key. */
        stop_lf_125khz_radio();
        hitag2_hfclk_release();
        return false;
    }
    memcpy(pages[HITAG2_PAGE_CONFIG], reply, 4);
    memcpy(pages[HITAG2_PAGE_PWD], password, 4);

    static const uint8_t remaining_pages[] = {2, 4, 5, 6, 7};
    for (size_t i = 0; i < sizeof(remaining_pages); i++) {
        uint8_t page = remaining_pages[i];
        uint16_t frame = hitag2_page_frame(HITAG2_READ_PAGE, page);
        uint8_t out[4];
        if (!hitag2_tx_rx(frame, 10, out, 32, 0, timeout_ms)) {
            stop_lf_125khz_radio();
            hitag2_hfclk_release();
            return false;
        }
        memcpy(pages[page], out, 4);
    }
    stop_lf_125khz_radio();
    hitag2_hfclk_release();
    return true;
}

bool hitag2_reader_crypto_read(const uint8_t key[HITAG2_KEY_SIZE],
                                uint8_t pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE],
                                uint32_t timeout_ms) {
    memset(pages, 0, HITAG2_NUM_PAGES * HITAG2_PAGE_SIZE);

    /* Field lifecycle is owned here, same reasoning as hitag2_reader_read(). */
    if (!hitag2_reader_get_uid(pages[HITAG2_PAGE_UID], timeout_ms)) {
        stop_lf_125khz_radio();
        hitag2_hfclk_release();
        return false;
    }

    /* Key and UID are plain little-endian decodes of the raw bytes, then bit-reversed per byte (hitag2_rev64/32) --
     * matches RfidResearchGroup/proxmark3's hitag2_crypto() reader function exactly. IV fixed to 0: Nr freshness
     * only matters to an attacker, not to this legitimate known-key read. */
    uint64_t key_raw = (uint64_t)key[0] | ((uint64_t)key[1] << 8) | ((uint64_t)key[2] << 16) |
                        ((uint64_t)key[3] << 24) | ((uint64_t)key[4] << 32) | ((uint64_t)key[5] << 40);
    uint64_t cs = hitag2_crypto_init(hitag2_rev64(key_raw), hitag2_rev32(le32(pages[HITAG2_PAGE_UID])), 0);

    uint8_t nrar[8];
    memset(nrar, 0x00, 4);           /* Nr */
    memset(nrar + 4, 0xFF, 4);
    hitag2_crypto_build_auth(&cs, nrar + 4);  /* Ar = inverted keystream, consumes 32 bits */

    uint8_t reply[4];
    if (!hitag2_tx_rx_bytes(nrar, 64, reply, 32, 0, timeout_ms)) {
        /* No answer: wrong key, or the tag is actually in password mode. */
        stop_lf_125khz_radio();
        hitag2_hfclk_release();
        return false;
    }
    hitag2_crypto_transcrypt(&cs, reply, 4, 0);
    memcpy(pages[HITAG2_PAGE_CONFIG], reply, 4);  /* already have page 3 -- skip re-reading it below */

    static const uint8_t remaining_pages[] = {1, 2, 4, 5, 6, 7};
    for (size_t i = 0; i < sizeof(remaining_pages); i++) {
        uint8_t page = remaining_pages[i];
        uint16_t frame = hitag2_page_frame(HITAG2_READ_PAGE, page);
        /* Every frame is encrypted once crypto mode is active, the command as much as the reply: pack the 10-bit
         * frame into bytes the same way a received frame would be, XOR it with the next keystream bits (1 byte +
         * 2 bits, matching the frame's own 10/8 split), then send the result. */
        uint8_t fb[2] = { (uint8_t)(frame >> 2), (uint8_t)((frame & 0x3u) << 6) };
        hitag2_crypto_transcrypt(&cs, fb, 1, 2);
        uint32_t enc_value = ((uint32_t)fb[0] << 2) | (fb[1] >> 6);

        uint8_t out[4];
        if (!hitag2_tx_rx(enc_value, 10, out, 32, 0, timeout_ms)) {
            stop_lf_125khz_radio();
            hitag2_hfclk_release();
            return false;
        }
        hitag2_crypto_transcrypt(&cs, out, 4, 0);
        memcpy(pages[page], out, 4);
    }
    stop_lf_125khz_radio();
    hitag2_hfclk_release();
    return true;
}
