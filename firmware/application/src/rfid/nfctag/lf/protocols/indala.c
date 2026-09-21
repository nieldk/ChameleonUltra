#include "indala.h"

#include <stdlib.h>
#include <string.h>

#include "nordic_common.h"
#include "protocols.h"
#include "t55xx.h"
#include "tag_base_type.h"
#include "utils/pskdemod.h"

#define NRF_LOG_MODULE_NAME indala
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
NRF_LOG_MODULE_REGISTER();

#define INDALA_RAW_SIZE (64)  // 64-bit frame
#define INDALA_DATA_SIZE (8)  // 8 bytes stored

// PSK1 fc/2 RF/32: 16 fc/2 subcarrier cycles per bit.
// Each fc/2 cycle = 2 entries: one carrier cycle ON, one OFF (or vice versa).
// The modulator builds a PWM-format array that is converted to a simple 0/1
// timer pattern by psk_build_pattern() in lf_tag_em.c.
// Timer3 ISR plays back the pattern at exactly 125 kHz (8us per entry).
#define INDALA_PSK_CYCLES_PER_BIT (16)
#define INDALA_PSK_ENTRIES_PER_CYCLE (2)
#define INDALA_PSK_COUNTER_TOP (4)   // arbitrary (only ch0 > 0 vs == 0 matters for pattern)

#define INDALA_T55XX_BLOCK_COUNT (3) // config + 2 data blocks

// Indala 64-bit preamble (33 bits): {1,0,1, 29×0, 1}
// In shift register (MSB = first bit): bits 63..31 must match exactly
#define INDALA_PREAMBLE_MASK  ((uint64_t)0xFFFFFFFF80000000ULL)
#define INDALA_PREAMBLE_CHECK ((uint64_t)0xA000000080000000ULL)

// Reader decoder: Period-8 DDC for PSK1 fc/8 at 125kHz SAADC.
//
// T55XX configured for fc/8: subcarrier at 15.625kHz, 8 SAADC samples per cycle.
// Rectangular wave mixer extracts subcarrier: I=[+1,+1,+1,+1,-1,-1,-1,-1],
// Q=[-1,-1,+1,+1,+1,+1,-1,-1] (90° shifted, orthogonal).
// Integrate 32 samples per bit → one (I,Q) complex vector per bit.
// Differential PSK1: dot product of adjacent IQ vectors.
#define INDALA_BPS (32)             // samples per bit (32 carrier cycles at RF/32)
#define INDALA_PSK_BUF_SIZE (6144)  // ~192 bits (3 frames)
#define INDALA_SKIP (1024)          // skip first 32 bits — settling transient
#define INDALA_MAX_BITS (160)       // max bits in decode buffer

typedef struct {
    uint8_t data[INDALA_DATA_SIZE];
    psk_t *modem;
} indala_codec;

static indala_codec *indala_alloc(void) {
    indala_codec *codec = malloc(sizeof(indala_codec));
    codec->modem = psk_alloc(PSK166_BITRATE_43, 0);  // fc/2 @ 166.67 kHz; struct only
    codec->modem->buf_size = INDALA_PSK_BUF_SIZE;
    codec->modem->samples = psk_shared_samples;    // shared static buffer
    return codec;
};

static void indala_free(indala_codec *d) {
    if (d->modem) {
        d->modem->samples = NULL;  // static buffer, don't free
        psk_free(d->modem);
        d->modem = NULL;
    }
    free(d);
};

static uint8_t *indala_get_data(indala_codec *d) {
    return d->data;
};

static void indala_decoder_start(indala_codec *d, uint8_t format) {
    memset(d->data, 0, INDALA_DATA_SIZE);
    d->modem->sample_count = 0;
    d->modem->phase_offset = 0;
};

static bool indala_check_preamble(uint64_t reg) {
    return (reg & INDALA_PREAMBLE_MASK) == INDALA_PREAMBLE_CHECK;
}

static void indala_extract_data(indala_codec *d, uint64_t reg) {
    // Store raw 64-bit frame as 8 bytes, MSB first
    for (int i = 0; i < INDALA_DATA_SIZE; i++) {
        d->data[i] = (uint8_t)(reg >> (56 - i * 8));
    }
}

// ── fc/2 PSK1 read (166.67 kHz capture) ─────────────────────────────────────
// Real Indala flips the 125 kHz CARRIER phase per data bit; the tuned LF
// antenna filters out the 62.5 kHz subcarrier. Sampled at 166.667 kHz the
// carrier aliases to 41.67 kHz = DFT bin 2, and psk166_correlate_iq() returns a
// signed scalar whose sign tracks carrier phase, so a sign flip between adjacent
// bits is a PSK1 transition.
//
// Bit period = 32 carrier cycles = 256 µs = 128/3 samples (42.667) at 166.667
// kHz. Bit boundaries step with that fixed-point ratio so error does not
// accumulate across a 64-bit frame.
#define IND166_BIT_NUM   (128)   // bit spacing numerator (128/3 = 42.667 samples/bit)
#define IND166_BIT_DEN   (3)
#define IND166_OFFSETS   (43)    // alignment search span: one bit period
#define IND166_CORR_LEN  (40)    // per-bit integration: 10 alias cycles (clean DFT); bench-tunable 40..43

static inline uint16_t ind166_base(uint8_t off, uint16_t bit) {
    return (uint16_t)(INDALA_SKIP + off + ((uint32_t)bit * IND166_BIT_NUM) / IND166_BIT_DEN);
}

static bool indala_try_decode(indala_codec *d) {
    psk_t *m = d->modem;
    uint16_t n = m->sample_count;

    // Need: skip + one bit of alignment slack + 64 bits.
    if (n < INDALA_SKIP + (IND166_BIT_NUM / IND166_BIT_DEN)
            + (uint32_t)INDALA_RAW_SIZE * IND166_BIT_NUM / IND166_BIT_DEN)
        return false;

    // Phase 1: alignment search. The offset that maximises total bit energy has
    // each integration window inside one bit; wrong offsets straddle transitions
    // and lose energy.
    uint8_t best_off = 0;
    int64_t best_mag = 0;
    for (uint8_t off = 0; off < IND166_OFFSETS; off++) {
        int64_t total = 0;
        for (uint8_t bit = 0; bit < INDALA_RAW_SIZE; bit++) {
            uint16_t base = ind166_base(off, bit);
            if ((uint32_t)base + IND166_CORR_LEN > n) break;
            int32_t sc = psk166_correlate_iq(m, base, IND166_CORR_LEN);
            total += (int64_t)sc * sc;
        }
        if (total > best_mag) { best_mag = total; best_off = off; }
    }

    // Phase 2: signed per-bit correlation at best alignment.
    int32_t bit_s[INDALA_MAX_BITS];
    uint16_t num_bits = 0;
    for (uint16_t bit = 0; bit < INDALA_MAX_BITS; bit++) {
        uint16_t base = ind166_base(best_off, bit);
        if ((uint32_t)base + IND166_CORR_LEN > n) break;
        bit_s[num_bits++] = psk166_correlate_iq(m, base, IND166_CORR_LEN);
    }
    if (num_bits < INDALA_RAW_SIZE) return false;

    NRF_LOG_INFO("IND fc/2: off=%d nb=%d mag=%d",
        best_off, num_bits, (int32_t)(best_mag >> 20));

    // Phase 3: differential PSK1 — sign flip between adjacent bits = transition.
    uint8_t diff_bits[INDALA_MAX_BITS];
    uint16_t ndiff = 0;
    for (uint16_t j = 1; j < num_bits; j++) {
        int64_t prod = (int64_t)bit_s[j] * bit_s[j - 1];
        diff_bits[ndiff++] = (prod < 0) ? 1 : 0;
    }

    // Phase 4: cumulative XOR recovers raw bits; unknown start phase → the
    // preamble check also tries the inverse.
    uint8_t raw_bits[INDALA_MAX_BITS];
    raw_bits[0] = 0;
    for (uint16_t j = 0; j < ndiff; j++) raw_bits[j + 1] = raw_bits[j] ^ diff_bits[j];
    uint16_t nraw = ndiff + 1;

    for (uint16_t pos = 0; pos + INDALA_RAW_SIZE <= nraw; pos++) {
        uint64_t reg = 0;
        for (uint8_t j = 0; j < INDALA_RAW_SIZE; j++) reg = (reg << 1) | raw_bits[pos + j];
        if (indala_check_preamble(reg))  {
            NRF_LOG_INFO("IND fc/2: DONE pos=%d reg=%08x%08x",
                pos, (uint32_t)(reg >> 32), (uint32_t)reg);
            indala_extract_data(d, reg);  return true;
        }
        if (indala_check_preamble(~reg)) {
            NRF_LOG_INFO("IND fc/2: DONE pos=%d reg=%08x%08x (inv)",
                pos, (uint32_t)((~reg) >> 32), (uint32_t)(~reg));
            indala_extract_data(d, ~reg); return true;
        }
    }
    return false;
}

static bool indala_decoder_feed(indala_codec *d, uint16_t val) {
    psk_t *m = d->modem;
    psk_feed_sample(m, val);

    // Wait for a full buffer before attempting decode.
    if (m->sample_count < m->buf_size) {
        return false;
    }

    if (indala_try_decode(d)) {
        return true;
    }

    // Shift ~one frame of fresh samples in (psk_shift keeps psk166 phase_offset coherent).
    psk_shift(m, (uint16_t)((uint32_t)INDALA_RAW_SIZE * IND166_BIT_NUM / IND166_BIT_DEN));
    return false;
};

// PSK1 modulator: fc/2 carrier at RF/32 (1 MHz PWM clock, counter_top=8)
// Each fc/2 cycle uses 2 PWM entries with counter_top=8 (8us each):
//   Phase A (bit=0): {ch0=CT,ct=CT},{ch0=0,ct=CT} -> FET ON 8us, OFF 8us
//   Phase B (bit=1): {ch0=0,ct=CT},{ch0=CT,ct=CT} -> FET OFF 8us, ON 8us (180 shifted)
// 16 fc/2 cycles per bit = 32 PWM entries per bit.
static const nrf_pwm_sequence_t *indala_modulator(indala_codec *d, uint8_t *buf) {
    int k = 0;

    for (int i = 0; i < INDALA_RAW_SIZE; i++) {
        uint8_t byte_idx = i / 8;
        uint8_t bit_idx = 7 - (i % 8); // MSB first
        bool cur_bit = (buf[byte_idx] >> bit_idx) & 1;

        // PSK1: phase = data bit value
        // ch0 = COUNTER_TOP -> 100% duty (FET ON), ch0 = 0 -> 0% duty (FET OFF)
        uint16_t first  = cur_bit ? 0 : INDALA_PSK_COUNTER_TOP;
        uint16_t second = cur_bit ? INDALA_PSK_COUNTER_TOP : 0;

        for (int j = 0; j < INDALA_PSK_CYCLES_PER_BIT; j++) {
            psk_shared_pwm_vals[k].channel_0 = first;
            psk_shared_pwm_vals[k].counter_top = INDALA_PSK_COUNTER_TOP;
            k++;
            psk_shared_pwm_vals[k].channel_0 = second;
            psk_shared_pwm_vals[k].counter_top = INDALA_PSK_COUNTER_TOP;
            k++;
        }
    }

    psk_shared_pwm_seq.length = k * 4;
    return &psk_shared_pwm_seq;
};

const protocol indala = {
    .tag_type = TAG_TYPE_INDALA,
    .data_size = INDALA_DATA_SIZE,
    .alloc = (codec_alloc)indala_alloc,
    .free = (codec_free)indala_free,
    .get_data = (codec_get_data)indala_get_data,
    .modulator = (modulator)indala_modulator,
    .decoder =
        {
            .start = (decoder_start)indala_decoder_start,
            .feed = (decoder_feed)indala_decoder_feed,
        },
};

// Encode Indala 64-bit data to T55xx blocks
uint8_t indala_t55xx_writer(uint8_t *uid, uint32_t *blks) {
    blks[0] = T5577_INDALA_64_CONFIG;
    blks[1] = (uid[0] << 24) | (uid[1] << 16) | (uid[2] << 8) | uid[3];
    blks[2] = (uid[4] << 24) | (uid[5] << 16) | (uid[6] << 8) | uid[7];
    return INDALA_T55XX_BLOCK_COUNT;
}
