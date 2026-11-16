#pragma once

// Bits to and from the timings of an interactive LF exchange. No hardware state: the engine and the host tests both
// use it.
//
// Bit strings are packed first-sent-first: bit i is bit (7 - i % 8) of byte i / 8.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    LF_IA_CODING_ASK,         // on-off: a 1 loads for the whole bit
    LF_IA_CODING_MANCHESTER,  // a 1 loads in the first half, a 0 in the second
    LF_IA_CODING_BIPHASE,     // the level flips at every bit start, and a 0 flips again mid-bit
} lf_ia_coding_t;

// LF_IA_INVERT swaps load and no load in every coding.
#define LF_IA_INVERT (1u << 0)
// For biphase, a 1 flips mid-bit instead of a 0.
#define LF_IA_BIPHASE_ONE_FLIPS (1u << 1)

// A run is one stretch at one load level: bit 15 is the level (1 = load on), bits 14..0 its length in carrier periods.
#define LF_IA_RUN_LOAD      (0x8000u)
#define LF_IA_RUN_LEN_MAX   (0x7FFFu)
#define LF_IA_RUN(load, len) ((uint16_t)(((load) ? LF_IA_RUN_LOAD : 0u) | ((len) & LF_IA_RUN_LEN_MAX)))
#define LF_IA_RUN_IS_LOAD(r) (((r) & LF_IA_RUN_LOAD) != 0u)
#define LF_IA_RUN_LEN(r)     ((uint16_t)((r) & LF_IA_RUN_LEN_MAX))

typedef enum {
    LF_IA_DECODE_OK,
    LF_IA_DECODE_ONE_CLASS,  // every interval falls in one class, so which bit value they carry is unknown
    LF_IA_DECODE_TOO_FEW,    // fewer than one interval
    LF_IA_DECODE_OVERFLOW,   // more bits than the output holds
} lf_ia_decode_status_t;

typedef struct {
    // Two classes exist only if the longest interval is at least this percentage of the shortest. Below it, the
    // spread is capture jitter around one value.
    uint16_t min_ratio_pct;
    // Map the short class to 1 and the long class to 0, instead of short to 0.
    bool short_is_one;
} lf_ia_decode_cfg_t;

#define LF_IA_DECODE_CFG_DEFAULT { .min_ratio_pct = 115, .short_is_one = false }

static inline bool lf_ia_bit_get(const uint8_t *bits, size_t i) {
    return (bits[i >> 3] >> (7u - (i & 7u))) & 1u;
}

static inline void lf_ia_bit_put(uint8_t *bits, size_t i, bool v) {
    const uint8_t m = (uint8_t)(1u << (7u - (i & 7u)));
    bits[i >> 3] = v ? (uint8_t)(bits[i >> 3] | m) : (uint8_t)(bits[i >> 3] & ~m);
}

// Classifies each interval between gap starts as a bit. The split sits midway between the shortest and longest
// interval of this burst, so it follows the reader's own timing rather than a fixed threshold. split_out (if not
// NULL) receives that midpoint, or the one class's mean if the result is LF_IA_DECODE_ONE_CLASS.
lf_ia_decode_status_t lf_ia_decode_intervals(const uint32_t *intervals, size_t n, const lf_ia_decode_cfg_t *cfg,
                                             uint8_t *bits, size_t max_bits, size_t *n_bits, uint32_t *split_out);

// The reverse of lf_ia_decode_intervals for a reader that codes a 0 as interval t0 and a 1 as t1. Returns the
// number of intervals written (n_bits, or 0 if max is too small).
size_t lf_ia_encode_intervals(const uint8_t *bits, size_t n_bits, uint32_t t0, uint32_t t1, uint32_t *out, size_t max);

// Encodes bits as load runs at bit_fc carrier periods per bit (Manchester and biphase need it even). Adjacent runs
// at the same level merge. The frame starts with the load level its first half-bit needs and ends after the last
// bit, so a caller that idles with no load sees any leading or trailing no-load run as part of the idle. Returns the
// number of runs, or 0 if they do not fit in max_runs or the arguments are invalid.
size_t lf_ia_encode_runs(const uint8_t *bits, size_t n_bits, lf_ia_coding_t coding, uint16_t bit_fc, uint32_t flags,
                         uint16_t *runs, size_t max_runs);

// Decodes load runs back to bits: each run is rounded to whole half-bits, then read per coding. A trailing lone
// half-bit is dropped. The decode stops at the first bit that breaks the coding (a Manchester bit with both halves
// equal, a biphase bit with no flip at its start), because whatever follows a frame (noise, or another device
// answering) is not part of it. Returns the number of bits written before that, which a caller checks against the
// frame length it expects. Returns 0 if the bits do not fit in max_bits.
//
// lf_ia_decode_runs_ex also sets clean: true if the decode ran to the end of the runs (so the frame ended in quiet),
// false if it stopped at a bit that broke the coding.
size_t lf_ia_decode_runs(const uint16_t *runs, size_t n_runs, lf_ia_coding_t coding, uint16_t bit_fc, uint32_t flags,
                         uint8_t *bits, size_t max_bits);
size_t lf_ia_decode_runs_ex(const uint16_t *runs, size_t n_runs, lf_ia_coding_t coding, uint16_t bit_fc,
                            uint32_t flags, uint8_t *bits, size_t max_bits, bool *clean);

// The frame's length in carrier periods.
uint32_t lf_ia_runs_total_fc(const uint16_t *runs, size_t n_runs);

typedef struct {
    size_t first;       // the answer's first loaded sample
    int32_t idle;       // the line's level with no load
    int32_t load;       // the level the load takes it to
    int32_t threshold;  // the level the runs are sliced at
} lf_ia_envelope_info_t;

// Turns a reader's envelope, sampled once per carrier period, into load runs. Samples [skip, window) are taken as the
// idle line (no load), so the answer must start at or after window. The load level is the extreme after window on
// either side of idle. If it is less than min_depth away, there is no answer and the result is 0. The answer starts at
// the first sample past the midpoint between idle and load. The runs are sliced slice_pct percent of the way from the
// answer's other extreme to the load level: 50 is the middle of the swing, and a lower value suits a detector that
// returns from load slowly. The runs end at a stretch of either level longer than max_idle_fc, which is not part of
// the answer. A last no-load run is cut to half_fc, because it may still hold a final half-bit. Returns the number of
// runs.
size_t lf_ia_envelope_runs(const int16_t *s, size_t n, size_t skip, size_t window, int32_t min_depth, uint8_t slice_pct,
                           uint16_t half_fc, uint16_t max_idle_fc, uint16_t *runs, size_t max_runs,
                           lf_ia_envelope_info_t *info);
