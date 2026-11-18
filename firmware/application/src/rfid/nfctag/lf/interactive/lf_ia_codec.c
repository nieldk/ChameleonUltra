#include "lf_ia_codec.h"

#include <string.h>

lf_ia_decode_status_t lf_ia_decode_intervals(const uint32_t *intervals, size_t n, const lf_ia_decode_cfg_t *cfg,
                                             uint8_t *bits, size_t max_bits, size_t *n_bits, uint32_t *split_out) {
    *n_bits = 0;
    if (n == 0) {
        return LF_IA_DECODE_TOO_FEW;
    }

    uint32_t lo = intervals[0], hi = intervals[0];
    uint64_t sum = 0;
    for (size_t i = 0; i < n; i++) {
        lo = intervals[i] < lo ? intervals[i] : lo;
        hi = intervals[i] > hi ? intervals[i] : hi;
        sum += intervals[i];
    }

    uint32_t split;
    if ((uint64_t)hi * 100u < (uint64_t)lo * cfg->min_ratio_pct) {
        if (cfg->fallback_t0_us == 0 || cfg->fallback_t1_us == 0) {
            if (split_out) {
                *split_out = (uint32_t)(sum / n);
            }
            return LF_IA_DECODE_ONE_CLASS;
        }
        // No second class to self-calibrate against (every bit this frame carries is the same value): fall back to
        // the module's known fixed timing instead of refusing a protocol-valid frame.
        split = (cfg->fallback_t0_us + cfg->fallback_t1_us) / 2u;
    } else {
        split = lo + (hi - lo) / 2u;
    }
    if (n > max_bits) {
        return LF_IA_DECODE_OVERFLOW;
    }

    if (split_out) {
        *split_out = split;
    }
    for (size_t i = 0; i < n; i++) {
        const bool is_long = intervals[i] > split;
        lf_ia_bit_put(bits, i, is_long != cfg->short_is_one);
    }
    *n_bits = n;
    return LF_IA_DECODE_OK;
}

size_t lf_ia_encode_intervals(const uint8_t *bits, size_t n_bits, uint32_t t0, uint32_t t1, uint32_t *out, size_t max) {
    if (n_bits > max) {
        return 0;
    }
    for (size_t i = 0; i < n_bits; i++) {
        out[i] = lf_ia_bit_get(bits, i) ? t1 : t0;
    }
    return n_bits;
}

// Appends a stretch of one level, merging it into the previous run if that run has the same level.
static bool run_append(uint16_t *runs, size_t *n, size_t max, bool load, uint32_t len) {
    if (len == 0) {
        return true;
    }
    if (*n > 0 && LF_IA_RUN_IS_LOAD(runs[*n - 1]) == load) {
        const uint32_t merged = LF_IA_RUN_LEN(runs[*n - 1]) + len;
        if (merged <= LF_IA_RUN_LEN_MAX) {
            runs[*n - 1] = LF_IA_RUN(load, merged);
            return true;
        }
    }
    if (len > LF_IA_RUN_LEN_MAX || *n >= max) {
        return false;
    }
    runs[(*n)++] = LF_IA_RUN(load, len);
    return true;
}

// The load level of each half of bit i, before LF_IA_INVERT. prev is the level of the half-bit before this bit.
static void bit_halves(lf_ia_coding_t coding, bool bit, uint32_t flags, bool prev, bool *h0, bool *h1) {
    switch (coding) {
        case LF_IA_CODING_MANCHESTER:
            *h0 = bit;
            *h1 = !bit;
            break;
        case LF_IA_CODING_BIPHASE: {
            const bool mid_flip = (flags & LF_IA_BIPHASE_ONE_FLIPS) ? bit : !bit;
            *h0 = !prev;
            *h1 = mid_flip ? prev : *h0;
            break;
        }
        case LF_IA_CODING_ASK:
        default:
            *h0 = bit;
            *h1 = bit;
            break;
    }
}

size_t lf_ia_encode_runs(const uint8_t *bits, size_t n_bits, lf_ia_coding_t coding, uint16_t bit_fc, uint32_t flags,
                         uint16_t *runs, size_t max_runs) {
    if (bit_fc == 0 || (coding != LF_IA_CODING_ASK && (bit_fc & 1u))) {
        return 0;
    }
    const uint32_t half = bit_fc / 2u;
    const bool inv = (flags & LF_IA_INVERT) != 0;
    size_t n = 0;
    // Biphase's first bit flips from the idle level, which is no load before inversion.
    bool prev = false;

    for (size_t i = 0; i < n_bits; i++) {
        bool h0, h1;
        bit_halves(coding, lf_ia_bit_get(bits, i), flags, prev, &h0, &h1);
        if (coding == LF_IA_CODING_ASK) {
            if (!run_append(runs, &n, max_runs, h0 != inv, bit_fc)) {
                return 0;
            }
        } else {
            if (!run_append(runs, &n, max_runs, h0 != inv, half) || !run_append(runs, &n, max_runs, h1 != inv, half)) {
                return 0;
            }
        }
        prev = h1;
    }
    return n;
}

size_t lf_ia_decode_runs(const uint16_t *runs, size_t n_runs, lf_ia_coding_t coding, uint16_t bit_fc, uint32_t flags,
                         uint8_t *bits, size_t max_bits) {
    return lf_ia_decode_runs_ex(runs, n_runs, coding, bit_fc, flags, bits, max_bits, NULL);
}

size_t lf_ia_decode_runs_ex(const uint16_t *runs, size_t n_runs, lf_ia_coding_t coding, uint16_t bit_fc,
                            uint32_t flags, uint8_t *bits, size_t max_bits, bool *clean) {
    bool dummy;
    if (clean == NULL) {
        clean = &dummy;
    }
    *clean = false;
    if (bit_fc == 0 || (coding != LF_IA_CODING_ASK && (bit_fc & 1u))) {
        return 0;
    }
    const uint32_t unit = coding == LF_IA_CODING_ASK ? bit_fc : bit_fc / 2u;
    const bool inv = (flags & LF_IA_INVERT) != 0;
    const size_t per_bit = coding == LF_IA_CODING_ASK ? 1u : 2u;

    // Walk the runs as a stream of units (half-bits, or whole bits for ASK), one bit at a time.
    size_t r = 0;
    uint32_t left = 0;  // units still to read from run r
    bool level = false;
    size_t n = 0;
    bool prev = false;

    for (;;) {
        bool h[2];
        for (size_t k = 0; k < per_bit; k++) {
            while (left == 0) {
                if (r >= n_runs) {
                    *clean = true;
                    return n;  // a trailing half-bit is dropped
                }
                left = (LF_IA_RUN_LEN(runs[r]) + unit / 2u) / unit;
                level = LF_IA_RUN_IS_LOAD(runs[r]) != inv;
                r++;
            }
            h[k] = level;
            left--;
        }
        if (n >= max_bits) {
            return 0;
        }

        bool bit;
        switch (coding) {
            case LF_IA_CODING_MANCHESTER:
                if (h[0] == h[1]) {
                    return n;
                }
                bit = h[0];
                break;
            case LF_IA_CODING_BIPHASE: {
                if (n > 0 && h[0] == prev) {
                    return n;
                }
                const bool mid_flip = h[0] != h[1];
                bit = (flags & LF_IA_BIPHASE_ONE_FLIPS) ? mid_flip : !mid_flip;
                prev = h[1];
                break;
            }
            case LF_IA_CODING_ASK:
            default:
                bit = h[0];
                break;
        }
        lf_ia_bit_put(bits, n++, bit);
    }
}

uint32_t lf_ia_runs_total_fc(const uint16_t *runs, size_t n_runs) {
    uint32_t t = 0;
    for (size_t i = 0; i < n_runs; i++) {
        t += LF_IA_RUN_LEN(runs[i]);
    }
    return t;
}

size_t lf_ia_envelope_runs(const int16_t *s, size_t n, size_t skip, size_t window, int32_t min_depth, uint8_t slice_pct,
                           uint16_t half_fc, uint16_t max_idle_fc, uint16_t *runs, size_t max_runs,
                           lf_ia_envelope_info_t *info) {
    memset(info, 0, sizeof(*info));
    if (skip >= window || window + 3 > n) {
        return 0;
    }
    int64_t sum = 0;
    for (size_t i = skip; i < window; i++) {
        sum += s[i];
    }
    const int32_t idle = (int32_t)(sum / (int64_t)(window - skip));

    // The extreme of a 3-sample mean, so one noisy sample cannot set the load level.
    int32_t lo = INT32_MAX, hi = INT32_MIN;
    for (size_t i = window + 1; i + 1 < n; i++) {
        const int32_t m = (s[i - 1] + s[i] + s[i + 1]) / 3;
        lo = m < lo ? m : lo;
        hi = m > hi ? m : hi;
    }
    const int32_t load = (idle - lo) > (hi - idle) ? lo : hi;
    const int32_t depth = load > idle ? load - idle : idle - load;
    info->idle = idle;
    info->load = load;
    if (depth < min_depth || depth == 0) {
        return 0;
    }
    const bool load_low = load < idle;
    const int32_t first_thr = idle + (load - idle) / 2;
    const int32_t other = load_low ? hi : lo;
    const int32_t thr = other + (int32_t)(((int64_t)(load - other) * slice_pct) / 100);
    info->threshold = thr;

    size_t i = window;
    while (i < n && ((s[i] < first_thr) != load_low)) {
        i++;
    }
    if (i >= n) {
        return 0;
    }
    info->first = i;

    size_t nr = 0;
    bool level = true;
    uint32_t len = 0;
    for (; i < n; i++) {
        const bool l = (s[i] < thr) == load_low;
        if (l == level) {
            len++;
            if (len > max_idle_fc) {
                break;
            }
            continue;
        }
        if (nr >= max_runs || len > LF_IA_RUN_LEN_MAX) {
            return 0;
        }
        runs[nr++] = LF_IA_RUN(level, len);
        level = l;
        len = 1;
    }
    // A stretch past max_idle_fc ends the answer, and may still hold its final half-bit. A no-load one usually does. A
    // loaded one does when the tag rests loaded (a CU emulating one listens with its load on), so its last load half
    // runs on into the rest. A loaded stretch with nothing before it is no answer.
    const bool ended = len > max_idle_fc;
    if (len > 0 && nr < max_runs && !(level && ended && nr == 0)) {
        if ((!level || ended) && len > half_fc) {
            len = half_fc;
        }
        runs[nr++] = LF_IA_RUN(level, len);
    }
    return nr;
}
