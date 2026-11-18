#include "lf_hitag2_frame.h"

#include "lf_ia_codec.h"

#define HT2_SOF_MIN (5u)
#define HT2_SOF_MAX (6u)

void ht2_frame_reset(ht2_frame_t *f) {
    f->sof = 0;
}

bool ht2_frame_page(ht2_frame_t *f, const uint8_t *bits, size_t n, bool clean, uint32_t *page) {
    (void)clean;
    if (f->sof == 0) {
        // Learn the SOF length from an answer of exactly 37 or 38 bits that
        // opens with that many ones. The decoder marks an answer clean only
        // when the runs run out; a capture that runs past the reply into the
        // settled field ends on a coding violation instead, so a complete
        // frame reads back not-clean. The tight length and all-ones prefix
        // pin the SOF without the clean flag: junk after the frame would push
        // n past 38 (rejected here), and a short frame below 37.
        if (n < 32u + HT2_SOF_MIN || n > 32u + HT2_SOF_MAX) {
            return false;
        }
        for (size_t i = 0; i < n - 32u; i++) {
            if (!lf_ia_bit_get(bits, i)) {
                return false;
            }
        }
        f->sof = (uint8_t)(n - 32u);
    }

    const size_t sof = f->sof;
    if (n < sof + 32u) {
        return false;
    }
    for (size_t i = 0; i < sof; i++) {
        if (!lf_ia_bit_get(bits, i)) {
            return false;
        }
    }
    uint32_t v = 0;
    for (size_t i = 0; i < 32u; i++) {
        v = v << 1 | (lf_ia_bit_get(bits, sof + i) ? 1u : 0u);
    }
    *page = v;
    return true;
}

void ht2_agree_reset(ht2_agree_t *a) {
    a->n = 0;
}

bool ht2_agree_add(ht2_agree_t *a, uint32_t value, uint32_t *agreed) {
    for (uint8_t i = 0; i < a->n; i++) {
        if (a->seen[i] == value) {
            *agreed = value;
            return true;
        }
    }
    if (a->n < HT2_AGREE_MAX) {
        a->seen[a->n++] = value;
    }
    return false;
}
