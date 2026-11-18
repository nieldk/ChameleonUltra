#pragma once

// Taking a Hitag 2 reader's answers apart, with no hardware: the start-of-frame, and agreement between answers.
//
// Hitag 2 password mode has no CRC, so a decode that slips its framing returns a plausible wrong page. Two guards:
// the start-of-frame length is learned once per use from an answer that ended cleanly, so a later answer with junk
// after it cannot shift its page; and a page counts only when two answers agree.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// One use of the reader (a scan or a read), from the field's power-up. The start-of-frame length is the tag's: the
// datasheet gives 5 ones, and some tags (and the PM3's simulation) send 6.
typedef struct {
    uint8_t sof;  // 0 until learned
} ht2_frame_t;

void ht2_frame_reset(ht2_frame_t *f);

// Takes the 32-bit page out of an answer of n bits. clean says the decode ran to the answer's end rather than stopping
// at junk after it. Until the start-of-frame length is known, only a clean answer of 37 or 38 bits counts, and it
// sets the length. After that, an answer counts if it opens with that many ones and has 32 bits after them; bits past
// those are ignored. Returns false if the answer does not count.
bool ht2_frame_page(ht2_frame_t *f, const uint8_t *bits, size_t n, bool clean, uint32_t *page);

#define HT2_AGREE_MAX (4u)

// Answers to one question (a page, or the UID), until two agree.
typedef struct {
    uint32_t seen[HT2_AGREE_MAX];
    uint8_t n;
} ht2_agree_t;

void ht2_agree_reset(ht2_agree_t *a);

// Adds an answer. Returns true, with the value in agreed, if it matches an earlier one. The first HT2_AGREE_MAX answers
// are remembered; the caller bounds the tries.
bool ht2_agree_add(ht2_agree_t *a, uint32_t value, uint32_t *agreed);
