#pragma once

// The reader side of an interactive LF exchange: send a command by field gaps, then capture and decode the tag's
// load-modulated answer. A protocol supplies the link timings and the command bits, and reads the answer bits.
//
// The command goes out inside a SoftDevice timeslot, with busy-wait timing and no interrupts. The answer is captured
// with no software in the path: the field PWM triggers one ADC sample per carrier period through PPI, into a buffer
// by DMA, starting when the command ends. The samples are decoded once the capture is complete.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "lf_ia_codec.h"

#define LF_RDR_MAX_TX_BITS  (128u)
#define LF_RDR_MAX_RX_BITS  (256u)
#define LF_RDR_CAPTURE_MAX  (4096u)  // carrier periods, 32.8 ms
#define LF_RDR_MAX_RUNS     (600u)

// Bench diagnosis, in eof_gap: start the capture before the command instead of after it, so the reader's own
// field gaps show in the samples.
#define LF_RDR_CAPTURE_COMMAND (0x02u)
// In eof_gap: load the antenna through Q3 (LF_MOD) during each gap. With only the drive stopped, the antenna's tuned
// circuit keeps ringing at its own resonance for over 200 µs, so a gap is a shallow dip rather than the field going
// off. The load drains it through VD1 and R11 within a few cycles.
#define LF_RDR_DAMP_GAPS (0x04u)

typedef struct __attribute__((packed)) {
    // Command: pulse-interval coding. Each bit is a gap of gap_us, then field on until the bit's period ends.
    uint16_t gap_us;
    uint16_t bit0_us;   // a 0's period, from its gap's start to the next gap's start
    uint16_t bit1_us;
    uint8_t eof_gap;    // bit 0: one more gap after the last bit. LF_RDR_CAPTURE_COMMAND: see below
    uint16_t stop_us;   // field on after the frame. The answer window counts from the end of it
    // Answer.
    uint8_t coding;     // lf_ia_coding_t
    uint8_t coding_flags;
    uint16_t bit_fc;    // carrier periods per bit
    uint16_t window_us; // the answer starts no earlier than this. The line before it is taken as idle
    uint16_t capture_n; // carrier periods to capture after the frame, at most LF_RDR_CAPTURE_MAX
    int16_t min_depth;  // ADC counts: a smaller swing from idle is no answer
    uint8_t slice_pct;  // where the answer is sliced, see lf_ia_envelope_runs. 0 means 50
} lf_rdr_link_t;

typedef struct {
    size_t n_bits;
    bool clean;  // the decode ran to the answer's end, rather than stopping at junk after it
    uint8_t bits[LF_RDR_MAX_RX_BITS / 8];
    size_t n_runs;
    lf_ia_envelope_info_t env;
} lf_rdr_reply_t;

void lf_rdr_field(bool on);

// Sends tx (n_tx bits, first bit first) and decodes the answer into rx. If power_up_us is not 0, the field is
// switched on that long before the command, inside the same timeslot, for a tag that must hear its first command in
// a window after power-up. Returns false if the arguments are invalid or the capture did not complete. A missing
// answer returns true with rx->n_bits 0.
bool lf_rdr_transact(const lf_rdr_link_t *link, const uint8_t *tx, size_t n_tx, uint32_t power_up_us,
                     lf_rdr_reply_t *rx);

// The last capture's samples and load runs, for diagnosis.
const int16_t *lf_rdr_capture(size_t *n);
const uint16_t *lf_rdr_runs(size_t *n);
