#pragma once

// The exchange trace: one record per command, and one at the end of each field session that had a command, kept in
// retained RAM and read over USB. A record says what the engine captured, how it decoded it, what the module answered,
// and when the answer went out, which is what tells a capture fault from a decode, module or modulation fault.
//
// The first LF_IA_TRACE_KEEP records since a clear stay put, and the rest roll, so a long run at a reader keeps both
// how the exchange started and how it ended. Field sessions with no command only count in the counters.

#include <stddef.h>
#include <stdint.h>

#include "lf_ia.h"
#include "lf_ia_debug.h"

#ifndef LF_IA_DEBUG
#define LF_IA_DEBUG (0)
#endif

#if LF_IA_DEBUG
#define LF_IA_TRACE_RECORDS (32u)
#define LF_IA_TRACE_KEEP    (8u)   // the first records since a clear, never overwritten
#else
// The full ring is bench-only RAM (32 * ~280 bytes); a production build keeps just the latest command, since the
// summary counters (lf_ia_trace_stats) are what a field check actually reads. Build with LF_IA_DEBUG=1 for the ring.
#define LF_IA_TRACE_RECORDS (2u)
#define LF_IA_TRACE_KEEP    (1u)
#endif
#define LF_IA_TRACE_GAPS    (48u)

enum {
    LF_IA_TR_FIELD_OFF = 2,  // the end of a session that had a command (1 was a field-on record)
    LF_IA_TR_COMMAND = 3,
};

// Record flags.
#define LF_IA_TRF_LATE          (1u << 0)  // the answer started after its due time
#define LF_IA_TRF_GAPS_DROPPED  (1u << 1)  // the command had more gaps than the engine keeps
#define LF_IA_TRF_ENCODE_FAILED (1u << 2)  // the response did not fit the run buffer
#define LF_IA_TRF_FIELD_BACK    (1u << 3)  // FIELD_OFF only: the recheck found the field, so a new session started

typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t verdict;
    uint8_t decode_status;
    uint8_t flags;
    uint32_t t_us;         // FIELD_OFF: when the field went; COMMAND: the end of its last gap
    uint32_t t_detect_us;  // when the engine saw the command's end
    uint32_t t_ready_us;   // when the answer was armed, after decode, module and encode
    uint32_t t_due_us;     // when the answer was due to start
    uint32_t t_tx_us;      // when the modulator started it
    uint32_t t_tx_end_us;  // when the modulator finished
    uint16_t n_gaps;
    uint16_t n_bits;
    uint16_t n_tx_bits;
    uint16_t n_runs;
    uint32_t split;        // the decode's split point, or its one class's mean
    uint16_t level;        // the field-on level the gap detector tracked, in ADC counts after smoothing
    uint16_t n_noise;      // dips shorter than the minimum gap, skipped
    uint8_t bits[16];      // the first 128 decoded bits
    uint8_t tx_bits[16];   // the first 128 sent bits
    struct __attribute__((packed)) {
        uint16_t start_us;  // from the first gap's start
        uint16_t width_us;
    } gaps[LF_IA_TRACE_GAPS];
    // Each wake from System OFF is a reset, and the times above start again from 0. These tell the wakes apart.
    uint16_t boot;          // the boot the record was made in, counted since the clear
    uint16_t session;       // the field session, counted since the clear
    uint32_t t_session_us;  // when that session's field came on
} lf_ia_trace_rec_t;

// Field sessions. session_start counts the session. session_end writes its FIELD_OFF record, committed, if the
// session had a command, and returns it (else NULL).
void lf_ia_trace_session_start(uint32_t t_us);
lf_ia_trace_rec_t *lf_ia_trace_session_end(uint32_t t_us, uint16_t level);

// Takes the next record slot, zeroed and stamped with the boot and session. The engine fills it and calls
// lf_ia_trace_commit.
lf_ia_trace_rec_t *lf_ia_trace_begin(uint8_t type);
void lf_ia_trace_commit(void);
// The record most recently committed, for the engine to complete after the answer goes out. NULL if none.
lf_ia_trace_rec_t *lf_ia_trace_last(void);

// The engine's counters, kept with the trace so they survive sleep.
lf_ia_stats_t *lf_ia_trace_stats(void);

// Clears the records and the counters, and restarts the boot count.
void lf_ia_trace_clear(void);
// Copies records from index first into out, oldest first: the kept first records, then the rolling ones. Returns how
// many. total_out receives the records written since the clear: if it exceeds LF_IA_TRACE_RECORDS, the records
// between the kept ones and the rolling ones were overwritten. boot_out receives the current boot number.
size_t lf_ia_trace_read(size_t first, lf_ia_trace_rec_t *out, size_t max, uint32_t *total_out, uint16_t *boot_out);
