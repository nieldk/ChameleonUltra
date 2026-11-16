#ifndef LF_XTAL_COUNTER_H
#define LF_XTAL_COUNTER_H

#include <stdbool.h>
#include <stdint.h>

/*
 * HFXO tick counter for measuring this device's own crystal ppm offset
 * against an external time reference (the host's clock, which the CLI is
 * responsible for checking against something trustworthy — see
 * emv_audit_report.py's sibling `hw lf xtal measure` CLI command for how
 * this is used; this module only counts ticks).
 *
 * Usage: lf_xtal_counter_start() to hold HFXO on and start a free-running
 * 16 MHz TIMER1 count, lf_xtal_counter_read() as many times as wanted while
 * it runs, lf_xtal_counter_stop() to release both. The raw tick count is a
 * plain 32-bit hardware register that wraps roughly every 268 s at 16 MHz —
 * callers must poll more often than that to reconstruct a 64-bit count on
 * their side (accumulate +2^32 each time a read is lower than the last).
 *
 * TIMER1 is borrowed hardware shared with the hf14a sniff --tap capture
 * (see timer1_lock.h) — start fails with LF_XTAL_BUSY if that's using it.
 */
typedef enum {
    LF_XTAL_OK = 0,
    LF_XTAL_BUSY = 1,      // TIMER1 is on loan to something else right now
    LF_XTAL_NOT_RUNNING = 2,
} lf_xtal_status_t;

typedef struct {
    uint32_t raw_ticks;  // current TIMER1 CC[0] capture (16 MHz, wraps ~268 s)
    bool     running;
    bool     hfclk_lapsed; // sticky: HFXO was ever reported not-running during this run
} lf_xtal_sample_t;

lf_xtal_status_t lf_xtal_counter_start(void);
lf_xtal_status_t lf_xtal_counter_read(lf_xtal_sample_t *out);
lf_xtal_status_t lf_xtal_counter_stop(lf_xtal_sample_t *out);

#endif
