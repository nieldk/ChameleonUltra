/*
 * sa_radio.h - one-shot 2.4 GHz ISM energy-detect sweep in chained SoftDevice
 * timeslots. See sa_radio.c for the timing/design notes.
 */
#ifndef __SA_RADIO_H
#define __SA_RADIO_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define SA_START_MHZ    2400u
#define SA_POINT_COUNT  84u      /* 2400..2483 MHz inclusive, 1 MHz steps */

typedef struct {
    uint32_t slots, blocked, canceled;
    uint32_t last_rc;
    uint16_t points_done;   /* out of SA_POINT_COUNT; == SA_POINT_COUNT when finished */
    uint32_t ready_ok, ready_timeout;   /* per-point TASKS_RXEN -> EVENTS_READY wait */
    uint32_t ed_ok, ed_timeout;         /* per-point TASKS_EDSTART -> EVENTS_EDEND wait */
} sa_stats_t;

/* Starts a new sweep over [start_offset, start_offset+count) MHz above 2400
 * (aborts and discards any sweep already in progress). count must be 1..84
 * and start_offset+count must be <= 84 -- caller validates before calling.
 * Returns false if the radio session couldn't be opened. Non-blocking --
 * runs across however many timeslots it needs; poll sa_radio_busy()/
 * sa_radio_done() from the mode's on_tick. */
bool sa_radio_sweep_start(uint16_t start_offset, uint16_t count);

/* The range of the most recently started sweep (valid once busy() or done()
 * is true), so a caller that doesn't track it separately can still report
 * it -- e.g. when persisting the result record. */
void sa_radio_get_range(uint16_t *start_offset, uint16_t *count);

/* True while a sweep is running (session open, not finished yet). */
bool sa_radio_busy(void);

/* True once a sweep has completed and sa_radio_get_result() is valid.
 * Stays true (result held) until the next sa_radio_sweep_start(). */
bool sa_radio_done(void);

/* Main-context re-request pump, call every tick like zb_radio_poll(). */
void sa_radio_poll(void);

/* Copies up to SA_POINT_COUNT raw EDSAMPLE bytes (index i == SA_START_MHZ+i
 * MHz) into out. *count is set to the number of valid points (SA_POINT_COUNT
 * once done() is true, fewer while still in progress). */
void sa_radio_get_result(uint8_t *out, size_t out_max, size_t *count);

void sa_radio_get_stats(sa_stats_t *out);

#endif
