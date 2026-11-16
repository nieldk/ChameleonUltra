#ifndef TIMER1_LOCK_H
#define TIMER1_LOCK_H

#include <stdbool.h>

/*
 * TIMER1 is shared, borrow-and-release, raw-register hardware (TIMER0 is
 * SoftDevice's, TIMER2 is the LF radio's, TIMER3/4 are enabled elsewhere —
 * see hf14a_sniff_tap_run()'s comment in app_cmd.c). Two features now borrow
 * it for their own, non-overlapping windows: the hf14a sniff --tap capture
 * and the LF crystal tick counter (lf_xtal_counter.c). Neither owns it
 * permanently, so a plain acquire/release guard is enough to stop one from
 * reconfiguring it out from under the other if they're ever started at the
 * same time.
 */
bool timer1_lock_try_acquire(void);
void timer1_lock_release(void);

#endif
