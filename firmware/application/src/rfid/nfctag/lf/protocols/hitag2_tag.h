#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "lf_hitag2_data.h"

#ifdef __cplusplus
extern "C" {
#endif

// Loads 8 pages (32 bytes) of Hitag2 tag data for emulation.
void hitag2_tag_load(const uint8_t pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE]);

// Arms RX decode of the external reader's BPLM downlink. Call once, from
// lf_tag_em.c's LPCOMP field-detected handler, right after that handler sets
// m_is_lf_emulating -- this only arms the listener and returns immediately,
// it does not run the session (that happens in hitag2_tag_tick(), below,
// from main-loop/thread context, never from the interrupt that calls this).
void hitag2_tag_session_start(void);

// Call every main-loop iteration while a Hitag2 slot is emulating (same
// pattern as this firmware's other per-tick emulation helpers, e.g.
// desfire_random_pump()). Non-blocking except for the few milliseconds of
// a reply burst when one is actually due. Also what notices field loss and
// unwinds back to lf_tag_em.c's normal teardown path.
// Returns false once the field is gone (session over); true while still
// armed and listening.
// No crypto mode -- a crypto-mode reader's 64-bit Nr/Ar challenge is ignored.
bool hitag2_tag_tick(void);

#ifdef __cplusplus
}
#endif
