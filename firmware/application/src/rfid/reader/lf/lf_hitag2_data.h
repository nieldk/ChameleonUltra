#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
 * Hitag2 (NXP/Philips PCF7936, password mode only -- no crypto mode).
 *
 * Protocol constants below are taken from RfidResearchGroup/proxmark3's
 * armsrc/hitag2.c + include/protocols.h (the working reference
 * implementation PM3's "Aurora" release ported from RFIDler), not derived
 * from a datasheet guess. Receive-side Manchester classifier thresholds are
 * the one exception: they are dimensionally scaled from this codebase's own
 * hardware-proven EM4x05 RF/64 classifier (lf_em4x05_data.c) to Hitag2's
 * RF/32 (4 kbit/s) rate, and -- like EM4x05/T55xx read in this tree -- should
 * be expected to need first-hardware-capture tuning.
 * --------------------------------------------------------------------- */

#define HITAG2_NUM_PAGES   8
#define HITAG2_PAGE_SIZE   4   /* bytes per page */

#define HITAG2_PAGE_UID     0  /* page 0: UID (read-only) */
#define HITAG2_PAGE_PWD     1  /* page 1: reader's password (password mode) */
#define HITAG2_PAGE_KEY     2  /* page 2: key high bytes (crypto mode only) */
#define HITAG2_PAGE_CONFIG  3  /* page 3: config byte + tag's own password */

/* Config byte (page 3, byte 0) bit 3: 0 = password mode, 1 = crypto mode. */
#define HITAG2_CONFIG_CRYPTO_BIT  0x08

/* Command opcodes (top bits of the frame; see hitag2_page_frame() in
 * lf_hitag2_data.c for how READ_PAGE/WRITE_PAGE pack the rest of the
 * frame). Shared between the reader side (lf_hitag2_data.c, which sends
 * these) and tag-emulation (hitag2_tag.c, which matches against them). */
#define HITAG2_START_AUTH     0xC0   /* top 5 bits only: "11000" */
#define HITAG2_READ_PAGE      0xC0   /* page in bits 5-3, complement in bit 0 + next 2 bits */
#define HITAG2_READ_PAGE_INV  0x44
#define HITAG2_WRITE_PAGE     0x82

/* Get the UID by sending START_AUTH and capturing the tag's page-0 reply.
 * Works regardless of password/crypto mode -- no authentication performed. */
bool hitag2_reader_get_uid(uint8_t uid[HITAG2_PAGE_SIZE], uint32_t timeout_ms);

/* Full password-mode session: START_AUTH, read UID, send `password`, and if
 * the tag accepts it (replies with its own page 3), read every other page
 * with individual READ_PAGE commands.
 *
 * pages[HITAG2_PAGE_PWD] is filled from `password` itself (the reader does
 * not read its own password back over the air); pages[HITAG2_PAGE_CONFIG]
 * is filled from the tag's auth reply.  pages[HITAG2_PAGE_UID] is filled
 * from the START_AUTH reply.
 *
 * Returns false if the tag never answers, or answers but rejects the
 * password (wrong key, or the tag is actually in crypto mode). */
bool hitag2_reader_read(const uint8_t password[HITAG2_PAGE_SIZE],
                         uint8_t pages[HITAG2_NUM_PAGES][HITAG2_PAGE_SIZE],
                         uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
