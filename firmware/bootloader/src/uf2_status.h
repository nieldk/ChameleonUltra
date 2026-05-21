/*
 * uf2_status.h — track UF2 transfer state and surface diagnostic
 * INFO_UF2.TXT / RESULT.TXT / FAIL.TXT files via the GhostFAT root.
 *
 * Design:
 *   - INFO_UF2.TXT is always present in the root directory and gives the
 *     user device info plus a hint about what to drag onto the drive.
 *
 *   - After a UF2 transfer attempt, exactly one of:
 *       * RESULT.TXT (transfer succeeded — all blocks accepted, last block
 *                     marked the app valid, reset is about to happen)
 *       * FAIL.TXT   (one or more blocks were rejected — explains why,
 *                     gives a hint to fix it)
 *     ...will be present in the root directory. The user can re-read the
 *     drive after each transfer attempt to see what happened, instead of
 *     guessing whether a silent "dd success" actually wrote to flash.
 *
 *   - Session state is RAM-only; cleared on every replug. That matches
 *     the user's mental model of "the most recent attempt this session".
 *
 * Integration:
 *   uf2_ghostfat.c calls these functions in three places:
 *     - At bootloader init: uf2_status_init()
 *     - In the UF2 write handler: uf2_status_record_accepted() or
 *                                 uf2_status_record_rejected(...) for
 *                                 each block, then
 *                                 uf2_status_record_complete() when the
 *                                 last block arrives with no rejections
 *     - In the FAT directory/data synthesizer: query
 *                                 uf2_status_has_result() /
 *                                 uf2_status_has_failure() and fetch
 *                                 buffer contents via the get_*() funcs
 */

#ifndef UF2_STATUS_H
#define UF2_STATUS_H

#include <stdint.h>
#include <stdbool.h>

/* Buffer sizes. Each status file fits in one 512-byte FAT sector.
 * INFO_UF2.TXT is mostly static so it's a single string in .rodata. */
#define UF2_STATUS_RESULT_TXT_MAX  512
#define UF2_STATUS_FAIL_TXT_MAX    512

/* Reasons a UF2 block can be rejected. The write handler should pick
 * the most specific reason that applies. */
typedef enum {
    UF2_REJECT_NONE   = 0,
    UF2_REJECT_MAGIC  = 1,   /* magic_start_0/1 or magic_end mismatch */
    UF2_REJECT_FAMILY = 2,   /* family ID flag missing or wrong family */
    UF2_REJECT_BOUNDS = 3,   /* target_addr outside writable region */
    UF2_REJECT_WRITE  = 4,   /* NVMC operation returned failure */
    UF2_REJECT_SEQ    = 5,   /* block_no >= num_blocks, or num_blocks
                                changed mid-transfer */
} uf2_reject_reason_t;

/* Call once at bootloader startup. Resets session state and prepares
 * the static INFO_UF2.TXT buffer. */
void uf2_status_init(void);

/* Call from the UF2 write handler when a block has been written
 * successfully to flash. */
void uf2_status_record_accepted(uint32_t block_no,
                                uint32_t num_blocks,
                                uint32_t target_addr);

/* Call from the UF2 write handler when a block has been rejected. */
void uf2_status_record_rejected(uint32_t block_no,
                                uint32_t num_blocks,
                                uint32_t target_addr,
                                uf2_reject_reason_t reason);

/* Call when the last block of a transfer has been received AND all
 * blocks were accepted. Marks the transfer as a success. */
void uf2_status_record_complete(void);

/* Query: should RESULT.TXT be shown in the root directory? */
bool uf2_status_has_result(void);

/* Query: should FAIL.TXT be shown in the root directory? */
bool uf2_status_has_failure(void);

/* Fetch text contents and sizes. The pointers remain valid for the
 * lifetime of the bootloader; the contents change as session state
 * changes. */
const char *uf2_status_get_info_txt(uint32_t *out_size);
const char *uf2_status_get_result_txt(uint32_t *out_size);
const char *uf2_status_get_fail_txt(uint32_t *out_size);

#endif /* UF2_STATUS_H */
