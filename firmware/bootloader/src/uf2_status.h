/*
 * uf2_status.h — UF2 transfer diagnostic files.
 *
 * Provides two files in the GhostFAT root:
 *   - INFO_UF2.TXT: always present, device info + dd recommendations
 *   - FAIL.TXT:     appears when a UF2 block was rejected, explains why
 *
 * Success is implicit (device boots the new app). Failures are what
 * actually need surfacing, because "dd succeeded but nothing happened"
 * is otherwise invisible.
 *
 * Integration in uf2_ghostfat.c:
 *   - uf2_status_init() at boot
 *   - uf2_status_record_accepted() / record_rejected() on each block
 *   - Query uf2_status_has_failure() and uf2_status_get_*_txt() in the
 *     root dir + data sector synthesizers.
 */

#ifndef UF2_STATUS_H
#define UF2_STATUS_H

#include <stdint.h>
#include <stdbool.h>

#define UF2_STATUS_FAIL_TXT_MAX    512

typedef enum {
    UF2_REJECT_NONE   = 0,
    UF2_REJECT_MAGIC  = 1,   /* magic_start_0/1 or magic_end mismatch */
    UF2_REJECT_FAMILY = 2,   /* family ID flag missing or wrong family */
    UF2_REJECT_BOUNDS = 3,   /* target_addr outside writable region */
    UF2_REJECT_WRITE  = 4,   /* NVMC operation returned failure */
    UF2_REJECT_SEQ    = 5,   /* block_no >= num_blocks, or num_blocks
                                changed mid-transfer */
} uf2_reject_reason_t;

void uf2_status_init(void);

void uf2_status_record_accepted(uint32_t block_no,
                                uint32_t num_blocks,
                                uint32_t target_addr);

void uf2_status_record_rejected(uint32_t block_no,
                                uint32_t num_blocks,
                                uint32_t target_addr,
                                uf2_reject_reason_t reason);

bool uf2_status_has_failure(void);

const char *uf2_status_get_info_txt(uint32_t *out_size);
const char *uf2_status_get_fail_txt(uint32_t *out_size);

#endif /* UF2_STATUS_H */
