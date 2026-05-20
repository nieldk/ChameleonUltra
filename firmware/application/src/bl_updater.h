/*
 * bl_updater.h — bootloader self-update from the application.
 */
#ifndef BL_UPDATER_H
#define BL_UPDATER_H

#include <stdint.h>

typedef enum {
    BL_UPDATER_OK             = 0,
    BL_UPDATER_ERR_EMPTY      = 1,
    BL_UPDATER_ERR_TOO_LARGE  = 2,
    BL_UPDATER_ERR_CRC        = 3,
    BL_UPDATER_ERR_SD_DISABLE = 4,
} bl_updater_status_t;

/* Validate the embedded BL data (size + CRC32) without touching flash. */
bl_updater_status_t bl_updater_validate(void);

/* Write the embedded BL into the BL region, then reset.
 * On success does not return. The application that called this remains
 * valid in flash and will be booted normally by the new BL. */
bl_updater_status_t bl_updater_run(void);

/* Write the embedded BL into the BL region, then erase our own vector
 * table to make ourselves un-bootable, then reset.
 *
 * This is the recovery-mode variant: the new (stock) BL boots, fails to
 * validate the app, and falls through to DFU mode automatically — the
 * state the user needs for pushing a fresh signed application via the
 * stock DFU flow.
 *
 * On success does not return. */
bl_updater_status_t bl_updater_run_and_invalidate_app(void);

#endif /* BL_UPDATER_H */
