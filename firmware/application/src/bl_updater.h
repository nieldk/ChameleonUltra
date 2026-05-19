/*
 * bl_updater.h — one-shot bootloader self-update from the application.
 */
#ifndef BL_UPDATER_H
#define BL_UPDATER_H

#include <stdint.h>

typedef enum {
    BL_UPDATER_OK            = 0,  /* success — but bl_updater_run() resets, doesn't return */
    BL_UPDATER_ERR_EMPTY     = 1,  /* embedded BL data is zero-length */
    BL_UPDATER_ERR_TOO_LARGE = 2,  /* embedded BL data won't fit in BL region */
    BL_UPDATER_ERR_CRC       = 3,  /* embedded BL data fails its own CRC32 check */
    BL_UPDATER_ERR_SD_DISABLE = 4, /* couldn't take SoftDevice offline */
} bl_updater_status_t;

/* Pure validation — checks size & CRC of the embedded BL data. */
bl_updater_status_t bl_updater_validate(void);

/* Disables SoftDevice, erases & rewrites the bootloader region, resets.
 * On success this function does not return. On failure (validation
 * before any destructive operation) returns the error code. */
bl_updater_status_t bl_updater_run(void);

#endif /* BL_UPDATER_H */
