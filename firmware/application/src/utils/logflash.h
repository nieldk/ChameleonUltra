#ifndef LOGFLASH_H
#define LOGFLASH_H

#include <stdbool.h>
#include <stdint.h>

#define LOGFLASH_LEVEL_MAX 4   /* 0 off, 1 error, 2 warning, 3 info, 4 debug */

typedef struct {
    uint8_t  level;
    bool     failed;      /* flash write/erase failed, logging to RAM only */
    uint32_t stored;      /* bytes in the flash ring */
    uint32_t pending;     /* bytes in RAM, not yet in flash */
    uint32_t dropped;     /* bytes lost to a full RAM buffer */
    uint32_t boots;       /* boots since the RAM state was last cold */
    uint32_t err;         /* first failure: stage<<24 | op<<16 | code, 0 = none */
} logflash_stats_t;

/* Register the log backend. Call after NRF_LOG_DEFAULT_BACKENDS_INIT(). */
void logflash_init(uint8_t level);

/* Runtime level for the flash backend (RTT is not affected). */
void logflash_set_level(uint8_t level);

/* Drive the RAM -> flash pipeline. Call from the main loop. */
void logflash_poll(void);

/* Push everything out to flash and wait (reset / DFU / system off paths). */
void logflash_flush_blocking(uint32_t timeout_ms);

/* Ask for a flush without waiting. */
void logflash_request_flush(void);

void logflash_get_stats(logflash_stats_t *out);
uint32_t logflash_read(uint32_t offset, uint8_t *dst, uint32_t len);
void logflash_clear(void);

/* Fill [base, base+size) with 0xFF but leave the log RAM ring untouched. */
void logflash_wipe_noinit(uint32_t base, uint32_t size);

#endif
