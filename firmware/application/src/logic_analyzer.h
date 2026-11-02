#ifndef LOGIC_ANALYZER_H
#define LOGIC_ANALYZER_H

#include <stdbool.h>
#include <stdint.h>
#include "logic_hook.h"

#define LOGIC_MAX_EVENTS   1024
#define LOGIC_MAX_CHANNELS 4
#define LOGIC_EV_BYTES     5   /* ts u32 BE + (level<<7 | channel) */

/* Channel source: LOGIC_SRC_* net (logic_hook.h), or LOGIC_SRC_RAW | (port<<5 | pin) */
#define LOGIC_SRC_RAW        0x40

#define LOGIC_OK         0
#define LOGIC_ERR_PARAM  1
#define LOGIC_ERR_BUSY   2
#define LOGIC_ERR_NORES  3

typedef struct {
    bool     running;
    bool     overflow;
    uint8_t  init_levels;
    uint16_t count;
    uint16_t calls;                    /* handler invocations */
    uint32_t cc[LOGIC_MAX_CHANNELS];   /* last PPI capture per channel, 0 = none */
} logic_info_t;

int      logic_start(const uint8_t *src, uint8_t n, uint8_t prescaler, uint16_t merge_ticks);
void     logic_stop(void);
void     logic_get_info(logic_info_t *info);
uint16_t logic_read(uint16_t offset, uint16_t max_events, uint8_t *out);

/* SPI log: packed entries, see logic_spi_slow() */
uint16_t logic_spi_read(uint16_t offset, uint16_t max_bytes, uint8_t *out);
void     logic_spi_info(uint16_t *total, bool *overflow, uint16_t *drops);

#endif
