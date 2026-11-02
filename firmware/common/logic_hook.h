#ifndef LOGIC_HOOK_H
#define LOGIC_HOOK_H

#include <stdint.h>

/* Nets the firmware drives itself; logged by the logic analyser. */
#define LOGIC_SRC_HF_CS      0x00
#define LOGIC_SRC_FIELD_LED  0x01
#define LOGIC_SRC_SPI        0x02   /* RC522 register accesses, logged by value */

#if defined(PROJECT_CHAMELEON_ULTRA) && defined(CONFIG_LOGIC_HOOKS)
extern volatile uint8_t g_logic_hook_mask;
void logic_hook_slow(uint8_t src, uint8_t level);
extern volatile uint8_t g_logic_spi_on;
void logic_spi_slow(uint8_t reg, uint8_t rw, const uint8_t *data, uint8_t len, uint8_t burst);

static inline void logic_hook(uint8_t src, uint8_t level) {
    if (g_logic_hook_mask & (1u << src)) {
        logic_hook_slow(src, level);
    }
}
static inline void logic_spi(uint8_t reg, uint8_t rw, const uint8_t *data, uint8_t len, uint8_t burst) {
    if (g_logic_spi_on) {
        logic_spi_slow(reg, rw, data, len, burst);
    }
}
#else
static inline void logic_spi(uint8_t reg, uint8_t rw, const uint8_t *data, uint8_t len, uint8_t burst) {
    (void)reg;
    (void)rw;
    (void)data;
    (void)len;
    (void)burst;
}

static inline void logic_hook(uint8_t src, uint8_t level) {
    (void)src;
    (void)level;
}
#endif

#endif
