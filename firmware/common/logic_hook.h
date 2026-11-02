#ifndef LOGIC_HOOK_H
#define LOGIC_HOOK_H

#include <stdint.h>

/* Nets the firmware drives itself; logged by the logic analyser. */
#define LOGIC_SRC_HF_CS      0x00
#define LOGIC_SRC_FIELD_LED  0x01

#if defined(PROJECT_CHAMELEON_ULTRA) && defined(CONFIG_LOGIC_HOOKS)
extern volatile uint8_t g_logic_hook_mask;
void logic_hook_slow(uint8_t src, uint8_t level);

static inline void logic_hook(uint8_t src, uint8_t level) {
    if (g_logic_hook_mask & (1u << src)) {
        logic_hook_slow(src, level);
    }
}
#else
static inline void logic_hook(uint8_t src, uint8_t level) {
    (void)src;
    (void)level;
}
#endif

#endif
