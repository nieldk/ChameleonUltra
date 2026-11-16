#pragma once

// Bench instrumentation for the interactive engine: run-time tuning, counters, and a ring of the smoothed field
// envelope. It proves the framework on the bench and is not part of it.

#include <stddef.h>
#include <stdint.h>

typedef struct __attribute__((packed)) {
    uint16_t settle_us;       // samples skipped after the load switches on, while the field line settles
    uint16_t lost_us;         // a gap this long means the field has gone
    uint16_t min_gap_us;      // shorter dips are noise
    uint8_t thr_pct;          // a gap is a dip below this percentage of the tracked field-on level
    uint8_t quiet_after_cmd;  // 1: drop the load as soon as a command ends; 0: hold it until the answer starts
    int16_t tx_lead_us;       // the answer is armed this much early, to cancel the modulator's start latency
    uint16_t eof_us;          // overrides the module's eof_us if not 0
    uint16_t rsp_delay_us;    // overrides the module's answer delay if not 0
} lf_ia_tuning_t;

typedef struct __attribute__((packed)) {
    uint32_t sessions;
    uint32_t commands;
    uint32_t responses;
    uint32_t late;
    uint32_t buffers;
    uint32_t buffer_slips;    // ADC buffers whose end time was not one buffer after the previous one
    uint32_t max_handler_us;  // the longest ADC buffer handling, including any command handling it did
} lf_ia_stats_t;

#ifndef LF_IA_DEBUG
#define LF_IA_DEBUG (0)
#endif

#if LF_IA_DEBUG
// 1024 samples at 10 us apart = 10.24 ms of history. Upstream uses 4096; cut for this board's RAM budget. Read
// promptly after the test -- with no command to freeze it (see below), the ring keeps recording and this is all
// the lookback there is.
#define LF_IA_ENV_SAMPLES (1024u)
#else
// Bench-only RAM (2KB for the full ring). A production build keeps a token-sized ring so lf_ia_env_arm/read still
// work if called, just with no useful history. Build with LF_IA_DEBUG=1 for real envelope capture.
#define LF_IA_ENV_SAMPLES (32u)
#endif

lf_ia_tuning_t *lf_ia_tuning(void);
const lf_ia_stats_t *lf_ia_stats(void);

// The envelope ring keeps the latest smoothed samples (10 µs apart) while the engine listens. Once armed, it freezes
// at the next command's end, so it holds that command.
void lf_ia_env_arm(void);
// Copies up to max samples, oldest first, from offset. Returns how many. last_us receives the newest sample's time,
// frozen whether the ring has frozen.
size_t lf_ia_env_read(size_t offset, int16_t *out, size_t max, uint32_t *last_us, uint8_t *frozen);
