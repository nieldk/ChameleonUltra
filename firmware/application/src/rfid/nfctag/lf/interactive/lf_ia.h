#pragma once

// The interactive LF engine and the interface a protocol module implements.
//
// The engine owns the hardware and the timing: it listens for a reader's command as field gaps, hands the command to
// the module, and sends the module's answer by load modulation at the delay the module asks for. The module owns
// every piece of protocol knowledge and state. All times are in microseconds of the CU's own clock, with the
// high-frequency crystal held on.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "lf_ia_codec.h"

#define LF_IA_US_PER_FC         (8u)    // one carrier period at 125 kHz
// Upstream sizes these for any future module; this fork only runs Hitag2 password mode, whose longest handled
// command is the 32-bit password (5/10/32-bit frames; a 64-bit crypto-mode frame just falls through to LF_IA_IGNORE,
// truncated gaps and all) and whose longest answer is 5+32=37 bits. Cut to fit this board's RAM, with headroom.
#define LF_IA_MAX_GAPS          (48u)   // gaps kept per command
#define LF_IA_MAX_BITS          (LF_IA_MAX_GAPS)
#define LF_IA_MAX_RESPONSE_BITS (64u)

// One field gap: when the field dropped, and for how long.
typedef struct {
    uint32_t start_us;
    uint16_t width_us;
} lf_ia_gap_t;

// One reader command: the gaps from its first to its last, ended by a field-on stretch of the module's eof_us.
typedef struct {
    const lf_ia_gap_t *gaps;
    size_t n_gaps;
    uint32_t end_us;  // the end of the last gap, which response delays count from

    // Filled when the module set want_decode: one bit per interval between consecutive gap starts, so n_gaps - 1 bits.
    lf_ia_decode_status_t decode_status;
    const uint8_t *bits;
    size_t n_bits;
} lf_ia_command_t;

typedef enum {
    LF_IA_IGNORE,    // no answer, keep listening
    LF_IA_RESPOND,   // send the response, then keep listening
    LF_IA_END,       // no answer, and the exchange is over until the field drops and comes back
} lf_ia_verdict_t;

typedef struct {
    uint8_t bits[LF_IA_MAX_RESPONSE_BITS / 8];
    size_t n_bits;
    lf_ia_coding_t coding;
    uint32_t coding_flags;  // LF_IA_INVERT, LF_IA_BIPHASE_ONE_FLIPS
    uint16_t bit_fc;        // carrier periods per bit, for example 32 for RF/32
    uint32_t delay_us;      // from the command's end_us to the first half-bit of the answer
} lf_ia_response_t;

typedef struct {
    const char *name;

    // Command framing.
    uint32_t eof_us;        // a field-on stretch this long after a gap ends the command
    bool want_decode;       // run lf_ia_decode_intervals on each command before on_command
    lf_ia_decode_cfg_t decode;

    // Called with the field newly up, before the first command. May be NULL.
    void (*field_on)(void *ctx);
    // Called once per command, in interrupt context: keep it short, because its time comes out of the response window.
    lf_ia_verdict_t (*on_command)(void *ctx, const lf_ia_command_t *cmd, lf_ia_response_t *rsp);
    // Called when the field drops, so the module can reset. May be NULL.
    void (*field_off)(void *ctx);
    void *ctx;
} lf_ia_module_t;

// Registers the module the engine runs while the slot's LF tag type is this module's. NULL clears it.
void lf_ia_set_module(const lf_ia_module_t *module);
const lf_ia_module_t *lf_ia_get_module(void);

// lf_tag_em.c's side: the engine replaces the fixed broadcast while a module is set.
void lf_ia_sense_enable(void);
void lf_ia_sense_disable(void);
void lf_ia_field_detected(void);
// Provided by lf_tag_em.c: the field has gone. Re-arms the wake comparator and starts the sleep timer.
void lf_tag_em_ia_field_lost(void);
