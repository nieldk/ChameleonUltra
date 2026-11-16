// Hitag 2 in password mode, as an interactive engine module.
//
// The reader codes its bits by pulse length (a 0 is 20 carrier periods from gap to gap, a 1 is 30) and ends each
// command with a stop gap, so a command of n bits is n + 1 gaps and the engine's standard decode gives the n bits. The
// tag answers in Manchester at RF/32, behind five start-of-frame ones.
//
// The exchange: START_AUTH (5 bits, 11000) gets the UID. The reader then sends its 32-bit password. If it matches
// page 1, the tag answers with page 3 (the configuration byte and the tag password) and then serves READ PAGE commands
// (10 bits). Crypto mode and writes are not handled.

#include "lf_ia_hitag2.h"

#include <string.h>

#define HT2_EOF_US    (300u)   // longer than a 1 bit's field-on time (30 - 6 periods, 192 µs)
// The reader samples from 192 to about 320 periods after its command, which ends 36 periods after the stop gap. A
// genuine fob answers 227 periods after the reader's last edge. 240 periods after the stop gap sits early in the
// reader's window, near the fob.
#define HT2_DELAY_US  (240u * LF_IA_US_PER_FC)
#define HT2_BIT_FC    (32u)
#define HT2_SOF_BITS  (5u)

typedef enum {
    HT2_IDLE,           // waiting for START_AUTH
    HT2_UID_SENT,       // waiting for the password
    HT2_AUTHENTICATED,  // serving page reads
} ht2_state_t;

static uint8_t m_pages[LF_HITAG2_DATA_SIZE];
static ht2_state_t m_state;

static uint32_t bits_value(const uint8_t *bits, size_t first, size_t n) {
    uint32_t v = 0;
    for (size_t i = 0; i < n; i++) {
        v = (v << 1) | (lf_ia_bit_get(bits, first + i) ? 1u : 0u);
    }
    return v;
}

static uint32_t page(size_t n) {
    const uint8_t *p = &m_pages[4u * n];
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

// Sets rsp to a start-of-frame and one 32-bit page, sent at the module's delay.
static lf_ia_verdict_t answer(lf_ia_response_t *rsp, uint32_t value) {
    memset(rsp->bits, 0, sizeof(rsp->bits));
    for (size_t i = 0; i < HT2_SOF_BITS; i++) {
        lf_ia_bit_put(rsp->bits, i, true);
    }
    for (size_t i = 0; i < 32; i++) {
        lf_ia_bit_put(rsp->bits, HT2_SOF_BITS + i, (value >> (31u - i)) & 1u);
    }
    rsp->n_bits = HT2_SOF_BITS + 32u;
    rsp->coding = LF_IA_CODING_MANCHESTER;
    rsp->coding_flags = 0;
    rsp->bit_fc = HT2_BIT_FC;
    rsp->delay_us = HT2_DELAY_US;
    return LF_IA_RESPOND;
}

static void field_on(void *ctx) {
    (void)ctx;
    m_state = HT2_IDLE;
}

static void field_off(void *ctx) {
    (void)ctx;
    m_state = HT2_IDLE;
}

static lf_ia_verdict_t on_command(void *ctx, const lf_ia_command_t *cmd, lf_ia_response_t *rsp) {
    (void)ctx;
    if (cmd->decode_status != LF_IA_DECODE_OK) {
        return LF_IA_IGNORE;
    }

    // A Hitag 2 reader frame is 5, 10, 32 or 64 bits. Other lengths are noise, and must not move the state.
    switch (cmd->n_bits) {
        case 5:
            if (bits_value(cmd->bits, 0, 5) != 0x18u) {  // START_AUTH, 11000
                return LF_IA_IGNORE;
            }
            m_state = HT2_UID_SENT;
            return answer(rsp, page(0));

        case 32:
            if (m_state != HT2_UID_SENT) {
                return LF_IA_IGNORE;
            }
            if (bits_value(cmd->bits, 0, 32) != page(1)) {
                m_state = HT2_IDLE;
                return LF_IA_IGNORE;
            }
            m_state = HT2_AUTHENTICATED;
            return answer(rsp, page(3));

        case 10: {
            if (m_state != HT2_AUTHENTICATED) {
                return LF_IA_IGNORE;
            }
            // READ PAGE is 11 nnn 00 ~nnn, and READ PAGE INVERTED is 01 nnn 10 ~nnn.
            const uint32_t op = bits_value(cmd->bits, 0, 2) << 2 | bits_value(cmd->bits, 5, 2);
            const uint32_t n = bits_value(cmd->bits, 2, 3);
            if (bits_value(cmd->bits, 7, 3) != (~n & 7u)) {
                return LF_IA_IGNORE;
            }
            if (op == 0xCu) {
                return answer(rsp, page(n));
            }
            if (op == 0x6u) {
                return answer(rsp, ~page(n));
            }
            return LF_IA_IGNORE;
        }

        default:
            return LF_IA_IGNORE;
    }
}

static const lf_ia_module_t m_hitag2 = {
    .name = "hitag2",
    .eof_us = HT2_EOF_US,
    .want_decode = true,
    .decode = LF_IA_DECODE_CFG_DEFAULT,
    .field_on = field_on,
    .on_command = on_command,
    .field_off = field_off,
    .ctx = NULL,
};

const lf_ia_module_t *lf_ia_hitag2_load(const uint8_t *pages) {
    memcpy(m_pages, pages, sizeof(m_pages));
    m_state = HT2_IDLE;
    return &m_hitag2;
}
