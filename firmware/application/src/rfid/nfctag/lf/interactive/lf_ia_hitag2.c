// Hitag 2 in password and (known-key) crypto mode, as an interactive engine module.
//
// The reader codes its bits by pulse length (a 0 is 20 carrier periods from gap to gap, a 1 is 30) and ends each
// command with a stop gap, so a command of n bits is n + 1 gaps and the engine's standard decode gives the n bits. The
// tag answers in Manchester at RF/32, behind five start-of-frame ones.
//
// Password mode: START_AUTH (5 bits, 11000) gets the UID. The reader sends its 32-bit password; if it matches page 1,
// the tag answers with page 3 and then serves READ PAGE commands (10 bits).
//
// Crypto mode (page 3 byte 0 bit 3 set): after START_AUTH, the reader sends a 64-bit Nr||Ar challenge instead of the
// plaintext password. The cipher is reset from the stored key/UID/Nr and Ar is checked against the keystream
// (hitag2_crypto_check_auth); from then on every frame in both directions is XORed with the continuing keystream
// (hitag2_crypto_transcrypt) before being read or after being built -- same wire framing as password mode underneath.
// The key is assumed known (loaded into pages 1/2) and fixed; no key recovery, and writes are still not handled.

#include "lf_ia_hitag2.h"

#include <string.h>

#include "hitag2_crypto.h"
#include "lf_hitag2_data.h"

#define HT2_EOF_US    (300u)   // longer than a 1 bit's field-on time (30 - 6 periods, 192 µs)
// The reader samples from 192 to about 320 periods after its command, which ends 36 periods after the stop gap. A
// genuine fob answers 227 periods after the reader's last edge. 240 periods after the stop gap sits early in the
// reader's window, near the fob.
#define HT2_DELAY_US  (240u * LF_IA_US_PER_FC)
#define HT2_BIT_FC    (32u)
#define HT2_SOF_BITS  (5u)
#define HT2_T0_US     (20u * LF_IA_US_PER_FC)  // a 0 bit, gap to gap
#define HT2_T1_US     (30u * LF_IA_US_PER_FC)  // a 1 bit, gap to gap

typedef enum {
    HT2_IDLE,           // waiting for START_AUTH
    HT2_UID_SENT,       // waiting for the password
    HT2_AUTHENTICATED,  // serving page reads
} ht2_state_t;

static uint8_t m_pages[LF_HITAG2_DATA_SIZE];
static ht2_state_t m_state;
static bool m_crypto_active;
static uint64_t m_cs;

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

static bool crypto_configured(void) {
    return (page(HITAG2_PAGE_CONFIG) & ((uint32_t)HITAG2_CONFIG_CRYPTO_BIT << 24)) != 0;
}

// 48-bit key, plain little-endian decode of the stored page bytes -- matches RfidResearchGroup/proxmark3's
// ht2_hitag2_cipher_reset exactly: the low 32 bits live in page 1, the high 16 bits in page 2's last two bytes.
static uint64_t crypto_key_raw(void) {
    const uint8_t *p1 = &m_pages[4u * HITAG2_PAGE_PWD];
    const uint8_t *p2 = &m_pages[4u * HITAG2_PAGE_KEY];
    return (uint64_t)p2[2]
           | ((uint64_t)p2[3] << 8)
           | ((uint64_t)p1[0] << 16)
           | ((uint64_t)p1[1] << 24)
           | ((uint64_t)p1[2] << 32)
           | ((uint64_t)p1[3] << 40);
}

// Plain little-endian decode, same as PM3's MemLeToUint4byte.
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t bytes_to_be32(const uint8_t *p) {
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
    m_crypto_active = false;
}

static void field_off(void *ctx) {
    (void)ctx;
    m_state = HT2_IDLE;
    m_crypto_active = false;
}

static lf_ia_verdict_t on_command(void *ctx, const lf_ia_command_t *cmd, lf_ia_response_t *rsp) {
    (void)ctx;
    if (cmd->decode_status != LF_IA_DECODE_OK) {
        return LF_IA_IGNORE;
    }

    // Authenticated read, including redundancy-extended commands ("Gone in 360
    // Seconds" sect 4.1): the reader repeats the 10-bit read command, the tag
    // consumes them all and answers 32 bits of the page at the later keystream
    // offset. A real tag validates the repetition, so every 10-bit block must
    // decode to the same read command; otherwise a wrong-page command padded
    // with garbage would be accepted and the crack would lock onto it.
    if (m_state == HT2_AUTHENTICATED && cmd->n_bits >= 10 && cmd->n_bits <= LF_IA_MAX_BITS &&
        (cmd->n_bits % 10u) == 0u) {
        uint8_t frame[LF_IA_MAX_BITS / 8];
        memcpy(frame, cmd->bits, sizeof(frame));
        if (m_crypto_active) {
            // Decrypt the whole command so the keystream advances by n_bits.
            hitag2_crypto_transcrypt(&m_cs, frame, cmd->n_bits / 8u, cmd->n_bits % 8u);
        }
        // Every 10-bit block after the first must repeat it exactly.
        for (uint32_t off = 10; off < cmd->n_bits; off += 10) {
            for (uint32_t i = 0; i < 10; i++) {
                if (lf_ia_bit_get(frame, off + i) != lf_ia_bit_get(frame, i)) {
                    return LF_IA_IGNORE;
                }
            }
        }
        // READ PAGE is 11 nnn 00 ~nnn, READ PAGE INVERTED is 01 nnn 10 ~nnn.
        const uint32_t op = bits_value(frame, 0, 2) << 2 | bits_value(frame, 5, 2);
        const uint32_t n = bits_value(frame, 2, 3);
        if (bits_value(frame, 7, 3) != (~n & 7u)) {
            return LF_IA_IGNORE;
        }
        uint32_t value;
        if (op == 0xCu) {
            value = page(n);
        } else if (op == 0x6u) {
            value = ~page(n);
        } else {
            return LF_IA_IGNORE;
        }
        if (m_crypto_active) {
            uint8_t v[4] = {
                (uint8_t)(value >> 24), (uint8_t)(value >> 16), (uint8_t)(value >> 8), (uint8_t)value
            };
            hitag2_crypto_transcrypt(&m_cs, v, sizeof(v), 0);
            value = bytes_to_be32(v);
        }
        return answer(rsp, value);
    }

    // The remaining reader frames are 5, 32 or 64 bits. Other lengths are noise, and must not move the state.
    switch (cmd->n_bits) {
        case 5:
            if (bits_value(cmd->bits, 0, 5) != 0x18u) {  // START_AUTH, 11000
                return LF_IA_IGNORE;
            }
            m_state = HT2_UID_SENT;
            m_crypto_active = false;
            return answer(rsp, page(0));

        case 32:
            // A crypto-mode tag never takes a plaintext password here; the reader only reaches this frame length
            // after a 64-bit Nr/Ar probe goes unanswered, same as a real crypto-mode fob staying silent to one.
            if (m_state != HT2_UID_SENT || crypto_configured()) {
                return LF_IA_IGNORE;
            }
            if (bits_value(cmd->bits, 0, 32) != page(1)) {
                m_state = HT2_IDLE;
                return LF_IA_IGNORE;
            }
            m_state = HT2_AUTHENTICATED;
            return answer(rsp, page(3));

        case 64: {
            // Nr (4 bytes) || Ar (4 bytes). cmd->bits is already packed as the raw over-the-air byte array, same
            // convention PM3's rx[] uses, so no bit-by-bit reassembly is needed.
            if (m_state != HT2_UID_SENT || !crypto_configured()) {
                return LF_IA_IGNORE;
            }
            const uint8_t *rx = cmd->bits;
            uint64_t key = hitag2_rev64(crypto_key_raw());
            uint32_t uid = hitag2_rev32(le32(&m_pages[4u * HITAG2_PAGE_UID]));
            uint32_t iv = hitag2_rev32(le32(rx));  // Nr
            uint64_t cs = hitag2_crypto_init(key, uid, iv);
            if (!hitag2_crypto_check_auth(&cs, rx + 4)) {  // Ar
                m_state = HT2_IDLE;
                return LF_IA_IGNORE;
            }
            m_cs = cs;
            m_crypto_active = true;
            m_state = HT2_AUTHENTICATED;
            uint8_t p3[4];
            memcpy(p3, &m_pages[4u * HITAG2_PAGE_CONFIG], sizeof(p3));
            hitag2_crypto_transcrypt(&m_cs, p3, sizeof(p3), 0);
            return answer(rsp, bytes_to_be32(p3));
        }

        default:
            return LF_IA_IGNORE;
    }
}

static const lf_ia_module_t m_hitag2 = {
    .name = "hitag2",
    .eof_us = HT2_EOF_US,
    .want_decode = true,
    // All 32 bits of a command can share a value (e.g. a zero password), leaving no second class to self-calibrate
    // against; fall back to the reader's documented fixed timing for that case.
    .decode = { .min_ratio_pct = 115, .short_is_one = false, .fallback_t0_us = HT2_T0_US, .fallback_t1_us = HT2_T1_US },
    .field_on = field_on,
    .on_command = on_command,
    .field_off = field_off,
    .ctx = NULL,
};

const lf_ia_module_t *lf_ia_hitag2_load(const uint8_t *pages) {
    memcpy(m_pages, pages, sizeof(m_pages));
    m_state = HT2_IDLE;
    m_crypto_active = false;
    return &m_hitag2;
}
