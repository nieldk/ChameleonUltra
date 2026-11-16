#include "hitag2_crypto.h"

#include <string.h>

#include "rfid/byte_mirror.h"

/* Single-bit input selector: packs 4 chosen state bits into a 0-15 index. */
#define HT2_I4(x, a, b, c, d) \
    ((uint32_t)((((x) >> (a)) & 1) + (((x) >> (b)) & 1) * 2 + (((x) >> (c)) & 1) * 4 + (((x) >> (d)) & 1) * 8))

static const uint32_t HT2_F4A = 0x2C79;
static const uint32_t HT2_F4B = 0x6671;
static const uint32_t HT2_F5C = 0x7907287B;

/* The filter function: five 4-bit taps off the state feed two small lookup
 * tables, whose 5-bit result indexes a third, producing one output bit. */
static uint32_t ht2_f20(uint64_t state) {
    uint32_t i5 = ((HT2_F4A >> HT2_I4(state, 1, 2, 4, 5)) & 1) * 1
                  + ((HT2_F4B >> HT2_I4(state, 7, 11, 13, 14)) & 1) * 2
                  + ((HT2_F4B >> HT2_I4(state, 16, 20, 22, 25)) & 1) * 4
                  + ((HT2_F4B >> HT2_I4(state, 27, 28, 30, 32)) & 1) * 8
                  + ((HT2_F4A >> HT2_I4(state, 33, 42, 43, 45)) & 1) * 16;
    return (HT2_F5C >> i5) & 1u;
}

/* Upstream's REV32/REV64 reverse the bits WITHIN each byte but leave the
 * bytes in place (no byte-swap) -- confirmed against common/commonutil.h.
 * Each byte position keeps its position; only byte_mirror (REV8) applies. */
uint32_t hitag2_rev32(uint32_t x) {
    return (uint32_t)byte_mirror[x & 0xFF]
           | ((uint32_t)byte_mirror[(x >> 8) & 0xFF] << 8)
           | ((uint32_t)byte_mirror[(x >> 16) & 0xFF] << 16)
           | ((uint32_t)byte_mirror[(x >> 24) & 0xFF] << 24);
}

uint64_t hitag2_rev64(uint64_t x) {
    uint64_t r = 0;
    for (int i = 0; i < 8; i++) {
        r |= (uint64_t)byte_mirror[(x >> (8 * i)) & 0xFF] << (8 * i);
    }
    return r;
}

uint64_t hitag2_crypto_init(uint64_t key, uint32_t uid, uint32_t iv) {
    uint64_t x = ((key & 0xFFFFu) << 32) + uid;
    for (uint32_t i = 0; i < 32; i++) {
        x >>= 1;
        x += (uint64_t)(ht2_f20(x) ^ (((iv >> i) ^ (key >> (i + 16))) & 1u)) << 47;
    }
    return x;
}

int hitag2_crypto_bit(uint64_t *state) {
    uint64_t x = *state;
    x = (x >> 1) +
        ((((x >> 0) ^ (x >> 2) ^ (x >> 3) ^ (x >> 6)
           ^ (x >> 7) ^ (x >> 8) ^ (x >> 16) ^ (x >> 22)
           ^ (x >> 23) ^ (x >> 26) ^ (x >> 30) ^ (x >> 41)
           ^ (x >> 42) ^ (x >> 43) ^ (x >> 46) ^ (x >> 47)) & 1u) << 47);
    *state = x;
    return (int)ht2_f20(x);
}

uint8_t hitag2_crypto_byte(uint64_t *state) {
    uint8_t c = 0;
    for (int i = 7; i >= 0; i--) {
        c = (uint8_t)(c | ((uint8_t)hitag2_crypto_bit(state) << i));
    }
    return c;
}

bool hitag2_crypto_check_auth(uint64_t *state, const uint8_t authenticator[4]) {
    uint8_t should[4];
    for (int i = 0; i < 4; i++) {
        should[i] = (uint8_t) ~hitag2_crypto_byte(state);
    }
    return memcmp(should, authenticator, 4) == 0;
}

void hitag2_crypto_build_auth(uint64_t *state, uint8_t out[4]) {
    memset(out, 0xFF, 4);
    hitag2_crypto_transcrypt(state, out, 4, 0);
}

void hitag2_crypto_transcrypt(uint64_t *state, uint8_t *data, uint16_t bytes, uint16_t bits) {
    for (uint16_t i = 0; i < bytes; i++) {
        data[i] = (uint8_t)(data[i] ^ hitag2_crypto_byte(state));
    }
    for (uint16_t i = 0; i < bits; i++) {
        data[bytes] = (uint8_t)(data[bytes] ^ ((uint8_t)hitag2_crypto_bit(state) << (7u - i)));
    }
}
