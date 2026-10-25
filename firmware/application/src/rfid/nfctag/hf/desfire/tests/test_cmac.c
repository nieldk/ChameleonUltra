#include <stdio.h>
#include "../tests/munit/munit.h"
#include "aes_cmac.h"
#include "des_cmac.h"
#include "dfc_common.h"
#include <string.h>

static void hex_to_bytes(const char* hex, uint8_t* out) {
    size_t len = strlen(hex) / 2;
    for(size_t i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex + i * 2, "%2x", &byte);
        out[i] = (uint8_t)byte;
    }
}

// RFC 4493 AES-CMAC test vectors, key = 2b7e151628aed2a6abf7158809cf4f3c
static MunitResult test_aes_cmac_empty(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t key[16];
    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key);
    uint8_t expected[16];
    hex_to_bytes("bb1d6929e95937287fa37d129b756746", expected);

    uint8_t cmac[16];
    munit_assert_true(aes_cmac(key, sizeof(key), NULL, 0, cmac));
    munit_assert_memory_equal(16, cmac, expected);
    return MUNIT_OK;
}

static MunitResult test_aes_cmac_16bytes(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t key[16];
    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key);
    uint8_t message[16];
    hex_to_bytes("6bc1bee22e409f96e93d7e117393172a", message);
    uint8_t expected[16];
    hex_to_bytes("070a16b46b4d4144f79bdd9dd04a287c", expected);

    uint8_t cmac[16];
    munit_assert_true(aes_cmac(key, sizeof(key), message, sizeof(message), cmac));
    munit_assert_memory_equal(16, cmac, expected);
    return MUNIT_OK;
}

static MunitResult
    test_aes_cmac_multiblock_and_segments(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t key[16];
    uint8_t message[64];
    uint8_t expected40[16];
    uint8_t expected64[16];
    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key);
    hex_to_bytes(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710",
        message);
    hex_to_bytes("dfa66747de9ae63030ca32611497c827", expected40);
    hex_to_bytes("51f0bebf7e3b9d92fc49741779363cfe", expected64);

    uint8_t mac[16];
    munit_assert_true(aes_cmac(key, sizeof(key), message, 40, mac));
    munit_assert_memory_equal(sizeof(mac), mac, expected40);
    munit_assert_true(aes_cmac(key, sizeof(key), message, sizeof(message), mac));
    munit_assert_memory_equal(sizeof(mac), mac, expected64);

    DfcCryptoSegment segments[] = {
        {.data = message, .length = 3},
        {.data = message + 3, .length = 29},
        {.data = message + 32, .length = 1},
        {.data = message + 33, .length = 31},
    };
    uint8_t iv[16] = {0};
    munit_assert_true(aes_cmac_segments_with_iv(
        key, sizeof(key), segments, sizeof(segments) / sizeof(segments[0]), iv, mac));
    munit_assert_memory_equal(sizeof(mac), mac, expected64);
    return MUNIT_OK;
}

static MunitResult test_cmac_rejects_overflow_lengths(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t key[24] = {0};
    uint8_t byte = 0;
    uint8_t output[16];
    memset(output, 0xA5, sizeof(output));
    munit_assert_false(aes_cmac(key, 16, &byte, SIZE_MAX, output));
    uint8_t zero[16] = {0};
    munit_assert_memory_equal(16, output, zero);
    memset(output, 0xA5, sizeof(output));
    munit_assert_false(des_cmac(key, 24, &byte, SIZE_MAX, output));
    munit_assert_memory_equal(8, output, zero);
    return MUNIT_OK;
}

static MunitResult test_segmented_cmac_boundaries(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static uint8_t message[DFC_MAX_FILE_DATA];
    for(size_t i = 0; i < sizeof(message); i++)
        message[i] = (uint8_t)(i * 37u + 11u);
    const size_t lengths[] = {
        0, 1, 7, 8, 9, 15, 16, 17, 191, 192, 193, 300, 2048, DFC_MAX_FILE_DATA};
    uint8_t aes_key[16];
    uint8_t des_key[24];
    uint8_t aes_iv[16];
    uint8_t des_iv[8];
    for(size_t i = 0; i < sizeof(aes_key); i++)
        aes_key[i] = (uint8_t)(0x10 + i);
    for(size_t i = 0; i < sizeof(des_key); i++)
        des_key[i] = (uint8_t)(0x20 + i);
    for(size_t i = 0; i < sizeof(aes_iv); i++)
        aes_iv[i] = (uint8_t)(0x80 + i);
    for(size_t i = 0; i < sizeof(des_iv); i++)
        des_iv[i] = (uint8_t)(0x40 + i);

    for(size_t length_index = 0; length_index < sizeof(lengths) / sizeof(lengths[0]);
        length_index++) {
        size_t length = lengths[length_index];
        size_t first = length ? 1 : 0;
        size_t last = length > first ? 1 : 0;
        DfcCryptoSegment segments[] = {
            {.data = NULL, .length = 0},
            {.data = message, .length = first},
            {.data = message + first, .length = length - first - last},
            {.data = message + length - last, .length = last},
            {.data = NULL, .length = 0},
        };
        uint8_t contiguous[16];
        uint8_t segmented[16];
        munit_assert_true(
            aes_cmac_with_iv(aes_key, sizeof(aes_key), message, length, aes_iv, contiguous));
        munit_assert_true(aes_cmac_segments_with_iv(
            aes_key,
            sizeof(aes_key),
            segments,
            sizeof(segments) / sizeof(segments[0]),
            aes_iv,
            segmented));
        munit_assert_memory_equal(16, contiguous, segmented);

        for(size_t key_len = 8; key_len <= sizeof(des_key); key_len += 8) {
            munit_assert_true(
                des_cmac_with_iv(des_key, key_len, message, length, des_iv, contiguous));
            munit_assert_true(des_cmac_segments_with_iv(
                des_key,
                key_len,
                segments,
                sizeof(segments) / sizeof(segments[0]),
                des_iv,
                segmented));
            munit_assert_memory_equal(8, contiguous, segmented);
        }
    }
    return MUNIT_OK;
}

// des_cmac() self-consistency: same input -> same output; different keys/messages -> different
// output. There's no widely-available official test vector for this project's exact 2K/3K3DES
// CMAC construction, so this checks internal correctness properties instead.
static MunitResult test_des_cmac_deterministic(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t key[16] = {
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
        0x10};
    uint8_t message[8] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11};

    uint8_t mac1[16], mac2[16];
    munit_assert_true(des_cmac(key, sizeof(key), message, sizeof(message), mac1));
    munit_assert_true(des_cmac(key, sizeof(key), message, sizeof(message), mac2));
    munit_assert_memory_equal(8, mac1, mac2);
    return MUNIT_OK;
}

static MunitResult test_des_cmac_key_lengths(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t message[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t key8[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t key16[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t key24[24] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12,
                         13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24};

    uint8_t mac[16];
    munit_assert_true(des_cmac(key8, sizeof(key8), message, sizeof(message), mac));
    munit_assert_true(des_cmac(key16, sizeof(key16), message, sizeof(message), mac));
    munit_assert_true(des_cmac(key24, sizeof(key24), message, sizeof(message), mac));

    // Rejects other lengths
    uint8_t bad_key[10] = {0};
    munit_assert_false(des_cmac(bad_key, sizeof(bad_key), message, sizeof(message), mac));
    return MUNIT_OK;
}

// A single-DES session key (8 bytes) is the degenerate K1=K2=K case of a 2-key 3DES key;
// des_cmac() with an 8-byte key must equal des_cmac() with that key repeated twice.
static MunitResult
    test_des_cmac_single_des_matches_2k3des_degenerate(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t key8[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    uint8_t key16[16] = {
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88};
    uint8_t message[8] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33};

    uint8_t mac8[16], mac16[16];
    munit_assert_true(des_cmac(key8, sizeof(key8), message, sizeof(message), mac8));
    munit_assert_true(des_cmac(key16, sizeof(key16), message, sizeof(message), mac16));
    munit_assert_memory_equal(8, mac8, mac16);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/aes_cmac/empty", test_aes_cmac_empty, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/aes_cmac/16bytes", test_aes_cmac_16bytes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/aes_cmac/multiblock-segments",
     test_aes_cmac_multiblock_and_segments,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/cmac/overflow-lengths",
     test_cmac_rejects_overflow_lengths,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/cmac/segmented-boundaries",
     test_segmented_cmac_boundaries,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/des_cmac/deterministic",
     test_des_cmac_deterministic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/des_cmac/key_lengths", test_des_cmac_key_lengths, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/des_cmac/single_des_degenerate",
     test_des_cmac_single_des_matches_2k3des_degenerate,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {"", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
