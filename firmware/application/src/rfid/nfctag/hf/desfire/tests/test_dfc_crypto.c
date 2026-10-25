#include "munit.h"

#include "dfc_crypto.h"
#include "dfc_ev2_crypto.h"

#include <string.h>

static MunitResult test_aes_cbc_vector(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t key[16] = {
        0x2b,
        0x7e,
        0x15,
        0x16,
        0x28,
        0xae,
        0xd2,
        0xa6,
        0xab,
        0xf7,
        0x15,
        0x88,
        0x09,
        0xcf,
        0x4f,
        0x3c};
    const uint8_t clear[16] = {
        0x6b,
        0xc1,
        0xbe,
        0xe2,
        0x2e,
        0x40,
        0x9f,
        0x96,
        0xe9,
        0x3d,
        0x7e,
        0x11,
        0x73,
        0x93,
        0x17,
        0x2a};
    const uint8_t expected[16] = {
        0x76,
        0x49,
        0xab,
        0xac,
        0x81,
        0x19,
        0xb2,
        0x46,
        0xce,
        0xe9,
        0x8e,
        0x9b,
        0x12,
        0xe9,
        0x19,
        0x7d};
    const uint8_t initial_iv[16] = {
        0x00,
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
        0x0f};
    uint8_t iv[16];
    uint8_t buffer[16];

    memcpy(iv, initial_iv, sizeof(iv));
    memcpy(buffer, clear, sizeof(buffer));
    munit_assert_true(
        dfc_crypto_aes_cbc(true, key, sizeof(key), iv, buffer, buffer, sizeof(buffer)));
    munit_assert_memory_equal(sizeof(expected), buffer, expected);
    munit_assert_memory_equal(sizeof(expected), iv, expected);

    memcpy(iv, initial_iv, sizeof(iv));
    munit_assert_true(
        dfc_crypto_aes_cbc(false, key, sizeof(key), iv, buffer, buffer, sizeof(buffer)));
    munit_assert_memory_equal(sizeof(clear), buffer, clear);
    return MUNIT_OK;
}

static MunitResult test_des_ecb_vector(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t key[8] = {0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1};
    const uint8_t clear[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    const uint8_t expected[8] = {0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05};
    uint8_t buffer[8];

    munit_assert_true(dfc_crypto_des_ecb(true, key, sizeof(key), clear, buffer));
    munit_assert_memory_equal(sizeof(expected), buffer, expected);
    munit_assert_true(dfc_crypto_des_ecb(false, key, sizeof(key), buffer, buffer));
    munit_assert_memory_equal(sizeof(clear), buffer, clear);
    return MUNIT_OK;
}

static void assert_tdes_cbc_vector(
    const uint8_t* key,
    size_t key_len,
    const uint8_t clear[16],
    const uint8_t expected[16]) {
    const uint8_t initial_iv[8] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef};
    uint8_t iv[8];
    uint8_t buffer[16];

    memcpy(iv, initial_iv, sizeof(iv));
    munit_assert_true(dfc_crypto_des_cbc(true, key, key_len, iv, clear, buffer, sizeof(buffer)));
    munit_assert_memory_equal(sizeof(buffer), buffer, expected);
    munit_assert_memory_equal(sizeof(iv), iv, expected + 8);

    memcpy(iv, initial_iv, sizeof(iv));
    munit_assert_true(dfc_crypto_des_cbc(false, key, key_len, iv, buffer, buffer, sizeof(buffer)));
    munit_assert_memory_equal(sizeof(buffer), buffer, clear);
    munit_assert_memory_equal(sizeof(iv), iv, expected + 8);
}

static MunitResult test_tdes_cbc_vectors(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    /* Pinned known-answer vectors from the tiny-crypto-c 2.0 test suite. */
    const uint8_t key_2k[16] = {
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xab,
        0xcd,
        0xef,
        0x23,
        0x45,
        0x67,
        0x89,
        0xab,
        0xcd,
        0xef,
        0x01};
    const uint8_t clear_2k[16] = {
        0x6b,
        0xc1,
        0xbe,
        0xe2,
        0x2e,
        0x40,
        0x9f,
        0x96,
        0xe9,
        0x3d,
        0x7e,
        0x11,
        0x73,
        0x93,
        0x17,
        0x2a};
    const uint8_t expected_2k[16] = {
        0xa9,
        0xf1,
        0xda,
        0x98,
        0x21,
        0xcd,
        0x5a,
        0x85,
        0x0a,
        0x07,
        0xd1,
        0x9f,
        0x76,
        0x83,
        0xa8,
        0x4b};
    const uint8_t key_3k[24] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
                                0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23};
    const uint8_t clear_3k[16] = {
        0x4e,
        0x6f,
        0x77,
        0x20,
        0x69,
        0x73,
        0x20,
        0x74,
        0x68,
        0x65,
        0x20,
        0x74,
        0x69,
        0x6d,
        0x65,
        0x20};
    const uint8_t expected_3k[16] = {
        0xf3,
        0xc0,
        0xff,
        0x02,
        0x6c,
        0x02,
        0x30,
        0x89,
        0x65,
        0x6f,
        0xbb,
        0x16,
        0x9d,
        0xef,
        0x7e,
        0xdb};

    assert_tdes_cbc_vector(key_2k, sizeof(key_2k), clear_2k, expected_2k);
    assert_tdes_cbc_vector(key_3k, sizeof(key_3k), clear_3k, expected_3k);
    return MUNIT_OK;
}

static MunitResult test_rejects_invalid_lengths(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t key[24] = {0};
    uint8_t iv[16] = {0};
    uint8_t buffer[16] = {0};

    munit_assert_false(dfc_crypto_aes_cbc(true, key, 24, iv, buffer, buffer, 16));
    munit_assert_false(dfc_crypto_aes_cbc(true, key, 16, iv, buffer, buffer, 15));
    munit_assert_false(dfc_crypto_des_cbc(true, key, 12, iv, buffer, buffer, 8));
    munit_assert_false(dfc_crypto_des_cbc(true, key, 8, iv, buffer, buffer, 7));
    return MUNIT_OK;
}

static MunitResult test_cbc_front_door_validation(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t key[24] = {0};
    const uint8_t aes_iv_initial[16] = {1, 2, 3, 4};
    const uint8_t des_iv_initial[8] = {5, 6, 7, 8};
    uint8_t iv[16];
    uint8_t output[16];
    uint8_t expected[16];
    memset(expected, 0xA5, sizeof(expected));

#define ASSERT_AES_REJECTED(k, v, in, out, len)                                \
    do {                                                                       \
        memcpy(iv, aes_iv_initial, sizeof(aes_iv_initial));                    \
        memset(output, 0xA5, sizeof(output));                                  \
        munit_assert_false(dfc_crypto_aes_cbc(true, k, 16, v, in, out, len));  \
        munit_assert_memory_equal(sizeof(aes_iv_initial), iv, aes_iv_initial); \
        munit_assert_memory_equal(sizeof(output), output, expected);           \
    } while(0)

    ASSERT_AES_REJECTED(NULL, iv, output, output, sizeof(output));
    ASSERT_AES_REJECTED(key, NULL, output, output, sizeof(output));
    ASSERT_AES_REJECTED(key, iv, NULL, output, sizeof(output));
    ASSERT_AES_REJECTED(key, iv, output, NULL, sizeof(output));
    memcpy(iv, aes_iv_initial, sizeof(aes_iv_initial));
    munit_assert_true(dfc_crypto_aes_cbc(true, key, 16, iv, NULL, NULL, 0));

#define ASSERT_DES_REJECTED(k, v, in, out, len)                                \
    do {                                                                       \
        memcpy(iv, des_iv_initial, sizeof(des_iv_initial));                    \
        memset(output, 0xA5, sizeof(output));                                  \
        munit_assert_false(dfc_crypto_des_cbc(true, k, 8, v, in, out, len));   \
        munit_assert_memory_equal(sizeof(des_iv_initial), iv, des_iv_initial); \
        munit_assert_memory_equal(sizeof(output), output, expected);           \
    } while(0)

    ASSERT_DES_REJECTED(NULL, iv, output, output, 8);
    ASSERT_DES_REJECTED(key, NULL, output, output, 8);
    ASSERT_DES_REJECTED(key, iv, NULL, output, 8);
    ASSERT_DES_REJECTED(key, iv, output, NULL, 8);
    memcpy(iv, des_iv_initial, sizeof(des_iv_initial));
    munit_assert_true(dfc_crypto_des_cbc(true, key, 8, iv, NULL, NULL, 0));

#undef ASSERT_AES_REJECTED
#undef ASSERT_DES_REJECTED
    return MUNIT_OK;
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING
static MunitResult test_ev2_encrypt_alias_and_bounds(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t key[DFC_AES_KEY_LENGTH] = {0x11};
    const uint8_t ti[DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH] = {1, 2, 3, 4};
    uint8_t clear[31];
    for(size_t i = 0; i < sizeof(clear); i++)
        clear[i] = (uint8_t)(0x40 + i);

    uint8_t expected[48] = {0};
    size_t expected_len = 0;
    munit_assert_true(dfc_ev2_encrypt_data(
        key,
        DfcEv2DirectionCommand,
        7,
        ti,
        clear,
        sizeof(clear),
        expected,
        sizeof(expected),
        &expected_len));
    munit_assert_size(expected_len, ==, 32);

    uint8_t in_place[48] = {0};
    memcpy(in_place, clear, sizeof(clear));
    size_t actual_len = 99;
    munit_assert_true(dfc_ev2_encrypt_data(
        key,
        DfcEv2DirectionCommand,
        7,
        ti,
        in_place,
        sizeof(clear),
        in_place,
        sizeof(in_place),
        &actual_len));
    munit_assert_size(actual_len, ==, expected_len);
    munit_assert_memory_equal(expected_len, in_place, expected);

    uint8_t overlap[64] = {0};
    memcpy(overlap + 3, clear, sizeof(clear));
    actual_len = 99;
    munit_assert_true(dfc_ev2_encrypt_data(
        key,
        DfcEv2DirectionCommand,
        7,
        ti,
        overlap + 3,
        sizeof(clear),
        overlap,
        sizeof(overlap),
        &actual_len));
    munit_assert_size(actual_len, ==, expected_len);
    munit_assert_memory_equal(expected_len, overlap, expected);

    uint8_t canary[32];
    memset(canary, 0xA5, sizeof(canary));
    actual_len = 99;
    munit_assert_false(dfc_ev2_encrypt_data(
        key,
        DfcEv2DirectionCommand,
        7,
        ti,
        clear,
        sizeof(clear),
        canary,
        expected_len - 1,
        &actual_len));
    munit_assert_size(actual_len, ==, 0);
    for(size_t i = 0; i < sizeof(canary); i++)
        munit_assert_uint8(canary[i], ==, 0xA5);

    actual_len = 99;
    munit_assert_false(dfc_ev2_encrypt_data(
        key, DfcEv2DirectionCommand, 7, ti, clear, SIZE_MAX, canary, SIZE_MAX, &actual_len));
    munit_assert_size(actual_len, ==, 0);
    for(size_t i = 0; i < sizeof(canary); i++)
        munit_assert_uint8(canary[i], ==, 0xA5);
    return MUNIT_OK;
}

static MunitResult test_ev2_mac_front_door_validation(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t key[DFC_AES_KEY_LENGTH] = {0};
    uint8_t ti[DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH] = {0};
    uint8_t output[DFC_WIRE_MAC_LENGTH];
    uint8_t zero[DFC_WIRE_MAC_LENGTH] = {0};

    memset(output, 0xA5, sizeof(output));
    munit_assert_false(dfc_ev2_wire_mac(NULL, NULL, 0, output));
    munit_assert_memory_equal(sizeof(output), output, zero);
    memset(output, 0xA5, sizeof(output));
    munit_assert_false(dfc_ev2_wire_mac(key, NULL, 1, output));
    munit_assert_memory_equal(sizeof(output), output, zero);
    munit_assert_false(dfc_ev2_wire_mac(key, NULL, 0, NULL));
    munit_assert_true(dfc_ev2_wire_mac(key, NULL, 0, output));

    memset(output, 0xA5, sizeof(output));
    munit_assert_false(dfc_ev2_mac(NULL, 0, 0, ti, NULL, 0, NULL, 0, output));
    munit_assert_memory_equal(sizeof(output), output, zero);
    memset(output, 0xA5, sizeof(output));
    munit_assert_false(dfc_ev2_mac(key, 0, 0, NULL, NULL, 0, NULL, 0, output));
    munit_assert_memory_equal(sizeof(output), output, zero);
    memset(output, 0xA5, sizeof(output));
    munit_assert_false(dfc_ev2_mac(key, 0, 0, ti, NULL, 1, NULL, 0, output));
    munit_assert_memory_equal(sizeof(output), output, zero);
    memset(output, 0xA5, sizeof(output));
    munit_assert_false(dfc_ev2_mac(key, 0, 0, ti, NULL, 0, NULL, 1, output));
    munit_assert_memory_equal(sizeof(output), output, zero);
    munit_assert_false(dfc_ev2_mac(key, 0, 0, ti, NULL, 0, NULL, 0, NULL));
    munit_assert_true(dfc_ev2_mac(key, 0, 0, ti, NULL, 0, NULL, 0, output));
    return MUNIT_OK;
}

static MunitResult
    test_ev2_decrypt_validation_and_alias(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t key[DFC_AES_KEY_LENGTH] = {0x11};
    const uint8_t ti[DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH] = {1, 2, 3, 4};
    const uint8_t clear[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t encrypted[32];
    size_t encrypted_len = 0;
    munit_assert_true(dfc_ev2_encrypt_data(
        key,
        DfcEv2DirectionCommand,
        7,
        ti,
        clear,
        sizeof(clear),
        encrypted,
        sizeof(encrypted),
        &encrypted_len));
    munit_assert_size(encrypted_len, ==, 32);

    uint8_t output[32];
    size_t output_len = 99;
    munit_assert_true(dfc_ev2_decrypt_data(
        key, DfcEv2DirectionCommand, 7, ti, encrypted, encrypted_len, output, &output_len, false));
    munit_assert_size(output_len, ==, sizeof(clear));
    munit_assert_memory_equal(sizeof(clear), output, clear);

    uint8_t in_place[32];
    memcpy(in_place, encrypted, sizeof(in_place));
    output_len = 99;
    munit_assert_true(dfc_ev2_decrypt_data(
        key,
        DfcEv2DirectionCommand,
        7,
        ti,
        in_place,
        sizeof(in_place),
        in_place,
        &output_len,
        false));
    munit_assert_size(output_len, ==, sizeof(clear));
    munit_assert_memory_equal(sizeof(clear), in_place, clear);

    memset(output, 0xA5, sizeof(output));
    output_len = 99;
    munit_assert_false(dfc_ev2_decrypt_data(
        NULL, DfcEv2DirectionCommand, 7, ti, encrypted, 16, output, &output_len, false));
    munit_assert_size(output_len, ==, 0);
    for(size_t i = 0; i < 16; i++)
        munit_assert_uint8(output[i], ==, 0);

    memset(output, 0xA5, sizeof(output));
    output_len = 99;
    munit_assert_false(dfc_ev2_decrypt_data(
        key, DfcEv2DirectionCommand, 7, ti, encrypted, 15, output, &output_len, false));
    munit_assert_size(output_len, ==, 0);
    for(size_t i = 0; i < 15; i++)
        munit_assert_uint8(output[i], ==, 0);

    output_len = 99;
    munit_assert_false(dfc_ev2_decrypt_data(
        key, DfcEv2DirectionCommand, 7, ti, NULL, 16, output, &output_len, false));
    munit_assert_size(output_len, ==, 0);
    for(size_t i = 0; i < 16; i++)
        munit_assert_uint8(output[i], ==, 0);

    output_len = 99;
    munit_assert_false(dfc_ev2_decrypt_data(
        key, DfcEv2DirectionCommand, 7, ti, encrypted, 0, output, &output_len, false));
    munit_assert_size(output_len, ==, 0);
    munit_assert_false(dfc_ev2_decrypt_data(
        key, DfcEv2DirectionCommand, 7, ti, encrypted, 16, output, NULL, false));

    uint8_t bad_padding[16] = {0};
    uint8_t bad_encrypted[16];
    uint8_t iv[DFC_AES_KEY_LENGTH];
    munit_assert_true(dfc_ev2_derive_iv(key, DfcEv2DirectionCommand, 7, ti, iv));
    munit_assert_true(dfc_crypto_aes_cbc(
        true, key, sizeof(key), iv, bad_padding, bad_encrypted, sizeof(bad_encrypted)));
    memset(output, 0xA5, sizeof(output));
    output_len = 99;
    munit_assert_false(dfc_ev2_decrypt_data(
        key,
        DfcEv2DirectionCommand,
        7,
        ti,
        bad_encrypted,
        sizeof(bad_encrypted),
        output,
        &output_len,
        false));
    munit_assert_size(output_len, ==, 0);
    for(size_t i = 0; i < sizeof(bad_encrypted); i++)
        munit_assert_uint8(output[i], ==, 0);

    output_len = 0;
    munit_assert_true(dfc_ev2_decrypt_data(
        key,
        DfcEv2DirectionCommand,
        7,
        ti,
        bad_encrypted,
        sizeof(bad_encrypted),
        output,
        &output_len,
        true));
    munit_assert_size(output_len, ==, sizeof(bad_padding));
    munit_assert_memory_equal(sizeof(bad_padding), output, bad_padding);
    return MUNIT_OK;
}
#endif

static MunitTest tests[] = {
    {(char*)"/aes-cbc-vector", test_aes_cbc_vector, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/des-ecb-vector", test_des_ecb_vector, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/tdes-cbc-vectors", test_tdes_cbc_vectors, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/invalid-lengths",
     test_rejects_invalid_lengths,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {(char*)"/cbc-front-door-validation",
     test_cbc_front_door_validation,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    {(char*)"/ev2-encrypt-alias-and-bounds",
     test_ev2_encrypt_alias_and_bounds,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {(char*)"/ev2-mac-front-door-validation",
     test_ev2_mac_front_door_validation,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {(char*)"/ev2-decrypt-validation-and-alias",
     test_ev2_decrypt_validation_and_alias,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {(char*)"/crypto", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
