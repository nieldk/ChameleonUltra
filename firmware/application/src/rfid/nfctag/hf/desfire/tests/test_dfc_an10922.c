#include "dfc_an10922.h"

#include <string.h>

#include "munit.h"

static MunitResult test_official_aes128_vector(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t master[] = {
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
        0xff,
    };
    const uint8_t input[] = {
        0x04,
        0x78,
        0x2e,
        0x21,
        0x80,
        0x1d,
        0x80,
        0x30,
        0x42,
        0xf5,
        0x4e,
        0x58,
        0x50,
        0x20,
        0x41,
        0x62,
        0x75,
    };
    const uint8_t expected[] = {
        0xa8,
        0xdd,
        0x63,
        0xa3,
        0xb8,
        0x9d,
        0x54,
        0xb3,
        0x7c,
        0xa8,
        0x02,
        0x47,
        0x3f,
        0xda,
        0x91,
        0x75,
    };
    uint8_t output[sizeof(expected)] = {0};

    munit_assert_true(dfc_an10922_diversify(
        DfcAn10922Aes128, master, sizeof(master), input, sizeof(input), output, sizeof(output)));
    munit_assert_memory_equal(sizeof(expected), expected, output);
    return MUNIT_OK;
}

static MunitResult test_official_tdea2_vector(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t master[] = {
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
        0xff,
    };
    const uint8_t input[] = {
        0x04,
        0x78,
        0x2e,
        0x21,
        0x80,
        0x1d,
        0x80,
        0x30,
        0x42,
        0xf5,
        0x4e,
        0x58,
        0x50,
        0x20,
        0x41,
    };
    const uint8_t expected[] = {
        0x16,
        0xf9,
        0x58,
        0x7d,
        0x9e,
        0x89,
        0x10,
        0xc9,
        0x6b,
        0x96,
        0x48,
        0xd0,
        0x06,
        0x10,
        0x7d,
        0xd7,
    };
    uint8_t output[sizeof(expected)] = {0};

    munit_assert_true(dfc_an10922_diversify(
        DfcAn10922Tdea2, master, sizeof(master), input, sizeof(input), output, sizeof(output)));
    munit_assert_memory_equal(sizeof(expected), expected, output);
    return MUNIT_OK;
}

static MunitResult test_official_tdea3_vector(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t master[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    const uint8_t input[] = {
        0x04,
        0x78,
        0x2e,
        0x21,
        0x80,
        0x1d,
        0x80,
        0x30,
        0x42,
        0xf5,
        0x4e,
        0x58,
        0x50,
    };
    const uint8_t expected[] = {
        0x2e, 0x0d, 0xd0, 0x37, 0x74, 0xd3, 0xfa, 0x9b, 0x57, 0x05, 0xab, 0x0b,
        0xda, 0x91, 0xca, 0x0b, 0x55, 0xb8, 0xe0, 0x7f, 0xcd, 0xbf, 0x10, 0xec,
    };
    uint8_t output[sizeof(expected)] = {0};

    munit_assert_true(dfc_an10922_diversify(
        DfcAn10922Tdea3, master, sizeof(master), input, sizeof(input), output, sizeof(output)));
    munit_assert_memory_equal(sizeof(expected), expected, output);
    return MUNIT_OK;
}

static MunitResult test_input_boundaries_and_overlap(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t master[24];
    uint8_t input[31];
    uint8_t expected[24];
    uint8_t overlap[32];
    for(size_t i = 0; i < sizeof(master); i++)
        master[i] = (uint8_t)(i * 7 + 1);
    for(size_t i = 0; i < sizeof(input); i++)
        input[i] = (uint8_t)(i * 5 + 3);

    munit_assert_true(
        dfc_an10922_diversify(DfcAn10922Aes128, master, 16, input, 31, expected, 16));
    memcpy(overlap, input, sizeof(input));
    munit_assert_true(
        dfc_an10922_diversify(DfcAn10922Aes128, master, 16, overlap, 31, overlap, 16));
    munit_assert_memory_equal(16, expected, overlap);

    munit_assert_true(dfc_an10922_diversify(DfcAn10922Tdea3, master, 24, input, 1, expected, 24));
    memcpy(overlap, master, sizeof(master));
    munit_assert_true(dfc_an10922_diversify(DfcAn10922Tdea3, overlap, 24, input, 1, overlap, 24));
    munit_assert_memory_equal(24, expected, overlap);
    return MUNIT_OK;
}

static MunitResult test_every_supported_input_length(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static const struct {
        DfcAn10922Algorithm algorithm;
        size_t key_len;
        size_t input_max;
    } cases[] = {
        {DfcAn10922Aes128, 16, 31},
        {DfcAn10922Tdea2, 16, 15},
        {DfcAn10922Tdea3, 24, 15},
    };
    uint8_t master[24];
    uint8_t input[31];
    uint8_t first[24];
    uint8_t second[24];
    for(size_t i = 0; i < sizeof(master); i++)
        master[i] = (uint8_t)(i * 11 + 1);
    for(size_t i = 0; i < sizeof(input); i++)
        input[i] = (uint8_t)(i * 13 + 7);

    for(size_t case_index = 0; case_index < sizeof(cases) / sizeof(cases[0]); case_index++) {
        for(size_t input_len = 1; input_len <= cases[case_index].input_max; input_len++) {
            munit_assert_true(dfc_an10922_diversify(
                cases[case_index].algorithm,
                master,
                cases[case_index].key_len,
                input,
                input_len,
                first,
                cases[case_index].key_len));
            munit_assert_true(dfc_an10922_diversify(
                cases[case_index].algorithm,
                master,
                cases[case_index].key_len,
                input,
                input_len,
                second,
                cases[case_index].key_len));
            munit_assert_memory_equal(cases[case_index].key_len, first, second);
            if(cases[case_index].algorithm != DfcAn10922Aes128) {
                for(size_t i = 0; i < 8; i++)
                    munit_assert_uint8(first[i] & 1, ==, master[i] & 1);
            }
        }
    }
    return MUNIT_OK;
}

static MunitResult
    test_rejects_invalid_inputs_atomically(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t master[24] = {0};
    uint8_t input[32] = {0};
    uint8_t output[24];
    const uint8_t zero[24] = {0};

    memset(output, 0xa5, sizeof(output));
    munit_assert_false(dfc_an10922_diversify(DfcAn10922Aes128, master, 15, input, 1, output, 16));
    munit_assert_memory_equal(16, zero, output);

    memset(output, 0xa5, sizeof(output));
    munit_assert_false(dfc_an10922_diversify(DfcAn10922Tdea2, master, 16, input, 0, output, 16));
    munit_assert_memory_equal(16, zero, output);

    memset(output, 0xa5, sizeof(output));
    munit_assert_false(dfc_an10922_diversify(DfcAn10922Tdea3, master, 24, input, 16, output, 24));
    munit_assert_memory_equal(24, zero, output);

    memset(output, 0xa5, sizeof(output));
    munit_assert_false(dfc_an10922_diversify(DfcAn10922Aes128, master, 16, input, 32, output, 16));
    munit_assert_memory_equal(16, zero, output);

    memset(output, 0xa5, sizeof(output));
    munit_assert_false(dfc_an10922_diversify(
        (DfcAn10922Algorithm)99, master, 16, input, 1, output, sizeof(output)));
    for(size_t i = 0; i < sizeof(output); i++)
        munit_assert_uint8(output[i], ==, 0xa5);

    memset(output, 0xa5, sizeof(output));
    munit_assert_false(dfc_an10922_diversify(DfcAn10922Aes128, master, 16, input, 1, output, 15));
    for(size_t i = 0; i < sizeof(output); i++)
        munit_assert_uint8(output[i], ==, 0xa5);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/official/aes128", test_official_aes128_vector, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/official/tdea2", test_official_tdea2_vector, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/official/tdea3", test_official_tdea3_vector, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/boundaries-overlap",
     test_input_boundaries_and_overlap,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/all-input-lengths",
     test_every_supported_input_length,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/invalid-atomic",
     test_rejects_invalid_inputs_atomically,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {"/an10922", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
