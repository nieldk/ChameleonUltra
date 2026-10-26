#include "munit/munit.h"

#include "dfc_sdm.h"
#include "dfc_sdm_i.h"

#include "aes_cmac.h"
#include "dfc_common.h"

#include <string.h>

static const uint8_t zero_key[DFC_SDM_VERIFY_AES_KEY_LENGTH] = {0};
static const uint8_t captured_uid[] = {0x04, 0x83, 0xB4, 0xF2, 0xCF, 0x18, 0x90};

static uint8_t changed_hex_digit(uint8_t value) {
    return value == '0' ? '1' : '0';
}

static void encode_hex(const uint8_t* input, size_t length, uint8_t* output) {
    static const uint8_t digits[] = "0123456789ABCDEF";
    for(size_t index = 0; index < length; index++) {
        output[index * 2] = digits[input[index] >> 4];
        output[index * 2 + 1] = digits[input[index] & 0x0F];
    }
}

static void build_encrypted_picc_message(
    const uint8_t* clear,
    size_t clear_length,
    const uint8_t* uid,
    size_t uid_length,
    bool has_counter,
    uint32_t counter,
    uint8_t* message) {
    uint8_t cipher[32] = {0};
    uint8_t iv[16] = {0};
    uint8_t session_key[16] = {0};
    uint8_t mac[16] = {0};
    uint8_t wire_mac[8] = {0};
    munit_assert_true(dfc_worker_aes_cbc_encrypt(zero_key, 16, iv, clear_length, clear, cipher));
    encode_hex(cipher, clear_length, message);
    munit_assert_true(dfc_sdm_derive_session_key(
        zero_key, 0x3C, 0xC3, uid, uid_length, uid != NULL, counter, has_counter, session_key));
    munit_assert_true(aes_cmac(session_key, 16, message, clear_length * 2, mac));
    dfc_truncate_aes_wire_mac(mac, wire_mac);
    encode_hex(wire_mac, sizeof(wire_mac), message + clear_length * 2);
}

static MunitResult test_captured_encrypted_picc_data(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    // Captured response: tests/vectors/desfire/v4/hardware/hardware_genuine_ev3_sdm_picc_native_iso.vec
    static const uint8_t message[] = "342FFCCF91C2B0730E2F4735A009A666A63259C3FD050C6E";
    DfcSdmVerifyConfig config = {
        .encrypted_picc_data = {.present = true, .offset = 0},
        .encrypted_picc_data_length = 32,
        .mac_input_offset = 0,
        .mac_offset = 32,
    };
    DfcSdmVerifyResult result;
    size_t required = SIZE_MAX;
    munit_assert_int(
        dfc_sdm_verify_ascii(
            message, sizeof(message) - 1, &config, zero_key, zero_key, NULL, 0, &required, &result),
        ==,
        DfcSdmVerifyOk);
    munit_assert_size(required, ==, 0);
    munit_assert_true(result.has_uid);
    munit_assert_size(result.uid_length, ==, sizeof(captured_uid));
    munit_assert_memory_equal(sizeof(captured_uid), result.uid, captured_uid);
    munit_assert_true(result.has_read_counter);
    munit_assert_uint32(result.read_counter, ==, 1);
    return MUNIT_OK;
}

static MunitResult test_captured_encrypted_file_data(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    // Captured response: tests/vectors/desfire/v4/hardware/hardware_genuine_ev3_sdm_encrypted_file_native_iso.vec
    static const uint8_t message[] =
        "0483B4F2CF1890000001163F0AC4319102F37F4B61FE6BFDE1469CF53E287D682A2E";
    static const uint8_t expected[] = {
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
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        0xEE,
        0xFF,
    };
    DfcSdmVerifyConfig config = {
        .plain_uid_length = sizeof(captured_uid),
        .plain_uid = {.present = true, .offset = 0},
        .plain_read_counter = {.present = true, .offset = 14},
        .encrypted_file_data = {.present = true, .offset = 20},
        .encrypted_file_data_length = 32,
        .mac_input_offset = 20,
        .mac_offset = 52,
    };
    uint8_t clear[sizeof(expected)];
    memset(clear, 0xA5, sizeof(clear));
    DfcSdmVerifyResult result;
    size_t required = 0;
    munit_assert_int(
        dfc_sdm_verify_ascii(
            message,
            sizeof(message) - 1,
            &config,
            NULL,
            zero_key,
            clear,
            sizeof(clear),
            &required,
            &result),
        ==,
        DfcSdmVerifyOk);
    munit_assert_size(required, ==, sizeof(expected));
    munit_assert_memory_equal(sizeof(expected), clear, expected);
    munit_assert_memory_equal(sizeof(captured_uid), result.uid, captured_uid);
    munit_assert_uint32(result.read_counter, ==, 1);
    munit_assert_size(result.decrypted_file_data_length, ==, sizeof(expected));
    return MUNIT_OK;
}

static MunitResult
    test_authentication_and_capacity_are_atomic(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t message[] = "0483B4F2CF1890000001163F0AC4319102F37F4B61FE6BFDE1469CF53E287D682A2E";
    DfcSdmVerifyConfig config = {
        .plain_uid_length = sizeof(captured_uid),
        .plain_uid = {.present = true, .offset = 0},
        .plain_read_counter = {.present = true, .offset = 14},
        .encrypted_file_data = {.present = true, .offset = 20},
        .encrypted_file_data_length = 32,
        .mac_input_offset = 20,
        .mac_offset = 52,
    };
    uint8_t clear[16];
    DfcSdmVerifyResult result;
    size_t required = 0;
    memset(clear, 0xA5, sizeof(clear));
    memset(&result, 0xA5, sizeof(result));
    munit_assert_int(
        dfc_sdm_verify_ascii(
            message,
            sizeof(message) - 1,
            &config,
            NULL,
            zero_key,
            clear,
            sizeof(clear) - 1,
            &required,
            &result),
        ==,
        DfcSdmVerifyBufferTooSmall);
    munit_assert_size(required, ==, sizeof(clear));
    for(size_t index = 0; index < sizeof(clear); index++)
        munit_assert_uint8(clear[index], ==, 0xA5);

    const DfcSdmVerifyResult empty = {0};
    for(size_t index = 0; index < sizeof(message) - 1; index++) {
        uint8_t saved = message[index];
        message[index] = changed_hex_digit(message[index]);
        memset(&result, 0xA5, sizeof(result));
        munit_assert_int(
            dfc_sdm_verify_ascii(
                message,
                sizeof(message) - 1,
                &config,
                NULL,
                zero_key,
                clear,
                sizeof(clear),
                &required,
                &result),
            ==,
            DfcSdmVerifyAuthenticationFailed);
        munit_assert_memory_equal(sizeof(result), &result, &empty);
        for(size_t output_index = 0; output_index < sizeof(clear); output_index++)
            munit_assert_uint8(clear[output_index], ==, 0xA5);
        message[index] = saved;
    }

    uint8_t wrong_key[sizeof(zero_key)] = {0};
    wrong_key[0] = 1;
    munit_assert_int(
        dfc_sdm_verify_ascii(
            message,
            sizeof(message) - 1,
            &config,
            NULL,
            wrong_key,
            clear,
            sizeof(clear),
            &required,
            &result),
        ==,
        DfcSdmVerifyAuthenticationFailed);

    munit_assert_int(
        dfc_sdm_verify_ascii(
            message,
            sizeof(message) - 1,
            &config,
            NULL,
            zero_key,
            message,
            sizeof(clear),
            &required,
            &result),
        ==,
        DfcSdmVerifyMalformed);
    return MUNIT_OK;
}

static MunitResult
    test_malformed_ranges_and_hex_are_rejected(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t message[] = "342FFCCF91C2B0730E2F4735A009A666A63259C3FD050C6E";
    DfcSdmVerifyConfig config = {
        .encrypted_picc_data = {.present = true, .offset = 0},
        .encrypted_picc_data_length = 32,
        .mac_input_offset = 0,
        .mac_offset = 32,
    };
    DfcSdmVerifyResult result;
    munit_assert_int(
        dfc_sdm_verify_ascii(
            message, sizeof(message) - 2, &config, zero_key, zero_key, NULL, 0, NULL, &result),
        ==,
        DfcSdmVerifyMalformed);
    message[0] = 'Z';
    munit_assert_int(
        dfc_sdm_verify_ascii(
            message, sizeof(message) - 1, &config, zero_key, zero_key, NULL, 0, NULL, &result),
        ==,
        DfcSdmVerifyMalformed);
    return MUNIT_OK;
}

static MunitResult test_picc_authentication_is_opaque(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t message[] = "342FFCCF91C2B0730E2F4735A009A666A63259C3FD050C6E";
    DfcSdmVerifyConfig config = {
        .encrypted_picc_data = {.present = true, .offset = 0},
        .encrypted_picc_data_length = 32,
        .mac_input_offset = 0,
        .mac_offset = 32,
    };
    DfcSdmVerifyResult result;
    uint8_t wrong_key[16] = {1};
    munit_assert_int(
        dfc_sdm_verify_ascii(
            message, sizeof(message) - 1, &config, wrong_key, zero_key, NULL, 0, NULL, &result),
        ==,
        DfcSdmVerifyAuthenticationFailed);
    for(size_t index = 0; index < config.encrypted_picc_data_length; index++) {
        uint8_t saved = message[index];
        message[index] = changed_hex_digit(saved);
        munit_assert_int(
            dfc_sdm_verify_ascii(
                message, sizeof(message) - 1, &config, zero_key, zero_key, NULL, 0, NULL, &result),
            ==,
            DfcSdmVerifyAuthenticationFailed);
        message[index] = saved;
    }
    return MUNIT_OK;
}

static MunitResult test_supported_field_combinations(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static const uint8_t captured[] =
        "0483B4F2CF1890000001163F0AC4319102F37F4B61FE6BFDE1469CF53E287D682A2E";
    DfcSdmVerifyConfig plain = {
        .plain_uid_length = sizeof(captured_uid),
        .plain_uid = {.present = true, .offset = 0},
        .plain_read_counter = {.present = true, .offset = 14},
        .mac_input_offset = 20,
        .mac_offset = 52,
    };
    DfcSdmVerifyResult result;
    munit_assert_int(
        dfc_sdm_verify_ascii(
            captured, sizeof(captured) - 1, &plain, NULL, zero_key, NULL, 0, NULL, &result),
        ==,
        DfcSdmVerifyOk);
    munit_assert_size(result.decrypted_file_data_length, ==, 0);

    static const uint8_t uid[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    uint8_t clear[32] = {0};
    clear[0] = 0x8A;
    memcpy(clear + 22, uid, sizeof(uid));
    uint8_t synthetic[80];
    build_encrypted_picc_message(clear, sizeof(clear), uid, sizeof(uid), false, 0, synthetic);
    DfcSdmVerifyConfig encrypted = {
        .encrypted_picc_data = {.present = true, .offset = 0},
        .encrypted_picc_data_length = 64,
        .mac_input_offset = 0,
        .mac_offset = 64,
    };
    munit_assert_int(
        dfc_sdm_verify_ascii(
            synthetic, sizeof(synthetic), &encrypted, zero_key, zero_key, NULL, 0, NULL, &result),
        ==,
        DfcSdmVerifyOk);
    munit_assert_size(result.uid_length, ==, sizeof(uid));
    munit_assert_memory_equal(sizeof(uid), result.uid, uid);
    munit_assert_false(result.has_read_counter);

    uint8_t invalid_clear[16] = {0};
    invalid_clear[0] = 0x8A;
    memcpy(invalid_clear + 6, uid, sizeof(uid));
    uint8_t invalid_short_uid[48];
    build_encrypted_picc_message(
        invalid_clear, sizeof(invalid_clear), uid, sizeof(uid), false, 0, invalid_short_uid);
    encrypted.encrypted_picc_data_length = 32;
    encrypted.mac_offset = 32;
    munit_assert_int(
        dfc_sdm_verify_ascii(
            invalid_short_uid,
            sizeof(invalid_short_uid),
            &encrypted,
            zero_key,
            zero_key,
            NULL,
            0,
            NULL,
            &result),
        ==,
        DfcSdmVerifyAuthenticationFailed);

    memset(clear, 0, 16);
    clear[0] = 0x40;
    clear[1] = 1;
    uint8_t counter_only[48];
    build_encrypted_picc_message(clear, 16, NULL, 0, true, 1, counter_only);
    encrypted.encrypted_picc_data_length = 32;
    encrypted.mac_offset = 32;
    munit_assert_int(
        dfc_sdm_verify_ascii(
            counter_only,
            sizeof(counter_only),
            &encrypted,
            zero_key,
            zero_key,
            NULL,
            0,
            NULL,
            &result),
        ==,
        DfcSdmVerifyOk);
    munit_assert_false(result.has_uid);
    munit_assert_true(result.has_read_counter);
    munit_assert_uint32(result.read_counter, ==, 1);
    return MUNIT_OK;
}

static MunitResult test_configuration_boundaries(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static const uint8_t message[] = "342FFCCF91C2B0730E2F4735A009A666A63259C3FD050C6E";
    const DfcSdmVerifyConfig valid = {
        .encrypted_picc_data = {.present = true, .offset = 0},
        .encrypted_picc_data_length = 32,
        .mac_input_offset = 0,
        .mac_offset = 32,
    };
    DfcSdmVerifyConfig config;
    DfcSdmVerifyResult result;
#define EXPECT_MALFORMED()                                                                      \
    munit_assert_int(                                                                           \
        dfc_sdm_verify_ascii(                                                                   \
            message, sizeof(message) - 1, &config, zero_key, zero_key, NULL, 0, NULL, &result), \
        ==,                                                                                     \
        DfcSdmVerifyMalformed)
    config = valid;
    config.plain_uid_length = 7;
    EXPECT_MALFORMED();
    config = valid;
    config.encrypted_picc_data.present = false;
    EXPECT_MALFORMED();
    config = valid;
    config.encrypted_file_data_length = 32;
    EXPECT_MALFORMED();
    config = valid;
    config.mac_offset = SIZE_MAX;
    EXPECT_MALFORMED();
    config = valid;
    config.encrypted_picc_data.offset = SIZE_MAX;
    EXPECT_MALFORMED();
    config = valid;
    config.mac_input_offset = SIZE_MAX;
    EXPECT_MALFORMED();

    config = valid;
    config.encrypted_file_data.present = true;
    config.encrypted_file_data.offset = 0;
    config.encrypted_file_data_length = 32;
    config.mac_input_offset = 1;
    EXPECT_MALFORMED();
    config = valid;
    config.encrypted_file_data.present = true;
    config.encrypted_file_data.offset = 16;
    config.encrypted_file_data_length = 32;
    EXPECT_MALFORMED();

    config = (DfcSdmVerifyConfig){
        .plain_uid_length = 7,
        .plain_uid = {.present = true, .offset = SIZE_MAX},
        .mac_input_offset = 0,
        .mac_offset = 32,
    };
    EXPECT_MALFORMED();
    config = (DfcSdmVerifyConfig){
        .plain_read_counter = {.present = true, .offset = SIZE_MAX},
        .mac_input_offset = 0,
        .mac_offset = 32,
    };
    EXPECT_MALFORMED();
    config = valid;
    config.encrypted_file_data.present = true;
    config.encrypted_file_data.offset = SIZE_MAX;
    config.encrypted_file_data_length = 32;
    EXPECT_MALFORMED();

    munit_assert_int(
        dfc_sdm_verify_ascii(
            message, sizeof(message) - 1, &valid, NULL, zero_key, NULL, 0, NULL, &result),
        ==,
        DfcSdmVerifyMalformed);
    munit_assert_int(
        dfc_sdm_verify_ascii(
            message, sizeof(message) - 1, &valid, zero_key, NULL, NULL, 0, NULL, &result),
        ==,
        DfcSdmVerifyMalformed);
#undef EXPECT_MALFORMED
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/captured-encrypted-picc-data", test_captured_encrypted_picc_data, NULL, NULL, 0, NULL},
    {"/captured-encrypted-file-data", test_captured_encrypted_file_data, NULL, NULL, 0, NULL},
    {"/authentication-and-capacity-are-atomic",
     test_authentication_and_capacity_are_atomic,
     NULL,
     NULL,
     0,
     NULL},
    {"/malformed-ranges-and-hex", test_malformed_ranges_and_hex_are_rejected, NULL, NULL, 0, NULL},
    {"/picc-authentication-is-opaque", test_picc_authentication_is_opaque, NULL, NULL, 0, NULL},
    {"/supported-field-combinations", test_supported_field_combinations, NULL, NULL, 0, NULL},
    {"/configuration-boundaries", test_configuration_boundaries, NULL, NULL, 0, NULL},
    {NULL, NULL, NULL, NULL, 0, NULL},
};

static const MunitSuite suite = {"/dfc_sdm_verify", tests, NULL, 1, 0};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
