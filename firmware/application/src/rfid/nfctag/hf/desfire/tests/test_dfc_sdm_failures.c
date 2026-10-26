#include "munit/munit.h"

#include "aes_cmac.h"
#include "auth_fault_test_support.h"
#include "dfc_common.h"
#include "dfc_sdm.h"
#include "dfc_sdm_i.h"

#include <string.h>

static const uint8_t key[16] = {0};
static const uint8_t uid[7] = {0x04, 0x83, 0xB4, 0xF2, 0xCF, 0x18, 0x90};

static void encode_hex(const uint8_t* input, size_t length, uint8_t* output) {
    static const uint8_t digits[] = "0123456789ABCDEF";
    for(size_t index = 0; index < length; index++) {
        output[index * 2] = digits[input[index] >> 4];
        output[index * 2 + 1] = digits[input[index] & 0x0F];
    }
}

static void build_message(uint8_t message[68]) {
    static const uint8_t clear[16] = {
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
    uint8_t cipher[16];
    uint8_t iv[16] = {0};
    uint8_t session_key[16];
    uint8_t mac[16];
    uint8_t wire_mac[8];
    encode_hex(uid, sizeof(uid), message);
    memcpy(message + 14, "000001", 6);
    munit_assert_true(dfc_worker_aes_cbc_encrypt(key, 16, iv, 16, clear, cipher));
    encode_hex(cipher, sizeof(cipher), message + 20);
    munit_assert_true(
        dfc_sdm_derive_session_key(key, 0x3C, 0xC3, uid, 7, true, 1, true, session_key));
    munit_assert_true(aes_cmac(session_key, 16, message + 20, 32, mac));
    dfc_truncate_aes_wire_mac(mac, wire_mac);
    encode_hex(wire_mac, sizeof(wire_mac), message + 52);
}

static MunitResult test_crypto_failures_are_atomic(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t message[68];
    auth_faults_clear();
    build_message(message);
    DfcSdmVerifyConfig config = {
        .plain_uid_length = sizeof(uid),
        .plain_uid = {.present = true, .offset = 0},
        .plain_read_counter = {.present = true, .offset = 14},
        .encrypted_file_data = {.present = true, .offset = 20},
        .encrypted_file_data_length = 32,
        .mac_input_offset = 20,
        .mac_offset = 52,
    };
    const DfcSdmVerifyResult empty = {0};
    DfcSdmVerifyResult result;
    uint8_t output[16];

    fail_aes_cbc_call = 2;
    memset(output, 0xA5, sizeof(output));
    memset(&result, 0xA5, sizeof(result));
    munit_assert_int(
        dfc_sdm_verify_ascii(
            message, sizeof(message), &config, NULL, key, output, sizeof(output), NULL, &result),
        ==,
        DfcSdmVerifyCryptoFailed);
    munit_assert_memory_equal(sizeof(result), &result, &empty);
    for(size_t index = 0; index < sizeof(output); index++)
        munit_assert_uint8(output[index], ==, 0);

    auth_faults_clear();
    build_message(message);
    fail_aes_block_call = 1;
    memset(output, 0xA5, sizeof(output));
    munit_assert_int(
        dfc_sdm_verify_ascii(
            message, sizeof(message), &config, NULL, key, output, sizeof(output), NULL, &result),
        ==,
        DfcSdmVerifyCryptoFailed);
    for(size_t index = 0; index < sizeof(output); index++)
        munit_assert_uint8(output[index], ==, 0xA5);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/crypto-failures-are-atomic", test_crypto_failures_are_atomic, NULL, NULL, 0, NULL},
    {NULL, NULL, NULL, NULL, 0, NULL},
};

static const MunitSuite suite = {"/dfc_sdm_failures", tests, NULL, 1, 0};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
