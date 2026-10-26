#include "munit/munit.h"

#include "dfc_transaction_mac.h"
#include "dfc_transaction_mac_i.h"

#include <string.h>

static void
    init_captured(DfcTransactionMacVerifier* verifier, uint8_t* input, size_t input_capacity) {
    static const uint8_t key[DFC_AES_KEY_LENGTH] = {0};
    static const uint8_t uid[DFC_DESFIRE_UID_LEN] = {0x04, 0x83, 0xB4, 0xF2, 0xCF, 0x18, 0x90};
    munit_assert_int(
        dfc_transaction_mac_verifier_init(
            verifier, input, input_capacity, key, uid, sizeof(uid), 1),
        ==,
        DfcTransactionMacOk);
}

static MunitResult test_captured_credit_receipt(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t input[64] = {0};
    DfcTransactionMacVerifier verifier;
    init_captured(&verifier, input, sizeof(input));
    munit_assert_int(
        dfc_transaction_mac_add_value(&verifier, DFC_CMD_CREDIT, 5, 1), ==, DfcTransactionMacOk);

    const uint8_t captured_mac[DFC_WIRE_MAC_LENGTH] = {
        0x35, 0x2E, 0x57, 0xAD, 0xDA, 0x91, 0x1E, 0xDC};
    bool verified = false;
    munit_assert_int(
        dfc_transaction_mac_verify(&verifier, captured_mac, &verified), ==, DfcTransactionMacOk);
    munit_assert_true(verified);

    uint8_t modified_mac[DFC_WIRE_MAC_LENGTH];
    memcpy(modified_mac, captured_mac, sizeof(modified_mac));
    modified_mac[3] ^= 0x80;
    munit_assert_int(
        dfc_transaction_mac_verify(&verifier, modified_mac, &verified), ==, DfcTransactionMacOk);
    munit_assert_false(verified);
    dfc_transaction_mac_verifier_clear(&verifier);
    return MUNIT_OK;
}

static MunitResult
    test_structured_inputs_are_canonical(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t input[160] = {0};
    DfcTransactionMacVerifier verifier;
    init_captured(&verifier, input, sizeof(input));
    const uint8_t file_data[] = {0xA1, 0xB2, 0xC3};
    munit_assert_int(
        dfc_transaction_mac_add_data(
            &verifier,
            DFC_CMD_WRITE_DATA,
            2,
            0x030201,
            sizeof(file_data),
            file_data,
            sizeof(file_data)),
        ==,
        DfcTransactionMacOk);
    munit_assert_size(verifier.input_length, ==, 32);
    const uint8_t expected_header[] = {0x3D, 0x02, 0x01, 0x02, 0x03, 0x03, 0x00, 0x00};
    munit_assert_memory_equal(sizeof(expected_header), input, expected_header);
    for(size_t index = sizeof(expected_header); index < 16; index++)
        munit_assert_uint8(input[index], ==, 0);
    munit_assert_memory_equal(sizeof(file_data), input + 16, file_data);
    for(size_t index = 16 + sizeof(file_data); index < 32; index++)
        munit_assert_uint8(input[index], ==, 0);

    const uint8_t update[] = {0x44, 0x55};
    munit_assert_int(
        dfc_transaction_mac_add_record_update(
            &verifier, DFC_CMD_UPDATE_RECORD, 3, 4, 5, sizeof(update), update, sizeof(update)),
        ==,
        DfcTransactionMacOk);
    const uint8_t expected_update[] = {
        0xDB, 0x03, 0x04, 0x00, 0x00, 0x05, 0x00, 0x00, 0x02, 0x00, 0x00};
    munit_assert_memory_equal(sizeof(expected_update), input + 32, expected_update);
    munit_assert_memory_equal(sizeof(update), input + 48, update);

    uint8_t current_reader[DFC_TRANSACTION_READER_ID_LENGTH];
    uint8_t encrypted_previous[DFC_TRANSACTION_READER_ID_LENGTH];
    memset(current_reader, 0x66, sizeof(current_reader));
    memset(encrypted_previous, 0x77, sizeof(encrypted_previous));
    munit_assert_int(
        dfc_transaction_mac_add_reader_id(&verifier, current_reader, encrypted_previous),
        ==,
        DfcTransactionMacOk);
    munit_assert_size(verifier.input_length, ==, 112);
    munit_assert_uint8(input[64], ==, DFC_CMD_COMMIT_READER_ID);
    munit_assert_memory_equal(sizeof(current_reader), input + 65, current_reader);
    munit_assert_memory_equal(sizeof(encrypted_previous), input + 96, encrypted_previous);
    dfc_transaction_mac_verifier_clear(&verifier);
    return MUNIT_OK;
}

static MunitResult
    test_errors_are_atomic_and_clear_wipes(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t input[16];
    memset(input, 0xA5, sizeof(input));
    DfcTransactionMacVerifier verifier;
    init_captured(&verifier, input, sizeof(input));
    const uint8_t payload = 0x42;
    munit_assert_int(
        dfc_transaction_mac_add_data(
            &verifier, DFC_CMD_WRITE_DATA, 1, 0, 1, &payload, sizeof(payload)),
        ==,
        DfcTransactionMacCapacity);
    munit_assert_size(verifier.input_length, ==, 0);
    for(size_t index = 0; index < sizeof(input); index++)
        munit_assert_uint8(input[index], ==, 0xA5);

    munit_assert_int(
        dfc_transaction_mac_add_record_update(
            &verifier, DFC_CMD_UPDATE_RECORD, 1, 0, 0, 2, &payload, sizeof(payload)),
        ==,
        DfcTransactionMacInvalid);
    munit_assert_size(verifier.input_length, ==, 0);

    munit_assert_int(
        dfc_transaction_mac_add_value(&verifier, DFC_CMD_CREDIT, 1, 2), ==, DfcTransactionMacOk);
    dfc_transaction_mac_verifier_clear(&verifier);
    const uint8_t uid[DFC_DESFIRE_UID_LEN] = {0};
    munit_assert_int(
        dfc_transaction_mac_verifier_init(
            &verifier, input, sizeof(input), NULL, uid, sizeof(uid), 1),
        ==,
        DfcTransactionMacInvalid);
    for(size_t index = 0; index < sizeof(input); index++)
        munit_assert_uint8(input[index], ==, 0);
    const uint8_t zeroed[sizeof(verifier)] = {0};
    munit_assert_memory_equal(sizeof(verifier), &verifier, zeroed);
    return MUNIT_OK;
}

static MunitResult
    test_init_accepts_poisoned_public_storage(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t key[DFC_AES_KEY_LENGTH] = {0};
    const uint8_t uid[DFC_DESFIRE_UID_LEN] = {0};
    uint8_t input[32] = {0};
    DfcTransactionMacVerifier verifier;

    memset(&verifier, 0xA5, sizeof(verifier));
    munit_assert_int(
        dfc_transaction_mac_verifier_init(
            &verifier, input, sizeof(input), NULL, uid, sizeof(uid), 1),
        ==,
        DfcTransactionMacInvalid);
    const uint8_t zeroed[sizeof(verifier)] = {0};
    munit_assert_memory_equal(sizeof(verifier), &verifier, zeroed);

    memset(&verifier, 0xA5, sizeof(verifier));
    munit_assert_int(
        dfc_transaction_mac_verifier_init(
            &verifier, input, sizeof(input), key, uid, sizeof(uid), 1),
        ==,
        DfcTransactionMacOk);
    munit_assert_ptr_equal(verifier.input, input);
    dfc_transaction_mac_verifier_clear(&verifier);
    return MUNIT_OK;
}

static MunitResult
    test_wrong_key_counter_order_and_omission_fail(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t key[DFC_AES_KEY_LENGTH] = {0};
    const uint8_t uid[DFC_DESFIRE_UID_LEN] = {0x04, 0x83, 0xB4, 0xF2, 0xCF, 0x18, 0x90};
    const uint8_t captured_mac[DFC_WIRE_MAC_LENGTH] = {
        0x35, 0x2E, 0x57, 0xAD, 0xDA, 0x91, 0x1E, 0xDC};
    for(unsigned int variation = 0; variation < 4; variation++) {
        uint8_t input[64] = {0};
        uint8_t changed_key[sizeof(key)] = {0};
        if(variation == 0) changed_key[0] = 1;
        DfcTransactionMacVerifier verifier;
        munit_assert_int(
            dfc_transaction_mac_verifier_init(
                &verifier,
                input,
                sizeof(input),
                variation == 0 ? changed_key : key,
                uid,
                sizeof(uid),
                variation == 1 ? 2 : 1),
            ==,
            DfcTransactionMacOk);
        if(variation != 2) {
            munit_assert_int(
                dfc_transaction_mac_add_value(
                    &verifier, variation == 3 ? DFC_CMD_DEBIT : DFC_CMD_CREDIT, 5, 1),
                ==,
                DfcTransactionMacOk);
        } else {
            munit_assert_int(
                dfc_transaction_mac_add_value(&verifier, DFC_CMD_CREDIT, 6, 1),
                ==,
                DfcTransactionMacOk);
        }
        bool verified = true;
        munit_assert_int(
            dfc_transaction_mac_verify(&verifier, captured_mac, &verified),
            ==,
            DfcTransactionMacOk);
        munit_assert_false(verified);
        dfc_transaction_mac_verifier_clear(&verifier);
    }
    return MUNIT_OK;
}

static void add_two_value_operations(DfcTransactionMacVerifier* verifier, bool reverse) {
    munit_assert_int(
        dfc_transaction_mac_add_value(
            verifier, reverse ? DFC_CMD_DEBIT : DFC_CMD_CREDIT, 5, reverse ? 2 : 1),
        ==,
        DfcTransactionMacOk);
    munit_assert_int(
        dfc_transaction_mac_add_value(
            verifier, reverse ? DFC_CMD_CREDIT : DFC_CMD_DEBIT, 5, reverse ? 1 : 2),
        ==,
        DfcTransactionMacOk);
}

static MunitResult
    test_omitted_and_reordered_inputs_fail(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t expected_mac[DFC_WIRE_MAC_LENGTH] = {
        0x7B, 0xEE, 0x57, 0x7D, 0x5D, 0x8D, 0x0C, 0x69};
    for(unsigned int variation = 0; variation < 3; variation++) {
        uint8_t input[64] = {0};
        DfcTransactionMacVerifier verifier;
        init_captured(&verifier, input, sizeof(input));
        if(variation == 0) {
            add_two_value_operations(&verifier, false);
        } else if(variation == 1) {
            add_two_value_operations(&verifier, true);
        } else {
            munit_assert_int(
                dfc_transaction_mac_add_value(&verifier, DFC_CMD_CREDIT, 5, 1),
                ==,
                DfcTransactionMacOk);
        }
        bool verified = false;
        munit_assert_int(
            dfc_transaction_mac_verify(&verifier, expected_mac, &verified),
            ==,
            DfcTransactionMacOk);
        munit_assert_int(verified, ==, variation == 0);
        dfc_transaction_mac_verifier_clear(&verifier);
    }
    return MUNIT_OK;
}

static MunitResult
    test_streaming_input_exceeds_old_limit(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static const uint8_t key[DFC_AES_KEY_LENGTH] = {0};
    static const uint8_t uid[DFC_DESFIRE_UID_LEN] = {0x04, 0x83, 0xB4, 0xF2, 0xCF, 0x18, 0x90};
    static const uint8_t expected_full_mac[DFC_AES_CMAC_LENGTH] = {
        0x72,
        0xA9,
        0xFC,
        0x1D,
        0x90,
        0x15,
        0x50,
        0xB5,
        0x0C,
        0x26,
        0x3F,
        0xE9,
        0x4E,
        0xF2,
        0xA6,
        0x86};
    static const uint8_t expected_wire_mac[DFC_WIRE_MAC_LENGTH] = {
        0xA9, 0x1D, 0x15, 0xB5, 0x26, 0xE9, 0xF2, 0x86};

    uint8_t input[160] = {0};
    DfcTransactionMacVerifier verifier;
    init_captured(&verifier, input, sizeof(input));
    uint8_t session_key[DFC_AES_KEY_LENGTH] = {0};
    munit_assert_true(
        dfc_transaction_mac_derive_session_key(key, uid, sizeof(uid), 1, session_key));
    DfcTransactionMacAccumulator accumulator;
    munit_assert_true(dfc_transaction_mac_accumulator_init(&accumulator, session_key));

    for(uint32_t value = 1; value <= 10; value++) {
        uint8_t encoded[4] = {
            (uint8_t)value, (uint8_t)(value >> 8), (uint8_t)(value >> 16), (uint8_t)(value >> 24)};
        munit_assert_int(
            dfc_transaction_mac_add_value(&verifier, DFC_CMD_CREDIT, 5, value),
            ==,
            DfcTransactionMacOk);
        munit_assert_true(
            dfc_transaction_mac_accumulator_add_value(&accumulator, DFC_CMD_CREDIT, 5, encoded));
    }
    munit_assert_size(verifier.input_length, ==, sizeof(input));

    uint8_t full_mac[DFC_AES_CMAC_LENGTH] = {0};
    munit_assert_true(dfc_transaction_mac_accumulator_finalize(&accumulator, full_mac));
    munit_assert_memory_equal(sizeof(full_mac), full_mac, expected_full_mac);
    bool verified = false;
    munit_assert_int(
        dfc_transaction_mac_verify(&verifier, expected_wire_mac, &verified),
        ==,
        DfcTransactionMacOk);
    munit_assert_true(verified);

    dfc_transaction_mac_accumulator_clear(&accumulator);
    dfc_transaction_mac_verifier_clear(&verifier);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/captured-credit", test_captured_credit_receipt, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/structured-input",
     test_structured_inputs_are_canonical,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/atomic-errors",
     test_errors_are_atomic_and_clear_wipes,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/poisoned-init",
     test_init_accepts_poisoned_public_storage,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/negative-variations",
     test_wrong_key_counter_order_and_omission_fail,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ordering", test_omitted_and_reordered_inputs_fail, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/streaming-over-128",
     test_streaming_input_exceeds_old_limit,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite =
    {"/dfc_transaction_mac_verify", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
