#include "munit/munit.h"

#include <string.h>

#include "dfc_command.h"
#include "aes_cmac.h"
#include "dfc_crypto_internal.h"
#include "dfc_emulator_commands_i.h"
#include "dfc_emulator_i.h"
#include "dfc_ev2.h"
#include "dfc_port_host.h"
#include "dfc_transaction_mac.h"
#include "dfc_virtual_picc.h"

#if DFC_ENABLE_TRANSACTION_MAC

typedef struct {
    DfcCredential credential;
    DfcVirtualPiccSession* session;
} LifecycleFixture;

static void exchange_status(
    DfcVirtualPiccSession* session,
    const uint8_t* command,
    size_t command_len,
    uint8_t expected) {
    uint8_t response[64];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, expected}));
}

static size_t exchange_response(
    DfcVirtualPiccSession* session,
    const uint8_t* command,
    size_t command_len,
    uint8_t* response,
    size_t response_capacity) {
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, command_len, response, response_capacity, &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, >=, 2);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_OK);
    return response_len - 2;
}

static DfcFile*
    add_file(DfcCredential* credential, uint8_t number, uint8_t type, size_t length, uint8_t fill) {
    DfcFile* file = dfc_credential_create_file(credential, 0, number);
    munit_assert_not_null(file);
    file->type = type;
    file->comm_settings = DFC_COMM_PLAIN;
    file->access_rights = 0xEEEE;
    if(type == DFC_FILE_TYPE_LINEAR_RECORD || type == DFC_FILE_TYPE_CYCLIC_RECORD) {
        file->state.record.size = 4;
        file->state.record.max_records = 3;
        file->state.record.count = 1;
    } else if(type == DFC_FILE_TYPE_VALUE) {
        file->state.value.lower_limit = 0;
        file->state.value.upper_limit = 100;
        file->state.value.current = 10;
        file->state.value.limited_credit = 1;
    }
    if(length) {
        munit_assert_true(dfc_file_resize(credential, file, length));
        memset(dfc_file_data(credential, file), fill, length);
    }
    return file;
}

static void add_transaction_mac_file(DfcCredential* credential) {
    DfcFile* file =
        add_file(credential, 5, DFC_FILE_TYPE_TRANSACTION_MAC, DFC_TRANSACTION_MAC_FILE_LENGTH, 0);
    // Most lifecycle tests do not exercise ReaderID, so disable that optional command.
    file->access_rights = 0xEFFE;
    file->contents_complete = true;
    memset(file->state.transaction_mac.key, 0x5A, sizeof(file->state.transaction_mac.key));
}

static void fixture_open(LifecycleFixture* fixture, bool with_transaction_mac) {
    memset(fixture, 0, sizeof(*fixture));
    dfc_credential_clear(&fixture->credential);
    fixture->credential.card.generation = DfcGenerationEv3;
    fixture->credential.card.storage = DfcStorage4KByteCount;
    fixture->credential.picc_has_static_signature = true;
    const uint8_t uid[] = {0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    memcpy(fixture->credential.uid, uid, sizeof(uid));
    fixture->credential.uid_len = sizeof(uid);
    const uint8_t aid[] = {1, 2, 3};
    munit_assert_not_null(dfc_credential_create_application_desfire_order(
        &fixture->credential, aid, 0x0F, DFC_KEY_TYPE_DES_2K3DES | 1));
    add_file(&fixture->credential, 1, DFC_FILE_TYPE_BACKUP_DATA, 8, 0x21);
    add_file(&fixture->credential, 2, DFC_FILE_TYPE_LINEAR_RECORD, 12, 0x32);
    add_file(&fixture->credential, 3, DFC_FILE_TYPE_CYCLIC_RECORD, 12, 0x43);
    add_file(&fixture->credential, 4, DFC_FILE_TYPE_VALUE, 0, 0);
    if(with_transaction_mac) add_transaction_mac_file(&fixture->credential);
    dfc_credential_clear_dirty(&fixture->credential);

    fixture->session = dfc_virtual_picc_session_alloc(&fixture->credential);
    munit_assert_not_null(fixture->session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(fixture->session, &activation),
        ==,
        DfcVirtualPiccStatusOk);
    const uint8_t select[] = {0x90, DFC_CMD_SELECT_APPLICATION, 0, 0, 3, 1, 2, 3, 0};
    exchange_status(fixture->session, select, sizeof(select), DFC_STATUS_OK);
}

static void fixture_close(LifecycleFixture* fixture) {
    dfc_virtual_picc_session_free(fixture->session);
}

static void open_pending(LifecycleFixture* fixture, const char* family) {
    if(strcmp(family, "backup") == 0 || strcmp(family, "mixed") == 0) {
        const uint8_t command[] = {
            0x90, DFC_CMD_WRITE_DATA, 0, 0, 11, 1, 0, 0, 0, 4, 0, 0, 0xB1, 0xB2, 0xB3, 0xB4, 0};
        exchange_status(fixture->session, command, sizeof(command), DFC_STATUS_OK);
    }
    if(strcmp(family, "linear") == 0 || strcmp(family, "mixed") == 0) {
        const uint8_t command[] = {
            0x90, DFC_CMD_WRITE_RECORD, 0, 0, 11, 2, 0, 0, 0, 4, 0, 0, 0xC1, 0xC2, 0xC3, 0xC4, 0};
        exchange_status(fixture->session, command, sizeof(command), DFC_STATUS_OK);
    }
    if(strcmp(family, "cyclic") == 0 || strcmp(family, "mixed") == 0) {
        const uint8_t command[] = {
            0x90, DFC_CMD_WRITE_RECORD, 0, 0, 11, 3, 0, 0, 0, 4, 0, 0, 0xD1, 0xD2, 0xD3, 0xD4, 0};
        exchange_status(fixture->session, command, sizeof(command), DFC_STATUS_OK);
    }
    if(strcmp(family, "value") == 0 || strcmp(family, "mixed") == 0) {
        const uint8_t command[] = {0x90, DFC_CMD_CREDIT, 0, 0, 5, 4, 5, 0, 0, 0, 0};
        exchange_status(fixture->session, command, sizeof(command), DFC_STATUS_OK);
    }
    if(strcmp(family, "input") == 0 || strcmp(family, "mixed") == 0) {
        memset(
            &fixture->session->emulator->transaction_mac,
            0xA5,
            sizeof(fixture->session->emulator->transaction_mac));
        fixture->session->emulator->transaction_mac.initialized = true;
        fixture->session->emulator->transaction_mac.has_pending = true;
    }
}

typedef struct {
    bool dirty;
    uint8_t* snapshot_pool;
    size_t snapshot_length;
} PendingState;

static PendingState capture_pending_state(const LifecycleFixture* fixture) {
    return (PendingState){
        .dirty = fixture->credential.dirty,
        .snapshot_pool = fixture->session->emulator->transaction_snapshot_pool,
        .snapshot_length = fixture->session->emulator->transaction_snapshot_pool_length,
    };
}

static void assert_mixed_pending_unchanged(LifecycleFixture* fixture, PendingState before) {
    const DfcEmulator* emulator = fixture->session->emulator;
    DfcFile* backup = dfc_credential_find_file_in_app(&fixture->credential, 0, 1);
    DfcFile* linear = dfc_credential_find_file_in_app(&fixture->credential, 0, 2);
    DfcFile* cyclic = dfc_credential_find_file_in_app(&fixture->credential, 0, 3);
    DfcFile* value = dfc_credential_find_file_in_app(&fixture->credential, 0, 4);
    munit_assert_true(emulator->transaction_snapshot_active);
    munit_assert_ptr_equal(emulator->transaction_snapshot_pool, before.snapshot_pool);
    munit_assert_size(emulator->transaction_snapshot_pool_length, ==, before.snapshot_length);
    munit_assert_int(fixture->credential.dirty, ==, before.dirty);
    munit_assert_true(backup->transaction_pending);
    munit_assert_memory_equal(
        8,
        dfc_file_data_const(&fixture->credential, backup),
        ((uint8_t[]){0xB1, 0xB2, 0xB3, 0xB4, 0x21, 0x21, 0x21, 0x21}));
    munit_assert_true(linear->transaction_pending);
    munit_assert_uint32(linear->state.record.count, ==, 2);
    munit_assert_memory_equal(
        8,
        dfc_file_data_const(&fixture->credential, linear),
        ((uint8_t[]){0x32, 0x32, 0x32, 0x32, 0xC1, 0xC2, 0xC3, 0xC4}));
    munit_assert_true(cyclic->transaction_pending);
    munit_assert_uint32(cyclic->state.record.count, ==, 2);
    munit_assert_memory_equal(
        8,
        dfc_file_data_const(&fixture->credential, cyclic),
        ((uint8_t[]){0x43, 0x43, 0x43, 0x43, 0xD1, 0xD2, 0xD3, 0xD4}));
    munit_assert_true(value->state.value.pending);
    munit_assert_int32(value->state.value.pending_delta, ==, 5);
    munit_assert_int32(value->state.value.current, ==, 10);
    munit_assert_true(emulator->transaction_mac.initialized);
    munit_assert_true(emulator->transaction_mac.has_pending);
}

static void assert_transaction_retired(LifecycleFixture* fixture, bool verify_abort_status) {
    DfcFile* backup = dfc_credential_find_file_in_app(&fixture->credential, 0, 1);
    DfcFile* linear = dfc_credential_find_file_in_app(&fixture->credential, 0, 2);
    DfcFile* cyclic = dfc_credential_find_file_in_app(&fixture->credential, 0, 3);
    DfcFile* value = dfc_credential_find_file_in_app(&fixture->credential, 0, 4);
    munit_assert_false(fixture->session->emulator->transaction_snapshot_active);
    munit_assert_null(fixture->session->emulator->transaction_snapshot_pool);
    munit_assert_false(backup->transaction_pending);
    munit_assert_false(linear->transaction_pending);
    munit_assert_false(cyclic->transaction_pending);
    munit_assert_false(value->state.value.pending);
    munit_assert_int32(value->state.value.current, ==, 10);
    munit_assert_memory_equal(
        sizeof(fixture->session->emulator->transaction_mac),
        &fixture->session->emulator->transaction_mac,
        &(DfcTransactionMacAccumulator){0});
    munit_assert_memory_equal(
        4,
        dfc_file_data_const(&fixture->credential, backup),
        ((uint8_t[]){0x21, 0x21, 0x21, 0x21}));
    munit_assert_uint32(linear->state.record.count, ==, 1);
    munit_assert_uint32(cyclic->state.record.count, ==, 1);
    if(verify_abort_status) {
        const uint8_t abort[] = {0x90, DFC_CMD_ABORT_TRANSACTION, 0, 0, 0};
        exchange_status(fixture->session, abort, sizeof(abort), DFC_STATUS_NO_CHANGES);
    }
}

static size_t build_create_transaction_mac(uint8_t file_number, uint8_t apdu[64]) {
    DfcCommand command;
    DfcCommandTransactionMacFile file = {
        .file_no = file_number,
        .comm_settings = DFC_COMM_PLAIN,
        .access_rights = 0xEFEE,
        .key_type = DFC_TRANSACTION_MAC_KEY_TYPE_AES,
        .key_version = 1,
    };
    memset(file.key, 0x5A, sizeof(file.key));
    munit_assert_int(dfc_command_create_transaction_mac_file(&command, &file), ==, DfcCommandOk);
    size_t apdu_len = 0;
    munit_assert_int(dfc_command_to_apdu(&command, apdu, 64, &apdu_len), ==, DfcCommandOk);
    return apdu_len;
}

static void create_transaction_mac(LifecycleFixture* fixture) {
    uint8_t apdu[64];
    size_t apdu_len = build_create_transaction_mac(5, apdu);
    exchange_status(fixture->session, apdu, apdu_len, DFC_STATUS_OK);
    DfcFile* file = dfc_credential_find_file_in_app(&fixture->credential, 0, 5);
    munit_assert_not_null(file);
    munit_assert_uint8(file->state.transaction_mac.key_type, ==, DFC_TRANSACTION_MAC_KEY_TYPE_AES);
    munit_assert_uint32(file->state.transaction_mac.counter, ==, 0);
}

static void
    assert_transaction_receipt(LifecycleFixture* fixture, DfcTransactionMacVerifier* verifier) {
    munit_assert_true(fixture->session->emulator->transaction_mac.has_pending);
    const uint8_t commit[] = {
        0x90, DFC_CMD_COMMIT_TRANSACTION, 0, 0, 1, DFC_TRANSACTION_COMMIT_RETURN_MAC_OPTION, 0};
    uint8_t response[32] = {0};
    size_t payload_len =
        exchange_response(fixture->session, commit, sizeof(commit), response, sizeof(response));
    munit_assert_size(payload_len, ==, DFC_UINT32_BYTE_COUNT + DFC_WIRE_MAC_LENGTH);
    munit_assert_memory_equal(DFC_UINT32_BYTE_COUNT, response, ((uint8_t[]){1, 0, 0, 0}));
    bool verified = false;
    munit_assert_int(
        dfc_transaction_mac_verify(verifier, response + DFC_UINT32_BYTE_COUNT, &verified),
        ==,
        DfcTransactionMacOk);
    munit_assert_true(verified);
}

static void init_fixture_verifier(
    const LifecycleFixture* fixture,
    DfcTransactionMacVerifier* verifier,
    uint8_t* input,
    size_t input_capacity) {
    uint8_t key[DFC_AES_KEY_LENGTH];
    memset(key, 0x5A, sizeof(key));
    munit_assert_int(
        dfc_transaction_mac_verifier_init(
            verifier,
            input,
            input_capacity,
            key,
            fixture->credential.uid,
            fixture->credential.uid_len,
            1),
        ==,
        DfcTransactionMacOk);
    dfc_secure_wipe(key, sizeof(key));
}

static MunitResult test_data_value_and_record_receipts_match_structured_inputs(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;

    LifecycleFixture fixture;
    DfcTransactionMacVerifier verifier;
    uint8_t input[128] = {0};
    uint8_t response[32] = {0};

    fixture_open(&fixture, true);
    init_fixture_verifier(&fixture, &verifier, input, sizeof(input));
    const uint8_t read_data[] = {0x90, DFC_CMD_READ_DATA, 0, 0, 7, 1, 0, 0, 0, 4, 0, 0, 0};
    munit_assert_size(
        exchange_response(
            fixture.session, read_data, sizeof(read_data), response, sizeof(response)),
        ==,
        4);
    munit_assert_int(
        dfc_transaction_mac_add_data(&verifier, DFC_CMD_READ_DATA, 1, 0, 4, response, 4),
        ==,
        DfcTransactionMacOk);
    assert_transaction_receipt(&fixture, &verifier);
    dfc_transaction_mac_verifier_clear(&verifier);
    fixture_close(&fixture);

    memset(input, 0, sizeof(input));
    fixture_open(&fixture, true);
    init_fixture_verifier(&fixture, &verifier, input, sizeof(input));
    const uint8_t get_value[] = {0x90, DFC_CMD_GET_VALUE, 0, 0, 1, 4, 0};
    munit_assert_size(
        exchange_response(
            fixture.session, get_value, sizeof(get_value), response, sizeof(response)),
        ==,
        4);
    uint32_t value = (uint32_t)response[0] | ((uint32_t)response[1] << 8) |
                     ((uint32_t)response[2] << 16) | ((uint32_t)response[3] << 24);
    munit_assert_int(
        dfc_transaction_mac_add_value(&verifier, DFC_CMD_GET_VALUE, 4, value),
        ==,
        DfcTransactionMacOk);
    assert_transaction_receipt(&fixture, &verifier);
    dfc_transaction_mac_verifier_clear(&verifier);
    fixture_close(&fixture);

    memset(input, 0, sizeof(input));
    fixture_open(&fixture, true);
    init_fixture_verifier(&fixture, &verifier, input, sizeof(input));
    const uint8_t record_data[] = {0xA1, 0xA2, 0xA3, 0xA4};
    const uint8_t write_record[] = {
        0x90, DFC_CMD_WRITE_RECORD, 0, 0, 11, 2, 0, 0, 0, 4, 0, 0, 0xA1, 0xA2, 0xA3, 0xA4, 0};
    munit_assert_size(
        exchange_response(
            fixture.session, write_record, sizeof(write_record), response, sizeof(response)),
        ==,
        0);
    munit_assert_int(
        dfc_transaction_mac_add_data(
            &verifier,
            DFC_CMD_WRITE_RECORD,
            2,
            0,
            sizeof(record_data),
            record_data,
            sizeof(record_data)),
        ==,
        DfcTransactionMacOk);
    assert_transaction_receipt(&fixture, &verifier);
    dfc_transaction_mac_verifier_clear(&verifier);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_free_reader_id_is_one_shot_and_not_persisted(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    LifecycleFixture fixture;
    fixture_open(&fixture, true);
    DfcFile* transaction = dfc_credential_find_file_in_app(&fixture.credential, 0, 5);
    munit_assert_not_null(transaction);
    transaction->access_rights = 0xEFEE;
    memset(
        transaction->state.transaction_mac.previous_reader_id,
        0x77,
        sizeof(transaction->state.transaction_mac.previous_reader_id));
    const uint8_t reader_id[] = {0x90, DFC_CMD_COMMIT_READER_ID,
                                 0,    0,
                                 16,   0x10,
                                 0x11, 0x12,
                                 0x13, 0x14,
                                 0x15, 0x16,
                                 0x17, 0x18,
                                 0x19, 0x1A,
                                 0x1B, 0x1C,
                                 0x1D, 0x1E,
                                 0x1F, 0};
    exchange_status(fixture.session, reader_id, sizeof(reader_id), DFC_STATUS_OK);
    munit_assert_true(fixture.session->emulator->transaction_mac.has_pending);
    munit_assert_true(fixture.session->emulator->transaction_reader_id_pending);
    munit_assert_false(fixture.session->emulator->transaction_reader_id_persist);
    const uint8_t commit[] = {0x90, DFC_CMD_COMMIT_TRANSACTION, 0, 0, 0};
    exchange_status(fixture.session, commit, sizeof(commit), DFC_STATUS_OK);
    uint8_t expected_previous[DFC_TRANSACTION_READER_ID_LENGTH];
    memset(expected_previous, 0x77, sizeof(expected_previous));
    munit_assert_memory_equal(
        sizeof(transaction->state.transaction_mac.previous_reader_id),
        transaction->state.transaction_mac.previous_reader_id,
        expected_previous);
    fixture_close(&fixture);

    fixture_open(&fixture, true);
    transaction = dfc_credential_find_file_in_app(&fixture.credential, 0, 5);
    transaction->access_rights = 0xEFEE;
    exchange_status(fixture.session, reader_id, sizeof(reader_id), DFC_STATUS_OK);
    exchange_status(fixture.session, reader_id, sizeof(reader_id), DFC_STATUS_PERMISSION_DENIED);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_reader_id_access_and_commit_requirement(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    LifecycleFixture fixture;
    fixture_open(&fixture, true);
    DfcFile* transaction = dfc_credential_find_file_in_app(&fixture.credential, 0, 5);
    const uint8_t reader_id[] = {0x90, DFC_CMD_COMMIT_READER_ID,
                                 0,    0,
                                 16,   1,
                                 2,    3,
                                 4,    5,
                                 6,    7,
                                 8,    9,
                                 10,   11,
                                 12,   13,
                                 14,   15,
                                 16,   0};
    transaction->access_rights = 0xEFFE;
    exchange_status(fixture.session, reader_id, sizeof(reader_id), DFC_STATUS_PERMISSION_DENIED);
    transaction->access_rights = 0xEF0E;
    exchange_status(fixture.session, reader_id, sizeof(reader_id), DFC_STATUS_AUTHENTICATION_ERR);

    transaction->access_rights = 0xEFEE;
    const uint8_t read[] = {0x90, DFC_CMD_READ_DATA, 0, 0, 7, 1, 0, 0, 0, 1, 0, 0, 0};
    uint8_t response[8];
    munit_assert_size(
        exchange_response(fixture.session, read, sizeof(read), response, sizeof(response)), ==, 1);
    const uint8_t commit[] = {0x90, DFC_CMD_COMMIT_TRANSACTION, 0, 0, 0};
    exchange_status(fixture.session, commit, sizeof(commit), DFC_STATUS_PERMISSION_DENIED);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_data_block_starting_with_reader_id_command_is_not_reader_state(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;

    LifecycleFixture fixture;
    fixture_open(&fixture, true);
    DfcFile* file = dfc_credential_find_file_in_app(&fixture.credential, 0, 1);
    munit_assert_true(dfc_file_resize(&fixture.credential, file, 16));
    memset(dfc_file_data(&fixture.credential, file), 0x31, 16);
    dfc_file_data(&fixture.credential, file)[0] = DFC_CMD_COMMIT_READER_ID;
    const uint8_t read[] = {0x90, DFC_CMD_READ_DATA, 0, 0, 7, 1, 0, 0, 0, 16, 0, 0, 0};
    uint8_t response[32];
    munit_assert_size(
        exchange_response(fixture.session, read, sizeof(read), response, sizeof(response)),
        ==,
        16);
    munit_assert_false(fixture.session->emulator->transaction_reader_id_pending);
    const uint8_t commit[] = {0x90, DFC_CMD_COMMIT_TRANSACTION, 0, 0, 0};
    exchange_status(fixture.session, commit, sizeof(commit), DFC_STATUS_OK);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static void assert_direct_write_status(
    DfcEmulator* emulator,
    const uint8_t* command,
    size_t command_length,
    DfcByteBuf* response,
    uint8_t expected_status) {
    dfc_emulator_command_write_data(emulator, command, command_length, response);
    munit_assert_size(dfc_bytebuf_get_size_bytes(response), ==, 1);
    munit_assert_uint8(dfc_bytebuf_get_data(response)[0], ==, expected_status);
}

static MunitResult test_write_data_preparation_failures_preserve_transcript(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;

    const uint8_t write[] = {DFC_CMD_WRITE_DATA, 1, 0, 0, 0, 1, 0, 0, 0xBC};
    uint8_t expected_transcript[16];
    memset(expected_transcript, 0xA5, sizeof(expected_transcript));

    LifecycleFixture fixture;
    fixture_open(&fixture, true);
    DfcEmulator* emulator = fixture.session->emulator;
    memset(&emulator->transaction_mac, 0xA5, sizeof(emulator->transaction_mac));
    emulator->transaction_mac.initialized = true;
    emulator->transaction_mac.has_pending = true;
    DfcTransactionMacAccumulator expected_accumulator = emulator->transaction_mac;
    uint8_t original[8];
    DfcFile* file = dfc_credential_find_file_in_app(&fixture.credential, 0, 1);
    memcpy(original, dfc_file_data_const(&fixture.credential, file), sizeof(original));
    DfcByteBuf* response = dfc_bytebuf_alloc(8);
    munit_assert_not_null(response);
    dfc_host_fail_next_allocation(DfcAllocTransactionSnapshot);
    assert_direct_write_status(
        emulator, write, sizeof(write), response, DFC_STATUS_PERMISSION_DENIED);
    munit_assert_memory_equal(
        sizeof(expected_accumulator), &emulator->transaction_mac, &expected_accumulator);
    munit_assert_memory_equal(
        sizeof(original), dfc_file_data_const(&fixture.credential, file), original);
    munit_assert_false(emulator->transaction_snapshot_active);
    dfc_bytebuf_free(response);
    fixture_close(&fixture);
    return MUNIT_OK;
}

// Synthetic oracle: these fixtures construct protected commands directly from
// the cipher primitives. Expected TMI and TMV bytes are literal test data.
enum {
    TestDesKeyLength = 8
};

static void oracle_d40_mac(
    const uint8_t key[TestDesKeyLength],
    const uint8_t* input,
    size_t input_length,
    uint8_t output[DFC_SM_LEGACY_MAC_LENGTH]) {
    uint8_t chaining[DFC_SM_LEGACY_BLOCK_SIZE] = {0};
    DfcCryptoDesBlock cipher;
    munit_assert_true(dfc_crypto_des_block_init(&cipher, true, key, TestDesKeyLength));
    for(size_t offset = 0; offset < input_length; offset += sizeof(chaining)) {
        uint8_t block[DFC_SM_LEGACY_BLOCK_SIZE] = {0};
        size_t count = DFC_MIN(sizeof(block), input_length - offset);
        memcpy(block, input + offset, count);
        for(size_t index = 0; index < sizeof(block); index++)
            block[index] ^= chaining[index];
        munit_assert_true(dfc_crypto_des_block_crypt(&cipher, block, chaining));
    }
    memcpy(output, chaining, DFC_SM_LEGACY_MAC_LENGTH);
    dfc_crypto_des_block_clear(&cipher);
}

static void oracle_ev1_command_mac(
    const uint8_t key[DFC_AES_KEY_LENGTH],
    uint8_t command,
    const uint8_t* data,
    size_t data_length,
    uint8_t output[DFC_WIRE_MAC_LENGTH]) {
    uint8_t message[1 + DFC_TRANSACTION_READER_ID_LENGTH];
    uint8_t full[DFC_AES_CMAC_LENGTH];
    message[0] = command;
    memcpy(message + 1, data, data_length);
    munit_assert_true(aes_cmac((uint8_t*)key, DFC_AES_KEY_LENGTH, message, data_length + 1, full));
    memcpy(output, full, DFC_WIRE_MAC_LENGTH);
}

static size_t oracle_full_value_command(
    uint8_t cipher,
    const uint8_t* key,
    size_t key_length,
    uint8_t command,
    const uint8_t amount[4],
    uint8_t output[2 + DFC_AES_KEY_LENGTH]) {
    output[0] = command;
    output[1] = 4;
    if(cipher == DFC_CMD_AUTHENTICATE_LEGACY) {
        uint8_t block[DFC_SM_LEGACY_BLOCK_SIZE] = {0};
        memcpy(block, amount, 4);
        uint16_t crc = dfc_crc16_iso14443(amount, 4);
        block[4] = (uint8_t)crc;
        block[5] = (uint8_t)(crc >> 8);
        DfcCryptoDesBlock des;
        munit_assert_true(dfc_crypto_des_block_init(&des, false, key, key_length));
        munit_assert_true(dfc_crypto_des_block_crypt(&des, block, output + 2));
        dfc_crypto_des_block_clear(&des);
        return 2 + sizeof(block);
    }

    uint8_t block[DFC_AES_KEY_LENGTH] = {0};
    memcpy(block, amount, 4);
    uint32_t crc = 0xFFFFFFFF;
    crc = dfc_crc32_extend(crc, output, 2);
    crc = dfc_crc32_extend(crc, amount, 4);
    for(size_t index = 0; index < 4; index++)
        block[4 + index] = (uint8_t)(crc >> (index * 8));
    uint8_t iv[DFC_AES_KEY_LENGTH] = {0};
    munit_assert_true(
        dfc_worker_aes_cbc_encrypt(key, key_length, iv, sizeof(block), block, output + 2));
    return 2 + sizeof(block);
}

static void assert_commit_reader_id_oracle(uint8_t cipher, size_t key_length) {
    LifecycleFixture fixture;
    fixture_open(&fixture, true);
    DfcEmulator* emulator = fixture.session->emulator;
    DfcFile* transaction = dfc_credential_find_file_in_app(&fixture.credential, 0, 5);
    transaction->access_rights = 0xEF0E;
    uint8_t key[DFC_AES_KEY_LENGTH] = {0};
    emulator->secure_messaging = dfc_secure_messaging_alloc(cipher, key, key_length, NULL);
    munit_assert_not_null(emulator->secure_messaging);
    emulator->auth_cipher = cipher;
    emulator->auth_key_no = 0;
    munit_assert_true(dfc_emulator_native_authentication_active(emulator));

    uint8_t command[1 + DFC_TRANSACTION_READER_ID_LENGTH + DFC_WIRE_MAC_LENGTH] = {
        DFC_CMD_COMMIT_READER_ID};
    for(size_t index = 0; index < DFC_TRANSACTION_READER_ID_LENGTH; index++)
        command[index + 1] = (uint8_t)(0x20 + index);
    size_t mac_length;
    if(cipher == DFC_CMD_AUTHENTICATE_LEGACY) {
        mac_length = DFC_SM_LEGACY_MAC_LENGTH;
        oracle_d40_mac(key, command + 1, DFC_TRANSACTION_READER_ID_LENGTH, command + 17);
    } else {
        mac_length = DFC_WIRE_MAC_LENGTH;
        oracle_ev1_command_mac(
            key, command[0], command + 1, DFC_TRANSACTION_READER_ID_LENGTH, command + 17);
    }

    DfcByteBuf* response = dfc_bytebuf_alloc(32);
    munit_assert_not_null(response);
    dfc_emulator_command_commit_reader_id(emulator, command, 17, response);
    munit_assert_uint8(dfc_bytebuf_get_data(response)[0], ==, DFC_STATUS_INTEGRITY_ERROR);
    dfc_bytebuf_reset(response);
    dfc_emulator_command_commit_reader_id(emulator, command, 17 + mac_length, response);
    munit_assert_uint8(dfc_bytebuf_get_data(response)[0], ==, DFC_STATUS_OK);

    uint8_t expected_prefix[2 * DFC_AES_KEY_LENGTH] = {DFC_CMD_COMMIT_READER_ID};
    memcpy(expected_prefix + 1, command + 1, DFC_TRANSACTION_READER_ID_LENGTH);
    munit_assert_true(emulator->transaction_mac.has_pending);
    dfc_bytebuf_free(response);
    fixture_close(&fixture);
}

static MunitResult
    test_commit_reader_id_secure_mode_oracles(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    // Synthetic oracle: command MAC construction is local to this test and the
    // expected clear TMI is literal, rather than produced by transaction helpers.
    assert_commit_reader_id_oracle(DFC_CMD_AUTHENTICATE_LEGACY, TestDesKeyLength);
    assert_commit_reader_id_oracle(DFC_CMD_AUTHENTICATE_AES, DFC_AES_KEY_LENGTH);
    return MUNIT_OK;
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING
static MunitResult
    test_commit_reader_id_ev2_mac_only_oracle(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    LifecycleFixture fixture;
    fixture_open(&fixture, true);
    DfcEmulator* emulator = fixture.session->emulator;
    DfcFile* transaction = dfc_credential_find_file_in_app(&fixture.credential, 0, 5);
    transaction->access_rights = 0xEF0E;
    emulator->auth_key_no = 0;
    emulator->ev2_session_active = true;
    const uint8_t transaction_identifier[DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH] = {1, 2, 3, 4};
    memcpy(
        emulator->ev2_transaction_identifier,
        transaction_identifier,
        sizeof(transaction_identifier));

    uint8_t secured[1 + DFC_TRANSACTION_READER_ID_LENGTH + DFC_WIRE_MAC_LENGTH] = {
        DFC_CMD_COMMIT_READER_ID};
    for(size_t index = 0; index < DFC_TRANSACTION_READER_ID_LENGTH; index++)
        secured[index + 1] = (uint8_t)(0x40 + index);
    uint8_t mac_input
        [1 + 2 + DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH + DFC_TRANSACTION_READER_ID_LENGTH] = {
            DFC_CMD_COMMIT_READER_ID};
    memcpy(mac_input + 3, transaction_identifier, sizeof(transaction_identifier));
    memcpy(mac_input + 7, secured + 1, DFC_TRANSACTION_READER_ID_LENGTH);
    uint8_t full_mac[DFC_AES_CMAC_LENGTH];
    munit_assert_true(aes_cmac(
        emulator->ev2_session_mac_key, DFC_AES_KEY_LENGTH, mac_input, sizeof(mac_input), full_mac));
    for(size_t index = 0; index < DFC_WIRE_MAC_LENGTH; index++)
        secured[17 + index] = full_mac[index * 2 + 1];

    uint8_t clear[1 + DFC_TRANSACTION_READER_ID_LENGTH];
    size_t clear_length = 0;
    munit_assert_int(
        dfc_ev2_prepare_command(
            emulator, secured, sizeof(secured), clear, sizeof(clear), &clear_length),
        ==,
        DfcEv2CommandSecured);
    munit_assert_size(clear_length, ==, sizeof(clear));
    munit_assert_memory_equal(sizeof(clear), clear, secured);

    DfcByteBuf* response = dfc_bytebuf_alloc(32);
    munit_assert_not_null(response);
    dfc_emulator_command_commit_reader_id(emulator, clear, clear_length, response);
    munit_assert_uint8(dfc_bytebuf_get_data(response)[0], ==, DFC_STATUS_OK);
    uint8_t expected_prefix[2 * DFC_AES_KEY_LENGTH] = {DFC_CMD_COMMIT_READER_ID};
    memcpy(expected_prefix + 1, secured + 1, DFC_TRANSACTION_READER_ID_LENGTH);
    munit_assert_true(emulator->transaction_mac.has_pending);
    dfc_bytebuf_free(response);
    fixture_close(&fixture);
    return MUNIT_OK;
}
#endif

static void assert_full_value_transaction_oracle(uint8_t cipher, size_t key_length) {
    const uint8_t commands[] = {DFC_CMD_CREDIT, DFC_CMD_DEBIT, DFC_CMD_LIMITED_CREDIT};
    const uint32_t amounts[] = {5, 2, 1};
    const uint8_t expected_tmvs[][DFC_WIRE_MAC_LENGTH] = {
        {0x26, 0xC8, 0xAF, 0xE3, 0xD6, 0x86, 0xCC, 0x45},
        {0xA6, 0x48, 0x2B, 0x23, 0x88, 0x99, 0x88, 0x99},
        {0x52, 0xE5, 0x35, 0x67, 0xB5, 0x7D, 0x5D, 0x95},
    };
    for(size_t index = 0; index < sizeof(commands); index++) {
        LifecycleFixture fixture;
        fixture_open(&fixture, true);
        DfcFile* value = dfc_credential_find_file_in_app(&fixture.credential, 0, 4);
        value->comm_settings = DFC_COMM_ENCIPHERED;
        value->access_rights = 0x0000;
        value->state.value.limited_credit_value = 10;
        uint8_t session_key[DFC_MAX_KEY_LEN] = {0};
        fixture.session->emulator->secure_messaging =
            dfc_secure_messaging_alloc(cipher, session_key, key_length, NULL);
        munit_assert_not_null(fixture.session->emulator->secure_messaging);
        fixture.session->emulator->auth_cipher = cipher;
        fixture.session->emulator->auth_key_no = 0;
        munit_assert_true(dfc_emulator_native_authentication_active(fixture.session->emulator));

        uint8_t amount[4] = {
            (uint8_t)amounts[index],
            (uint8_t)(amounts[index] >> 8),
            (uint8_t)(amounts[index] >> 16),
            (uint8_t)(amounts[index] >> 24),
        };
        uint8_t command[2 + DFC_SM_MAX_CIPHER_BLOCK_SIZE] = {commands[index], 4};
        size_t command_length = oracle_full_value_command(
            cipher, session_key, key_length, commands[index], amount, command);
        DfcByteBuf* response = dfc_bytebuf_alloc(8);
        munit_assert_not_null(response);
        dfc_emulator_command_value_delta(
            fixture.session->emulator,
            command,
            command_length,
            response,
            commands[index],
            commands[index] == DFC_CMD_DEBIT,
            commands[index] == DFC_CMD_LIMITED_CREDIT);
        munit_assert_size(dfc_bytebuf_get_size_bytes(response), ==, 1);
        munit_assert_uint8(dfc_bytebuf_get_data(response)[0], ==, DFC_STATUS_OK);
        dfc_bytebuf_free(response);

        uint8_t expected_tmi[DFC_AES_KEY_LENGTH] = {commands[index], 4};
        memcpy(expected_tmi + 2, amount, sizeof(amount));
        munit_assert_true(fixture.session->emulator->transaction_mac.has_pending);
        DfcByteBuf* receipt = dfc_bytebuf_alloc(16);
        munit_assert_not_null(receipt);
        dfc_emulator_command_commit_transaction(fixture.session->emulator, true, receipt);
        uint8_t expected_receipt[1 + DFC_UINT32_BYTE_COUNT + DFC_WIRE_MAC_LENGTH] = {
            DFC_STATUS_OK, 1, 0, 0, 0};
        memcpy(expected_receipt + 5, expected_tmvs[index], DFC_WIRE_MAC_LENGTH);
        munit_assert_size(dfc_bytebuf_get_size_bytes(receipt), ==, sizeof(expected_receipt));
        munit_assert_memory_equal(
            sizeof(expected_receipt), dfc_bytebuf_get_data(receipt), expected_receipt);
        dfc_bytebuf_free(receipt);
        fixture_close(&fixture);
    }
}

static MunitResult test_full_value_transaction_oracles(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    assert_full_value_transaction_oracle(DFC_CMD_AUTHENTICATE_LEGACY, TestDesKeyLength);
    assert_full_value_transaction_oracle(DFC_CMD_AUTHENTICATE_AES, DFC_AES_KEY_LENGTH);
    return MUNIT_OK;
}

static MunitResult test_lifecycle_retires_family(const MunitParameter params[], void* data) {
    (void)data;
    const char* lifecycle = munit_parameters_get(params, "lifecycle");
    const char* family = munit_parameters_get(params, "family");
    bool deleting = strcmp(lifecycle, "delete") == 0;
    LifecycleFixture fixture;
    fixture_open(&fixture, deleting);
    open_pending(&fixture, family);
    if(deleting) {
        const uint8_t command[] = {0x90, DFC_CMD_DELETE_FILE, 0, 0, 1, 5, 0};
        exchange_status(fixture.session, command, sizeof(command), DFC_STATUS_OK);
        munit_assert_null(dfc_credential_find_file_in_app(&fixture.credential, 0, 5));
    } else {
        create_transaction_mac(&fixture);
        munit_assert_not_null(dfc_credential_find_file_in_app(&fixture.credential, 0, 5));
    }
    assert_transaction_retired(&fixture, true);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_retry_is_single_execution(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    LifecycleFixture fixture;
    fixture_open(&fixture, true);
    open_pending(&fixture, "mixed");
    const uint8_t command[] = {0x90, DFC_CMD_DELETE_FILE, 0, 0, 1, 5, 0};
    uint8_t response[2];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, command, sizeof(command), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_null(dfc_credential_find_file_in_app(&fixture.credential, 0, 5));
    assert_transaction_retired(&fixture, false);
    /* Re-open pending input: replay must return the cached response without executing again. */
    memset(
        &fixture.session->emulator->transaction_mac,
        0x6C,
        sizeof(fixture.session->emulator->transaction_mac));
    fixture.session->emulator->transaction_mac.initialized = true;
    fixture.session->emulator->transaction_mac.has_pending = true;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, command, sizeof(command), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));
    munit_assert_true(fixture.session->emulator->transaction_mac.has_pending);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_retry_rejects_different_command(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    LifecycleFixture fixture;
    fixture_open(&fixture, true);
    open_pending(&fixture, "backup");
    const uint8_t command[] = {0x90, DFC_CMD_DELETE_FILE, 0, 0, 1, 5, 0};
    uint8_t response[2];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, command, sizeof(command), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    const uint8_t different[] = {0x90, DFC_CMD_ABORT_TRANSACTION, 0, 0, 0};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session,
            different,
            sizeof(different),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_null(dfc_credential_find_file_in_app(&fixture.credential, 0, 5));
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_create_retry_is_single_execution(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    LifecycleFixture fixture;
    fixture_open(&fixture, false);
    open_pending(&fixture, "mixed");
    uint8_t command[64];
    size_t command_len = build_create_transaction_mac(5, command);
    uint8_t response[2];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, command, command_len, response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_not_null(dfc_credential_find_file_in_app(&fixture.credential, 0, 5));
    assert_transaction_retired(&fixture, false);
    memset(
        &fixture.session->emulator->transaction_mac,
        0x6C,
        sizeof(fixture.session->emulator->transaction_mac));
    fixture.session->emulator->transaction_mac.initialized = true;
    fixture.session->emulator->transaction_mac.has_pending = true;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));
    munit_assert_size(fixture.credential.num_files, ==, 5);
    munit_assert_true(fixture.session->emulator->transaction_mac.has_pending);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_create_retry_rejects_different_command(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    LifecycleFixture fixture;
    fixture_open(&fixture, false);
    open_pending(&fixture, "mixed");
    uint8_t command[64];
    size_t command_len = build_create_transaction_mac(5, command);
    uint8_t response[2];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, command, command_len, response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    const uint8_t different[] = {0x90, DFC_CMD_ABORT_TRANSACTION, 0, 0, 0};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session,
            different,
            sizeof(different),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_not_null(dfc_credential_find_file_in_app(&fixture.credential, 0, 5));
    munit_assert_size(fixture.credential.num_files, ==, 5);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_create_prevalidation(const MunitParameter params[], void* data) {
    (void)data;
    const char* failure = munit_parameters_get(params, "failure");
    bool existing_transaction_mac = strcmp(failure, "existing-transaction-mac") == 0;
    LifecycleFixture fixture;
    fixture_open(&fixture, existing_transaction_mac);
    open_pending(&fixture, "mixed");
    uint8_t file_number = strcmp(failure, "duplicate-number") == 0 ? 1 : 5;
    if(strcmp(failure, "file-count") == 0) {
        uint8_t next = 6;
        while(fixture.credential.num_files < DFC_MAX_FILES) {
            add_file(&fixture.credential, next++, DFC_FILE_TYPE_STANDARD_DATA, 0, 0);
        }
    }
    if(strcmp(failure, "pool-full") == 0) fixture.credential.file_pool_used = DFC_FILE_POOL_SIZE;
    if(strcmp(failure, "unauthorized") == 0) fixture.credential.apps[0].key_settings_1 = 0x0B;

    size_t files_before = fixture.credential.num_files;
    size_t pool_before = fixture.credential.file_pool_used;
    PendingState pending_before = capture_pending_state(&fixture);
    uint8_t apdu[64];
    size_t apdu_len = build_create_transaction_mac(file_number, apdu);
    if(strcmp(failure, "invalid-number") == 0) apdu[5] = DFC_EV1_MAX_FILE_NUMBER + 1;
    uint8_t expected = DFC_STATUS_PARAMETER_ERROR;
    if(strcmp(failure, "malformed") == 0) {
        // Drop one data byte but keep the trailing Le, which the card requires.
        apdu[4]--;
        apdu[apdu_len - 2] = apdu[apdu_len - 1];
        apdu_len -= 1;
    }
    if(strcmp(failure, "invalid-key-option") == 0) apdu[9] = DFC_KEY_TYPE_AES;
    if(strcmp(failure, "file-count") == 0) expected = DFC_STATUS_COUNT_ERROR;
    if(strcmp(failure, "pool-full") == 0) expected = DFC_STATUS_OUT_OF_EEPROM;
    if(strcmp(failure, "unauthorized") == 0) expected = DFC_STATUS_AUTHENTICATION_ERR;
    exchange_status(fixture.session, apdu, apdu_len, expected);
    munit_assert_size(fixture.credential.num_files, ==, files_before);
    munit_assert_size(fixture.credential.file_pool_used, ==, pool_before);
    DfcFile* transaction_file = dfc_credential_find_file_in_app(&fixture.credential, 0, 5);
    munit_assert_int(
        transaction_file && transaction_file->type == DFC_FILE_TYPE_TRANSACTION_MAC,
        ==,
        existing_transaction_mac);
    assert_mixed_pending_unchanged(&fixture, pending_before);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_delete_prevalidation(const MunitParameter params[], void* data) {
    (void)data;
    const char* failure = munit_parameters_get(params, "failure");
    LifecycleFixture fixture;
    fixture_open(&fixture, true);
    open_pending(&fixture, "mixed");
    uint8_t file_number = 6;
    uint8_t expected = DFC_STATUS_FILE_NOT_FOUND;
    bool preserves_transaction = false;
    if(strcmp(failure, "unauthorized-transaction-mac") == 0) {
        file_number = 5;
        fixture.credential.apps[0].key_settings_1 = 0x0B;
        expected = DFC_STATUS_AUTHENTICATION_ERR;
        preserves_transaction = true;
    } else if(strcmp(failure, "unauthorized-ordinary") == 0) {
        file_number = 1;
        fixture.credential.apps[0].key_settings_1 = 0x0B;
        expected = DFC_STATUS_AUTHENTICATION_ERR;
    }
    size_t files_before = fixture.credential.num_files;
    size_t pool_before = fixture.credential.file_pool_used;
    PendingState pending_before = capture_pending_state(&fixture);
    const uint8_t command[] = {0x90, DFC_CMD_DELETE_FILE, 0, 0, 1, file_number, 0};
    const uint8_t malformed[] = {0x90, DFC_CMD_DELETE_FILE, 0, 0, 0};
    const uint8_t* request = command;
    size_t request_len = sizeof(command);
    if(strcmp(failure, "malformed") == 0) {
        request = malformed;
        request_len = sizeof(malformed);
        expected = DFC_STATUS_LENGTH_ERROR;
    }
    exchange_status(fixture.session, request, request_len, expected);
    munit_assert_size(fixture.credential.num_files, ==, files_before);
    munit_assert_size(fixture.credential.file_pool_used, ==, pool_before);
    munit_assert_not_null(dfc_credential_find_file_in_app(&fixture.credential, 0, 5));
    if(preserves_transaction)
        assert_mixed_pending_unchanged(&fixture, pending_before);
    else
        assert_transaction_retired(&fixture, true);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_transport_reuses_session_buffer(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    LifecycleFixture fixture;
    fixture_open(&fixture, false);
    open_pending(&fixture, "mixed");
    size_t files_before = fixture.credential.num_files;
    size_t pool_before = fixture.credential.file_pool_used;
    uint8_t apdu[64];
    size_t apdu_len = build_create_transaction_mac(5, apdu);
    uint8_t response[2];
    size_t response_len = 0;
    dfc_host_fail_next_allocation(DfcAllocByteBuf);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, apdu, apdu_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));
    munit_assert_size(fixture.credential.num_files, ==, files_before + 1);
    DfcFile* created = dfc_credential_find_file_in_app(&fixture.credential, 0, 5);
    munit_assert_not_null(created);
    munit_assert_size(fixture.credential.file_pool_used, ==, pool_before + created->data_len);
    munit_assert_null(dfc_platform_alloc(1, DfcAllocByteBuf));
    fixture_close(&fixture);
    return MUNIT_OK;
}

static char* lifecycle_values[] = {"create", "delete", NULL};
static char* family_values[] = {"backup", "linear", "cyclic", "value", "input", "mixed", NULL};
static MunitParameterEnum lifecycle_params[] = {
    {"lifecycle", lifecycle_values},
    {"family", family_values},
    {NULL, NULL},
};
static char* create_failure_values[] = {
    "malformed",
    "invalid-key-option",
    "existing-transaction-mac",
    "duplicate-number",
    "invalid-number",
    "file-count",
    "pool-full",
    "unauthorized",
    NULL,
};
static MunitParameterEnum create_failure_params[] = {
    {"failure", create_failure_values},
    {NULL, NULL},
};
static char* delete_failure_values[] = {
    "missing",
    "malformed",
    "unauthorized-ordinary",
    "unauthorized-transaction-mac",
    NULL,
};
static MunitParameterEnum delete_failure_params[] = {
    {"failure", delete_failure_values},
    {NULL, NULL},
};

static MunitTest tests[] = {
    {"/receipt-input-families",
     test_data_value_and_record_receipts_match_structured_inputs,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/reader-id/free-one-shot",
     test_free_reader_id_is_one_shot_and_not_persisted,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/reader-id/access-and-required",
     test_reader_id_access_and_commit_requirement,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/reader-id/c8-data-block",
     test_data_block_starting_with_reader_id_command_is_not_reader_state,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/capacity/write-preparation-atomic",
     test_write_data_preparation_failures_preserve_transcript,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/synthetic-oracle/full-value-modes",
     test_full_value_transaction_oracles,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/synthetic-oracle/commit-reader-id-secure-modes",
     test_commit_reader_id_secure_mode_oracles,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    {"/synthetic-oracle/commit-reader-id-ev2-mac-only",
     test_commit_reader_id_ev2_mac_only_oracle,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
    {"/families",
     test_lifecycle_retires_family,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     lifecycle_params},
    {"/retry-once", test_retry_is_single_execution, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/retry-different",
     test_retry_rejects_different_command,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/create-retry-once",
     test_create_retry_is_single_execution,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/create-retry-different",
     test_create_retry_rejects_different_command,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/create-prevalidation",
     test_create_prevalidation,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     create_failure_params},
    {"/delete-prevalidation",
     test_delete_prevalidation,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     delete_failure_params},
    {"/transport-reuses-session-buffer",
     test_transport_reuses_session_buffer,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

#else

static MunitResult test_disabled_profile(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/disabled-profile", test_disabled_profile, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

#endif

static const MunitSuite suite =
    {"/dfc_transaction_mac_lifecycle", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
