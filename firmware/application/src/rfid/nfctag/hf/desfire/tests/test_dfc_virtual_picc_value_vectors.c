#include "dfc_virtual_picc_test_helpers.h"

static void init_value_credential(DfcCredential* credential) {
    dfc_credential_clear(credential);
    credential->uid_len = DFC_DESFIRE_UID_LEN;
    memcpy(
        credential->uid,
        ((uint8_t[]){0x04, 0x76, 0x61, 0x6C, 0x75, 0x65, 0x31}),
        DFC_DESFIRE_UID_LEN);
}

static void put_i32_le(uint8_t* out, int32_t value) {
    uint32_t raw = (uint32_t)value;
    out[0] = (uint8_t)(raw & 0xFF);
    out[1] = (uint8_t)((raw >> 8) & 0xFF);
    out[2] = (uint8_t)((raw >> 16) & 0xFF);
    out[3] = (uint8_t)((raw >> 24) & 0xFF);
}

static size_t wrap(uint8_t ins, const uint8_t* data, size_t data_len, uint8_t* out) {
    out[0] = 0x90;
    out[1] = ins;
    out[2] = 0x00;
    out[3] = 0x00;
    out[4] = (uint8_t)data_len;
    if(data_len > 0) {
        memcpy(out + 5, data, data_len);
        out[5 + data_len] = 0x00;
        return data_len + 6;
    }
    return 5;
}

static size_t build_value_payload(
    uint8_t file_no,
    uint8_t comm_settings,
    uint16_t access_rights,
    int32_t lower_limit,
    int32_t upper_limit,
    int32_t value,
    uint8_t limited_credit,
    uint8_t* out) {
    out[0] = file_no;
    out[1] = comm_settings;
    // `access_rights` is logical; the wire takes it least-significant octet first.
    out[2] = (uint8_t)(access_rights & 0xFF);
    out[3] = (uint8_t)(access_rights >> 8);
    put_i32_le(out + 4, lower_limit);
    put_i32_le(out + 8, upper_limit);
    put_i32_le(out + 12, value);
    out[16] = limited_credit;
    return 17;
}

static size_t build_value_command(uint8_t ins, uint8_t file_no, int32_t amount, uint8_t* out) {
    uint8_t data[5];
    data[0] = file_no;
    put_i32_le(data + 1, amount);
    return wrap(ins, data, sizeof(data), out);
}

static void exchange(
    DfcVirtualPiccSession* session,
    const uint8_t* command,
    size_t command_len,
    uint8_t* response,
    size_t* response_len) {
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, command_len, response, 128, response_len),
        ==,
        DfcVirtualPiccStatusOk);
}

static void assert_response(
    DfcVirtualPiccSession* session,
    const uint8_t* command,
    size_t command_len,
    const uint8_t* expected,
    size_t expected_len) {
    uint8_t response[128];
    size_t response_len = 0;
    exchange(session, command, command_len, response, &response_len);
    munit_assert_size(response_len, ==, expected_len);
    munit_assert_memory_equal(expected_len, response, expected);
}

static void assert_status(
    DfcVirtualPiccSession* session,
    const uint8_t* command,
    size_t command_len,
    uint8_t status) {
    assert_response(session, command, command_len, ((uint8_t[]){0x91, status}), 2);
}

static void assert_get_value(DfcVirtualPiccSession* session, uint8_t file_no, int32_t value) {
    uint8_t data[] = {file_no};
    uint8_t command[8];
    size_t command_len = wrap(DFC_CMD_GET_VALUE, data, sizeof(data), command);
    uint8_t expected[6];
    put_i32_le(expected, value);
    expected[4] = 0x91;
    expected[5] = DFC_STATUS_OK;
    assert_response(session, command, command_len, expected, sizeof(expected));
}

static void assert_value_file_settings(
    DfcVirtualPiccSession* session,
    uint8_t file_no,
    uint8_t comm_settings,
    uint16_t access_rights,
    int32_t lower_limit,
    int32_t upper_limit,
    int32_t limited_credit_value,
    uint8_t limited_credit_option) {
    uint8_t command[] = {0x90, DFC_CMD_GET_FILE_SETTINGS, 0x00, 0x00, 0x01, file_no, 0x00};
    uint8_t expected[19] = {
        DFC_FILE_TYPE_VALUE,
        comm_settings,
        (uint8_t)(access_rights & 0xFF),
        (uint8_t)(access_rights >> 8),
    };
    put_i32_le(expected + 4, lower_limit);
    put_i32_le(expected + 8, upper_limit);
    put_i32_le(expected + 12, limited_credit_value);
    expected[16] = limited_credit_option;
    expected[17] = 0x91;
    expected[18] = DFC_STATUS_OK;
    assert_response(session, command, sizeof(command), expected, sizeof(expected));
}

static void assert_value_status(
    DfcVirtualPiccSession* session,
    uint8_t ins,
    uint8_t file_no,
    int32_t amount,
    uint8_t status) {
    uint8_t command[16];
    size_t command_len = build_value_command(ins, file_no, amount, command);
    assert_status(session, command, command_len, status);
}

static void create_value_file(
    DfcVirtualPiccSession* session,
    uint8_t file_no,
    uint8_t comm_settings,
    uint16_t access_rights,
    int32_t lower_limit,
    int32_t upper_limit,
    int32_t value,
    uint8_t limited_credit,
    uint8_t expected_status) {
    uint8_t data[17];
    uint8_t command[24];
    size_t data_len = build_value_payload(
        file_no,
        comm_settings,
        access_rights,
        lower_limit,
        upper_limit,
        value,
        limited_credit,
        data);
    size_t command_len = wrap(DFC_CMD_CREATE_VALUE_FILE, data, data_len, command);
    assert_status(session, command, command_len, expected_status);
}

static void setup_app(DfcCredential* credential, DfcVirtualPiccSession** session) {
    init_value_credential(credential);
    *session = dfc_virtual_picc_session_alloc(credential);

    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(*session, &activation), ==, DfcVirtualPiccStatusOk);

    const uint8_t create_app[] = {
        0x90, DFC_CMD_CREATE_APPLICATION, 0x00, 0x00, 0x05, 0xA1, 0xB2, 0xC3, 0x0F, 0x01, 0x00};
    assert_status(*session, create_app, sizeof(create_app), DFC_STATUS_OK);

    const uint8_t select_app[] = {
        0x90, DFC_CMD_SELECT_APPLICATION, 0x00, 0x00, 0x03, 0xA1, 0xB2, 0xC3, 0x00};
    assert_status(*session, select_app, sizeof(select_app), DFC_STATUS_OK);
}

static void select_picc(DfcVirtualPiccSession* session) {
    const uint8_t select_picc_command[] = {
        0x90, DFC_CMD_SELECT_APPLICATION, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00};
    assert_status(session, select_picc_command, sizeof(select_picc_command), DFC_STATUS_OK);
}

static void select_app(DfcVirtualPiccSession* session) {
    const uint8_t select_app_command[] = {
        0x90, DFC_CMD_SELECT_APPLICATION, 0x00, 0x00, 0x03, 0xA1, 0xB2, 0xC3, 0x00};
    assert_status(session, select_app_command, sizeof(select_app_command), DFC_STATUS_OK);
}

static void commit(DfcVirtualPiccSession* session, uint8_t expected_status) {
    const uint8_t command[] = {0x90, DFC_CMD_COMMIT_TRANSACTION, 0x00, 0x00, 0x00};
    assert_status(session, command, sizeof(command), expected_status);
}

static void abort_transaction(DfcVirtualPiccSession* session, uint8_t expected_status) {
    const uint8_t command[] = {0x90, DFC_CMD_ABORT_TRANSACTION, 0x00, 0x00, 0x00};
    assert_status(session, command, sizeof(command), expected_status);
}

static MunitResult
    test_value_create_status_vectors(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = NULL;
    setup_app(&credential, &session);

    create_value_file(session, 0x05, DFC_COMM_PLAIN, 0xEEEE, 0, 1000, 10, 1, DFC_STATUS_OK);
    create_value_file(
        session, 0x05, DFC_COMM_PLAIN, 0xEEEE, 0, 1000, 10, 1, DFC_STATUS_DUPLICATE_ERROR);
    create_value_file(
        session, 0x06, DFC_COMM_PLAIN, 0xEEEE, 100, 0, 10, 1, DFC_STATUS_PARAMETER_ERROR);
    create_value_file(
        session, 0x07, DFC_COMM_PLAIN, 0xEEEE, 0, 100, -1, 1, DFC_STATUS_PARAMETER_ERROR);
    create_value_file(
        session, 0x08, DFC_COMM_PLAIN, 0xEEEE, 0, 100, 101, 1, DFC_STATUS_PARAMETER_ERROR);
    create_value_file(session, 0x09, DFC_COMM_PLAIN, 0xEEEE, -100, 100, -5, 1, DFC_STATUS_OK);
    assert_get_value(session, 0x09, -5);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_value_transaction_vectors_from_card(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = NULL;
    setup_app(&credential, &session);
    create_value_file(session, 0x01, DFC_COMM_PLAIN, 0xEEEE, 0, 20, 10, 1, DFC_STATUS_OK);

    assert_value_status(session, DFC_CMD_DEBIT, 0x01, 11, DFC_STATUS_BOUNDARY_ERROR);
    assert_value_status(session, DFC_CMD_CREDIT, 0x01, 10, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x01, 20);
    assert_value_status(session, DFC_CMD_DEBIT, 0x01, 20, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x01, 0);

    assert_value_status(session, DFC_CMD_CREDIT, 0x01, 7, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_DEBIT, 0x01, 2, DFC_STATUS_OK);
    assert_get_value(session, 0x01, 0);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x01, 5);

    assert_value_status(session, DFC_CMD_CREDIT, 0x01, 5, DFC_STATUS_OK);
    abort_transaction(session, DFC_STATUS_OK);
    assert_get_value(session, 0x01, 5);
    abort_transaction(session, DFC_STATUS_NO_CHANGES);
    commit(session, DFC_STATUS_NO_CHANGES);

    assert_value_status(session, DFC_CMD_CREDIT, 0x01, 5, DFC_STATUS_OK);
    select_picc(session);
    select_app(session);
    commit(session, DFC_STATUS_NO_CHANGES);
    assert_get_value(session, 0x01, 5);

    assert_value_status(session, DFC_CMD_CREDIT, 0x01, 5, DFC_STATUS_OK);
    munit_assert_int(dfc_virtual_picc_field_off(session), ==, DfcVirtualPiccStatusOk);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    select_app(session);
    commit(session, DFC_STATUS_NO_CHANGES);
    assert_get_value(session, 0x01, 5);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_value_file_access_vectors(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = NULL;
    setup_app(&credential, &session);

    uint8_t get_missing[] = {0x90, DFC_CMD_GET_VALUE, 0x00, 0x00, 0x01, 0x1E, 0x00};
    assert_status(session, get_missing, sizeof(get_missing), DFC_STATUS_FILE_NOT_FOUND);
    assert_value_status(session, DFC_CMD_CREDIT, 0x1E, 1, DFC_STATUS_FILE_NOT_FOUND);
    assert_value_status(session, DFC_CMD_DEBIT, 0x1E, 1, DFC_STATUS_FILE_NOT_FOUND);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x1E, 1, DFC_STATUS_FILE_NOT_FOUND);

    const uint8_t create_std[] = {
        0x90,
        DFC_CMD_CREATE_STD_DATA_FILE,
        0x00,
        0x00,
        0x07,
        0x0A,
        0x00,
        0xEE,
        0xEE,
        0x04,
        0x00,
        0x00,
        0x00};
    assert_status(session, create_std, sizeof(create_std), DFC_STATUS_OK);
    // File 0x0A is a standard data file, so value commands do not apply to it at
    // all. That is not an access-rights refusal and stays 0x9D; measured on a
    // genuine EV1 4K, GetValue on a standard data file answers 0x9D.
    uint8_t get_std[] = {0x90, DFC_CMD_GET_VALUE, 0x00, 0x00, 0x01, 0x0A, 0x00};
    assert_status(session, get_std, sizeof(get_std), DFC_STATUS_PERMISSION_DENIED);
    assert_value_status(session, DFC_CMD_CREDIT, 0x0A, 1, DFC_STATUS_PERMISSION_DENIED);
    assert_value_status(session, DFC_CMD_DEBIT, 0x0A, 1, DFC_STATUS_PERMISSION_DENIED);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x0A, 1, DFC_STATUS_PERMISSION_DENIED);

    create_value_file(session, 0x0B, DFC_COMM_PLAIN, 0x0000, 0, 100, 10, 1, DFC_STATUS_OK);
    uint8_t get_protected[] = {0x90, DFC_CMD_GET_VALUE, 0x00, 0x00, 0x01, 0x0B, 0x00};
    // Access rights 0x0000: every nibble names key 0, so the refusal is a
    // missing authentication rather than a denial, and the card answers 0xAE.
    assert_status(session, get_protected, sizeof(get_protected), DFC_STATUS_AUTHENTICATION_ERR);
    assert_value_status(session, DFC_CMD_CREDIT, 0x0B, 1, DFC_STATUS_AUTHENTICATION_ERR);

    uint8_t response[128];
    size_t response_len = 0;
    uint8_t session_key[DFC_MAX_KEY_LEN];
    size_t session_key_len = 0;
    uint8_t zero_key[8] = {0};
    authenticate_legacy_key0(
        session,
        zero_key,
        sizeof(zero_key),
        response,
        sizeof(response),
        &response_len,
        session_key,
        &session_key_len,
        DFC_STATUS_OK);
    assert_get_value(session, 0x0B, 10);
    assert_value_status(session, DFC_CMD_CREDIT, 0x0B, 1, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x0B, 11);

    // With the PICC level selected there is no application to address, so these
    // never reach the access-rights check; the refusal stays 0x9D.
    select_picc(session);
    assert_status(session, get_protected, sizeof(get_protected), DFC_STATUS_PERMISSION_DENIED);
    assert_value_status(session, DFC_CMD_CREDIT, 0x0B, 1, DFC_STATUS_PERMISSION_DENIED);
    commit(session, DFC_STATUS_PERMISSION_DENIED);
    abort_transaction(session, DFC_STATUS_PERMISSION_DENIED);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_value_comm_limited_and_option_vectors(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = NULL;
    setup_app(&credential, &session);

    create_value_file(session, 0x0C, DFC_COMM_MAC, 0xEEEE, 0, 100, 10, 1, DFC_STATUS_OK);
    assert_get_value(session, 0x0C, 10);
    assert_value_status(session, DFC_CMD_CREDIT, 0x0C, 1, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x0C, 11);

    create_value_file(session, 0x0D, DFC_COMM_ENCIPHERED, 0xEEEE, 0, 100, 10, 1, DFC_STATUS_OK);
    assert_get_value(session, 0x0D, 10);
    assert_value_status(session, DFC_CMD_CREDIT, 0x0D, 1, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x0D, 11);

    // Access rights 0xEEEE are free, so nothing is refused on access grounds.
    // LimitedCredit is refused because the file was created without the
    // limited-credit flag, which is a wrong-operation refusal and stays 0x9D.
    create_value_file(session, 0x0E, DFC_COMM_PLAIN, 0xEEEE, 0, 100, 10, 0, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x0E, 1, DFC_STATUS_PERMISSION_DENIED);
    create_value_file(session, 0x0F, DFC_COMM_PLAIN, 0xEEEE, 0, 100, 10, 1, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x0F, 1, DFC_STATUS_BOUNDARY_ERROR);
    create_value_file(session, 0x10, DFC_COMM_PLAIN, 0xEEEE, 0, 100, 10, 3, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x10, 1, DFC_STATUS_BOUNDARY_ERROR);

    assert_value_status(session, DFC_CMD_CREDIT, 0x0F, 1, DFC_STATUS_OK);
    const uint8_t commit_with_option[] = {
        0x90, DFC_CMD_COMMIT_TRANSACTION, 0x00, 0x00, 0x01, 0x00, 0x00};
    assert_status(
        session, commit_with_option, sizeof(commit_with_option), DFC_STATUS_LENGTH_ERROR);
    assert_get_value(session, 0x0F, 10);
    commit(session, DFC_STATUS_NO_CHANGES);

    assert_value_status(session, DFC_CMD_CREDIT, 0x0F, 1, DFC_STATUS_OK);
    const uint8_t abort_with_option[] = {
        0x90, DFC_CMD_ABORT_TRANSACTION, 0x00, 0x00, 0x01, 0x00, 0x00};
    assert_status(session, abort_with_option, sizeof(abort_with_option), DFC_STATUS_LENGTH_ERROR);
    assert_get_value(session, 0x0F, 10);
    commit(session, DFC_STATUS_NO_CHANGES);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_value_multi_file_delete_vectors(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = NULL;
    setup_app(&credential, &session);

    create_value_file(session, 0x02, DFC_COMM_PLAIN, 0xEEEE, 0, 100, 10, 1, DFC_STATUS_OK);
    create_value_file(session, 0x03, DFC_COMM_PLAIN, 0xEEEE, 0, 100, 20, 1, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_CREDIT, 0x02, 5, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_DEBIT, 0x03, 6, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x02, 15);
    assert_get_value(session, 0x03, 14);

    assert_value_status(session, DFC_CMD_CREDIT, 0x02, 5, DFC_STATUS_OK);
    const uint8_t delete_file[] = {0x90, DFC_CMD_DELETE_FILE, 0x00, 0x00, 0x01, 0x02, 0x00};
    assert_status(session, delete_file, sizeof(delete_file), DFC_STATUS_OK);
    uint8_t get_deleted[] = {0x90, DFC_CMD_GET_VALUE, 0x00, 0x00, 0x01, 0x02, 0x00};
    assert_status(session, get_deleted, sizeof(get_deleted), DFC_STATUS_FILE_NOT_FOUND);
    commit(session, DFC_STATUS_NO_CHANGES);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_limited_credit_transaction_state(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = NULL;
    setup_app(&credential, &session);
    create_value_file(session, 0x04, DFC_COMM_PLAIN, 0xEEEE, 0, 100, 50, 1, DFC_STATUS_OK);

    // Zero is the explicit reset operation, even when no credit is available.
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x04, 0, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x04, 50);

    // Zero also consumes an established limit without changing the value.
    create_value_file(session, 0x08, DFC_COMM_PLAIN, 0xEEEE, 0, 100, 50, 1, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_DEBIT, 0x08, 9, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x08, 0, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x08, 41);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x08, 1, DFC_STATUS_BOUNDARY_ERROR);

    // A debit makes its amount available immediately in the same transaction.
    assert_value_status(session, DFC_CMD_DEBIT, 0x04, 6, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x04, 6, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x04, 50);

    // A committed debit establishes a one-use limit. The exact amount succeeds,
    // and a later use is refused without changing the committed value.
    assert_value_status(session, DFC_CMD_DEBIT, 0x04, 10, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x04, 40);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x04, 10, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x04, 50);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x04, 1, DFC_STATUS_BOUNDARY_ERROR);
    assert_get_value(session, 0x04, 50);

    // A rejected amount does not consume the limit. Aborting either a newer
    // debit or a successful use restores both the value and the previous limit.
    assert_value_status(session, DFC_CMD_DEBIT, 0x04, 7, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_DEBIT, 0x04, 3, DFC_STATUS_OK);
    abort_transaction(session, DFC_STATUS_OK);
    assert_get_value(session, 0x04, 43);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x04, 8, DFC_STATUS_BOUNDARY_ERROR);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x04, 5, DFC_STATUS_OK);
    abort_transaction(session, DFC_STATUS_OK);
    assert_get_value(session, 0x04, 43);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x04, 7, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x04, 50);

    // Credit-only transactions leave the latest debit limit untouched. A newer
    // debit transaction replaces, rather than accumulates with, the old limit.
    assert_value_status(session, DFC_CMD_DEBIT, 0x04, 4, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_CREDIT, 0x04, 1, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x04, 4, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x04, 51);
    assert_value_status(session, DFC_CMD_DEBIT, 0x04, 3, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_DEBIT, 0x04, 2, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x04, 3, DFC_STATUS_BOUNDARY_ERROR);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x04, 2, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x04, 48);

    // Selection and field reset abort an in-flight debit and preserve the last
    // committed limit. The later debit establishes a fresh limit normally.
    assert_value_status(session, DFC_CMD_DEBIT, 0x04, 6, DFC_STATUS_OK);
    select_picc(session);
    select_app(session);
    commit(session, DFC_STATUS_NO_CHANGES);
    assert_get_value(session, 0x04, 48);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x04, 1, DFC_STATUS_BOUNDARY_ERROR);
    assert_value_status(session, DFC_CMD_DEBIT, 0x04, 5, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    munit_assert_int(dfc_virtual_picc_field_off(session), ==, DfcVirtualPiccStatusOk);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    select_app(session);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x04, 5, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x04, 48);

    create_value_file(session, 0x05, DFC_COMM_PLAIN, 0xEEEE, 0, 100, 50, 0, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x05, 0, DFC_STATUS_PERMISSION_DENIED);

    // LimitedCredit still obeys the common value-command gates. A disabled
    // write path and a non-value file must not create transaction state.
    create_value_file(session, 0x07, DFC_COMM_PLAIN, 0xFFFF, 0, 100, 50, 1, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x07, 0, DFC_STATUS_PERMISSION_DENIED);
    DfcFile* wrong_type =
        dfc_credential_find_file_in_app(&credential, session->emulator->selected_app_index, 0x07);
    munit_assert_not_null(wrong_type);
    wrong_type->type = DFC_FILE_TYPE_STANDARD_DATA;
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x07, 0, DFC_STATUS_PERMISSION_DENIED);
    commit(session, DFC_STATUS_NO_CHANGES);

    // Debit accumulation saturates only the reusable limit, while the pending
    // value keeps enough width to span the complete signed value range.
    create_value_file(
        session, 0x06, DFC_COMM_PLAIN, 0xEEEE, INT32_MIN, INT32_MAX, INT32_MAX, 1, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_DEBIT, 0x06, INT32_MAX, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_DEBIT, 0x06, 1, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x06, -1);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x06, INT32_MAX, DFC_STATUS_OK);
    commit(session, DFC_STATUS_OK);
    assert_get_value(session, 0x06, INT32_MAX - 1);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_get_file_settings_reports_committed_limit(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = NULL;
    setup_app(&credential, &session);
    create_value_file(session, 0x01, DFC_COMM_PLAIN, 0xEEEE, -100, 100, 37, 1, DFC_STATUS_OK);

    assert_value_file_settings(session, 0x01, DFC_COMM_PLAIN, 0xEEEE, -100, 100, 0, 1);
    assert_value_status(session, DFC_CMD_DEBIT, 0x01, 11, DFC_STATUS_OK);
    assert_value_file_settings(session, 0x01, DFC_COMM_PLAIN, 0xEEEE, -100, 100, 0, 1);
    commit(session, DFC_STATUS_OK);
    assert_value_file_settings(session, 0x01, DFC_COMM_PLAIN, 0xEEEE, -100, 100, 11, 1);

    assert_value_status(session, DFC_CMD_DEBIT, 0x01, 7, DFC_STATUS_OK);
    assert_value_file_settings(session, 0x01, DFC_COMM_PLAIN, 0xEEEE, -100, 100, 11, 1);
    abort_transaction(session, DFC_STATUS_OK);
    assert_value_file_settings(session, 0x01, DFC_COMM_PLAIN, 0xEEEE, -100, 100, 11, 1);

    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x01, 11, DFC_STATUS_OK);
    assert_value_file_settings(session, 0x01, DFC_COMM_PLAIN, 0xEEEE, -100, 100, 11, 1);
    commit(session, DFC_STATUS_OK);
    assert_value_file_settings(session, 0x01, DFC_COMM_PLAIN, 0xEEEE, -100, 100, 0, 1);

    DfcApplication* app = dfc_credential_get_primary_application(&credential);
    munit_assert_not_null(app);
    app->key_settings_2 = DFC_KEY_TYPE_DES_2K3DES | 2;
    munit_assert_true(dfc_credential_keys_resize(&credential, app, 2, 8));
    uint8_t* non_master_key = dfc_credential_key(&credential, app, 1);
    munit_assert_not_null(non_master_key);
    memset(non_master_key, 0x11, 8);
    app->key_settings_1 &= (uint8_t)~DFC_KS1_FREE_DIRECTORY_ACCESS;
    uint8_t get_settings[] = {0x90, DFC_CMD_GET_FILE_SETTINGS, 0x00, 0x00, 0x01, 0x01, 0x00};
    assert_status(session, get_settings, sizeof(get_settings), DFC_STATUS_AUTHENTICATION_ERR);

    uint8_t response[128];
    size_t response_len = 0;
    uint8_t session_key[DFC_MAX_KEY_LEN];
    size_t session_key_len = 0;
    uint8_t zero_key[8] = {0};
    authenticate_legacy_key(
        session,
        1,
        non_master_key,
        8,
        response,
        sizeof(response),
        &response_len,
        session_key,
        &session_key_len,
        DFC_STATUS_OK);
    assert_status(session, get_settings, sizeof(get_settings), DFC_STATUS_AUTHENTICATION_ERR);
    munit_assert_not_null(session->emulator->secure_messaging);
    munit_assert_uint8(session->emulator->secure_messaging->cipher, !=, 0);
    munit_assert_uint8(session->emulator->auth_key_no, ==, 1);

    authenticate_legacy_key0(
        session,
        zero_key,
        sizeof(zero_key),
        response,
        sizeof(response),
        &response_len,
        session_key,
        &session_key_len,
        DFC_STATUS_OK);
    assert_value_file_settings(session, 0x01, DFC_COMM_PLAIN, 0xEEEE, -100, 100, 0, 1);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_value_malformed_vectors(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = NULL;
    setup_app(&credential, &session);

    const uint8_t create_short[] = {
        0x90, DFC_CMD_CREATE_VALUE_FILE, 0x00, 0x00, 0x04, 0x01, 0x00, 0xEE, 0xEE, 0x00};
    assert_status(session, create_short, sizeof(create_short), DFC_STATUS_LENGTH_ERROR);
    const uint8_t get_no_file_no[] = {0x90, DFC_CMD_GET_VALUE, 0x00, 0x00, 0x00};
    assert_status(session, get_no_file_no, sizeof(get_no_file_no), DFC_STATUS_LENGTH_ERROR);
    const uint8_t credit_short[] = {
        0x90, DFC_CMD_CREDIT, 0x00, 0x00, 0x04, 0x01, 0x01, 0x00, 0x00, 0x00};
    assert_status(session, credit_short, sizeof(credit_short), DFC_STATUS_LENGTH_ERROR);

    create_value_file(session, 0x01, DFC_COMM_PLAIN, 0xEEEE, 0, 100, 10, 1, DFC_STATUS_OK);
    assert_value_status(session, DFC_CMD_DEBIT, 0x01, -1, DFC_STATUS_PARAMETER_ERROR);
    assert_value_status(session, DFC_CMD_CREDIT, 0x01, -1, DFC_STATUS_PARAMETER_ERROR);
    assert_value_status(session, DFC_CMD_LIMITED_CREDIT, 0x01, -1, DFC_STATUS_PARAMETER_ERROR);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/create-status-vectors",
     test_value_create_status_vectors,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/transactions",
     test_value_transaction_vectors_from_card,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/access", test_value_file_access_vectors, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/comm-limited-options",
     test_value_comm_limited_and_option_vectors,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/multi-file-delete",
     test_value_multi_file_delete_vectors,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/limited-credit-transaction-state",
     test_limited_credit_transaction_state,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/get-file-settings-reports-committed-limit",
     test_get_file_settings_reports_committed_limit,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/malformed", test_value_malformed_vectors, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite =
    {"/dfc_virtual_picc_value_vectors", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
