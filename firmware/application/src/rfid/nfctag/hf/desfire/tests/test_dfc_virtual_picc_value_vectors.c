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

static MunitResult test_get_file_settings_refuses_non_master_session(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = NULL;
    setup_app(&credential, &session);
    create_value_file(session, 0x01, DFC_COMM_PLAIN, 0xEEEE, -100, 100, 37, 1, DFC_STATUS_OK);

    // The committed-limit reporting that used to be asserted here is
    // get-file-settings-limited-credit-limit.vec. What stays is the session
    // state the vector format cannot assert: which key a refused GetFileSettings
    // leaves the session authenticated with.
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

static MunitTest tests[] = {
    {"/get-file-settings-refuses-non-master-session",
     test_get_file_settings_refuses_non_master_session,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite =
    {"/dfc_virtual_picc_value_vectors", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
