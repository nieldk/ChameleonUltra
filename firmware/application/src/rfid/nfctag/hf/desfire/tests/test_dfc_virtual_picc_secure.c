#include "dfc_virtual_picc_test_helpers.h"
#include "dfc_emulator_i.h"

static void install_test_authentication(
    DfcEmulator* emulator,
    uint8_t cipher,
    const uint8_t* key,
    size_t key_len,
    uint8_t key_no) {
    emulator->secure_messaging = dfc_secure_messaging_alloc(cipher, key, key_len, NULL);
    munit_assert_not_null(emulator->secure_messaging);
    emulator->auth_cipher = cipher;
    emulator->auth_key_no = key_no;
    munit_assert_true(dfc_emulator_native_authentication_active(emulator));
}

static MunitResult test_iso_authentication_resets_ev1_secure_messaging_iv(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    load_standard_credential(&credential);
    DfcApplication* app = dfc_credential_get_primary_application(&credential);
    munit_assert_not_null(app);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);

    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    uint8_t response[128];
    size_t response_len = 0;
    const uint8_t select_app[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x4F, 0x49, 0xD3, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);

    const uint8_t authenticate[] = {0x90, 0x1A, 0x00, 0x00, 0x01, 0x01, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, authenticate, sizeof(authenticate), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 10);
    munit_assert_uint8(response[8], ==, 0x91);
    munit_assert_uint8(response[9], ==, 0xAF);

    const uint8_t* key = dfc_credential_key_const(&credential, app, 1);
    uint8_t iv[16] = {0};
    uint8_t rnd_b[16];
    dfc_worker_des_cbc_decrypt(key, app->key_len, iv, 8, response, rnd_b);

    uint8_t rnd_b_rot[16];
    memcpy(rnd_b_rot, rnd_b, 8);
    dfc_rotate_left(rnd_b_rot, 8);

    uint8_t rnd_a[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    uint8_t challenge[16];
    memcpy(challenge, rnd_a, 8);
    memcpy(challenge + 8, rnd_b_rot, 8);

    memcpy(iv, response, 8);
    uint8_t encrypted_challenge[16];
    dfc_worker_des_cbc_encrypt(
        key, app->key_len, iv, sizeof(challenge), challenge, encrypted_challenge);

    uint8_t additional_frame[22] = {0x90, 0xAF, 0x00, 0x00, 0x10};
    memcpy(additional_frame + 5, encrypted_challenge, sizeof(encrypted_challenge));
    additional_frame[21] = 0x00;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            additional_frame,
            sizeof(additional_frame),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 10);
    munit_assert_uint8(response[8], ==, 0x91);
    munit_assert_uint8(response[9], ==, 0x00);

    uint8_t session_key[DFC_MAX_KEY_LEN];
    size_t session_key_len = 0;
    dfc_derive_session_key(
        DFC_CMD_AUTHENTICATE_ISO, key, app->key_len, rnd_a, rnd_b, session_key, &session_key_len);
    DfcSecureMessaging* expected_sm =
        dfc_secure_messaging_alloc(DFC_CMD_AUTHENTICATE_ISO, session_key, session_key_len, NULL);

    const uint8_t get_file_settings[] = {0x90, 0xF5, 0x00, 0x00, 0x01, 0x0F, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            get_file_settings,
            sizeof(get_file_settings),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 17);
    munit_assert_uint8(response[15], ==, 0x91);
    munit_assert_uint8(response[16], ==, 0x00);

    uint8_t file_no[] = {0x0F};
    dfc_secure_messaging_update_ev1_command(
        expected_sm, DFC_CMD_GET_FILE_SETTINGS, file_no, sizeof(file_no));

    uint8_t recovered[DFC_SM_MAX_SIZE];
    size_t recovered_len = dfc_secure_messaging_unwrap_ev1_response(
        expected_sm, DFC_STATUS_OK, response, response_len - 2, recovered, sizeof(recovered));

    // The fixture holds logical rights 0x1230, emitted low octet first.
    uint8_t expected_settings[] = {0x00, 0x01, 0x30, 0x12, 0x03, 0x00, 0x00};
    munit_assert_size(recovered_len, ==, sizeof(expected_settings));
    munit_assert_memory_equal(sizeof(expected_settings), recovered, expected_settings);

    dfc_secure_messaging_free(expected_sm);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_ev1_error_response_clears_authenticated_session(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    load_standard_credential(&credential);
    DfcApplication* app = dfc_credential_get_primary_application(&credential);
    munit_assert_not_null(app);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);

    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    uint8_t response[128];
    size_t response_len = 0;
    const uint8_t select_app[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x4F, 0x49, 0xD3, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);

    const uint8_t authenticate[] = {0x90, 0x1A, 0x00, 0x00, 0x01, 0x01, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, authenticate, sizeof(authenticate), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 10);

    const uint8_t* key = dfc_credential_key_const(&credential, app, 1);
    uint8_t iv[16] = {0};
    uint8_t rnd_b[16];
    dfc_worker_des_cbc_decrypt(key, app->key_len, iv, 8, response, rnd_b);

    uint8_t rnd_b_rot[16];
    memcpy(rnd_b_rot, rnd_b, 8);
    dfc_rotate_left(rnd_b_rot, 8);

    uint8_t rnd_a[16] = {0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87};
    uint8_t challenge[16];
    memcpy(challenge, rnd_a, 8);
    memcpy(challenge + 8, rnd_b_rot, 8);

    memcpy(iv, response, 8);
    uint8_t encrypted_challenge[16];
    dfc_worker_des_cbc_encrypt(
        key, app->key_len, iv, sizeof(challenge), challenge, encrypted_challenge);

    uint8_t additional_frame[22] = {0x90, 0xAF, 0x00, 0x00, 0x10};
    memcpy(additional_frame + 5, encrypted_challenge, sizeof(encrypted_challenge));
    additional_frame[21] = 0x00;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            additional_frame,
            sizeof(additional_frame),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_not_null(session->emulator->secure_messaging);

    const uint8_t get_missing_file_settings[] = {0x90, 0xF5, 0x00, 0x00, 0x01, 0x7F, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            get_missing_file_settings,
            sizeof(get_missing_file_settings),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_uint8(response[0], ==, 0x91);
    munit_assert_uint8(response[1], ==, DFC_STATUS_PARAMETER_ERROR);
    munit_assert_not_null(session->emulator->secure_messaging);
    munit_assert_false(dfc_emulator_native_authentication_active(session->emulator));

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static void build_read_data_command(uint32_t offset, uint32_t length, uint8_t command[13]) {
    const uint8_t prefix[] = {0x90, DFC_CMD_READ_DATA, 0x00, 0x00, 0x07, 0x0F};
    memcpy(command, prefix, sizeof(prefix));
    command[6] = (uint8_t)offset;
    command[7] = (uint8_t)(offset >> 8);
    command[8] = (uint8_t)(offset >> 16);
    command[9] = (uint8_t)length;
    command[10] = (uint8_t)(length >> 8);
    command[11] = (uint8_t)(length >> 16);
    command[12] = 0x00;
}

static size_t exchange_read_data(
    DfcVirtualPiccSession* session,
    uint32_t offset,
    uint32_t length,
    uint8_t* response,
    size_t response_capacity) {
    uint8_t command[13];
    build_read_data_command(offset, length, command);
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, sizeof(command), response, response_capacity, &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    return response_len;
}

static void seed_incompatible_file_state(DfcFile* file) {
    switch(file->type) {
    case DFC_FILE_TYPE_VALUE:
        file->state.value.lower_limit = -41;
        file->state.value.upper_limit = 93;
        file->state.value.current = 17;
        break;
    case DFC_FILE_TYPE_LINEAR_RECORD:
    case DFC_FILE_TYPE_CYCLIC_RECORD:
        file->state.record.size = 4;
        file->state.record.max_records = 3;
        file->state.record.count = 2;
        break;
    default:
        munit_error("incompatible ReadData fixture requires a value or record file");
    }
}

static DfcVirtualPiccSession* prepare_read_data_session(
    DfcCredential* credential,
    uint8_t file_type,
    size_t file_len,
    uint8_t fill) {
    load_standard_credential(credential);
    DfcFile* file = &credential->files[0];
    file->type = file_type;
    file->access_rights = 0xEEEE;
    file->state.data.sdm_read_counter = 7;
    munit_assert_true(dfc_file_resize(credential, file, file_len));
    uint8_t* file_data = dfc_file_data(credential, file);
    munit_assert_not_null(file_data);
    memset(file_data, fill, file_len);

    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(credential);
    munit_assert_not_null(session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    return session;
}

static MunitResult
    test_read_data_type_errors_retire_ev1_session(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    static const uint8_t incompatible_types[] = {
        DFC_FILE_TYPE_VALUE,
        DFC_FILE_TYPE_LINEAR_RECORD,
        DFC_FILE_TYPE_CYCLIC_RECORD,
    };
    static const uint32_t rejected_ranges[][2] = {
        {0, 0},
        {7, 1},
        {0, 9},
    };

    for(size_t i = 0; i < sizeof(incompatible_types) / sizeof(incompatible_types[0]); i++) {
        for(size_t range = 0; range < sizeof(rejected_ranges) / sizeof(rejected_ranges[0]);
            range++) {
            DfcCredential credential;
            DfcVirtualPiccSession* session =
                prepare_read_data_session(&credential, incompatible_types[i], 8, 0x5A);
            DfcFile* file = &credential.files[0];
            seed_incompatible_file_state(file);
            uint8_t* file_data = dfc_file_data(&credential, file);
            DfcFile file_before = *file;
            uint8_t file_data_before[8];
            memcpy(file_data_before, file_data, sizeof(file_data_before));

            uint8_t session_key[16] = {0};
            install_test_authentication(
                session->emulator, DFC_CMD_AUTHENTICATE_ISO, session_key, sizeof(session_key), 1);

            uint8_t response[32];
            memset(response, 0xA5, sizeof(response));
            size_t response_len = exchange_read_data(
                session,
                rejected_ranges[range][0],
                rejected_ranges[range][1],
                response,
                sizeof(response));
            munit_assert_size(response_len, ==, 2);
            munit_assert_memory_equal(
                response_len, response, ((uint8_t[]){0x91, DFC_STATUS_PERMISSION_DENIED}));
            for(size_t tail = response_len; tail < sizeof(response); tail++) {
                munit_assert_uint8(response[tail], ==, 0xA5);
            }
            munit_assert_memory_equal(sizeof(file_before), file, &file_before);
            munit_assert_memory_equal(sizeof(file_data_before), file_data, file_data_before);
            munit_assert_false(dfc_emulator_native_authentication_active(session->emulator));
            munit_assert_uint8(session->emulator->auth_cipher, ==, 0);
            munit_assert_uint8(session->emulator->auth_key_no, ==, 0);

            dfc_virtual_picc_session_free(session);
        }
    }

    return MUNIT_OK;
}

static MunitResult test_read_data_transaction_mac_uses_configured_protection(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_read_data_session(
        &credential, DFC_FILE_TYPE_TRANSACTION_MAC, DFC_TRANSACTION_MAC_FILE_LENGTH, 0);
    DfcFile* file = &credential.files[0];
    file->comm_settings = DFC_COMM_ENCIPHERED;
    file->access_rights = 0x1EFE;
    uint8_t* file_data = dfc_file_data(&credential, file);
    munit_assert_not_null(file_data);
    for(size_t i = 0; i < DFC_TRANSACTION_MAC_FILE_LENGTH; i++)
        file_data[i] = (uint8_t)(0x70 + i);

    uint8_t session_key[16] = {0};
    install_test_authentication(
        session->emulator, DFC_CMD_AUTHENTICATE_ISO, session_key, sizeof(session_key), 1);
    DfcSecureMessaging* oracle = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_ISO, session_key, sizeof(session_key), NULL);
    munit_assert_not_null(oracle);

    static const uint32_t accepted_ranges[][2] = {
        {0, DFC_TRANSACTION_MAC_FILE_LENGTH},
        {DFC_TRANSACTION_MAC_FILE_LENGTH - 1, 1},
    };
    for(size_t range = 0; range < sizeof(accepted_ranges) / sizeof(accepted_ranges[0]); range++) {
        uint8_t read_data[13];
        build_read_data_command(accepted_ranges[range][0], accepted_ranges[range][1], read_data);
        munit_assert_true(
            dfc_secure_messaging_update_ev1_command(oracle, DFC_CMD_READ_DATA, read_data + 5, 7));
        size_t expected_len = accepted_ranges[range][1];

        uint8_t response[64];
        size_t response_len = exchange_read_data(
            session,
            accepted_ranges[range][0],
            accepted_ranges[range][1],
            response,
            sizeof(response));
        munit_assert_size(response_len, >, expected_len + 2);
        munit_assert_uint8(response[response_len - 2], ==, 0x91);
        munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_OK);

        uint8_t clear[DFC_SM_MAX_SIZE];
        size_t clear_len = 0;
        munit_assert_true(dfc_secure_messaging_unwrap(
            oracle,
            DFC_COMM_ENCIPHERED,
            DFC_STATUS_OK,
            response,
            response_len - 2,
            clear,
            sizeof(clear),
            &clear_len));
        munit_assert_size(clear_len, ==, expected_len);
        munit_assert_memory_equal(expected_len, clear, file_data + accepted_ranges[range][0]);
    }

    uint8_t response[64];
    size_t response_len = exchange_read_data(
        session, 0, DFC_TRANSACTION_MAC_FILE_LENGTH + 1, response, sizeof(response));
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_BOUNDARY_ERROR}));
    munit_assert_false(dfc_emulator_native_authentication_active(session->emulator));

    dfc_secure_messaging_free(oracle);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_read_data_type_error_aborts_pending_transaction(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    DfcVirtualPiccSession* session =
        prepare_read_data_session(&credential, DFC_FILE_TYPE_VALUE, 8, 0x5A);
    DfcFile* file = &credential.files[0];
    seed_incompatible_file_state(file);
    file->state.value.pending = true;
    file->state.value.pending_delta = 5;
    uint8_t session_key[16] = {0};
    install_test_authentication(
        session->emulator, DFC_CMD_AUTHENTICATE_ISO, session_key, sizeof(session_key), 1);

    uint8_t response[32];
    size_t response_len = exchange_read_data(session, 0, 0, response, sizeof(response));
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_PERMISSION_DENIED}));
    // Error finalization rolls back the open transaction and retires the
    // authenticated session after returning the card status.
    munit_assert_false(file->state.value.pending);
    munit_assert_int32(file->state.value.pending_delta, ==, 0);
    munit_assert_int32(file->state.value.lower_limit, ==, -41);
    munit_assert_int32(file->state.value.upper_limit, ==, 93);
    munit_assert_int32(file->state.value.current, ==, 17);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 7);
    munit_assert_false(dfc_emulator_native_authentication_active(session->emulator));

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static void check_get_version_terminal_frame(uint8_t cipher, size_t key_len, const char* name) {
    munit_logf(MUNIT_LOG_INFO, "GetVersion terminal MAC with %s", name);
    DfcCredential credential;
    load_standard_credential(&credential);
    credential.card.generation = DfcGenerationEv1;
    credential.card.storage = 4096;
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    uint8_t key[24] = {0};
    install_test_authentication(session->emulator, cipher, key, key_len, 0);
    DfcSecureMessaging* reader = dfc_secure_messaging_alloc(cipher, key, key_len, NULL);
    munit_assert_not_null(reader);

    const uint8_t get_version[] = {0x90, 0x60, 0x00, 0x00, 0x00};
    const uint8_t af[] = {0x90, 0xAF, 0x00, 0x00, 0x00};
    const uint8_t* commands[] = {get_version, af, af};
    size_t lengths[] = {sizeof(get_version), sizeof(af), sizeof(af)};
    uint8_t response[64];
    uint8_t recovered[32];
    size_t response_len = 0;
    static const uint8_t frame_one[] = {0x04, 0x01, 0x01, 0x01, 0x00, 0x18, 0x05};
    static const uint8_t frame_two[] = {0x04, 0x01, 0x01, 0x01, 0x03, 0x18, 0x05};
    static const uint8_t frame_three[] = {
        0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x24};
    const uint8_t* expected_plain[] = {frame_one, frame_two};
    for(size_t i = 0; i < 3; i++) {
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                session, commands[i], lengths[i], response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        uint8_t status = i == 2 ? DFC_STATUS_OK : DFC_CMD_ADDITIONAL_FRAME;
        size_t plain_len = i == 2 ? 14 : 7;
        size_t mac_len = i == 2 ? DFC_WIRE_MAC_LENGTH : 0;
        munit_assert_size(response_len, ==, plain_len + mac_len + 2);
        munit_assert_uint8(response[response_len - 2], ==, 0x91);
        munit_assert_uint8(response[response_len - 1], ==, status);
        if(i < 2) munit_assert_memory_equal(plain_len, response, expected_plain[i]);
        uint8_t previous_iv[sizeof(reader->iv)];
        memcpy(previous_iv, reader->iv, sizeof(previous_iv));
        munit_assert_true(dfc_secure_messaging_update_ev1_command(
            reader, i == 0 ? DFC_CMD_GET_VERSION : DFC_CMD_ADDITIONAL_FRAME, NULL, 0));
        munit_assert_memory_not_equal(sizeof(previous_iv), previous_iv, reader->iv);
        if(i == 2) {
            size_t recovered_len = dfc_secure_messaging_unwrap_ev1_response(
                reader, status, response, response_len - 2, recovered, sizeof(recovered));
            munit_assert_size(recovered_len, ==, plain_len);
            munit_assert_memory_equal(sizeof(frame_three), recovered, frame_three);
        }
    }

    // The following protected response proves the terminal CMAC became the IV
    // on both sides of the exchange.
    const uint8_t get_key_settings[] = {0x90, DFC_CMD_GET_KEY_SETTINGS, 0, 0, 0};
    munit_assert_true(
        dfc_secure_messaging_update_ev1_command(reader, DFC_CMD_GET_KEY_SETTINGS, NULL, 0));
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            get_key_settings,
            sizeof(get_key_settings),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2 + DFC_WIRE_MAC_LENGTH + 2);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_OK);
    size_t recovered_len = dfc_secure_messaging_unwrap_ev1_response(
        reader, DFC_STATUS_OK, response, response_len - 2, recovered, sizeof(recovered));
    munit_assert_size(recovered_len, ==, 2);
    munit_assert_uint8(recovered[0], ==, credential.picc_key_settings_1);
    munit_assert_uint8(recovered[1], ==, credential.picc_key_settings_2);

    dfc_secure_messaging_free(reader);
    dfc_virtual_picc_session_free(session);
}

static MunitResult test_get_version_terminal_frame_uses_ev1_response_mac(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    check_get_version_terminal_frame(DFC_CMD_AUTHENTICATE_ISO, 8, "DES");
    check_get_version_terminal_frame(DFC_CMD_AUTHENTICATE_ISO, 16, "two-key TDEA");
    check_get_version_terminal_frame(DFC_CMD_AUTHENTICATE_ISO, 24, "three-key TDEA");
    check_get_version_terminal_frame(DFC_CMD_AUTHENTICATE_AES, 16, "AES");
    return MUNIT_OK;
}

static MunitResult test_get_version_length_error_clears_ev1_session(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    const uint8_t invalid_commands[][7] = {
        {0x90, 0x60, 0x00, 0x00, 0x01, 0x00, 0x00},
        {0x90, 0xAF, 0x00, 0x00, 0x01, 0x00, 0x00},
    };
    const uint8_t get_version[] = {0x90, 0x60, 0x00, 0x00, 0x00};
    const uint8_t af[] = {0x90, 0xAF, 0x00, 0x00, 0x00};
    for(size_t i = 0; i < 3; i++) {
        DfcCredential credential;
        load_standard_credential(&credential);
        DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
        DfcVirtualPiccActivation activation;
        munit_assert_int(
            dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

        uint8_t key[16] = {0};
        install_test_authentication(
            session->emulator, DFC_CMD_AUTHENTICATE_ISO, key, sizeof(key), 0);

        uint8_t response[64];
        size_t response_len = 0;
        if(i > 0) {
            munit_assert_int(
                dfc_virtual_picc_iso_dep_exchange(
                    session,
                    get_version,
                    sizeof(get_version),
                    response,
                    sizeof(response),
                    &response_len),
                ==,
                DfcVirtualPiccStatusOk);
            munit_assert_uint8(response[response_len - 1], ==, DFC_CMD_ADDITIONAL_FRAME);
        }
        if(i == 2) {
            munit_assert_int(
                dfc_virtual_picc_iso_dep_exchange(
                    session, af, sizeof(af), response, sizeof(response), &response_len),
                ==,
                DfcVirtualPiccStatusOk);
            munit_assert_uint8(response[response_len - 1], ==, DFC_CMD_ADDITIONAL_FRAME);
        }
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                session,
                invalid_commands[i == 0 ? 0 : 1],
                sizeof(invalid_commands[0]),
                response,
                sizeof(response),
                &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(response_len, ==, 2);
        munit_assert_uint8(response[0], ==, 0x91);
        munit_assert_uint8(response[1], ==, DFC_STATUS_LENGTH_ERROR);
        munit_assert_not_null(session->emulator->secure_messaging);
        munit_assert_false(dfc_emulator_native_authentication_active(session->emulator));
        munit_assert_uint8(session->emulator->get_version_frame, ==, 0);
        dfc_virtual_picc_session_free(session);
    }
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/iso-authentication-resets-ev1-secure-messaging-iv",
     test_iso_authentication_resets_ev1_secure_messaging_iv,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev1-error-response-clears-authenticated-session",
     test_ev1_error_response_clears_authenticated_session,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/read-data-type-errors-retire-ev1-session",
     test_read_data_type_errors_retire_ev1_session,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/read-data-transaction-mac-uses-configured-protection",
     test_read_data_transaction_mac_uses_configured_protection,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/read-data-type-error-aborts-pending-transaction",
     test_read_data_type_error_aborts_pending_transaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/get-version-terminal-frame-uses-ev1-response-mac",
     test_get_version_terminal_frame_uses_ev1_response_mac,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/get-version-length-error-clears-ev1-session",
     test_get_version_length_error_clears_ev1_session,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite =
    {"/dfc_virtual_picc_secure", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
