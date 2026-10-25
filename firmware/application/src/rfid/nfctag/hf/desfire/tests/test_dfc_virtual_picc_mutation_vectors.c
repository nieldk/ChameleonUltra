#include "dfc_virtual_picc_test_helpers.h"

static MunitResult test_pcsc_change_key_mutation_proves_auth_behavior(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    memset(&credential, 0, sizeof(credential));
    credential.uid_len = DFC_DESFIRE_UID_LEN;
    memcpy(
        credential.uid,
        ((uint8_t[]){0x04, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}),
        DFC_DESFIRE_UID_LEN);
    credential.picc_key_settings_1 = 0x0F;
    credential.picc_key_settings_2 = DFC_KEY_TYPE_DES_2K3DES | 1;
    credential.picc_auth_command = DFC_CMD_AUTHENTICATE_LEGACY;
    // PICC key material lives in the shared pool, so it is reserved not assigned.
    munit_assert_true(dfc_credential_keys_resize(&credential, NULL, 1, 16));

    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    uint8_t response[128];
    size_t response_len = 0;

    const uint8_t select_picc[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00};
    const uint8_t create_app[] = {
        0x90, 0xCA, 0x00, 0x00, 0x05, 0x7E, 0xC1, 0xD5, 0x0F, 0x01, 0x00};
    const uint8_t select_app[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x7E, 0xC1, 0xD5, 0x00};
    const uint8_t get_key_version[] = {0x90, 0x64, 0x00, 0x00, 0x01, 0x00, 0x00};

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_picc, sizeof(select_picc), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, create_app, sizeof(create_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            get_key_version,
            sizeof(get_key_version),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(3, response, ((uint8_t[]){0x00, 0x91, DFC_STATUS_OK}));

    uint8_t zero_key[16] = {0};
    uint8_t old_session_key[DFC_MAX_KEY_LEN];
    size_t old_session_key_len = 0;
    authenticate_legacy_key0(
        session,
        zero_key,
        sizeof(zero_key),
        response,
        sizeof(response),
        &response_len,
        old_session_key,
        &old_session_key_len,
        DFC_STATUS_OK);

    uint8_t new_key[16] = {
        0x10,
        0x32,
        0x54,
        0x76,
        0x98,
        0xBA,
        0xDC,
        0xFE,
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xAB,
        0xCD,
        0xEF};
    uint8_t change_key_payload[1 + 24];
    size_t change_key_payload_len = build_legacy_change_key_payload(
        old_session_key, old_session_key_len, new_key, sizeof(new_key), 0x5A, change_key_payload);
    uint8_t change_key[5 + sizeof(change_key_payload) + 1] = {0x90, 0xC4, 0x00, 0x00};
    change_key[4] = change_key_payload_len;
    memcpy(change_key + 5, change_key_payload, change_key_payload_len);
    change_key[5 + change_key_payload_len] = 0x00;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            change_key,
            6 + change_key_payload_len,
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    authenticate_legacy_key0(
        session,
        zero_key,
        sizeof(zero_key),
        response,
        sizeof(response),
        &response_len,
        NULL,
        NULL,
        DFC_STATUS_AUTHENTICATION_ERR);

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    uint8_t new_session_key[DFC_MAX_KEY_LEN];
    size_t new_session_key_len = 0;
    authenticate_legacy_key0(
        session,
        new_key,
        sizeof(new_key),
        response,
        sizeof(response),
        &response_len,
        new_session_key,
        &new_session_key_len,
        DFC_STATUS_OK);

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            get_key_version,
            sizeof(get_key_version),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(3, response, ((uint8_t[]){0x5A, 0x91, DFC_STATUS_OK}));

    change_key_payload_len = build_legacy_change_key_payload(
        new_session_key, new_session_key_len, zero_key, sizeof(zero_key), 0x00, change_key_payload);
    change_key[4] = change_key_payload_len;
    memcpy(change_key + 5, change_key_payload, change_key_payload_len);
    change_key[5 + change_key_payload_len] = 0x00;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            change_key,
            6 + change_key_payload_len,
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    authenticate_legacy_key0(
        session,
        new_key,
        sizeof(new_key),
        response,
        sizeof(response),
        &response_len,
        NULL,
        NULL,
        DFC_STATUS_AUTHENTICATION_ERR);

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    authenticate_legacy_key0(
        session,
        zero_key,
        sizeof(zero_key),
        response,
        sizeof(response),
        &response_len,
        NULL,
        NULL,
        DFC_STATUS_OK);

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            get_key_version,
            sizeof(get_key_version),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(3, response, ((uint8_t[]){0x00, 0x91, DFC_STATUS_OK}));

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_d40_change_key_rejects_nonzero_tail(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    // D40 authentication is defined only for the DES/2K3DES key family.
    static const size_t key_lengths[] = {8, 16};
    const uint8_t wire_aid[] = {0x03, 0x02, 0x01};
    const uint8_t select_app[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x03, 0x02, 0x01, 0x00};

    for(size_t key_index = 0; key_index < sizeof(key_lengths) / sizeof(key_lengths[0]);
        key_index++) {
        size_t key_len = key_lengths[key_index];
        for(size_t different = 0; different < 2; different++) {
            for(size_t invalid_tail = 0; invalid_tail < 2; invalid_tail++) {
                DfcCredential credential = {0};
                munit_assert_true(dfc_credential_clear(&credential));
                credential.card.generation = DfcGenerationEv3;
                credential.card.storage = 4096;
                memcpy(
                    credential.uid,
                    ((uint8_t[]){0x04, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36}),
                    DFC_DESFIRE_UID_LEN);
                credential.uid_len = DFC_DESFIRE_UID_LEN;
                DfcApplication* app = dfc_credential_create_application_desfire_order(
                    &credential, wire_aid, 0x0F, DFC_KEY_TYPE_DES_2K3DES | 2);
                munit_assert_not_null(app);
                app->auth_command = DFC_CMD_AUTHENTICATE_LEGACY;
                app->has_auth_commands = true;
                app->auth_commands = DFC_AUTH_COMMAND_ALL;
                munit_assert_true(dfc_credential_keys_resize(&credential, app, 2, key_len));

                DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
                munit_assert_not_null(session);
                DfcVirtualPiccActivation activation;
                munit_assert_int(
                    dfc_virtual_picc_scan_iso14443a(session, &activation),
                    ==,
                    DfcVirtualPiccStatusOk);
                uint8_t response[128];
                size_t response_len = 0;
                munit_assert_int(
                    dfc_virtual_picc_iso_dep_exchange(
                        session,
                        select_app,
                        sizeof(select_app),
                        response,
                        sizeof(response),
                        &response_len),
                    ==,
                    DfcVirtualPiccStatusOk);

                uint8_t zero_key[DFC_MAX_KEY_LEN] = {0};
                uint8_t session_key[DFC_MAX_KEY_LEN];
                size_t session_key_len = 0;
                authenticate_legacy_key0(
                    session,
                    zero_key,
                    key_len,
                    response,
                    sizeof(response),
                    &response_len,
                    session_key,
                    &session_key_len,
                    DFC_STATUS_OK);

                uint8_t new_key[DFC_MAX_KEY_LEN];
                for(size_t i = 0; i < key_len; i++)
                    new_key[i] = (uint8_t)(0x20 + i);
                uint8_t payload[1 + DFC_MAX_KEY_LEN + 8];
                size_t payload_len;
                if(different) {
                    payload_len = invalid_tail ?
                                      build_legacy_change_other_key_payload_with_nonzero_tail(
                                          session_key,
                                          session_key_len,
                                          1,
                                          zero_key,
                                          new_key,
                                          key_len,
                                          0x5A,
                                          payload) :
                                      build_legacy_change_other_key_payload(
                                          session_key,
                                          session_key_len,
                                          1,
                                          zero_key,
                                          new_key,
                                          key_len,
                                          0x5A,
                                          payload);
                } else {
                    payload_len =
                        invalid_tail ?
                            build_legacy_change_key_payload_with_nonzero_tail(
                                session_key, session_key_len, new_key, key_len, 0x5A, payload) :
                            build_legacy_change_key_payload(
                                session_key, session_key_len, new_key, key_len, 0x5A, payload);
                }

                DfcCredential credential_before = credential;
                DfcSecureMessaging session_before = *session->emulator->secure_messaging;
                uint8_t command[5 + sizeof(payload) + 1] = {0x90, DFC_CMD_CHANGE_KEY, 0, 0};
                command[4] = (uint8_t)payload_len;
                memcpy(command + 5, payload, payload_len);
                command[5 + payload_len] = 0;
                munit_assert_int(
                    dfc_virtual_picc_iso_dep_exchange(
                        session,
                        command,
                        6 + payload_len,
                        response,
                        sizeof(response),
                        &response_len),
                    ==,
                    DfcVirtualPiccStatusOk);

                if(invalid_tail) {
                    munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_INTEGRITY_ERROR);
                    munit_assert_memory_equal(sizeof(credential), &credential, &credential_before);
                    munit_assert_not_null(session->emulator->secure_messaging);
                    munit_assert_memory_equal(
                        sizeof(session_before),
                        session->emulator->secure_messaging,
                        &session_before);
                    munit_assert_uint8(session->emulator->auth_key_no, ==, 0);
                } else {
                    munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_OK);
                    munit_assert_memory_not_equal(
                        key_len,
                        dfc_credential_key_const(&credential, app, different ? 1 : 0),
                        zero_key);
                }
                dfc_virtual_picc_session_free(session);
            }
        }
    }
    return MUNIT_OK;
}

static MunitResult
    test_aes_change_key_same_key_round_trip(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    memset(&credential, 0, sizeof(credential));
    credential.uid_len = DFC_DESFIRE_UID_LEN;
    memcpy(
        credential.uid,
        ((uint8_t[]){0x04, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}),
        DFC_DESFIRE_UID_LEN);
    credential.picc_key_settings_1 = 0x0F;
    credential.picc_key_settings_2 = DFC_KEY_TYPE_AES | 1;
    credential.picc_auth_command = DFC_CMD_AUTHENTICATE_AES;
    // PICC key material lives in the shared pool, so it is reserved not assigned.
    munit_assert_true(dfc_credential_keys_resize(&credential, NULL, 1, 16));

    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    uint8_t response[128];
    size_t response_len = 0;

    const uint8_t select_picc[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00};
    // Create AES app with 1 key, free change of master.
    const uint8_t create_app[] = {
        0x90, 0xCA, 0x00, 0x00, 0x05, 0x7E, 0xC1, 0xD5, 0x0F, 0x81, 0x00};
    const uint8_t select_app[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x7E, 0xC1, 0xD5, 0x00};
    const uint8_t get_key_version[] = {0x90, 0x64, 0x00, 0x00, 0x01, 0x00, 0x00};

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_picc, sizeof(select_picc), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, create_app, sizeof(create_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);

    uint8_t zero_key[16] = {0};
    uint8_t session_key[DFC_MAX_KEY_LEN];
    size_t session_key_len = 0;
    uint8_t session_iv[16] = {0};
    authenticate_aes_key(
        session,
        0x00,
        zero_key,
        sizeof(zero_key),
        response,
        sizeof(response),
        &response_len,
        session_key,
        &session_key_len,
        session_iv,
        DFC_STATUS_OK);

    uint8_t new_key[16] = {
        0x10,
        0x32,
        0x54,
        0x76,
        0x98,
        0xBA,
        0xDC,
        0xFE,
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xAB,
        0xCD,
        0xEF};
    uint8_t change_payload[1 + 48];
    size_t change_payload_len = build_ev1_change_key_payload(
        DFC_CMD_AUTHENTICATE_AES,
        session_key,
        session_key_len,
        session_iv,
        0x00,
        0x00,
        zero_key,
        new_key,
        sizeof(new_key),
        true,
        0x5A,
        change_payload);

    uint8_t change_key[5 + 64];
    change_key[0] = 0x90;
    change_key[1] = 0xC4;
    change_key[2] = 0x00;
    change_key[3] = 0x00;
    change_key[4] = (uint8_t)change_payload_len;
    memcpy(change_key + 5, change_payload, change_payload_len);
    change_key[5 + change_payload_len] = 0x00;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, change_key, 6 + change_payload_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    // Same-key change ends the session: plain status, no CMAC.
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));
    munit_assert_uint8(credential.apps[0].key_versions[0], ==, 0x5A);
    munit_assert_memory_equal(
        16, dfc_credential_key_const(&credential, &credential.apps[0], 0), new_key);

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    authenticate_aes_key(
        session,
        0x00,
        zero_key,
        sizeof(zero_key),
        response,
        sizeof(response),
        &response_len,
        NULL,
        NULL,
        NULL,
        DFC_STATUS_AUTHENTICATION_ERR);

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    authenticate_aes_key(
        session,
        0x00,
        new_key,
        sizeof(new_key),
        response,
        sizeof(response),
        &response_len,
        NULL,
        NULL,
        NULL,
        DFC_STATUS_OK);

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            get_key_version,
            sizeof(get_key_version),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    // EV1 response carries version + 8-byte CMAC + 91 00.
    munit_assert_uint8(response[0], ==, 0x5A);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_OK);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_aes_change_key_integrity_error_preserves_key(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    memset(&credential, 0, sizeof(credential));
    credential.uid_len = DFC_DESFIRE_UID_LEN;
    memcpy(
        credential.uid,
        ((uint8_t[]){0x04, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}),
        DFC_DESFIRE_UID_LEN);
    credential.picc_key_settings_1 = 0x0F;
    credential.picc_key_settings_2 = DFC_KEY_TYPE_AES | 1;
    credential.picc_auth_command = DFC_CMD_AUTHENTICATE_AES;
    // PICC key material lives in the shared pool, so it is reserved not assigned.
    munit_assert_true(dfc_credential_keys_resize(&credential, NULL, 1, 16));

    const uint8_t aid[] = {0x11, 0x22, 0x33};
    DfcApplication* app = dfc_credential_create_application_desfire_order(
        &credential, aid, 0x0F, DFC_KEY_TYPE_AES | 1);
    munit_assert_not_null(app);

    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    uint8_t response[128];
    size_t response_len = 0;
    const uint8_t select_app[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x11, 0x22, 0x33, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);

    uint8_t zero_key[16] = {0};
    uint8_t session_key[DFC_MAX_KEY_LEN];
    size_t session_key_len = 0;
    uint8_t session_iv[16] = {0};
    authenticate_aes_key(
        session,
        0x00,
        zero_key,
        sizeof(zero_key),
        response,
        sizeof(response),
        &response_len,
        session_key,
        &session_key_len,
        session_iv,
        DFC_STATUS_OK);

    uint8_t new_key[16];
    memset(new_key, 0xAB, sizeof(new_key));
    uint8_t change_payload[1 + 48];
    size_t change_payload_len = build_ev1_change_key_payload(
        DFC_CMD_AUTHENTICATE_AES,
        session_key,
        session_key_len,
        session_iv,
        0x00,
        0x00,
        zero_key,
        new_key,
        sizeof(new_key),
        true,
        0x01,
        change_payload);
    change_payload[1] ^= 0x80; // tamper cryptogram

    uint8_t change_key[5 + 64];
    change_key[0] = 0x90;
    change_key[1] = 0xC4;
    change_key[2] = 0x00;
    change_key[3] = 0x00;
    change_key[4] = (uint8_t)change_payload_len;
    memcpy(change_key + 5, change_payload, change_payload_len);
    change_key[5 + change_payload_len] = 0x00;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, change_key, 6 + change_payload_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_INTEGRITY_ERROR}));
    munit_assert_memory_equal(
        16, dfc_credential_key_const(&credential, &credential.apps[0], 0), zero_key);

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    authenticate_aes_key(
        session,
        0x00,
        zero_key,
        sizeof(zero_key),
        response,
        sizeof(response),
        &response_len,
        NULL,
        NULL,
        NULL,
        DFC_STATUS_OK);

    uint8_t oversized_change_key[5 + 1 + 64 + 1] = {0x90, 0xC4, 0x00, 0x00, 65, 0x00};
    memset(oversized_change_key + 6, 0xA5, 64);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            oversized_change_key,
            sizeof(oversized_change_key),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_LENGTH_ERROR);
    munit_assert_memory_equal(
        16, dfc_credential_key_const(&credential, &credential.apps[0], 0), zero_key);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_iso_change_key_same_key_round_trip(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    memset(&credential, 0, sizeof(credential));
    credential.uid_len = DFC_DESFIRE_UID_LEN;
    memcpy(
        credential.uid,
        ((uint8_t[]){0x04, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}),
        DFC_DESFIRE_UID_LEN);
    credential.picc_key_settings_1 = 0x0F;
    credential.picc_key_settings_2 = DFC_KEY_TYPE_DES_2K3DES | 1;
    credential.picc_auth_command = DFC_CMD_AUTHENTICATE_LEGACY;
    // PICC key material lives in the shared pool, so it is reserved not assigned.
    munit_assert_true(dfc_credential_keys_resize(&credential, NULL, 1, 16));

    const uint8_t aid[] = {0xAA, 0xBB, 0xCC};
    DfcApplication* app = dfc_credential_create_application_desfire_order(
        &credential, aid, 0x0F, DFC_KEY_TYPE_DES_2K3DES | 1);
    munit_assert_not_null(app);
    app->auth_command = DFC_CMD_AUTHENTICATE_ISO;

    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    uint8_t response[128];
    size_t response_len = 0;
    const uint8_t select_app[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);

    uint8_t zero_key[16] = {0};
    uint8_t session_key[DFC_MAX_KEY_LEN];
    size_t session_key_len = 0;
    uint8_t session_iv[16] = {0};
    authenticate_iso_key(
        session,
        0x00,
        zero_key,
        sizeof(zero_key),
        response,
        sizeof(response),
        &response_len,
        session_key,
        &session_key_len,
        session_iv,
        DFC_STATUS_OK);

    uint8_t new_key[16] = {
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xAB,
        0xCD,
        0xEF,
        0xFE,
        0xDC,
        0xBA,
        0x98,
        0x76,
        0x54,
        0x32,
        0x10};
    uint8_t change_payload[1 + 48];
    size_t change_payload_len = build_ev1_change_key_payload(
        DFC_CMD_AUTHENTICATE_ISO,
        session_key,
        session_key_len,
        session_iv,
        0x00,
        0x00,
        zero_key,
        new_key,
        sizeof(new_key),
        false,
        0x00,
        change_payload);

    uint8_t change_key[5 + 64];
    change_key[0] = 0x90;
    change_key[1] = 0xC4;
    change_key[2] = 0x00;
    change_key[3] = 0x00;
    change_key[4] = (uint8_t)change_payload_len;
    memcpy(change_key + 5, change_payload, change_payload_len);
    change_key[5 + change_payload_len] = 0x00;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, change_key, 6 + change_payload_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));
    munit_assert_memory_equal(
        16, dfc_credential_key_const(&credential, &credential.apps[0], 0), new_key);

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    authenticate_iso_key(
        session,
        0x00,
        new_key,
        sizeof(new_key),
        response,
        sizeof(response),
        &response_len,
        NULL,
        NULL,
        NULL,
        DFC_STATUS_OK);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/pcsc-change-key-mutation-proves-auth-behavior",
     test_pcsc_change_key_mutation_proves_auth_behavior,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/d40-change-key-rejects-nonzero-tail",
     test_d40_change_key_rejects_nonzero_tail,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/aes-change-key-same-key-round-trip",
     test_aes_change_key_same_key_round_trip,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/aes-change-key-integrity-error-preserves-key",
     test_aes_change_key_integrity_error_preserves_key,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-change-key-same-key-round-trip",
     test_iso_change_key_same_key_round_trip,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite =
    {"/dfc_virtual_picc_mutation_vectors", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
