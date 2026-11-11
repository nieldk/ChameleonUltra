#include "dfc_virtual_picc_test_helpers.h"

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

static MunitTest tests[] = {
    {"/d40-change-key-rejects-nonzero-tail",
     test_d40_change_key_rejects_nonzero_tail,
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
