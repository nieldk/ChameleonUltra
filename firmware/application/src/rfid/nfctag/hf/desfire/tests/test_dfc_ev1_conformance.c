// Ported from MrClean.WireRoom.Tests DesfirePiccSimulatorConformanceTests /
// DesfirePiccSimulatorTests (EV1-native command subset).

#include "dfc_virtual_picc_test_helpers.h"
#include "aes_cmac.h"
#include "dfc_der.h"
#include "dfc_emulator_i.h"
#include "dfc_emulator_commands_i.h"
#include "dfc_sdm_i.h"

#include <string.h>

static void blank_picc(DfcCredential* credential, uint8_t picc_key_settings_1) {
    memset(credential, 0, sizeof(*credential));
    credential->card.generation = DfcGenerationEv1;
    credential->uid_len = DFC_DESFIRE_UID_LEN;
    memcpy(
        credential->uid,
        ((uint8_t[]){0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6}),
        DFC_DESFIRE_UID_LEN);
    credential->picc_key_settings_1 = picc_key_settings_1;
    credential->picc_key_settings_2 = DFC_KEY_TYPE_DES_2K3DES | 1;
    credential->picc_auth_command = DFC_CMD_AUTHENTICATE_LEGACY;
    // PICC key material lives in the shared pool, so it is reserved not assigned.
    munit_assert_true(dfc_credential_keys_resize(credential, NULL, 1, 16));
}

static DfcVirtualPiccSession* open_blank(uint8_t picc_key_settings_1, DfcCredential* credential) {
    blank_picc(credential, picc_key_settings_1);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    return session;
}

static void exchange(
    DfcVirtualPiccSession* session,
    const uint8_t* cmd,
    size_t cmd_len,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len) {
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, cmd, cmd_len, response, response_capacity, response_len),
        ==,
        DfcVirtualPiccStatusOk);
}

// A PICC that records no key material at all: key count zero, nothing reserved in
// the pool. Section 1.4 says an absent key entry is the factory default, so this
// describes a card whose master key has never been changed.
static void keyless_picc(DfcCredential* credential) {
    memset(credential, 0, sizeof(*credential));
    credential->uid_len = DFC_DESFIRE_UID_LEN;
    memcpy(
        credential->uid,
        ((uint8_t[]){0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6}),
        DFC_DESFIRE_UID_LEN);
    credential->picc_key_settings_1 = 0x0F;
    credential->picc_key_settings_2 = DFC_KEY_TYPE_DES_2K3DES | 0;
    credential->picc_auth_command = DFC_CMD_AUTHENTICATE_LEGACY;
}

// The factory key authenticates a PICC that carries no key material, and the
// session it opens is a real one: GetCardUID answers only under authentication.
static MunitResult test_absent_key_is_factory_default(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential credential;
    keyless_picc(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    uint8_t factory[16] = {0};
    uint8_t response[64];
    size_t response_len = 0;
    uint8_t session_key[DFC_MAX_KEY_LEN];
    size_t session_key_len = 0;
    authenticate_legacy_key0(
        session,
        factory,
        sizeof(factory),
        response,
        sizeof(response),
        &response_len,
        session_key,
        &session_key_len,
        DFC_STATUS_OK);

    const uint8_t get_card_uid[] = {0x90, 0x51, 0x00, 0x00, 0x00};
    exchange(
        session, get_card_uid, sizeof(get_card_uid), response, sizeof(response), &response_len);
    munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_OK);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static void assert_status(
    DfcVirtualPiccSession* session,
    const uint8_t* cmd,
    size_t cmd_len,
    uint8_t expected_status) {
    uint8_t response[128];
    size_t response_len = 0;
    exchange(session, cmd, cmd_len, response, sizeof(response), &response_len);
    munit_assert_size(response_len, ==, 2);
    munit_assert_uint8(response[0], ==, 0x91);
    munit_assert_uint8(response[1], ==, expected_status);
}

static void assert_trailing_status(
    DfcVirtualPiccSession* session,
    const uint8_t* cmd,
    size_t cmd_len,
    uint8_t expected_status) {
    uint8_t response[128];
    size_t response_len = 0;
    exchange(session, cmd, cmd_len, response, sizeof(response), &response_len);
    munit_assert_size(response_len, >=, 2);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, expected_status);
}

static DfcVirtualPiccSession* open_file_policy(
    DfcCredential* credential,
    uint8_t key_settings_1,
    uint16_t access_rights,
    uint8_t comm_settings,
    const uint8_t* data,
    size_t data_len) {
    blank_picc(credential, 0x0F);
    const uint8_t aid[] = {0x01, 0x02, 0x03};
    DfcApplication* app =
        dfc_credential_create_application_desfire_order(credential, aid, key_settings_1, 0x01);
    munit_assert_not_null(app);
    DfcFile* file = dfc_credential_create_file(credential, 0, 0x01);
    munit_assert_not_null(file);
    file->type = 0x00;
    file->comm_settings = comm_settings;
    file->access_rights = access_rights;
    munit_assert_size(data_len, <=, DFC_MAX_FILE_DATA);
    munit_assert_true(dfc_file_resize(credential, file, data_len));
    if(data_len > 0) {
        uint8_t* bytes = dfc_file_data(credential, file);
        munit_assert_not_null(bytes);
        memcpy(bytes, data, data_len);
    }

    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    return session;
}

static MunitResult test_get_version_frames(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t response[32];
    size_t response_len = 0;
    const uint8_t get_version[] = {0x90, 0x60, 0x00, 0x00, 0x00};
    const uint8_t af[] = {0x90, 0xAF, 0x00, 0x00, 0x00};
    static const struct {
        DfcGeneration generation;
        uint8_t hardware[7];
        uint8_t software[7];
    } cases[] = {
        {DfcGenerationEv1,
         {0x04, 0x01, 0x01, 0x01, 0x00, 0x18, 0x05},
         {0x04, 0x01, 0x01, 0x01, 0x03, 0x18, 0x05}},
        {DfcGenerationEv2,
         {0x04, 0x01, 0x01, 0x12, 0x00, 0x18, 0x05},
         {0x04, 0x01, 0x01, 0x02, 0x01, 0x18, 0x05}},
        {DfcGenerationEv3,
         {0x04, 0x01, 0x01, 0x33, 0x00, 0x18, 0x05},
         {0x04, 0x01, 0x01, 0x03, 0x00, 0x18, 0x05}},
    };
    static const struct {
        uint32_t bytes;
        uint8_t code;
    } capacities[] = {{2048, 0x16}, {4096, 0x18}, {8192, 0x1A}};
    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        for(size_t j = 0; j < sizeof(capacities) / sizeof(capacities[0]); j++) {
            DfcCredential credential;
            DfcVirtualPiccSession* session = open_blank(0x0F, &credential);
            credential.card.generation = cases[i].generation;
            credential.card.storage = capacities[j].bytes;
            uint8_t expected_hardware[7];
            uint8_t expected_software[7];
            memcpy(expected_hardware, cases[i].hardware, 7);
            memcpy(expected_software, cases[i].software, 7);
            expected_hardware[5] = capacities[j].code;
            expected_software[5] = capacities[j].code;

            exchange(
                session,
                get_version,
                sizeof(get_version),
                response,
                sizeof(response),
                &response_len);
            munit_assert_size(response_len, ==, 9);
            munit_assert_memory_equal(7, response, expected_hardware);
            munit_assert_uint8(response[7], ==, 0x91);
            munit_assert_uint8(response[8], ==, 0xAF);

            exchange(session, af, sizeof(af), response, sizeof(response), &response_len);
            munit_assert_size(response_len, ==, 9);
            munit_assert_memory_equal(7, response, expected_software);
            munit_assert_uint8(response[7], ==, 0x91);
            munit_assert_uint8(response[8], ==, 0xAF);

            exchange(session, af, sizeof(af), response, sizeof(response), &response_len);
            munit_assert_size(response_len, ==, 16);
            munit_assert_memory_equal(7, response, credential.uid);
            static const uint8_t legacy_production[7] = {0, 0, 0, 0, 0, 0x01, 0x24};
            static const uint8_t ev3_production[7] = {0, 0, 0, '0', '0', 0x01, 0x24};
            const uint8_t* production =
                cases[i].generation == DfcGenerationEv3 ? ev3_production : legacy_production;
            munit_assert_memory_equal(7, response + 7, production);
            munit_assert_uint8(response[14], ==, 0x91);
            munit_assert_uint8(response[15], ==, 0x00);
            dfc_virtual_picc_session_free(session);
        }
    }

    DfcCredential overridden;
    DfcVirtualPiccSession* session = open_blank(0x0F, &overridden);
    overridden.card.generation = DfcGenerationEv2;
    overridden.card.storage = 4096;
    overridden.card.has_hardware_version = true;
    memcpy(overridden.card.hardware_version, "\x04\x01\x01\xAA\xBB\xCC\xDD", 7);
    overridden.card.has_software_version = true;
    memcpy(overridden.card.software_version, "\x04\x01\x01\x11\x22\x33\x44", 7);
    exchange(session, get_version, sizeof(get_version), response, sizeof(response), &response_len);
    munit_assert_memory_equal(7, response, overridden.card.hardware_version);
    exchange(session, af, sizeof(af), response, sizeof(response), &response_len);
    munit_assert_memory_equal(7, response, overridden.card.software_version);
    dfc_virtual_picc_session_free(session);

    for(size_t i = 0; i < 2; i++) {
        DfcCredential invalid;
        session = open_blank(0x0F, &invalid);
        invalid.card.generation = i == 0 ? (DfcGeneration)0 : (DfcGeneration)4;
        invalid.card.storage = 4096;
        exchange(
            session, get_version, sizeof(get_version), response, sizeof(response), &response_len);
        munit_assert_size(response_len, ==, 9);
        munit_assert_memory_equal(7, response, cases[0].hardware);
        dfc_virtual_picc_session_free(session);
    }

    static const struct {
        DfcGeneration generation;
        uint32_t storage;
    } unsupported[] = {
        {DfcGenerationEv1, 3000},
        {DfcGenerationEv3, 1024},
        {DfcGenerationEv3, 16384},
    };
    for(size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
        DfcCredential invalid;
        session = open_blank(0x0F, &invalid);
        invalid.card.generation = unsupported[i].generation;
        invalid.card.storage = unsupported[i].storage;
        assert_status(session, get_version, sizeof(get_version), DFC_STATUS_PARAMETER_ERROR);
        dfc_virtual_picc_session_free(session);
    }
    return MUNIT_OK;
}

static MunitResult
    test_plain_write_data_borrows_apdu_payload(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential credential;
    uint8_t zeros[4] = {0};
    DfcVirtualPiccSession* session =
        open_file_policy(&credential, 0x0F, 0xEEEE, DFC_COMM_PLAIN, zeros, sizeof(zeros));
    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    session->emulator->selected_app_index = 0;
    memset(session->emulator->pending_chain, 0xA5, sizeof(session->emulator->pending_chain));

    const uint8_t write[] = {
        DFC_CMD_WRITE_DATA, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x11, 0x22};
    dfc_bytebuf_reset(session->emulator->tx_buffer);
    dfc_emulator_command_write_data(
        session->emulator, write, sizeof(write), session->emulator->tx_buffer);

    munit_assert_size(dfc_bytebuf_get_size_bytes(session->emulator->tx_buffer), ==, 1);
    munit_assert_uint8(dfc_bytebuf_get_byte(session->emulator->tx_buffer, 0), ==, DFC_STATUS_OK);
    for(size_t i = 0; i < sizeof(session->emulator->pending_chain); i++) {
        munit_assert_uint8(session->emulator->pending_chain[i], ==, 0xA5);
    }
    munit_assert_memory_equal(
        2, dfc_file_data(&credential, &credential.files[0]), ((uint8_t[]){0x11, 0x22}));

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_create_file_state_is_complete(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential credential;
    DfcVirtualPiccSession* session = open_blank(0x0F, &credential);

    const uint8_t create_app[] = {
        0x90, 0xCA, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x0F, 0x01, 0x00};
    assert_status(session, create_app, sizeof(create_app), DFC_STATUS_OK);
    const uint8_t select[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00};
    assert_status(session, select, sizeof(select), DFC_STATUS_OK);

    const uint8_t create_file[] = {
        0x90, 0xCD, 0x00, 0x00, 0x07, 0x01, 0x00, 0xEE, 0xEE, 0x04, 0x00, 0x00, 0x00};
    assert_status(session, create_file, sizeof(create_file), DFC_STATUS_OK);
    uint32_t declared_size;
    munit_assert_true(dfc_file_get_declared_size(&credential.files[0], &declared_size));
    munit_assert_uint32(declared_size, ==, 4);
    munit_assert_true(credential.files[0].contents_complete);
    size_t encoded_size = 0;
    munit_assert_int(dfc_der_encoded_size(&credential, &encoded_size), ==, DfcDerOk);
    // The duplicate-file status itself is ev1_create-duplicate-file.vec.

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_create_application_and_list(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential credential;
    DfcVirtualPiccSession* session = open_blank(0x0F, &credential);

    const uint8_t create_app[] = {
        0x90, 0xCA, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x0F, 0x21, 0x00};
    assert_status(session, create_app, sizeof(create_app), DFC_STATUS_OK);
    assert_status(session, create_app, sizeof(create_app), DFC_STATUS_DUPLICATE_ERROR);

    uint8_t response[16];
    size_t response_len = 0;
    const uint8_t get_aids[] = {0x90, 0x6A, 0x00, 0x00, 0x00};
    exchange(session, get_aids, sizeof(get_aids), response, sizeof(response), &response_len);
    munit_assert_memory_equal(5, response, ((uint8_t[]){0x01, 0x02, 0x03, 0x91, 0x00}));
    munit_assert_uint8(credential.apps[0].key_settings_1, ==, 0x0F);
    munit_assert_uint8(credential.apps[0].key_settings_2, ==, 0x21);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_free_access_full_read_treated_as_plain(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcCredential credential;
    uint8_t file_data[] = {0xAA, 0xBB, 0xCC, 0xDD};
    // Free access (0xEEEE) + Full: must not encrypt (EV3 free-access Full demotion).
    DfcVirtualPiccSession* session = open_file_policy(
        &credential, 0x0F, 0xEEEE, DFC_COMM_ENCIPHERED, file_data, sizeof(file_data));

    uint8_t session_key[16] = {0};
    for(size_t i = 0; i < sizeof(session_key); i++) {
        session_key[i] = (uint8_t)(0x30 + i);
    }
    session->emulator->secure_messaging = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_AES, session_key, sizeof(session_key), NULL);
    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    session->emulator->auth_cipher = DFC_CMD_AUTHENTICATE_AES;
    session->emulator->auth_key_no = 0x00;
    munit_assert_true(dfc_emulator_native_authentication_active(session->emulator));

    uint8_t response[64];
    size_t response_len = 0;
    const uint8_t read_all[] = {
        0x90, 0xBD, 0x00, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    exchange(session, read_all, sizeof(read_all), response, sizeof(response), &response_len);

    // Plain data + 8-byte CMAC + 91 00 (not a ciphertext block).
    munit_assert_size(response_len, ==, 4 + 8 + 2);
    munit_assert_memory_equal(4, response, file_data);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_OK);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_ev1_write_data_mac_requires_transmitted_cmac(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcCredential credential;
    uint8_t zeros[8] = {0};
    DfcVirtualPiccSession* session =
        open_file_policy(&credential, 0x0F, 0xE00F, DFC_COMM_MAC, zeros, sizeof(zeros));

    uint8_t session_key[16];
    for(size_t i = 0; i < sizeof(session_key); i++) {
        session_key[i] = (uint8_t)(0x40 + i);
    }
    session->emulator->secure_messaging = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_AES, session_key, sizeof(session_key), NULL);
    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    session->emulator->auth_cipher = DFC_CMD_AUTHENTICATE_AES;
    session->emulator->auth_key_no = 0x00;
    munit_assert_true(dfc_emulator_native_authentication_active(session->emulator));

    uint8_t response[64];
    size_t response_len = 0;

    // A complete write carrying a wrong MACt fails integrity and drops auth.
    const uint8_t write_bad_mac[] = {0x90, 0x3D, 0x00, 0x00, 0x11, 0x01, 0x00, 0x00,
                                     0x00, 0x02, 0x00, 0x00, 0x11, 0x22, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    exchange(
        session, write_bad_mac, sizeof(write_bad_mac), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_INTEGRITY_ERROR}));
    munit_assert_not_null(session->emulator->secure_messaging);
    munit_assert_false(dfc_emulator_native_authentication_active(session->emulator));

    // Restore session for positive path.
    dfc_secure_messaging_free(session->emulator->secure_messaging);
    session->emulator->secure_messaging = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_AES, session_key, sizeof(session_key), NULL);
    munit_assert_not_null(session->emulator->secure_messaging);
    session->emulator->auth_cipher = DFC_CMD_AUTHENTICATE_AES;
    session->emulator->auth_key_no = 0x00;
    munit_assert_true(dfc_emulator_native_authentication_active(session->emulator));

    uint8_t body[] = {0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x11, 0x22};
    // MACt = first 8 bytes of EV1 command CMAC (stored as IV after update).
    DfcSecureMessaging* twin = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_AES, session_key, sizeof(session_key), NULL);
    dfc_secure_messaging_update_ev1_command(twin, DFC_CMD_WRITE_DATA, body, sizeof(body));
    uint8_t mact[8];
    memcpy(mact, twin->iv, 8);

    uint8_t write_cmd[5 + sizeof(body) + 8 + 1];
    write_cmd[0] = 0x90;
    write_cmd[1] = 0x3D;
    write_cmd[2] = 0x00;
    write_cmd[3] = 0x00;
    write_cmd[4] = (uint8_t)(sizeof(body) + 8);
    memcpy(write_cmd + 5, body, sizeof(body));
    memcpy(write_cmd + 5 + sizeof(body), mact, 8);
    write_cmd[5 + sizeof(body) + 8] = 0x00;
    exchange(session, write_cmd, 6 + sizeof(body) + 8, response, sizeof(response), &response_len);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_OK);
    munit_assert_memory_equal(
        2, dfc_file_data(&credential, &credential.files[0]), ((uint8_t[]){0x11, 0x22}));

    dfc_secure_messaging_free(twin);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_read_data_ev1_enciphered_wraps_payload(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcCredential credential;
    uint8_t file_data[] = {0x30, 0x2F, 0x81, 0x02, 0x0C};
    // Key-gated read (nibble 0) so Full is not demoted by free-access rule.
    DfcVirtualPiccSession* session = open_file_policy(
        &credential, 0x0F, 0x0EEE, DFC_COMM_ENCIPHERED, file_data, sizeof(file_data));

    uint8_t session_key[16] = {0};
    for(size_t i = 0; i < sizeof(session_key); i++) {
        session_key[i] = (uint8_t)(0x20 + i);
    }
    session->emulator->secure_messaging = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_AES, session_key, sizeof(session_key), NULL);
    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    session->emulator->auth_cipher = DFC_CMD_AUTHENTICATE_AES;
    session->emulator->auth_key_no = 0x00;
    munit_assert_true(dfc_emulator_native_authentication_active(session->emulator));

    uint8_t response[64];
    size_t response_len = 0;
    const uint8_t read_all[] = {
        0x90, 0xBD, 0x00, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    exchange(session, read_all, sizeof(read_all), response, sizeof(response), &response_len);

    // EV1 Full response: Enc(RespData||CRC32||pad) || 91 00 — no trailing CMAC.
    munit_assert_size(response_len, ==, 16 + 2);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_OK);
    munit_assert_false(memcmp(response, file_data, sizeof(file_data)) == 0);

    // Reader: command CMAC sets IV, then decrypt the body (CRC covers data||status).
    DfcSecureMessaging* reader = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_AES, session_key, sizeof(session_key), NULL);
    uint8_t file_no_off_len[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    dfc_secure_messaging_update_ev1_command(
        reader, DFC_CMD_READ_DATA, file_no_off_len, sizeof(file_no_off_len));

    uint8_t recovered[DFC_SM_MAX_SIZE];
    size_t recovered_len = 0;
    munit_assert_true(dfc_secure_messaging_unwrap(
        reader,
        DFC_COMM_ENCIPHERED,
        DFC_STATUS_OK,
        response,
        16,
        recovered,
        sizeof(recovered),
        &recovered_len));
    munit_assert_size(recovered_len, ==, sizeof(file_data));
    munit_assert_memory_equal(sizeof(file_data), recovered, file_data);

    dfc_secure_messaging_free(reader);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_can_change_key_policy(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    // Mirrors DesfireApplicationState.CanChangeKey policy cases.
    struct {
        uint8_t key_settings_1;
        uint8_t target;
        uint8_t auth;
        bool expected;
    } cases[] = {
        {0x0B, 0x01, 0x00, true},
        {0x0B, 0x01, 0x01, false},
        {0xFB, 0x01, 0x00, false},
        {0xEB, 0x01, 0x01, true},
        {0xEB, 0x01, 0x00, false},
        {0x2B, 0x01, 0x02, true},
        {0x2B, 0x01, 0x00, false},
        {0x0B, 0x00, 0x00, true},
        {0x0A, 0x00, 0x00, false},
    };

    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t ks1 = cases[i].key_settings_1;
        uint8_t target = cases[i].target;
        uint8_t auth = cases[i].auth;
        bool expected = cases[i].expected;
        bool allowed;
        if(target == 0x00) {
            allowed = ((ks1 & DFC_KS1_MASTER_KEY_CHANGEABLE) != 0) && auth == 0x00;
        } else {
            uint8_t change_access = (uint8_t)(ks1 >> DFC_KS1_CHANGE_KEY_ACCESS_SHIFT);
            if(change_access == DFC_CHANGE_KEY_ACCESS_FROZEN) {
                allowed = false;
            } else if(change_access == DFC_CHANGE_KEY_ACCESS_SAME) {
                allowed = auth == target;
            } else if(change_access == 0x00) {
                allowed = auth == 0x00;
            } else {
                allowed = auth == change_access;
            }
        }
        munit_assert_true(allowed == expected);
    }
    return MUNIT_OK;
}

// Access-rights nibbles are only distinguishable when the four of them name four
// different keys. These fixtures create the file over the air, so the wire octets
// are the input and `files[0].access_rights` is the logical value the engine must
// have derived from them.
static DfcVirtualPiccSession* open_rights_file_over_the_air(
    DfcCredential* credential,
    uint8_t rights_wire_low,
    uint8_t rights_wire_high) {
    DfcVirtualPiccSession* session = open_blank(0x0F, credential);
    // Four 2K3DES keys, so keys 0..3 are all available to authenticate as.
    const uint8_t create_app[] = {
        0x90, 0xCA, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x0F, 0x04, 0x00};
    assert_status(session, create_app, sizeof(create_app), DFC_STATUS_OK);
    const uint8_t select_app[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00};
    assert_status(session, select_app, sizeof(select_app), DFC_STATUS_OK);

    // CreateStdDataFile: FileNo Comm AR_lo AR_hi Size(3, LE).
    const uint8_t create_file[] = {
        0x90,
        0xCD,
        0x00,
        0x00,
        0x07,
        0x01,
        DFC_COMM_PLAIN,
        rights_wire_low,
        rights_wire_high,
        0x04,
        0x00,
        0x00,
        0x00};
    assert_status(session, create_file, sizeof(create_file), DFC_STATUS_OK);
    return session;
}

static void reselect_and_authenticate(DfcVirtualPiccSession* session, uint8_t key_no) {
    const uint8_t select_app[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00};
    assert_status(session, select_app, sizeof(select_app), DFC_STATUS_OK);

    uint8_t zero_key[16] = {0};
    uint8_t response[64];
    size_t response_len = 0;
    authenticate_legacy_key(
        session,
        key_no,
        zero_key,
        16,
        response,
        sizeof(response),
        &response_len,
        NULL,
        NULL,
        DFC_STATUS_OK);
}

static size_t build_protected_change_file_settings(
    DfcVirtualPiccSession* session,
    uint8_t file_no,
    const uint8_t* settings,
    size_t settings_len,
    bool wrong_key,
    uint8_t* apdu,
    size_t apdu_capacity) {
    DfcSecureMessaging reader = *session->emulator->secure_messaging;
    reader.pcd = true;
    if(wrong_key) reader.session_key[0] ^= 0x80;
    const uint8_t header[] = {DFC_CMD_CHANGE_FILE_SETTINGS, file_no};
    munit_assert_size(apdu_capacity, >=, 6);
    size_t wrapped_len = dfc_secure_messaging_wrap(
        &reader,
        DFC_COMM_ENCIPHERED,
        header,
        sizeof(header),
        settings,
        settings_len,
        apdu + 6,
        apdu_capacity - 7);
    munit_assert_size(wrapped_len, >, 0);
    munit_assert_size(wrapped_len, <=, UINT8_MAX - 1);
    apdu[0] = DFC_ISO7816_CLA_WRAPPER;
    apdu[1] = DFC_CMD_CHANGE_FILE_SETTINGS;
    apdu[2] = 0;
    apdu[3] = 0;
    apdu[4] = (uint8_t)(1 + wrapped_len);
    apdu[5] = file_no;
    apdu[6 + wrapped_len] = 0;
    return 7 + wrapped_len;
}

static size_t build_protected_change_key_settings(
    DfcVirtualPiccSession* session,
    uint8_t settings,
    bool wrong_key,
    uint8_t* apdu,
    size_t apdu_capacity) {
    DfcSecureMessaging reader = *session->emulator->secure_messaging;
    reader.pcd = true;
    if(wrong_key) reader.session_key[0] ^= 0x80;
    const uint8_t header[] = {DFC_CMD_CHANGE_KEY_SETTINGS};
    munit_assert_size(apdu_capacity, >=, 6);
    size_t wrapped_len = dfc_secure_messaging_wrap(
        &reader,
        DFC_COMM_ENCIPHERED,
        header,
        sizeof(header),
        &settings,
        sizeof(settings),
        apdu + 5,
        apdu_capacity - 6);
    munit_assert_size(wrapped_len, >, 0);
    munit_assert_size(wrapped_len, <=, UINT8_MAX);
    apdu[0] = DFC_ISO7816_CLA_WRAPPER;
    apdu[1] = DFC_CMD_CHANGE_KEY_SETTINGS;
    apdu[2] = 0;
    apdu[3] = 0;
    apdu[4] = (uint8_t)wrapped_len;
    apdu[5 + wrapped_len] = 0;
    return 6 + wrapped_len;
}

static void assert_write_status(DfcVirtualPiccSession* session, uint8_t expected_status) {
    const uint8_t write_data[] = {
        0x90,
        0x3D,
        0x00,
        0x00,
        0x0B,
        0x01,
        0x00,
        0x00,
        0x00,
        0x04,
        0x00,
        0x00,
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        0x00};
    assert_status(session, write_data, sizeof(write_data), expected_status);
}

static void assert_read_status(DfcVirtualPiccSession* session, uint8_t expected_status) {
    const uint8_t read_data[] = {
        0x90, 0xBD, 0x00, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00};
    uint8_t response[64];
    size_t response_len = 0;
    exchange(session, read_data, sizeof(read_data), response, sizeof(response), &response_len);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, expected_status);
}

// Wire octets 30 12 mean logical 0x1230: read key 1, write key 2, read&write
// key 3, change key 0. Writing must therefore admit keys 2 and 3 and refuse
// keys 0 and 1 — in particular the change key must not be able to write.
static MunitResult
    test_write_honours_write_and_read_write_nibbles(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = open_rights_file_over_the_air(&credential, 0x30, 0x12);
    munit_assert_uint16(credential.files[0].access_rights, ==, 0x1230);

    reselect_and_authenticate(session, 0x02);
    assert_write_status(session, DFC_STATUS_OK);

    reselect_and_authenticate(session, 0x03);
    assert_write_status(session, DFC_STATUS_OK);

    reselect_and_authenticate(session, 0x00);
    assert_write_status(session, DFC_STATUS_AUTHENTICATION_ERR);

    reselect_and_authenticate(session, 0x01);
    assert_write_status(session, DFC_STATUS_AUTHENTICATION_ERR);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

// Same file: reading must admit keys 1 and 3 and refuse keys 0 and 2.
static MunitResult
    test_read_honours_read_and_read_write_nibbles(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = open_rights_file_over_the_air(&credential, 0x30, 0x12);
    munit_assert_uint16(credential.files[0].access_rights, ==, 0x1230);

    reselect_and_authenticate(session, 0x01);
    assert_read_status(session, DFC_STATUS_OK);

    reselect_and_authenticate(session, 0x03);
    assert_read_status(session, DFC_STATUS_OK);

    reselect_and_authenticate(session, 0x02);
    assert_read_status(session, DFC_STATUS_AUTHENTICATION_ERR);

    reselect_and_authenticate(session, 0x00);
    assert_read_status(session, DFC_STATUS_AUTHENTICATION_ERR);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

// Wire octets 30 FF mean logical 0xFF30: read and write both denied outright, so
// the read&write nibble (key 3) is the only path to either direction.
static MunitResult test_read_write_nibble_alone_authorises_both_directions(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = open_rights_file_over_the_air(&credential, 0x30, 0xFF);
    munit_assert_uint16(credential.files[0].access_rights, ==, 0xFF30);

    reselect_and_authenticate(session, 0x03);
    assert_write_status(session, DFC_STATUS_OK);
    assert_read_status(session, DFC_STATUS_OK);

    reselect_and_authenticate(session, 0x01);
    assert_write_status(session, DFC_STATUS_AUTHENTICATION_ERR);
    assert_read_status(session, DFC_STATUS_AUTHENTICATION_ERR);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

// ChangeFileSettings is gated by the change nibble, which for logical 0x1230 is
// key 0. Confirms the change nibble is the low one, not one of the read/write pair.
static MunitResult test_change_file_settings_round_trips_logical_rights(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = open_rights_file_over_the_air(&credential, 0x30, 0x12);

    // Rewrite the rights to logical 0x2130 with wire octets 30 21.
    reselect_and_authenticate(session, 0x00);
    const uint8_t settings[] = {DFC_COMM_PLAIN, 0x30, 0x21};
    uint8_t change[32];
    size_t change_len = build_protected_change_file_settings(
        session, 1, settings, sizeof(settings), false, change, sizeof(change));
    assert_status(session, change, change_len, DFC_STATUS_OK);
    munit_assert_uint16(credential.files[0].access_rights, ==, 0x2130);

    // Read is now key 2, write key 1.
    reselect_and_authenticate(session, 0x02);
    assert_read_status(session, DFC_STATUS_OK);
    assert_write_status(session, DFC_STATUS_AUTHENTICATION_ERR);

    reselect_and_authenticate(session, 0x01);
    assert_write_status(session, DFC_STATUS_OK);
    assert_read_status(session, DFC_STATUS_AUTHENTICATION_ERR);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static void assert_file_settings_unchanged(
    DfcVirtualPiccSession* session,
    DfcFile* file,
    const uint8_t* command,
    size_t command_len,
    uint8_t expected_status) {
    DfcFile before = *file;
    bool dirty_before = session->credential->dirty;
    assert_status(session, command, command_len, expected_status);
    munit_assert_memory_equal(sizeof(before), &before, file);
    munit_assert_int(session->credential->dirty, ==, dirty_before);
}

static MunitResult test_change_file_settings_rejects_missing_files_and_keys(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = open_rights_file_over_the_air(&credential, 0xE0, 0xEE);
    DfcFile* file = dfc_credential_find_file_in_app(&credential, 0, 1);
    munit_assert_not_null(file);
    dfc_credential_clear_dirty(&credential);

    const uint8_t missing_file[] = {
        0x90, 0x5F, 0x00, 0x00, 0x04, 0x1E, DFC_COMM_PLAIN, 0xEE, 0xEE, 0x00};
    assert_file_settings_unchanged(
        session, file, missing_file, sizeof(missing_file), DFC_STATUS_FILE_NOT_FOUND);

    const uint8_t unauthorised_invalid_key[] = {
        0x90, 0x5F, 0x00, 0x00, 0x04, 0x01, DFC_COMM_PLAIN, 0xE0, 0x4E, 0x00};
    assert_file_settings_unchanged(
        session,
        file,
        unauthorised_invalid_key,
        sizeof(unauthorised_invalid_key),
        DFC_STATUS_AUTHENTICATION_ERR);

    const uint8_t invalid_rights[][2] = {
        {0xE0, 0x4E},
        {0xE0, 0xE4},
        {0x40, 0xEE},
        {0xE4, 0xEE},
    };
    for(size_t i = 0; i < sizeof(invalid_rights) / sizeof(invalid_rights[0]); i++) {
        reselect_and_authenticate(session, 0x00);
        uint8_t settings[] = {DFC_COMM_PLAIN, invalid_rights[i][0], invalid_rights[i][1]};
        uint8_t command[32];
        size_t command_len = build_protected_change_file_settings(
            session, 1, settings, sizeof(settings), false, command, sizeof(command));
        assert_file_settings_unchanged(
            session, file, command, command_len, DFC_STATUS_PARAMETER_ERROR);
    }

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static void assert_change_file_settings_rejected_atomically(
    DfcVirtualPiccSession* session,
    DfcCredential* credential,
    uint8_t expected_status) {
    DfcFile* file = dfc_credential_find_file_in_app(credential, 0, 1);
    munit_assert_not_null(file);
    uint8_t file_before[sizeof(*file)];
    memcpy(file_before, file, sizeof(file_before));
#if DFC_ENABLE_SDM
    session->emulator->sdm_read_cache_valid = true;
    session->emulator->sdm_read_cache_file_number = file->number;
    session->emulator->sdm_read_cache_len = 23;
    memset(session->emulator->sdm_read_cache, 0xA5, sizeof(session->emulator->sdm_read_cache));
    uint8_t cache_before[DFC_SDM_READ_CACHE_SIZE];
    memcpy(cache_before, session->emulator->sdm_read_cache, sizeof(cache_before));
#endif
    dfc_credential_clear_dirty(credential);

    const uint8_t change[] = {0x90, 0x5F, 0x00, 0x00, 0x04, 0x01, DFC_COMM_MAC, 0xCD, 0xAB, 0x00};
    assert_status(session, change, sizeof(change), expected_status);

    munit_assert_memory_equal(sizeof(file_before), file_before, file);
    munit_assert_false(credential->dirty);
#if DFC_ENABLE_SDM
    munit_assert_true(session->emulator->sdm_read_cache_valid);
    munit_assert_uint8(session->emulator->sdm_read_cache_file_number, ==, file->number);
    munit_assert_size(session->emulator->sdm_read_cache_len, ==, 23);
    munit_assert_memory_equal(
        sizeof(cache_before), cache_before, session->emulator->sdm_read_cache);
#endif
}

static MunitResult
    test_change_file_settings_enforces_change_access(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    const struct {
        uint8_t change_access;
        int8_t authenticated_key;
        uint8_t expected_status;
    } rejected[] = {
        {DFC_ACCESS_DENY, -1, DFC_STATUS_PERMISSION_DENIED},
        {DFC_ACCESS_DENY, 0, DFC_STATUS_PERMISSION_DENIED},
        {1, -1, DFC_STATUS_AUTHENTICATION_ERR},
        {1, 0, DFC_STATUS_AUTHENTICATION_ERR},
    };
    for(size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
        DfcCredential credential;
        DfcVirtualPiccSession* session = open_rights_file_over_the_air(
            &credential, (uint8_t)(0xE0 | rejected[i].change_access), 0xEE);
        if(rejected[i].authenticated_key >= 0) {
            reselect_and_authenticate(session, (uint8_t)rejected[i].authenticated_key);
        }
        assert_change_file_settings_rejected_atomically(
            session, &credential, rejected[i].expected_status);
        dfc_virtual_picc_session_free(session);
    }

    const struct {
        uint8_t change_access;
        int8_t authenticated_key;
    } accepted[] = {
        {DFC_ACCESS_FREE, -1},
        {DFC_ACCESS_FREE, 0},
        {1, 1},
    };
    for(size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
        DfcCredential credential;
        DfcVirtualPiccSession* session = open_rights_file_over_the_air(
            &credential, (uint8_t)(0xE0 | accepted[i].change_access), 0xEE);
        if(accepted[i].authenticated_key >= 0) {
            reselect_and_authenticate(session, (uint8_t)accepted[i].authenticated_key);
        }
        dfc_credential_clear_dirty(&credential);
        const uint8_t settings[] = {DFC_COMM_MAC, 0xE0, 0x1E};
        const uint8_t plain_change[] = {
            0x90, 0x5F, 0x00, 0x00, 0x04, 0x01, DFC_COMM_MAC, 0xE0, 0x1E, 0x00};
        uint8_t change[32];
        memcpy(change, plain_change, sizeof(plain_change));
        size_t change_len = sizeof(plain_change);
        if(accepted[i].authenticated_key >= 0 && accepted[i].change_access != DFC_ACCESS_FREE) {
            change_len = build_protected_change_file_settings(
                session, 1, settings, sizeof(settings), false, change, sizeof(change));
        }
        assert_trailing_status(session, change, change_len, DFC_STATUS_OK);
        munit_assert_uint8(credential.files[0].comm_settings, ==, DFC_COMM_MAC);
        munit_assert_uint16(credential.files[0].access_rights, ==, 0x1EE0);
        munit_assert_true(credential.dirty);
        dfc_virtual_picc_session_free(session);
    }

    return MUNIT_OK;
}

static DfcVirtualPiccSession*
    open_authenticated_change_file(DfcCredential* credential, uint8_t cipher) {
    DfcVirtualPiccSession* session = open_rights_file_over_the_air(credential, 0xE0, 0xEE);
    uint8_t session_key[16];
    for(size_t i = 0; i < sizeof(session_key); i++)
        session_key[i] = (uint8_t)(0x30 + i);
    session->emulator->secure_messaging =
        dfc_secure_messaging_alloc(cipher, session_key, sizeof(session_key), NULL);
    munit_assert_not_null(session->emulator->secure_messaging);
    session->emulator->auth_cipher = cipher;
    session->emulator->auth_key_no = 0;
    munit_assert_true(dfc_emulator_native_authentication_active(session->emulator));
    return session;
}

static MunitResult
    test_change_key_settings_requires_full_protection(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    const uint8_t ciphers[] = {DFC_CMD_AUTHENTICATE_LEGACY, DFC_CMD_AUTHENTICATE_AES};
    enum ProtectedFailure {
        ProtectedFailurePlaintext,
        ProtectedFailureTruncated,
        ProtectedFailureCorrupted,
        ProtectedFailureWrongKey,
        ProtectedFailureReplay,
    };
    const enum ProtectedFailure failures[] = {
        ProtectedFailurePlaintext,
        ProtectedFailureTruncated,
        ProtectedFailureCorrupted,
        ProtectedFailureWrongKey,
        ProtectedFailureReplay,
    };

    for(size_t cipher_index = 0; cipher_index < sizeof(ciphers); cipher_index++) {
        DfcCredential credential;
        DfcVirtualPiccSession* session =
            open_authenticated_change_file(&credential, ciphers[cipher_index]);
        uint8_t command[48];
        size_t command_len =
            build_protected_change_key_settings(session, 0x0E, false, command, sizeof(command));
        assert_trailing_status(session, command, command_len, DFC_STATUS_OK);
        munit_assert_uint8(credential.apps[0].key_settings_1, ==, 0x0E);
        munit_assert_true(credential.dirty);
        dfc_virtual_picc_session_free(session);

        for(size_t failure_index = 0; failure_index < sizeof(failures) / sizeof(failures[0]);
            failure_index++) {
            if(failures[failure_index] == ProtectedFailureReplay &&
               ciphers[cipher_index] == DFC_CMD_AUTHENTICATE_LEGACY)
                continue;
            session = open_authenticated_change_file(&credential, ciphers[cipher_index]);
            uint8_t before = credential.apps[0].key_settings_1;
            bool dirty_before = credential.dirty;
            if(failures[failure_index] == ProtectedFailurePlaintext) {
                const uint8_t plain[] = {0x90, DFC_CMD_CHANGE_KEY_SETTINGS, 0, 0, 1, 0x0E, 0};
                memcpy(command, plain, sizeof(plain));
                command_len = sizeof(plain);
            } else {
                command_len = build_protected_change_key_settings(
                    session,
                    0x0E,
                    failures[failure_index] == ProtectedFailureWrongKey,
                    command,
                    sizeof(command));
                if(failures[failure_index] == ProtectedFailureTruncated) {
                    command[4]--;
                    command[command_len - 2] = 0;
                    command_len--;
                } else if(failures[failure_index] == ProtectedFailureCorrupted) {
                    command[5] ^= 0x80;
                } else if(failures[failure_index] == ProtectedFailureReplay) {
                    assert_trailing_status(session, command, command_len, DFC_STATUS_OK);
                    before = credential.apps[0].key_settings_1;
                    dirty_before = credential.dirty;
                }
            }

            assert_status(session, command, command_len, DFC_STATUS_INTEGRITY_ERROR);
            munit_assert_uint8(credential.apps[0].key_settings_1, ==, before);
            munit_assert_int(credential.dirty, ==, dirty_before);
            if(ciphers[cipher_index] != DFC_CMD_AUTHENTICATE_LEGACY)
                munit_assert_false(dfc_emulator_native_authentication_active(session->emulator));
            dfc_virtual_picc_session_free(session);
        }
    }

    DfcCredential frozen;
    DfcVirtualPiccSession* frozen_session =
        open_authenticated_change_file(&frozen, DFC_CMD_AUTHENTICATE_AES);
    frozen.apps[0].key_settings_1 = 0x07;
    uint8_t command[48];
    size_t command_len =
        build_protected_change_key_settings(frozen_session, 0x0F, false, command, sizeof(command));
    assert_status(frozen_session, command, command_len, DFC_STATUS_PERMISSION_DENIED);
    munit_assert_uint8(frozen.apps[0].key_settings_1, ==, 0x07);
    dfc_virtual_picc_session_free(frozen_session);

    return MUNIT_OK;
}

static MunitResult
    test_change_file_settings_requires_full_protection(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    const uint8_t ciphers[] = {DFC_CMD_AUTHENTICATE_LEGACY, DFC_CMD_AUTHENTICATE_AES};
    const uint8_t settings[] = {DFC_COMM_MAC, 0xE0, 0x0E};
    for(size_t cipher_index = 0; cipher_index < sizeof(ciphers); cipher_index++) {
        DfcCredential credential;
        DfcVirtualPiccSession* session =
            open_authenticated_change_file(&credential, ciphers[cipher_index]);
        uint8_t command[48];
        size_t command_len = build_protected_change_file_settings(
            session, 1, settings, sizeof(settings), false, command, sizeof(command));
        assert_trailing_status(session, command, command_len, DFC_STATUS_OK);
        munit_assert_uint8(credential.files[0].comm_settings, ==, DFC_COMM_MAC);
        munit_assert_uint16(credential.files[0].access_rights, ==, 0x0EE0);
        dfc_virtual_picc_session_free(session);
    }

    DfcCredential free_credential;
    DfcVirtualPiccSession* free_session =
        open_rights_file_over_the_air(&free_credential, 0xEE, 0xEE);
    uint8_t session_key[16] = {0};
    free_session->emulator->secure_messaging = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_AES, session_key, sizeof(session_key), NULL);
    munit_assert_not_null(free_session->emulator->secure_messaging);
    free_session->emulator->auth_cipher = DFC_CMD_AUTHENTICATE_AES;
    free_session->emulator->auth_key_no = 0;
    munit_assert_true(dfc_emulator_native_authentication_active(free_session->emulator));
    const uint8_t free_change[] = {
        0x90, DFC_CMD_CHANGE_FILE_SETTINGS, 0, 0, 4, 1, DFC_COMM_MAC, 0xEE, 0xEE, 0};
    assert_trailing_status(free_session, free_change, sizeof(free_change), DFC_STATUS_OK);
    munit_assert_uint8(free_credential.files[0].comm_settings, ==, DFC_COMM_MAC);
    dfc_virtual_picc_session_free(free_session);

    enum ProtectedFailure {
        ProtectedFailurePlaintext,
        ProtectedFailureTruncated,
        ProtectedFailureCorrupted,
        ProtectedFailureWrongKey,
    };
    const enum ProtectedFailure failures[] = {
        ProtectedFailurePlaintext,
        ProtectedFailureTruncated,
        ProtectedFailureCorrupted,
        ProtectedFailureWrongKey,
    };
    for(size_t cipher_index = 0; cipher_index < sizeof(ciphers); cipher_index++) {
        for(size_t failure_index = 0; failure_index < sizeof(failures) / sizeof(failures[0]);
            failure_index++) {
            DfcCredential credential;
            DfcVirtualPiccSession* session =
                open_authenticated_change_file(&credential, ciphers[cipher_index]);
            DfcFile before = credential.files[0];
            uint8_t command[48];
            size_t command_len;
            if(failures[failure_index] == ProtectedFailurePlaintext) {
                const uint8_t plain[] = {
                    0x90, DFC_CMD_CHANGE_FILE_SETTINGS, 0, 0, 4, 1, DFC_COMM_MAC, 0xE0, 0x0E, 0};
                memcpy(command, plain, sizeof(plain));
                command_len = sizeof(plain);
            } else {
                command_len = build_protected_change_file_settings(
                    session,
                    1,
                    settings,
                    sizeof(settings),
                    failures[failure_index] == ProtectedFailureWrongKey,
                    command,
                    sizeof(command));
                if(failures[failure_index] == ProtectedFailureTruncated) {
                    command[4]--;
                    command[command_len - 2] = 0;
                    command_len--;
                } else if(failures[failure_index] == ProtectedFailureCorrupted) {
                    command[6] ^= 0x80;
                }
            }

            assert_status(session, command, command_len, DFC_STATUS_INTEGRITY_ERROR);
            munit_assert_memory_equal(sizeof(before), &before, &credential.files[0]);
            munit_assert_false(dfc_emulator_native_authentication_active(session->emulator));
            dfc_virtual_picc_session_free(session);
        }
    }
    return MUNIT_OK;
}

#if DFC_ENABLE_SDM
static void encode_upper_hex(const uint8_t* input, size_t input_len, uint8_t* output) {
    static const uint8_t digits[] = "0123456789ABCDEF";
    for(size_t i = 0; i < input_len; i++) {
        output[i * 2] = digits[input[i] >> 4];
        output[i * 2 + 1] = digits[input[i] & 0x0F];
    }
}

static void assert_sdm_mac_covers_final_rendered_bytes(bool encrypted_range_overlaps_mac_input) {
    DfcCredential credential;
    uint8_t contents[96];
    memset(contents, '0', sizeof(contents));
    DfcVirtualPiccSession* session =
        open_file_policy(&credential, 0x0F, 0xEEEE, DFC_COMM_PLAIN, contents, sizeof(contents));
    credential.card.generation = DfcGenerationEv3;
    DfcApplication* app = &credential.apps[0];
    app->key_settings_2 = DFC_KEY_TYPE_AES | 1;
    munit_assert_true(dfc_credential_keys_resize(&credential, app, 1, DFC_AES_KEY_LENGTH));
    uint8_t* file_read_key = dfc_credential_key(&credential, app, 0);
    munit_assert_not_null(file_read_key);
    for(size_t i = 0; i < DFC_AES_KEY_LENGTH; i++)
        file_read_key[i] = (uint8_t)(0x10 + i);

    DfcFile* file = dfc_credential_find_file_in_app(&credential, 0, 1);
    munit_assert_not_null(file);
    uint8_t* file_data = dfc_file_data(&credential, file);
    munit_assert_not_null(file_data);
    for(size_t i = 32; i < 64; i++)
        file_data[i] = (uint8_t)('A' + (i % 26));
    dfc_file_sdm_flag_set(file, DfcSdmFlagEnabled, true);
    file->state.data.sdm.options = DFC_SDM_UID_MIRROR_MASK | DFC_SDM_COUNTER_MIRROR_MASK |
                                   DFC_SDM_ENCRYPTED_FILE_MASK | DFC_SDM_ASCII_ENCODING_MASK;
    file->state.data.sdm.access_rights = 0;
    dfc_file_sdm_flag_set(file, DfcSdmFlagPiccDataOffset, true);
    file->state.data.sdm.picc_data_offset = 0;
    dfc_file_sdm_flag_set(file, DfcSdmFlagEncryptedFile, true);
    file->state.data.sdm.encrypted_file_offset = 32;
    file->state.data.sdm.encrypted_file_length = 32;
    dfc_file_sdm_flag_set(file, DfcSdmFlagMacInputOffset, true);
    file->state.data.sdm.mac_input_offset = encrypted_range_overlaps_mac_input ? 32 : 64;
    dfc_file_sdm_flag_set(file, DfcSdmFlagMacOffset, true);
    file->state.data.sdm.mac_offset = 80;
    file->state.data.sdm_read_counter = 0;

    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    session->emulator->selected_app_index = 0;
    munit_assert_true(dfc_emulator_render_sdm_read(session->emulator, file));

    uint8_t session_mac_key[DFC_AES_KEY_LENGTH];
    uint8_t full_mac[DFC_AES_CMAC_LENGTH];
    uint8_t wire_mac[DFC_WIRE_MAC_LENGTH];
    uint8_t expected_ascii[DFC_WIRE_MAC_LENGTH * DFC_SDM_HEX_EXPANSION];
    munit_assert_true(dfc_sdm_derive_session_key(
        file_read_key,
        DFC_SDM_MAC_LABEL_HIGH,
        DFC_SDM_MAC_LABEL_LOW,
        credential.uid,
        credential.uid_len,
        true,
        file->state.data.sdm_read_counter,
        true,
        session_mac_key));
    munit_assert_true(aes_cmac(
        session_mac_key,
        sizeof(session_mac_key),
        session->emulator->sdm_read_cache + file->state.data.sdm.mac_input_offset,
        file->state.data.sdm.mac_offset - file->state.data.sdm.mac_input_offset,
        full_mac));
    dfc_truncate_aes_wire_mac(full_mac, wire_mac);
    encode_upper_hex(wire_mac, sizeof(wire_mac), expected_ascii);
    munit_assert_memory_equal(
        sizeof(expected_ascii),
        expected_ascii,
        session->emulator->sdm_read_cache + file->state.data.sdm.mac_offset);

    dfc_secure_wipe(session_mac_key, sizeof(session_mac_key));
    dfc_secure_wipe(full_mac, sizeof(full_mac));
    dfc_secure_wipe(wire_mac, sizeof(wire_mac));
    dfc_virtual_picc_session_free(session);
}

static MunitResult
    test_sdm_mac_covers_overlapping_encrypted_file(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    assert_sdm_mac_covers_final_rendered_bytes(true);
    return MUNIT_OK;
}

static MunitResult
    test_sdm_mac_non_overlapping_encrypted_file_control(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    assert_sdm_mac_covers_final_rendered_bytes(false);
    return MUNIT_OK;
}

static void set_sdm_settings_sentinels(DfcVirtualPiccSession* session, DfcFile* file) {
    file->comm_settings = DFC_SDM_ENABLED_MASK | DFC_COMM_PLAIN;
    file->access_rights = 0xEEEE;
    dfc_file_sdm_flag_set(file, DfcSdmFlagEnabled, true);
    file->state.data.sdm.options = DFC_SDM_UID_MIRROR_MASK | DFC_SDM_COUNTER_MIRROR_MASK |
                                   DFC_SDM_COUNTER_LIMIT_MASK | DFC_SDM_ENCRYPTED_FILE_MASK |
                                   DFC_SDM_ASCII_ENCODING_MASK;
    file->state.data.sdm.access_rights = 0xE0FE;
    dfc_file_sdm_flag_set(file, DfcSdmFlagUidOffset, true);
    file->state.data.sdm.uid_offset = 3;
    dfc_file_sdm_flag_set(file, DfcSdmFlagCounterOffset, true);
    file->state.data.sdm.counter_offset = 17;
    dfc_file_sdm_flag_set(file, DfcSdmFlagPiccDataOffset, true);
    file->state.data.sdm.picc_data_offset = 29;
    dfc_file_sdm_flag_set(file, DfcSdmFlagMacInputOffset, true);
    file->state.data.sdm.mac_input_offset = 41;
    dfc_file_sdm_flag_set(file, DfcSdmFlagMacOffset, true);
    file->state.data.sdm.mac_offset = 97;
    dfc_file_sdm_flag_set(file, DfcSdmFlagEncryptedFile, true);
    file->state.data.sdm.encrypted_file_offset = 53;
    file->state.data.sdm.encrypted_file_length = 32;
    dfc_file_sdm_flag_set(file, DfcSdmFlagCounterLimit, true);
    file->state.data.sdm.counter_limit = 0x654321;
    file->state.data.sdm_read_counter = 0x123456;

    session->emulator->sdm_read_cache_valid = true;
    session->emulator->sdm_read_cache_file_number = file->number;
    session->emulator->sdm_read_cache_len = 23;
    memset(session->emulator->sdm_read_cache, 0xA5, sizeof(session->emulator->sdm_read_cache));
    dfc_credential_clear_dirty(session->credential);
}

static void assert_rejected_change_is_atomic(
    DfcVirtualPiccSession* session,
    DfcFile* file,
    const uint8_t* native,
    size_t native_len,
    uint8_t expected_status) {
    uint8_t before[sizeof(*file)];
    uint8_t cache_before[DFC_SDM_READ_CACHE_SIZE];
    memcpy(before, file, sizeof(before));
    uint32_t counter_before = file->state.data.sdm_read_counter;
    memcpy(cache_before, session->emulator->sdm_read_cache, sizeof(cache_before));
    bool cache_valid_before = session->emulator->sdm_read_cache_valid;
    uint8_t cache_file_before = session->emulator->sdm_read_cache_file_number;
    size_t cache_len_before = session->emulator->sdm_read_cache_len;

    uint8_t apdu[64] = {0x90, DFC_CMD_CHANGE_FILE_SETTINGS, 0x00, 0x00};
    munit_assert_size(native_len, >=, 1);
    munit_assert_size(native_len - 1, <=, UINT8_MAX);
    munit_assert_size(native_len + 5, <=, sizeof(apdu));
    apdu[4] = (uint8_t)(native_len - 1);
    memcpy(apdu + 5, native + 1, native_len - 1);
    size_t apdu_len = native_len + 5;

    assert_status(session, apdu, apdu_len, expected_status);
    munit_assert_memory_equal(sizeof(before), before, file);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, counter_before);
    munit_assert_false(session->credential->dirty);
    munit_assert_int(session->emulator->sdm_read_cache_valid, ==, cache_valid_before);
    munit_assert_uint8(session->emulator->sdm_read_cache_file_number, ==, cache_file_before);
    munit_assert_size(session->emulator->sdm_read_cache_len, ==, cache_len_before);
    munit_assert_memory_equal(
        sizeof(cache_before), cache_before, session->emulator->sdm_read_cache);
}

static MunitResult
    test_change_file_settings_rejections_are_atomic(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcCredential credential;
    uint8_t contents[128] = {0};
    DfcVirtualPiccSession* session =
        open_file_policy(&credential, 0x0F, 0xEEEE, DFC_COMM_PLAIN, contents, sizeof(contents));
    credential.card.generation = DfcGenerationEv3;
    const uint8_t select[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00};
    assert_status(session, select, sizeof(select), DFC_STATUS_OK);
    DfcFile* file = dfc_credential_find_file_in_app(&credential, 0, 1);
    munit_assert_not_null(file);

    const struct {
        const uint8_t* command;
        size_t length;
        uint8_t status;
    } cases[] = {
        {(const uint8_t[]){0x5F, 0x01, 0x00, 0xCD, 0xAB, 0x00}, 6, DFC_STATUS_LENGTH_ERROR},
        {(const uint8_t[]){0x5F, 0x01, 0x40, 0xCD, 0xAB}, 5, DFC_STATUS_LENGTH_ERROR},
        {(const uint8_t[]){0x5F, 0x01, 0x40, 0xCD, 0xAB, 0x81, 0xFF, 0xEF},
         8,
         DFC_STATUS_LENGTH_ERROR},
        {(const uint8_t[]){0x5F, 0x01, 0x40, 0xCD, 0xAB, 0x41, 0xFF, 0xEF},
         8,
         DFC_STATUS_LENGTH_ERROR},
        {(const uint8_t[]){0x5F, 0x01, 0x40, 0xCD, 0xAB, 0x01, 0xFF, 0x0F},
         8,
         DFC_STATUS_LENGTH_ERROR},
        {(const uint8_t[]){0x5F, 0x01, 0x40, 0xCD, 0xAB, 0x01, 0xFF, 0xF0},
         8,
         DFC_STATUS_LENGTH_ERROR},
        {(const uint8_t[]){0x5F, 0x01, 0x40, 0xCD, 0xAB, 0x11, 0xFF, 0xF0, 0x02, 0x00, 0x00},
         11,
         DFC_STATUS_LENGTH_ERROR},
        {(const uint8_t[]){0x5F, 0x01, 0x40, 0xCD, 0xAB, 0x21, 0xFF, 0xFF},
         8,
         DFC_STATUS_LENGTH_ERROR},
        {(const uint8_t[]){0x5F, 0x01, 0x40, 0xCD, 0xAB, 0x00, 0xFF, 0xFF},
         8,
         DFC_STATUS_PARAMETER_ERROR},
        {(const uint8_t[]){0x5F, 0x01, 0x40, 0xCD, 0xAB, 0x01, 0xFF, 0xFF, 0x00},
         9,
         DFC_STATUS_PARAMETER_ERROR},
        {(const uint8_t[]){0x5F, 0x01, 0x40, 0xEE, 0xEE, 0x01, 0xFF, 0x1F, 0x00, 0x00, 0x00},
         11,
         DFC_STATUS_PARAMETER_ERROR},
        {(const uint8_t[]){
             0x5F, 0x01, 0x40, 0xEE, 0xEE, 0x01, 0xFF, 0xE1, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00},
         14,
         DFC_STATUS_PARAMETER_ERROR},
        {(const uint8_t[]){
             0x5F, 0x01, 0x40, 0xEE, 0xEE, 0x01, 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00},
         14,
         DFC_STATUS_PARAMETER_ERROR},
    };

    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        set_sdm_settings_sentinels(session, file);
        assert_rejected_change_is_atomic(
            session, file, cases[i].command, cases[i].length, cases[i].status);
    }

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_change_file_settings_validates_sdm_reserved_access(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = open_rights_file_over_the_air(&credential, 0xEE, 0xEE);
    credential.card.generation = DfcGenerationEv3;
    DfcFile* file = dfc_credential_find_file_in_app(&credential, 0, 1);
    munit_assert_not_null(file);

    for(uint8_t reserved = 0; reserved < 0x0F; reserved++) {
        uint8_t native[] = {
            0x5F, 0x01, 0x40, 0xEE, 0xEE, 0x81, (uint8_t)((reserved << 4) | 0x0F), 0xEF, 0, 0, 0};
        set_sdm_settings_sentinels(session, file);
        assert_rejected_change_is_atomic(
            session, file, native, sizeof(native) - 1, DFC_STATUS_LENGTH_ERROR);
        assert_rejected_change_is_atomic(
            session, file, native, sizeof(native), DFC_STATUS_PARAMETER_ERROR);
    }

    const uint8_t valid[] = {
        0x90, 0x5F, 0, 0, 0x0A, 0x01, 0x40, 0xEE, 0xEE, 0x81, 0xFF, 0xEF, 0, 0, 0, 0};
    set_sdm_settings_sentinels(session, file);
    assert_status(session, valid, sizeof(valid), DFC_STATUS_OK);
    munit_assert_uint16(file->state.data.sdm.access_rights, ==, 0xEFFF);
    munit_assert_true(dfc_file_sdm_flag_is_set(file, DfcSdmFlagUidOffset));
    munit_assert_true(credential.dirty);
    munit_assert_false(session->emulator->sdm_read_cache_valid);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_change_file_settings_validates_sdm_meta_mirroring(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = open_rights_file_over_the_air(&credential, 0xEE, 0xEE);
    credential.card.generation = DfcGenerationEv3;
    DfcFile* file = dfc_credential_find_file_in_app(&credential, 0, 1);
    munit_assert_not_null(file);

    const uint8_t mirrors[] = {0, 0x40, 0x80, 0xC0};
    for(size_t i = 0; i < sizeof(mirrors); i++) {
        for(uint8_t meta = 0; meta <= 0x0F; meta++) {
            uint8_t native[15] = {
                0x5F,
                1,
                0x40,
                0xEE,
                0xEE,
                (uint8_t)(mirrors[i] | 1),
                0xFF,
                (uint8_t)((meta << 4) | 0x0F)};
            size_t length = 8;
            if(meta < DFC_SDM_FREE_ACCESS) length += 3;
            if(meta == DFC_SDM_FREE_ACCESS) {
                if(mirrors[i] & DFC_SDM_UID_MIRROR_MASK) length += 3;
                if(mirrors[i] & DFC_SDM_COUNTER_MIRROR_MASK) length += 3;
            }
            set_sdm_settings_sentinels(session, file);
            assert_rejected_change_is_atomic(
                session, file, native, length - 1, DFC_STATUS_LENGTH_ERROR);
            bool valid =
                (meta < 4 || meta >= DFC_SDM_FREE_ACCESS) &&
                (mirrors[i] != 0 || meta == DFC_SDM_DENIED_ACCESS) &&
                (meta != DFC_SDM_DENIED_ACCESS || (mirrors[i] & DFC_SDM_UID_MIRROR_MASK) == 0);
            if(!valid) {
                assert_rejected_change_is_atomic(
                    session, file, native, length, DFC_STATUS_PARAMETER_ERROR);
                continue;
            }
            uint8_t apdu[20] = {0x90, 0x5F, 0, 0};
            apdu[4] = (uint8_t)(length - 1);
            memcpy(apdu + 5, native + 1, length - 1);
            assert_status(session, apdu, length + 5, DFC_STATUS_OK);
            munit_assert_uint16(
                file->state.data.sdm.access_rights, ==, (uint16_t)((meta << 12) | 0x0FFF));
            munit_assert_true(credential.dirty);
            munit_assert_uint32(file->state.data.sdm_read_counter, ==, 0);
            munit_assert_false(session->emulator->sdm_read_cache_valid);
        }
    }

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_change_file_settings_validates_sdm_counter_access(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = open_rights_file_over_the_air(&credential, 0xEE, 0xEE);
    credential.card.generation = DfcGenerationEv3;
    DfcFile* file = dfc_credential_find_file_in_app(&credential, 0, 1);
    munit_assert_not_null(file);

    const uint8_t missing_key[] = {
        0x5F, 0x01, 0x40, 0xEE, 0xEE, 0x41, 0xF9, 0xEF, 0x00, 0x00, 0x00};
    set_sdm_settings_sentinels(session, file);
    assert_rejected_change_is_atomic(
        session, file, missing_key, sizeof(missing_key), DFC_STATUS_PARAMETER_ERROR);

    set_sdm_settings_sentinels(session, file);
    assert_rejected_change_is_atomic(
        session, file, missing_key, sizeof(missing_key) - 1, DFC_STATUS_LENGTH_ERROR);

    const uint8_t counter_disabled[] = {0x5F, 0x01, 0x40, 0xEE, 0xEE, 0x01, 0xF3, 0xFF};
    set_sdm_settings_sentinels(session, file);
    assert_rejected_change_is_atomic(
        session, file, counter_disabled, sizeof(counter_disabled), DFC_STATUS_PARAMETER_ERROR);

    const uint8_t file_read_rfu[] = {
        0x5F, 0x01, 0x40, 0xEE, 0xEE, 0x01, 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    set_sdm_settings_sentinels(session, file);
    assert_rejected_change_is_atomic(
        session, file, file_read_rfu, sizeof(file_read_rfu), DFC_STATUS_PARAMETER_ERROR);

    const struct {
        uint8_t counter_access;
        uint16_t stored_rights;
    } accepted[] = {
        {0x03, 0xEFF3},
        {DFC_SDM_FREE_ACCESS, 0xEFFE},
        {DFC_SDM_DENIED_ACCESS, 0xEFFF},
    };
    for(size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
        uint8_t command[] = {
            0x90,
            0x5F,
            0x00,
            0x00,
            0x0A,
            0x01,
            0x40,
            0xEE,
            0xEE,
            0x41,
            (uint8_t)(0xF0 | accepted[i].counter_access),
            0xEF,
            0x00,
            0x00,
            0x00,
            0x00};
        set_sdm_settings_sentinels(session, file);
        assert_status(session, command, sizeof(command), DFC_STATUS_OK);
        munit_assert_uint16(file->state.data.sdm.access_rights, ==, accepted[i].stored_rights);
        munit_assert_true(dfc_file_sdm_flag_is_set(file, DfcSdmFlagCounterOffset));
        munit_assert_uint32(file->state.data.sdm.counter_offset, ==, 0);
        munit_assert_uint32(file->state.data.sdm_read_counter, ==, 0);
        munit_assert_true(credential.dirty);
        munit_assert_false(session->emulator->sdm_read_cache_valid);
    }

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_change_file_settings_success_replaces_sdm_settings(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;

    DfcCredential credential;
    uint8_t contents[128] = {0};
    DfcVirtualPiccSession* session =
        open_file_policy(&credential, 0x0F, 0xEEEE, DFC_COMM_PLAIN, contents, sizeof(contents));
    credential.card.generation = DfcGenerationEv3;
    const uint8_t select[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00};
    assert_status(session, select, sizeof(select), DFC_STATUS_OK);
    DfcFile* file = dfc_credential_find_file_in_app(&credential, 0, 1);
    munit_assert_not_null(file);
    set_sdm_settings_sentinels(session, file);

    const uint8_t change[] = {
        0x90, 0x5F, 0x00, 0x00, 0x07, 0x01, 0x40, 0xEE, 0xEE, 0x01, 0xFF, 0xFF, 0x00};
    assert_status(session, change, sizeof(change), DFC_STATUS_OK);

    munit_assert_uint8(file->comm_settings, ==, DFC_SDM_ENABLED_MASK | DFC_COMM_PLAIN);
    munit_assert_uint16(file->access_rights, ==, 0xEEEE);
    munit_assert_true(dfc_file_sdm_flag_is_set(file, DfcSdmFlagEnabled));
    munit_assert_uint8(file->state.data.sdm.options, ==, DFC_SDM_ASCII_ENCODING_MASK);
    munit_assert_uint16(file->state.data.sdm.access_rights, ==, 0xFFFF);
    munit_assert_false(dfc_file_sdm_flag_is_set(file, DfcSdmFlagUidOffset));
    munit_assert_uint32(file->state.data.sdm.uid_offset, ==, 0);
    munit_assert_false(dfc_file_sdm_flag_is_set(file, DfcSdmFlagCounterOffset));
    munit_assert_uint32(file->state.data.sdm.counter_offset, ==, 0);
    munit_assert_false(dfc_file_sdm_flag_is_set(file, DfcSdmFlagPiccDataOffset));
    munit_assert_uint32(file->state.data.sdm.picc_data_offset, ==, 0);
    munit_assert_false(dfc_file_sdm_flag_is_set(file, DfcSdmFlagMacInputOffset));
    munit_assert_uint32(file->state.data.sdm.mac_input_offset, ==, 0);
    munit_assert_false(dfc_file_sdm_flag_is_set(file, DfcSdmFlagMacOffset));
    munit_assert_uint32(file->state.data.sdm.mac_offset, ==, 0);
    munit_assert_false(dfc_file_sdm_flag_is_set(file, DfcSdmFlagEncryptedFile));
    munit_assert_uint32(file->state.data.sdm.encrypted_file_offset, ==, 0);
    munit_assert_uint32(file->state.data.sdm.encrypted_file_length, ==, 0);
    munit_assert_false(dfc_file_sdm_flag_is_set(file, DfcSdmFlagCounterLimit));
    munit_assert_uint32(file->state.data.sdm.counter_limit, ==, 0);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 0);
    munit_assert_true(credential.dirty);
    munit_assert_false(session->emulator->sdm_read_cache_valid);

    set_sdm_settings_sentinels(session, file);
    const uint8_t all_sdm_fields[] = {
        0x90, 0x5F, 0x00, 0x00, 0x1C, 0x01, 0x40, 0xEE, 0xEE, 0xF1, 0xFE, 0xE0,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x00,
    };
    assert_status(session, all_sdm_fields, sizeof(all_sdm_fields), DFC_STATUS_OK);
    munit_assert_true(dfc_file_sdm_flag_is_set(file, DfcSdmFlagUidOffset));
    munit_assert_uint32(file->state.data.sdm.uid_offset, ==, 0x030201);
    munit_assert_true(dfc_file_sdm_flag_is_set(file, DfcSdmFlagCounterOffset));
    munit_assert_uint32(file->state.data.sdm.counter_offset, ==, 0x060504);
    munit_assert_false(dfc_file_sdm_flag_is_set(file, DfcSdmFlagPiccDataOffset));
    munit_assert_true(dfc_file_sdm_flag_is_set(file, DfcSdmFlagMacInputOffset));
    munit_assert_uint32(file->state.data.sdm.mac_input_offset, ==, 0x090807);
    munit_assert_true(dfc_file_sdm_flag_is_set(file, DfcSdmFlagEncryptedFile));
    munit_assert_uint32(file->state.data.sdm.encrypted_file_offset, ==, 0x0C0B0A);
    munit_assert_uint32(file->state.data.sdm.encrypted_file_length, ==, 0x0F0E0D);
    munit_assert_true(dfc_file_sdm_flag_is_set(file, DfcSdmFlagMacOffset));
    munit_assert_uint32(file->state.data.sdm.mac_offset, ==, 0x121110);
    munit_assert_true(dfc_file_sdm_flag_is_set(file, DfcSdmFlagCounterLimit));
    munit_assert_uint32(file->state.data.sdm.counter_limit, ==, 0x151413);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 0);

    set_sdm_settings_sentinels(session, file);
    const uint8_t hidden_counter[] = {
        0x90, 0x5F, 0x00, 0x00, 0x10, 0x01, 0x40, 0xEE, 0xEE, 0xE1, 0xFF,
        0xEF, 0x01, 0x02, 0x03, 0xFF, 0xFF, 0xFF, 0x07, 0x08, 0x09, 0x00,
    };
    assert_status(session, hidden_counter, sizeof(hidden_counter), DFC_STATUS_OK);
    munit_assert_true(dfc_file_sdm_flag_is_set(file, DfcSdmFlagUidOffset));
    munit_assert_uint32(file->state.data.sdm.uid_offset, ==, 0x030201);
    munit_assert_false(dfc_file_sdm_flag_is_set(file, DfcSdmFlagCounterOffset));
    munit_assert_uint32(file->state.data.sdm.counter_offset, ==, DFC_SDM_HIDDEN_COUNTER_OFFSET);
    munit_assert_true(dfc_file_sdm_flag_is_set(file, DfcSdmFlagCounterLimit));
    munit_assert_uint32(file->state.data.sdm.counter_limit, ==, 0x090807);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 0);

    set_sdm_settings_sentinels(session, file);
    const uint8_t keyed_picc_data[] = {
        0x90,
        0x5F,
        0x00,
        0x00,
        0x0A,
        0x01,
        0x40,
        0xEE,
        0xEE,
        0x81,
        0xFF,
        0x0F,
        0x21,
        0x22,
        0x23,
        0x00,
    };
    assert_status(session, keyed_picc_data, sizeof(keyed_picc_data), DFC_STATUS_OK);
    munit_assert_false(dfc_file_sdm_flag_is_set(file, DfcSdmFlagUidOffset));
    munit_assert_false(dfc_file_sdm_flag_is_set(file, DfcSdmFlagCounterOffset));
    munit_assert_true(dfc_file_sdm_flag_is_set(file, DfcSdmFlagPiccDataOffset));
    munit_assert_uint32(file->state.data.sdm.picc_data_offset, ==, 0x232221);
    munit_assert_false(dfc_file_sdm_flag_is_set(file, DfcSdmFlagMacInputOffset));
    munit_assert_false(dfc_file_sdm_flag_is_set(file, DfcSdmFlagEncryptedFile));
    munit_assert_false(dfc_file_sdm_flag_is_set(file, DfcSdmFlagMacOffset));
    munit_assert_false(dfc_file_sdm_flag_is_set(file, DfcSdmFlagCounterLimit));
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 0);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_change_file_settings_resets_sdm_read_counter(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcCredential credential;
    uint8_t contents[128] = {0};
    DfcVirtualPiccSession* session =
        open_file_policy(&credential, 0x0F, 0xEEEE, DFC_COMM_PLAIN, contents, sizeof(contents));
    credential.card.generation = DfcGenerationEv3;
    const uint8_t select[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00};
    assert_status(session, select, sizeof(select), DFC_STATUS_OK);
    DfcFile* file = dfc_credential_find_file_in_app(&credential, 0, 1);
    munit_assert_not_null(file);
    munit_assert_false(dfc_file_sdm_flag_is_set(file, DfcSdmFlagEnabled));

    const uint8_t change[] = {
        0x90, 0x5F, 0x00, 0x00, 0x07, 0x01, 0x40, 0xEE, 0xEE, 0x01, 0xFF, 0xFF, 0x00};
    const uint32_t counters[] = {1, 0x123456, 0xFFFFFF};
    for(size_t i = 0; i < sizeof(counters) / sizeof(counters[0]); i++) {
        file->state.data.sdm_read_counter = counters[i];
        assert_status(session, change, sizeof(change), DFC_STATUS_OK);
        munit_assert_true(dfc_file_sdm_flag_is_set(file, DfcSdmFlagEnabled));
        munit_assert_uint32(file->state.data.sdm_read_counter, ==, 0);
    }

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}
#endif

static MunitResult
    test_malformed_single_record_cyclic_is_rejected(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential credential;
    DfcVirtualPiccSession* session = open_blank(0x0F, &credential);
    const uint8_t create_app[] = {
        0x90, 0xCA, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x0F, 0x01, 0x00};
    const uint8_t select_app[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00};
    const uint8_t create_file[] = {
        0x90,
        0xC0,
        0x00,
        0x00,
        0x0A,
        0x01,
        0x00,
        0xEE,
        0xEE,
        0x02,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00};
    assert_status(session, create_app, sizeof(create_app), DFC_STATUS_OK);
    assert_status(session, select_app, sizeof(select_app), DFC_STATUS_OK);
    assert_status(session, create_file, sizeof(create_file), DFC_STATUS_PARAMETER_ERROR);
    munit_assert_size(credential.num_files, ==, 0);

    // A malformed stored credential may still carry the zero-capacity edge.
    DfcFile* file = dfc_credential_create_file(&credential, 0, 1);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_CYCLIC_RECORD;
    file->comm_settings = DFC_COMM_PLAIN;
    file->access_rights = 0xEEEE;
    file->state.record.size = 2;
    file->state.record.max_records = 1;
    munit_assert_true(dfc_file_resize(&credential, file, 2));
    const uint8_t write[] = {
        0x90, 0x3B, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xA1, 0x00};
    const uint8_t commit[] = {0x90, 0xC7, 0x00, 0x00, 0x00};
    const uint8_t read_all[] = {
        0x90, 0xBB, 0x00, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    assert_status(session, write, sizeof(write), DFC_STATUS_BOUNDARY_ERROR);
    assert_status(session, commit, sizeof(commit), DFC_STATUS_NO_CHANGES);
    assert_status(session, read_all, sizeof(read_all), DFC_STATUS_BOUNDARY_ERROR);
    munit_assert_uint32(credential.files[0].state.record.count, ==, 0);
    munit_assert_false(credential.files[0].transaction_pending);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/write-honours-write-and-read-write-nibbles",
     test_write_honours_write_and_read_write_nibbles,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/read-honours-read-and-read-write-nibbles",
     test_read_honours_read_and_read_write_nibbles,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/read-write-nibble-alone-authorises-both-directions",
     test_read_write_nibble_alone_authorises_both_directions,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/change-file-settings-round-trips-logical-rights",
     test_change_file_settings_round_trips_logical_rights,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/change-key-settings-requires-full-protection",
     test_change_key_settings_requires_full_protection,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/change-file-settings-rejects-missing-files-and-keys",
     test_change_file_settings_rejects_missing_files_and_keys,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/change-file-settings-enforces-change-access",
     test_change_file_settings_enforces_change_access,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/change-file-settings-requires-full-protection",
     test_change_file_settings_requires_full_protection,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#if DFC_ENABLE_SDM
    {"/sdm-mac-covers-overlapping-encrypted-file",
     test_sdm_mac_covers_overlapping_encrypted_file,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/sdm-mac-non-overlapping-encrypted-file-control",
     test_sdm_mac_non_overlapping_encrypted_file_control,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/change-file-settings-rejections-are-atomic",
     test_change_file_settings_rejections_are_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/change-file-settings-validates-sdm-reserved-access",
     test_change_file_settings_validates_sdm_reserved_access,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/change-file-settings-validates-sdm-meta-mirroring",
     test_change_file_settings_validates_sdm_meta_mirroring,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/change-file-settings-validates-sdm-counter-access",
     test_change_file_settings_validates_sdm_counter_access,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/change-file-settings-success-replaces-sdm-settings",
     test_change_file_settings_success_replaces_sdm_settings,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/change-file-settings-resets-sdm-read-counter",
     test_change_file_settings_resets_sdm_read_counter,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
    {"/absent-key-is-factory-default",
     test_absent_key_is_factory_default,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/get-version-frames", test_get_version_frames, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/plain-write-data-borrows-apdu-payload",
     test_plain_write_data_borrows_apdu_payload,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/create-file-state-is-complete",
     test_create_file_state_is_complete,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/create-application-and-list",
     test_create_application_and_list,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/can-change-key-policy", test_can_change_key_policy, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/read-data-ev1-enciphered-wraps-payload",
     test_read_data_ev1_enciphered_wraps_payload,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/free-access-full-read-treated-as-plain",
     test_free_access_full_read_treated_as_plain,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev1-write-data-mac-requires-transmitted-cmac",
     test_ev1_write_data_mac_requires_transmitted_cmac,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/malformed-single-record-cyclic-is-rejected",
     test_malformed_single_record_cyclic_is_rejected,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {
    "/dfc_ev1_conformance",
    tests,
    NULL,
    1,
    MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
