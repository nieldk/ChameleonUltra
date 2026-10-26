#include "dfc_reader_test_link.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const uint8_t AID_AES[3] = {0x00, 0x00, 0x01};
const uint8_t AID_ISO[3] = {0x00, 0x00, 0x02};
const uint8_t AID_3K[3] = {0x00, 0x00, 0x03};
const uint8_t AID_D40[3] = {0x00, 0x00, 0x04};

const uint8_t AES_KEY_0[16] =
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
const uint8_t AES_KEY_1[16] =
    {0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F};
const uint8_t TDES_KEY_0[16] =
    {0xC6, 0xEF, 0x84, 0x7C, 0xAE, 0x0A, 0x2A, 0x56, 0xC0, 0x19, 0x2A, 0xA1, 0xC4, 0xE8, 0xD9, 0xFB};
const uint8_t TDES3_KEY_0[24] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28};
const uint8_t DES_KEY_0[16] =
    {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

void add_data_file(DfcCredential* c, size_t app, uint8_t number, uint8_t comm, size_t size) {
    DfcFile* file = dfc_credential_create_file(c, app, number);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_STANDARD_DATA;
    file->comm_settings = comm;
    file->access_rights = 0x0000;
    munit_assert_true(dfc_file_resize(c, file, size));
    uint8_t* bytes = dfc_file_data(c, file);
    for(size_t i = 0; i < size; i++)
        bytes[i] = (uint8_t)(number * 0x10 + i);
}

static void add_value_file(DfcCredential* c, size_t app, uint8_t number, uint8_t comm) {
    DfcFile* file = dfc_credential_create_file(c, app, number);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_VALUE;
    file->comm_settings = comm;
    file->access_rights = 0x0000;
    file->state.value.lower_limit = 0;
    file->state.value.upper_limit = 1000;
    file->state.value.current = 100;
}

static DfcApplication*
    add_app(DfcCredential* c, const uint8_t aid[3], uint8_t ks2, uint8_t auth, const uint8_t* key0) {
    const uint8_t wire_aid[3] = {aid[2], aid[1], aid[0]};
    DfcApplication* app = dfc_credential_create_application_desfire_order(c, wire_aid, 0x0F, ks2);
    munit_assert_not_null(app);
    app->auth_command = auth;
    app->has_auth_commands = true;
    app->auth_commands = dfc_credential_default_auth_commands(ks2, c->card.generation) |
                         DFC_AUTH_COMMAND_ISO7816;
    memcpy(dfc_credential_key(c, app, 0), key0, app->key_len);
    size_t index = dfc_credential_application_index(c, app);
    add_data_file(c, index, FilePlain, DFC_COMM_PLAIN, 32);
    add_data_file(c, index, FileMac, DFC_COMM_MAC, 32);
    add_data_file(c, index, FileFull, DFC_COMM_ENCIPHERED, 32);
    add_value_file(c, index, FileValueMac, DFC_COMM_MAC);
    add_value_file(c, index, FileValueFull, DFC_COMM_ENCIPHERED);
    add_data_file(c, index, FileLong, DFC_COMM_MAC, LONG_FILE_SIZE);
    return app;
}

void link_open(Link* link, DfcGeneration generation, DfcReaderFraming framing) {
    DfcCredential* c = &link->credential;
    dfc_credential_clear(c);
    const uint8_t uid[] = {0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    memcpy(c->uid, uid, sizeof(uid));
    c->uid_len = sizeof(uid);
    c->card.generation = generation;
    DfcApplication* aes =
        add_app(c, AID_AES, DFC_KEY_TYPE_AES | 2, DFC_CMD_AUTHENTICATE_AES, AES_KEY_0);
    memcpy(dfc_credential_key(c, aes, 1), AES_KEY_1, sizeof(AES_KEY_1));
    add_app(c, AID_ISO, DFC_KEY_TYPE_DES_2K3DES | 2, DFC_CMD_AUTHENTICATE_ISO, TDES_KEY_0);
    add_app(c, AID_3K, DFC_KEY_TYPE_3K3DES | 2, DFC_CMD_AUTHENTICATE_ISO, TDES3_KEY_0);
    add_app(c, AID_D40, DFC_KEY_TYPE_DES_2K3DES | 2, DFC_CMD_AUTHENTICATE_LEGACY, DES_KEY_0);

    link->picc = dfc_virtual_picc_session_alloc(c);
    munit_assert_not_null(link->picc);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(link->picc, &activation), ==, DfcVirtualPiccStatusOk);
    dfc_reader_session_init(&link->session);
    link->framing = framing;
}

void link_close(Link* link) {
    dfc_virtual_picc_session_free(link->picc);
}

// Set DFC_READER_TRACE to print every frame the loopback carries.
static void trace(const char* direction, const uint8_t* bytes, size_t len) {
    if(!getenv("DFC_READER_TRACE")) return;
    fprintf(stderr, "%s ", direction);
    for(size_t i = 0; i < len; i++)
        fprintf(stderr, "%02X", bytes[i]);
    fprintf(stderr, "\n");
}

DfcReaderStatus link_run(Link* link, DfcReaderExchange* ex) {
    uint8_t tx[DFC_COMMAND_MAX_APDU];
    size_t tx_len = 0;
    uint8_t rx[512];
    size_t rx_len = 0;
    const uint8_t* answer = NULL;
    DfcReaderStatus st;
    while((st = dfc_reader_step(ex, answer, rx_len, tx, sizeof(tx), &tx_len)) ==
          DfcReaderPending) {
        trace(">>", tx, tx_len);
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(link->picc, tx, tx_len, rx, sizeof(rx), &rx_len),
            ==,
            DfcVirtualPiccStatusOk);
        trace("<<", rx, rx_len);
        answer = rx;
    }
    return st;
}

DfcReaderStatus
    link_send(Link* link, const DfcCommand* command, uint8_t comm, DfcReaderExchange* ex) {
    DfcReaderOptions options = {0};
    options.comm_mode = comm;
    munit_assert_int(
        dfc_reader_exchange_begin(ex, &link->session, link->framing, command, &options),
        ==,
        DfcReaderOk);
    return link_run(link, ex);
}

void select_app(Link* link, const uint8_t aid[3]) {
    DfcCommand command;
    DfcReaderExchange ex;
    munit_assert_int(dfc_command_select_application(&command, aid, NULL), ==, DfcCommandOk);
    munit_assert_int(link_send(link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderOk);
    munit_assert_false(dfc_reader_session_is_authenticated(&link->session));
}

DfcReaderStatus
    authenticate(Link* link, uint8_t cipher, uint8_t key_no, const uint8_t* key, size_t key_len) {
    uint8_t random_a[16];
    for(size_t i = 0; i < sizeof(random_a); i++)
        random_a[i] = (uint8_t)(0xA0 + i);
    DfcReaderExchange ex;
    munit_assert_int(
        dfc_reader_authenticate_begin(
            &ex,
            &link->session,
            link->framing,
            cipher,
            key_no,
            key,
            key_len,
            random_a,
            dfc_reader_challenge_length(cipher, key_len)),
        ==,
        DfcReaderOk);
    return link_run(link, &ex);
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING
DfcReaderStatus authenticate_ev2(Link* link, bool first, uint8_t key_no, const uint8_t key[16]) {
    uint8_t random_a[16];
    for(size_t i = 0; i < sizeof(random_a); i++)
        random_a[i] = (uint8_t)(0x30 + i);
    const uint8_t capabilities[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    DfcReaderExchange ex;
    munit_assert_int(
        dfc_reader_authenticate_ev2_begin(
            &ex,
            &link->session,
            link->framing,
            first,
            key_no,
            key,
            random_a,
            first ? capabilities : NULL,
            first ? sizeof(capabilities) : 0),
        ==,
        DfcReaderOk);
    return link_run(link, &ex);
}
#endif
