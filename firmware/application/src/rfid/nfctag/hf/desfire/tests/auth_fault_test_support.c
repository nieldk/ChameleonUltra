#include "auth_fault_test_support.h"

#include "munit.h"

#include "dfc_crypto_internal.h"
#include "dfc_port.h"

#include <stdlib.h>
#include <string.h>

static size_t aes_block_call;
static size_t des_block_call;
static size_t aes_cbc_call;
static size_t des_cbc_call;
size_t fail_aes_block_call;
size_t fail_des_block_call;
size_t fail_aes_cbc_call;
size_t fail_des_cbc_call;
bool fail_random;
bool fail_secure_messaging_allocation;

bool dfc_crypto_aes_block_init(DfcCryptoAesBlock* block, const uint8_t* key, size_t key_len) {
    if(!block || !key || key_len != DFC_AES_KEY_LENGTH) return false;
    memset(block, 0, sizeof(*block));
    block->initialized = true;
    aes_block_call = 0;
    return true;
}

bool dfc_crypto_aes_block_encrypt(
    DfcCryptoAesBlock* block,
    const uint8_t input[DFC_AES_KEY_LENGTH],
    uint8_t output[DFC_AES_KEY_LENGTH]) {
    if(!block || !block->initialized || !input || !output) return false;
    aes_block_call++;
    if(aes_block_call == fail_aes_block_call) return false;
    for(size_t i = 0; i < DFC_AES_KEY_LENGTH; i++)
        output[i] = input[i] ^ (uint8_t)(0x31 + aes_block_call);
    return true;
}

void dfc_crypto_aes_block_clear(DfcCryptoAesBlock* block) {
    if(block) memset(block, 0, sizeof(*block));
}

bool dfc_crypto_des_block_init(
    DfcCryptoDesBlock* block,
    bool encrypt,
    const uint8_t* key,
    size_t key_len) {
    if(!block || !key || (key_len != 8 && key_len != 16 && key_len != 24)) return false;
    memset(block, 0, sizeof(*block));
    block->key_len = key_len;
    block->encrypt = encrypt;
    block->initialized = true;
    des_block_call = 0;
    return true;
}

bool dfc_crypto_des_block_crypt(
    DfcCryptoDesBlock* block,
    const uint8_t input[8],
    uint8_t output[8]) {
    if(!block || !block->initialized || !input || !output) return false;
    des_block_call++;
    if(des_block_call == fail_des_block_call) return false;
    for(size_t i = 0; i < 8; i++)
        output[i] = input[i] ^ (uint8_t)(0x51 + des_block_call);
    return true;
}

void dfc_crypto_des_block_clear(DfcCryptoDesBlock* block) {
    if(block) memset(block, 0, sizeof(*block));
}

static bool fault_cbc(
    bool encrypt,
    uint8_t* iv,
    size_t block_size,
    const uint8_t* input,
    uint8_t* output,
    size_t length,
    size_t* call,
    size_t fail_call) {
    (*call)++;
    if(*call == fail_call) {
        memset(iv, 0xDD, block_size);
        if(length) memset(output, 0xCC, length);
        return false;
    }
    uint8_t last_input[DFC_AES_KEY_LENGTH] = {0};
    if(!encrypt && length) memcpy(last_input, input + length - block_size, block_size);
    for(size_t i = 0; i < length; i++)
        output[i] = input[i] ^ 0xA7;
    if(length) memcpy(iv, encrypt ? output + length - block_size : last_input, block_size);
    dfc_secure_wipe(last_input, sizeof(last_input));
    return true;
}

bool dfc_crypto_aes_cbc(
    bool encrypt,
    const uint8_t* key,
    size_t key_len,
    uint8_t iv[DFC_AES_KEY_LENGTH],
    const uint8_t* input,
    uint8_t* output,
    size_t length) {
    (void)key;
    if(key_len != DFC_AES_KEY_LENGTH || length % DFC_AES_KEY_LENGTH != 0) return false;
    return fault_cbc(
        encrypt, iv, DFC_AES_KEY_LENGTH, input, output, length, &aes_cbc_call, fail_aes_cbc_call);
}

bool dfc_crypto_des_cbc(
    bool encrypt,
    const uint8_t* key,
    size_t key_len,
    uint8_t iv[8],
    const uint8_t* input,
    uint8_t* output,
    size_t length) {
    (void)key;
    if((key_len != 8 && key_len != 16 && key_len != 24) || length % 8 != 0) return false;
    return fault_cbc(encrypt, iv, 8, input, output, length, &des_cbc_call, fail_des_cbc_call);
}

bool dfc_crypto_des_ecb(
    bool encrypt,
    const uint8_t* key,
    size_t key_len,
    const uint8_t input[8],
    uint8_t output[8]) {
    DfcCryptoDesBlock block;
    if(!dfc_crypto_des_block_init(&block, encrypt, key, key_len)) return false;
    bool ok = dfc_crypto_des_block_crypt(&block, input, output);
    dfc_crypto_des_block_clear(&block);
    return ok;
}

bool dfc_random_fill(uint8_t* data, size_t length) {
    if(fail_random) return false;
    for(size_t i = 0; i < length; i++)
        data[i] = (uint8_t)(0x20 + i);
    return true;
}

void dfc_random_operation_begin(void) {
}

bool dfc_random_failure_is_retryable(void) {
    return false;
}

void* dfc_platform_alloc(size_t size, DfcAllocTag tag) {
    if(tag == DfcAllocSecureMessaging && fail_secure_messaging_allocation) return NULL;
    return calloc(1, size);
}

void dfc_platform_free(void* pointer) {
    free(pointer);
}

void dfc_port_notify(void* context, DfcEvent event) {
    (void)context;
    (void)event;
}

const AuthCase auth_cases[] = {
    {DFC_CMD_AUTHENTICATE_LEGACY, DFC_KEY_TYPE_DES_2K3DES, false, false},
    {DFC_CMD_AUTHENTICATE_ISO, DFC_KEY_TYPE_3K3DES, false, false},
    {DFC_CMD_AUTHENTICATE_AES, DFC_KEY_TYPE_AES, false, false},
    {DFC_CMD_AUTHENTICATE_EV2_FIRST, DFC_KEY_TYPE_AES, true, false},
    {DFC_CMD_AUTHENTICATE_EV2_NON_FIRST, DFC_KEY_TYPE_AES, true, true},
};

const size_t auth_case_count = sizeof(auth_cases) / sizeof(auth_cases[0]);

void auth_faults_clear(void) {
    aes_block_call = 0;
    des_block_call = 0;
    aes_cbc_call = 0;
    des_cbc_call = 0;
    fail_aes_block_call = 0;
    fail_des_block_call = 0;
    fail_aes_cbc_call = 0;
    fail_des_cbc_call = 0;
    fail_random = false;
    fail_secure_messaging_allocation = false;
}

void auth_fixture_open(AuthFixture* fixture, const AuthCase* auth_case) {
    memset(fixture, 0, sizeof(*fixture));
    munit_assert_true(dfc_credential_clear(&fixture->credential));
    static const uint8_t uid[] = {0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    memcpy(fixture->credential.uid, uid, sizeof(uid));
    fixture->credential.uid_len = sizeof(uid);
    fixture->credential.card.generation = auth_case->ev2 ? DfcGenerationEv3 : DfcGenerationEv1;
    const uint8_t aid[3] = {1, 2, 3};
    DfcApplication* app = dfc_credential_create_application_desfire_order(
        &fixture->credential, aid, 0x0F, auth_case->key_type | 1);
    munit_assert_not_null(app);
    app->has_auth_commands = true;
    app->auth_command = auth_case->key_type == DFC_KEY_TYPE_AES ? DFC_CMD_AUTHENTICATE_AES :
                                                                  DFC_CMD_AUTHENTICATE_ISO;
    app->auth_commands = dfc_credential_default_auth_commands(
        auth_case->key_type | 1, fixture->credential.card.generation);
    memset(dfc_credential_key(&fixture->credential, app, 0), 0x11, app->key_len);

    fixture->value_file = dfc_credential_create_file(&fixture->credential, 0, 1);
    munit_assert_not_null(fixture->value_file);
    fixture->value_file->type = DFC_FILE_TYPE_VALUE;
    fixture->value_file->state.value.current = 40;
    fixture->value_file->state.value.pending = true;
    fixture->value_file->state.value.pending_delta = 2;

    fixture->session = dfc_virtual_picc_session_alloc(&fixture->credential);
    munit_assert_not_null(fixture->session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(fixture->session, &activation),
        ==,
        DfcVirtualPiccStatusOk);
    DfcEmulator* emulator = fixture->session->emulator;
    emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    emulator->selected_app_index = 0;

    if(auth_case->ev2 && auth_case->non_first) {
        emulator->ev2_session_active = true;
        emulator->ev2_authenticated_key_no = 7;
        emulator->ev2_command_counter = 9;
        memset(emulator->ev2_session_encryption_key, 0x42, DFC_AES_KEY_LENGTH);
        memset(emulator->ev2_session_mac_key, 0x43, DFC_AES_KEY_LENGTH);
        memset(emulator->ev2_transaction_identifier, 0x44, DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH);
    } else {
        uint8_t session_key[DFC_MAX_KEY_LEN];
        size_t session_key_len = auth_case->command == DFC_CMD_AUTHENTICATE_ISO    ? 24 :
                                 auth_case->command == DFC_CMD_AUTHENTICATE_LEGACY ? 16 :
                                                                                     16;
        uint8_t session_cipher = auth_case->ev2 ? DFC_CMD_AUTHENTICATE_AES : auth_case->command;
        memset(session_key, 0x52, sizeof(session_key));
        emulator->secure_messaging =
            dfc_secure_messaging_alloc(session_cipher, session_key, session_key_len, NULL);
        munit_assert_not_null(emulator->secure_messaging);
        emulator->auth_cipher = session_cipher;
        emulator->auth_key_no = 7;
        memset(emulator->secure_messaging->iv, 0x55, sizeof(emulator->secure_messaging->iv));
        dfc_secure_wipe(session_key, sizeof(session_key));
    }
}

void auth_fixture_close(AuthFixture* fixture) {
    dfc_virtual_picc_session_free(fixture->session);
}
