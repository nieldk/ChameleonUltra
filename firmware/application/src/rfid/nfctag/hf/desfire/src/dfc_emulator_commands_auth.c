#include "dfc_emulator_commands_i.h"
#include "dfc_credential_i.h"
#include "dfc_ev2.h"
#include "dfc_ev2_crypto.h"

#if DFC_ENABLE_EMULATOR

#define TAG                          DFC_EMULATOR_TAG
#define emulator_accepts_auth_cipher dfc_emulator_accepts_auth_cipher
#define emulator_num_keys            dfc_emulator_num_keys
#define d40_receive_plain            dfc_emulator_d40_receive_plain

static void
    reject_authentication_start(DfcEmulator* emulator, DfcByteBuf* tx_buffer, uint8_t status) {
    dfc_emulator_clear_active_authentication(emulator);
    dfc_bytebuf_append_byte(tx_buffer, status);
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING
static void clear_pending_ev2_authentication(DfcEmulator* emulator) {
    emulator->ev2_authentication_pending = false;
    emulator->ev2_authentication_non_first = false;
    emulator->ev2_pending_authenticated_key_no = 0;
    dfc_secure_wipe(emulator->ev2_static_key, sizeof(emulator->ev2_static_key));
    dfc_secure_wipe(emulator->ev2_random_b, sizeof(emulator->ev2_random_b));
    dfc_secure_wipe(
        emulator->ev2_pending_transaction_identifier,
        sizeof(emulator->ev2_pending_transaction_identifier));
    dfc_secure_wipe(
        emulator->ev2_pending_card_capabilities, sizeof(emulator->ev2_pending_card_capabilities));
    dfc_secure_wipe(
        emulator->ev2_pending_reader_capabilities,
        sizeof(emulator->ev2_pending_reader_capabilities));
}

static void fail_pending_ev2_authentication(DfcEmulator* emulator) {
    clear_pending_ev2_authentication(emulator);
    dfc_emulator_clear_active_authentication(emulator);
}

bool dfc_emulator_command_authenticate_ev2_start(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    bool non_first,
    DfcByteBuf* tx_buffer) {
    clear_pending_ev2_authentication(emulator);
    if(emulator->credential->card.generation < DfcGenerationEv2) {
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_ILLEGAL_COMMAND_CODE);
        return true;
    }
    if((non_first && apdu_len != 2) || (!non_first && apdu_len < 3) ||
       (!non_first && apdu_len != (size_t)3 + apdu[2])) {
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return true;
    }
    if(non_first && !emulator->ev2_session_active) {
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return true;
    }
    uint8_t key_no = apdu[1];
#if DFC_ENABLE_SPECIAL_KEY_STATUS
    if(dfc_emulator_command_picc_disabled_special_key(emulator, key_no)) {
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return true;
    }
#endif
    if(!dfc_emulator_command_is_available_authentication_key(emulator, key_no) ||
       !emulator_accepts_auth_cipher(
           emulator,
           non_first ? DFC_CMD_AUTHENTICATE_EV2_NON_FIRST : DFC_CMD_AUTHENTICATE_EV2_FIRST)) {
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_NO_SUCH_KEY);
        return true;
    }

    uint8_t factory[DFC_MAX_KEY_LEN];
    size_t key_len = 0;
    const uint8_t* key =
        dfc_emulator_command_auth_key(emulator, key_no, factory, sizeof(factory), &key_len);
    if(key_len != DFC_AES_KEY_LENGTH) {
        dfc_secure_wipe(factory, sizeof(factory));
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return true;
    }
    uint8_t random_material[DFC_EV2_RANDOM_LENGTH + DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH];
    size_t random_material_len = non_first ? DFC_EV2_RANDOM_LENGTH : sizeof(random_material);
    if(!dfc_random_fill(random_material, random_material_len)) {
        dfc_secure_wipe(factory, sizeof(factory));
        dfc_secure_wipe(random_material, sizeof(random_material));
        if(!dfc_random_failure_is_retryable()) dfc_emulator_clear_active_authentication(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_MEMORY_ERROR);
        return false;
    }
    const uint8_t* random_b = random_material;
    const uint8_t* transaction_identifier = random_material + DFC_EV2_RANDOM_LENGTH;
    uint8_t iv[DFC_AES_KEY_LENGTH] = {0};
    uint8_t encrypted[DFC_EV2_RANDOM_LENGTH];
    if(!dfc_worker_aes_cbc_encrypt(key, key_len, iv, DFC_EV2_RANDOM_LENGTH, random_b, encrypted)) {
        dfc_secure_wipe(factory, sizeof(factory));
        dfc_secure_wipe(random_material, sizeof(random_material));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_secure_wipe(encrypted, sizeof(encrypted));
        dfc_emulator_clear_active_authentication(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_MEMORY_ERROR);
        return false;
    }

    if(non_first) {
        dfc_emulator_retire_ev2_non_first_authentication(emulator);
    } else {
        dfc_emulator_clear_active_authentication(emulator);
    }

    memcpy(emulator->ev2_static_key, key, DFC_AES_KEY_LENGTH);
    emulator->ev2_pending_authenticated_key_no = key_no;
    emulator->ev2_authentication_non_first = non_first;
    emulator->ev2_authentication_pending = true;
    memcpy(emulator->ev2_random_b, random_b, DFC_EV2_RANDOM_LENGTH);
    if(!non_first) {
        memcpy(
            emulator->ev2_pending_transaction_identifier,
            transaction_identifier,
            DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH);
#if DFC_ENABLE_APPLICATION_CAPABILITY_DATA
        DfcApplication* app = dfc_emulator_current_app(emulator);
        if(app && app->has_capability_data) {
            memcpy(
                emulator->ev2_pending_card_capabilities,
                app->capability_data + DFC_APPLICATION_CARD_CAPABILITY_OFFSET,
                DFC_EV2_CAPABILITY_LENGTH);
        } else
#endif
        {
            memset(
                emulator->ev2_pending_card_capabilities,
                0,
                sizeof(emulator->ev2_pending_card_capabilities));
            if(emulator->selected_application == DfcEmulatorSelectedApplicationPicc &&
               emulator->credential->picc_has_ev2_capabilities) {
                memcpy(
                    emulator->ev2_pending_card_capabilities,
                    emulator->credential->picc_ev2_capabilities,
                    DFC_EV2_CAPABILITY_LENGTH);
            }
        }
        memset(
            emulator->ev2_pending_reader_capabilities,
            0,
            sizeof(emulator->ev2_pending_reader_capabilities));
        size_t reader_capability_len = apdu[2];
        if(reader_capability_len > DFC_EV2_CAPABILITY_LENGTH) {
            reader_capability_len = DFC_EV2_CAPABILITY_LENGTH;
        }
        memcpy(emulator->ev2_pending_reader_capabilities, apdu + 3, reader_capability_len);
    }

    dfc_bytebuf_append_byte(tx_buffer, DFC_CMD_ADDITIONAL_FRAME);
    dfc_bytebuf_append_bytes(tx_buffer, encrypted, sizeof(encrypted));
    dfc_secure_wipe(factory, sizeof(factory));
    dfc_secure_wipe(random_material, sizeof(random_material));
    dfc_secure_wipe(iv, sizeof(iv));
    dfc_secure_wipe(encrypted, sizeof(encrypted));
    return true;
}

void dfc_emulator_command_authenticate_ev2_continuation(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer) {
    if(!emulator->ev2_authentication_pending) {
        clear_pending_ev2_authentication(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }
    if(apdu_len != 1 + DFC_EV2_AUTHENTICATION_RESPONSE_LENGTH) {
        fail_pending_ev2_authentication(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }
    uint8_t iv[DFC_AES_KEY_LENGTH] = {0};
    uint8_t clear[DFC_EV2_AUTHENTICATION_RESPONSE_LENGTH];
    if(!dfc_worker_aes_cbc_decrypt(
           emulator->ev2_static_key, DFC_AES_KEY_LENGTH, iv, sizeof(clear), apdu + 1, clear)) {
        fail_pending_ev2_authentication(emulator);
        dfc_secure_wipe(clear, sizeof(clear));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_MEMORY_ERROR);
        return;
    }
    uint8_t rotated_b[DFC_EV2_RANDOM_LENGTH];
    dfc_ev2_rotate_left(emulator->ev2_random_b, rotated_b);
    if(!dfc_ct_equal(clear + DFC_EV2_RANDOM_LENGTH, rotated_b, sizeof(rotated_b))) {
        fail_pending_ev2_authentication(emulator);
        dfc_secure_wipe(clear, sizeof(clear));
        dfc_secure_wipe(rotated_b, sizeof(rotated_b));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }
    uint8_t candidate_random_a[DFC_EV2_RANDOM_LENGTH];
    uint8_t candidate_encryption_key[DFC_AES_KEY_LENGTH];
    uint8_t candidate_mac_key[DFC_AES_KEY_LENGTH];
    memcpy(candidate_random_a, clear, sizeof(candidate_random_a));
    if(!dfc_ev2_derive_session_keys(
           emulator->ev2_static_key,
           candidate_random_a,
           emulator->ev2_random_b,
           candidate_encryption_key,
           candidate_mac_key)) {
        fail_pending_ev2_authentication(emulator);
        dfc_secure_wipe(clear, sizeof(clear));
        dfc_secure_wipe(rotated_b, sizeof(rotated_b));
        dfc_secure_wipe(candidate_random_a, sizeof(candidate_random_a));
        dfc_secure_wipe(candidate_encryption_key, sizeof(candidate_encryption_key));
        dfc_secure_wipe(candidate_mac_key, sizeof(candidate_mac_key));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_MEMORY_ERROR);
        return;
    }

    uint8_t rotated_a[DFC_EV2_RANDOM_LENGTH];
    dfc_ev2_rotate_left(candidate_random_a, rotated_a);
    uint8_t response[DFC_EV2_AUTHENTICATION_RESPONSE_LENGTH] = {0};
    size_t response_len = DFC_EV2_RANDOM_LENGTH;
    if(emulator->ev2_authentication_non_first) {
        memcpy(response, rotated_a, sizeof(rotated_a));
    } else {
        memcpy(
            response,
            emulator->ev2_pending_transaction_identifier,
            DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH);
        memcpy(response + DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH, rotated_a, sizeof(rotated_a));
        memcpy(
            response + DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH + DFC_EV2_RANDOM_LENGTH,
            emulator->ev2_pending_card_capabilities,
            DFC_EV2_CAPABILITY_LENGTH);
        memcpy(
            response + DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH + DFC_EV2_RANDOM_LENGTH +
                DFC_EV2_CAPABILITY_LENGTH,
            emulator->ev2_pending_reader_capabilities,
            DFC_EV2_CAPABILITY_LENGTH);
        response_len = sizeof(response);
    }
    memset(iv, 0, sizeof(iv));
    uint8_t encrypted[DFC_EV2_AUTHENTICATION_RESPONSE_LENGTH];
    if(!dfc_worker_aes_cbc_encrypt(
           emulator->ev2_static_key, DFC_AES_KEY_LENGTH, iv, response_len, response, encrypted)) {
        fail_pending_ev2_authentication(emulator);
        dfc_secure_wipe(candidate_random_a, sizeof(candidate_random_a));
        dfc_secure_wipe(candidate_encryption_key, sizeof(candidate_encryption_key));
        dfc_secure_wipe(candidate_mac_key, sizeof(candidate_mac_key));
        dfc_secure_wipe(clear, sizeof(clear));
        dfc_secure_wipe(rotated_b, sizeof(rotated_b));
        dfc_secure_wipe(rotated_a, sizeof(rotated_a));
        dfc_secure_wipe(response, sizeof(response));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_secure_wipe(encrypted, sizeof(encrypted));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_MEMORY_ERROR);
        return;
    }
    memcpy(
        emulator->ev2_session_encryption_key,
        candidate_encryption_key,
        sizeof(candidate_encryption_key));
    memcpy(emulator->ev2_session_mac_key, candidate_mac_key, sizeof(candidate_mac_key));
    emulator->ev2_authenticated_key_no = emulator->ev2_pending_authenticated_key_no;
    if(!emulator->ev2_authentication_non_first) {
        memcpy(
            emulator->ev2_transaction_identifier,
            emulator->ev2_pending_transaction_identifier,
            sizeof(emulator->ev2_transaction_identifier));
        memcpy(
            emulator->ev2_card_capabilities,
            emulator->ev2_pending_card_capabilities,
            sizeof(emulator->ev2_card_capabilities));
        memcpy(
            emulator->ev2_reader_capabilities,
            emulator->ev2_pending_reader_capabilities,
            sizeof(emulator->ev2_reader_capabilities));
    }
    emulator->ev2_session_active = true;
    emulator->ev2_command_counter = 0;
    dfc_emulator_commit_auth_family(emulator, DfcEmulatorAuthFamilyEv2);
    dfc_secure_wipe(clear, sizeof(clear));
    dfc_secure_wipe(rotated_b, sizeof(rotated_b));
    dfc_secure_wipe(candidate_random_a, sizeof(candidate_random_a));
    dfc_secure_wipe(candidate_encryption_key, sizeof(candidate_encryption_key));
    dfc_secure_wipe(candidate_mac_key, sizeof(candidate_mac_key));
    dfc_secure_wipe(rotated_a, sizeof(rotated_a));
    dfc_secure_wipe(response, sizeof(response));
    dfc_secure_wipe(iv, sizeof(iv));
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    dfc_bytebuf_append_bytes(tx_buffer, encrypted, response_len);
    dfc_secure_wipe(encrypted, sizeof(encrypted));
    clear_pending_ev2_authentication(emulator);
}
#endif

// A 3K3DES key answers ISO authentication with sixteen-octet challenges over
// its eight-octet block, which is what its session-key derivation reads.
static size_t auth_challenge_length(uint8_t cipher, size_t key_len) {
    if(cipher == DFC_CMD_AUTHENTICATE_AES) return 16;
    if(cipher == DFC_CMD_AUTHENTICATE_ISO && key_len == 24) return 16;
    return 8;
}

static void clear_pending_authentication(DfcEmulator* emulator) {
    emulator->awaiting_step2 = false;
    emulator->pending_auth_cipher = 0;
    emulator->pending_auth_key_no = 0;
    dfc_secure_wipe(emulator->rnd_b, sizeof(emulator->rnd_b));
    dfc_secure_wipe(emulator->enc_rnd_b, sizeof(emulator->enc_rnd_b));
}

static void fail_pending_authentication(DfcEmulator* emulator) {
    clear_pending_authentication(emulator);
    dfc_emulator_clear_active_authentication(emulator);
}

bool dfc_emulator_abort_pending_native_work(DfcEmulator* emulator) {
    if(!emulator || (!emulator->command_chain_active &&
                     !dfc_emulator_command_has_pending_additional_work(emulator))) {
        return false;
    }

    dfc_emulator_discard_command_chain(emulator);
    if(emulator->awaiting_step2) {
        fail_pending_authentication(emulator);
    } else {
        clear_pending_authentication(emulator);
    }
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    if(emulator->ev2_authentication_pending) {
        fail_pending_ev2_authentication(emulator);
    } else {
        clear_pending_ev2_authentication(emulator);
    }
#endif
#if DFC_ENABLE_DELEGATED_APPLICATIONS
    emulator->delegated_creation_pending = false;
    emulator->delegated_creation_header_length = 0;
    dfc_secure_wipe(
        emulator->delegated_creation_header, sizeof(emulator->delegated_creation_header));
#endif
    dfc_emulator_command_clear_pending_chain(emulator);
    return true;
}

void dfc_emulator_command_authenticate_step1(
    DfcEmulator* emulator,
    uint8_t cipher,
    const uint8_t* apdu,
    DfcByteBuf* tx_buffer) {
    uint8_t key_no = apdu[1];
    clear_pending_authentication(emulator);

#if DFC_ENABLE_SPECIAL_KEY_STATUS
    if(dfc_emulator_command_picc_disabled_special_key(emulator, key_no)) {
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
#endif

    if(key_no >= emulator_num_keys(emulator)) {
        DFC_LOG_W(TAG, "Authenticate: key_no %u beyond the key count", key_no);
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_NO_SUCH_KEY);
        return;
    }
    if(!emulator_accepts_auth_cipher(emulator, cipher)) {
        // A handshake the key type does not answer is an authentication failure,
        // not a missing key: the two statuses say different things and the key
        // number here is perfectly valid.
        DFC_LOG_W(TAG, "Authenticate: cipher %02X not this key type's", cipher);
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }

    uint8_t factory[DFC_MAX_KEY_LEN];
    size_t key_len = 0;
    const uint8_t* key =
        dfc_emulator_command_auth_key(emulator, key_no, factory, sizeof(factory), &key_len);
    size_t challenge_len = auth_challenge_length(cipher, key_len);
    uint8_t rnd_b[DFC_EV2_RANDOM_LENGTH];
    if(!dfc_random_fill(rnd_b, challenge_len)) {
        dfc_secure_wipe(factory, sizeof(factory));
        dfc_secure_wipe(rnd_b, sizeof(rnd_b));
        if(!dfc_random_failure_is_retryable()) dfc_emulator_clear_active_authentication(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_MEMORY_ERROR);
        return;
    }

    uint8_t iv[16];
    memset(iv, 0, sizeof(iv));
    uint8_t encrypted[16];
    bool encrypted_ok =
        cipher == DFC_CMD_AUTHENTICATE_AES ?
            dfc_worker_aes_cbc_encrypt(key, key_len, iv, challenge_len, rnd_b, encrypted) :
            dfc_worker_des_cbc_encrypt(key, key_len, iv, challenge_len, rnd_b, encrypted);
    if(!encrypted_ok) {
        dfc_secure_wipe(factory, sizeof(factory));
        dfc_secure_wipe(rnd_b, sizeof(rnd_b));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_secure_wipe(encrypted, sizeof(encrypted));
        dfc_emulator_clear_active_authentication(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_MEMORY_ERROR);
        return;
    }
    dfc_emulator_clear_active_authentication(emulator);
    memcpy(emulator->rnd_b, rnd_b, challenge_len);
    memcpy(emulator->enc_rnd_b, encrypted, challenge_len);

    emulator->pending_auth_cipher = cipher;
    emulator->pending_auth_key_no = key_no;
    emulator->awaiting_step2 = true;

    dfc_bytebuf_append_byte(tx_buffer, DFC_CMD_ADDITIONAL_FRAME);
    dfc_bytebuf_append_bytes(tx_buffer, encrypted, challenge_len);
    dfc_secure_wipe(factory, sizeof(factory));
    dfc_secure_wipe(rnd_b, sizeof(rnd_b));
    dfc_secure_wipe(iv, sizeof(iv));
    dfc_secure_wipe(encrypted, sizeof(encrypted));
}

void dfc_emulator_command_authenticate_step2(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer,
    Dfc* dfc) {
    if(!emulator->awaiting_step2) {
        DFC_LOG_W(TAG, "Authenticate step 2: no authentication pending");
        clear_pending_authentication(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }
    uint8_t cipher = emulator->pending_auth_cipher;
    size_t block_size = dfc_block_size_for_cipher(cipher);

    uint8_t factory[DFC_MAX_KEY_LEN];
    size_t key_len = 0;
    const uint8_t* key = dfc_emulator_command_auth_key(
        emulator, emulator->pending_auth_key_no, factory, sizeof(factory), &key_len);
    size_t challenge_len = auth_challenge_length(cipher, key_len);

    if(apdu_len != 1 + challenge_len * 2) {
        DFC_LOG_W(TAG, "Authenticate step 2: unexpected frame");
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        fail_pending_authentication(emulator);
        dfc_secure_wipe(factory, sizeof(factory));
        return;
    }

    // ISO and AES chain from the last block of the challenge this card sent.
    uint8_t iv[16];
    memset(iv, 0, sizeof(iv));
    if(cipher != DFC_CMD_AUTHENTICATE_LEGACY) {
        memcpy(iv, emulator->enc_rnd_b + challenge_len - block_size, block_size);
    }

    uint8_t plain[32];
    bool decrypted_ok = true;
    if(cipher == DFC_CMD_AUTHENTICATE_AES) {
        decrypted_ok =
            dfc_worker_aes_cbc_decrypt(key, key_len, iv, challenge_len * 2, apdu + 1, plain);
    } else if(cipher == DFC_CMD_AUTHENTICATE_LEGACY) {
        decrypted_ok = d40_receive_plain(key, key_len, apdu + 1, challenge_len * 2, plain);
    } else {
        decrypted_ok =
            dfc_worker_des_cbc_decrypt(key, key_len, iv, challenge_len * 2, apdu + 1, plain);
    }
    if(!decrypted_ok) {
        fail_pending_authentication(emulator);
        dfc_secure_wipe(plain, sizeof(plain));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_secure_wipe(factory, sizeof(factory));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_MEMORY_ERROR);
        return;
    }

    uint8_t* rnd_a = plain;
    uint8_t* rnd_b_rot = plain + challenge_len;

    uint8_t expected_rnd_b_rot[16];
    memcpy(expected_rnd_b_rot, emulator->rnd_b, challenge_len);
    dfc_rotate_left(expected_rnd_b_rot, challenge_len);

    if(!dfc_ct_equal(rnd_b_rot, expected_rnd_b_rot, challenge_len)) {
        DFC_LOG_W(TAG, "Authenticate step 2: RndB' mismatch");
        fail_pending_authentication(emulator);
        dfc_secure_wipe(expected_rnd_b_rot, sizeof(expected_rnd_b_rot));
        dfc_secure_wipe(plain, sizeof(plain));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_secure_wipe(factory, sizeof(factory));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }

    uint8_t rnd_a_rot[16];
    memcpy(rnd_a_rot, rnd_a, challenge_len);
    dfc_rotate_left(rnd_a_rot, challenge_len);

    if(cipher == DFC_CMD_AUTHENTICATE_LEGACY) {
        memset(iv, 0, sizeof(iv));
    }

    uint8_t encrypted[16];
    bool response_ok =
        cipher == DFC_CMD_AUTHENTICATE_AES ?
            dfc_worker_aes_cbc_encrypt(key, key_len, iv, challenge_len, rnd_a_rot, encrypted) :
            dfc_worker_des_cbc_encrypt(key, key_len, iv, challenge_len, rnd_a_rot, encrypted);
    if(!response_ok) {
        fail_pending_authentication(emulator);
        dfc_secure_wipe(encrypted, sizeof(encrypted));
        dfc_secure_wipe(rnd_a_rot, sizeof(rnd_a_rot));
        dfc_secure_wipe(expected_rnd_b_rot, sizeof(expected_rnd_b_rot));
        dfc_secure_wipe(plain, sizeof(plain));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_secure_wipe(factory, sizeof(factory));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_MEMORY_ERROR);
        return;
    }

    uint8_t session_key[DFC_MAX_KEY_LEN];
    size_t session_key_len = 0;
    dfc_derive_session_key(
        cipher, key, key_len, rnd_a, emulator->rnd_b, session_key, &session_key_len);

    DfcSecureMessaging candidate;
    if(!dfc_secure_messaging_init(&candidate, cipher, session_key, session_key_len, NULL)) {
        fail_pending_authentication(emulator);
        dfc_secure_wipe(session_key, sizeof(session_key));
        dfc_secure_wipe(encrypted, sizeof(encrypted));
        dfc_secure_wipe(rnd_a_rot, sizeof(rnd_a_rot));
        dfc_secure_wipe(expected_rnd_b_rot, sizeof(expected_rnd_b_rot));
        dfc_secure_wipe(plain, sizeof(plain));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_secure_wipe(factory, sizeof(factory));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_MEMORY_ERROR);
        return;
    }
    if(!emulator->secure_messaging) {
        emulator->secure_messaging =
            dfc_secure_messaging_alloc(cipher, session_key, session_key_len, NULL);
        if(!emulator->secure_messaging) {
            fail_pending_authentication(emulator);
            dfc_secure_wipe(&candidate, sizeof(candidate));
            dfc_secure_wipe(session_key, sizeof(session_key));
            dfc_secure_wipe(encrypted, sizeof(encrypted));
            dfc_secure_wipe(rnd_a_rot, sizeof(rnd_a_rot));
            dfc_secure_wipe(expected_rnd_b_rot, sizeof(expected_rnd_b_rot));
            dfc_secure_wipe(plain, sizeof(plain));
            dfc_secure_wipe(iv, sizeof(iv));
            dfc_secure_wipe(factory, sizeof(factory));
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_MEMORY_ERROR);
            return;
        }
    }
    *emulator->secure_messaging = candidate;
    dfc_secure_wipe(&candidate, sizeof(candidate));
    emulator->auth_cipher = cipher;
    emulator->auth_key_no = emulator->pending_auth_key_no;
    memcpy(emulator->rnd_a, rnd_a, challenge_len);
    dfc_emulator_commit_auth_family(emulator, DfcEmulatorAuthFamilyNative);
    clear_pending_authentication(emulator);

    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    dfc_bytebuf_append_bytes(tx_buffer, encrypted, challenge_len);

    if(dfc) {
        dfc_port_notify(dfc, DfcEventAuthenticated);
    }
    dfc_secure_wipe(session_key, sizeof(session_key));
    dfc_secure_wipe(encrypted, sizeof(encrypted));
    dfc_secure_wipe(rnd_a_rot, sizeof(rnd_a_rot));
    dfc_secure_wipe(expected_rnd_b_rot, sizeof(expected_rnd_b_rot));
    dfc_secure_wipe(plain, sizeof(plain));
    dfc_secure_wipe(iv, sizeof(iv));
    dfc_secure_wipe(factory, sizeof(factory));
}

#endif
