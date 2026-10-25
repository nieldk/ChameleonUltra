#include "dfc_emulator_i.h"

#if DFC_ENABLE_EMULATOR

DfcEmulator* dfc_emulator_alloc(DfcCredential* credential) {
    if(!credential) return NULL;

    DfcEmulator* emulator = dfc_platform_alloc(sizeof(DfcEmulator), DfcAllocEmulator);
    if(!emulator) return NULL;
    memset(emulator, 0, sizeof(DfcEmulator));

    emulator->credential = credential;
    emulator->tx_buffer = dfc_bytebuf_alloc(DFC_WORKER_MAX_BUFFER_SIZE);
    if(!emulator->tx_buffer) {
        dfc_platform_free(emulator);
        return NULL;
    }
    emulator->selected_application = DfcEmulatorSelectedApplicationPicc;

    return emulator;
}

void dfc_emulator_free(DfcEmulator* emulator) {
    DFC_ASSERT(emulator);

    dfc_emulator_discard_command_chain(emulator);
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
    dfc_emulator_discard_transaction_snapshot(emulator);
#endif
    if(emulator->secure_messaging) {
        dfc_secure_messaging_free(emulator->secure_messaging);
    }

    if(emulator->tx_buffer) {
        dfc_secure_wipe(emulator->tx_buffer, sizeof(*emulator->tx_buffer));
        dfc_bytebuf_free(emulator->tx_buffer);
    }
    dfc_secure_wipe(emulator, sizeof(*emulator));
    dfc_platform_free(emulator);
}

void dfc_emulator_discard_command_chain(DfcEmulator* emulator) {
    if(emulator->command_chain) {
        dfc_secure_wipe(emulator->command_chain, emulator->command_chain_len);
        dfc_platform_free(emulator->command_chain);
    }
    emulator->command_chain = NULL;
    emulator->command_chain_active = false;
    emulator->command_chain_len = 0;
    emulator->command_chain_expected = 0;
}

#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
static void transaction_snapshot_replace(
    DfcEmulator* emulator,
    uint8_t* replacement,
    size_t replacement_length) {
    if(emulator->transaction_snapshot_pool) {
        dfc_secure_wipe(
            emulator->transaction_snapshot_pool, emulator->transaction_snapshot_pool_capacity);
        dfc_platform_free(emulator->transaction_snapshot_pool);
    }
    emulator->transaction_snapshot_pool = replacement;
    emulator->transaction_snapshot_pool_length = replacement_length;
    emulator->transaction_snapshot_pool_capacity = replacement ? replacement_length : 0;
}

void dfc_emulator_discard_transaction_snapshot(DfcEmulator* emulator) {
    transaction_snapshot_replace(emulator, NULL, 0);
}

static void transaction_snapshot_clear_state(DfcEmulator* emulator) {
    emulator->transaction_snapshot_active = false;
    dfc_emulator_discard_transaction_snapshot(emulator);
    memset(
        emulator->transaction_record_operations,
        0,
        sizeof(emulator->transaction_record_operations));
    memset(emulator->transaction_record_numbers, 0, sizeof(emulator->transaction_record_numbers));
}

bool dfc_emulator_transaction_snapshot_insert_file(DfcEmulator* emulator, size_t file_index) {
    if(!emulator->transaction_snapshot_active) return true;
    DfcCredential* credential = emulator->credential;
    if(file_index >= credential->num_files) return false;
    DfcFile* file = &credential->files[file_index];
    size_t inserted_len = file->data_len;
    size_t inserted_offset = inserted_len ? file->data_offset :
                                            emulator->transaction_snapshot_pool_length;
    size_t old_len = emulator->transaction_snapshot_pool_length;
    if(inserted_offset > old_len || inserted_len > credential->file_pool_used ||
       old_len > credential->file_pool_used - inserted_len)
        return false;

    if(inserted_len) {
        uint8_t* grown = dfc_platform_alloc(old_len + inserted_len, DfcAllocEmulator);
        if(!grown) return false;
        memcpy(grown, emulator->transaction_snapshot_pool, inserted_offset);
        memcpy(grown + inserted_offset, credential->file_pool + inserted_offset, inserted_len);
        memcpy(
            grown + inserted_offset + inserted_len,
            emulator->transaction_snapshot_pool + inserted_offset,
            old_len - inserted_offset);
        transaction_snapshot_replace(emulator, grown, old_len + inserted_len);
    }

    if(file_index + 1 < DFC_MAX_FILES) {
        size_t count = DFC_MAX_FILES - file_index - 1;
        memmove(
            &emulator->transaction_snapshot_record_counts[file_index + 1],
            &emulator->transaction_snapshot_record_counts[file_index],
            count * sizeof(emulator->transaction_snapshot_record_counts[0]));
        memmove(
            &emulator->transaction_record_operations[file_index + 1],
            &emulator->transaction_record_operations[file_index],
            count * sizeof(emulator->transaction_record_operations[0]));
        memmove(
            &emulator->transaction_record_numbers[file_index + 1],
            &emulator->transaction_record_numbers[file_index],
            count * sizeof(emulator->transaction_record_numbers[0]));
    }
    emulator->transaction_snapshot_record_counts[file_index] =
        (file->type == DFC_FILE_TYPE_LINEAR_RECORD || file->type == DFC_FILE_TYPE_CYCLIC_RECORD) ?
            file->record_count :
            0;
    emulator->transaction_record_operations[file_index] = 0;
    emulator->transaction_record_numbers[file_index] = 0;
    return true;
}

void dfc_emulator_transaction_snapshot_delete_file(DfcEmulator* emulator, size_t file_index) {
    if(!emulator->transaction_snapshot_active) return;
    DfcCredential* credential = emulator->credential;
    if(file_index >= credential->num_files) return;
    DfcFile* file = &credential->files[file_index];
    size_t removed_len = file->data_len;
    size_t removed_offset = file->data_offset;
    size_t old_len = emulator->transaction_snapshot_pool_length;
    if(removed_len && removed_offset <= old_len && removed_len <= old_len - removed_offset) {
        memmove(
            emulator->transaction_snapshot_pool + removed_offset,
            emulator->transaction_snapshot_pool + removed_offset + removed_len,
            old_len - removed_offset - removed_len);
        emulator->transaction_snapshot_pool_length -= removed_len;
        dfc_secure_wipe(
            emulator->transaction_snapshot_pool + emulator->transaction_snapshot_pool_length,
            removed_len);
    }
    if(file_index + 1 < DFC_MAX_FILES) {
        size_t count = DFC_MAX_FILES - file_index - 1;
        memmove(
            &emulator->transaction_snapshot_record_counts[file_index],
            &emulator->transaction_snapshot_record_counts[file_index + 1],
            count * sizeof(emulator->transaction_snapshot_record_counts[0]));
        memmove(
            &emulator->transaction_record_operations[file_index],
            &emulator->transaction_record_operations[file_index + 1],
            count * sizeof(emulator->transaction_record_operations[0]));
        memmove(
            &emulator->transaction_record_numbers[file_index],
            &emulator->transaction_record_numbers[file_index + 1],
            count * sizeof(emulator->transaction_record_numbers[0]));
    }
    emulator->transaction_snapshot_record_counts[DFC_MAX_FILES - 1] = 0;
    emulator->transaction_record_operations[DFC_MAX_FILES - 1] = 0;
    emulator->transaction_record_numbers[DFC_MAX_FILES - 1] = 0;
}

bool dfc_emulator_transaction_snapshot_mirror_write(
    DfcEmulator* emulator,
    size_t file_index,
    size_t offset,
    const uint8_t* data,
    size_t length) {
    if(!emulator->transaction_snapshot_active) return true;
    DfcCredential* credential = emulator->credential;
    if(file_index >= credential->num_files || (length && !data)) return false;
    DfcFile* file = &credential->files[file_index];
    if(file->app_index != emulator->transaction_snapshot_app_index || offset > file->data_len ||
       length > file->data_len - offset ||
       file->data_offset > emulator->transaction_snapshot_pool_length ||
       offset > emulator->transaction_snapshot_pool_length - file->data_offset ||
       length > emulator->transaction_snapshot_pool_length - file->data_offset - offset) {
        return false;
    }
    if(length) {
        memcpy(emulator->transaction_snapshot_pool + file->data_offset + offset, data, length);
    }
    emulator->transaction_snapshot_dirty = true;
    return true;
}

bool dfc_emulator_abort_transaction_snapshot(DfcEmulator* emulator) {
    if(!emulator->transaction_snapshot_active) return false;

    // The logical image must fit its allocation and describe the live pool.
    // Reject inconsistent internal state before either buffer is touched.
    if(emulator->transaction_snapshot_pool_length > emulator->transaction_snapshot_pool_capacity ||
       emulator->transaction_snapshot_pool_length != emulator->credential->file_pool_used) {
        transaction_snapshot_clear_state(emulator);
        return true;
    }

    size_t app_index = emulator->transaction_snapshot_app_index;
    memcpy(
        emulator->credential->file_pool,
        emulator->transaction_snapshot_pool,
        emulator->transaction_snapshot_pool_length);
    for(size_t index = 0; index < emulator->credential->num_files; index++) {
        DfcFile* file = &emulator->credential->files[index];
        if(file->app_index != app_index) continue;
        if(file->type == DFC_FILE_TYPE_LINEAR_RECORD ||
           file->type == DFC_FILE_TYPE_CYCLIC_RECORD) {
            file->record_count = emulator->transaction_snapshot_record_counts[index];
        }
        file->transaction_pending = false;
    }
    emulator->credential->dirty = emulator->transaction_snapshot_dirty;
    transaction_snapshot_clear_state(emulator);
    return true;
}
#endif

DfcApplication* dfc_emulator_current_app(DfcEmulator* emulator) {
    if(emulator->selected_application != DfcEmulatorSelectedApplicationApp) return NULL;
    return dfc_credential_get_application(emulator->credential, emulator->selected_app_index);
}

bool dfc_emulator_accepts_auth_cipher(DfcEmulator* emulator, uint8_t cipher) {
    DfcApplication* app = dfc_emulator_current_app(emulator);
    uint8_t commands = app ? dfc_credential_app_auth_commands(emulator->credential, app) :
                             dfc_credential_picc_auth_commands(emulator->credential);
    uint8_t disabled =
        emulator->credential->picc_has_sm_disable ? emulator->credential->picc_sm_disable : 0;
    if(app && app->has_sm_disable) disabled |= app->sm_disable;
    uint8_t bit;
    switch(cipher) {
    case DFC_CMD_AUTHENTICATE_LEGACY:
        bit = DFC_AUTH_COMMAND_D40;
        if(disabled & DFC_SM_DISABLE_D40) return false;
        break;
    case DFC_CMD_AUTHENTICATE_ISO:
        bit = DFC_AUTH_COMMAND_ISO_NATIVE;
        if(disabled & DFC_SM_DISABLE_EV1) return false;
        break;
    case DFC_CMD_AUTHENTICATE_AES:
        bit = DFC_AUTH_COMMAND_AES;
        if(disabled & DFC_SM_DISABLE_EV1) return false;
        break;
    case DFC_CMD_AUTHENTICATE_EV2_FIRST:
        bit = DFC_AUTH_COMMAND_EV2_FIRST;
        break;
    case DFC_CMD_AUTHENTICATE_EV2_NON_FIRST:
        bit = DFC_AUTH_COMMAND_EV2_NON_FIRST;
        break;
    default:
        return false;
    }
    return (commands & bit) != 0;
}

static void clear_native_authentication(DfcEmulator* emulator) {
    if(emulator->secure_messaging) {
        dfc_secure_wipe(emulator->secure_messaging, sizeof(*emulator->secure_messaging));
    }
    emulator->auth_cipher = 0;
    emulator->auth_key_no = 0;
    dfc_secure_wipe(emulator->rnd_a, sizeof(emulator->rnd_a));
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING
static void clear_ev2_authentication(DfcEmulator* emulator, bool keep_transaction_context) {
    emulator->ev2_session_active = false;
    emulator->ev2_authenticated_key_no = 0;
    if(!keep_transaction_context) emulator->ev2_command_counter = 0;
    dfc_secure_wipe(
        emulator->ev2_session_encryption_key, sizeof(emulator->ev2_session_encryption_key));
    dfc_secure_wipe(emulator->ev2_session_mac_key, sizeof(emulator->ev2_session_mac_key));
    if(!keep_transaction_context) {
        dfc_secure_wipe(
            emulator->ev2_transaction_identifier, sizeof(emulator->ev2_transaction_identifier));
        dfc_secure_wipe(emulator->ev2_card_capabilities, sizeof(emulator->ev2_card_capabilities));
        dfc_secure_wipe(
            emulator->ev2_reader_capabilities, sizeof(emulator->ev2_reader_capabilities));
    }
}
#endif

void dfc_emulator_clear_active_authentication(DfcEmulator* emulator) {
    clear_native_authentication(emulator);
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    clear_ev2_authentication(emulator, false);
#endif
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING
void dfc_emulator_retire_ev2_non_first_authentication(DfcEmulator* emulator) {
    clear_native_authentication(emulator);
    clear_ev2_authentication(emulator, true);
}
#endif

void dfc_emulator_commit_auth_family(DfcEmulator* emulator, DfcEmulatorAuthFamily family) {
    if(family == DfcEmulatorAuthFamilyEv2) {
        clear_native_authentication(emulator);
        return;
    }

#if DFC_ENABLE_EV2_SECURE_MESSAGING
    clear_ev2_authentication(emulator, false);
#else
    DFC_UNUSED(emulator);
#endif
}

size_t dfc_emulator_key_len(DfcEmulator* emulator) {
    DfcApplication* app = dfc_emulator_current_app(emulator);
#if DFC_ENABLE_KEY_SETS
    if(app && app->num_key_sets >= DFC_KEY_SET_MINIMUM_COUNT) {
        return dfc_key_set_type_length(app->key_set_types[0]);
    }
#endif
    return app ? app->key_len : emulator->credential->picc_key_len;
}

size_t dfc_emulator_num_keys(DfcEmulator* emulator) {
    DfcApplication* app = dfc_emulator_current_app(emulator);
    // Every object has a master key whether or not the credential records one:
    // an absent entry is the factory default, not an absent slot.
    if(!app) return 1;
    return app->num_keys ? app->num_keys : 1;
}

uint8_t* dfc_emulator_key(DfcEmulator* emulator, uint8_t key_no) {
    DfcApplication* app = dfc_emulator_current_app(emulator);
    // dfc_emulator_num_keys reports 1 at PICC level, so only slot 0 is reachable.
    return dfc_credential_key(emulator->credential, app, app ? key_no : 0);
}

uint8_t* dfc_emulator_key_version(DfcEmulator* emulator, uint8_t key_no) {
    DfcApplication* app = dfc_emulator_current_app(emulator);
    return app ? &app->key_versions[key_no] : &emulator->credential->picc_key_versions[0];
}

bool dfc_emulator_abort_transaction(DfcEmulator* emulator) {
    bool changed = false;
#if DFC_ENABLE_TRANSACTION_MAC
    if(emulator->transaction_input_len > 0) {
        size_t used =
            DFC_MIN(emulator->transaction_input_len, sizeof(emulator->transaction_input));
        dfc_secure_wipe(emulator->transaction_input, used);
        emulator->transaction_input_len = 0;
        changed = true;
    }
#endif
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
    changed = dfc_emulator_abort_transaction_snapshot(emulator) || changed;
#endif
    for(size_t i = 0; i < emulator->credential->num_files; i++) {
        DfcFile* file = &emulator->credential->files[i];
        if(file->app_index != emulator->selected_app_index || file->type != DFC_FILE_TYPE_VALUE ||
           !file->value_pending) {
            continue;
        }
        file->value_pending = false;
        file->value_pending_delta = 0;
        file->value_pending_value = 0;
        file->value_pending_absolute = false;
        file->limited_credit_pending = 0;
        changed = true;
    }
    return changed;
}

void dfc_emulator_publish_transaction(DfcEmulator* emulator) {
    for(size_t i = 0; i < emulator->credential->num_files; i++) {
        DfcFile* file = &emulator->credential->files[i];
        if(file->app_index != emulator->selected_app_index) continue;
        if(file->type == DFC_FILE_TYPE_VALUE && file->value_pending) {
            file->value = file->value_pending_absolute ?
                              file->value_pending_value :
                              (int32_t)((int64_t)file->value + file->value_pending_delta);
            if(file->limited_credit_pending == DFC_LIMITED_CREDIT_TRANSACTION_CONSUMED) {
                file->limited_credit_value = 0;
            } else if(file->limited_credit_pending > 0) {
                file->limited_credit_value = file->limited_credit_pending;
            }
            file->value_pending = false;
            file->value_pending_delta = 0;
            file->value_pending_value = 0;
            file->value_pending_absolute = false;
            file->limited_credit_pending = 0;
        }
        file->transaction_pending = false;
    }
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
    if(emulator->transaction_snapshot_active &&
       emulator->transaction_snapshot_app_index == emulator->selected_app_index) {
        emulator->transaction_snapshot_active = false;
        dfc_emulator_discard_transaction_snapshot(emulator);
        memset(
            emulator->transaction_record_operations,
            0,
            sizeof(emulator->transaction_record_operations));
        memset(
            emulator->transaction_record_numbers, 0, sizeof(emulator->transaction_record_numbers));
    }
#endif
#if DFC_ENABLE_TRANSACTION_MAC
    dfc_secure_wipe(emulator->transaction_input, sizeof(emulator->transaction_input));
    emulator->transaction_input_len = 0;
#endif
    dfc_credential_mark_dirty(emulator->credential);
}

void dfc_emulator_clear_iso_authentication(DfcEmulator* emulator) {
#if DFC_ENABLE_ISO7816_AUTH
    emulator->iso_auth_phase = 0;
    emulator->iso_auth_challenge_len = 0;
    emulator->iso_auth_key_no = 0;
    emulator->iso_auth_cipher = 0;
    emulator->iso_auth_reference = 0;
    emulator->iso_auth_key_len = 0;
    dfc_secure_wipe(emulator->iso_auth_card_first, sizeof(emulator->iso_auth_card_first));
    dfc_secure_wipe(emulator->iso_auth_host_first, sizeof(emulator->iso_auth_host_first));
    dfc_secure_wipe(emulator->iso_auth_external_iv, sizeof(emulator->iso_auth_external_iv));
    dfc_secure_wipe(emulator->iso_auth_key, sizeof(emulator->iso_auth_key));
#else
    (void)emulator;
#endif
}

void dfc_emulator_retire_authentication(DfcEmulator* emulator) {
    size_t pending_chain_len =
        DFC_MIN(emulator->pending_chain_len, sizeof(emulator->pending_chain));
    size_t pending_chunk_count = DFC_MIN(
        (size_t)emulator->pending_chain_chunk_count,
        sizeof(emulator->pending_chain_chunks) / sizeof(emulator->pending_chain_chunks[0]));
    emulator->awaiting_step2 = false;
    dfc_emulator_clear_iso_authentication(emulator);
    clear_native_authentication(emulator);
    emulator->pending_auth_cipher = 0;
    emulator->pending_auth_key_no = 0;
    dfc_secure_wipe(emulator->rnd_b, sizeof(emulator->rnd_b));
    dfc_secure_wipe(emulator->enc_rnd_b, sizeof(emulator->enc_rnd_b));
    emulator->get_version_frame = 0;
    emulator->pending_chain_len = 0;
    emulator->pending_chain_offset = 0;
    emulator->pending_chain_frame = 0;
    emulator->pending_chain_last = 0;
    emulator->pending_chain_chunk_count = 0;
    emulator->pending_chain_chunk_index = 0;
    if(pending_chain_len > 0) dfc_secure_wipe(emulator->pending_chain, pending_chain_len);
    if(pending_chunk_count > 0) {
        dfc_secure_wipe(
            emulator->pending_chain_chunks,
            pending_chunk_count * sizeof(emulator->pending_chain_chunks[0]));
    }
    dfc_emulator_discard_command_chain(emulator);
    emulator->df_names_pending = false;
    emulator->df_names_next = 0;
#if DFC_ENABLE_DELEGATED_APPLICATIONS
    emulator->delegated_creation_pending = false;
    emulator->delegated_creation_header_length = 0;
    dfc_secure_wipe(
        emulator->delegated_creation_header, sizeof(emulator->delegated_creation_header));
#endif
#if DFC_ENABLE_PROXIMITY_CHECK
    emulator->proximity_active = false;
    emulator->proximity_verified = false;
    emulator->proximity_offset = 0;
    emulator->proximity_published_len = 0;
    emulator->proximity_transcript_len = 0;
    dfc_secure_wipe(emulator->proximity_random, sizeof(emulator->proximity_random));
    dfc_secure_wipe(emulator->proximity_published, sizeof(emulator->proximity_published));
    dfc_secure_wipe(emulator->proximity_transcript, sizeof(emulator->proximity_transcript));
#endif
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    emulator->ev2_response_plain = false;
    emulator->ev2_authentication_pending = false;
    emulator->ev2_authentication_non_first = false;
    emulator->ev2_session_active = false;
    emulator->ev2_authenticated_key_no = 0;
    emulator->ev2_pending_authenticated_key_no = 0;
    emulator->ev2_command_counter = 0;
    dfc_secure_wipe(emulator->ev2_static_key, sizeof(emulator->ev2_static_key));
    dfc_secure_wipe(emulator->ev2_random_b, sizeof(emulator->ev2_random_b));
    dfc_secure_wipe(
        emulator->ev2_transaction_identifier, sizeof(emulator->ev2_transaction_identifier));
    dfc_secure_wipe(
        emulator->ev2_pending_transaction_identifier,
        sizeof(emulator->ev2_pending_transaction_identifier));
    dfc_secure_wipe(emulator->ev2_card_capabilities, sizeof(emulator->ev2_card_capabilities));
    dfc_secure_wipe(emulator->ev2_reader_capabilities, sizeof(emulator->ev2_reader_capabilities));
    dfc_secure_wipe(
        emulator->ev2_pending_card_capabilities, sizeof(emulator->ev2_pending_card_capabilities));
    dfc_secure_wipe(
        emulator->ev2_pending_reader_capabilities,
        sizeof(emulator->ev2_pending_reader_capabilities));
    dfc_secure_wipe(
        emulator->ev2_session_encryption_key, sizeof(emulator->ev2_session_encryption_key));
    dfc_secure_wipe(emulator->ev2_session_mac_key, sizeof(emulator->ev2_session_mac_key));
#endif
#if DFC_ENABLE_SDM
    emulator->sdm_read_cache_valid = false;
    emulator->sdm_read_cache_file_number = 0;
    emulator->sdm_read_cache_len = 0;
    dfc_secure_wipe(emulator->sdm_read_cache, sizeof(emulator->sdm_read_cache));
#endif
}

void dfc_emulator_reset_session(DfcEmulator* emulator) {
    dfc_emulator_abort_transaction(emulator);
    dfc_emulator_retire_authentication(emulator);
}

void dfc_emulator_select_application(
    DfcEmulator* emulator,
    DfcEmulatorSelectedApplication selection,
    size_t app_index) {
    dfc_emulator_reset_session(emulator);
    emulator->selected_application = selection;
    emulator->selected_app_index = selection == DfcEmulatorSelectedApplicationApp ? app_index : 0;
#if DFC_ENABLE_TRANSACTION_TIMER
    DfcApplication* app = selection == DfcEmulatorSelectedApplicationApp ?
                              dfc_credential_get_application(emulator->credential, app_index) :
                              NULL;
    emulator->transaction_timer_enabled =
        app && app->has_capability_data &&
        app->capability_data[DFC_TRANSACTION_TIMER_CAPABILITY_OFFSET] ==
            DFC_TRANSACTION_TIMER_SHORT;
    emulator->transaction_timer_elapsed_milliseconds = 0;
#endif
}

void dfc_emulator_reset_activation(DfcEmulator* emulator) {
    DFC_ASSERT(emulator);

    dfc_emulator_abort_transaction(emulator);
    DfcCredential* credential = emulator->credential;
    DfcByteBuf* tx_buffer = emulator->tx_buffer;
    DfcSecureMessaging* secure_messaging = emulator->secure_messaging;
    if(secure_messaging) dfc_secure_wipe(secure_messaging, sizeof(*secure_messaging));
    dfc_emulator_discard_command_chain(emulator);
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
    dfc_emulator_discard_transaction_snapshot(emulator);
#endif

    if(tx_buffer) dfc_secure_wipe(tx_buffer, sizeof(*tx_buffer));
    memset(emulator, 0, sizeof(*emulator));
    emulator->credential = credential;
    emulator->tx_buffer = tx_buffer;
    emulator->secure_messaging = secure_messaging;
    emulator->selected_application = DfcEmulatorSelectedApplicationPicc;
    if(tx_buffer) {
        dfc_bytebuf_reset(tx_buffer);
    }
}

void dfc_emulator_advance_time(DfcEmulator* emulator, uint32_t elapsed_milliseconds) {
#if DFC_ENABLE_TRANSACTION_TIMER
    if(!emulator || !emulator->transaction_timer_enabled) return;
    if(UINT32_MAX - emulator->transaction_timer_elapsed_milliseconds < elapsed_milliseconds)
        emulator->transaction_timer_elapsed_milliseconds = UINT32_MAX;
    else
        emulator->transaction_timer_elapsed_milliseconds += elapsed_milliseconds;
    if(emulator->transaction_timer_elapsed_milliseconds >=
       DFC_TRANSACTION_TIMER_EXPIRY_MILLISECONDS) {
        dfc_emulator_reset_activation(emulator);
    }
#else
    DFC_UNUSED(emulator);
    DFC_UNUSED(elapsed_milliseconds);
#endif
}

#endif // DFC_ENABLE_EMULATOR
