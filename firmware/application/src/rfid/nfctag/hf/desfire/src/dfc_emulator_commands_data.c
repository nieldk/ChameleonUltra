#include "dfc_emulator_commands_i.h"
#include "dfc_credential_i.h"
#include "dfc_ev2.h"
#include "dfc_ev2_crypto.h"

#if DFC_ENABLE_EMULATOR

#define read_uint24_le dfc_emulator_read_uint24_le

#if DFC_ENABLE_SDM
static void sdm_write_ascii_hex(uint8_t* output, const uint8_t* input, size_t input_len) {
    static const uint8_t alphabet[] = "0123456789ABCDEF";
    for(size_t i = 0; i < input_len; i++) {
        output[i * DFC_SDM_HEX_EXPANSION] = alphabet[input[i] >> 4];
        output[(i * DFC_SDM_HEX_EXPANSION) + 1] = alphabet[input[i] & 0x0F];
    }
}

static bool sdm_derive_key(
    const uint8_t* static_key,
    uint8_t label_high,
    uint8_t label_low,
    const DfcCredential* credential,
    const DfcFile* file,
    uint32_t counter,
    uint8_t output[DFC_AES_KEY_LENGTH]) {
    uint8_t vector[DFC_AES_KEY_LENGTH * 2] = {0};
    size_t length = 0;
    const uint8_t prefix[] = {
        label_high,
        label_low,
        DFC_DERIVATION_COUNTER_HIGH,
        DFC_DERIVATION_COUNTER_LOW,
        DFC_DERIVED_AES_KEY_LENGTH_HIGH,
        DFC_DERIVED_AES_KEY_LENGTH_LOW,
    };
    memcpy(vector, prefix, sizeof(prefix));
    length += sizeof(prefix);
    if((file->sdm_options & DFC_SDM_UID_MIRROR_MASK) != 0) {
        memcpy(vector + length, credential->uid, credential->uid_len);
        length += credential->uid_len;
    }
    uint8_t meta_read = (uint8_t)(file->sdm_access_rights >> DFC_SDM_META_READ_SHIFT);
    bool includes_counter = (file->sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) != 0 &&
                            (meta_read != DFC_SDM_FREE_ACCESS || file->sdm_has_counter_offset);
    if(includes_counter) {
        vector[length++] = (uint8_t)counter;
        vector[length++] = (uint8_t)(counter >> 8);
        vector[length++] = (uint8_t)(counter >> 16);
    }
    length = ((length + DFC_AES_KEY_LENGTH - 1) / DFC_AES_KEY_LENGTH) * DFC_AES_KEY_LENGTH;
    bool success = aes_cmac((uint8_t*)static_key, DFC_AES_KEY_LENGTH, vector, length, output);
    dfc_secure_wipe(vector, sizeof(vector));
    if(!success && output) dfc_secure_wipe(output, DFC_AES_KEY_LENGTH);
    return success;
}

static bool sdm_range_fits(const DfcFile* file, uint32_t offset, size_t length) {
    return offset <= file->data_len && length <= file->data_len - offset;
}

static DfcSdmRenderStatus render_sdm_read_in_place(DfcEmulator* emulator, DfcFile* file) {
    if(emulator->sdm_read_cache_valid && emulator->sdm_read_cache_file_number == file->number)
        return DfcSdmRenderOk;
    DfcSdmRenderStatus status = DfcSdmRenderFailed;
    size_t pending_scratch_len = 0;
    uint8_t picc_clear[DFC_SDM_PICC_DATA_BLOCK_LENGTH * 2] = {0};
    uint8_t picc_encrypted[DFC_SDM_PICC_DATA_BLOCK_LENGTH * 2] = {0};
    uint8_t session_mac_key[DFC_AES_KEY_LENGTH] = {0};
    uint8_t full_mac[DFC_AES_CMAC_LENGTH] = {0};
    uint8_t wire_mac[DFC_WIRE_MAC_LENGTH] = {0};
    uint8_t session_encryption_key[DFC_AES_KEY_LENGTH] = {0};
    uint8_t counter_block[DFC_AES_KEY_LENGTH] = {0};
    uint8_t picc_iv[DFC_AES_KEY_LENGTH] = {0};
    uint8_t zero_iv[DFC_AES_KEY_LENGTH] = {0};
    uint8_t file_iv[DFC_AES_KEY_LENGTH] = {0};

    if(file->sdm_read_counter >= 0xFFFFFFu) goto cleanup;
    if(file->data_len > sizeof(emulator->sdm_read_cache)) goto cleanup;
    size_t picc_clear_len = emulator->credential->uid_len == DFC_DESFIRE_UID_MAX_LENGTH ?
                                DFC_SDM_PICC_DATA_BLOCK_LENGTH * 2 :
                                DFC_SDM_PICC_DATA_BLOCK_LENGTH;
    if(file->sdm_has_uid_offset &&
       !sdm_range_fits(
           file, file->sdm_uid_offset, emulator->credential->uid_len * DFC_SDM_HEX_EXPANSION))
        goto cleanup;
    if(file->sdm_has_counter_offset && !sdm_range_fits(file, file->sdm_counter_offset, 6))
        goto cleanup;
    if(file->sdm_has_picc_data_offset &&
       !sdm_range_fits(file, file->sdm_picc_data_offset, picc_clear_len * DFC_SDM_HEX_EXPANSION))
        goto cleanup;
    if(file->sdm_has_mac_input_offset && file->sdm_has_mac_offset &&
       (file->sdm_mac_offset < file->sdm_mac_input_offset ||
        !sdm_range_fits(file, file->sdm_mac_offset, DFC_WIRE_MAC_LENGTH * DFC_SDM_HEX_EXPANSION)))
        goto cleanup;
    if(file->sdm_has_encrypted_file_offset &&
       (file->sdm_encrypted_file_length == 0 ||
        file->sdm_encrypted_file_length % (DFC_AES_KEY_LENGTH * DFC_SDM_HEX_EXPANSION) != 0 ||
        !sdm_range_fits(file, file->sdm_encrypted_file_offset, file->sdm_encrypted_file_length) ||
        file->sdm_encrypted_file_length / DFC_SDM_HEX_EXPANSION > DFC_SDM_READ_CACHE_SIZE))
        goto cleanup;
    const uint8_t* source = dfc_file_data_const(emulator->credential, file);
    if(!source) goto cleanup;
    size_t random_padding_len = 0;
    if(file->sdm_has_picc_data_offset) {
        size_t clear_len = picc_clear_len;
        random_padding_len = clear_len - 1 - emulator->credential->uid_len;
        if((file->sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) != 0) random_padding_len -= 3;
        size_t random_offset =
            emulator->credential->uid_len == DFC_DESFIRE_UID_MAX_LENGTH &&
                    (file->sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) == 0 ?
                1 :
                1 + emulator->credential->uid_len +
                    ((file->sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) != 0 ? 3 : 0);
        if(!dfc_random_fill(picc_clear + random_offset, random_padding_len)) {
            status = DfcSdmRenderRandomExhausted;
            goto cleanup;
        }
    }
    memcpy(emulator->sdm_read_cache, source, file->data_len);

    uint32_t counter = ++file->sdm_read_counter;
    if(file->sdm_has_counter_limit && counter > file->sdm_counter_limit) goto cleanup;
    if(file->sdm_has_uid_offset) {
        size_t encoded_uid_len = emulator->credential->uid_len * DFC_SDM_HEX_EXPANSION;
        if(!sdm_range_fits(file, file->sdm_uid_offset, encoded_uid_len)) goto cleanup;
        uint8_t uid[DFC_DESFIRE_UID_MAX_LENGTH] = {0};
        if(!emulator->credential->picc_random_id)
            memcpy(uid, emulator->credential->uid, emulator->credential->uid_len);
        sdm_write_ascii_hex(
            emulator->sdm_read_cache + file->sdm_uid_offset, uid, emulator->credential->uid_len);
        dfc_secure_wipe(uid, sizeof(uid));
    }
    if(file->sdm_has_counter_offset) {
        if(!sdm_range_fits(file, file->sdm_counter_offset, 6)) goto cleanup;
        uint8_t counter_bytes[] = {
            (uint8_t)(counter >> 16), (uint8_t)(counter >> 8), (uint8_t)counter};
        sdm_write_ascii_hex(
            emulator->sdm_read_cache + file->sdm_counter_offset,
            counter_bytes,
            sizeof(counter_bytes));
        dfc_secure_wipe(counter_bytes, sizeof(counter_bytes));
    }

    if(file->sdm_has_picc_data_offset) {
        size_t clear_len = picc_clear_len;
        size_t encoded_len = clear_len * DFC_SDM_HEX_EXPANSION;
        if(!sdm_range_fits(file, file->sdm_picc_data_offset, encoded_len)) goto cleanup;
        picc_clear[0] = (uint8_t)(DFC_SDM_PICC_UID_TAG_MASK |
                                  ((file->sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) != 0 ?
                                       DFC_SDM_COUNTER_MIRROR_MASK :
                                       0) |
                                  emulator->credential->uid_len);
        size_t padding_len = clear_len - 1 - emulator->credential->uid_len;
        if((file->sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) != 0) padding_len -= 3;
        if(emulator->credential->uid_len == DFC_DESFIRE_UID_MAX_LENGTH &&
           (file->sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) == 0) {
            memcpy(
                picc_clear + 1 + padding_len,
                emulator->credential->uid,
                emulator->credential->uid_len);
        } else {
            size_t payload_offset = 1;
            memcpy(
                picc_clear + payload_offset,
                emulator->credential->uid,
                emulator->credential->uid_len);
            payload_offset += emulator->credential->uid_len;
            if((file->sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) != 0) {
                picc_clear[payload_offset++] = (uint8_t)counter;
                picc_clear[payload_offset++] = (uint8_t)(counter >> 8);
                picc_clear[payload_offset++] = (uint8_t)(counter >> 16);
            }
        }
        DfcApplication* app = dfc_emulator_current_app(emulator);
        uint8_t* meta_key = app ? dfc_credential_key(emulator->credential, app, 0) : NULL;
        if(!meta_key) goto cleanup;
        if(!dfc_worker_aes_cbc_encrypt(
               meta_key, DFC_AES_KEY_LENGTH, picc_iv, clear_len, picc_clear, picc_encrypted))
            goto cleanup;
        sdm_write_ascii_hex(
            emulator->sdm_read_cache + file->sdm_picc_data_offset, picc_encrypted, clear_len);

        if(file->sdm_has_mac_input_offset && file->sdm_has_mac_offset) {
            uint8_t file_read_key_number =
                (uint8_t)((file->sdm_access_rights >> DFC_SDM_FILE_READ_SHIFT) &
                          DFC_SDM_ACCESS_MASK);
            uint8_t* file_read_key =
                app ? dfc_credential_key(emulator->credential, app, file_read_key_number) : NULL;
            if(!file_read_key) goto cleanup;
            if(!sdm_derive_key(
                   file_read_key,
                   DFC_SDM_MAC_LABEL_HIGH,
                   DFC_SDM_MAC_LABEL_LOW,
                   emulator->credential,
                   file,
                   counter,
                   session_mac_key))
                goto cleanup;
            if(file->sdm_mac_offset < file->sdm_mac_input_offset ||
               !sdm_range_fits(
                   file, file->sdm_mac_offset, DFC_WIRE_MAC_LENGTH * DFC_SDM_HEX_EXPANSION))
                goto cleanup;
            if(!aes_cmac(
                   session_mac_key,
                   DFC_AES_KEY_LENGTH,
                   emulator->sdm_read_cache + file->sdm_mac_input_offset,
                   file->sdm_mac_offset - file->sdm_mac_input_offset,
                   full_mac))
                goto cleanup;
            dfc_truncate_aes_wire_mac(full_mac, wire_mac);
            sdm_write_ascii_hex(
                emulator->sdm_read_cache + file->sdm_mac_offset, wire_mac, sizeof(wire_mac));
        }
    }
    if(file->sdm_has_encrypted_file_offset) {
        if(file->sdm_encrypted_file_length == 0 ||
           file->sdm_encrypted_file_length % (DFC_AES_KEY_LENGTH * DFC_SDM_HEX_EXPANSION) != 0 ||
           !sdm_range_fits(
               file, file->sdm_encrypted_file_offset, file->sdm_encrypted_file_length) ||
           file->sdm_encrypted_file_length / DFC_SDM_HEX_EXPANSION >
               sizeof(emulator->sdm_read_cache))
            goto cleanup;
        DfcApplication* app = dfc_emulator_current_app(emulator);
        uint8_t file_read_key_number =
            (uint8_t)((file->sdm_access_rights >> DFC_SDM_FILE_READ_SHIFT) & DFC_SDM_ACCESS_MASK);
        uint8_t* file_read_key =
            app ? dfc_credential_key(emulator->credential, app, file_read_key_number) : NULL;
        if(!file_read_key) goto cleanup;
        if(!sdm_derive_key(
               file_read_key,
               DFC_SDM_ENCRYPTION_LABEL_HIGH,
               DFC_SDM_ENCRYPTION_LABEL_LOW,
               emulator->credential,
               file,
               counter,
               session_encryption_key))
            goto cleanup;
        size_t clear_len = file->sdm_encrypted_file_length / DFC_SDM_HEX_EXPANSION;
        if(clear_len > DFC_SDM_READ_CACHE_SIZE) goto cleanup;
        uint8_t* encrypted = emulator->pending_chain;
        memcpy(encrypted, source + file->sdm_encrypted_file_offset, clear_len);
        pending_scratch_len = clear_len;
        counter_block[0] = (uint8_t)counter;
        counter_block[1] = (uint8_t)(counter >> 8);
        counter_block[2] = (uint8_t)(counter >> 16);
        if(!dfc_worker_aes_cbc_encrypt(
               session_encryption_key,
               DFC_AES_KEY_LENGTH,
               zero_iv,
               sizeof(counter_block),
               counter_block,
               file_iv) ||
           !dfc_worker_aes_cbc_encrypt(
               session_encryption_key, DFC_AES_KEY_LENGTH, file_iv, clear_len, encrypted, encrypted))
            goto cleanup;
        sdm_write_ascii_hex(
            emulator->sdm_read_cache + file->sdm_encrypted_file_offset, encrypted, clear_len);
    }
    if(!file->sdm_has_picc_data_offset && file->sdm_has_mac_input_offset &&
       file->sdm_has_mac_offset) {
        DfcApplication* app = dfc_emulator_current_app(emulator);
        uint8_t file_read_key_number =
            (uint8_t)((file->sdm_access_rights >> DFC_SDM_FILE_READ_SHIFT) & DFC_SDM_ACCESS_MASK);
        uint8_t* file_read_key =
            app ? dfc_credential_key(emulator->credential, app, file_read_key_number) : NULL;
        if(!file_read_key ||
           !sdm_derive_key(
               file_read_key,
               DFC_SDM_MAC_LABEL_HIGH,
               DFC_SDM_MAC_LABEL_LOW,
               emulator->credential,
               file,
               counter,
               session_mac_key) ||
           file->sdm_mac_offset < file->sdm_mac_input_offset ||
           !sdm_range_fits(
               file, file->sdm_mac_offset, DFC_WIRE_MAC_LENGTH * DFC_SDM_HEX_EXPANSION) ||
           !aes_cmac(
               session_mac_key,
               DFC_AES_KEY_LENGTH,
               emulator->sdm_read_cache + file->sdm_mac_input_offset,
               file->sdm_mac_offset - file->sdm_mac_input_offset,
               full_mac))
            goto cleanup;
        dfc_truncate_aes_wire_mac(full_mac, wire_mac);
        sdm_write_ascii_hex(
            emulator->sdm_read_cache + file->sdm_mac_offset, wire_mac, sizeof(wire_mac));
    }
    DFC_UNUSED(counter);
    emulator->sdm_read_cache_valid = true;
    emulator->sdm_read_cache_file_number = file->number;
    emulator->sdm_read_cache_len = file->data_len;
    status = DfcSdmRenderOk;

cleanup:
    if(pending_scratch_len != 0) dfc_secure_wipe(emulator->pending_chain, pending_scratch_len);
    dfc_secure_wipe(picc_clear, sizeof(picc_clear));
    dfc_secure_wipe(picc_encrypted, sizeof(picc_encrypted));
    dfc_secure_wipe(session_mac_key, sizeof(session_mac_key));
    dfc_secure_wipe(full_mac, sizeof(full_mac));
    dfc_secure_wipe(wire_mac, sizeof(wire_mac));
    dfc_secure_wipe(session_encryption_key, sizeof(session_encryption_key));
    dfc_secure_wipe(counter_block, sizeof(counter_block));
    dfc_secure_wipe(picc_iv, sizeof(picc_iv));
    dfc_secure_wipe(zero_iv, sizeof(zero_iv));
    dfc_secure_wipe(file_iv, sizeof(file_iv));
    return status;
}

DfcSdmRenderStatus dfc_emulator_render_sdm_read_status(DfcEmulator* emulator, DfcFile* file) {
    if(!emulator || !file) return DfcSdmRenderFailed;
    _Static_assert(
        DFC_EMULATOR_CHAIN_BUFFER_SIZE >= DFC_SDM_READ_CACHE_SIZE * 2,
        "SDM rollback requires two cache-sized regions");
    if(emulator->command_chain_active ||
       emulator->pending_chain_len > emulator->pending_chain_offset) {
        return DfcSdmRenderFailed;
    }
    uint8_t* saved_cache = emulator->pending_chain + DFC_SDM_READ_CACHE_SIZE;
    memcpy(saved_cache, emulator->sdm_read_cache, sizeof(emulator->sdm_read_cache));
    uint32_t saved_counter = file->sdm_read_counter;
    bool saved_valid = emulator->sdm_read_cache_valid;
    uint8_t saved_file_number = emulator->sdm_read_cache_file_number;
    size_t saved_len = emulator->sdm_read_cache_len;
    DfcSdmRenderStatus status = render_sdm_read_in_place(emulator, file);
    if(status != DfcSdmRenderOk) {
        memcpy(emulator->sdm_read_cache, saved_cache, sizeof(emulator->sdm_read_cache));
        file->sdm_read_counter = saved_counter;
        emulator->sdm_read_cache_valid = saved_valid;
        emulator->sdm_read_cache_file_number = saved_file_number;
        emulator->sdm_read_cache_len = saved_len;
    }
    dfc_secure_wipe(saved_cache, sizeof(emulator->sdm_read_cache));
    return status;
}

bool dfc_emulator_render_sdm_read(DfcEmulator* emulator, DfcFile* file) {
    return dfc_emulator_render_sdm_read_status(emulator, file) == DfcSdmRenderOk;
}
#endif

bool dfc_emulator_command_read_data(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer,
    Dfc* dfc) {
    DFC_UNUSED(apdu_len);
    uint8_t file_no = apdu[1];
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, file_no);
    if(!file) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return true;
    }
    if(file->type != DFC_FILE_TYPE_STANDARD_DATA && file->type != DFC_FILE_TYPE_BACKUP_DATA &&
       file->type != DFC_FILE_TYPE_TRANSACTION_MAC) {
        // ReadData cannot reinterpret a value or record file as an octet stream.
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return true;
    }
    if(!dfc_emulator_command_file_allows_read(file, emulator)) {
        dfc_bytebuf_append_byte(
            tx_buffer, dfc_emulator_command_file_access_refusal_status(file, false));
        return true;
    }

    uint32_t offset = read_uint24_le(apdu + 2);
    uint32_t requested_len = read_uint24_le(apdu + 5);
    if(offset > file->data_len ||
       (requested_len != 0 && (size_t)offset + (size_t)requested_len > file->data_len)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return true;
    }

    size_t available = file->data_len - offset;
    size_t read_len = requested_len == 0 ? available : (size_t)requested_len;

    const uint8_t* file_bytes = dfc_file_data_const(emulator->credential, file);
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
    // Backup reads keep showing the committed image until CommitTransaction.
    if(file->type == DFC_FILE_TYPE_BACKUP_DATA && emulator->transaction_snapshot_active &&
       emulator->transaction_snapshot_app_index == emulator->selected_app_index &&
       file->data_offset != DFC_FILE_POOL_NONE &&
       file->data_offset <= emulator->transaction_snapshot_pool_length &&
       file->data_len <= emulator->transaction_snapshot_pool_length - file->data_offset) {
        file_bytes = emulator->transaction_snapshot_pool + file->data_offset;
    }
#endif
#if DFC_ENABLE_SDM
    if(file->sdm_enabled) {
        if(!emulator->sdm_read_cache_valid && file->sdm_has_counter_limit &&
           file->sdm_read_counter >= file->sdm_counter_limit) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
            return true;
        }
        DfcSdmRenderStatus render_status = dfc_emulator_render_sdm_read_status(emulator, file);
        if(render_status == DfcSdmRenderRandomExhausted) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_MEMORY_ERROR);
            return true;
        }
        if(render_status != DfcSdmRenderOk) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
            return true;
        }
        file_bytes = emulator->sdm_read_cache;
    }
#endif
    if(read_len > 0 && !file_bytes) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return true;
    }

    uint8_t comm = dfc_emulator_file_effective_comm_settings(
        emulator, file, DfcFileAccessRead, file->comm_settings);
    dfc_emulator_command_emit_payload_with_chaining_comm(
        emulator,
        tx_buffer,
        DFC_CMD_READ_DATA,
        read_len ? file_bytes + offset : NULL,
        read_len,
        1,
        comm,
        requested_len == 0);

    if(dfc && read_len > 0) {
        dfc_port_notify(dfc, DfcEventFileRequested);
    }
    return true;
}

#if DFC_ENABLE_SDM
void dfc_emulator_command_get_file_counters(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    bool ev1 = dfc_emulator_native_authentication_active(emulator) &&
               dfc_secure_messaging_applies_ev1(emulator->secure_messaging, buffer[0]);
    if(ev1) {
        size_t clear_len = dfc_secure_messaging_verify_ev1_transmitted_command_mac(
            emulator->secure_messaging, buffer[0], buffer + 1, buffer_len - 1);
        if(clear_len != 1) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return;
        }
    } else if(buffer_len != 2) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    uint8_t file_selector = buffer[1];
    if((file_selector & 0x60u) != 0) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    // The model has no secondary-application selection state, so SAI cannot
    // name a reachable file even when its low five bits are otherwise valid.
    if((file_selector & 0x80u) != 0) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, file_selector & 0x1Fu);
    if(!file) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(file->type != DFC_FILE_TYPE_STANDARD_DATA || !file->sdm_enabled) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }

    // SDMCtrRet is the low access-rights nibble. A key reference requires that
    // exact authenticated key; 0xE is free access and 0xF denies the command.
    uint8_t counter_access = (uint8_t)(file->sdm_access_rights & DFC_SDM_ACCESS_MASK);
    if(counter_access == DFC_SDM_DENIED_ACCESS) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    if(counter_access != DFC_SDM_FREE_ACCESS &&
       !dfc_emulator_command_is_authenticated_with_key(emulator, counter_access)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }

    const uint8_t encoded_counter[] = {
        (uint8_t)file->sdm_read_counter,
        (uint8_t)(file->sdm_read_counter >> 8),
        (uint8_t)(file->sdm_read_counter >> 16),
        0,
        0,
    };
    bool authenticated = dfc_emulator_native_authentication_active(emulator);
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    authenticated = authenticated || emulator->ev2_session_active;
#endif
    dfc_emulator_command_emit_payload_with_chaining_comm(
        emulator,
        tx_buffer,
        DFC_CMD_GET_FILE_COUNTERS,
        encoded_counter,
        sizeof(encoded_counter),
        1,
        authenticated ? DFC_COMM_ENCIPHERED : DFC_COMM_PLAIN,
        false);
    emulator->sdm_read_cache_valid = false;
}
#endif

void dfc_emulator_command_write_data(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer) {
    uint8_t file_no = apdu[1];
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, file_no);
    if(!file) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(!dfc_emulator_command_file_allows_write(file, emulator)) {
        dfc_bytebuf_append_byte(
            tx_buffer, dfc_emulator_command_file_access_refusal_status(file, true));
        return;
    }
    uint8_t comm = dfc_emulator_file_effective_comm_settings(
        emulator, file, DfcFileAccessWrite, file->comm_settings);
    if(apdu_len > DFC_EMULATOR_CHAIN_BUFFER_SIZE ||
       (comm == DFC_COMM_ENCIPHERED && apdu_len - 8 > DFC_SM_MAX_CRYPTO_SIZE)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }

    uint32_t offset = read_uint24_le(apdu + 2);
    uint32_t declared_len = read_uint24_le(apdu + 5);
    if(offset > file->data_len || (size_t)offset + (size_t)declared_len > file->data_len) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }

    const uint8_t* wrapped = apdu + 8;
    size_t wrapped_len = apdu_len - 8;

    const uint8_t* clear = wrapped;
    size_t out_len = wrapped_len;
    size_t scratch_len = 0;
    if(dfc_emulator_native_authentication_active(emulator)) {
        bool ev1_sm =
            dfc_secure_messaging_applies_ev1(emulator->secure_messaging, DFC_CMD_WRITE_DATA);
        if(ev1_sm && comm == DFC_COMM_MAC &&
           dfc_secure_messaging_ev1_transmits_command_mac(DFC_CMD_WRITE_DATA)) {
            // Option b: MACt covers Cmd||FileNo||Offset||Len||Data (whole body after Cmd).
            size_t clear_body = dfc_secure_messaging_verify_ev1_transmitted_command_mac_full(
                emulator->secure_messaging, apdu, apdu_len);
            if(clear_body == SIZE_MAX || clear_body < 7) {
                dfc_emulator_reset_session(emulator);
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
                return;
            }
            out_len = clear_body - 7;
            clear = wrapped;
        } else if(ev1_sm && comm == DFC_COMM_ENCIPHERED) {
            if(wrapped_len > sizeof(emulator->pending_chain)) {
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
                return;
            }
            uint8_t* target = emulator->pending_chain;
            out_len = dfc_secure_messaging_verify_command(
                emulator->secure_messaging,
                DFC_COMM_ENCIPHERED,
                apdu,
                8,
                wrapped,
                wrapped_len,
                target,
                sizeof(emulator->pending_chain));
            clear = target;
            scratch_len = wrapped_len;
            if(out_len == 0 && wrapped_len > 0) {
                dfc_secure_wipe(target, scratch_len);
                dfc_emulator_reset_session(emulator);
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
                return;
            }
            // IV left as last CT block for response MACt(RC).
        } else if(ev1_sm) {
            // Plain (or free-access Full demoted to plain): CMAC updates IV only.
            if(!dfc_secure_messaging_update_ev1_command_full(
                   emulator->secure_messaging, apdu, apdu_len)) {
                dfc_emulator_reset_session(emulator);
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
                return;
            }
        } else {
            // D40 file comm modes.
            if(comm != DFC_COMM_PLAIN) {
                if(wrapped_len > sizeof(emulator->pending_chain)) {
                    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
                    return;
                }
                uint8_t* target = emulator->pending_chain;
                bool d40_mac_ok = true;
                if(comm == DFC_COMM_MAC) {
                    d40_mac_ok = dfc_secure_messaging_verify_d40_command_mac(
                        emulator->secure_messaging,
                        wrapped,
                        wrapped_len,
                        target,
                        sizeof(emulator->pending_chain),
                        &out_len);
                } else {
                    out_len = dfc_secure_messaging_verify_command(
                        emulator->secure_messaging,
                        DFC_COMM_ENCIPHERED,
                        apdu,
                        8,
                        wrapped,
                        wrapped_len,
                        target,
                        sizeof(emulator->pending_chain));
                }
                if(!d40_mac_ok) out_len = SIZE_MAX;
                clear = target;
                scratch_len = wrapped_len;
            }
            if((out_len == 0 && wrapped_len > 0 && comm != DFC_COMM_PLAIN) ||
               out_len == SIZE_MAX) {
                dfc_secure_wipe(emulator->pending_chain, scratch_len);
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
                return;
            }
        }
    }

    if(out_len != declared_len) {
        dfc_secure_wipe(emulator->pending_chain, scratch_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }
    uint8_t* file_bytes = dfc_file_data(emulator->credential, file);
#if DFC_ENABLE_BACKUP_FILES
    if(file->type == DFC_FILE_TYPE_BACKUP_DATA &&
       !dfc_emulator_command_transaction_snapshot_begin(emulator)) {
        dfc_secure_wipe(emulator->pending_chain, scratch_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
#endif
    if(out_len > 0) {
        if(!file_bytes) {
            dfc_secure_wipe(emulator->pending_chain, scratch_len);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
            return;
        }
    }
    if(file->type == DFC_FILE_TYPE_STANDARD_DATA &&
       !dfc_emulator_transaction_snapshot_mirror_write(
           emulator, (size_t)(file - emulator->credential->files), offset, clear, out_len)) {
        dfc_secure_wipe(emulator->pending_chain, scratch_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }
    if(out_len > 0) {
        memcpy(file_bytes + offset, clear, out_len);
    }
    if(file->type == DFC_FILE_TYPE_BACKUP_DATA) file->transaction_pending = true;
    emulator->data_written = true;
    dfc_credential_mark_dirty(emulator->credential);

    dfc_secure_wipe(emulator->pending_chain, scratch_len);
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

#endif
