#include "dfc_emulator_commands_i.h"
#include "dfc_credential_i.h"
#include "dfc_ev2.h"

#if DFC_ENABLE_EMULATOR
#if DFC_ENABLE_TRANSACTION_MAC
static void write_uint32_le(uint8_t output[DFC_UINT32_BYTE_COUNT], uint32_t value) {
    for(size_t index = 0; index < DFC_UINT32_BYTE_COUNT; index++) {
        output[index] = (uint8_t)(value >> (index * DFC_BITS_PER_BYTE));
    }
}
#endif

static bool value_delta_result(const DfcFile* file, int32_t delta, int32_t* result) {
    int64_t current = file->value_pending ?
                          (file->value_pending_absolute ?
                               file->value_pending_value :
                               (int64_t)file->value + file->value_pending_delta) :
                          file->value;
    int64_t next = current + delta;
    if(next < file->value_lower_limit || next > file->value_upper_limit) return false;
    *result = (int32_t)next;
    return true;
}

void dfc_emulator_command_get_value(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    DfcByteBuf* tx_buffer) {
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, apdu[1]);
    if(!file) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(file->type != 0x02) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    if(!dfc_emulator_command_file_allows_read(file, emulator)) {
        dfc_bytebuf_append_byte(
            tx_buffer, dfc_emulator_command_file_access_refusal_status(file, false));
        return;
    }

    uint8_t value_bytes[4] = {0};
    uint32_t raw = (uint32_t)file->value;
    value_bytes[0] = (uint8_t)(raw & 0xFF);
    value_bytes[1] = (uint8_t)((raw >> 8) & 0xFF);
    value_bytes[2] = (uint8_t)((raw >> 16) & 0xFF);
    value_bytes[3] = (uint8_t)((raw >> 24) & 0xFF);

    uint8_t comm = dfc_emulator_file_effective_comm_settings(
        emulator, file, DfcFileAccessRead, file->comm_settings);
    bool ev1_sm = dfc_emulator_native_authentication_active(emulator) &&
                  dfc_secure_messaging_applies_ev1(emulator->secure_messaging, DFC_CMD_GET_VALUE);

    bool protect_here = dfc_emulator_native_authentication_active(emulator) &&
                        comm != DFC_COMM_PLAIN && (!ev1_sm || comm == DFC_COMM_ENCIPHERED);
    if(protect_here) {
        uint8_t wrapped[DFC_SM_MAX_CIPHER_BLOCK_SIZE] = {0};
        size_t wrapped_len = comm == DFC_COMM_MAC ? dfc_secure_messaging_generate_d40_response_mac(
                                                        emulator->secure_messaging,
                                                        value_bytes,
                                                        sizeof(value_bytes),
                                                        wrapped,
                                                        sizeof(wrapped)) :
                                                    dfc_secure_messaging_generate_response(
                                                        emulator->secure_messaging,
                                                        DFC_COMM_ENCIPHERED,
                                                        DFC_STATUS_OK,
                                                        value_bytes,
                                                        sizeof(value_bytes),
                                                        wrapped,
                                                        sizeof(wrapped));
        dfc_secure_wipe(value_bytes, sizeof(value_bytes));
        if(wrapped_len == 0) {
            dfc_secure_wipe(wrapped, sizeof(wrapped));
            dfc_emulator_reset_session(emulator);
            dfc_bytebuf_reset(tx_buffer);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return;
        }
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
        dfc_bytebuf_append_bytes(tx_buffer, wrapped, wrapped_len);
        emulator->response_secured = true;
        dfc_secure_wipe(wrapped, sizeof(wrapped));
        return;
    }

    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    dfc_bytebuf_append_bytes(tx_buffer, value_bytes, sizeof(value_bytes));
    dfc_secure_wipe(value_bytes, sizeof(value_bytes));
}

#if DFC_ENABLE_TRANSACTION_MAC
static bool transaction_input_append_segments(
    DfcEmulator* emulator,
    const DfcCryptoSegment* segments,
    size_t segment_count) {
    size_t entry_len = 0;
    for(size_t i = 0; i < segment_count; i++) {
        if((segments[i].length && !segments[i].data) || segments[i].length > SIZE_MAX - entry_len)
            return false;
        entry_len += segments[i].length;
    }
    if(entry_len > SIZE_MAX - (DFC_AES_KEY_LENGTH - 1)) return false;
    size_t padded_len =
        ((entry_len + DFC_AES_KEY_LENGTH - 1) / DFC_AES_KEY_LENGTH) * DFC_AES_KEY_LENGTH;
    if(emulator->transaction_input_len > sizeof(emulator->transaction_input) ||
       padded_len > sizeof(emulator->transaction_input) - emulator->transaction_input_len)
        return false;

    size_t offset = emulator->transaction_input_len;
    for(size_t i = 0; i < segment_count; i++) {
        if(segments[i].length) {
            memcpy(emulator->transaction_input + offset, segments[i].data, segments[i].length);
            offset += segments[i].length;
        }
    }
    memset(emulator->transaction_input + offset, 0, padded_len - entry_len);
    emulator->transaction_input_len += padded_len;
    return true;
}
#endif

void dfc_emulator_command_value_delta(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer,
    uint8_t cmd,
    bool debit,
    bool limited_credit) {
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, apdu[1]);
    if(!file) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(file->type != 0x02) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    if(!dfc_emulator_command_file_allows_write(file, emulator)) {
        dfc_bytebuf_append_byte(
            tx_buffer, dfc_emulator_command_file_access_refusal_status(file, true));
        return;
    }

    // Native body after cmd: FileNo || Amount(4) [|| MACt / Enc(Amount)].
    const uint8_t* body = apdu + 1;
    size_t body_len = apdu_len - 1;
    int32_t amount = 0;

    if(dfc_emulator_native_authentication_active(emulator) &&
       dfc_secure_messaging_applies_ev1(emulator->secure_messaging, cmd)) {
        uint8_t comm = dfc_emulator_file_effective_comm_settings(
            emulator, file, DfcFileAccessWrite, file->comm_settings);
        if(comm == DFC_COMM_MAC && dfc_secure_messaging_ev1_transmits_command_mac(cmd)) {
            size_t clear_len = dfc_secure_messaging_verify_ev1_transmitted_command_mac(
                emulator->secure_messaging, cmd, body, body_len);
            if(clear_len == SIZE_MAX || clear_len < 5) {
                dfc_emulator_reset_session(emulator);
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
                return;
            }
            amount = dfc_emulator_command_read_int32_le(body + 1);
        } else if(comm == DFC_COMM_ENCIPHERED) {
            // Full: clear FileNo + encrypted Amount. CRC covers Cmd||FileNo||Amount.
            if(body_len < 1 + 8) {
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
                return;
            }
            uint8_t header[2] = {cmd, body[0]};
            if(body_len - 1 > DFC_SM_MAX_CIPHER_BLOCK_SIZE) {
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
                return;
            }
            uint8_t clear[DFC_SM_MAX_CIPHER_BLOCK_SIZE];
            size_t clear_len = dfc_secure_messaging_verify_command(
                emulator->secure_messaging,
                DFC_COMM_ENCIPHERED,
                header,
                sizeof(header),
                body + 1,
                body_len - 1,
                clear,
                sizeof(clear));
            if(clear_len < 4) {
                dfc_emulator_reset_session(emulator);
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
                return;
            }
            amount = dfc_emulator_command_read_int32_le(clear);
        } else {
            if(!dfc_secure_messaging_update_ev1_command(
                   emulator->secure_messaging, cmd, body, body_len)) {
                dfc_emulator_reset_session(emulator);
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
                return;
            }
            if(body_len < 5) {
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
                return;
            }
            amount = dfc_emulator_command_read_int32_le(body + 1);
        }
    } else if(
        dfc_emulator_native_authentication_active(emulator) &&
        !dfc_secure_messaging_applies_ev1(emulator->secure_messaging, cmd)) {
        // D40: Amount may be MAC/ENC under file comm mode.
        uint8_t comm = dfc_emulator_file_effective_comm_settings(
            emulator, file, DfcFileAccessWrite, file->comm_settings);
        if(body_len < 1) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return;
        }
        if(body_len - 1 > DFC_SM_MAX_CIPHER_BLOCK_SIZE) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return;
        }
        uint8_t clear[DFC_SM_MAX_CIPHER_BLOCK_SIZE];
        uint8_t header[2] = {cmd, body[0]};
        size_t clear_len = 0;
        bool d40_mac_ok = true;
        if(comm == DFC_COMM_MAC) {
            d40_mac_ok = dfc_secure_messaging_verify_d40_command_mac(
                emulator->secure_messaging,
                body + 1,
                body_len - 1,
                clear,
                sizeof(clear),
                &clear_len);
        } else if(comm == DFC_COMM_ENCIPHERED) {
            clear_len = dfc_secure_messaging_verify_command(
                emulator->secure_messaging,
                DFC_COMM_ENCIPHERED,
                header,
                sizeof(header),
                body + 1,
                body_len - 1,
                clear,
                sizeof(clear));
        } else {
            clear_len = body_len - 1;
        }
        if(!d40_mac_ok || (clear_len < 4 && comm != DFC_COMM_PLAIN)) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return;
        }
        if(comm == DFC_COMM_PLAIN) {
            if(body_len < 5) {
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
                return;
            }
            amount = dfc_emulator_command_read_int32_le(body + 1);
        } else {
            amount = dfc_emulator_command_read_int32_le(clear);
        }
    } else {
        if(body_len < 5) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return;
        }
        amount = dfc_emulator_command_read_int32_le(body + 1);
    }

    if(amount < 0) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }

    int32_t delta = debit ? -amount : amount;
    if(limited_credit) {
        if((file->limited_credit & 0x01u) == 0) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
            return;
        }
        int32_t available = file->limited_credit_pending > 0 ? file->limited_credit_pending :
                                                               file->limited_credit_value;
        if(file->limited_credit_pending == DFC_LIMITED_CREDIT_TRANSACTION_CONSUMED ||
           amount > available) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
            return;
        }
    }
    int32_t next_value;
    if(!value_delta_result(file, delta, &next_value)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }

#if DFC_ENABLE_TRANSACTION_MAC
    DfcCryptoSegment transaction_segments[] = {
        {.data = &cmd, .length = 1},
        {.data = apdu + 1, .length = 5},
    };
    if(!transaction_input_append_segments(emulator, transaction_segments, 2)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }
#endif
    int64_t aggregate = (int64_t)next_value - file->value;
    file->value_pending = true;
    file->value_pending_value = next_value;
    file->value_pending_absolute = true;
    file->value_pending_delta = aggregate > INT32_MAX ? INT32_MAX :
                                aggregate < INT32_MIN ? INT32_MIN :
                                                        (int32_t)aggregate;
    if(limited_credit) {
        file->limited_credit_pending = DFC_LIMITED_CREDIT_TRANSACTION_CONSUMED;
    } else if(debit && file->limited_credit_pending >= 0) {
        if(amount > INT32_MAX - file->limited_credit_pending) {
            file->limited_credit_pending = INT32_MAX;
        } else {
            file->limited_credit_pending += amount;
        }
    }
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

#if DFC_ENABLE_TRANSACTION_MAC
static DfcFile* transaction_mac_file(DfcEmulator* emulator) {
    return dfc_credential_find_transaction_mac_file(
        emulator->credential, emulator->selected_app_index);
}

static bool transaction_mac_calculate(
    DfcEmulator* emulator,
    DfcFile* file,
    uint8_t mac[DFC_WIRE_MAC_LENGTH],
    uint32_t* next_counter) {
    if(file->transaction_counter == UINT32_MAX) {
        memset(mac, 0, DFC_WIRE_MAC_LENGTH);
        return false;
    }
    *next_counter = file->transaction_counter + 1;
    uint8_t vector[DFC_AES_KEY_LENGTH] = {0};
    vector[0] = DFC_TRANSACTION_MAC_DERIVATION_LABEL;
    vector[1] = DFC_DERIVATION_COUNTER_HIGH;
    vector[2] = DFC_DERIVATION_COUNTER_LOW;
    vector[3] = DFC_DERIVED_AES_KEY_LENGTH_HIGH;
    vector[4] = DFC_DERIVED_AES_KEY_LENGTH_LOW;
    write_uint32_le(vector + DFC_TRANSACTION_VECTOR_COUNTER_OFFSET, *next_counter);
    memcpy(
        vector + DFC_TRANSACTION_VECTOR_UID_OFFSET,
        emulator->credential->uid,
        emulator->credential->uid_len);
    uint8_t session_key[DFC_AES_CMAC_LENGTH] = {0};
    uint8_t full_mac[DFC_AES_CMAC_LENGTH] = {0};
    bool ok =
        aes_cmac(
            file->transaction_mac_key, DFC_AES_KEY_LENGTH, vector, sizeof(vector), session_key) &&
        aes_cmac(
            session_key,
            DFC_AES_KEY_LENGTH,
            emulator->transaction_input,
            emulator->transaction_input_len,
            full_mac);
    if(ok) {
        dfc_truncate_aes_wire_mac(full_mac, mac);
    } else {
        memset(mac, 0, DFC_WIRE_MAC_LENGTH);
    }
    dfc_secure_wipe(vector, sizeof(vector));
    dfc_secure_wipe(session_key, sizeof(session_key));
    dfc_secure_wipe(full_mac, sizeof(full_mac));
    return ok;
}

static bool transaction_pending_reader_id(
    const DfcEmulator* emulator,
    uint8_t reader_id[DFC_TRANSACTION_READER_ID_LENGTH]) {
    bool found = false;
    size_t offset = 0;
    while(offset < emulator->transaction_input_len) {
        size_t entry_len = DFC_AES_KEY_LENGTH;
        if(emulator->transaction_input[offset] == DFC_CMD_COMMIT_READER_ID) {
            entry_len = 3 * DFC_AES_KEY_LENGTH;
            if(entry_len > emulator->transaction_input_len - offset) return false;
            memcpy(
                reader_id,
                emulator->transaction_input + offset + 1,
                DFC_TRANSACTION_READER_ID_LENGTH);
            found = true;
        }
        if(entry_len > emulator->transaction_input_len - offset) return false;
        offset += entry_len;
    }
    return found;
}

void dfc_emulator_command_commit_reader_id(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    DfcFile* file = transaction_mac_file(emulator);
    if(!file) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(buffer_len != 1 + DFC_TRANSACTION_READER_ID_LENGTH) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    if(file->transaction_counter == UINT32_MAX) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }
    uint32_t next_counter = file->transaction_counter + 1;
    uint8_t vector[DFC_AES_KEY_LENGTH] = {0};
    vector[0] = DFC_TRANSACTION_ENCRYPTION_DERIVATION_LABEL;
    vector[1] = DFC_DERIVATION_COUNTER_HIGH;
    vector[2] = DFC_DERIVATION_COUNTER_LOW;
    vector[3] = DFC_DERIVED_AES_KEY_LENGTH_HIGH;
    vector[4] = DFC_DERIVED_AES_KEY_LENGTH_LOW;
    write_uint32_le(vector + DFC_TRANSACTION_VECTOR_COUNTER_OFFSET, next_counter);
    memcpy(
        vector + DFC_TRANSACTION_VECTOR_UID_OFFSET,
        emulator->credential->uid,
        emulator->credential->uid_len);
    uint8_t session_key[DFC_AES_KEY_LENGTH] = {0};
    uint8_t zero_iv[DFC_AES_KEY_LENGTH] = {0};
    uint8_t encrypted[DFC_TRANSACTION_READER_ID_LENGTH] = {0};
    if(!aes_cmac(
           file->transaction_mac_key, DFC_AES_KEY_LENGTH, vector, sizeof(vector), session_key)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        goto cleanup;
    }
    if(!dfc_worker_aes_cbc_encrypt(
           session_key,
           DFC_AES_KEY_LENGTH,
           zero_iv,
           sizeof(file->previous_reader_id),
           file->previous_reader_id,
           encrypted)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        goto cleanup;
    }
    const uint8_t command = DFC_CMD_COMMIT_READER_ID;
    DfcCryptoSegment transaction_segments[] = {
        {.data = &command, .length = 1},
        {.data = buffer + 1, .length = DFC_TRANSACTION_READER_ID_LENGTH},
        {.data = encrypted, .length = sizeof(encrypted)},
    };
    if(!transaction_input_append_segments(emulator, transaction_segments, 3)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        goto cleanup;
    }
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    dfc_bytebuf_append_bytes(tx_buffer, encrypted, sizeof(encrypted));
cleanup:
    dfc_secure_wipe(vector, sizeof(vector));
    dfc_secure_wipe(session_key, sizeof(session_key));
    dfc_secure_wipe(zero_iv, sizeof(zero_iv));
    dfc_secure_wipe(encrypted, sizeof(encrypted));
}
#endif

#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
bool dfc_emulator_command_transaction_snapshot_begin(DfcEmulator* emulator) {
    if(emulator->transaction_snapshot_active) {
        return emulator->transaction_snapshot_app_index == emulator->selected_app_index;
    }

    size_t length = emulator->credential->file_pool_used;
    uint8_t* snapshot = dfc_platform_alloc(length ? length : 1, DfcAllocEmulator);
    if(!snapshot) return false;
    emulator->transaction_snapshot_pool = snapshot;
    emulator->transaction_snapshot_active = true;
    emulator->transaction_snapshot_app_index = emulator->selected_app_index;
    emulator->transaction_snapshot_pool_length = length;
    emulator->transaction_snapshot_pool_capacity = length ? length : 1;
    emulator->transaction_snapshot_dirty = emulator->credential->dirty;
    memcpy(
        emulator->transaction_snapshot_pool,
        emulator->credential->file_pool,
        emulator->transaction_snapshot_pool_length);
    for(size_t index = 0; index < emulator->credential->num_files; index++) {
        const DfcFile* file = &emulator->credential->files[index];
        emulator->transaction_snapshot_record_counts[index] =
            (file->type == DFC_FILE_TYPE_LINEAR_RECORD ||
             file->type == DFC_FILE_TYPE_CYCLIC_RECORD) ?
                file->record_count :
                0;
    }
    memset(
        emulator->transaction_record_operations,
        RecordTransactionNone,
        sizeof(emulator->transaction_record_operations));
    memset(emulator->transaction_record_numbers, 0, sizeof(emulator->transaction_record_numbers));
    return true;
}

size_t
    dfc_emulator_command_transaction_file_index(const DfcEmulator* emulator, const DfcFile* file) {
    return (size_t)(file - emulator->credential->files);
}

uint8_t dfc_emulator_command_transaction_record_operation(
    const DfcEmulator* emulator,
    const DfcFile* file) {
    size_t index = dfc_emulator_command_transaction_file_index(emulator, file);
    return index < DFC_MAX_FILES ? emulator->transaction_record_operations[index] :
                                   RecordTransactionNone;
}

void dfc_emulator_command_transaction_set_record_operation(
    DfcEmulator* emulator,
    const DfcFile* file,
    uint8_t operation,
    uint32_t record_number) {
    size_t index = dfc_emulator_command_transaction_file_index(emulator, file);
    if(index >= DFC_MAX_FILES) return;
    emulator->transaction_record_operations[index] = operation;
    emulator->transaction_record_numbers[index] = record_number;
}
#endif

void dfc_emulator_command_commit_transaction(
    DfcEmulator* emulator,
    bool return_transaction_mac,
    DfcByteBuf* tx_buffer) {
    bool changed = false;
#if DFC_ENABLE_TRANSACTION_MAC
    if(emulator->transaction_input_len > 0) changed = true;
#endif
    for(size_t i = 0; i < emulator->credential->num_files; i++) {
        DfcFile* file = &emulator->credential->files[i];
        if(file->app_index != emulator->selected_app_index) continue;
        if((file->type == DFC_FILE_TYPE_VALUE && file->value_pending) || file->transaction_pending)
            changed = true;
    }

    if(!changed) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_NO_CHANGES);
        return;
    }

#if DFC_ENABLE_TRANSACTION_MAC
    DfcFile* transaction_file = transaction_mac_file(emulator);
    uint8_t mac[DFC_WIRE_MAC_LENGTH] = {0};
    uint8_t pending_reader_id[DFC_TRANSACTION_READER_ID_LENGTH] = {0};
    bool has_pending_reader_id = transaction_pending_reader_id(emulator, pending_reader_id);
    uint32_t next_counter = 0;
    if(transaction_file) {
        if(!transaction_mac_calculate(emulator, transaction_file, mac, &next_counter)) {
            dfc_secure_wipe(mac, sizeof(mac));
            dfc_secure_wipe(pending_reader_id, sizeof(pending_reader_id));
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return;
        }
    }
#else
    DFC_UNUSED(return_transaction_mac);
#endif

    dfc_emulator_publish_transaction(emulator);
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
#if DFC_ENABLE_TRANSACTION_MAC
    if(transaction_file) {
        if(has_pending_reader_id) {
            memcpy(
                transaction_file->previous_reader_id,
                pending_reader_id,
                sizeof(transaction_file->previous_reader_id));
        }
        transaction_file->transaction_counter = next_counter;
        if(return_transaction_mac) {
            const uint8_t counter[] = {
                (uint8_t)next_counter,
                (uint8_t)(next_counter >> 8),
                (uint8_t)(next_counter >> 16),
                (uint8_t)(next_counter >> 24),
            };
            dfc_bytebuf_append_bytes(tx_buffer, counter, sizeof(counter));
            dfc_bytebuf_append_bytes(tx_buffer, mac, sizeof(mac));
        }
    }
    dfc_secure_wipe(mac, sizeof(mac));
    dfc_secure_wipe(pending_reader_id, sizeof(pending_reader_id));
#endif
}

void dfc_emulator_command_abort_transaction(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    bool changed = dfc_emulator_abort_transaction(emulator);
    dfc_bytebuf_append_byte(tx_buffer, changed ? DFC_STATUS_OK : DFC_STATUS_NO_CHANGES);
}

void dfc_emulator_command_clear_selected_app_pending_values(DfcEmulator* emulator) {
    for(size_t i = 0; i < emulator->credential->num_files; i++) {
        DfcFile* file = &emulator->credential->files[i];
        if(file->app_index != emulator->selected_app_index || file->type != DFC_FILE_TYPE_VALUE) {
            continue;
        }
        file->value_pending = false;
        file->value_pending_delta = 0;
        file->value_pending_value = 0;
        file->value_pending_absolute = false;
        file->limited_credit_pending = 0;
    }
#if DFC_ENABLE_TRANSACTION_MAC
    dfc_secure_wipe(emulator->transaction_input, sizeof(emulator->transaction_input));
    emulator->transaction_input_len = 0;
#endif
}

#endif
