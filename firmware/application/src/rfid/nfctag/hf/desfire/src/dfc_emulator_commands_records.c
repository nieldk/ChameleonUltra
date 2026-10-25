#include "dfc_emulator_commands_i.h"
#include "dfc_credential_i.h"

#if DFC_ENABLE_EMULATOR && DFC_ENABLE_RECORD_FILES

#define read_uint24_le dfc_emulator_read_uint24_le
void dfc_emulator_command_write_record(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer) {
    if(apdu_len > DFC_EMULATOR_CHAIN_BUFFER_SIZE) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, apdu[1]);
    if(!file ||
       (file->type != DFC_FILE_TYPE_LINEAR_RECORD && file->type != DFC_FILE_TYPE_CYCLIC_RECORD)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(!dfc_emulator_command_file_allows_write(file, emulator)) {
        dfc_bytebuf_append_byte(
            tx_buffer, dfc_emulator_command_file_access_refusal_status(file, true));
        return;
    }

    uint32_t offset = read_uint24_le(apdu + 2);
    uint32_t write_len = read_uint24_le(apdu + 5);
    uint8_t comm = dfc_emulator_file_effective_comm_settings(
        emulator, file, DfcFileAccessWrite, file->comm_settings);
    uint8_t* record_data = emulator->pending_chain;
    size_t clear_len = dfc_emulator_command_unwrap_write_payload(
        emulator, apdu, apdu_len, 7, comm, record_data, sizeof(emulator->pending_chain));
    if(clear_len == SIZE_MAX) {
        dfc_emulator_reset_session(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }
    if(clear_len != write_len || offset + write_len > file->record_size) {
        dfc_secure_wipe(record_data, clear_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }
    // A cyclic file keeps one record in reserve, so it holds one fewer than its
    // declared size, measured against a genuine EV1.
    size_t cyclic_capacity = file->max_records > 0 ? (size_t)file->max_records - 1 : 0;

    uint8_t* data = dfc_file_data(emulator->credential, file);
    if(!data) {
        dfc_secure_wipe(record_data, clear_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(!dfc_emulator_command_transaction_snapshot_begin(emulator)) {
        dfc_secure_wipe(record_data, clear_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    uint8_t operation = dfc_emulator_command_transaction_record_operation(emulator, file);
    if(operation == RecordTransactionClear || operation == RecordTransactionUpdate) {
        dfc_secure_wipe(record_data, clear_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }

    size_t record_index = 0;
    if(operation == RecordTransactionWrite) {
        size_t index = dfc_emulator_command_transaction_file_index(emulator, file);
        record_index = emulator->transaction_record_numbers[index];
    } else {
        // A linear file with no room left refuses the first write in a
        // transaction. Further writes target the record that call created.
        if(file->record_count >= file->max_records && file->type == DFC_FILE_TYPE_LINEAR_RECORD) {
            dfc_secure_wipe(record_data, clear_len);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
            return;
        }
        if(file->type == DFC_FILE_TYPE_CYCLIC_RECORD && cyclic_capacity == 0) {
            dfc_secure_wipe(record_data, clear_len);
            dfc_emulator_command_transaction_set_record_operation(
                emulator, file, RecordTransactionWrite, 0);
            file->transaction_pending = true;
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
            return;
        }

        record_index = file->record_count;
        if(file->type == DFC_FILE_TYPE_CYCLIC_RECORD && file->record_count >= cyclic_capacity) {
            size_t retained_len = (cyclic_capacity - 1) * (size_t)file->record_size;
            if(retained_len > 0) {
                memmove(data, data + file->record_size, retained_len);
            }
            record_index = cyclic_capacity - 1;
            file->record_count = (uint32_t)cyclic_capacity;
        } else {
            file->record_count++;
        }
        memset(data + record_index * file->record_size, 0, file->record_size);
        dfc_emulator_command_transaction_set_record_operation(
            emulator, file, RecordTransactionWrite, (uint32_t)record_index);
    }
    if(write_len > 0) {
        memcpy(data + record_index * file->record_size + offset, record_data, write_len);
    }
    dfc_secure_wipe(record_data, clear_len);
    file->transaction_pending = true;
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

void dfc_emulator_command_update_record(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer) {
    if(apdu_len > DFC_EMULATOR_CHAIN_BUFFER_SIZE) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, apdu[1]);
    if(!file ||
       (file->type != DFC_FILE_TYPE_LINEAR_RECORD && file->type != DFC_FILE_TYPE_CYCLIC_RECORD)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(!dfc_emulator_command_file_allows_read_write(file, emulator)) {
        dfc_bytebuf_append_byte(
            tx_buffer, dfc_emulator_command_file_access_refusal_status(file, true));
        return;
    }
    uint32_t record_number = read_uint24_le(apdu + 2);
    uint32_t offset = read_uint24_le(apdu + 5);
    uint32_t write_length = read_uint24_le(apdu + 8);
    if(record_number >= file->record_count || offset >= file->record_size || write_length == 0 ||
       offset + write_length > file->record_size) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }
    uint8_t comm = dfc_emulator_file_effective_comm_settings(
        emulator, file, DfcFileAccessReadWrite, file->comm_settings);
    uint8_t* update_data = emulator->pending_chain;
    size_t clear_len = dfc_emulator_command_unwrap_write_payload(
        emulator,
        apdu,
        apdu_len,
        DFC_UPDATE_RECORD_HEADER_SIZE - 1,
        comm,
        update_data,
        sizeof(emulator->pending_chain));
    if(clear_len == SIZE_MAX) {
        dfc_emulator_reset_session(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }
    if(clear_len != write_length) {
        dfc_secure_wipe(update_data, clear_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    uint8_t* data = dfc_file_data(emulator->credential, file);
    if(!data || !dfc_emulator_command_transaction_snapshot_begin(emulator)) {
        dfc_secure_wipe(update_data, clear_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        return;
    }
    if(file->type == DFC_FILE_TYPE_LINEAR_RECORD && file->record_count >= file->max_records) {
        dfc_secure_wipe(update_data, clear_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }
    uint8_t operation = dfc_emulator_command_transaction_record_operation(emulator, file);
    if(operation == RecordTransactionWrite || operation == RecordTransactionClear ||
       (operation == RecordTransactionUpdate &&
        emulator->transaction_record_numbers[dfc_emulator_command_transaction_file_index(
            emulator, file)] != record_number)) {
        dfc_secure_wipe(update_data, clear_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    size_t stored_index = file->record_count - record_number - 1;
    memcpy(data + stored_index * file->record_size + offset, update_data, write_length);
    dfc_secure_wipe(update_data, clear_len);
    dfc_emulator_command_transaction_set_record_operation(
        emulator, file, RecordTransactionUpdate, record_number);
    file->transaction_pending = true;
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

void dfc_emulator_command_clear_record_file(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer) {
    if(apdu_len != 2) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, apdu[1]);
    if(!file ||
       (file->type != DFC_FILE_TYPE_LINEAR_RECORD && file->type != DFC_FILE_TYPE_CYCLIC_RECORD)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(!dfc_emulator_command_file_allows_read_write(file, emulator)) {
        dfc_bytebuf_append_byte(
            tx_buffer, dfc_emulator_command_file_access_refusal_status(file, true));
        return;
    }
    if(!dfc_emulator_command_transaction_snapshot_begin(emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        return;
    }
    if(dfc_emulator_command_transaction_record_operation(emulator, file) !=
       RecordTransactionNone) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    file->record_count = 0;
    dfc_emulator_command_transaction_set_record_operation(
        emulator, file, RecordTransactionClear, 0);
    file->transaction_pending = true;
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

#endif
