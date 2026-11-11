#include "dfc_transaction_mac.h"

#include "aes_cmac.h"
#include "cmac_internal.h"
#include "dfc_transaction_mac_i.h"
#include "dfc_port.h"

#include <string.h>

#define TRANSACTION_BLOCK_SIZE      16u
#define TRANSACTION_VERIFIER_COOKIE 0x544D4143u

enum {
    TransactionDataHeaderLength = 8,
    TransactionRecordUpdateHeaderLength = 11,
    TransactionValueHeaderLength = 6,
    TransactionClearRecordHeaderLength = 2,
    TransactionReaderIdHeaderLength = 1 + DFC_TRANSACTION_READER_ID_LENGTH,
};

typedef struct {
    uint8_t header[TransactionReaderIdHeaderLength];
    size_t header_length;
    const uint8_t* data;
    size_t data_length;
} TransactionMacEntry;

static bool uint24_is_valid(uint32_t value) {
    return value <= 0xFFFFFFu;
}

static bool verifier_is_valid(const DfcTransactionMacVerifier* verifier) {
    return verifier && verifier->lifecycle_cookie == TRANSACTION_VERIFIER_COOKIE &&
           verifier->initialized && verifier->input &&
           verifier->input_length <= verifier->input_capacity;
}

static bool padded_length(size_t length, size_t* padded) {
    if(!padded || length > SIZE_MAX - (TRANSACTION_BLOCK_SIZE - 1)) return false;
    *padded =
        (length + TRANSACTION_BLOCK_SIZE - 1) / TRANSACTION_BLOCK_SIZE * TRANSACTION_BLOCK_SIZE;
    return true;
}

static bool entry_is_valid(const TransactionMacEntry* entry) {
    return entry && entry->header_length > 0 && entry->header_length <= sizeof(entry->header) &&
           (!entry->data_length || entry->data);
}

static bool append_entry(
    uint8_t* input,
    size_t input_capacity,
    size_t* input_length,
    const TransactionMacEntry* entry) {
    if(!input || !input_length || !entry_is_valid(entry) || *input_length > input_capacity)
        return false;
    size_t padded_header_length;
    size_t padded_data_length;
    if(!padded_length(entry->header_length, &padded_header_length) ||
       !padded_length(entry->data_length, &padded_data_length) ||
       padded_header_length > SIZE_MAX - padded_data_length)
        return false;
    size_t entry_length = padded_header_length + padded_data_length;
    if(entry_length > input_capacity - *input_length) return false;

    size_t offset = *input_length;
    memcpy(input + offset, entry->header, entry->header_length);
    offset += entry->header_length;
    memset(input + offset, 0, padded_header_length - entry->header_length);
    offset = *input_length + padded_header_length;
    if(entry->data_length) memcpy(input + offset, entry->data, entry->data_length);
    offset += entry->data_length;
    memset(input + offset, 0, padded_data_length - entry->data_length);
    *input_length += entry_length;
    return true;
}

static bool input_has_capacity(
    size_t input_capacity,
    size_t input_length,
    size_t header_length,
    size_t data_length) {
    if(input_length > input_capacity) return false;
    size_t padded_header_length;
    size_t padded_data_length;
    if(!padded_length(header_length, &padded_header_length) ||
       !padded_length(data_length, &padded_data_length) ||
       padded_header_length > SIZE_MAX - padded_data_length)
        return false;
    return padded_header_length + padded_data_length <= input_capacity - input_length;
}

bool dfc_transaction_mac_input_can_add_data(
    size_t input_capacity,
    size_t input_length,
    size_t data_length) {
    return input_has_capacity(
        input_capacity, input_length, TransactionDataHeaderLength, data_length);
}

bool dfc_transaction_mac_input_can_add_record_update(
    size_t input_capacity,
    size_t input_length,
    size_t data_length) {
    return input_has_capacity(
        input_capacity, input_length, TransactionRecordUpdateHeaderLength, data_length);
}

bool dfc_transaction_mac_input_can_add_value(size_t input_capacity, size_t input_length) {
    return input_has_capacity(input_capacity, input_length, TransactionValueHeaderLength, 0);
}

bool dfc_transaction_mac_input_can_add_clear_record(size_t input_capacity, size_t input_length) {
    return input_has_capacity(input_capacity, input_length, TransactionClearRecordHeaderLength, 0);
}

bool dfc_transaction_mac_input_can_add_reader_id(
    size_t input_capacity,
    size_t input_length,
    bool authenticated) {
    return input_has_capacity(
        input_capacity,
        input_length,
        TransactionReaderIdHeaderLength,
        authenticated ? DFC_TRANSACTION_READER_ID_LENGTH : 0);
}

static void write_uint24_le(uint8_t output[3], uint32_t value) {
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
    output[2] = (uint8_t)(value >> 16);
}

static bool entry_data(
    TransactionMacEntry* entry,
    uint8_t command,
    uint8_t file_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_length) {
    if(!entry || !uint24_is_valid(offset) || !uint24_is_valid(length) || (data_length && !data))
        return false;
    *entry = (TransactionMacEntry){
        .header = {command, file_number},
        .header_length = TransactionDataHeaderLength,
        .data = data,
        .data_length = data_length,
    };
    write_uint24_le(entry->header + 2, offset);
    write_uint24_le(entry->header + 5, length);
    return true;
}

static bool entry_record_update(
    TransactionMacEntry* entry,
    uint8_t command,
    uint8_t file_number,
    uint32_t record_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_length) {
    if(!entry || !uint24_is_valid(record_number) || !uint24_is_valid(offset) ||
       !uint24_is_valid(length) || (data_length && !data))
        return false;
    *entry = (TransactionMacEntry){
        .header = {command, file_number},
        .header_length = TransactionRecordUpdateHeaderLength,
        .data = data,
        .data_length = data_length,
    };
    write_uint24_le(entry->header + 2, record_number);
    write_uint24_le(entry->header + 5, offset);
    write_uint24_le(entry->header + 8, length);
    return true;
}

static bool entry_value(
    TransactionMacEntry* entry,
    uint8_t command,
    uint8_t file_number,
    const uint8_t value[4]) {
    if(!entry || !value) return false;
    *entry = (TransactionMacEntry){
        .header = {command, file_number},
        .header_length = TransactionValueHeaderLength,
    };
    memcpy(entry->header + 2, value, 4);
    return true;
}

static bool entry_clear_record(TransactionMacEntry* entry, uint8_t file_number) {
    if(!entry) return false;
    *entry = (TransactionMacEntry){
        .header = {DFC_CMD_CLEAR_RECORD_FILE, file_number},
        .header_length = TransactionClearRecordHeaderLength,
    };
    return true;
}

static bool entry_reader_id(
    TransactionMacEntry* entry,
    const uint8_t current_reader_id[DFC_TRANSACTION_READER_ID_LENGTH],
    const uint8_t encrypted_previous_reader_id[DFC_TRANSACTION_READER_ID_LENGTH]) {
    if(!entry || !current_reader_id) return false;
    *entry = (TransactionMacEntry){
        .header = {DFC_CMD_COMMIT_READER_ID},
        .header_length = TransactionReaderIdHeaderLength,
        .data = encrypted_previous_reader_id,
        .data_length = encrypted_previous_reader_id ? DFC_TRANSACTION_READER_ID_LENGTH : 0,
    };
    memcpy(entry->header + 1, current_reader_id, DFC_TRANSACTION_READER_ID_LENGTH);
    return true;
}

bool dfc_transaction_mac_derive_session_key(
    const uint8_t key[DFC_AES_KEY_LENGTH],
    const uint8_t* uid,
    size_t uid_length,
    uint32_t counter,
    uint8_t session_key[DFC_AES_KEY_LENGTH]) {
    if(!key || !uid || !session_key || counter == 0 ||
       (uid_length != DFC_DESFIRE_UID_SHORT_LEN &&
        uid_length != DFC_TRANSACTION_MAC_UID_MAX_LENGTH)) {
        if(session_key) memset(session_key, 0, DFC_AES_KEY_LENGTH);
        return false;
    }
    uint8_t vector[DFC_AES_KEY_LENGTH] = {
        DFC_TRANSACTION_MAC_DERIVATION_LABEL,
        DFC_DERIVATION_COUNTER_HIGH,
        DFC_DERIVATION_COUNTER_LOW,
        DFC_DERIVED_AES_KEY_LENGTH_HIGH,
        DFC_DERIVED_AES_KEY_LENGTH_LOW};
    dfc_write_uint32_le(vector + DFC_TRANSACTION_VECTOR_COUNTER_OFFSET, counter);
    memcpy(vector + DFC_TRANSACTION_VECTOR_UID_OFFSET, uid, uid_length);
    bool ok = aes_cmac((uint8_t*)key, DFC_AES_KEY_LENGTH, vector, sizeof(vector), session_key);
    dfc_secure_wipe(vector, sizeof(vector));
    if(!ok) memset(session_key, 0, DFC_AES_KEY_LENGTH);
    return ok;
}

void dfc_transaction_mac_accumulator_clear(DfcTransactionMacAccumulator* accumulator) {
    if(accumulator) dfc_secure_wipe(accumulator, sizeof(*accumulator));
}

bool dfc_transaction_mac_accumulator_init(
    DfcTransactionMacAccumulator* accumulator,
    const uint8_t session_key[DFC_AES_KEY_LENGTH]) {
    if(!accumulator) return false;
    dfc_transaction_mac_accumulator_clear(accumulator);
    if(!session_key) return false;
    memcpy(accumulator->session_key, session_key, DFC_AES_KEY_LENGTH);
    accumulator->initialized = true;
    return true;
}

static bool accumulator_push_block(
    DfcTransactionMacAccumulator* accumulator,
    DfcAesCmacContext* context,
    const uint8_t block[TRANSACTION_BLOCK_SIZE],
    uint8_t chained[TRANSACTION_BLOCK_SIZE]) {
    if(accumulator->has_pending) {
        for(size_t index = 0; index < TRANSACTION_BLOCK_SIZE; index++)
            chained[index] = accumulator->chain[index] ^ accumulator->pending[index];
        if(!dfc_crypto_aes_block_encrypt(&context->cipher, chained, accumulator->chain))
            return false;
    }
    memcpy(accumulator->pending, block, TRANSACTION_BLOCK_SIZE);
    accumulator->has_pending = true;
    return true;
}

static bool accumulator_add_segments_and_zeroes(
    DfcTransactionMacAccumulator* accumulator,
    const DfcCryptoSegment* segments,
    size_t segment_count,
    size_t zero_length) {
    if(!accumulator || !accumulator->initialized || !segments || segment_count == 0) return false;

    DfcTransactionMacAccumulator candidate = *accumulator;
    DfcAesCmacContext context;
    uint8_t block[DFC_AES_KEY_LENGTH] = {0};
    uint8_t chained[DFC_AES_KEY_LENGTH] = {0};
    size_t block_length = 0;
    size_t total_length = zero_length;
    bool ok = false;

    if(!dfc_aes_cmac_context_init(&context, candidate.session_key, sizeof(candidate.session_key)))
        goto cleanup;
    for(size_t segment_index = 0; segment_index < segment_count; segment_index++) {
        const uint8_t* data = segments[segment_index].data;
        size_t remaining = segments[segment_index].length;
        if((remaining && !data) || remaining > SIZE_MAX - total_length) goto clear_context;
        total_length += remaining;
        while(remaining) {
            size_t take = sizeof(block) - block_length;
            if(take > remaining) take = remaining;
            memcpy(block + block_length, data, take);
            block_length += take;
            data += take;
            remaining -= take;
            if(block_length != sizeof(block)) continue;
            if(!accumulator_push_block(&candidate, &context, block, chained)) goto clear_context;
            block_length = 0;
        }
    }
    while(zero_length) {
        size_t take = DFC_MIN(sizeof(block) - block_length, zero_length);
        memset(block + block_length, 0, take);
        block_length += take;
        zero_length -= take;
        if(block_length != sizeof(block)) continue;
        if(!accumulator_push_block(&candidate, &context, block, chained)) goto clear_context;
        block_length = 0;
    }
    if(total_length == 0 || block_length != 0 || total_length % DFC_AES_KEY_LENGTH != 0)
        goto clear_context;
    *accumulator = candidate;
    ok = true;

clear_context:
    dfc_aes_cmac_context_clear(&context);
cleanup:
    dfc_secure_wipe(&candidate, sizeof(candidate));
    dfc_secure_wipe(block, sizeof(block));
    dfc_secure_wipe(chained, sizeof(chained));
    return ok;
}

static bool accumulator_add_segments(
    DfcTransactionMacAccumulator* accumulator,
    const DfcCryptoSegment* segments,
    size_t segment_count) {
    return accumulator_add_segments_and_zeroes(accumulator, segments, segment_count, 0);
}

static bool accumulator_add_entry(
    DfcTransactionMacAccumulator* accumulator,
    const TransactionMacEntry* entry) {
    uint8_t padded_header[2 * DFC_AES_KEY_LENGTH] = {0};
    static const uint8_t zero_padding[DFC_AES_KEY_LENGTH] = {0};
    size_t padded_header_length;
    size_t padded_data_length;
    if(!entry_is_valid(entry) || !padded_length(entry->header_length, &padded_header_length) ||
       !padded_length(entry->data_length, &padded_data_length) ||
       padded_header_length > sizeof(padded_header))
        return false;
    memcpy(padded_header, entry->header, entry->header_length);
    const DfcCryptoSegment segments[] = {
        {.data = padded_header, .length = padded_header_length},
        {.data = entry->data, .length = entry->data_length},
        {.data = zero_padding, .length = padded_data_length - entry->data_length},
    };
    bool ok =
        accumulator_add_segments(accumulator, segments, sizeof(segments) / sizeof(segments[0]));
    dfc_secure_wipe(padded_header, sizeof(padded_header));
    return ok;
}

bool dfc_transaction_mac_accumulator_add_data(
    DfcTransactionMacAccumulator* accumulator,
    uint8_t command,
    uint8_t file_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_length) {
    TransactionMacEntry entry;
    return entry_data(&entry, command, file_number, offset, length, data, data_length) &&
           accumulator_add_entry(accumulator, &entry);
}

bool dfc_transaction_mac_accumulator_add_zero_data(
    DfcTransactionMacAccumulator* accumulator,
    uint8_t command,
    uint8_t file_number,
    uint32_t offset,
    uint32_t length,
    size_t data_length) {
    TransactionMacEntry entry;
    if(!entry_data(&entry, command, file_number, offset, length, NULL, 0)) return false;
    uint8_t padded_header[DFC_AES_KEY_LENGTH] = {0};
    memcpy(padded_header, entry.header, entry.header_length);
    size_t padded_data_length;
    if(!padded_length(data_length, &padded_data_length)) return false;
    DfcCryptoSegment segment = {.data = padded_header, .length = sizeof(padded_header)};
    bool ok = accumulator_add_segments_and_zeroes(accumulator, &segment, 1, padded_data_length);
    dfc_secure_wipe(&entry, sizeof(entry));
    dfc_secure_wipe(padded_header, sizeof(padded_header));
    return ok;
}

bool dfc_transaction_mac_accumulator_add_record_update(
    DfcTransactionMacAccumulator* accumulator,
    uint8_t command,
    uint8_t file_number,
    uint32_t record_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_length) {
    TransactionMacEntry entry;
    return entry_record_update(
               &entry, command, file_number, record_number, offset, length, data, data_length) &&
           accumulator_add_entry(accumulator, &entry);
}

bool dfc_transaction_mac_accumulator_add_value(
    DfcTransactionMacAccumulator* accumulator,
    uint8_t command,
    uint8_t file_number,
    const uint8_t value[4]) {
    TransactionMacEntry entry;
    return entry_value(&entry, command, file_number, value) &&
           accumulator_add_entry(accumulator, &entry);
}

bool dfc_transaction_mac_accumulator_add_reader_id(
    DfcTransactionMacAccumulator* accumulator,
    const uint8_t current_reader_id[DFC_TRANSACTION_READER_ID_LENGTH],
    const uint8_t encrypted_previous_reader_id[DFC_TRANSACTION_READER_ID_LENGTH]) {
    TransactionMacEntry entry;
    return entry_reader_id(&entry, current_reader_id, encrypted_previous_reader_id) &&
           accumulator_add_entry(accumulator, &entry);
}

bool dfc_transaction_mac_accumulator_add_clear_record(
    DfcTransactionMacAccumulator* accumulator,
    uint8_t file_number) {
    TransactionMacEntry entry;
    return entry_clear_record(&entry, file_number) && accumulator_add_entry(accumulator, &entry);
}

bool dfc_transaction_mac_accumulator_finalize(
    const DfcTransactionMacAccumulator* accumulator,
    uint8_t mac[DFC_AES_CMAC_LENGTH]) {
    if(!mac) return false;
    memset(mac, 0, DFC_AES_CMAC_LENGTH);
    if(!accumulator || !accumulator->initialized || !accumulator->has_pending) return false;

    DfcAesCmacContext context;
    uint8_t final_block[DFC_AES_KEY_LENGTH];
    if(!dfc_aes_cmac_context_init(
           &context, accumulator->session_key, sizeof(accumulator->session_key)))
        return false;
    for(size_t index = 0; index < sizeof(final_block); index++) {
        final_block[index] = accumulator->chain[index] ^ accumulator->pending[index] ^
                             context.subkey1[index];
    }
    bool ok = dfc_crypto_aes_block_encrypt(&context.cipher, final_block, mac);
    dfc_aes_cmac_context_clear(&context);
    dfc_secure_wipe(final_block, sizeof(final_block));
    if(!ok) memset(mac, 0, DFC_AES_CMAC_LENGTH);
    return ok;
}

DfcTransactionMacStatus dfc_transaction_mac_verifier_init(
    DfcTransactionMacVerifier* verifier,
    uint8_t* input,
    size_t input_capacity,
    const uint8_t key[DFC_AES_KEY_LENGTH],
    const uint8_t* uid,
    size_t uid_length,
    uint32_t counter) {
    if(!verifier) return DfcTransactionMacInvalid;
    // The public object may be uninitialized storage. Never inspect a prior
    // pointer here; callers that need input wiping clear an initialized object first.
    dfc_secure_wipe(verifier, sizeof(*verifier));
    if(!input || input_capacity == 0 || !key || !uid || counter == 0 ||
       (uid_length != DFC_DESFIRE_UID_SHORT_LEN &&
        uid_length != DFC_TRANSACTION_MAC_UID_MAX_LENGTH))
        return DfcTransactionMacInvalid;
    verifier->input = input;
    verifier->input_capacity = input_capacity;
    memcpy(verifier->key, key, sizeof(verifier->key));
    memcpy(verifier->uid, uid, uid_length);
    verifier->uid_length = uid_length;
    verifier->counter = counter;
    verifier->lifecycle_cookie = TRANSACTION_VERIFIER_COOKIE;
    verifier->initialized = true;
    return DfcTransactionMacOk;
}

void dfc_transaction_mac_verifier_clear(DfcTransactionMacVerifier* verifier) {
    if(!verifier) return;
    if(verifier->input && verifier->input_length <= verifier->input_capacity)
        dfc_secure_wipe(verifier->input, verifier->input_length);
    dfc_secure_wipe(verifier, sizeof(*verifier));
}

DfcTransactionMacStatus dfc_transaction_mac_add_data(
    DfcTransactionMacVerifier* verifier,
    uint8_t command,
    uint8_t file_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_length) {
    if(!verifier_is_valid(verifier) || !uint24_is_valid(offset) || !uint24_is_valid(length) ||
       (data_length && !data))
        return DfcTransactionMacInvalid;
    switch(command) {
    case DFC_CMD_READ_DATA:
    case DFC_CMD_READ_DATA_ISO:
    case DFC_CMD_WRITE_DATA:
    case DFC_CMD_WRITE_DATA_ISO:
        if(data_length != length) return DfcTransactionMacInvalid;
        break;
    case DFC_CMD_READ_RECORDS:
    case DFC_CMD_READ_RECORDS_ISO:
        break;
    case DFC_CMD_WRITE_RECORD:
    case DFC_CMD_WRITE_RECORD_ISO:
        if(data_length != length) return DfcTransactionMacInvalid;
        break;
    default:
        return DfcTransactionMacInvalid;
    }
    return dfc_transaction_mac_input_add_data(
               verifier->input,
               verifier->input_capacity,
               &verifier->input_length,
               command,
               file_number,
               offset,
               length,
               data,
               data_length) ?
               DfcTransactionMacOk :
               DfcTransactionMacCapacity;
}

bool dfc_transaction_mac_input_add_data(
    uint8_t* input,
    size_t input_capacity,
    size_t* input_length,
    uint8_t command,
    uint8_t file_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_length) {
    TransactionMacEntry entry;
    return entry_data(&entry, command, file_number, offset, length, data, data_length) &&
           append_entry(input, input_capacity, input_length, &entry);
}

DfcTransactionMacStatus dfc_transaction_mac_add_record_update(
    DfcTransactionMacVerifier* verifier,
    uint8_t command,
    uint8_t file_number,
    uint32_t record_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_length) {
    if(!verifier_is_valid(verifier) ||
       (command != DFC_CMD_UPDATE_RECORD && command != DFC_CMD_UPDATE_RECORD_ISO) ||
       !uint24_is_valid(record_number) || !uint24_is_valid(offset) || !uint24_is_valid(length) ||
       data_length != length || (data_length && !data))
        return DfcTransactionMacInvalid;
    return dfc_transaction_mac_input_add_record_update(
               verifier->input,
               verifier->input_capacity,
               &verifier->input_length,
               command,
               file_number,
               record_number,
               offset,
               length,
               data,
               data_length) ?
               DfcTransactionMacOk :
               DfcTransactionMacCapacity;
}

bool dfc_transaction_mac_input_add_record_update(
    uint8_t* input,
    size_t input_capacity,
    size_t* input_length,
    uint8_t command,
    uint8_t file_number,
    uint32_t record_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_length) {
    TransactionMacEntry entry;
    return entry_record_update(
               &entry, command, file_number, record_number, offset, length, data, data_length) &&
           append_entry(input, input_capacity, input_length, &entry);
}

bool dfc_transaction_mac_input_add_value(
    uint8_t* input,
    size_t input_capacity,
    size_t* input_length,
    uint8_t command,
    uint8_t file_number,
    const uint8_t value[4]) {
    TransactionMacEntry entry;
    return entry_value(&entry, command, file_number, value) &&
           append_entry(input, input_capacity, input_length, &entry);
}

DfcTransactionMacStatus dfc_transaction_mac_add_value(
    DfcTransactionMacVerifier* verifier,
    uint8_t command,
    uint8_t file_number,
    uint32_t value) {
    if(!verifier_is_valid(verifier) ||
       (command != DFC_CMD_GET_VALUE && command != DFC_CMD_CREDIT && command != DFC_CMD_DEBIT &&
        command != DFC_CMD_LIMITED_CREDIT))
        return DfcTransactionMacInvalid;
    uint8_t encoded[4];
    dfc_write_uint32_le(encoded, value);
    return dfc_transaction_mac_input_add_value(
               verifier->input,
               verifier->input_capacity,
               &verifier->input_length,
               command,
               file_number,
               encoded) ?
               DfcTransactionMacOk :
               DfcTransactionMacCapacity;
}

DfcTransactionMacStatus
    dfc_transaction_mac_add_clear_record(DfcTransactionMacVerifier* verifier, uint8_t file_number) {
    if(!verifier_is_valid(verifier)) return DfcTransactionMacInvalid;
    return dfc_transaction_mac_input_add_clear_record(
               verifier->input, verifier->input_capacity, &verifier->input_length, file_number) ?
               DfcTransactionMacOk :
               DfcTransactionMacCapacity;
}

bool dfc_transaction_mac_input_add_clear_record(
    uint8_t* input,
    size_t input_capacity,
    size_t* input_length,
    uint8_t file_number) {
    TransactionMacEntry entry;
    return entry_clear_record(&entry, file_number) &&
           append_entry(input, input_capacity, input_length, &entry);
}

bool dfc_transaction_mac_input_add_reader_id(
    uint8_t* input,
    size_t input_capacity,
    size_t* input_length,
    const uint8_t current_reader_id[16],
    const uint8_t encrypted_previous_reader_id[16]) {
    TransactionMacEntry entry;
    return entry_reader_id(&entry, current_reader_id, encrypted_previous_reader_id) &&
           append_entry(input, input_capacity, input_length, &entry);
}

DfcTransactionMacStatus dfc_transaction_mac_add_reader_id(
    DfcTransactionMacVerifier* verifier,
    const uint8_t current_reader_id[DFC_TRANSACTION_READER_ID_LENGTH],
    const uint8_t encrypted_previous_reader_id[DFC_TRANSACTION_READER_ID_LENGTH]) {
    if(!verifier_is_valid(verifier) || !current_reader_id) return DfcTransactionMacInvalid;
    return dfc_transaction_mac_input_add_reader_id(
               verifier->input,
               verifier->input_capacity,
               &verifier->input_length,
               current_reader_id,
               encrypted_previous_reader_id) ?
               DfcTransactionMacOk :
               DfcTransactionMacCapacity;
}

DfcTransactionMacStatus dfc_transaction_mac_verify(
    const DfcTransactionMacVerifier* verifier,
    const uint8_t mac[DFC_WIRE_MAC_LENGTH],
    bool* verified) {
    if(verified) *verified = false;
    if(!verifier_is_valid(verifier) || verifier->input_length == 0 || !mac || !verified)
        return DfcTransactionMacInvalid;
    uint8_t session_key[DFC_AES_KEY_LENGTH] = {0};
    uint8_t full_mac[DFC_AES_CMAC_LENGTH] = {0};
    uint8_t wire_mac[DFC_WIRE_MAC_LENGTH] = {0};
    bool ok =
        dfc_transaction_mac_derive_session_key(
            verifier->key, verifier->uid, verifier->uid_length, verifier->counter, session_key) &&
        aes_cmac(
            session_key, sizeof(session_key), verifier->input, verifier->input_length, full_mac);
    if(ok) {
        dfc_truncate_aes_wire_mac(full_mac, wire_mac);
        *verified = dfc_ct_equal(wire_mac, mac, sizeof(wire_mac));
    }
    dfc_secure_wipe(session_key, sizeof(session_key));
    dfc_secure_wipe(full_mac, sizeof(full_mac));
    dfc_secure_wipe(wire_mac, sizeof(wire_mac));
    return ok ? DfcTransactionMacOk : DfcTransactionMacCryptoFailed;
}
