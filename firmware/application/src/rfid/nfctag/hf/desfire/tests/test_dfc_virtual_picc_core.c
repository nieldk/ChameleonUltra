#include <stdio.h>
#include "dfc_virtual_picc_test_helpers.h"
#include <stdlib.h>
#include "dfc_port_host.h"
#include "dfc_emulator_i.h"

typedef struct {
    const void* target;
    size_t length;
    bool observed;
    bool zeroed;
} VirtualPiccFreeAudit;

static void observe_virtual_picc_free(const void* pointer, void* context) {
    VirtualPiccFreeAudit* audit = context;
    if(pointer != audit->target) return;
    audit->observed = true;
    audit->zeroed = true;
    const uint8_t* bytes = pointer;
    for(size_t i = 0; i < audit->length; i++) {
        if(bytes[i] != 0) audit->zeroed = false;
    }
}

static void assert_zeroed_bytes(const uint8_t* bytes, size_t length) {
    for(size_t i = 0; i < length; i++)
        munit_assert_uint8(bytes[i], ==, 0);
}

static DfcVirtualPiccStatus exchange_wrapped_data_read(
    DfcVirtualPiccSession* session,
    uint8_t instruction,
    uint8_t file_number,
    uint32_t offset,
    uint32_t length,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len) {
    const uint8_t command[] = {
        DFC_ISO7816_CLA_WRAPPER,
        instruction,
        0,
        0,
        7,
        file_number,
        (uint8_t)offset,
        (uint8_t)(offset >> 8),
        (uint8_t)(offset >> 16),
        (uint8_t)length,
        (uint8_t)(length >> 8),
        (uint8_t)(length >> 16),
        0,
    };
    return dfc_virtual_picc_iso_dep_exchange(
        session, command, sizeof(command), response, response_capacity, response_len);
}

static void activate_iso_dep(
    DfcVirtualPiccSession* session,
    uint8_t cid,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len) {
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    const uint8_t rats[] = {0xE0, (uint8_t)(0x80 | cid)};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, rats, sizeof(rats), response, response_capacity, response_len),
        ==,
        DfcVirtualPiccStatusOk);
}

static void assert_iso_abort_preflight_is_atomic(DfcVirtualPiccSession* session) {
    const uint8_t read_binary[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 1};
    uint8_t response[1];
    size_t response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, read_binary, sizeof(read_binary), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
}

static void assert_iso_abort_and_no_native_continuation(DfcVirtualPiccSession* session) {
    const uint8_t read_binary[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 1};
    const uint8_t additional_frame[] = {
        DFC_ISO7816_CLA_WRAPPER, DFC_CMD_ADDITIONAL_FRAME, 0, 0, 0};
    uint8_t response[2];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, read_binary, sizeof(read_binary), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(
        2,
        response,
        ((uint8_t[]){
            DFC_ISO7816_SW_CONDITIONS_NOT_SATISFIED_HI,
            DFC_ISO7816_SW_CONDITIONS_NOT_SATISFIED_LO}));
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            additional_frame,
            sizeof(additional_frame),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_ILLEGAL_COMMAND_CODE}));
}

static void add_applications_for_chained_listing(DfcCredential* credential) {
    for(size_t i = credential->num_apps; i < 24; i++) {
        const uint8_t aid[3] = {(uint8_t)i, 0xA5, 0x5A};
        munit_assert_not_null(dfc_credential_create_application_desfire_order(
            credential, aid, 0x0F, DFC_KEY_TYPE_AES | 1));
    }
}

static void start_application_id_response_chain(
    DfcVirtualPiccSession* session,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len) {
    const uint8_t get_application_ids[] = {
        DFC_ISO7816_CLA_WRAPPER, DFC_CMD_GET_APPLICATION_IDS, 0, 0, 0};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            get_application_ids,
            sizeof(get_application_ids),
            response,
            response_capacity,
            response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint8(response[*response_len - 1], ==, DFC_CMD_ADDITIONAL_FRAME);
    munit_assert_size(
        session->emulator->pending_chain_len, >, session->emulator->pending_chain_offset);
}

static MunitResult
    test_iso_command_aborts_native_response_chain(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    credential.card.generation = DfcGenerationEv3;
    add_applications_for_chained_listing(&credential);
    DfcFile* file = &credential.files[0];
    file->access_rights = 0xEEEE;
    dfc_file_sdm_flag_set(file, DfcSdmFlagEnabled, true);
    file->state.data.sdm_read_counter = 41;

    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    // The chain is started at card level, where GetApplicationIDs is allowed.
    uint8_t response[128];
    size_t response_len = 0;
    start_application_id_response_chain(session, response, sizeof(response), &response_len);

    const size_t pending_len = session->emulator->pending_chain_len;
    const size_t pending_offset = session->emulator->pending_chain_offset;
    const uint32_t sdm_counter = file->state.data.sdm_read_counter;
    const bool sdm_cache_valid = session->emulator->sdm_read_cache_valid;
    uint8_t sdm_cache[DFC_SDM_READ_CACHE_SIZE];
    memcpy(sdm_cache, session->emulator->sdm_read_cache, sizeof(sdm_cache));
    const uint8_t read_binary[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 3};

    assert_iso_abort_preflight_is_atomic(session);
    munit_assert_size(session->emulator->pending_chain_len, ==, pending_len);
    munit_assert_size(session->emulator->pending_chain_offset, ==, pending_offset);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, sdm_counter);
    munit_assert_true(session->emulator->sdm_read_cache_valid == sdm_cache_valid);
    munit_assert_memory_equal(sizeof(sdm_cache), session->emulator->sdm_read_cache, sdm_cache);

    assert_iso_abort_and_no_native_continuation(session);
    munit_assert_size(session->emulator->pending_chain_len, ==, 0);
    assert_zeroed_bytes(session->emulator->pending_chain, pending_len);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, sdm_counter);
    munit_assert_true(session->emulator->sdm_read_cache_valid == sdm_cache_valid);
    munit_assert_memory_equal(sizeof(sdm_cache), session->emulator->sdm_read_cache, sdm_cache);

    // With the chain gone, read the SDM file. The current file is only honoured
    // inside the application that holds it, so select that application first.
    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    session->emulator->selected_app_index = file->app_index;
    session->iso_file_selected = true;
    session->iso_file_index = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, read_binary, sizeof(read_binary), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 5);
    munit_assert_memory_equal(2, response + 3, ((uint8_t[]){0x90, 0x00}));
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, sdm_counter + 1);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_sdm_read_family_and_boundary_lifecycle(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    credential.card.generation = DfcGenerationEv3;
    DfcFile* file = &credential.files[0];
    file->access_rights = 0xEEEE;
    munit_assert_true(dfc_file_resize(&credential, file, 100));
    uint8_t* file_data = dfc_file_data(&credential, file);
    for(size_t index = 0; index < file->data_len; index++)
        file_data[index] = (uint8_t)index;
    dfc_file_sdm_flag_set(file, DfcSdmFlagEnabled, true);
    DfcFile* non_sdm_file = dfc_credential_create_file(&credential, file->app_index, 1);
    munit_assert_not_null(non_sdm_file);
    non_sdm_file->type = DFC_FILE_TYPE_STANDARD_DATA;
    non_sdm_file->comm_settings = DFC_COMM_PLAIN;
    non_sdm_file->access_rights = 0xEEEE;
    munit_assert_true(dfc_file_resize(&credential, non_sdm_file, 4));
    memset(dfc_file_data(&credential, non_sdm_file), 0xA5, non_sdm_file->data_len);
    DfcFile* record_file = dfc_credential_create_file(&credential, file->app_index, 2);
    munit_assert_not_null(record_file);
    record_file->type = DFC_FILE_TYPE_LINEAR_RECORD;
    record_file->comm_settings = DFC_COMM_PLAIN;
    record_file->access_rights = 0xEEEE;
    record_file->state.record.size = 2;
    record_file->state.record.max_records = 2;
    record_file->state.record.count = 1;
    munit_assert_true(dfc_file_resize(&credential, record_file, 4));
    memset(dfc_file_data(&credential, record_file), 0x5A, record_file->data_len);

    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    session->emulator->selected_app_index = file->app_index;
    session->iso_file_selected = true;
    session->iso_file_index = 0;
    uint8_t response[DFC_EMULATOR_CHAIN_BUFFER_SIZE];
    size_t response_len = 0;

    file->state.data.sdm_read_counter = 10;
    dfc_emulator_retire_sdm_read_cache(session->emulator);
    munit_assert_int(
        exchange_wrapped_data_read(
            session,
            DFC_CMD_READ_DATA,
            file->number,
            0,
            1,
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 11);
    munit_assert_int(
        exchange_wrapped_data_read(
            session,
            DFC_CMD_READ_DATA,
            file->number,
            1,
            1,
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 11);

    munit_assert_int(
        exchange_wrapped_data_read(
            session,
            DFC_CMD_READ_DATA_ISO,
            file->number,
            2,
            1,
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 12);
    munit_assert_int(
        exchange_wrapped_data_read(
            session,
            DFC_CMD_READ_DATA,
            file->number,
            3,
            1,
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 13);

    const uint8_t get_file_ids[] = {DFC_ISO7816_CLA_WRAPPER, DFC_CMD_GET_FILE_IDS, 0, 0, 0};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, get_file_ids, sizeof(get_file_ids), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_false(session->emulator->sdm_read_cache_valid);
    munit_assert_int(
        exchange_wrapped_data_read(
            session,
            DFC_CMD_READ_DATA,
            file->number,
            4,
            1,
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 14);

    const uint8_t iso_read_0[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 1};
    const uint8_t iso_read_1[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 1, 1};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, iso_read_0, sizeof(iso_read_0), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 15);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, iso_read_1, sizeof(iso_read_1), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 15);
    munit_assert_int(
        exchange_wrapped_data_read(
            session,
            DFC_CMD_READ_DATA,
            file->number,
            5,
            1,
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 16);

    dfc_emulator_retire_sdm_read_cache(session->emulator);
    file->state.data.sdm_read_counter = 20;
    munit_assert_int(
        exchange_wrapped_data_read(
            session,
            DFC_CMD_READ_DATA,
            file->number,
            0,
            0,
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint8(response[response_len - 1], ==, DFC_CMD_ADDITIONAL_FRAME);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 21);
    const uint8_t additional_frame[] = {
        DFC_ISO7816_CLA_WRAPPER, DFC_CMD_ADDITIONAL_FRAME, 0, 0, 0};
    while(response[response_len - 1] == DFC_CMD_ADDITIONAL_FRAME) {
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                session,
                additional_frame,
                sizeof(additional_frame),
                response,
                sizeof(response),
                &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_uint32(file->state.data.sdm_read_counter, ==, 21);
    }

    dfc_emulator_retire_sdm_read_cache(session->emulator);
    file->state.data.sdm_read_counter = 30;
    response_len = SIZE_MAX;
    munit_assert_int(
        exchange_wrapped_data_read(
            session, DFC_CMD_READ_DATA_ISO, file->number, 0, 0, response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 31);
    munit_assert_int(
        exchange_wrapped_data_read(
            session,
            DFC_CMD_READ_DATA_ISO,
            file->number,
            0,
            0,
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 31);

    /* A different, non-SDM ISO data file is a logical-command boundary. */
    dfc_emulator_retire_sdm_read_cache(session->emulator);
    file->state.data.sdm_read_counter = 40;
    munit_assert_int(
        exchange_wrapped_data_read(
            session,
            DFC_CMD_READ_DATA,
            file->number,
            0,
            1,
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 41);
    session->iso_file_index = (size_t)(non_sdm_file - credential.files);
    response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, iso_read_0, sizeof(iso_read_0), response, 2, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_true(session->emulator->sdm_read_cache_valid);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, iso_read_0, sizeof(iso_read_0), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_false(session->emulator->sdm_read_cache_valid);
    munit_assert_int(
        exchange_wrapped_data_read(
            session,
            DFC_CMD_READ_DATA,
            file->number,
            0,
            1,
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 42);

    /* READ RECORD also retires an unrelated SDM data-file continuation. */
    session->iso_file_index = (size_t)(record_file - credential.files);
    const uint8_t iso_read_record[] = {0, DFC_ISO7816_INS_READ_RECORD, 1, 0x04, 2};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            iso_read_record,
            sizeof(iso_read_record),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_false(session->emulator->sdm_read_cache_valid);
    munit_assert_int(
        exchange_wrapped_data_read(
            session,
            DFC_CMD_READ_DATA,
            file->number,
            0,
            1,
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 43);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_iso_command_aborts_pending_native_authentication(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    const uint8_t active_key[16] = {0xA7};
    session->emulator->secure_messaging =
        dfc_secure_messaging_alloc(DFC_CMD_AUTHENTICATE_ISO, active_key, sizeof(active_key), NULL);
    munit_assert_not_null(session->emulator->secure_messaging);
    DfcSecureMessaging* retained_secure_messaging = session->emulator->secure_messaging;
    session->emulator->auth_cipher = DFC_CMD_AUTHENTICATE_ISO;
    session->emulator->auth_key_no = 1;

    uint8_t response[64];
    size_t response_len = 0;
    const uint8_t authenticate[] = {
        DFC_ISO7816_CLA_WRAPPER, DFC_CMD_AUTHENTICATE_LEGACY, 0, 0, 1, 0, 0};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, authenticate, sizeof(authenticate), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint8(response[response_len - 1], ==, DFC_CMD_ADDITIONAL_FRAME);
    munit_assert_true(session->emulator->awaiting_step2);

    assert_iso_abort_preflight_is_atomic(session);
    munit_assert_true(session->emulator->awaiting_step2);
    assert_iso_abort_and_no_native_continuation(session);
    munit_assert_false(session->emulator->awaiting_step2);
    munit_assert_uint8(session->emulator->pending_auth_cipher, ==, 0);
    munit_assert_ptr_equal(session->emulator->secure_messaging, retained_secure_messaging);
    munit_assert_false(dfc_emulator_native_authentication_active(session->emulator));
    munit_assert_uint8(session->emulator->auth_cipher, ==, 0);
    munit_assert_uint8(session->emulator->auth_key_no, ==, 0);
    assert_zeroed_bytes(
        (const uint8_t*)retained_secure_messaging, sizeof(*retained_secure_messaging));
    munit_assert_memory_equal(
        sizeof(session->emulator->pending_authentication.native.random_b),
        session->emulator->pending_authentication.native.random_b,
        ((uint8_t[sizeof(session->emulator->pending_authentication.native.random_b)]){0}));
    munit_assert_memory_equal(
        sizeof(session->emulator->pending_authentication.native.encrypted_random_b),
        session->emulator->pending_authentication.native.encrypted_random_b,
        ((uint8_t[sizeof(session->emulator->pending_authentication.native.encrypted_random_b)]){
            0}));

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_iso_command_aborts_incoming_native_write_chain(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcFile* file = &credential.files[0];
    file->comm_settings = DFC_COMM_PLAIN;
    file->access_rights = 0xEEEE;
    munit_assert_true(dfc_file_resize(&credential, file, 100));

    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    uint8_t response[64];
    size_t response_len = 0;
    const uint8_t select[] = {
        DFC_ISO7816_CLA_WRAPPER, DFC_CMD_SELECT_APPLICATION, 0, 0, 3, 0x4F, 0x49, 0xD3, 0};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select, sizeof(select), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));

    DfcCredential* credential_before = dfc_credential_alloc();
    munit_assert_not_null(credential_before);
    dfc_credential_copy_model(credential_before, &credential);
    const size_t emulator_allocations = dfc_host_allocation_count(DfcAllocEmulator);
    const size_t chain_allocations = dfc_host_allocation_count(DfcAllocCommandChain);
    uint8_t first[6 + DFC_EV1_MAX_FRAME_PAYLOAD] = {0};
    first[0] = DFC_ISO7816_CLA_WRAPPER;
    first[1] = DFC_CMD_WRITE_DATA;
    first[4] = DFC_EV1_MAX_FRAME_PAYLOAD;
    first[5] = file->number;
    first[9] = 100;
    for(size_t i = 0; i < 52; i++)
        first[12 + i] = (uint8_t)(i + 1);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, first, sizeof(first), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_CMD_ADDITIONAL_FRAME}));
    munit_assert_size(dfc_host_allocation_count(DfcAllocEmulator), ==, emulator_allocations);
    munit_assert_size(dfc_host_allocation_count(DfcAllocCommandChain), ==, chain_allocations + 1);
    munit_assert_true(session->emulator->command_chain_active);
    munit_assert_memory_equal(sizeof(credential), &credential, credential_before);

    VirtualPiccFreeAudit audit = {
        .target = session->emulator->command_chain,
        .length = session->emulator->command_chain_len,
    };
    const uint8_t* command_chain = session->emulator->command_chain;
    const size_t command_chain_len = session->emulator->command_chain_len;
    uint8_t command_chain_before[DFC_EV1_MAX_FRAME_PAYLOAD + 1];
    munit_assert_size(command_chain_len, <=, sizeof(command_chain_before));
    memcpy(command_chain_before, command_chain, command_chain_len);
    assert_iso_abort_preflight_is_atomic(session);
    munit_assert_true(session->emulator->command_chain_active);
    munit_assert_ptr_equal(session->emulator->command_chain, command_chain);
    munit_assert_size(session->emulator->command_chain_len, ==, command_chain_len);
    munit_assert_memory_equal(
        command_chain_len, session->emulator->command_chain, command_chain_before);
    munit_assert_memory_equal(sizeof(credential), &credential, credential_before);

    dfc_host_set_free_observer(observe_virtual_picc_free, &audit);
    assert_iso_abort_and_no_native_continuation(session);
    dfc_host_set_free_observer(NULL, NULL);
    munit_assert_true(audit.observed);
    munit_assert_true(audit.zeroed);
    munit_assert_false(session->emulator->command_chain_active);
    munit_assert_null(session->emulator->command_chain);
    munit_assert_memory_equal(sizeof(credential), &credential, credential_before);

    dfc_credential_free(credential_before);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_iso_command_aborts_native_continuation_states(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    enum {
        PendingGetVersion,
        PendingDfNames,
#if DFC_ENABLE_DELEGATED_APPLICATIONS
        PendingDelegatedCreation,
#endif
        PendingContinuationCount,
    };
    const uint8_t commands[][5] = {
        {DFC_ISO7816_CLA_WRAPPER, DFC_CMD_GET_VERSION, 0, 0, 0},
        {DFC_ISO7816_CLA_WRAPPER, DFC_CMD_GET_DF_NAMES, 0, 0, 0},
    };
    for(size_t kind = PendingGetVersion; kind < PendingContinuationCount; kind++) {
        DfcCredential credential;
        load_standard_credential(&credential);
        if(kind == PendingDfNames) {
            credential.picc_key_settings_1 |= DFC_KS1_FREE_DIRECTORY_ACCESS;
            credential.apps[0].has_iso_file_id = true;
            credential.apps[0].iso_file_id = 0x1001;
            const uint8_t aid[3] = {1, 2, 3};
            DfcApplication* second = dfc_credential_create_application_desfire_order(
                &credential, aid, 0x0F, DFC_KEY_TYPE_AES | 1);
            munit_assert_not_null(second);
            second->has_iso_file_id = true;
            second->iso_file_id = 0x1002;
            second->iso_aid[0] = 0xA5;
            second->iso_aid_len = 1;
        }

        DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
        munit_assert_not_null(session);
        DfcVirtualPiccActivation activation;
        munit_assert_int(
            dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
        uint8_t response[64];
        size_t response_len = 0;
        if(kind <= PendingDfNames) {
            munit_assert_int(
                dfc_virtual_picc_iso_dep_exchange(
                    session,
                    commands[kind],
                    sizeof(commands[kind]),
                    response,
                    sizeof(response),
                    &response_len),
                ==,
                DfcVirtualPiccStatusOk);
            munit_assert_uint8(response[response_len - 1], ==, DFC_CMD_ADDITIONAL_FRAME);
        }
        if(kind == PendingGetVersion) {
            munit_assert_size(session->emulator->get_version_frame, !=, 0);
        } else if(kind == PendingDfNames) {
            munit_assert_true(session->emulator->df_names_pending);
            munit_assert_size(session->emulator->df_names_next, ==, 1);
#if DFC_ENABLE_DELEGATED_APPLICATIONS
        } else {
            session->emulator->delegated_creation_pending = true;
            session->emulator->delegated_creation_header_length =
                sizeof(session->emulator->delegated_creation_header) - 3;
            memset(
                session->emulator->delegated_creation_header,
                0xD5,
                sizeof(session->emulator->delegated_creation_header));
#endif
        }

        const size_t scratch_len = 19;
        memset(session->emulator->pending_chain, 0xC7, scratch_len);
        session->emulator->pending_chain_len = scratch_len;
        session->emulator->pending_chain_offset = scratch_len;
        assert_iso_abort_preflight_is_atomic(session);
        if(kind == PendingGetVersion) {
            munit_assert_size(session->emulator->get_version_frame, !=, 0);
        } else if(kind == PendingDfNames) {
            munit_assert_true(session->emulator->df_names_pending);
            munit_assert_size(session->emulator->df_names_next, ==, 1);
#if DFC_ENABLE_DELEGATED_APPLICATIONS
        } else {
            munit_assert_true(session->emulator->delegated_creation_pending);
            munit_assert_size(
                session->emulator->delegated_creation_header_length,
                ==,
                sizeof(session->emulator->delegated_creation_header) - 3);
            munit_assert_uint8(session->emulator->delegated_creation_header[0], ==, 0xD5);
#endif
        }
        for(size_t i = 0; i < scratch_len; i++)
            munit_assert_uint8(session->emulator->pending_chain[i], ==, 0xC7);

        assert_iso_abort_and_no_native_continuation(session);
        munit_assert_size(session->emulator->get_version_frame, ==, 0);
        munit_assert_false(session->emulator->df_names_pending);
        munit_assert_size(session->emulator->df_names_next, ==, 0);
        munit_assert_size(session->emulator->pending_chain_len, ==, 0);
        assert_zeroed_bytes(session->emulator->pending_chain, scratch_len);
#if DFC_ENABLE_DELEGATED_APPLICATIONS
        if(kind == PendingDelegatedCreation) {
            munit_assert_false(session->emulator->delegated_creation_pending);
            munit_assert_size(session->emulator->delegated_creation_header_length, ==, 0);
            assert_zeroed_bytes(
                session->emulator->delegated_creation_header,
                sizeof(session->emulator->delegated_creation_header));
        }
#endif

        dfc_virtual_picc_session_free(session);
    }
    return MUNIT_OK;
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING
static MunitResult test_iso_command_aborts_ev2_first_and_non_first(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    const uint8_t authenticate_first[] = {
        DFC_ISO7816_CLA_WRAPPER, DFC_CMD_AUTHENTICATE_EV2_FIRST, 0, 0, 2, 0, 0, 0};
    const uint8_t authenticate_non_first[] = {
        DFC_ISO7816_CLA_WRAPPER, DFC_CMD_AUTHENTICATE_EV2_NON_FIRST, 0, 0, 1, 0, 0};
    for(size_t non_first = 0; non_first < 2; non_first++) {
        DfcCredential credential;
        load_standard_credential(&credential);
        credential.card.generation = DfcGenerationEv3;
        credential.picc_key_settings_2 = DFC_KEY_TYPE_AES | 1;
        credential.picc_has_auth_commands = false;
        munit_assert_true(dfc_credential_keys_resize(&credential, NULL, 1, DFC_AES_KEY_LENGTH));
        memset(dfc_credential_key(&credential, NULL, 0), 0x11, DFC_AES_KEY_LENGTH);

        DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
        munit_assert_not_null(session);
        DfcVirtualPiccActivation activation;
        munit_assert_int(
            dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
        DfcEmulator* emulator = session->emulator;
        emulator->ev2_session_active = true;
        emulator->ev2_authenticated_key_no = 4;
        emulator->ev2_command_counter = 0x1234;
        memset(
            emulator->ev2_session_encryption_key,
            0x51,
            sizeof(emulator->ev2_session_encryption_key));
        memset(emulator->ev2_session_mac_key, 0x52, sizeof(emulator->ev2_session_mac_key));
        memset(
            emulator->ev2_transaction_identifier,
            0x53,
            sizeof(emulator->ev2_transaction_identifier));
        memset(emulator->ev2_card_capabilities, 0x54, sizeof(emulator->ev2_card_capabilities));
        memset(emulator->ev2_reader_capabilities, 0x55, sizeof(emulator->ev2_reader_capabilities));

        const uint8_t* authenticate = non_first ? authenticate_non_first : authenticate_first;
        const size_t authenticate_len = non_first ? sizeof(authenticate_non_first) :
                                                    sizeof(authenticate_first);
        uint8_t response[64];
        size_t response_len = 0;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                session, authenticate, authenticate_len, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_uint8(response[response_len - 1], ==, DFC_CMD_ADDITIONAL_FRAME);
        munit_assert_true(emulator->ev2_authentication_pending);
        munit_assert_true(emulator->ev2_authentication_non_first == (non_first != 0));
        munit_assert_uint8(emulator->pending_authentication.ev2.static_key[0], ==, 0x11);
        munit_assert_false(emulator->ev2_session_active);
        munit_assert_uint8(emulator->ev2_authenticated_key_no, ==, 0);
        munit_assert_uint16(emulator->ev2_command_counter, ==, non_first ? 0x1234 : 0);
        assert_zeroed_bytes(
            emulator->ev2_session_encryption_key, sizeof(emulator->ev2_session_encryption_key));
        assert_zeroed_bytes(emulator->ev2_session_mac_key, sizeof(emulator->ev2_session_mac_key));
        if(non_first) {
            munit_assert_uint8(emulator->ev2_transaction_identifier[0], ==, 0x53);
            munit_assert_uint8(emulator->ev2_card_capabilities[0], ==, 0x54);
            munit_assert_uint8(emulator->ev2_reader_capabilities[0], ==, 0x55);
        } else {
            assert_zeroed_bytes(
                emulator->ev2_transaction_identifier,
                sizeof(emulator->ev2_transaction_identifier));
            assert_zeroed_bytes(
                emulator->ev2_card_capabilities, sizeof(emulator->ev2_card_capabilities));
            assert_zeroed_bytes(
                emulator->ev2_reader_capabilities, sizeof(emulator->ev2_reader_capabilities));
        }

        uint8_t pending_random[DFC_EV2_RANDOM_LENGTH];
        uint8_t pending_transaction_identifier[DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH];
        memcpy(
            pending_random, emulator->pending_authentication.ev2.random_b, sizeof(pending_random));
        memcpy(
            pending_transaction_identifier,
            emulator->pending_authentication.ev2.transaction_identifier,
            sizeof(pending_transaction_identifier));
        assert_iso_abort_preflight_is_atomic(session);
        munit_assert_true(emulator->ev2_authentication_pending);
        munit_assert_memory_equal(
            sizeof(pending_random), emulator->pending_authentication.ev2.random_b, pending_random);
        munit_assert_memory_equal(
            sizeof(pending_transaction_identifier),
            emulator->pending_authentication.ev2.transaction_identifier,
            pending_transaction_identifier);

        assert_iso_abort_and_no_native_continuation(session);
        munit_assert_false(emulator->ev2_authentication_pending);
        munit_assert_false(emulator->ev2_authentication_non_first);
        munit_assert_uint8(emulator->ev2_pending_authenticated_key_no, ==, 0);
        assert_zeroed_bytes(
            emulator->pending_authentication.ev2.static_key,
            sizeof(emulator->pending_authentication.ev2.static_key));
        assert_zeroed_bytes(
            emulator->pending_authentication.ev2.random_b,
            sizeof(emulator->pending_authentication.ev2.random_b));
        assert_zeroed_bytes(
            emulator->pending_authentication.ev2.transaction_identifier,
            sizeof(emulator->pending_authentication.ev2.transaction_identifier));
        assert_zeroed_bytes(
            emulator->pending_authentication.ev2.card_capabilities,
            sizeof(emulator->pending_authentication.ev2.card_capabilities));
        assert_zeroed_bytes(
            emulator->pending_authentication.ev2.reader_capabilities,
            sizeof(emulator->pending_authentication.ev2.reader_capabilities));
        assert_zeroed_bytes(
            emulator->ev2_transaction_identifier, sizeof(emulator->ev2_transaction_identifier));
        assert_zeroed_bytes(
            emulator->ev2_card_capabilities, sizeof(emulator->ev2_card_capabilities));
        assert_zeroed_bytes(
            emulator->ev2_reader_capabilities, sizeof(emulator->ev2_reader_capabilities));

        dfc_virtual_picc_session_free(session);
    }
    return MUNIT_OK;
}
#endif

#if DFC_ENABLE_VIRTUAL_CARD
static MunitResult test_virtual_card_select_does_not_abort_native_response_chain(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    static const uint8_t installation_id[] = {0x11, 0x22, 0x33};
    DfcCredential credential;
    load_standard_credential(&credential);
    credential.card.generation = DfcGenerationEv3;
    add_applications_for_chained_listing(&credential);
    credential.virtual_card_configured = true;
    credential.virtual_card_authentication_mandatory = true;
    memcpy(credential.virtual_card_installation_id, installation_id, sizeof(installation_id));
    credential.virtual_card_installation_id_len = sizeof(installation_id);
    memcpy(credential.virtual_card_uid, credential.uid, credential.uid_len);
    credential.virtual_card_uid_len = credential.uid_len;

    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    uint8_t response[128];
    size_t response_len = 0;
    start_application_id_response_chain(session, response, sizeof(response), &response_len);
    const size_t pending_len = session->emulator->pending_chain_len;
    const size_t pending_offset = session->emulator->pending_chain_offset;

    const uint8_t select_virtual_card[] = {
        DFC_ISO7816_CLA_STANDARD,
        DFC_ISO7816_INS_SELECT,
        0x04,
        0x00,
        sizeof(installation_id),
        installation_id[0],
        installation_id[1],
        installation_id[2]};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            select_virtual_card,
            sizeof(select_virtual_card),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response + response_len - 2, ((uint8_t[]){0x90, 0x00}));
    munit_assert_true(session->emulator->virtual_card_authentication_expected);
    munit_assert_size(session->emulator->pending_chain_len, ==, pending_len);
    munit_assert_size(session->emulator->pending_chain_offset, ==, pending_offset);

    const uint8_t additional_frame[] = {
        DFC_ISO7816_CLA_WRAPPER, DFC_CMD_ADDITIONAL_FRAME, 0, 0, 0};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            additional_frame,
            sizeof(additional_frame),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint8(response[0], !=, DFC_STATUS_ILLEGAL_COMMAND_CODE);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}
#endif

static MunitResult test_framed_unknown_iso_select_preserves_prefix_and_returns_not_found(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    load_standard_credential(&credential);
    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    DfcByteBuf* tx_buffer = dfc_bytebuf_alloc(DFC_WORKER_MAX_BUFFER_SIZE);
    const uint8_t prefix[] = {0x0A, 0x00};
    dfc_bytebuf_append_bytes(tx_buffer, prefix, sizeof(prefix));

    const uint8_t unknown_select[] = {
        0x00,
        DFC_ISO7816_INS_SELECT,
        0x04,
        0x00,
        0x0A,
        0xA0,
        0x00,
        0x00,
        0x01,
        0x51,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00};
    bool app_selected = true;

    munit_assert_true(dfc_emulator_handle_iso7816_select(
        emulator, unknown_select, sizeof(unknown_select), tx_buffer, sizeof(prefix), &app_selected));
    munit_assert_false(app_selected);
    munit_assert_size(dfc_bytebuf_get_size_bytes(tx_buffer), ==, 4);
    munit_assert_memory_equal(
        4, dfc_bytebuf_get_data(tx_buffer), ((uint8_t[]){0x0A, 0x00, 0x6A, 0x82}));

    dfc_bytebuf_free(tx_buffer);
    dfc_emulator_free(emulator);
    return MUNIT_OK;
}

// A chain-capable command longer than the scratch area borrows the emulator's
// command-chain buffer to hold itself while it runs. If a native continuation
// (GetVersion's "more frames") is still pending, the command is aborted, and the
// abort used to free that very buffer under its own handler: a heap
// use-after-free the reader controlled. Run under AddressSan, this test fails
// loudly if the buffer is ever freed while it is lent again.
static MunitResult test_long_command_after_pending_continuation_is_safe(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    static const uint8_t long_commands[] = {0x8D, 0x8B};
    for(size_t i = 0; i < sizeof(long_commands); i++) {
        DfcCredential credential;
        load_standard_credential(&credential);
        DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
        DfcVirtualPiccActivation activation;
        munit_assert_int(
            dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
        uint8_t response[64];
        size_t response_len = 0;
        const uint8_t get_version[] = {DFC_CMD_GET_VERSION};
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                session,
                get_version,
                sizeof(get_version),
                response,
                sizeof(response),
                &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_uint8(response[0], ==, DFC_CMD_ADDITIONAL_FRAME);

        uint8_t long_command[200];
        memset(long_command, 0x41, sizeof(long_command));
        long_command[0] = long_commands[i];
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                session,
                long_command,
                sizeof(long_command),
                response,
                sizeof(response),
                &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        // The pending continuation is dropped and the new command is refused.
        munit_assert_size(response_len, >=, 1);
        munit_assert_uint8(response[0], ==, DFC_STATUS_COMMAND_ABORTED);
        dfc_virtual_picc_session_free(session);
    }
    return MUNIT_OK;
}

// Frame reassembly and the direct API share one staging area. A direct call that
// has to stage a retry (its answer did not fit) must not leave bytes of an
// earlier, longer request behind past the new length: everything beyond the
// staged length stays zero.
static MunitResult
    test_mixed_apis_leave_no_stale_request_bytes(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    uint8_t response[64];
    size_t response_len = 0;
    const uint8_t rats[] = {0xE0, 0x80};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);

    // One chained fragment of a request: 50 bytes of 0xAA staged.
    uint8_t fragment[51];
    fragment[0] = 0x12;
    memset(fragment + 1, 0xAA, 50);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, fragment, sizeof(fragment), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(session->pending_command_len, ==, 50);

    // A direct call whose answer does not fit stages a 1-byte retry in the same area.
    const uint8_t get_version[] = {DFC_CMD_GET_VERSION};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, get_version, sizeof(get_version), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(session->pending_command_len, >, 0);
    assert_zeroed_bytes(
        session->pending_command + session->pending_command_len,
        sizeof(session->pending_command) - session->pending_command_len);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

// A direct call is an alternative to ISO-DEP framing, so it must abandon a request
// the framing layer was still reassembling. If it did not, the next frame
// fragment would be glued onto the stale bytes and run as one command. Here a
// chained fragment is staged, a direct call completes normally, and nothing of
// the old request may remain staged afterwards.
static MunitResult test_a_direct_call_abandons_a_request_being_reassembled(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    uint8_t response[64];
    size_t response_len = 0;
    const uint8_t rats[] = {0xE0, 0x80};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);

    uint8_t fragment[11];
    fragment[0] = 0x12;
    memset(fragment + 1, 0xAA, 10);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, fragment, sizeof(fragment), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(session->pending_command_len, ==, 10);

    const uint8_t free_memory[] = {DFC_CMD_FREE_MEM};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, free_memory, sizeof(free_memory), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(session->pending_command_len, ==, 0);
    assert_zeroed_bytes(session->pending_command, sizeof(session->pending_command));
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

// The other half of the same rule: a response chain the framing layer is still
// delivering is abandoned by a direct call too, so its remaining bytes (answer
// data, possibly secret) are wiped rather than left staged.
static MunitResult test_a_direct_call_abandons_a_response_chain_in_flight(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    // Seed the transport after sending the first 50 bytes of a 60-byte response.
    session->iso_dep_selected = true;
    session->expected_pcd_sequence = 1;
    session->picc_sequence = 1;
    session->pending_response_len = 60;
    session->pending_response_offset = 50;
    session->last_picc_block_len = 51;
    memset(session->last_picc_block, 0xAA, 51);
    for(unsigned i = 0; i < 60; i++)
        session->emulator->tx_buffer->data[i] = (uint8_t)i;
    session->emulator->tx_buffer->size_bytes = 60;
    uint8_t response[64];
    size_t response_len = 0;

    const uint8_t free_memory[] = {DFC_CMD_FREE_MEM};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, free_memory, sizeof(free_memory), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(session->pending_response_len, ==, 0);
    // The last block sent (a copy of answer bytes) is wiped, not left behind.
    munit_assert_size(session->last_picc_block_len, ==, 0);
    assert_zeroed_bytes(session->last_picc_block, sizeof(session->last_picc_block));
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

// A direct-API retry that is waiting to be replayed is not a response chain, so
// an R(ACK) from the frame side must not be answered with an empty I-block or
// move the card's block number; the exact direct retry must still work.
static MunitResult test_r_block_does_not_touch_a_pending_direct_response(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    uint8_t response[64];
    size_t response_len = 0;
    const uint8_t rats[] = {0xE0, 0x80};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);

    const uint8_t get_version[] = {DFC_CMD_GET_VERSION};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, get_version, sizeof(get_version), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    const uint8_t sequence_before = session->picc_sequence;
    for(uint8_t pcb = 0xA2; pcb <= 0xA3; pcb++) {
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, &pcb, 1, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusProtocolError);
        munit_assert_uint8(session->picc_sequence, ==, sequence_before);
    }
    // The exact direct retry still succeeds.
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, get_version, sizeof(get_version), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

// A long command with an alternate opcode (here 0x8B, WriteRecord) is handed to
// its handler inside the command-chain buffer. A bad MAC makes the handler end
// the session, which frees that buffer, and the caller used to read the command
// code from it afterwards (a read of freed memory). The command goes in an
// exact-size heap buffer and the whole suite runs under AddressSanitizer, so any
// later read of freed bytes fails; the answer must be the integrity error.
static MunitResult test_a_bad_mac_on_a_long_alternate_opcode_write_frees_nothing_in_use(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    static DfcCredential credential;
    load_standard_credential(&credential);
    credential.card.generation = DfcGenerationEv3;
    DfcFile* file = dfc_credential_create_file(&credential, 0, 5);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_LINEAR_RECORD;
    file->comm_settings = DFC_COMM_MAC;
    file->access_rights = 0x1111;
    file->state.record.size = 200;
    file->state.record.max_records = 3;
    file->state.record.count = 0;
    munit_assert_true(dfc_file_resize(&credential, file, 600));
    static const uint8_t key1[16] = {
        0xC6,
        0xEF,
        0x84,
        0x7C,
        0xAE,
        0x0A,
        0x2A,
        0x56,
        0xC0,
        0x19,
        0x2A,
        0xA1,
        0xC4,
        0xE8,
        0xD9,
        0xFB};
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    uint8_t response[300];
    size_t response_len = 0;
    size_t session_key_len = 0;
    uint8_t session_key[32];
    uint8_t iv[16];
    const uint8_t select_app[] = {0x5A, 0x4F, 0x49, 0xD3};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    authenticate_iso_key(
        session,
        1,
        key1,
        16,
        response,
        sizeof(response),
        &response_len,
        session_key,
        &session_key_len,
        iv,
        0x00);

    // WriteRecord of 150 bytes followed by a MAC that cannot be right.
    const size_t body_len = 7 + 150 + 8;
    const size_t command_len = 5 + body_len + 1;
    uint8_t* command = malloc(command_len);
    munit_assert_not_null(command);
    memset(command, 0x41, command_len);
    command[0] = 0x90;
    command[1] = 0x8B;
    command[2] = command[3] = 0;
    command[4] = (uint8_t)body_len;
    command[5] = 5;
    command[6] = command[7] = command[8] = 0;
    command[9] = 150;
    command[10] = command[11] = 0;
    command[command_len - 1] = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    free(command);
    munit_assert_size(response_len, ==, 2);
    munit_assert_uint8(response[0], ==, 0x91);
    munit_assert_uint8(response[1], ==, DFC_STATUS_INTEGRITY_ERROR);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

// An empty I-block that carries a card identifier is answered with an empty
// I-block that echoes the identifier and carries the CARD's own next block
// number. The reader numbers its frames differently from the card here on
// purpose (first 1, then 0), so a card that took its number from the reader, or
// echoed the wrong identifier, answers differently.
static MunitResult test_empty_i_block_with_cid_uses_the_cards_own_number_and_echoes_the_cid(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    uint8_t response[16];
    size_t response_len = 0;
    const uint8_t rats[] = {0xE0, 0x82}; // frame size code 8, card identifier 2
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    const uint8_t first[] = {0x0B, 0x02}; // I-block, CID, reader number 1
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, first, sizeof(first), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x0A, 0x02})); // card number 0
    const uint8_t second[] = {0x0A, 0x02}; // reader number 0
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, second, sizeof(second), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x0B, 0x02})); // card number 1
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

// While a direct-API retry waits to be replayed, a frame I-block must be refused
// too (the staging area belongs to the direct retry), and the retry still works.
static MunitResult test_i_block_does_not_touch_a_pending_direct_response(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    uint8_t response[64];
    size_t response_len = 0;
    const uint8_t rats[] = {0xE0, 0x80};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    const uint8_t get_version[] = {DFC_CMD_GET_VERSION};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, get_version, sizeof(get_version), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    const uint8_t sequence_before = session->picc_sequence;
    const uint8_t empty_i_block[] = {0x02};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session,
            empty_i_block,
            sizeof(empty_i_block),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_uint8(session->picc_sequence, ==, sequence_before);
    // A frame carrying a command is refused as well, and must not be appended to
    // the bytes the direct retry staged.
    const size_t staged_before = session->pending_command_len;
    const uint8_t command_i_block[] = {0x02, 0x90, DFC_CMD_GET_VERSION, 0x00, 0x00, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session,
            command_i_block,
            sizeof(command_i_block),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_size(session->pending_command_len, ==, staged_before);
    munit_assert_uint8(session->picc_sequence, ==, sequence_before);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, get_version, sizeof(get_version), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_iso_dep_reader_chaining(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    uint8_t response[128];
    size_t response_len = 0;
    const uint8_t rats[] = {0xE0, 0x80};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    const uint8_t first[] = {0x12, 0x00, 0xA4};
    const uint8_t middle[] = {0x13, 0x04, 0x00, 0x07, 0xD2, 0x76};
    const uint8_t last[] = {0x02, 0x00, 0x00, 0x85, 0x01, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, first, sizeof(first), response, 0, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_size(session->pending_command_len, ==, 0);
    munit_assert_uint8(session->expected_pcd_sequence, ==, 0);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, first, sizeof(first), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, 0xA2);
    munit_assert_size(session->pending_command_len, ==, 2);
    uint8_t oversized[sizeof(session->pending_command)] = {0x13};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, oversized, sizeof(oversized), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_size(session->pending_command_len, ==, 2);
    munit_assert_uint8(session->expected_pcd_sequence, ==, 1);
    for(uint8_t pcb = 0xB2; pcb <= 0xB3; pcb++) {
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, &pcb, 1, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(response_len, ==, 1);
        // The card last sent A2. B2 repeats that number, so the card
        // retransmits A2; B3 carries the other number, so it answers with an
        // R(ACK) holding its current number. Both give A2.
        munit_assert_uint8(response[0], ==, 0xA2);
        munit_assert_size(session->pending_command_len, ==, 2);
    }
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, middle, sizeof(middle), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, 0xA3);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, last, sizeof(last), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 3);
    munit_assert_memory_equal(3, response, ((uint8_t[]){0x02, 0x90, 0x00}));
    munit_assert_size(session->pending_command_len, ==, 0);
    assert_zeroed_bytes(
        session->pending_command, (sizeof(first) - 1) + (sizeof(middle) - 1) + (sizeof(last) - 1));
    for(unsigned i = 0; i < 2; i++) {
        // A repeated RATS in an active session is ignored (measured), so each
        // new activation starts from a fresh selection.
        munit_assert_int(dfc_virtual_picc_field_off(session), ==, DfcVirtualPiccStatusOk);
        munit_assert_int(
            dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, rats, sizeof(rats), response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(session->pending_command_len, ==, 0);
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, first, sizeof(first), response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(session->pending_command_len, ==, 2);
    }
    munit_assert_int(dfc_virtual_picc_field_off(session), ==, DfcVirtualPiccStatusOk);
    munit_assert_size(session->pending_command_len, ==, 0);
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, first, sizeof(first), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    const uint8_t second[] = {0x03, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, second, sizeof(second), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 3);
    munit_assert_memory_equal(3, response, ((uint8_t[]){0x03, 0x90, 0x00}));
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static void prepare_iso_file_session(
    DfcCredential* credential,
    DfcVirtualPiccSession** session,
    uint8_t cid,
    uint8_t* response,
    size_t* response_len) {
    load_standard_credential(credential);
    credential->files[0].comm_settings = DFC_COMM_PLAIN;
    credential->files[0].access_rights = 0xEEEE;
    *session = dfc_virtual_picc_session_alloc(credential);
    munit_assert_not_null(*session);
    activate_iso_dep(*session, cid, response, 64, response_len);
    // The current file is only honoured inside the application that holds it.
    (*session)->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    (*session)->emulator->selected_app_index = (*session)->credential->files[0].app_index;
    (*session)->iso_file_selected = true;
    (*session)->iso_file_index = 0;
}

static void fill_iso_auth_pending_scratch(DfcEmulator* emulator, uint8_t phase) {
    emulator->iso_auth_phase = phase;
    emulator->iso_auth_challenge_len = DFC_ISO7816_AUTH_CHALLENGE_2TDEA;
    emulator->iso_auth_key_no = 3;
    emulator->iso_auth_cipher = DFC_CMD_AUTHENTICATE_ISO;
    emulator->iso_auth_reference = DFC_ISO7816_AUTH_APP_REFERENCE | 3;
    emulator->iso_auth_key_len = 16;
    memset(
        emulator->pending_authentication.iso_auth_card_first,
        0x11,
        sizeof(emulator->pending_authentication.iso_auth_card_first));
    memset(
        emulator->pending_authentication.iso_auth_host_first,
        0x22,
        sizeof(emulator->pending_authentication.iso_auth_host_first));
    memset(
        emulator->pending_authentication.iso_auth_external_iv,
        0x33,
        sizeof(emulator->pending_authentication.iso_auth_external_iv));
    memset(
        emulator->pending_authentication.iso_auth_key,
        0x44,
        sizeof(emulator->pending_authentication.iso_auth_key));
}

static void assert_iso_auth_pending_scratch_cleared(const DfcEmulator* emulator) {
    const uint8_t zero[DFC_MAX_KEY_LEN] = {0};
    munit_assert_uint8(emulator->iso_auth_phase, ==, 0);
    munit_assert_uint8(emulator->iso_auth_challenge_len, ==, 0);
    munit_assert_uint8(emulator->iso_auth_key_no, ==, 0);
    munit_assert_uint8(emulator->iso_auth_cipher, ==, 0);
    munit_assert_uint8(emulator->iso_auth_reference, ==, 0);
    munit_assert_size(emulator->iso_auth_key_len, ==, 0);
    munit_assert_memory_equal(
        sizeof(emulator->pending_authentication.iso_auth_card_first),
        emulator->pending_authentication.iso_auth_card_first,
        zero);
    munit_assert_memory_equal(
        sizeof(emulator->pending_authentication.iso_auth_host_first),
        emulator->pending_authentication.iso_auth_host_first,
        zero);
    munit_assert_memory_equal(
        sizeof(emulator->pending_authentication.iso_auth_external_iv),
        emulator->pending_authentication.iso_auth_external_iv,
        zero);
    munit_assert_memory_equal(
        sizeof(emulator->pending_authentication.iso_auth_key),
        emulator->pending_authentication.iso_auth_key,
        zero);
}

static MunitResult test_iso_auth_terminal_paths_clear_pending_scratch(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    uint8_t response[64];
    size_t response_len = 0;

    const uint8_t invalid_external[] = {
        DFC_ISO7816_CLA_STANDARD, DFC_ISO7816_INS_EXTERNAL_AUTHENTICATE, 0, 0, 0};
    fill_iso_auth_pending_scratch(session->emulator, 1);
    DfcEmulator before = *session->emulator;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, invalid_external, sizeof(invalid_external), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_memory_equal(sizeof(before), session->emulator, &before);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            invalid_external,
            sizeof(invalid_external),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    assert_iso_auth_pending_scratch_cleared(session->emulator);

    const uint8_t unexpected[] = {DFC_ISO7816_CLA_STANDARD, 0xFE, 0, 0};
    fill_iso_auth_pending_scratch(session->emulator, 1);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, unexpected, sizeof(unexpected), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    assert_iso_auth_pending_scratch_cleared(session->emulator);

    const uint8_t invalid_internal[] = {
        DFC_ISO7816_CLA_STANDARD, DFC_ISO7816_INS_INTERNAL_AUTHENTICATE, 0, 0, 0};
    fill_iso_auth_pending_scratch(session->emulator, 2);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            invalid_internal,
            sizeof(invalid_internal),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    assert_iso_auth_pending_scratch_cleared(session->emulator);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_iso_dep_capacity_stages_mutation_and_randomness(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[64];
    size_t response_len = 0;

    for(uint8_t cid = 0; cid <= 3; cid += 3) {
        DfcCredential credential;
        DfcVirtualPiccSession* session = NULL;
        prepare_iso_file_session(&credential, &session, cid, response, &response_len);
        uint8_t* file_data = dfc_file_data(&credential, &credential.files[0]);
        munit_assert_not_null(file_data);
        uint8_t update[8] = {0x02, 0x00, DFC_ISO7816_INS_UPDATE_BINARY, 0, 0, 1, 0xA5};
        size_t update_len = 7;
        size_t required = 3;
        if(cid != 0) {
            memmove(update + 2, update + 1, update_len - 1);
            update[0] = 0x0A;
            update[1] = cid;
            update_len++;
            required++;
        }
        uint8_t expected_sequence = session->expected_pcd_sequence;
        uint8_t picc_sequence = session->picc_sequence;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, update, update_len, response, required - 1, &response_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        munit_assert_size(response_len, ==, 0);
        munit_assert_uint8(file_data[0], ==, 0xA5);
        munit_assert_uint8(session->expected_pcd_sequence, ==, expected_sequence);
        munit_assert_uint8(session->picc_sequence, ==, picc_sequence);
        munit_assert_size(session->pending_response_len, >, 0);
        munit_assert_size(session->pending_command_len, ==, update_len);
        munit_assert_memory_equal(update_len, session->pending_command, update);
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, update, update_len, response, required, &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_uint8(file_data[0], ==, 0xA5);
        munit_assert_size(response_len, ==, required);
        munit_assert_size(session->pending_command_len, ==, 0);
        dfc_virtual_picc_session_free(session);
    }

    for(uint8_t cid = 0; cid <= 3; cid += 3) {
        DfcCredential credential;
        DfcVirtualPiccSession* session = NULL;
        prepare_iso_file_session(&credential, &session, cid, response, &response_len);
        uint8_t random_script[DFC_ISO7816_AUTH_CHALLENGE_2TDEA];
        memset(random_script, 0x5A, sizeof(random_script));
        dfc_host_clear_random_buffer();
        dfc_host_set_random_buffer(random_script, sizeof(random_script));
        uint8_t challenge[7] = {
            0x02,
            DFC_ISO7816_CLA_STANDARD,
            DFC_ISO7816_INS_GET_CHALLENGE,
            0,
            0,
            DFC_ISO7816_AUTH_CHALLENGE_2TDEA};
        size_t challenge_len = 6;
        size_t required = 1 + sizeof(random_script) + DFC_ISO7816_STATUS_WORD_LENGTH;
        if(cid != 0) {
            memmove(challenge + 2, challenge + 1, challenge_len - 1);
            challenge[0] = 0x0A;
            challenge[1] = cid;
            challenge_len++;
            required++;
        }
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, challenge, challenge_len, response, required - 1, &response_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        munit_assert_size(dfc_host_random_remaining(), ==, 0);
        munit_assert_uint8(session->emulator->iso_auth_phase, ==, 1);
        munit_assert_uint8(session->expected_pcd_sequence, ==, 0);
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, challenge, challenge_len, response, required, &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(dfc_host_random_remaining(), ==, 0);
        munit_assert_uint8(session->emulator->iso_auth_phase, ==, 1);
        munit_assert_size(response_len, ==, required);
        dfc_host_clear_random_buffer();
        dfc_virtual_picc_session_free(session);
    }

    return MUNIT_OK;
}

static MunitResult
    test_iso_dep_capacity_stages_chained_commands(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[64];
    size_t response_len = 0;
    for(uint8_t cid = 0; cid <= 3; cid += 3) {
        DfcCredential credential;
        DfcVirtualPiccSession* session = NULL;
        prepare_iso_file_session(&credential, &session, cid, response, &response_len);
        uint8_t* file_data = dfc_file_data(&credential, &credential.files[0]);
        uint8_t first[5] = {0x12, DFC_ISO7816_CLA_STANDARD, DFC_ISO7816_INS_UPDATE_BINARY, 0};
        size_t first_len = 4;
        size_t r_block_len = 1;
        if(cid != 0) {
            memmove(first + 2, first + 1, first_len - 1);
            first[0] = 0x1A;
            first[1] = cid;
            first_len++;
            r_block_len++;
        }
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, first, first_len, response, r_block_len - 1, &response_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        munit_assert_size(session->pending_command_len, ==, 0);
        munit_assert_uint8(session->expected_pcd_sequence, ==, 0);
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, first, first_len, response, r_block_len, &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(session->pending_command_len, ==, 3);
        munit_assert_uint8(session->expected_pcd_sequence, ==, 1);

        uint8_t final[5] = {0x03, 0, 1, 0xA6};
        size_t final_len = 4;
        size_t response_block_len = 3;
        if(cid != 0) {
            memmove(final + 2, final + 1, final_len - 1);
            final[0] = 0x0B;
            final[1] = cid;
            final_len++;
            response_block_len++;
        }
        const size_t assembled_command_len = 6;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, final, final_len, response, response_block_len - 1, &response_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        munit_assert_uint8(file_data[0], ==, 0xA6);
        munit_assert_size(session->pending_command_len, ==, final_len);
        munit_assert_memory_equal(final_len, session->pending_command, final);
        assert_zeroed_bytes(
            session->pending_command + final_len, assembled_command_len - final_len);
        munit_assert_uint8(session->expected_pcd_sequence, ==, 1);
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, final, final_len, response, response_block_len, &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_uint8(file_data[0], ==, 0xA6);
        munit_assert_size(session->pending_command_len, ==, 0);
        assert_zeroed_bytes(session->pending_command, assembled_command_len);
        dfc_virtual_picc_session_free(session);
    }
    return MUNIT_OK;
}

static MunitResult test_iso_dep_chained_terminal_failure_wipes_retired_tail(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);
    uint8_t response[32];
    size_t response_len = 0;
    activate_iso_dep(session, 0, response, sizeof(response), &response_len);

    const uint8_t first[] = {0x12, 0x00, DFC_ISO7816_INS_GET_CHALLENGE, 0x00};
    const uint8_t final[] = {0x03, 0x00, DFC_ISO7816_AUTH_CHALLENGE_2TDEA};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, first, sizeof(first), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(session->pending_command_len, ==, sizeof(first) - 1);

    const uint8_t empty_script = 0;
    dfc_host_clear_random_buffer();
    dfc_host_set_random_buffer(&empty_script, 0);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, final, sizeof(final), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_size(session->pending_command_len, ==, sizeof(first) - 1);
    assert_zeroed_bytes(
        session->pending_command + session->pending_command_len, sizeof(final) - 1);

    uint8_t random_script[DFC_ISO7816_AUTH_CHALLENGE_2TDEA];
    memset(random_script, 0x5A, sizeof(random_script));
    dfc_host_set_random_buffer(random_script, sizeof(random_script));
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, final, sizeof(final), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(session->pending_command_len, ==, 0);
    assert_zeroed_bytes(session->pending_command, (sizeof(first) - 1) + (sizeof(final) - 1));
    dfc_host_clear_random_buffer();
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_iso_dep_completed_response_retry_is_exact(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[64];
    size_t response_len = 0;

    for(uint8_t cid = 0; cid <= 3; cid += 3) {
        DfcCredential credential;
        load_standard_credential(&credential);
        credential.picc_key_settings_1 |= DFC_KS1_FREE_CREATE_DELETE;
        DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
        munit_assert_not_null(session);
        activate_iso_dep(session, cid, response, sizeof(response), &response_len);

        uint8_t frame[13] = {
            0x02,
            DFC_ISO7816_CLA_WRAPPER,
            DFC_CMD_CREATE_APPLICATION,
            0,
            0,
            5,
            0x66,
            0x55,
            0x44,
            0x0F,
            0x81,
            0,
        };
        size_t frame_len = 12;
        size_t required = 3;
        if(cid != 0) {
            memmove(frame + 2, frame + 1, frame_len - 1);
            frame[0] = 0x0A;
            frame[1] = cid;
            frame_len++;
            required++;
        }
        size_t app_count_before = credential.num_apps;
        response_len = SIZE_MAX;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, frame, frame_len, response, required - 1, &response_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        munit_assert_size(response_len, ==, 0);
        munit_assert_size(credential.num_apps, ==, app_count_before + 1);
        munit_assert_uint8(session->expected_pcd_sequence, ==, 0);
        munit_assert_uint8(session->picc_sequence, ==, 0);
        munit_assert_size(session->pending_command_len, ==, frame_len);
        munit_assert_memory_equal(frame_len, session->pending_command, frame);

        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, frame, frame_len, response, required - 1, &response_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        munit_assert_size(credential.num_apps, ==, app_count_before + 1);

        uint8_t different[sizeof(frame)];
        memcpy(different, frame, frame_len);
        different[frame_len - 4] ^= 0x01;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, different, frame_len, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusProtocolError);
        munit_assert_size(session->pending_command_len, ==, frame_len);
        munit_assert_size(credential.num_apps, ==, app_count_before + 1);

        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, frame, frame_len, response, required, &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(response_len, ==, required);
        munit_assert_uint8(response[required - 2], ==, 0x91);
        munit_assert_uint8(response[required - 1], ==, DFC_STATUS_OK);
        munit_assert_size(credential.num_apps, ==, app_count_before + 1);
        munit_assert_uint8(session->expected_pcd_sequence, ==, 1);
        munit_assert_size(session->pending_command_len, ==, 0);
        dfc_virtual_picc_session_free(session);
    }

    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);
    activate_iso_dep(session, 0, response, sizeof(response), &response_len);
    uint8_t random_script[DFC_ISO7816_AUTH_CHALLENGE_2TDEA];
    memset(random_script, 0x5A, sizeof(random_script));
    dfc_host_clear_random_buffer();
    dfc_host_set_random_buffer(random_script, sizeof(random_script));
    const uint8_t challenge[] = {
        0x02,
        DFC_ISO7816_CLA_STANDARD,
        DFC_ISO7816_INS_GET_CHALLENGE,
        0,
        0,
        DFC_ISO7816_AUTH_CHALLENGE_2TDEA,
    };
    size_t challenge_response_len = 1 + sizeof(random_script) + DFC_ISO7816_STATUS_WORD_LENGTH;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session,
            challenge,
            sizeof(challenge),
            response,
            challenge_response_len - 1,
            &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(dfc_host_random_remaining(), ==, 0);
    munit_assert_uint8(session->emulator->iso_auth_phase, ==, 1);
    munit_assert_uint8(session->expected_pcd_sequence, ==, 0);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, challenge, sizeof(challenge), response, challenge_response_len, &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, challenge_response_len);
    munit_assert_size(dfc_host_random_remaining(), ==, 0);
    munit_assert_uint8(session->expected_pcd_sequence, ==, 1);
    dfc_host_clear_random_buffer();
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_iso_dep_retry_command_storage_boundaries(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    const size_t frame_lengths[] = {
        sizeof(((DfcVirtualPiccSession*)0)->pending_command),
        sizeof(((DfcVirtualPiccSession*)0)->pending_command) + 1,
        255,
        600,
    };

    for(size_t case_index = 0; case_index < sizeof(frame_lengths) / sizeof(frame_lengths[0]);
        case_index++) {
        const size_t frame_len = frame_lengths[case_index];
        munit_logf(MUNIT_LOG_INFO, "retry command boundary: %zu bytes", frame_len);
        DfcCredential credential;
        load_standard_credential(&credential);
        DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
        munit_assert_not_null(session);
        uint8_t response[8];
        size_t response_len = 0;
        activate_iso_dep(session, 0, response, sizeof(response), &response_len);

        uint8_t frame[600] = {0};
        frame[0] = 0x02;
        frame[1] = DFC_ISO7816_CLA_STANDARD;
        frame[2] = DFC_ISO7816_INS_UPDATE_BINARY;
        for(size_t i = 3; i < frame_len; i++)
            frame[i] = (uint8_t)i;

        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, frame, frame_len, response, 1, &response_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        munit_assert_size(response_len, ==, 0);
        munit_assert_size(session->pending_command_len, ==, frame_len);
        const uint8_t* staged = frame_len <= sizeof(session->pending_command) ?
                                    session->pending_command :
                                    session->emulator->command_chain;
        munit_assert_not_null(staged);
        munit_assert_memory_equal(frame_len, staged, frame);

        frame[frame_len - 1] ^= 0x80;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, frame, frame_len, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusProtocolError);
        frame[frame_len - 1] ^= 0x80;

        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, frame, frame_len, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(response_len, ==, 3);
        munit_assert_uint8(response[0], ==, 0x02);
        munit_assert_size(session->pending_command_len, ==, 0);
        munit_assert_null(session->emulator->command_chain);
        dfc_virtual_picc_session_free(session);
    }
    return MUNIT_OK;
}

static MunitResult test_iso_file_capacity_and_request_classification(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcFile* file = &credential.files[0];
    file->type = DFC_FILE_TYPE_LINEAR_RECORD;
    file->state.record.size = 3;
    file->state.record.count = 1;
    // A record file's header must agree with its stored bytes (three here).
    file->state.record.max_records = 1;
    munit_assert_size(file->data_len, >=, 3);
    file->comm_settings = DFC_COMM_PLAIN;
    file->access_rights = 0xEEEE;
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    // The current file is only honoured inside the application that holds it.
    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    session->emulator->selected_app_index = session->credential->files[0].app_index;
    session->iso_file_selected = true;
    session->iso_file_index = 0;
    uint8_t response[8];
    size_t response_len = 0;
    const uint8_t read_record[] = {0, DFC_ISO7816_INS_READ_RECORD, 1, 0x04, 3};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, read_record, sizeof(read_record), response, 4, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    const uint8_t invalid_record[] = {0, DFC_ISO7816_INS_READ_RECORD, 2, 0x04, 3};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            invalid_record,
            sizeof(invalid_record),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    // Measured: a record the file does not hold is 6985.
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x69, 0x85}));

    file->type = DFC_FILE_TYPE_STANDARD_DATA;
    const uint8_t read_binary[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 3};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, read_binary, sizeof(read_binary), response, 4, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    uint8_t* data = dfc_file_data(&credential, file);
    uint8_t original = data[0];
    const uint8_t update_binary[] = {0, DFC_ISO7816_INS_UPDATE_BINARY, 0, 0, 1, 0xCC};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, update_binary, sizeof(update_binary), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_uint8(data[0], ==, original);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_iso_wrapped_oversize_is_terminal(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    uint8_t oversized[DFC_WORKER_MAX_BUFFER_SIZE + 7] = {0};
    oversized[0] = DFC_ISO7816_CLA_WRAPPER;
    oversized[1] = DFC_CMD_GET_VERSION;
    uint8_t response[2];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, oversized, sizeof(oversized), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_LENGTH_ERROR}));
    munit_assert_size(session->pending_response_len, ==, 0);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_virtual_picc_reset_and_free_wipe_transport_storage(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    memset(session->pending_command, 0xA1, sizeof(session->pending_command));
    memset(session->emulator->tx_buffer->data, 0xA2, sizeof(session->emulator->tx_buffer->data));
    session->emulator->tx_buffer->size_bytes = 8;
    memset(session->pending_response_prefix, 0xA3, sizeof(session->pending_response_prefix));
    memset(session->last_picc_block, 0xA4, sizeof(session->last_picc_block));
    session->pending_command_len = 7;
    session->pending_response_len = 8;
    session->pending_response_offset = 2;
    session->pending_response_prefix_len = 2;
    session->last_picc_block_len = 4;
    munit_assert_int(dfc_virtual_picc_reset_protocol(session), ==, DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(
        sizeof(session->pending_command),
        session->pending_command,
        ((uint8_t[sizeof(session->pending_command)]){0}));
    munit_assert_memory_equal(
        sizeof(session->emulator->tx_buffer->data),
        session->emulator->tx_buffer->data,
        ((uint8_t[sizeof(session->emulator->tx_buffer->data)]){0}));
    munit_assert_size(session->emulator->tx_buffer->size_bytes, ==, 0);
    munit_assert_memory_equal(
        sizeof(session->pending_response_prefix),
        session->pending_response_prefix,
        ((uint8_t[sizeof(session->pending_response_prefix)]){0}));
    munit_assert_memory_equal(
        sizeof(session->last_picc_block),
        session->last_picc_block,
        ((uint8_t[sizeof(session->last_picc_block)]){0}));

    memset(session->pending_command, 0xB1, sizeof(session->pending_command));
    memset(session->last_picc_block, 0xB3, sizeof(session->last_picc_block));
    VirtualPiccFreeAudit audit = {
        .target = session,
        .length = sizeof(*session),
    };
    dfc_host_set_free_observer(observe_virtual_picc_free, &audit);
    dfc_virtual_picc_session_free(session);
    dfc_host_set_free_observer(NULL, NULL);
    munit_assert_true(audit.observed);
    munit_assert_true(audit.zeroed);
    return MUNIT_OK;
}

static MunitResult
    test_iso_dep_response_chain_followup(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    // Seed the transport after sending the first 50 bytes of a chained response.
    session->iso_dep_selected = true;
    session->expected_pcd_sequence = 1;
    session->picc_sequence = 1;
    session->pending_response_len = 60;
    session->pending_response_offset = 50;
    session->last_picc_block_len = 51;
    session->last_picc_block[0] = 0x12;
    for(unsigned i = 0; i < 60; i++)
        session->emulator->tx_buffer->data[i] = (uint8_t)i;
    session->emulator->tx_buffer->size_bytes = 60;
    memcpy(session->last_picc_block + 1, session->emulator->tx_buffer->data, 50);
    uint8_t response[128];
    size_t response_len = 0;
    const uint8_t retry[] = {0xA2};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, retry, sizeof(retry), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 51);
    munit_assert_memory_equal(51, response, session->last_picc_block);
    munit_assert_size(session->pending_response_offset, ==, 50);
    const uint8_t ack[] = {0xA3};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, ack, sizeof(ack), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 11);
    munit_assert_uint8(response[0], ==, 0x03);
    // The final block carries bytes 50..59 of the response. The transmit buffer
    // that held them is wiped once the chain ends, so compare to the known values.
    uint8_t expected_tail[10];
    for(unsigned i = 0; i < sizeof(expected_tail); i++)
        expected_tail[i] = (uint8_t)(50 + i);
    munit_assert_memory_equal(10, response + 1, expected_tail);
    assert_zeroed_bytes(session->emulator->tx_buffer->data, 60);
    const uint8_t select[] = {0x03, 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0, 0, 0x85, 1, 0};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, select, sizeof(select), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 3);
    munit_assert_memory_equal(3, response, ((uint8_t[]){0x02, 0x90, 0x00}));
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_iso_dep_cid_response_sets_chaining_bit(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    session->iso_dep_selected = true;
    session->picc_sequence = 0;
    session->pending_response_len = 58;
    session->pending_response_offset = 0;
    session->pending_response_prefix[0] = 0x0A;
    session->pending_response_prefix[1] = 0x00;
    session->pending_response_prefix_len = 2;
    session->last_picc_block[0] = 0x03;
    session->last_picc_block_len = 1;
    for(size_t i = 0; i < session->pending_response_len; i++)
        session->emulator->tx_buffer->data[i] = (uint8_t)i;
    session->emulator->tx_buffer->size_bytes = session->pending_response_len;

    uint8_t response[128];
    size_t response_len = 0;
    const uint8_t ack[] = {0xA0};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, ack, sizeof(ack), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 50);
    munit_assert_uint8(response[0], ==, 0x1A);
    munit_assert_uint8(response[1], ==, 0x00);
    munit_assert_memory_equal(48, response + 2, session->emulator->tx_buffer->data);

    const uint8_t next[] = {0xA9, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, next, sizeof(next), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 12);
    munit_assert_uint8(response[0], ==, 0x0B);
    munit_assert_uint8(response[1], ==, 0x00);
    // The final block carries bytes 48..57; the buffer is wiped once the chain ends.
    uint8_t expected_tail[10];
    for(unsigned i = 0; i < sizeof(expected_tail); i++)
        expected_tail[i] = (uint8_t)(48 + i);
    munit_assert_memory_equal(10, response + 2, expected_tail);
    assert_zeroed_bytes(session->emulator->tx_buffer->data, 58);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_protocol_and_field_resets_reuse_allocations(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);

    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    DfcEmulator* emulator = session->emulator;
    DfcByteBuf* tx_buffer = emulator->tx_buffer;
    emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    emulator->selected_app_index = 1;
    emulator->awaiting_step2 = true;
    session->iso_dep_selected = true;
    session->expected_pcd_sequence = 1;

    munit_assert_int(dfc_virtual_picc_reset_protocol(session), ==, DfcVirtualPiccStatusOk);
    munit_assert_ptr_equal(session->emulator, emulator);
    munit_assert_ptr_equal(session->emulator->tx_buffer, tx_buffer);
    munit_assert_true(session->activated);
    munit_assert_false(session->iso_dep_selected);
    munit_assert_uint8(session->expected_pcd_sequence, ==, 0);
    munit_assert_int(
        session->emulator->selected_application, ==, DfcEmulatorSelectedApplicationPicc);
    munit_assert_false(session->emulator->awaiting_step2);

    munit_assert_int(dfc_virtual_picc_field_off(session), ==, DfcVirtualPiccStatusOk);
    munit_assert_ptr_equal(session->emulator, emulator);
    munit_assert_ptr_equal(session->emulator->tx_buffer, tx_buffer);
    munit_assert_false(session->activated);
    munit_assert_false(session->random_uid_valid);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_scan_reports_on_device_desfire_activation_vector(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);

    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    munit_assert_size(activation.protocol_len, ==, 2);
    munit_assert_memory_equal(2, activation.protocol, ((uint8_t[]){0x02, 0x02}));
    munit_assert_size(activation.uid_len, ==, 7);
    munit_assert_uint8(activation.uid[0], ==, 0x04);
    // The default ATS, SAK and ATQA are asserted by the picc-config-default-ats vector.
    munit_assert_size(activation.rf_detail_len, ==, 3);
    munit_assert_memory_equal(3, activation.rf_detail, ((uint8_t[]){0x01, 0x51, 0x57}));

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_wrapped_get_version_returns_detection_frame(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);

    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    uint8_t command[DFC_WRAPPED_GET_VERSION_FRAME_SIZE];
    dfc_build_wrapped_get_version_frame(command);

    uint8_t response[128];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, sizeof(command), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);

    uint8_t expected[] = {0x04, 0x01, 0x01, 0x01, 0x00, 0x16, 0x05, 0x91, 0xAF};
    munit_assert_size(response_len, ==, sizeof(expected));
    munit_assert_memory_equal(sizeof(expected), response, expected);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static void load_factory_d40_credential(DfcCredential* credential) {
    dfc_credential_clear(credential);
    memcpy(
        credential->uid,
        ((uint8_t[]){0x04, 0x02, 0xA5, 0xDA, 0x4F, 0x85, 0x5C}),
        DFC_DESFIRE_UID_LEN);
    credential->uid_len = DFC_DESFIRE_UID_LEN;

    const uint8_t factory_aid_desfire_order[] = {0x4F, 0x49, 0x53};
    DfcApplication* app = dfc_credential_create_application_desfire_order(
        credential, factory_aid_desfire_order, 0x0B, DFC_KEY_TYPE_DES_2K3DES | 4);
    munit_assert_not_null(app);
    const uint8_t iso_aid[] = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00};
    memcpy(app->iso_aid, iso_aid, sizeof(iso_aid));
    app->iso_aid_len = sizeof(iso_aid);
    app->auth_command = DFC_CMD_AUTHENTICATE_LEGACY;

    const uint8_t keys[][16] = {
        {0x5E,
         0xA0,
         0xA3,
         0xE3,
         0xA8,
         0xD2,
         0x20,
         0x6C,
         0xB3,
         0x96,
         0xC9,
         0xC8,
         0xDE,
         0xA9,
         0xC2,
         0xD9},
        {0xF9,
         0xF5,
         0xE5,
         0xBE,
         0x4D,
         0xEA,
         0x54,
         0xC6,
         0xB6,
         0xD2,
         0x5E,
         0x28,
         0xA8,
         0xBF,
         0xA1,
         0x56},
        {0x54,
         0x0A,
         0xF5,
         0x62,
         0x1B,
         0xD3,
         0x5C,
         0xB3,
         0x82,
         0x70,
         0xC2,
         0x50,
         0x06,
         0x3D,
         0x41,
         0x25},
        {0xC5,
         0x76,
         0x16,
         0x55,
         0x74,
         0xAC,
         0x9F,
         0x5E,
         0x84,
         0x5E,
         0x63,
         0xF3,
         0x3F,
         0x9F,
         0x4B,
         0x20},
    };
    for(size_t i = 0; i < 4; i++) {
        memcpy(dfc_credential_key(credential, app, i), keys[i], app->key_len);
    }

    DfcFile* file = dfc_credential_create_file(credential, 0, 0x0F);
    munit_assert_not_null(file);
    file->type = 0x00;
    file->comm_settings = DFC_COMM_MAC;
    // The captured card answers GetFileSettings with access-rights octets 12 03.
    // Those arrive least-significant octet first, so the logical value is 0x0312:
    // read key 0, write key 3, read&write key 1, change key 2.
    file->access_rights = 0x0312;
    static const uint8_t file_data[] = {0x30, 0x2F, 0x81, 0x02, 0x0C, 0x03, 0xA5, 0x02, 0x05,
                                        0x00, 0xA6, 0x08, 0x81, 0x01, 0x01, 0x04, 0x03, 0x03,
                                        0x00, 0x09, 0xA7, 0x17, 0x85, 0x15, 0xD2, 0x0B, 0x74,
                                        0x96, 0x7B, 0xE1, 0x16, 0x31, 0xE9, 0xC4, 0x02, 0x4B,
                                        0xD6, 0xDB, 0x18, 0xF5, 0x68, 0x2B, 0xE0, 0x7D, 0xA4,
                                        0xA9, 0x02, 0x05, 0x00, 0x05, 0x00};
    munit_assert_true(dfc_file_resize(credential, file, sizeof(file_data)));
    memcpy(dfc_file_data(credential, file), file_data, sizeof(file_data));
}

static void assert_trace_exchange(
    DfcVirtualPiccSession* session,
    const uint8_t* command,
    size_t command_len,
    const uint8_t* expected,
    size_t expected_len) {
    uint8_t response[128];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    if(response_len != expected_len || memcmp(response, expected, expected_len) != 0) {
        printf("command=");
        for(size_t i = 0; i < command_len; i++)
            printf("%02X", command[i]);
        printf("\nexpected=");
        for(size_t i = 0; i < expected_len; i++)
            printf("%02X", expected[i]);
        printf("\nactual=");
        for(size_t i = 0; i < response_len; i++)
            printf("%02X", response[i]);
        printf("\n");
    }
    munit_assert_size(response_len, ==, expected_len);
    munit_assert_memory_equal(expected_len, response, expected);
}

static MunitResult
    test_factory_d40_trace_select_auth_read_path(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    load_factory_d40_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);

    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    assert_trace_exchange(
        session,
        ((uint8_t[]){0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00}),
        12,
        ((uint8_t[]){0x90, 0x00}),
        2);

    assert_trace_exchange(
        session,
        ((uint8_t[]){0x90, DFC_CMD_SELECT_APPLICATION, 0x00, 0x00, 0x03, 0x4F, 0x49, 0xD3, 0x00}),
        9,
        ((uint8_t[]){0x91, DFC_STATUS_APPLICATION_NOT_FOUND}),
        2);

    assert_trace_exchange(
        session,
        ((uint8_t[]){0x90, DFC_CMD_SELECT_APPLICATION, 0x00, 0x00, 0x03, 0x4F, 0x49, 0x53, 0x00}),
        9,
        ((uint8_t[]){0x91, DFC_STATUS_OK}),
        2);
    munit_assert_uint8(
        session->emulator->selected_application, ==, DfcEmulatorSelectedApplicationApp);

    const uint8_t captured_rnd_b[] = {0x5E, 0xE1, 0x1A, 0x07, 0x43, 0xFB, 0x4E, 0xB5};
    dfc_host_set_random_buffer(captured_rnd_b, sizeof(captured_rnd_b));
    assert_trace_exchange(
        session,
        ((uint8_t[]){0x90, DFC_CMD_AUTHENTICATE_LEGACY, 0x00, 0x00, 0x01, 0x01, 0x00}),
        7,
        ((uint8_t[]){
            0x61, 0xBA, 0x91, 0xCD, 0x03, 0x13, 0x98, 0xD5, 0x91, DFC_CMD_ADDITIONAL_FRAME}),
        10);

    assert_trace_exchange(
        session,
        ((uint8_t[]){0x90, DFC_CMD_ADDITIONAL_FRAME,
                     0x00, 0x00,
                     0x10, 0xD3,
                     0x59, 0x19,
                     0x7F, 0x16,
                     0xEF, 0x09,
                     0xE4, 0xBE,
                     0x33, 0x3E,
                     0x63, 0xCC,
                     0xF2, 0xC1,
                     0x1B, 0x00}),
        22,
        ((uint8_t[]){0xA4, 0x4A, 0x65, 0xA8, 0x62, 0xF4, 0xA9, 0x54, 0x91, DFC_STATUS_OK}),
        10);

    assert_trace_exchange(
        session,
        ((uint8_t[]){0x90, DFC_CMD_GET_FILE_SETTINGS, 0x00, 0x00, 0x01, 0x0F, 0x00}),
        7,
        ((uint8_t[]){0x00, 0x01, 0x12, 0x03, 0x33, 0x00, 0x00, 0x91, DFC_STATUS_OK}),
        9);

    assert_trace_exchange(
        session,
        ((uint8_t[]){
            0x90,
            DFC_CMD_READ_DATA,
            0x00,
            0x00,
            0x07,
            0x0F,
            0x00,
            0x00,
            0x00,
            0x05,
            0x00,
            0x00,
            0x00}),
        13,
        ((uint8_t[]){0x30, 0x2F, 0x81, 0x02, 0x0C, 0x1E, 0xA1, 0x78, 0x17, 0x91, DFC_STATUS_OK}),
        11);

    assert_trace_exchange(
        session,
        ((uint8_t[]){
            0x90,
            DFC_CMD_READ_DATA,
            0x00,
            0x00,
            0x07,
            0x0F,
            0x00,
            0x00,
            0x00,
            0x31,
            0x00,
            0x00,
            0x00}),
        13,
        ((uint8_t[]){0x30, 0x2F, 0x81, 0x02, 0x0C, 0x03, 0xA5, 0x02, 0x05, 0x00, 0xA6,
                     0x08, 0x81, 0x01, 0x01, 0x04, 0x03, 0x03, 0x00, 0x09, 0xA7, 0x17,
                     0x85, 0x15, 0xD2, 0x0B, 0x74, 0x96, 0x7B, 0xE1, 0x16, 0x31, 0xE9,
                     0xC4, 0x02, 0x4B, 0xD6, 0xDB, 0x18, 0xF5, 0x68, 0x2B, 0xE0, 0x7D,
                     0xA4, 0xA9, 0x02, 0x05, 0x00, 0xEF, 0x5C, 0x8D, 0x4A, 0x91, DFC_STATUS_OK}),
        55);

    assert_trace_exchange(
        session,
        ((uint8_t[]){0x90, DFC_CMD_SELECT_APPLICATION, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00}),
        9,
        ((uint8_t[]){0x91, DFC_STATUS_OK}),
        2);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_direct_exchange_null_outputs(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    const uint8_t command[] = {0x00, 0xB0, 0x00, 0x00, 0x01};
    uint8_t response[64];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, sizeof(command), response, sizeof(response), NULL),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, sizeof(command), NULL, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            NULL, command, sizeof(command), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, NULL, sizeof(command), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_cid_frames_respect_reader_size(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    const size_t frame_sizes[] = {16, 24, 32, 40, 48, 64, 96, 128, 256};
    for(unsigned fsdi = 0; fsdi < 9; fsdi++) {
        // CID zero may also be explicitly present in a block header.
        for(unsigned mode = 0; mode < 3; mode++) {
            bool use_cid = mode != 0;
            uint8_t cid = mode == 2 ? 1 : 0;
            DfcCredential credential;
            load_standard_credential(&credential);
            DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
            munit_assert_not_null(session);
            DfcVirtualPiccActivation activation;
            munit_assert_int(
                dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
            uint8_t response[128];
            size_t response_len = 0;
            const uint8_t rats[] = {0xE0, (uint8_t)((fsdi << 4) | cid)};
            munit_assert_int(
                dfc_virtual_picc_iso_dep_frame_exchange(
                    session, rats, sizeof(rats), response, sizeof(response), &response_len),
                ==,
                DfcVirtualPiccStatusOk);
            session->pending_response_len = 58;
            session->pending_response_prefix[0] = use_cid ? 0x0A : 0x02;
            session->pending_response_prefix[1] = cid;
            session->pending_response_prefix_len = use_cid ? 2 : 1;
            session->last_picc_block[0] = 0x03;
            session->last_picc_block_len = 1;
            for(size_t i = 0; i < 58; i++)
                session->emulator->tx_buffer->data[i] = (uint8_t)i;
            session->emulator->tx_buffer->size_bytes = 58;
            size_t received = 0;
            while(received < 58) {
                const uint8_t ack[] = {
                    (uint8_t)(0xA0 | session->picc_sequence | (use_cid ? 8 : 0)), cid};
                munit_assert_int(
                    dfc_virtual_picc_iso_dep_frame_exchange(
                        session, ack, use_cid ? 2 : 1, response, sizeof(response), &response_len),
                    ==,
                    DfcVirtualPiccStatusOk);
                // The public API omits the two on-air CRC bytes.
                munit_assert_size(response_len + 2, <=, frame_sizes[fsdi]);
                size_t header = use_cid ? 2 : 1;
                munit_assert_size(response_len, >, header);
                munit_assert_size(response_len - header, <=, 48);
                if(use_cid) munit_assert_uint8(response[1], ==, cid);
                for(size_t i = header; i < response_len; i++)
                    munit_assert_uint8(response[i], ==, received++);
                munit_assert_true(((response[0] & 0x10) != 0) == (received < 58));
            }
            dfc_virtual_picc_session_free(session);
        }
    }
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/cid-frames-respect-reader-size",
     test_cid_frames_respect_reader_size,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/direct-exchange-null-outputs",
     test_direct_exchange_null_outputs,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/sdm-read-family-and-boundary-lifecycle",
     test_sdm_read_family_and_boundary_lifecycle,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-command-aborts-native-response-chain",
     test_iso_command_aborts_native_response_chain,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-command-aborts-pending-native-authentication",
     test_iso_command_aborts_pending_native_authentication,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-command-aborts-incoming-native-write-chain",
     test_iso_command_aborts_incoming_native_write_chain,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-command-aborts-native-continuation-states",
     test_iso_command_aborts_native_continuation_states,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    {"/iso-command-aborts-ev2-first-and-non-first",
     test_iso_command_aborts_ev2_first_and_non_first,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
#if DFC_ENABLE_VIRTUAL_CARD
    {"/virtual-card-select-preserves-native-response-chain",
     test_virtual_card_select_does_not_abort_native_response_chain,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
    {"/iso-auth-terminal-scratch-wipe",
     test_iso_auth_terminal_paths_clear_pending_scratch,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-dep-capacity-stages-mutation-random",
     test_iso_dep_capacity_stages_mutation_and_randomness,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-dep-capacity-stages-chained-command",
     test_iso_dep_capacity_stages_chained_commands,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-dep-chained-terminal-failure-wipes-retired-tail",
     test_iso_dep_chained_terminal_failure_wipes_retired_tail,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-dep-completed-response-retry-is-exact",
     test_iso_dep_completed_response_retry_is_exact,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-dep-retry-command-storage-boundaries",
     test_iso_dep_retry_command_storage_boundaries,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-file-capacity-and-request-classification",
     test_iso_file_capacity_and_request_classification,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-wrapped-oversize-is-terminal",
     test_iso_wrapped_oversize_is_terminal,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/reset-and-free-wipe-transport-storage",
     test_virtual_picc_reset_and_free_wipe_transport_storage,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-dep-cid-response-sets-chaining-bit",
     test_iso_dep_cid_response_sets_chaining_bit,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-dep-response-chain-followup",
     test_iso_dep_response_chain_followup,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/long-command-after-pending-continuation-is-safe",
     test_long_command_after_pending_continuation_is_safe,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/a-bad-mac-on-a-long-alternate-opcode-write-frees-nothing-in-use",
     test_a_bad_mac_on_a_long_alternate_opcode_write_frees_nothing_in_use,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/empty-i-block-with-cid-uses-the-cards-own-number-and-echoes-the-cid",
     test_empty_i_block_with_cid_uses_the_cards_own_number_and_echoes_the_cid,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/i-block-does-not-touch-a-pending-direct-response",
     test_i_block_does_not_touch_a_pending_direct_response,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/r-block-does-not-touch-a-pending-direct-response",
     test_r_block_does_not_touch_a_pending_direct_response,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/a-direct-call-abandons-a-response-chain-in-flight",
     test_a_direct_call_abandons_a_response_chain_in_flight,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/a-direct-call-abandons-a-request-being-reassembled",
     test_a_direct_call_abandons_a_request_being_reassembled,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/mixed-apis-leave-no-stale-request-bytes",
     test_mixed_apis_leave_no_stale_request_bytes,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-dep-reader-chaining",
     test_iso_dep_reader_chaining,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/framed-unknown-iso-select-preserves-prefix-and-returns-not-found",
     test_framed_unknown_iso_select_preserves_prefix_and_returns_not_found,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/protocol-and-field-resets-reuse-allocations",
     test_protocol_and_field_resets_reuse_allocations,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/scan-reports-on-device-desfire-activation-vector",
     test_scan_reports_on_device_desfire_activation_vector,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/wrapped-get-version-detection-frame",
     test_wrapped_get_version_returns_detection_frame,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/factory-d40-trace-select-auth-read-path",
     test_factory_d40_trace_select_auth_read_path,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {"/dfc_virtual_picc_core", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
