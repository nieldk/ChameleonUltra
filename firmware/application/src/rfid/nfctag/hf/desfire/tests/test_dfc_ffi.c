// Smoke test for the shared library. Calls use the public FFI; the internal
// credential layout is visible only for rollback assertions.

#include "dfc_ffi.h"
#include "dfc_credential.h"
#include "dfc_der.h"
#include "dfc_reader.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

struct DfcFfiCredential {
    DfcCredential model;
};

// Credential builders return the stable model-status family described by the
// FFI, where capacity is the third nonzero status.
static const int32_t model_capacity_status = 3;

#define CHECK(cond)                                                                  \
    do {                                                                             \
        if(!(cond)) {                                                                \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                                              \
        }                                                                            \
    } while(0)

static const char CREDENTIAL[] =
    "Filetype: DFC Credential\n"
    "Version: 4\n"
    "Card Generation: EV2\n"
    "Card Storage: 4096\n"
    "UID: 04 22 33 44 55 66 77\n"
    "UID Provenance: Real\n"
    "PICC Key Settings 1: 0F\n"
    "PICC Key Settings 2: 01\n"
    "PICC Authentication Mode: D40\n"
    "PICC Key Count: 1\n"
    "PICC Key 00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n"
    "PICC Key 00 Version: 00\n"
    "PICC File Count: 0\n"
    "Application Count: 1\n"
    "Application 00 AID: 00 00 01\n"
    "Application 00 Key Settings 1: 0F\n"
    "Application 00 Key Settings 2: 82\n"
    "Application 00 Authentication Mode: AES\n"
    "Application 00 Key Count: 2\n"
    "Application 00 Key 00: 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF\n"
    "Application 00 Key 00 Version: 01\n"
    "Application 00 Key 01: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n"
    "Application 00 Key 01 Version: 00\n"
    "Application 00 File Count: 2\n"
    "Application 00 File 00 Number: 01\n"
    "Application 00 File 00 Type: Standard Data\n"
    "Application 00 File 00 Communication Settings: 01\n"
    "Application 00 File 00 Access Rights: 00 00\n"
    "Application 00 File 00 Size: 16\n"
    "Application 00 File 00 Data: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
    "Application 00 File 00 Data Complete: 1\n"
    "Application 00 File 01 Number: 02\n"
    "Application 00 File 01 Type: Value\n"
    "Application 00 File 01 Communication Settings: 00\n"
    "Application 00 File 01 Access Rights: 00 00\n"
    "Application 00 File 01 Value Lower Limit: 0\n"
    "Application 00 File 01 Value Upper Limit: 1000\n"
    "Application 00 File 01 Value: 42\n"
    "Application 00 File 01 Limited Credit: 00\n";

static const uint8_t APP_KEY[16] =
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

static size_t random_calls;

static int32_t counting_random(void* context, uint8_t* buffer, size_t len) {
    size_t* calls = context;
    (*calls)++;
    for(size_t i = 0; i < len; i++)
        buffer[i] = (uint8_t)(0x40 + i);
    return DFC_FFI_OK;
}

static int32_t failing_random(void* context, uint8_t* buffer, size_t len) {
    (void)context;
    (void)buffer;
    (void)len;
    return DFC_FFI_RANDOM_FAILED;
}

typedef struct {
    size_t calls;
    size_t failures_remaining;
} ScriptedRandom;

static int32_t scripted_random(void* context, uint8_t* buffer, size_t len) {
    ScriptedRandom* script = context;
    script->calls++;
    if(script->failures_remaining) {
        script->failures_remaining--;
        return DFC_FFI_RANDOM_FAILED;
    }
    for(size_t i = 0; i < len; i++)
        buffer[i] = (uint8_t)(0x60 + i);
    return DFC_FFI_OK;
}

static uint8_t* encode(const DfcFfiCredential* credential, size_t* len) {
    CHECK(dfc_ffi_credential_encode(credential, NULL, 0, len) == 0);
    uint8_t* out = malloc(*len);
    CHECK(dfc_ffi_credential_encode(credential, out, *len, len) == 0);
    return out;
}

typedef struct {
    DfcCredential* model;
    uint8_t* encoded;
    size_t encoded_len;
} CredentialState;

static CredentialState capture_credential_state(const DfcFfiCredential* credential) {
    CredentialState state = {0};
    state.model = malloc(sizeof(*state.model));
    CHECK(state.model != NULL);
    if(state.model) memcpy(state.model, &credential->model, sizeof(*state.model));
    state.encoded = encode(credential, &state.encoded_len);
    CHECK(state.encoded != NULL);
    return state;
}

static void check_credential_state_unchanged(
    const DfcFfiCredential* credential,
    const CredentialState* before) {
    if(before->model) {
        CHECK(memcmp(&credential->model, before->model, sizeof(*before->model)) == 0);
    }
    size_t after_len = 0;
    uint8_t* after = encode(credential, &after_len);
    CHECK(after_len == before->encoded_len);
    if(after && before->encoded && after_len == before->encoded_len) {
        CHECK(memcmp(after, before->encoded, after_len) == 0);
    }
    free(after);
}

static void free_credential_state(CredentialState* state) {
    free(state->encoded);
    free(state->model);
    memset(state, 0, sizeof(*state));
}

static DfcFfiCredential* parse_test_credential(void) {
    DfcFfiCredential* credential = NULL;
    DfcFfiError error;
    int32_t status =
        dfc_ffi_credential_parse_text(CREDENTIAL, sizeof(CREDENTIAL) - 1, &credential, &error);
    if(status != DFC_FFI_OK) {
        fprintf(stderr, "parse: %d line %u %s\n", status, error.line, error.message);
    }
    CHECK(status == DFC_FFI_OK);
    CHECK(credential != NULL);
    return credential;
}

static void check_encoded_round_trip(const DfcFfiCredential* credential) {
    size_t first_len = 0;
    uint8_t* first = encode(credential, &first_len);
    DfcFfiCredential* decoded = NULL;
    DfcFfiError error;
    CHECK(dfc_ffi_credential_decode(first, first_len, &decoded, &error) == DFC_FFI_OK);
    if(decoded) {
        size_t second_len = 0;
        uint8_t* second = encode(decoded, &second_len);
        CHECK(second_len == first_len);
        if(second && first && second_len == first_len)
            CHECK(memcmp(second, first, first_len) == 0);
        free(second);
    }
    dfc_ffi_credential_free(decoded);
    free(first);
}

static DfcFfiApplication capacity_test_application(uint8_t id, bool multiple_key_sets) {
    DfcFfiApplication application = {0};
    application.aid[0] = id;
    application.aid[1] = 0x45;
    application.aid[2] = 0x01;
    application.has_iso_file_id = 1;
    application.iso_file_id = (uint16_t)(0xE100u + id);
    application.df_name_len = 16;
    memset(application.df_name, id, application.df_name_len);
    application.key_settings_1 = 0x0F;
    application.key_settings_2 = (uint8_t)(DFC_KEY_TYPE_3K3DES | DFC_MAX_KEYS);
    application.auth_command = 0x1A;
    application.has_auth_commands = 1;
    application.auth_commands = DFC_AUTH_COMMAND_ISO_NATIVE;
    application.has_preferred_auth_command = 1;
    application.preferred_auth_command = DFC_AUTH_COMMAND_ISO_NATIVE;
    application.num_keys = DFC_MAX_KEYS;
    application.key_len = 24;
    if(multiple_key_sets) {
        application.num_key_sets = DFC_MAX_KEY_SETS;
        application.key_set_max_size = 24;
        application.key_set_settings = 0x5A;
        for(size_t i = 0; i < DFC_MAX_KEY_SETS; i++) {
            application.key_set_versions[i] = (uint8_t)i;
            application.key_set_types[i] = 1;
            application.key_set_initialized[i] = 1;
        }
    }
    return application;
}

static void initialize_test_card(DfcFfiCredential* credential, uint32_t generation) {
    DfcFfiCard card;
    CHECK(dfc_ffi_credential_get_card(credential, &card) == DFC_FFI_OK);
    card.generation = generation;
    card.uid_len = 7;
    memset(card.uid, 0x45, card.uid_len);
    CHECK(dfc_ffi_credential_set_card(credential, &card) == DFC_FFI_OK);
}

static void check_rejected_application_is_atomic(
    DfcFfiCredential* credential,
    const DfcFfiApplication* application,
    int32_t expected_status) {
    size_t before_len = 0;
    uint8_t* before_bytes = encode(credential, &before_len);
    DfcCredential* before = malloc(sizeof(*before));
    CHECK(before != NULL);
    if(!before) {
        free(before_bytes);
        return;
    }
    memcpy(before, &credential->model, sizeof(*before));

    uint32_t index = UINT32_C(0xA5A5A5A5);
    CHECK(dfc_ffi_credential_add_application(credential, application, &index) == expected_status);
    CHECK(index == UINT32_C(0xA5A5A5A5));
    CHECK(memcmp(&credential->model, before, sizeof(*before)) == 0);

    size_t after_len = 0;
    uint8_t* after_bytes = encode(credential, &after_len);
    CHECK(after_len == before_len);
    CHECK(after_len != before_len || memcmp(after_bytes, before_bytes, before_len) == 0);

    if(credential->model.num_apps < DFC_MAX_APPS) {
        DfcApplication empty;
        dfc_credential_reset_application(&empty);
        CHECK(
            memcmp(&credential->model.apps[credential->model.num_apps], &empty, sizeof(empty)) ==
            0);
    }

    free(after_bytes);
    free(before);
    free(before_bytes);
}

static void check_application_creation_rollback(void) {
    for(size_t multiple_key_sets = 0; multiple_key_sets < 2; multiple_key_sets++) {
        DfcFfiCredential* credential = NULL;
        CHECK(dfc_ffi_credential_new(&credential) == DFC_FFI_OK);
        if(!credential) continue;

        initialize_test_card(credential, DfcGenerationEv2);

        DfcFfiApplication rejected = capacity_test_application(
            (uint8_t)(0x80u + multiple_key_sets), multiple_key_sets != 0);
        size_t allocation = (size_t)rejected.num_keys *
                            (multiple_key_sets ? rejected.num_key_sets : 1u) *
                            dfc_credential_stored_key_length(rejected.key_len);
        DfcFfiApplication large_filler =
            capacity_test_application((uint8_t)(credential->model.num_apps + 1u), true);
        size_t large_allocation = (size_t)large_filler.num_keys * large_filler.num_key_sets *
                                  dfc_credential_stored_key_length(large_filler.key_len);
        while(dfc_credential_key_pool_free(&credential->model) >= large_allocation &&
              credential->model.num_apps < DFC_MAX_APPS) {
            large_filler.aid[0] = (uint8_t)(credential->model.num_apps + 1u);
            uint32_t index = UINT32_MAX;
            CHECK(
                dfc_ffi_credential_add_application(credential, &large_filler, &index) ==
                DFC_FFI_OK);
        }
        while(dfc_credential_key_pool_free(&credential->model) >= allocation &&
              credential->model.num_apps < DFC_MAX_APPS) {
            DfcFfiApplication filler =
                capacity_test_application((uint8_t)(credential->model.num_apps + 1u), false);
            uint32_t index = UINT32_MAX;
            CHECK(dfc_ffi_credential_add_application(credential, &filler, &index) == DFC_FFI_OK);
        }
        CHECK(credential->model.num_apps < DFC_MAX_APPS);
        CHECK(dfc_credential_key_pool_free(&credential->model) < allocation);
        check_rejected_application_is_atomic(credential, &rejected, model_capacity_status);
        dfc_ffi_credential_free(credential);
    }

    DfcFfiCredential* duplicate = NULL;
    CHECK(dfc_ffi_credential_new(&duplicate) == DFC_FFI_OK);
    if(duplicate) {
        initialize_test_card(duplicate, DfcGenerationEv1);
        DfcFfiApplication application = capacity_test_application(0x31, false);
        application.num_keys = 1;
        uint32_t index = UINT32_MAX;
        CHECK(dfc_ffi_credential_add_application(duplicate, &application, &index) == DFC_FFI_OK);
        check_rejected_application_is_atomic(duplicate, &application, DfcDerMalformed);
        dfc_ffi_credential_free(duplicate);
    }

    DfcFfiCredential* full = NULL;
    CHECK(dfc_ffi_credential_new(&full) == DFC_FFI_OK);
    if(full) {
        initialize_test_card(full, DfcGenerationEv1);
        for(size_t i = 0; i < DFC_MAX_APPS; i++) {
            DfcFfiApplication application = capacity_test_application((uint8_t)(i + 1u), false);
            application.num_keys = 1;
            application.key_len = 8;
            application.key_settings_2 = (uint8_t)(DFC_KEY_TYPE_DES_2K3DES | 1u);
            uint32_t index = UINT32_MAX;
            CHECK(dfc_ffi_credential_add_application(full, &application, &index) == DFC_FFI_OK);
        }
        DfcFfiApplication rejected = capacity_test_application(0xF0, false);
        check_rejected_application_is_atomic(full, &rejected, model_capacity_status);
        dfc_ffi_credential_free(full);
    }
}

static void check_rejected_card_and_picc_updates(void) {
    DfcFfiCredential* credential = parse_test_credential();
    if(!credential) return;

    CredentialState before = capture_credential_state(credential);
    CHECK(dfc_ffi_credential_set_card(credential, NULL) == DFC_FFI_INVALID_ARGUMENT);
    check_credential_state_unchanged(credential, &before);
    free_credential_state(&before);

    DfcFfiCard card;
    CHECK(dfc_ffi_credential_get_card(credential, &card) == DFC_FFI_OK);
    card.uid_len = 5;
    before = capture_credential_state(credential);
    CHECK(dfc_ffi_credential_set_card(credential, &card) == DFC_FFI_INVALID_ARGUMENT);
    check_credential_state_unchanged(credential, &before);
    free_credential_state(&before);

    before = capture_credential_state(credential);
    CHECK(dfc_ffi_credential_set_picc(credential, NULL) == DFC_FFI_INVALID_ARGUMENT);
    check_credential_state_unchanged(credential, &before);
    free_credential_state(&before);

    DfcFfiPiccSettings valid;
    CHECK(dfc_ffi_credential_get_picc(credential, &valid) == DFC_FFI_OK);
    DfcFfiPiccSettings invalid[6];
    for(size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
        invalid[i] = valid;
    invalid[0].ats_len = (uint8_t)(DFC_PICC_ATS_MAX + 1);
    invalid[1].num_keys = DFC_MAX_KEYS + 1;
    invalid[2].key_len = DFC_MAX_KEY_LEN + 1;
    invalid[3].virtual_card_configured = 1;
    invalid[3].virtual_card_installation_id_len =
        (uint8_t)(DFC_VIRTUAL_CARD_MAX_INSTALLATION_ID_LENGTH + 1);
    invalid[3].virtual_card_uid_len = 7;
    invalid[4].virtual_card_configured = 1;
    invalid[4].virtual_card_installation_id_len = 1;
    invalid[4].virtual_card_uid_len = 5;
    invalid[5].random_id = 0;
    invalid[5].random_id_legacy = 1;

    for(size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        before = capture_credential_state(credential);
        CHECK(dfc_ffi_credential_set_picc(credential, &invalid[i]) == DFC_FFI_INVALID_ARGUMENT);
        check_credential_state_unchanged(credential, &before);
        free_credential_state(&before);
    }
    dfc_ffi_credential_free(credential);
}

static DfcFfiFile plain_file(int32_t owner, uint8_t number) {
    DfcFfiFile file = {0};
    file.owner = owner;
    file.number = number;
    file.type = DFC_FILE_TYPE_STANDARD_DATA;
    file.comm_settings = DFC_COMM_PLAIN;
    file.access_rights = 0xEEEE;
    file.declared_size = 1;
    return file;
}

static void check_rejected_file_creation_is_atomic(void) {
    DfcFfiCredential* credential = parse_test_credential();
    if(!credential) return;

    DfcFfiFile duplicate;
    CHECK(dfc_ffi_credential_get_file(credential, 0, &duplicate) == DFC_FFI_OK);
    uint32_t index = UINT32_C(0xA5A5A5A5);
    CredentialState before = capture_credential_state(credential);
    CHECK(dfc_ffi_credential_add_file(credential, &duplicate, &index) == DfcDerMalformed);
    CHECK(index == UINT32_C(0xA5A5A5A5));
    check_credential_state_unchanged(credential, &before);
    free_credential_state(&before);

    const int32_t invalid_owners[] = {-2, 1};
    for(size_t i = 0; i < sizeof(invalid_owners) / sizeof(invalid_owners[0]); i++) {
        DfcFfiFile invalid = plain_file(invalid_owners[i], DFC_EV1_MAX_FILE_NUMBER);
        index = UINT32_C(0xA5A5A5A5);
        before = capture_credential_state(credential);
        CHECK(
            dfc_ffi_credential_add_file(credential, &invalid, &index) == DFC_FFI_INVALID_ARGUMENT);
        CHECK(index == UINT32_C(0xA5A5A5A5));
        check_credential_state_unchanged(credential, &before);
        free_credential_state(&before);
    }

    DfcFfiFile invalid = plain_file(0, DFC_EV1_MAX_FILE_NUMBER);
    invalid.comm_settings = 0x02;
    index = UINT32_C(0xA5A5A5A5);
    before = capture_credential_state(credential);
    CHECK(dfc_ffi_credential_add_file(credential, &invalid, &index) == DfcDerMalformed);
    CHECK(index == UINT32_C(0xA5A5A5A5));
    check_credential_state_unchanged(credential, &before);
    free_credential_state(&before);

    invalid = plain_file(0, DFC_EV1_MAX_FILE_NUMBER);
    invalid.access_rights = 0x2EEE;
    index = UINT32_C(0xA5A5A5A5);
    before = capture_credential_state(credential);
    CHECK(dfc_ffi_credential_add_file(credential, &invalid, &index) == DfcDerMalformed);
    CHECK(index == UINT32_C(0xA5A5A5A5));
    check_credential_state_unchanged(credential, &before);
    free_credential_state(&before);

    invalid = plain_file(0, DFC_EV1_MAX_FILE_NUMBER);
    invalid.type = DFC_FILE_TYPE_VALUE;
    invalid.value_lower_limit = 0;
    invalid.value_upper_limit = 100;
    invalid.value = 50;
    invalid.limited_credit = 0;
    invalid.limited_credit_value = 1;
    index = UINT32_C(0xA5A5A5A5);
    before = capture_credential_state(credential);
    CHECK(dfc_ffi_credential_add_file(credential, &invalid, &index) == DfcDerMalformed);
    CHECK(index == UINT32_C(0xA5A5A5A5));
    check_credential_state_unchanged(credential, &before);
    free_credential_state(&before);

#if DFC_ENABLE_TRANSACTION_MAC
    invalid = plain_file(0, DFC_EV1_MAX_FILE_NUMBER);
    invalid.type = DFC_FILE_TYPE_TRANSACTION_MAC;
    invalid.access_rights = 0x0F00;
    invalid.transaction_mac_key_type = DFC_TRANSACTION_MAC_KEY_TYPE_AES + 1;
    index = UINT32_C(0xA5A5A5A5);
    before = capture_credential_state(credential);
    CHECK(dfc_ffi_credential_add_file(credential, &invalid, &index) == DfcDerMalformed);
    CHECK(index == UINT32_C(0xA5A5A5A5));
    check_credential_state_unchanged(credential, &before);
    free_credential_state(&before);
#endif

    while(credential->model.num_apps < 16) {
        DfcFfiApplication application =
            capacity_test_application((uint8_t)(0x40u + credential->model.num_apps), false);
        application.num_keys = 1;
        application.key_len = 8;
        application.key_settings_2 = (uint8_t)(DFC_KEY_TYPE_DES_2K3DES | 1u);
        index = UINT32_MAX;
        CHECK(dfc_ffi_credential_add_application(credential, &application, &index) == DFC_FFI_OK);
    }
    for(int32_t owner = DFC_FFI_OWNER_PICC;
        owner < (int32_t)credential->model.num_apps && credential->model.num_files < DFC_MAX_FILES;
        owner++) {
        for(uint32_t number = 0;
            number <= DFC_EV1_MAX_FILE_NUMBER && credential->model.num_files < DFC_MAX_FILES;
            number++) {
            DfcFfiFile file = plain_file(owner, (uint8_t)number);
            index = UINT32_MAX;
            int32_t status = dfc_ffi_credential_add_file(credential, &file, &index);
            CHECK(status == DFC_FFI_OK || status == DfcDerMalformed);
        }
    }
    CHECK(credential->model.num_files == DFC_MAX_FILES);
    CHECK(dfc_ffi_credential_validate(credential) == DFC_FFI_OK);
    DfcFfiFile full = plain_file(DFC_FFI_OWNER_PICC, 0xFF);
    index = UINT32_C(0xA5A5A5A5);
    before = capture_credential_state(credential);
    CHECK(dfc_ffi_credential_add_file(credential, &full, &index) == DfcDerCapacity);
    CHECK(index == UINT32_C(0xA5A5A5A5));
    check_credential_state_unchanged(credential, &before);
    free_credential_state(&before);
    dfc_ffi_credential_free(credential);
}

static void check_pool_resize_boundaries(void) {
    DfcFfiCredential* credential = parse_test_credential();
    if(!credential) return;

    uint8_t byte = 0xA5;
    CredentialState before = capture_credential_state(credential);
    CHECK(
        dfc_ffi_credential_set_file_data(credential, 0, &byte, (size_t)DFC_MAX_FILE_DATA + 1) ==
        DfcDerCapacity);
    check_credential_state_unchanged(credential, &before);
    free_credential_state(&before);

    DfcApplication* app = &credential->model.apps[0];
    before = capture_credential_state(credential);
    CHECK(!dfc_credential_keys_resize(
        &credential->model, app, (size_t)DFC_MAX_KEYS + 1, DFC_MAX_KEY_LEN));
    check_credential_state_unchanged(credential, &before);
    free_credential_state(&before);

    DfcFile no_file_slice = {.data_offset = DFC_FILE_POOL_NONE, .data_len = 1};
    DfcFile no_file_slice_before = no_file_slice;
    before = capture_credential_state(credential);
    CHECK(!dfc_file_resize(&credential->model, &no_file_slice, 1));
    CHECK(memcmp(&no_file_slice, &no_file_slice_before, sizeof(no_file_slice)) == 0);
    check_credential_state_unchanged(credential, &before);
    free_credential_state(&before);

    DfcApplication no_key_slice;
    dfc_credential_reset_application(&no_key_slice);
    no_key_slice.key_pool_len = 1;
    DfcApplication no_key_slice_before = no_key_slice;
    before = capture_credential_state(credential);
    CHECK(!dfc_credential_keys_resize(&credential->model, &no_key_slice, 1, 16));
    CHECK(memcmp(&no_key_slice, &no_key_slice_before, sizeof(no_key_slice)) == 0);
    check_credential_state_unchanged(credential, &before);
    free_credential_state(&before);

    size_t file_used = credential->model.file_pool_used;
    credential->model.file_pool_used = DFC_FILE_POOL_SIZE + 1;
    DfcCredential invalid_before = credential->model;
    size_t before_len = SIZE_MAX;
    int32_t before_status = dfc_ffi_credential_encode(credential, NULL, 0, &before_len);
    CHECK(before_status != DFC_FFI_OK);
    CHECK(!dfc_file_resize(&credential->model, &credential->model.files[0], 16));
    CHECK(memcmp(&credential->model, &invalid_before, sizeof(invalid_before)) == 0);
    size_t after_len = SIZE_MAX;
    CHECK(dfc_ffi_credential_encode(credential, NULL, 0, &after_len) == before_status);
    CHECK(after_len == before_len);
    credential->model.file_pool_used = file_used;

    size_t key_used = credential->model.key_pool_used;
    credential->model.key_pool_used = DFC_KEY_POOL_SIZE + 1;
    invalid_before = credential->model;
    before_len = SIZE_MAX;
    before_status = dfc_ffi_credential_encode(credential, NULL, 0, &before_len);
    CHECK(before_status != DFC_FFI_OK);
    CHECK(!dfc_credential_keys_resize(&credential->model, app, app->num_keys, app->key_len));
    CHECK(memcmp(&credential->model, &invalid_before, sizeof(invalid_before)) == 0);
    after_len = SIZE_MAX;
    CHECK(dfc_ffi_credential_encode(credential, NULL, 0, &after_len) == before_status);
    CHECK(after_len == before_len);
    credential->model.key_pool_used = key_used;

    credential->model.files[0].contents_complete = false;
    size_t initial_file_pool = credential->model.file_pool_used;
    CHECK(dfc_file_resize(&credential->model, &credential->model.files[0], 0));
    CHECK(credential->model.files[0].data_offset == DFC_FILE_POOL_NONE);
    CHECK(credential->model.files[0].data_len == 0);
    CHECK(credential->model.file_pool_used + 16 == initial_file_pool);
    check_encoded_round_trip(credential);

    DfcFfiPiccSettings picc;
    CHECK(dfc_ffi_credential_get_picc(credential, &picc) == DFC_FFI_OK);
    size_t initial_key_pool = credential->model.key_pool_used;
    size_t initial_app_offset = app->key_offset;
    uint8_t app_key[16];
    memcpy(app_key, dfc_credential_key_const(&credential->model, app, 0), sizeof(app_key));
    picc.num_keys = 0;
    picc.key_len = 0;
    CHECK(dfc_ffi_credential_set_picc(credential, &picc) == DFC_FFI_OK);
    CHECK(credential->model.picc_key_offset == DFC_KEY_POOL_NONE);
    CHECK(credential->model.picc_key_pool_len == 0);
    CHECK(credential->model.picc_num_keys == 0);
    CHECK(credential->model.key_pool_used + 16 == initial_key_pool);
    CHECK(app->key_offset + 16 == initial_app_offset);
    CHECK(
        memcmp(dfc_credential_key_const(&credential->model, app, 0), app_key, sizeof(app_key)) ==
        0);
    check_encoded_round_trip(credential);

    initial_key_pool = credential->model.key_pool_used;
    // Keep the model valid while exercising zero-length key-pool compaction.
    const uint16_t free_access_rights =
        (uint16_t)((DFC_ACCESS_FREE << 12) | (DFC_ACCESS_FREE << 8) | (DFC_ACCESS_FREE << 4) |
                   DFC_ACCESS_FREE);
    for(size_t i = 0; i < credential->model.num_files; i++) {
        if(credential->model.files[i].app_index == 0)
            credential->model.files[i].access_rights = free_access_rights;
    }
    CHECK(dfc_credential_keys_resize(&credential->model, app, 0, 16));
    CHECK(app->key_offset == DFC_KEY_POOL_NONE);
    CHECK(app->key_pool_len == 0);
    CHECK(app->num_keys == 0);
    CHECK(credential->model.key_pool_used + 32 == initial_key_pool);
    check_encoded_round_trip(credential);

    dfc_ffi_credential_free(credential);
}

static DfcFfiKey repeated_key(uint32_t len, uint8_t value, uint8_t version) {
    DfcFfiKey key = {.len = len, .version = version};
    memset(key.value, value, len);
    return key;
}

static void check_key(
    const DfcFfiCredential* credential,
    int32_t owner,
    uint32_t key_set,
    uint32_t slot,
    const DfcFfiKey* expected) {
    DfcFfiKey actual;
    CHECK(dfc_ffi_credential_get_key(credential, owner, key_set, slot, &actual) == 0);
    CHECK(actual.len == expected->len);
    CHECK(actual.version == expected->version);
    CHECK(memcmp(actual.value, expected->value, expected->len) == 0);
}

// Rebuild a credential from nothing but what the walk returns.
static DfcFfiCredential* rebuild(const DfcFfiCredential* source) {
    DfcFfiCredential* built = NULL;
    CHECK(dfc_ffi_credential_new(&built) == 0);
    DfcFfiCard card;
    DfcFfiPiccSettings picc;
    CHECK(dfc_ffi_credential_get_card(source, &card) == 0);
    CHECK(dfc_ffi_credential_get_picc(source, &picc) == 0);
    CHECK(dfc_ffi_credential_set_card(built, &card) == 0);
    CHECK(dfc_ffi_credential_set_picc(built, &picc) == 0);
    for(uint32_t slot = 0; slot < picc.num_keys; slot++) {
        DfcFfiKey key;
        CHECK(dfc_ffi_credential_get_key(source, DFC_FFI_OWNER_PICC, 0, slot, &key) == 0);
        CHECK(dfc_ffi_credential_set_key(built, DFC_FFI_OWNER_PICC, 0, slot, &key) == 0);
    }
    uint32_t apps = dfc_ffi_credential_application_count(source);
    for(uint32_t i = 0; i < apps; i++) {
        DfcFfiApplication app;
        uint32_t index = 0;
        CHECK(dfc_ffi_credential_get_application(source, i, &app) == 0);
        CHECK(dfc_ffi_credential_add_application(built, &app, &index) == 0);
        CHECK(index == i);
        for(uint32_t slot = 0; slot < app.num_keys; slot++) {
            DfcFfiKey key;
            CHECK(dfc_ffi_credential_get_key(source, (int32_t)i, 0, slot, &key) == 0);
            CHECK(dfc_ffi_credential_set_key(built, (int32_t)i, 0, slot, &key) == 0);
        }
    }
    uint32_t files = dfc_ffi_credential_file_count(source);
    for(uint32_t i = 0; i < files; i++) {
        DfcFfiFile file;
        uint32_t index = 0;
        CHECK(dfc_ffi_credential_get_file(source, i, &file) == 0);
        CHECK(dfc_ffi_credential_add_file(built, &file, &index) == 0);
        size_t len = 0;
        CHECK(dfc_ffi_credential_get_file_data(source, i, NULL, 0, &len) == 0);
        if(len) {
            uint8_t* data = malloc(len);
            CHECK(dfc_ffi_credential_get_file_data(source, i, data, len, &len) == 0);
            CHECK(dfc_ffi_credential_set_file_data(built, index, data, len) == 0);
            free(data);
        }
    }
    DfcFfiError error;
    CHECK(dfc_ffi_credential_finish(built, &error) == 0);
    return built;
}

static void check_delegated_format_ffi_round_trip(void) {
    DfcFfiCredential* source = parse_test_credential();
    if(!source) return;
    DfcApplication* native = &source->model.apps[0];
    native->delegated = true;
    native->delegated_slot_number = 1;
    native->delegated_slot_version = 1;
    native->delegated_quota_limit = 64;
    native->delegated_free_blocks = 40;
    native->delegated_format_disabled = true;

    DfcFfiApplication exported;
    CHECK(dfc_ffi_credential_get_application(source, 0, &exported) == DFC_FFI_OK);
    CHECK(exported.delegated_format_disabled == 1);

    DfcFfiCredential* copied = rebuild(source);
    DfcFfiApplication imported;
    CHECK(dfc_ffi_credential_get_application(copied, 0, &imported) == DFC_FFI_OK);
    CHECK(imported.delegated_format_disabled == 1);
    check_encoded_round_trip(copied);

    dfc_ffi_credential_free(copied);
    dfc_ffi_credential_free(source);
}

static void check_limited_credit_value_ffi_round_trip(void) {
    DfcFfiCredential* source = parse_test_credential();
    if(!source) return;
    DfcFile* native = &source->model.files[1];
    native->limited_credit = 1;
    native->limited_credit_value = 37;

    DfcFfiFile exported;
    CHECK(dfc_ffi_credential_get_file(source, 1, &exported) == DFC_FFI_OK);
    CHECK(exported.limited_credit_value == 37);

    DfcFfiCredential* copied = rebuild(source);
    DfcFfiFile imported;
    CHECK(dfc_ffi_credential_get_file(copied, 1, &imported) == DFC_FFI_OK);
    CHECK(imported.limited_credit_value == 37);
    check_encoded_round_trip(copied);

    dfc_ffi_credential_free(copied);
    dfc_ffi_credential_free(source);
}

// Drive one reader exchange against the PICC until it completes.
static int32_t run(DfcFfiPicc* picc, DfcFfiReaderExchange* exchange) {
    uint8_t tx[300];
    uint8_t rx[600];
    size_t tx_len = 0;
    size_t rx_len = 0;
    const uint8_t* answer = NULL;
    int32_t st;
    while((st = dfc_ffi_reader_step(exchange, answer, rx_len, tx, sizeof(tx), &tx_len)) == 1) {
        CHECK(dfc_ffi_picc_exchange(picc, tx, tx_len, rx, sizeof(rx), &rx_len) == 0);
        answer = rx;
    }
    return st;
}

// The clear head of an encrypted write is an int32 here and one octet in the
// reader, so this is where an out-of-range value would otherwise wrap into a
// legal one (256 into 0, 257 into 1). The core owns the bound; the interface
// refuses what lies beyond it, and what it refuses leaves the session alone.
// DFC_READER_MAX_CLEAR_HEADER_LENGTH is the only number the test relies on.
static void check_reader_header_length_bound(void) {
    DfcFfiReaderSession* session = NULL;
    DfcFfiReaderExchange* exchange = NULL;
    CHECK(dfc_ffi_reader_session_new(&session) == 0);
    CHECK(dfc_ffi_reader_exchange_new(&exchange) == 0);
    const uint8_t data[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA5};

    const int32_t accepted[] = {-1, 0, DFC_READER_MAX_CLEAR_HEADER_LENGTH};
    for(size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
        CHECK(
            dfc_ffi_reader_exchange_begin(
                exchange, session, 0, 0x3D, data, sizeof(data), DFC_COMM_ENCIPHERED, accepted[i]) ==
            0);
    }

    DfcFfiReaderState before;
    DfcFfiReaderState after;
    CHECK(dfc_ffi_reader_session_state(session, &before) == 0);
    const int32_t refused[] = {
        -2,
        DFC_READER_MAX_CLEAR_HEADER_LENGTH + 1,
        255,
        256, // would narrow to 0
        257, // would narrow to 1
        INT32_MAX,
        INT32_MIN,
    };
    for(size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
        CHECK(
            dfc_ffi_reader_exchange_begin(
                exchange, session, 0, 0x3D, data, sizeof(data), DFC_COMM_ENCIPHERED, refused[i]) ==
            DFC_FFI_INVALID_ARGUMENT);
        CHECK(dfc_ffi_reader_session_state(session, &after) == 0);
        CHECK(memcmp(&before, &after, sizeof(before)) == 0);
    }
    dfc_ffi_reader_exchange_free(exchange);
    dfc_ffi_reader_session_free(session);
}

static void check_failed_reader_result_is_retired(void) {
    DfcFfiReaderSession* session = NULL;
    DfcFfiReaderExchange* exchange = NULL;
    CHECK(dfc_ffi_reader_session_new(&session) == DFC_FFI_OK);
    CHECK(dfc_ffi_reader_exchange_new(&exchange) == DFC_FFI_OK);
    if(!session || !exchange) goto cleanup;

    CHECK(
        dfc_ffi_reader_exchange_begin(
            exchange, session, DfcReaderFramingNative, DFC_CMD_GET_VERSION, NULL, 0, 0, -1) ==
        DfcReaderOk);
    uint8_t frame[16] = {0};
    size_t frame_len = 0;
    CHECK(
        dfc_ffi_reader_step(exchange, NULL, 0, frame, sizeof(frame), &frame_len) ==
        DfcReaderPending);
    const uint8_t malformed_error[] = {DFC_STATUS_PERMISSION_DENIED, 0xA5, 0xB6};
    CHECK(
        dfc_ffi_reader_step(
            exchange, malformed_error, sizeof(malformed_error), frame, sizeof(frame), &frame_len) ==
        DfcReaderProtocolError);
    size_t result_len = SIZE_MAX;
    CHECK(dfc_ffi_reader_result_data(exchange, NULL, 0, &result_len) == DFC_FFI_OK);
    CHECK(result_len == 0);

cleanup:
    dfc_ffi_reader_exchange_free(exchange);
    dfc_ffi_reader_session_free(session);
}

int main(void) {
    check_rejected_card_and_picc_updates();
    check_application_creation_rollback();
    check_reader_header_length_bound();
    check_failed_reader_result_is_retired();
    check_rejected_file_creation_is_atomic();
    check_pool_resize_boundaries();
    check_delegated_format_ffi_round_trip();
    check_limited_credit_value_ffi_round_trip();

    CHECK(dfc_ffi_abi_version() == DFC_FFI_ABI_VERSION);
    CHECK(dfc_ffi_layout_fingerprint() != 0);
    enum {
        RandomSampleLength = 16
    };
    uint8_t random_bytes[RandomSampleLength];
    CHECK(dfc_ffi_random_fill(random_bytes, sizeof(random_bytes)) == DFC_FFI_OK);
    CHECK(dfc_ffi_random_fill(NULL, sizeof(random_bytes)) == DFC_FFI_INVALID_ARGUMENT);
    uint8_t same_bytes[RandomSampleLength];
    memcpy(same_bytes, random_bytes, sizeof(same_bytes));
    CHECK(dfc_ffi_fixed_time_equal(random_bytes, same_bytes, sizeof(same_bytes)));
    same_bytes[0] ^= 1;
    CHECK(!dfc_ffi_fixed_time_equal(random_bytes, same_bytes, sizeof(same_bytes)));
    dfc_ffi_secure_zero(random_bytes, sizeof(random_bytes));
    for(size_t index = 0; index < sizeof(random_bytes); index++)
        CHECK(random_bytes[index] == 0);
    DfcFfiCapabilities caps;
    dfc_ffi_capabilities(&caps);
    CHECK(caps.emulator && caps.reader && caps.text_codec);
    DfcFfiStructSizes sizes;
    dfc_ffi_struct_sizes(&sizes);
    CHECK(sizes.card == sizeof(DfcFfiCard));
    CHECK(sizes.file == sizeof(DfcFfiFile));
    CHECK(sizes.application == sizeof(DfcFfiApplication));

    // Reusing a builder replaces optional settings. Disabling an option must
    // clear both its presence bit and the data it previously owned.
    DfcFfiCredential* updated = NULL;
    CHECK(dfc_ffi_credential_new(&updated) == DFC_FFI_OK);
    DfcFfiCard update_card = {0};
    update_card.uid_len = 7;
    update_card.has_static_signature = 1;
    memset(update_card.static_signature, 0xA5, sizeof(update_card.static_signature));
    CHECK(dfc_ffi_credential_set_card(updated, &update_card) == DFC_FFI_OK);
    update_card.has_static_signature = 0;
    CHECK(dfc_ffi_credential_set_card(updated, &update_card) == DFC_FFI_OK);
    DfcFfiCard read_card;
    CHECK(dfc_ffi_credential_get_card(updated, &read_card) == DFC_FFI_OK);
    CHECK(!read_card.has_static_signature);
    for(size_t i = 0; i < sizeof(read_card.static_signature); i++)
        CHECK(read_card.static_signature[i] == 0);

    DfcFfiPiccSettings update_picc = {0};
    update_picc.num_keys = 1;
    update_picc.key_len = 16;
    update_picc.has_ev2_capabilities = 1;
    memset(update_picc.ev2_capabilities, 0x11, sizeof(update_picc.ev2_capabilities));
    update_picc.has_proximity_key = 1;
    memset(update_picc.proximity_key, 0x22, sizeof(update_picc.proximity_key));
    update_picc.proximity_option = 0x23;
    update_picc.has_proximity_bitrate = 1;
    update_picc.proximity_bitrate = 0x24;
    update_picc.proximity_published_response_time = 0x2526;
    update_picc.virtual_card_configured = 1;
    update_picc.virtual_card_uid_len = 7;
    update_picc.virtual_card_installation_id_len = 4;
    memset(
        update_picc.virtual_card_installation_id,
        0x31,
        sizeof(update_picc.virtual_card_installation_id));
    update_picc.virtual_card_information = 0x32;
    memset(
        update_picc.virtual_card_capabilities,
        0x33,
        sizeof(update_picc.virtual_card_capabilities));
    memset(update_picc.virtual_card_uid, 0x34, sizeof(update_picc.virtual_card_uid));
    memset(
        update_picc.virtual_card_select_mac_key,
        0x35,
        sizeof(update_picc.virtual_card_select_mac_key));
    memset(
        update_picc.virtual_card_select_encryption_key,
        0x36,
        sizeof(update_picc.virtual_card_select_encryption_key));
    update_picc.virtual_card_authentication_mandatory = 1;
    update_picc.virtual_card_proximity_mandatory = 1;
    update_picc.has_dam_keys = 1;
    memset(update_picc.dam_auth_key, 0x44, sizeof(update_picc.dam_auth_key));
    memset(update_picc.dam_mac_key, 0x45, sizeof(update_picc.dam_mac_key));
    memset(update_picc.dam_encryption_key, 0x46, sizeof(update_picc.dam_encryption_key));
    CHECK(dfc_ffi_credential_set_picc(updated, &update_picc) == DFC_FFI_OK);
    update_picc.has_ev2_capabilities = 0;
    update_picc.has_proximity_key = 0;
    update_picc.virtual_card_configured = 0;
    update_picc.has_dam_keys = 0;
    CHECK(dfc_ffi_credential_set_picc(updated, &update_picc) == DFC_FFI_OK);
    DfcFfiPiccSettings read_picc;
    CHECK(dfc_ffi_credential_get_picc(updated, &read_picc) == DFC_FFI_OK);
    CHECK(!read_picc.has_ev2_capabilities);
    CHECK(!read_picc.has_proximity_key);
    CHECK(!read_picc.virtual_card_configured);
    CHECK(!read_picc.has_dam_keys);
    for(size_t i = 0; i < sizeof(read_picc.ev2_capabilities); i++)
        CHECK(read_picc.ev2_capabilities[i] == 0);
    for(size_t i = 0; i < sizeof(read_picc.proximity_key); i++)
        CHECK(read_picc.proximity_key[i] == 0);
    CHECK(read_picc.proximity_option == 0);
    CHECK(!read_picc.has_proximity_bitrate);
    CHECK(read_picc.proximity_bitrate == 0);
    CHECK(read_picc.proximity_published_response_time == 0);
    CHECK(read_picc.virtual_card_installation_id_len == 0);
    for(size_t i = 0; i < sizeof(read_picc.virtual_card_installation_id); i++)
        CHECK(read_picc.virtual_card_installation_id[i] == 0);
    CHECK(read_picc.virtual_card_information == 0);
    for(size_t i = 0; i < sizeof(read_picc.virtual_card_capabilities); i++)
        CHECK(read_picc.virtual_card_capabilities[i] == 0);
    CHECK(read_picc.virtual_card_uid_len == 0);
    for(size_t i = 0; i < sizeof(read_picc.virtual_card_uid); i++)
        CHECK(read_picc.virtual_card_uid[i] == 0);
    for(size_t i = 0; i < sizeof(read_picc.virtual_card_select_mac_key); i++)
        CHECK(read_picc.virtual_card_select_mac_key[i] == 0);
    for(size_t i = 0; i < sizeof(read_picc.virtual_card_select_encryption_key); i++)
        CHECK(read_picc.virtual_card_select_encryption_key[i] == 0);
    CHECK(!read_picc.virtual_card_authentication_mandatory);
    CHECK(!read_picc.virtual_card_proximity_mandatory);
    for(size_t i = 0; i < sizeof(read_picc.dam_auth_key); i++)
        CHECK(read_picc.dam_auth_key[i] == 0);
    for(size_t i = 0; i < sizeof(read_picc.dam_mac_key); i++)
        CHECK(read_picc.dam_mac_key[i] == 0);
    for(size_t i = 0; i < sizeof(read_picc.dam_encryption_key); i++)
        CHECK(read_picc.dam_encryption_key[i] == 0);
    dfc_ffi_credential_free(updated);

    // Rejecting malformed optional settings must leave both settings and key
    // material unchanged, including when validation fails late in the group.
    DfcFfiCredential* atomic = NULL;
    CHECK(dfc_ffi_credential_new(&atomic) == DFC_FFI_OK);
    DfcFfiPiccSettings atomic_picc = {0};
    atomic_picc.num_keys = 1;
    atomic_picc.key_len = 16;
    atomic_picc.key_settings_1 = 0x0F;
    atomic_picc.key_settings_2 = 0x01;
    atomic_picc.random_id = 1;
    CHECK(dfc_ffi_credential_set_picc(atomic, &atomic_picc) == DFC_FFI_OK);
    DfcFfiKey atomic_key = repeated_key(16, 0x6A, 0x07);
    CHECK(dfc_ffi_credential_set_key(atomic, DFC_FFI_OWNER_PICC, 0, 0, &atomic_key) == DFC_FFI_OK);
    DfcFfiPiccSettings atomic_before;
    CHECK(dfc_ffi_credential_get_picc(atomic, &atomic_before) == DFC_FFI_OK);

    DfcFfiPiccSettings malformed = atomic_before;
    malformed.virtual_card_configured = 1;
    malformed.virtual_card_installation_id_len =
        (uint8_t)(sizeof(malformed.virtual_card_installation_id) + 1);
    malformed.virtual_card_uid_len = 7;
    CHECK(dfc_ffi_credential_set_picc(atomic, &malformed) == DFC_FFI_INVALID_ARGUMENT);
    DfcFfiPiccSettings atomic_after;
    CHECK(dfc_ffi_credential_get_picc(atomic, &atomic_after) == DFC_FFI_OK);
    CHECK(memcmp(&atomic_after, &atomic_before, sizeof(atomic_before)) == 0);
    check_key(atomic, DFC_FFI_OWNER_PICC, 0, 0, &atomic_key);

    malformed = atomic_before;
    malformed.virtual_card_configured = 1;
    malformed.virtual_card_uid_len = (uint8_t)(sizeof(malformed.virtual_card_uid) + 1);
    CHECK(dfc_ffi_credential_set_picc(atomic, &malformed) == DFC_FFI_INVALID_ARGUMENT);
    CHECK(dfc_ffi_credential_get_picc(atomic, &atomic_after) == DFC_FFI_OK);
    CHECK(memcmp(&atomic_after, &atomic_before, sizeof(atomic_before)) == 0);
    check_key(atomic, DFC_FFI_OWNER_PICC, 0, 0, &atomic_key);
    dfc_ffi_credential_free(atomic);

    // Text in, binary out, and back.
    DfcFfiCredential* credential = NULL;
    DfcFfiError error;
    int32_t st =
        dfc_ffi_credential_parse_text(CREDENTIAL, sizeof(CREDENTIAL) - 1, &credential, &error);
    if(st != 0) fprintf(stderr, "parse: %d line %u %s\n", st, error.line, error.message);
    CHECK(st == 0);
    size_t dfcb_len = 0;
    uint8_t* dfcb = encode(credential, &dfcb_len);
    DfcFfiCredential* decoded = NULL;
    CHECK(dfc_ffi_credential_load(dfcb, dfcb_len, &decoded, &error) == 0);
    size_t text_len = 0;
    CHECK(dfc_ffi_credential_write_text(decoded, NULL, 0, &text_len) == 0);
    CHECK(text_len > 0);

    // Malformed text reports the line.
    DfcFfiCredential* rejected = NULL;
    const char broken[] = "Filetype: DFC Credential\nVersion: 4\nCard Generation: EV9\n";
    CHECK(dfc_ffi_credential_parse_text(broken, sizeof(broken) - 1, &rejected, &error) != 0);
    CHECK(rejected == NULL);
    CHECK(error.line == 3);

    // Key-set storage accepts exact and mixed widths, but the active set must
    // have the application's declared key width and fit its slot.
    const struct {
        uint32_t key_len;
        uint32_t max_size;
        uint8_t active_type;
        uint8_t additional_type;
    } valid_key_sets[] = {
        {16, 16, 2, 2},
        {16, 24, 2, 1},
        {24, 24, 1, 2},
    };
    for(size_t i = 0; i < sizeof(valid_key_sets) / sizeof(valid_key_sets[0]); i++) {
        DfcFfiCredential* bounded = NULL;
        CHECK(dfc_ffi_credential_new(&bounded) == 0);
        DfcFfiApplication application = {0};
        application.aid[2] = (uint8_t)(2 + i);
        application.num_keys = 2;
        application.key_len = valid_key_sets[i].key_len;
        application.key_settings_2 = valid_key_sets[i].key_len == 24 ? 0x81 : 0x82;
        application.num_key_sets = 2;
        application.key_set_max_size = valid_key_sets[i].max_size;
        application.key_set_types[0] = valid_key_sets[i].active_type;
        application.key_set_types[1] = valid_key_sets[i].additional_type;
        application.key_set_initialized[0] = 1;
        application.key_set_initialized[1] = 1;
        uint32_t index = 0;
        CHECK(dfc_ffi_credential_add_application(bounded, &application, &index) == 0);

        uint32_t additional_len = application.key_set_types[1] == 1 ? 24 : 16;
        DfcFfiKey active = repeated_key(application.key_len, 0xA0 + (uint8_t)i, 0x10);
        DfcFfiKey adjacent = repeated_key(additional_len, 0x10 + (uint8_t)i, 0x20);
        CHECK(dfc_ffi_credential_set_key(bounded, (int32_t)index, 1, 0, &adjacent) == 0);
        CHECK(dfc_ffi_credential_set_key(bounded, (int32_t)index, 0, 0, &active) == 0);
        check_key(bounded, (int32_t)index, 0, 0, &active);
        check_key(bounded, (int32_t)index, 1, 0, &adjacent);

        DfcFfiKey wrong_width = repeated_key(active.len == 24 ? 16 : 24, 0xEE, 0xEE);
        CHECK(
            dfc_ffi_credential_set_key(bounded, (int32_t)index, 0, 0, &wrong_width) ==
            DFC_FFI_INVALID_ARGUMENT);
        CHECK(
            dfc_ffi_credential_set_key(bounded, (int32_t)index, 2, 0, &active) ==
            DFC_FFI_INVALID_ARGUMENT);
        CHECK(
            dfc_ffi_credential_set_key(bounded, (int32_t)index, 1, 2, &adjacent) ==
            DFC_FFI_INVALID_ARGUMENT);
        check_key(bounded, (int32_t)index, 0, 0, &active);
        check_key(bounded, (int32_t)index, 1, 0, &adjacent);
        dfc_ffi_credential_free(bounded);
    }

    const struct {
        uint32_t key_len;
        uint32_t max_size;
        uint8_t active_type;
    } invalid_key_sets[] = {
        {24, 16, 1},
        {16, 24, 1},
        {24, 24, 2},
        {8, 16, 0},
    };
    for(size_t i = 0; i < sizeof(invalid_key_sets) / sizeof(invalid_key_sets[0]); i++) {
        DfcFfiCredential* bounded = NULL;
        CHECK(dfc_ffi_credential_new(&bounded) == 0);
        DfcFfiApplication application = {0};
        application.aid[2] = (uint8_t)(8 + i);
        application.num_keys = 1;
        application.key_len = invalid_key_sets[i].key_len;
        application.key_settings_2 = invalid_key_sets[i].key_len == 24 ? 0x81 : 0x80;
        application.num_key_sets = 2;
        application.key_set_max_size = invalid_key_sets[i].max_size;
        application.key_set_types[0] = invalid_key_sets[i].active_type;
        application.key_set_types[1] = 2;
        application.key_set_initialized[0] = 1;
        application.key_set_initialized[1] = 1;
        uint32_t index = 0;
        CHECK(
            dfc_ffi_credential_add_application(bounded, &application, &index) ==
            DFC_FFI_INVALID_ARGUMENT);
        CHECK(dfc_ffi_credential_application_count(bounded) == 0);
        dfc_ffi_credential_free(bounded);
    }

    // A failed PICC-key expansion is a rejected update, not a destructive
    // replacement of the previously configured PICC keys and settings.
    DfcFfiCredential* crowded = NULL;
    CHECK(dfc_ffi_credential_new(&crowded) == DFC_FFI_OK);
    DfcFfiPiccSettings original_picc = {0};
    original_picc.num_keys = 1;
    original_picc.key_len = 16;
    original_picc.key_settings_1 = 0xA5;
    CHECK(dfc_ffi_credential_set_picc(crowded, &original_picc) == DFC_FFI_OK);
    DfcFfiKey original_key = repeated_key(16, 0x5A, 0x7E);
    CHECK(
        dfc_ffi_credential_set_key(crowded, DFC_FFI_OWNER_PICC, 0, 0, &original_key) ==
        DFC_FFI_OK);
    size_t crowded_apps = 0;
    for(size_t i = 0; i < caps.max_applications; i++) {
        DfcFfiApplication application = {0};
        application.aid[0] = (uint8_t)(i + 1);
        application.aid[1] = 0x70;
        application.aid[2] = 0x01;
        application.num_keys = 14;
        application.key_len = 24;
        application.key_settings_2 = 0x8E;
        application.num_key_sets = 16;
        application.key_set_max_size = 24;
        for(size_t key_set = 0; key_set < 16; key_set++)
            application.key_set_types[key_set] = 1;
        uint32_t index = 0;
        if(dfc_ffi_credential_add_application(crowded, &application, &index) != DFC_FFI_OK) break;
        crowded_apps++;
    }
    if(crowded_apps == 0) {
        for(size_t i = 0; i < caps.max_applications; i++) {
            DfcFfiApplication application = {0};
            application.aid[0] = (uint8_t)(i + 1);
            application.aid[1] = 0x71;
            application.aid[2] = 0x01;
            application.num_keys = 14;
            application.key_len = 24;
            application.key_settings_2 = 0x8E;
            uint32_t index = 0;
            if(dfc_ffi_credential_add_application(crowded, &application, &index) != DFC_FFI_OK)
                break;
            crowded_apps++;
        }
    }
    CHECK(crowded_apps > 0);
    DfcFfiPiccSettings too_large = original_picc;
    too_large.num_keys = 14;
    too_large.key_len = 24;
    too_large.key_settings_1 = 0x3C;
    CHECK(dfc_ffi_credential_set_picc(crowded, &too_large) == model_capacity_status);
    DfcFfiPiccSettings after_rejection;
    CHECK(dfc_ffi_credential_get_picc(crowded, &after_rejection) == DFC_FFI_OK);
    CHECK(after_rejection.num_keys == original_picc.num_keys);
    CHECK(after_rejection.key_len == original_picc.key_len);
    CHECK(after_rejection.key_settings_1 == original_picc.key_settings_1);
    check_key(crowded, DFC_FFI_OWNER_PICC, 0, 0, &original_key);
    dfc_ffi_credential_free(crowded);

    // The walk and the builder agree with the codec.
    DfcFfiCredential* built = rebuild(decoded);
    size_t rebuilt_len = 0;
    uint8_t* rebuilt = encode(built, &rebuilt_len);
    CHECK(rebuilt_len == dfcb_len && memcmp(rebuilt, dfcb, dfcb_len) == 0);

    DfcFfiCredential* cloned = NULL;
    CHECK(dfc_ffi_credential_clone(built, &cloned) == 0);
    size_t cloned_len = 0;
    uint8_t* cloned_bytes = encode(cloned, &cloned_len);
    CHECK(cloned_len == dfcb_len && memcmp(cloned_bytes, dfcb, dfcb_len) == 0);
    free(cloned_bytes);

    // A failed random request aborts the operation without changing card state.
    DfcFfiCredential* failure_credential = NULL;
    CHECK(dfc_ffi_credential_clone(built, &failure_credential) == 0);
    ScriptedRandom failure_random = {.failures_remaining = 1};
    DfcFfiPicc* failure_picc = NULL;
    CHECK(
        dfc_ffi_picc_create_take(
            &failure_credential, scripted_random, &failure_random, &failure_picc) == DFC_FFI_OK);
    DfcFfiActivation failure_activation;
    CHECK(dfc_ffi_picc_activate(failure_picc, &failure_activation) == DFC_FFI_OK);
    DfcFfiSnapshot before_failure;
    DfcFfiSnapshot after_failure;
    CHECK(dfc_ffi_picc_snapshot(failure_picc, &before_failure) == DFC_FFI_OK);
    const uint8_t authenticate[] = {0x90, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x00};
    uint8_t failed_response[32] = {0};
    size_t failed_response_len = 0;
    CHECK(
        dfc_ffi_picc_exchange(
            failure_picc,
            authenticate,
            sizeof(authenticate),
            failed_response,
            sizeof(failed_response),
            &failed_response_len) == DFC_FFI_RANDOM_FAILED);
    CHECK(dfc_ffi_picc_snapshot(failure_picc, &after_failure) == DFC_FFI_OK);
    CHECK(memcmp(&before_failure, &after_failure, sizeof(before_failure)) == 0);
    CHECK(failed_response_len == 0);

    uint8_t retry_response[32] = {0};
    size_t retry_response_len = 0;
    CHECK(
        dfc_ffi_picc_exchange(
            failure_picc,
            authenticate,
            sizeof(authenticate),
            retry_response,
            sizeof(retry_response),
            &retry_response_len) == DFC_FFI_OK);

    DfcFfiCredential* baseline_credential = NULL;
    CHECK(dfc_ffi_credential_clone(built, &baseline_credential) == DFC_FFI_OK);
    ScriptedRandom baseline_random = {0};
    DfcFfiPicc* baseline_picc = NULL;
    CHECK(
        dfc_ffi_picc_create_take(
            &baseline_credential, scripted_random, &baseline_random, &baseline_picc) ==
        DFC_FFI_OK);
    CHECK(dfc_ffi_picc_activate(baseline_picc, &failure_activation) == DFC_FFI_OK);
    uint8_t baseline_response[32] = {0};
    size_t baseline_response_len = 0;
    CHECK(
        dfc_ffi_picc_exchange(
            baseline_picc,
            authenticate,
            sizeof(authenticate),
            baseline_response,
            sizeof(baseline_response),
            &baseline_response_len) == DFC_FFI_OK);
    CHECK(retry_response_len == baseline_response_len);
    CHECK(memcmp(retry_response, baseline_response, retry_response_len) == 0);
    dfc_ffi_picc_free(baseline_picc);
    dfc_ffi_picc_free(failure_picc);

    // Random-ID activation is also atomic: a failed source leaves activation
    // and session state untouched.
    DfcFfiCredential* random_id_credential = NULL;
    CHECK(dfc_ffi_credential_clone(built, &random_id_credential) == DFC_FFI_OK);
    DfcFfiPiccSettings random_id_settings;
    CHECK(dfc_ffi_credential_get_picc(random_id_credential, &random_id_settings) == DFC_FFI_OK);
    random_id_settings.random_id = 1;
    CHECK(dfc_ffi_credential_set_picc(random_id_credential, &random_id_settings) == DFC_FFI_OK);
    DfcFfiError random_id_error;
    CHECK(dfc_ffi_credential_finish(random_id_credential, &random_id_error) == DFC_FFI_OK);
    DfcFfiPicc* random_id_picc = NULL;
    CHECK(
        dfc_ffi_picc_create_take(&random_id_credential, failing_random, NULL, &random_id_picc) ==
        DFC_FFI_OK);
    DfcFfiSnapshot before_activation;
    DfcFfiSnapshot after_activation;
    CHECK(dfc_ffi_picc_snapshot(random_id_picc, &before_activation) == DFC_FFI_OK);
    memset(&failure_activation, 0xA5, sizeof(failure_activation));
    CHECK(dfc_ffi_picc_activate(random_id_picc, &failure_activation) == DFC_FFI_RANDOM_FAILED);
    CHECK(dfc_ffi_picc_snapshot(random_id_picc, &after_activation) == DFC_FFI_OK);
    CHECK(memcmp(&before_activation, &after_activation, sizeof(before_activation)) == 0);
    DfcFfiActivation zero_activation = {0};
    CHECK(memcmp(&failure_activation, &zero_activation, sizeof(failure_activation)) == 0);
    dfc_ffi_picc_free(random_id_picc);

    // The original constructor keeps caller ownership, while the transfer
    // constructor consumes only a valid credential after the PICC is ready.
    DfcFfiPicc* copied_picc = NULL;
    CHECK(dfc_ffi_picc_create(cloned, counting_random, &random_calls, &copied_picc) == 0);
    CHECK(cloned != NULL);
    dfc_ffi_picc_free(copied_picc);
    dfc_ffi_credential_free(cloned);

    DfcFfiCredential* unfinished = NULL;
    CHECK(dfc_ffi_credential_new(&unfinished) == 0);
    DfcFfiCredential* retained = unfinished;
    DfcFfiPicc* rejected_picc = NULL;
    CHECK(dfc_ffi_picc_create_take(&unfinished, NULL, NULL, &rejected_picc) != 0);
    CHECK(unfinished == retained);
    CHECK(rejected_picc == NULL);
    dfc_ffi_credential_free(unfinished);

    // A virtual PICC answering a reader, both through the interface.
    DfcFfiPicc* picc = NULL;
    CHECK(dfc_ffi_picc_create_take(&built, counting_random, &random_calls, &picc) == 0);
    CHECK(built == NULL);
    DfcFfiActivation activation;
    CHECK(dfc_ffi_picc_activate(picc, &activation) == 0);
    CHECK(activation.uid_len == 7);

    DfcFfiReaderSession* session = NULL;
    DfcFfiReaderExchange* exchange = NULL;
    CHECK(dfc_ffi_reader_session_new(&session) == 0);
    CHECK(dfc_ffi_reader_exchange_new(&exchange) == 0);
    // The wire carries an AID least significant octet first; the model stores
    // it the way the text writes it.
    const uint8_t wire_aid[3] = {0x01, 0x00, 0x00};
    const uint8_t aid[3] = {0x00, 0x00, 0x01};
    CHECK(dfc_ffi_reader_exchange_begin(exchange, session, 0, 0x5A, wire_aid, 3, 0, -1) == 0);
    st = run(picc, exchange);
    if(st != 0)
        fprintf(stderr, "select: %d status %02X\n", st, dfc_ffi_reader_result_status(exchange));
    CHECK(st == 0);

    uint8_t random_a[16];
    for(size_t i = 0; i < sizeof(random_a); i++)
        random_a[i] = (uint8_t)i;
    CHECK(
        dfc_ffi_reader_authenticate_begin(
            exchange, session, 0, 0xAA, 0, APP_KEY, 16, random_a, 16) == 0);
    CHECK(run(picc, exchange) == 0);
    CHECK(random_calls > 0);
    DfcFfiReaderState state;
    CHECK(dfc_ffi_reader_session_state(session, &state) == 0);
    CHECK(state.auth_mode == 0xAA);

    const uint8_t read[] = {0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00};
    CHECK(
        dfc_ffi_reader_exchange_begin(exchange, session, 0, 0xBD, read, sizeof(read), 1, -1) == 0);
    CHECK(run(picc, exchange) == 0);
    uint8_t data[32];
    size_t data_len = 0;
    CHECK(dfc_ffi_reader_result_data(exchange, NULL, 0, &data_len) == 0);
    CHECK(data_len == 16);
    CHECK(dfc_ffi_reader_result_data(exchange, data, sizeof(data), &data_len) == 0);
    CHECK(data_len == 16);
    for(size_t i = 0; i < data_len; i++)
        CHECK(data[i] == i);
    data_len = SIZE_MAX;
    CHECK(dfc_ffi_reader_result_data(exchange, NULL, 0, &data_len) == 0);
    CHECK(data_len == 0);

    DfcFfiSnapshot snapshot;
    CHECK(dfc_ffi_picc_snapshot(picc, &snapshot) == 0);
    CHECK(snapshot.auth_mode == 0xAA);
    CHECK(snapshot.selected == 2);
    CHECK(memcmp(snapshot.selected_aid, aid, 3) == 0);

    DfcFfiDiagnosticSnapshot diagnostic;
    memset(&diagnostic, 0xA5, sizeof(diagnostic));
    CHECK(dfc_ffi_picc_diagnostic_snapshot(NULL, &diagnostic) == DFC_FFI_INVALID_ARGUMENT);
    CHECK(memcmp(&diagnostic, (uint8_t[sizeof(diagnostic)]){0}, sizeof(diagnostic)) == 0);
    CHECK(dfc_ffi_picc_diagnostic_snapshot(picc, &diagnostic) == 0);
    dfc_ffi_secure_zero(&diagnostic, sizeof(diagnostic));
    CHECK(memcmp(&diagnostic, (uint8_t[sizeof(diagnostic)]){0}, sizeof(diagnostic)) == 0);

    DfcFfiCredential* exported = NULL;
    CHECK(dfc_ffi_picc_export(picc, &exported) == 0);
    CHECK(dfc_ffi_credential_validate(exported) == 0);
    DfcFfiKey exported_picc_key;
    CHECK(dfc_ffi_credential_get_key(exported, DFC_FFI_OWNER_PICC, 0, 0, &exported_picc_key) == 0);
    CHECK(exported_picc_key.len == 16);

    dfc_ffi_credential_free(exported);
    dfc_ffi_reader_exchange_free(exchange);
    dfc_ffi_reader_session_free(session);
    dfc_ffi_picc_free(picc);
    free(rebuilt);
    free(dfcb);
    dfc_ffi_credential_free(decoded);
    dfc_ffi_credential_free(credential);

    if(failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("ffi smoke test passed\n");
    return 0;
}
