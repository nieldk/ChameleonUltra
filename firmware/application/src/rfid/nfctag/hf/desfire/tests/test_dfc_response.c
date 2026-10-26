#include "dfc_response.h"

#include "munit.h"

#include <string.h>

static MunitResult test_version_payload(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t response[] = {
        // Exact payload captured by hardware_genuine_ev1_4k_issued.vec.
        0x04, 0x01, 0x01, 0x01, 0x00, 0x1A, 0x05, 0x04, 0x01, 0x01, 0x01, 0x04, 0x1A, 0x05,
        0x04, 0x57, 0x04, 0xEA, 0x91, 0x6F, 0x80, 0xB9, 0x0C, 0x21, 0x45, 0x90, 0x19, 0x21,
    };
    DfcResponseVersion version;
    memset(&version, 0xA5, sizeof(version));
    munit_assert_int(
        dfc_response_decode_version(response, sizeof(response), &version),
        ==,
        DfcResponseDecodeOk);
    munit_assert_uint8(version.hardware.vendor_id, ==, 0x04);
    munit_assert_uint8(version.hardware.major_version, ==, 0x01);
    munit_assert_uint8(version.software.minor_version, ==, 0x04);
    munit_assert_uint8(version.hardware.storage_size, ==, 0x1A);
    munit_assert_memory_equal(
        DFC_RESPONSE_VERSION_UID_LENGTH,
        version.uid,
        ((const uint8_t[]){0x04, 0x57, 0x04, 0xEA, 0x91, 0x6F, 0x80}));
    munit_assert_memory_equal(
        DFC_RESPONSE_VERSION_BATCH_LENGTH,
        version.batch_number,
        ((const uint8_t[]){0xB9, 0x0C, 0x21, 0x45, 0x90}));
    munit_assert_uint8(version.production_week, ==, 0x19);
    munit_assert_uint8(version.production_year, ==, 0x21);
    return MUNIT_OK;
}

static MunitResult test_directory_decoders(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    // Captured by hardware_ev2_4k_directory_issue1.vec.
    const uint8_t wire_aids[] = {0x31, 0x41, 0xF5};
    uint8_t aids[1][DFC_RESPONSE_AID_LENGTH] = {{0}};
    size_t count = 0;
    munit_assert_int(
        dfc_response_decode_application_ids(wire_aids, sizeof(wire_aids), aids, 1, &count),
        ==,
        DfcResponseDecodeOk);
    munit_assert_size(count, ==, 1);
    munit_assert_memory_equal(3, aids[0], ((const uint8_t[]){0xF5, 0x41, 0x31}));

    memset(aids, 0xA5, sizeof(aids));
    count = 0;
    munit_assert_int(
        dfc_response_decode_application_ids(wire_aids, sizeof(wire_aids), aids, 0, &count),
        ==,
        DfcResponseDecodeBufferTooSmall);
    munit_assert_size(count, ==, 1);
    munit_assert_memory_equal(sizeof(aids), aids, ((const uint8_t[1][3]){{0xA5, 0xA5, 0xA5}}));

    uint8_t in_place_aids[] = {0x31, 0x41, 0xF5, 0x03, 0x02, 0x01};
    munit_assert_int(
        dfc_response_decode_application_ids(
            in_place_aids,
            sizeof(in_place_aids),
            (uint8_t (*)[DFC_RESPONSE_AID_LENGTH])in_place_aids,
            2,
            &count),
        ==,
        DfcResponseDecodeOk);
    munit_assert_memory_equal(
        sizeof(in_place_aids),
        in_place_aids,
        ((const uint8_t[]){0xF5, 0x41, 0x31, 0x01, 0x02, 0x03}));

    const uint8_t wire_files[] = {1, 7, 31};
    uint8_t files[3] = {0};
    munit_assert_int(
        dfc_response_decode_file_ids(wire_files, sizeof(wire_files), files, 3, &count),
        ==,
        DfcResponseDecodeOk);
    munit_assert_size(count, ==, 3);
    munit_assert_memory_equal(sizeof(files), files, wire_files);

    uint8_t in_place_files[] = {1, 7, 31};
    munit_assert_int(
        dfc_response_decode_file_ids(
            in_place_files, sizeof(in_place_files), in_place_files, sizeof(in_place_files), &count),
        ==,
        DfcResponseDecodeOk);
    munit_assert_size(count, ==, 3);
    munit_assert_memory_equal(sizeof(in_place_files), in_place_files, wire_files);
    return MUNIT_OK;
}

static void
    assert_access(const DfcResponseAccess* access, DfcResponseAccessKind kind, uint8_t key) {
    munit_assert_int(access->kind, ==, kind);
    munit_assert_uint8(access->key_number, ==, key);
}

static MunitResult test_file_settings_variants(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcResponseFileSettings settings;

    // Captured by hardware_genuine_ev1_4k_issued.vec.
    const uint8_t standard[] = {0x00, 0x01, 0x30, 0x12, 0x36, 0x00, 0x00};
    munit_assert_int(
        dfc_response_decode_file_settings(standard, sizeof(standard), &settings),
        ==,
        DfcResponseDecodeOk);
    munit_assert_uint8(settings.type, ==, DFC_FILE_TYPE_STANDARD_DATA);
    munit_assert_uint8(settings.communication_mode, ==, DFC_COMM_MAC);
    munit_assert_uint32(settings.settings.data.size, ==, 54);
    assert_access(&settings.access.read, DfcResponseAccessKey, 1);
    assert_access(&settings.access.write, DfcResponseAccessKey, 2);
    assert_access(&settings.access.read_write, DfcResponseAccessKey, 3);
    assert_access(&settings.access.change, DfcResponseAccessKey, 0);

    const uint8_t value[] = {
        0x02,
        0x00,
        0xEE,
        0xEE,
        0x9C,
        0xFF,
        0xFF,
        0xFF,
        0x64,
        0x00,
        0x00,
        0x00,
        0x0B,
        0x00,
        0x00,
        0x00,
        0x01,
    };
    munit_assert_int(
        dfc_response_decode_file_settings(value, sizeof(value), &settings),
        ==,
        DfcResponseDecodeOk);
    munit_assert_int32(settings.settings.value.lower_limit, ==, -100);
    munit_assert_int32(settings.settings.value.upper_limit, ==, 100);
    munit_assert_int32(settings.settings.value.limited_credit_value, ==, 11);
    munit_assert_true(settings.settings.value.limited_credit_enabled);
    assert_access(&settings.access.read, DfcResponseAccessFree, 0);
    assert_access(&settings.access.change, DfcResponseAccessFree, 0);

    const uint8_t records[] = {
        0x03,
        0x01,
        0xEF,
        0x12,
        0x20,
        0x00,
        0x00,
        0x10,
        0x00,
        0x00,
        0x07,
        0x00,
        0x00,
    };
    munit_assert_int(
        dfc_response_decode_file_settings(records, sizeof(records), &settings),
        ==,
        DfcResponseDecodeOk);
    munit_assert_uint32(settings.settings.records.record_size, ==, 32);
    munit_assert_uint32(settings.settings.records.max_records, ==, 16);
    munit_assert_uint32(settings.settings.records.current_records, ==, 7);
    assert_access(&settings.access.change, DfcResponseAccessDenied, 0);
    return MUNIT_OK;
}

static MunitResult test_key_settings(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcResponseKeySettings settings;
    // Captured by hardware_physical_ev3_4k_identity.vec.
    const uint8_t simple[] = {0x0F, 0x01};
    munit_assert_int(
        dfc_response_decode_key_settings(simple, sizeof(simple), &settings),
        ==,
        DfcResponseDecodeOk);
    munit_assert_uint8(settings.key_type, ==, DFC_KEY_TYPE_DES_2K3DES);
    munit_assert_uint8(settings.key_count, ==, 1);
    munit_assert_false(settings.has_key_set_settings);

    const uint8_t extended[] = {0x0F, 0x83, 0x21, 0x04, 0x10, 0x02};
    munit_assert_int(
        dfc_response_decode_key_settings(extended, sizeof(extended), &settings),
        ==,
        DfcResponseDecodeOk);
    munit_assert_true(settings.has_key_set_settings);
    munit_assert_uint8(settings.active_key_set_version, ==, 0x21);
    munit_assert_uint8(settings.key_set_count, ==, 4);
    munit_assert_uint8(settings.max_key_size, ==, 16);
    munit_assert_uint8(settings.key_set_settings, ==, 2);

    uint8_t version = 0;
    munit_assert_int(
        dfc_response_decode_key_version((const uint8_t[]){0xA5}, 1, &version),
        ==,
        DfcResponseDecodeOk);
    munit_assert_uint8(version, ==, 0xA5);
    return MUNIT_OK;
}

static MunitResult test_key_settings_boundaries(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcResponseKeySettings settings;

    for(uint8_t count = 0; count <= DFC_MAX_KEYS; count++) {
        const uint8_t response[] = {0x0F, (uint8_t)(DFC_KEY_TYPE_AES | count)};
        munit_assert_int(
            dfc_response_decode_key_settings(response, sizeof(response), &settings),
            ==,
            DfcResponseDecodeOk);
        munit_assert_uint8(settings.key_count, ==, count);
    }
    const uint8_t too_many_keys[] = {0x0F, DFC_MAX_KEYS + 1};
    munit_assert_int(
        dfc_response_decode_key_settings(too_many_keys, sizeof(too_many_keys), &settings),
        ==,
        DfcResponseDecodeUnsupported);

    for(uint8_t count = 2; count <= 16; count++) {
        const uint8_t response[] = {0x0F, 0x01, 0, count, 0x10, 0};
        munit_assert_int(
            dfc_response_decode_key_settings(response, sizeof(response), &settings),
            ==,
            DfcResponseDecodeOk);
    }
    const uint8_t invalid_set_counts[][6] = {
        {0x0F, 0x01, 0, 1, 0x10, 0},
        {0x0F, 0x01, 0, 17, 0x10, 0},
    };
    for(size_t i = 0; i < sizeof(invalid_set_counts) / sizeof(invalid_set_counts[0]); i++) {
        munit_assert_int(
            dfc_response_decode_key_settings(
                invalid_set_counts[i], sizeof(invalid_set_counts[i]), &settings),
            ==,
            DfcResponseDecodeUnsupported);
    }

    const uint8_t valid_key_sizes[] = {0x10, 0x18};
    for(size_t i = 0; i < sizeof(valid_key_sizes); i++) {
        const uint8_t response[] = {0x0F, 0x01, 0, 2, valid_key_sizes[i], 0};
        munit_assert_int(
            dfc_response_decode_key_settings(response, sizeof(response), &settings),
            ==,
            DfcResponseDecodeOk);
    }
    const uint8_t invalid_key_sizes[] = {0, 0x0F, 0x11, 0x17, 0x19, 0xFF};
    for(size_t i = 0; i < sizeof(invalid_key_sizes); i++) {
        const uint8_t response[] = {0x0F, 0x01, 0, 2, invalid_key_sizes[i], 0};
        munit_assert_int(
            dfc_response_decode_key_settings(response, sizeof(response), &settings),
            ==,
            DfcResponseDecodeUnsupported);
    }
    return MUNIT_OK;
}

static MunitResult test_malformed_inputs_clear_outputs(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t version[DFC_RESPONSE_VERSION_LENGTH] = {0};
    for(size_t length = 0; length < sizeof(version); length++) {
        DfcResponseVersion output;
        memset(&output, 0xA5, sizeof(output));
        munit_assert_int(
            dfc_response_decode_version(version, length, &output), ==, DfcResponseDecodeMalformed);
        munit_assert_memory_equal(sizeof(output), &output, &(DfcResponseVersion){0});
    }

    DfcResponseFileSettings settings;
    const uint8_t standard[] = {0x00, 0x00, 0xEE, 0xEE, 0x01, 0x00, 0x00};
    for(size_t length = 0; length < sizeof(standard); length++) {
        memset(&settings, 0xA5, sizeof(settings));
        munit_assert_int(
            dfc_response_decode_file_settings(standard, length, &settings),
            ==,
            DfcResponseDecodeMalformed);
        munit_assert_memory_equal(sizeof(settings), &settings, &(DfcResponseFileSettings){0});
    }
    const uint8_t unknown_type[] = {0x7F, 0, 0, 0};
    munit_assert_int(
        dfc_response_decode_file_settings(unknown_type, sizeof(unknown_type), &settings),
        ==,
        DfcResponseDecodeUnsupported);
    const uint8_t unknown_mode[] = {0x00, 0x02, 0xEE, 0xEE, 1, 0, 0};
    munit_assert_int(
        dfc_response_decode_file_settings(unknown_mode, sizeof(unknown_mode), &settings),
        ==,
        DfcResponseDecodeUnsupported);
    const uint8_t incomplete_sdm[] = {0x00, DFC_SDM_ENABLED_MASK, 0xEE, 0xEE, 1, 0, 0};
    memset(&settings, 0xA5, sizeof(settings));
    munit_assert_int(
        dfc_response_decode_file_settings(incomplete_sdm, sizeof(incomplete_sdm), &settings),
        ==,
        DfcResponseDecodeUnsupported);
    munit_assert_memory_equal(sizeof(settings), &settings, &(DfcResponseFileSettings){0});
    const uint8_t extended_sdm[] = {
        0x00,
        DFC_SDM_ENABLED_MASK,
        0xEE,
        0xEE,
        1,
        0,
        0,
        0xC1,
        0xF1,
        0x21,
        0,
        0,
        0,
    };
    munit_assert_int(
        dfc_response_decode_file_settings(extended_sdm, sizeof(extended_sdm), &settings),
        ==,
        DfcResponseDecodeUnsupported);

    const uint8_t file_settings[][17] = {
        {0x02, 0x00, 0xEE, 0xEE, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
        {0x03, 0x00, 0xEE, 0xEE, 1, 0, 0, 1, 0, 0, 0, 0, 0},
    };
    const size_t file_setting_lengths[] = {17, 13};
    for(size_t variant = 0; variant < sizeof(file_setting_lengths) / sizeof(size_t); variant++) {
        for(size_t length = 4; length < file_setting_lengths[variant]; length++) {
            memset(&settings, 0xA5, sizeof(settings));
            munit_assert_int(
                dfc_response_decode_file_settings(file_settings[variant], length, &settings),
                ==,
                DfcResponseDecodeMalformed);
            munit_assert_memory_equal(sizeof(settings), &settings, &(DfcResponseFileSettings){0});
        }
    }

    DfcResponseKeySettings key_settings;
    const uint8_t extended_key_settings[] = {0x0F, 0x83, 0x21, 0x04, 0x10, 0x02};
    for(size_t length = 0; length < sizeof(extended_key_settings); length++) {
        if(length == 2) continue;
        memset(&key_settings, 0xA5, sizeof(key_settings));
        munit_assert_int(
            dfc_response_decode_key_settings(extended_key_settings, length, &key_settings),
            ==,
            DfcResponseDecodeMalformed);
        munit_assert_memory_equal(
            sizeof(key_settings), &key_settings, &(DfcResponseKeySettings){0});
    }

    size_t count = 99;
    munit_assert_int(
        dfc_response_decode_application_ids((const uint8_t[]){1, 2}, 2, NULL, 0, &count),
        ==,
        DfcResponseDecodeMalformed);
    munit_assert_size(count, ==, 0);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/version-payload", test_version_payload, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/directory-decoders", test_directory_decoders, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/file-settings-variants",
     test_file_settings_variants,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/key-settings", test_key_settings, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/key-settings-boundaries",
     test_key_settings_boundaries,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/malformed-inputs-clear-outputs",
     test_malformed_inputs_clear_outputs,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {"/dfc_response", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
