#include "dfc_ev2_command.h"

#include "munit/munit.h"

static DfcEv2CommandMetadata expected_metadata(uint8_t command) {
    DfcEv2CommandMetadata expected = {.encrypted_header_length = DfcEv2NoEncryptedHeader};
    switch(dfc_file_command_base(command)) {
    case DFC_CMD_READ_DATA:
    case DFC_CMD_READ_RECORDS:
    case DFC_CMD_GET_VALUE:
        expected.flags = DfcEv2CommandFile | DfcEv2CommandFileRead | DfcEv2CommandTargetsFile |
                         DfcEv2CommandSupportsEffectivePlain;
        break;
    case DFC_CMD_WRITE_DATA:
    case DFC_CMD_WRITE_RECORD:
        expected.flags = DfcEv2CommandFile | DfcEv2CommandTargetsFile |
                         DfcEv2CommandSupportsEffectivePlain;
        expected.encrypted_header_length = DfcEv2FileHeaderLength;
        break;
    case DFC_CMD_UPDATE_RECORD:
        expected.flags = DfcEv2CommandFile | DfcEv2CommandTargetsFile |
                         DfcEv2CommandSupportsEffectivePlain;
        expected.encrypted_header_length = DfcEv2UpdateRecordHeaderLength;
        break;
    case DFC_CMD_CREDIT:
    case DFC_CMD_DEBIT:
    case DFC_CMD_LIMITED_CREDIT:
        expected.flags = DfcEv2CommandFile | DfcEv2CommandTargetsFile |
                         DfcEv2CommandSupportsEffectivePlain;
        expected.encrypted_header_length = DfcEv2ValueHeaderLength;
        break;
    case DFC_CMD_GET_FILE_COUNTERS:
        expected.flags = DfcEv2CommandTargetsFile;
        break;
    case DFC_CMD_CHANGE_FILE_SETTINGS:
        expected.flags = DfcEv2CommandTargetsFile | DfcEv2CommandSupportsEffectivePlain;
        expected.encrypted_header_length = DfcEv2ChangeFileSettingsHeaderLength;
        break;
    default:
        break;
    }

    switch(command) {
    case DFC_CMD_SET_CONFIGURATION:
        expected.encrypted_header_length = DfcEv2SetConfigurationHeaderLength;
        break;
    case DFC_CMD_CREATE_TRANSACTION_MAC_FILE:
        expected.encrypted_header_length = DfcEv2CreateTransactionMacHeaderLength;
        break;
    case DFC_CMD_CHANGE_KEY_EV2:
        expected.encrypted_header_length = DfcEv2ChangeKeyHeaderLength;
        break;
    case DFC_CMD_CHANGE_KEY_SETTINGS:
        expected.encrypted_header_length = 0;
        break;
    case DFC_CMD_ADDITIONAL_FRAME:
    case DFC_CMD_AUTHENTICATE_EV2_FIRST:
    case DFC_CMD_AUTHENTICATE_EV2_NON_FIRST:
        expected.flags |= DfcEv2CommandReaderBypass | DfcEv2CommandEmulatorBypass;
        break;
    case DFC_CMD_AUTHENTICATE_LEGACY:
    case DFC_CMD_AUTHENTICATE_ISO:
    case DFC_CMD_AUTHENTICATE_AES:
        expected.flags |= DfcEv2CommandEmulatorBypass;
        break;
    case DFC_CMD_CREATE_DELEGATED_APPLICATION:
        expected.flags |= DfcEv2CommandReaderBypass;
#if DFC_ENABLE_DELEGATED_APPLICATIONS
        expected.flags |= DfcEv2CommandEmulatorBypass;
#endif
        break;
    default:
        break;
    }
    return expected;
}

static MunitResult test_every_instruction(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    for(unsigned command = 0; command <= UINT8_MAX; command++) {
        DfcEv2CommandMetadata actual = dfc_ev2_command_metadata((uint8_t)command);
        DfcEv2CommandMetadata expected = expected_metadata((uint8_t)command);
        munit_assert_uint8(actual.flags, ==, expected.flags);
        munit_assert_uint8(actual.encrypted_header_length, ==, expected.encrypted_header_length);
    }
    return MUNIT_OK;
}

static MunitResult test_iso_chaining_aliases(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static const uint8_t aliases[][2] = {
        {DFC_CMD_READ_DATA_ISO, DFC_CMD_READ_DATA},
        {DFC_CMD_WRITE_DATA_ISO, DFC_CMD_WRITE_DATA},
        {DFC_CMD_READ_RECORDS_ISO, DFC_CMD_READ_RECORDS},
        {DFC_CMD_WRITE_RECORD_ISO, DFC_CMD_WRITE_RECORD},
        {DFC_CMD_UPDATE_RECORD_ISO, DFC_CMD_UPDATE_RECORD},
    };
    for(size_t index = 0; index < sizeof(aliases) / sizeof(aliases[0]); index++) {
        DfcEv2CommandMetadata alternate = dfc_ev2_command_metadata(aliases[index][0]);
        DfcEv2CommandMetadata canonical = dfc_ev2_command_metadata(aliases[index][1]);
        munit_assert_uint8(alternate.flags, ==, canonical.flags);
        munit_assert_uint8(
            alternate.encrypted_header_length, ==, canonical.encrypted_header_length);
    }
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/every-instruction", test_every_instruction, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/iso-chaining-aliases", test_iso_chaining_aliases, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite =
    {"/dfc_ev2_command_metadata", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
