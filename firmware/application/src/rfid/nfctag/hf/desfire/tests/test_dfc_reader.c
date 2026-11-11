// The reader against the emulator, in process: every exchange the reader
// builds is answered by the virtual card, so the two halves of the library are
// held to one wire.

#include "munit/munit.h"

#include "dfc_credential.h"
#include "dfc_emulator_i.h"
#include "dfc_ev2_crypto.h"
#include "dfc_port_host.h"
#include "dfc_reader.h"
#include "dfc_virtual_picc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dfc_reader_test_link.h"

static size_t decode_hex(const char* text, uint8_t* out, size_t capacity) {
    size_t length = strlen(text);
    if((length & 1u) != 0 || length / 2 > capacity) return SIZE_MAX;
    for(size_t i = 0; i < length / 2; i++) {
        unsigned value = 0;
        if(sscanf(text + i * 2, "%2x", &value) != 1) return SIZE_MAX;
        out[i] = (uint8_t)value;
    }
    return length / 2;
}

static bool split_iso_helper_vector(char* line, char* fields[4]) {
    fields[0] = line;
    for(size_t i = 1; i < 4; i++) {
        char* separator = strchr(fields[i - 1], '|');
        if(!separator) return false;
        *separator = '\0';
        fields[i] = separator + 1;
    }
    fields[3][strcspn(fields[3], "\r\n")] = '\0';
    return strchr(fields[3], '|') == NULL;
}

static FILE* open_iso_helper_vectors(void) {
    FILE* vectors = fopen("iso7816-helper-vectors.txt", "r");
    return vectors ? vectors : fopen("tests/iso7816-helper-vectors.txt", "r");
}

static void assert_iso_helper_vectors(void) {
    FILE* vectors = open_iso_helper_vectors();
    munit_assert_not_null(vectors);
    char line[1600];
    while(fgets(line, sizeof(line), vectors)) {
        if(line[0] == '#' || line[0] == '\n') continue;
        char* fields[4];
        munit_assert_true(split_iso_helper_vector(line, fields));
        uint8_t input[700], expected_data[700], output[700];
        size_t input_len = decode_hex(fields[1], input, sizeof(input));
        munit_assert_size(input_len, !=, SIZE_MAX);
        if(strcmp(fields[0], "append-record") == 0) {
            size_t expected_len = decode_hex(fields[3], expected_data, sizeof(expected_data));
            munit_assert_size(expected_len, !=, SIZE_MAX);
            size_t output_len = 0;
            munit_assert_int(
                dfc_reader_iso_append_record_apdu(
                    (uint8_t)strtoul(fields[2], NULL, 10),
                    input,
                    input_len,
                    output,
                    sizeof(output),
                    &output_len),
                ==,
                DfcReaderOk);
            munit_assert_size(output_len, ==, expected_len);
            munit_assert_memory_equal(expected_len, output, expected_data);
        } else {
            munit_assert_string_equal(fields[0], "parse-response");
            size_t expected_len = decode_hex(fields[2], expected_data, sizeof(expected_data));
            munit_assert_size(expected_len, !=, SIZE_MAX);
            const uint8_t* parsed_data = NULL;
            size_t parsed_len = 0;
            uint16_t status_word = 0;
            munit_assert_int(
                dfc_reader_iso7816_parse_response(
                    input, input_len, &parsed_data, &parsed_len, &status_word),
                ==,
                DfcReaderOk);
            munit_assert_size(parsed_len, ==, expected_len);
            munit_assert_memory_equal(expected_len, parsed_data, expected_data);
            munit_assert_uint(status_word, ==, strtoul(fields[3], NULL, 16));
        }
    }
    fclose(vectors);
}

static MunitResult test_iso_append_record_helpers(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t record[] = {0xA5, 0x5A};
    assert_iso_helper_vectors();
    uint8_t apdu[300];
    size_t apdu_len = 0;
    munit_assert_int(
        dfc_reader_iso_append_record_apdu(3, record, sizeof(record), apdu, sizeof(apdu), &apdu_len),
        ==,
        DfcReaderOk);
    const uint8_t expected[] = {0x00, 0xE2, 0x00, 0x18, 0x02, 0xA5, 0x5A};
    munit_assert_size(apdu_len, ==, sizeof(expected));
    munit_assert_memory_equal(sizeof(expected), apdu, expected);

    uint8_t long_record[256] = {0};
    munit_assert_int(
        dfc_reader_iso_append_record_apdu(
            0, long_record, sizeof(long_record), apdu, sizeof(apdu), &apdu_len),
        ==,
        DfcReaderOk);
    const uint8_t extended_header[] = {0x00, 0xE2, 0x00, 0x00, 0x00, 0x01, 0x00};
    munit_assert_memory_equal(sizeof(extended_header), apdu, extended_header);
    munit_assert_size(apdu_len, ==, sizeof(long_record) + sizeof(extended_header));

    const uint8_t response[] = {0x11, 0x22, 0x6A, 0x82};
    const uint8_t* response_data = NULL;
    size_t response_data_len = 0;
    uint16_t status_word = 0;
    munit_assert_int(
        dfc_reader_iso7816_parse_response(
            response, sizeof(response), &response_data, &response_data_len, &status_word),
        ==,
        DfcReaderOk);
    munit_assert_ptr_equal(response_data, response);
    munit_assert_size(response_data_len, ==, 2);
    munit_assert_uint(status_word, ==, 0x6A82);

    munit_assert_int(
        dfc_reader_iso_append_record_apdu(
            31, record, sizeof(record), apdu, sizeof(apdu), &apdu_len),
        ==,
        DfcReaderInvalid);
    munit_assert_int(
        dfc_reader_iso7816_parse_response(
            response, 1, &response_data, &response_data_len, &status_word),
        ==,
        DfcReaderInvalid);
    return MUNIT_OK;
}

static void assert_emulator_unchanged(const DfcEmulator* before, const Link* link) {
    munit_assert_memory_equal(sizeof(*before), before, link->picc->emulator);
}

static void assert_native_authentication_pending_cleared(const DfcEmulator* emulator) {
    const uint8_t zero[DFC_EV2_RANDOM_LENGTH] = {0};
    munit_assert_false(emulator->awaiting_step2);
    munit_assert_uint8(emulator->pending_auth_cipher, ==, 0);
    munit_assert_uint8(emulator->pending_auth_key_no, ==, 0);
    munit_assert_memory_equal(
        sizeof(emulator->pending_authentication.native.random_b),
        emulator->pending_authentication.native.random_b,
        zero);
    munit_assert_memory_equal(
        sizeof(emulator->pending_authentication.native.encrypted_random_b),
        emulator->pending_authentication.native.encrypted_random_b,
        zero);
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING
static void assert_ev2_authentication_cleared(const DfcEmulator* emulator) {
    const uint8_t zero[DFC_AES_KEY_LENGTH] = {0};
    munit_assert_false(emulator->ev2_authentication_pending);
    munit_assert_false(emulator->ev2_authentication_non_first);
    munit_assert_false(emulator->ev2_session_active);
    munit_assert_uint8(emulator->ev2_authenticated_key_no, ==, 0);
    munit_assert_uint8(emulator->ev2_pending_authenticated_key_no, ==, 0);
    munit_assert_uint16(emulator->ev2_command_counter, ==, 0);
    munit_assert_memory_equal(
        sizeof(emulator->ev2_session_encryption_key), emulator->ev2_session_encryption_key, zero);
    munit_assert_memory_equal(
        sizeof(emulator->ev2_session_mac_key), emulator->ev2_session_mac_key, zero);
    munit_assert_memory_equal(
        sizeof(emulator->pending_authentication.ev2.static_key),
        emulator->pending_authentication.ev2.static_key,
        zero);
    munit_assert_memory_equal(
        sizeof(emulator->pending_authentication.ev2.random_b),
        emulator->pending_authentication.ev2.random_b,
        zero);
    munit_assert_memory_equal(
        sizeof(emulator->ev2_transaction_identifier), emulator->ev2_transaction_identifier, zero);
    munit_assert_memory_equal(
        sizeof(emulator->pending_authentication.ev2.transaction_identifier),
        emulator->pending_authentication.ev2.transaction_identifier,
        zero);
    munit_assert_memory_equal(
        sizeof(emulator->ev2_card_capabilities), emulator->ev2_card_capabilities, zero);
    munit_assert_memory_equal(
        sizeof(emulator->ev2_reader_capabilities), emulator->ev2_reader_capabilities, zero);
    munit_assert_memory_equal(
        sizeof(emulator->pending_authentication.ev2.card_capabilities),
        emulator->pending_authentication.ev2.card_capabilities,
        zero);
    munit_assert_memory_equal(
        sizeof(emulator->pending_authentication.ev2.reader_capabilities),
        emulator->pending_authentication.ev2.reader_capabilities,
        zero);
}
#endif

static MunitResult test_aborted_native_reauthentication_clears_authorization(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    enum {
        AbortWithOtherCommand,
        AbortWithShortContinuation,
        AbortWithLongContinuation,
    };
    static Link link;

    for(size_t abort_kind = AbortWithOtherCommand; abort_kind <= AbortWithLongContinuation;
        abort_kind++) {
        link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
        select_app(&link, AID_AES);
        munit_assert_int(
            authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 1, AES_KEY_1, sizeof(AES_KEY_1)),
            ==,
            DfcReaderOk);

        DfcEmulator* emulator = link.picc->emulator;
        munit_assert_not_null(emulator->secure_messaging);
        munit_assert_uint8(emulator->auth_key_no, ==, 1);

        uint8_t response[64];
        size_t response_len = 0;
        const uint8_t begin_high_privilege[] = {0x90, DFC_CMD_AUTHENTICATE_AES, 0, 0, 1, 0, 0};
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link.picc,
                begin_high_privilege,
                sizeof(begin_high_privilege),
                response,
                sizeof(response),
                &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_uint8(response[response_len - 1], ==, DFC_CMD_ADDITIONAL_FRAME);
        munit_assert_true(emulator->awaiting_step2);
        munit_assert_uint8(emulator->pending_auth_cipher, ==, DFC_CMD_AUTHENTICATE_AES);
        munit_assert_uint8(emulator->pending_auth_key_no, ==, 0);
        munit_assert_uint8(emulator->auth_key_no, ==, 0);

        uint8_t abort_apdu[5 + DFC_EV2_AUTHENTICATION_RESPONSE_LENGTH + 2] = {0};
        size_t abort_len;
        if(abort_kind == AbortWithOtherCommand) {
            const uint8_t other[] = {0x90, DFC_CMD_GET_KEY_SETTINGS, 0, 0, 0};
            memcpy(abort_apdu, other, sizeof(other));
            abort_len = sizeof(other);
        } else {
            abort_apdu[0] = 0x90;
            abort_apdu[1] = DFC_CMD_ADDITIONAL_FRAME;
            size_t payload_len = abort_kind == AbortWithShortContinuation ?
                                     DFC_EV2_AUTHENTICATION_RESPONSE_LENGTH - 1 :
                                     DFC_EV2_AUTHENTICATION_RESPONSE_LENGTH + 1;
            abort_apdu[4] = (uint8_t)payload_len;
            abort_len = 5 + payload_len + 1;
        }
        response_len = 0;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link.picc, abort_apdu, abort_len, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_uint8(
            response[response_len - 1],
            ==,
            abort_kind == AbortWithOtherCommand ? DFC_STATUS_COMMAND_ABORTED :
                                                  DFC_STATUS_AUTHENTICATION_ERR);

        assert_native_authentication_pending_cleared(emulator);
        munit_assert_not_null(emulator->secure_messaging);
        munit_assert_false(dfc_emulator_native_authentication_active(emulator));
        munit_assert_memory_equal(
            sizeof(*emulator->secure_messaging),
            emulator->secure_messaging,
            ((uint8_t[sizeof(*emulator->secure_messaging)]){0}));
        munit_assert_uint8(emulator->auth_cipher, ==, 0);
        munit_assert_uint8(emulator->auth_key_no, ==, 0);

        DfcCommand privileged;
        DfcReaderExchange exchange;
        munit_assert_int(dfc_command_read_data(&privileged, FilePlain, 0, 1), ==, DfcCommandOk);
        munit_assert_int(
            link_send(&link, &privileged, DFC_COMM_PLAIN, &exchange), ==, DfcReaderCardError);
        munit_assert_uint8(dfc_reader_result_status(&exchange), ==, DFC_STATUS_AUTHENTICATION_ERR);
        link_close(&link);
    }
    return MUNIT_OK;
}

static MunitResult test_rejected_authentication_start_clears_authorization(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    static Link link;
    const struct {
        const uint8_t* command;
        size_t command_len;
        uint8_t expected_status;
    } native_cases[] = {
        {(const uint8_t[]){0x90, DFC_CMD_AUTHENTICATE_AES, 0, 0, 1, 9, 0},
         7,
         DFC_STATUS_NO_SUCH_KEY},
        {(const uint8_t[]){0x90, DFC_CMD_AUTHENTICATE_ISO, 0, 0, 1, 0, 0},
         7,
         DFC_STATUS_AUTHENTICATION_ERR},
    };

    for(size_t i = 0; i < sizeof(native_cases) / sizeof(native_cases[0]); i++) {
        link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
        select_app(&link, AID_AES);
        munit_assert_int(
            authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, sizeof(AES_KEY_0)),
            ==,
            DfcReaderOk);

        uint8_t response[64];
        size_t response_len = 0;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link.picc,
                native_cases[i].command,
                native_cases[i].command_len,
                response,
                sizeof(response),
                &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_uint8(response[response_len - 1], ==, native_cases[i].expected_status);
        assert_native_authentication_pending_cleared(link.picc->emulator);
        munit_assert_false(dfc_emulator_native_authentication_active(link.picc->emulator));
        munit_assert_uint8(link.picc->emulator->auth_cipher, ==, 0);
        munit_assert_uint8(link.picc->emulator->auth_key_no, ==, 0);
        munit_assert_memory_equal(
            sizeof(*link.picc->emulator->secure_messaging),
            link.picc->emulator->secure_messaging,
            ((uint8_t[sizeof(*link.picc->emulator->secure_messaging)]){0}));
        link_close(&link);
    }

#if DFC_ENABLE_EV2_SECURE_MESSAGING
    const struct {
        const uint8_t* command;
        size_t command_len;
        uint8_t expected_status;
    } ev2_cases[] = {
        {(const uint8_t[]){0x90, DFC_CMD_AUTHENTICATE_EV2_FIRST, 0, 0, 2, 9, 0, 0},
         8,
         DFC_STATUS_NO_SUCH_KEY},
        {(const uint8_t[]){0x90, DFC_CMD_AUTHENTICATE_EV2_FIRST, 0, 0, 1, 0, 0},
         7,
         DFC_STATUS_LENGTH_ERROR},
    };

    for(size_t i = 0; i < sizeof(ev2_cases) / sizeof(ev2_cases[0]); i++) {
        link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
        select_app(&link, AID_AES);
        munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);

        uint8_t response[64];
        size_t response_len = 0;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link.picc,
                ev2_cases[i].command,
                ev2_cases[i].command_len,
                response,
                sizeof(response),
                &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_uint8(response[response_len - 1], ==, ev2_cases[i].expected_status);
        assert_ev2_authentication_cleared(link.picc->emulator);
        link_close(&link);
    }
#endif

    return MUNIT_OK;
}

static void mark_host_random_failure_retryable(void) {
    const uint8_t one_byte = 0;
    uint8_t two_bytes[2];
    dfc_host_clear_random_buffer();
    dfc_host_set_random_buffer(&one_byte, sizeof(one_byte));
    munit_assert_false(dfc_random_fill(two_bytes, sizeof(two_bytes)));
    munit_assert_true(dfc_random_failure_is_retryable());
}

static MunitResult test_random_failures_are_atomic(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    const struct {
        const uint8_t* aid;
        uint8_t command;
        size_t short_random_len;
    } authentication_cases[] = {
        {AID_D40, DFC_CMD_AUTHENTICATE_LEGACY, 7},
        {AID_ISO, DFC_CMD_AUTHENTICATE_ISO, 7},
        {AID_AES, DFC_CMD_AUTHENTICATE_AES, 15},
    };
    uint8_t short_random[16] = {0};

    // Only an exhausted caller script is retryable, and replenishing or
    // successfully consuming it clears the failure cause.
    uint8_t random_probe[2];
    dfc_host_set_random_buffer(short_random, 1);
    munit_assert_false(dfc_random_fill(random_probe, sizeof(random_probe)));
    munit_assert_true(dfc_random_failure_is_retryable());
    dfc_host_set_random_buffer(short_random + 1, 1);
    munit_assert_false(dfc_random_failure_is_retryable());
    munit_assert_true(dfc_random_fill(random_probe, sizeof(random_probe)));
    munit_assert_false(dfc_random_failure_is_retryable());
    dfc_host_clear_random_buffer();

    // Every public PICC operation starts a new failure-classification scope,
    // including operations that do not draw randomness themselves.
    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    DfcVirtualPiccActivation activation;
    mark_host_random_failure_retryable();
    munit_assert_true(dfc_virtual_picc_anticollision(&link.credential, &activation));
    munit_assert_false(dfc_random_failure_is_retryable());
    mark_host_random_failure_retryable();
    munit_assert_int(dfc_virtual_picc_reset_protocol(link.picc), ==, DfcVirtualPiccStatusOk);
    munit_assert_false(dfc_random_failure_is_retryable());
    mark_host_random_failure_retryable();
    munit_assert_int(dfc_virtual_picc_advance_time(link.picc, 0), ==, DfcVirtualPiccStatusOk);
    munit_assert_false(dfc_random_failure_is_retryable());
    mark_host_random_failure_retryable();
    munit_assert_int(dfc_virtual_picc_field_off(link.picc), ==, DfcVirtualPiccStatusOk);
    munit_assert_false(dfc_random_failure_is_retryable());
    dfc_host_clear_random_buffer();
    link_close(&link);

    for(size_t i = 0; i < sizeof(authentication_cases) / sizeof(authentication_cases[0]); i++) {
        link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
        select_app(&link, authentication_cases[i].aid);
        DfcEmulator before = *link.picc->emulator;
        dfc_host_set_random_buffer(short_random, authentication_cases[i].short_random_len);
        munit_assert_false(dfc_random_failure_is_retryable());
        uint8_t apdu[] = {0x90, authentication_cases[i].command, 0, 0, 1, 0, 0};
        uint8_t response[32];
        size_t response_len = 0;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link.picc, apdu, sizeof(apdu), response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusProtocolError);
        munit_assert_size(response_len, ==, 0);
        munit_assert_true(dfc_random_failure_is_retryable());
        assert_emulator_unchanged(&before, &link);
        dfc_host_clear_random_buffer();
        munit_assert_false(dfc_random_failure_is_retryable());
        link_close(&link);
    }

#if DFC_ENABLE_ISO7816_AUTH
    const uint8_t reader_random_first[DFC_ISO7816_AUTH_CHALLENGE_LONG] = {0xA1};
    const uint8_t reader_random_second[DFC_ISO7816_AUTH_CHALLENGE_LONG] = {0xB2};
    uint8_t tx[DFC_COMMAND_MAX_APDU];
    uint8_t rx[64];
    size_t tx_len = 0;
    size_t rx_len = 0;
    DfcReaderExchange iso_exchange;

    // The GET CHALLENGE draw fails before the ISO authentication state advances.
    link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    munit_assert_int(
        dfc_reader_authenticate_iso7816_begin(
            &iso_exchange,
            &link.session,
            DFC_ISO7816_AUTH_APP_REFERENCE,
            AES_KEY_0,
            sizeof(AES_KEY_0),
            DFC_ISO7816_AUTH_ALGORITHM_AES,
            reader_random_first,
            reader_random_second,
            sizeof(reader_random_first)),
        ==,
        DfcReaderOk);
    munit_assert_int(
        dfc_reader_step(&iso_exchange, NULL, 0, tx, sizeof(tx), &tx_len), ==, DfcReaderPending);
    DfcEmulator before_iso_first = *link.picc->emulator;
    dfc_host_set_random_buffer(short_random, sizeof(reader_random_first) - 1);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(link.picc, tx, tx_len, rx, sizeof(rx), &rx_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_size(rx_len, ==, 0);
    assert_emulator_unchanged(&before_iso_first, &link);
    dfc_host_clear_random_buffer();
    link_close(&link);

    // Advance through GET CHALLENGE and EXTERNAL AUTHENTICATE, then fail the
    // independent INTERNAL AUTHENTICATE draw without committing phase state.
    link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    munit_assert_int(
        dfc_reader_authenticate_iso7816_begin(
            &iso_exchange,
            &link.session,
            DFC_ISO7816_AUTH_APP_REFERENCE,
            AES_KEY_0,
            sizeof(AES_KEY_0),
            DFC_ISO7816_AUTH_ALGORITHM_AES,
            reader_random_first,
            reader_random_second,
            sizeof(reader_random_first)),
        ==,
        DfcReaderOk);
    munit_assert_int(
        dfc_reader_step(&iso_exchange, NULL, 0, tx, sizeof(tx), &tx_len), ==, DfcReaderPending);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(link.picc, tx, tx_len, rx, sizeof(rx), &rx_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_int(
        dfc_reader_step(&iso_exchange, rx, rx_len, tx, sizeof(tx), &tx_len), ==, DfcReaderPending);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(link.picc, tx, tx_len, rx, sizeof(rx), &rx_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_int(
        dfc_reader_step(&iso_exchange, rx, rx_len, tx, sizeof(tx), &tx_len), ==, DfcReaderPending);
    DfcEmulator before_iso_second = *link.picc->emulator;
    dfc_host_set_random_buffer(short_random, sizeof(reader_random_first) - 1);
    rx_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(link.picc, tx, tx_len, rx, sizeof(rx), &rx_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_size(rx_len, ==, 0);
    assert_emulator_unchanged(&before_iso_second, &link);
    dfc_host_clear_random_buffer();
    link_close(&link);

#if DFC_ENABLE_EV2_SECURE_MESSAGING
    // An EV2 First attempt made from an EV1 session must not consume the
    // session CMAC state when either part of its random input is unavailable.
    const size_t ev2_first_short_lengths[] = {15, DFC_EV2_RANDOM_LENGTH};
    uint8_t ev2_from_ev1_response[64];
    size_t ev2_from_ev1_response_len = 0;
    for(size_t i = 0; i < sizeof(ev2_first_short_lengths) / sizeof(ev2_first_short_lengths[0]);
        i++) {
        link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
        select_app(&link, AID_AES);
        munit_assert_int(
            authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, sizeof(AES_KEY_0)),
            ==,
            DfcReaderOk);
        munit_assert_not_null(link.picc->emulator->secure_messaging);
        DfcSecureMessaging before_secure_messaging = *link.picc->emulator->secure_messaging;
        DfcEmulator before_ev2_from_ev1 = *link.picc->emulator;
        dfc_host_set_random_buffer(short_random, ev2_first_short_lengths[i]);
        const uint8_t ev2_from_ev1[] = {0x90, DFC_CMD_AUTHENTICATE_EV2_FIRST, 0, 0, 2, 0, 0, 0};
        ev2_from_ev1_response_len = 0;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link.picc,
                ev2_from_ev1,
                sizeof(ev2_from_ev1),
                ev2_from_ev1_response,
                sizeof(ev2_from_ev1_response),
                &ev2_from_ev1_response_len),
            ==,
            DfcVirtualPiccStatusProtocolError);
        munit_assert_size(ev2_from_ev1_response_len, ==, 0);
        assert_emulator_unchanged(&before_ev2_from_ev1, &link);
        munit_assert_memory_equal(
            sizeof(before_secure_messaging),
            &before_secure_messaging,
            link.picc->emulator->secure_messaging);
        dfc_host_clear_random_buffer();

        DfcCommand command;
        DfcReaderExchange exchange;
        munit_assert_int(dfc_command_read_data(&command, FileMac, 0, 8), ==, DfcCommandOk);
        munit_assert_int(link_send(&link, &command, DFC_COMM_MAC, &exchange), ==, DfcReaderOk);
        link_close(&link);
    }
#endif
#endif

#if DFC_ENABLE_EV2_SECURE_MESSAGING
    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    DfcEmulator before_first = *link.picc->emulator;
    dfc_host_set_random_buffer(short_random, 16);
    const uint8_t ev2_first[] = {0x90, DFC_CMD_AUTHENTICATE_EV2_FIRST, 0, 0, 2, 0, 0, 0};
    uint8_t ev2_response[64];
    size_t ev2_response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc,
            ev2_first,
            sizeof(ev2_first),
            ev2_response,
            sizeof(ev2_response),
            &ev2_response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_size(ev2_response_len, ==, 0);
    assert_emulator_unchanged(&before_first, &link);
    dfc_host_clear_random_buffer();
    link_close(&link);

    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);
    DfcEmulator before_non_first = *link.picc->emulator;
    dfc_host_set_random_buffer(short_random, 15);
    const uint8_t ev2_non_first[] = {0x90, DFC_CMD_AUTHENTICATE_EV2_NON_FIRST, 0, 0, 1, 1, 0};
    ev2_response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc,
            ev2_non_first,
            sizeof(ev2_non_first),
            ev2_response,
            sizeof(ev2_response),
            &ev2_response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_size(ev2_response_len, ==, 0);
    assert_emulator_unchanged(&before_non_first, &link);
    dfc_host_clear_random_buffer();
    link_close(&link);
#endif

#if DFC_ENABLE_PROXIMITY_CHECK
    link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
    link.credential.picc_has_proximity_key = true;
    DfcEmulator before_proximity = *link.picc->emulator;
    dfc_host_set_random_buffer(short_random, DFC_PROXIMITY_RANDOM_LENGTH - 1);
    const uint8_t proximity[] = {0x90, DFC_CMD_PREPARE_PROXIMITY_CHECK, 0, 0, 0};
    uint8_t proximity_response[32];
    size_t proximity_response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc,
            proximity,
            sizeof(proximity),
            proximity_response,
            sizeof(proximity_response),
            &proximity_response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_size(proximity_response_len, ==, 0);
    assert_emulator_unchanged(&before_proximity, &link);
    dfc_host_clear_random_buffer();
    link_close(&link);

    // Exercise the same failure through ISO-DEP while EV1 secure messaging is
    // active. The failed I-block must not consume either chaining state.
    link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
    link.credential.picc_has_proximity_key = true;
    select_app(&link, AID_AES);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, sizeof(AES_KEY_0)),
        ==,
        DfcReaderOk);
    const uint8_t rats[] = {0xE0, 0x80};
    uint8_t frame_response[128];
    size_t frame_response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            link.picc,
            rats,
            sizeof(rats),
            frame_response,
            sizeof(frame_response),
            &frame_response_len),
        ==,
        DfcVirtualPiccStatusOk);
    uint8_t expected_sequence = link.picc->expected_pcd_sequence;
    DfcVirtualPiccSession before_proximity_session = *link.picc;
    DfcSecureMessaging before_proximity_secure = *link.picc->emulator->secure_messaging;
    DfcEmulator before_secure_proximity = *link.picc->emulator;
    const uint8_t proximity_frame[] = {0x02, 0x90, DFC_CMD_PREPARE_PROXIMITY_CHECK, 0, 0, 0};
    dfc_host_set_random_buffer(short_random, DFC_PROXIMITY_RANDOM_LENGTH - 1);
    frame_response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            link.picc,
            proximity_frame,
            sizeof(proximity_frame),
            frame_response,
            sizeof(frame_response),
            &frame_response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_size(frame_response_len, ==, 0);
    munit_assert_uint8(link.picc->expected_pcd_sequence, ==, expected_sequence);
    munit_assert_memory_equal(
        sizeof(before_proximity_session), &before_proximity_session, link.picc);
    assert_emulator_unchanged(&before_secure_proximity, &link);
    munit_assert_memory_equal(
        sizeof(before_proximity_secure),
        &before_proximity_secure,
        link.picc->emulator->secure_messaging);
    dfc_host_clear_random_buffer();

    DfcCommand command;
    DfcReaderExchange exchange;
    DfcReaderOptions options = {.comm_mode = DFC_COMM_MAC};
    uint8_t secured_apdu[DFC_COMMAND_MAX_APDU];
    size_t secured_apdu_len = 0;
    munit_assert_int(dfc_command_read_data(&command, FileMac, 0, 8), ==, DfcCommandOk);
    munit_assert_int(
        dfc_reader_exchange_begin(&exchange, &link.session, link.framing, &command, &options),
        ==,
        DfcReaderOk);
    munit_assert_int(
        dfc_reader_step(&exchange, NULL, 0, secured_apdu, sizeof(secured_apdu), &secured_apdu_len),
        ==,
        DfcReaderPending);
    uint8_t secured_frame[1 + DFC_COMMAND_MAX_APDU];
    secured_frame[0] = (uint8_t)(0x02 | expected_sequence);
    memcpy(secured_frame + 1, secured_apdu, secured_apdu_len);
    frame_response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            link.picc,
            secured_frame,
            secured_apdu_len + 1,
            frame_response,
            sizeof(frame_response),
            &frame_response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(frame_response_len, >, 1);
    munit_assert_int(
        dfc_reader_step(
            &exchange,
            frame_response + 1,
            frame_response_len - 1,
            secured_apdu,
            sizeof(secured_apdu),
            &secured_apdu_len),
        ==,
        DfcReaderOk);
    link_close(&link);
#endif

#if DFC_ENABLE_VIRTUAL_CARD
    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    const uint8_t iid[] = {0xF0, 1, 2, 3, 4};
    link.credential.virtual_card_configured = true;
    link.credential.virtual_card_authentication_mandatory = true;
    memcpy(link.credential.virtual_card_installation_id, iid, sizeof(iid));
    link.credential.virtual_card_installation_id_len = sizeof(iid);
    link.credential.virtual_card_uid_len = link.credential.uid_len;
    memcpy(link.credential.virtual_card_uid, link.credential.uid, link.credential.uid_len);
    uint8_t apdu[32];
    size_t apdu_len = 0;
    munit_assert_int(
        dfc_reader_virtual_card_select_apdu(iid, sizeof(iid), apdu, sizeof(apdu), &apdu_len),
        ==,
        DfcReaderOk);
    DfcEmulator before_virtual = *link.picc->emulator;
    dfc_host_set_random_buffer(short_random, DFC_VIRTUAL_CARD_CHALLENGE_LENGTH - 1);
    uint8_t response[64];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, apdu, apdu_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_size(response_len, ==, 0);
    assert_emulator_unchanged(&before_virtual, &link);
    dfc_host_clear_random_buffer();
    link_close(&link);
#endif

#if DFC_ENABLE_SDM
    link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
    DfcFile* sdm_file = dfc_credential_find_file_in_app(&link.credential, 0, FileLong);
    munit_assert_not_null(sdm_file);
    dfc_file_sdm_flag_set(sdm_file, DfcSdmFlagEnabled, true);
    dfc_file_sdm_flag_set(sdm_file, DfcSdmFlagPiccDataOffset, true);
    sdm_file->state.data.sdm.picc_data_offset = 0;
    sdm_file->state.data.sdm_read_counter = 41;
    DfcEmulator before_sdm = *link.picc->emulator;
    uint32_t before_counter = sdm_file->state.data.sdm_read_counter;
    dfc_host_set_random_buffer(short_random, 7);
    munit_assert_false(dfc_emulator_render_sdm_read(link.picc->emulator, sdm_file));
    assert_emulator_unchanged(&before_sdm, &link);
    munit_assert_uint32(sdm_file->state.data.sdm_read_counter, ==, before_counter);
    dfc_host_clear_random_buffer();
    link_close(&link);
#endif

    // ISO SELECT must not reset the active application/session until its status
    // word fits. Retrying with two bytes performs the selection once.
    link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, sizeof(AES_KEY_0)),
        ==,
        DfcReaderOk);
    DfcApplication* iso_app = &link.credential.apps[0];
    const uint8_t iso_aid[] = {0xF0, 0x12, 0x34};
    memcpy(iso_app->iso_aid, iso_aid, sizeof(iso_aid));
    iso_app->iso_aid_len = sizeof(iso_aid);
    const uint8_t select_iso_app[] = {
        DFC_ISO7816_CLA_STANDARD,
        DFC_ISO7816_INS_SELECT,
        DFC_ISO7816_SELECT_BY_DF_NAME,
        0,
        sizeof(iso_aid),
        0xF0,
        0x12,
        0x34,
    };
    DfcVirtualPiccSession select_session_before = *link.picc;
    DfcEmulator select_emulator_before = *link.picc->emulator;
    DfcSecureMessaging select_sm_before = *link.picc->emulator->secure_messaging;
    for(size_t capacity = 0; capacity < DFC_ISO7816_STATUS_WORD_LENGTH; capacity++) {
        response_len = SIZE_MAX;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link.picc,
                select_iso_app,
                sizeof(select_iso_app),
                response,
                capacity,
                &response_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        munit_assert_size(response_len, ==, 0);
        munit_assert_memory_equal(
            sizeof(select_session_before), &select_session_before, link.picc);
        munit_assert_memory_equal(
            sizeof(select_emulator_before), &select_emulator_before, link.picc->emulator);
        munit_assert_memory_equal(
            sizeof(select_sm_before), &select_sm_before, link.picc->emulator->secure_messaging);
    }
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc,
            select_iso_app,
            sizeof(select_iso_app),
            response,
            DFC_ISO7816_STATUS_WORD_LENGTH,
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(
        DFC_ISO7816_STATUS_WORD_LENGTH,
        response,
        ((uint8_t[]){DFC_ISO7816_SW_OK_HI, DFC_ISO7816_SW_OK_LO}));
    munit_assert_ptr_equal(
        link.picc->emulator->secure_messaging, select_emulator_before.secure_messaging);
    munit_assert_false(dfc_emulator_native_authentication_active(link.picc->emulator));
    munit_assert_memory_equal(
        sizeof(*link.picc->emulator->secure_messaging),
        link.picc->emulator->secure_messaging,
        ((uint8_t[sizeof(*link.picc->emulator->secure_messaging)]){0}));
    munit_assert_int(
        link.picc->emulator->selected_application, ==, DfcEmulatorSelectedApplicationApp);
    munit_assert_size(link.picc->emulator->selected_app_index, ==, 0);
    link_close(&link);
    return MUNIT_OK;
}

static DfcReaderStatus
    run_with_output_capacity_retries(Link* link, DfcReaderExchange* ex, size_t* retry_count) {
    uint8_t tx[DFC_COMMAND_MAX_APDU];
    size_t tx_len = 0;
    uint8_t rx[512];
    size_t rx_len = 0;
    const uint8_t* answer = NULL;
    DfcReaderStatus st;
    for(;;) {
        DfcReaderExchange exchange_before = *ex;
        DfcReaderSession session_before = *ex->session;
        DfcReaderExchange expected_exchange = exchange_before;
        DfcReaderSession expected_session = session_before;
        expected_exchange.session = &expected_session;
        uint8_t expected_tx[DFC_COMMAND_MAX_APDU];
        size_t expected_tx_len = 0;
        DfcReaderStatus expected_status = dfc_reader_step(
            &expected_exchange, answer, rx_len, expected_tx, sizeof(expected_tx), &expected_tx_len);
        st = dfc_reader_step(ex, answer, rx_len, tx, 0, &tx_len);
        if(st == DfcReaderBufferTooSmall) {
            munit_assert_size(tx_len, ==, 0);
            munit_assert_memory_equal(sizeof(exchange_before), &exchange_before, ex);
            munit_assert_memory_equal(sizeof(session_before), &session_before, ex->session);
            (*retry_count)++;
            st = dfc_reader_step(ex, answer, rx_len, tx, sizeof(tx), &tx_len);
            munit_assert_int(st, ==, expected_status);
            munit_assert_size(tx_len, ==, expected_tx_len);
            munit_assert_memory_equal(tx_len, tx, expected_tx);
            expected_exchange.session = ex->session;
            munit_assert_memory_equal(sizeof(expected_exchange), &expected_exchange, ex);
            munit_assert_memory_equal(sizeof(expected_session), &expected_session, ex->session);
        }
        if(st != DfcReaderPending) return st;
        munit_assert_size(tx_len, >, 0);
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(link->picc, tx, tx_len, rx, sizeof(rx), &rx_len),
            ==,
            DfcVirtualPiccStatusOk);
        answer = rx;
    }
}

static void assert_internal_response_overflow_is_terminal(
    Link* link,
    const DfcCommand* command,
    uint8_t comm) {
    DfcReaderExchange exchange;
    DfcReaderOptions options = {.comm_mode = comm};
    munit_assert_int(
        dfc_reader_exchange_begin(&exchange, &link->session, link->framing, command, &options),
        ==,
        DfcReaderOk);

    uint8_t emitted[DFC_COMMAND_MAX_APDU];
    size_t emitted_len = 0;
    munit_assert_int(
        dfc_reader_step(&exchange, NULL, 0, emitted, sizeof(emitted), &emitted_len),
        ==,
        DfcReaderPending);

    uint8_t oversized[DFC_READER_MAX_RESPONSE + DFC_ISO7816_STATUS_WORD_LENGTH + 1] = {0};
    oversized[sizeof(oversized) - 2] = 0x91;
    oversized[sizeof(oversized) - 1] = DFC_CMD_ADDITIONAL_FRAME;
    size_t ignored = 0;
    DfcReaderStatus status = dfc_reader_step(
        &exchange, oversized, sizeof(oversized), emitted, sizeof(emitted), &ignored);
    munit_assert_int(status, ==, DfcReaderProtocolError);
    munit_assert_int(status, !=, DfcReaderBufferTooSmall);
}

static void assert_reader_pending_retry_is_atomic(
    DfcReaderExchange* exchange,
    const uint8_t* response,
    size_t response_len,
    size_t required_capacity,
    uint8_t* command,
    size_t* command_len) {
    DfcReaderExchange exchange_before = *exchange;
    DfcReaderSession session_before = *exchange->session;
    *command_len = SIZE_MAX;
    munit_assert_int(
        dfc_reader_step(
            exchange, response, response_len, command, required_capacity - 1, command_len),
        ==,
        DfcReaderBufferTooSmall);
    munit_assert_size(*command_len, ==, 0);
    munit_assert_memory_equal(sizeof(exchange_before), &exchange_before, exchange);
    munit_assert_memory_equal(sizeof(session_before), &session_before, exchange->session);

    munit_assert_int(
        dfc_reader_step(exchange, response, response_len, command, required_capacity, command_len),
        ==,
        DfcReaderPending);
    munit_assert_size(*command_len, ==, required_capacity);
}

static MunitResult
    test_stream_state_has_deterministic_representation(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcReaderSession session;
    dfc_reader_session_init(&session);
    uint8_t payload[] = {0xA5};
    DfcReaderExchange exchange;
    munit_assert_int(
        dfc_reader_write_data_begin(
            &exchange,
            &session,
            DfcReaderFramingNative,
            7,
            3,
            payload,
            sizeof(payload),
            DFC_COMM_PLAIN),
        ==,
        DfcReaderOk);

    DfcReaderStream expected;
    memset(&expected, 0, sizeof(expected));
    expected.data = payload;
    expected.length = sizeof(payload);
    expected.offset = sizeof(payload);
    expected.base_offset = 3;
    expected.file_number = 7;
    expected.comm_mode = DFC_COMM_PLAIN;
    expected.kind = 1;
    munit_assert_memory_equal(sizeof(expected), &expected, &exchange.stream);
    return MUNIT_OK;
}

static DfcReaderStatus run_authentication_with_capacity_retries(
    Link* link,
    DfcReaderExchange* exchange,
    const size_t* command_capacities,
    size_t command_count) {
    uint8_t command[DFC_COMMAND_MAX_APDU];
    uint8_t response[64];
    const uint8_t* answer = NULL;
    size_t response_len = 0;
    for(size_t i = 0; i < command_count; i++) {
        size_t command_len = 0;
        assert_reader_pending_retry_is_atomic(
            exchange, answer, response_len, command_capacities[i], command, &command_len);
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link->picc, command, command_len, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        answer = response;
    }

    size_t command_len = 0;
    return dfc_reader_step(exchange, answer, response_len, command, sizeof(command), &command_len);
}

static size_t native_auth_command_capacity(DfcReaderFraming framing, size_t data_len) {
    return framing == DfcReaderFramingIso7816 ? data_len + DFC_COMMAND_APDU_OVERHEAD :
                                                data_len + 1;
}

static FILE* open_authentication_boundary_contract(void) {
    FILE* contract = fopen("authentication-boundaries.txt", "r");
    return contract ? contract : fopen("tests/authentication-boundaries.txt", "r");
}

static uint8_t authentication_command(const char* cipher) {
    if(strcmp(cipher, "legacy") == 0) return DFC_CMD_AUTHENTICATE_LEGACY;
    if(strcmp(cipher, "iso") == 0) return DFC_CMD_AUTHENTICATE_ISO;
    if(strcmp(cipher, "aes") == 0) return DFC_CMD_AUTHENTICATE_AES;
    munit_errorf("unknown authentication cipher in shared contract: %s", cipher);
    return 0;
}

static MunitResult test_authentication_boundaries_match_shared_contract(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    FILE* contract = open_authentication_boundary_contract();
    munit_assert_not_null(contract);

    char line[96];
    size_t cases = 0;
    while(fgets(line, sizeof(line), contract)) {
        if(line[0] == '#') continue;
        char cipher_name[8];
        char accepted_name[4];
        size_t key_len = 0;
        size_t challenge_len = 0;
        munit_assert_int(
            sscanf(
                line, "%7[^|]|%zu|%zu|%3s", cipher_name, &key_len, &challenge_len, accepted_name),
            ==,
            4);

        uint8_t cipher = authentication_command(cipher_name);
        bool accepted = strcmp(accepted_name, "yes") == 0;
        uint8_t key[DFC_MAX_KEY_LEN] = {0};
        uint8_t random_a[DFC_EV2_RANDOM_LENGTH] = {0};
        DfcReaderSession session;
        DfcReaderExchange exchange;
        dfc_reader_session_init(&session);
        DfcReaderStatus status = dfc_reader_authenticate_begin(
            &exchange,
            &session,
            DfcReaderFramingNative,
            cipher,
            0,
            key,
            key_len,
            random_a,
            challenge_len);
        munit_assert_int(status, ==, accepted ? DfcReaderOk : DfcReaderInvalid);
        if(accepted)
            munit_assert_size(dfc_reader_challenge_length(cipher, key_len), ==, challenge_len);
        cases++;
    }
    fclose(contract);
    munit_assert_size(cases, ==, 12);
    return MUNIT_OK;
}

static MunitResult
    test_authentication_output_capacity_retries(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static const struct {
        const uint8_t* aid;
        uint8_t cipher;
        const uint8_t* key;
        size_t key_len;
    } native_cases[] = {
        {AID_D40, DFC_CMD_AUTHENTICATE_LEGACY, DES_KEY_0, sizeof(DES_KEY_0)},
        {AID_ISO, DFC_CMD_AUTHENTICATE_ISO, TDES_KEY_0, sizeof(TDES_KEY_0)},
        {AID_3K, DFC_CMD_AUTHENTICATE_ISO, TDES3_KEY_0, sizeof(TDES3_KEY_0)},
        {AID_AES, DFC_CMD_AUTHENTICATE_AES, AES_KEY_0, sizeof(AES_KEY_0)},
    };
    static const DfcReaderFraming framings[] = {
        DfcReaderFramingNative,
        DfcReaderFramingIso7816,
    };
    static Link link;

    for(size_t framing_index = 0; framing_index < sizeof(framings) / sizeof(framings[0]);
        framing_index++) {
        DfcReaderFraming framing = framings[framing_index];
        for(size_t i = 0; i < sizeof(native_cases) / sizeof(native_cases[0]); i++) {
            link_open(&link, DfcGenerationEv3, framing);
            select_app(&link, native_cases[i].aid);
            size_t challenge =
                dfc_reader_challenge_length(native_cases[i].cipher, native_cases[i].key_len);
            uint8_t random_a[DFC_EV2_RANDOM_LENGTH];
            for(size_t n = 0; n < challenge; n++)
                random_a[n] = (uint8_t)(0x40 + n);
            DfcReaderExchange exchange;
            munit_assert_int(
                dfc_reader_authenticate_begin(
                    &exchange,
                    &link.session,
                    framing,
                    native_cases[i].cipher,
                    0,
                    native_cases[i].key,
                    native_cases[i].key_len,
                    random_a,
                    challenge),
                ==,
                DfcReaderOk);
            const size_t capacities[] = {
                native_auth_command_capacity(framing, 1),
                native_auth_command_capacity(framing, challenge * 2),
            };
            munit_assert_int(
                run_authentication_with_capacity_retries(&link, &exchange, capacities, 2),
                ==,
                DfcReaderOk);
            link_close(&link);
        }
    }

#if DFC_ENABLE_ISO7816_AUTH
    static const struct {
        const uint8_t* aid;
        const uint8_t* key;
        size_t key_len;
        uint8_t algorithm;
        size_t challenge_len;
    } iso_cases[] = {
        {AID_ISO,
         TDES_KEY_0,
         sizeof(TDES_KEY_0),
         DFC_ISO7816_AUTH_ALGORITHM_2TDEA,
         DFC_ISO7816_AUTH_CHALLENGE_2TDEA},
        {AID_3K,
         TDES3_KEY_0,
         sizeof(TDES3_KEY_0),
         DFC_ISO7816_AUTH_ALGORITHM_3TDEA,
         DFC_ISO7816_AUTH_CHALLENGE_LONG},
        {AID_AES,
         AES_KEY_0,
         sizeof(AES_KEY_0),
         DFC_ISO7816_AUTH_ALGORITHM_AES,
         DFC_ISO7816_AUTH_CHALLENGE_LONG},
    };
    for(size_t i = 0; i < sizeof(iso_cases) / sizeof(iso_cases[0]); i++) {
        link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
        select_app(&link, iso_cases[i].aid);
        uint8_t first[DFC_ISO7816_AUTH_CHALLENGE_LONG];
        uint8_t second[DFC_ISO7816_AUTH_CHALLENGE_LONG];
        for(size_t n = 0; n < iso_cases[i].challenge_len; n++) {
            first[n] = (uint8_t)(0x60 + n);
            second[n] = (uint8_t)(0x80 + n);
        }
        DfcReaderExchange exchange;
        munit_assert_int(
            dfc_reader_authenticate_iso7816_begin(
                &exchange,
                &link.session,
                DFC_ISO7816_AUTH_APP_REFERENCE,
                iso_cases[i].key,
                iso_cases[i].key_len,
                iso_cases[i].algorithm,
                first,
                second,
                iso_cases[i].challenge_len),
            ==,
            DfcReaderOk);
        const size_t capacities[] = {
            5,
            5 + iso_cases[i].challenge_len * 2,
            6 + iso_cases[i].challenge_len,
        };
        munit_assert_int(
            run_authentication_with_capacity_retries(&link, &exchange, capacities, 3),
            ==,
            DfcReaderOk);
        link_close(&link);
    }
#endif

#if DFC_ENABLE_EV2_SECURE_MESSAGING
    for(size_t framing_index = 0; framing_index < sizeof(framings) / sizeof(framings[0]);
        framing_index++) {
        DfcReaderFraming framing = framings[framing_index];
        link_open(&link, DfcGenerationEv2, framing);
        select_app(&link, AID_AES);
        uint8_t random_a[DFC_EV2_RANDOM_LENGTH] = {0xA5};
        const uint8_t capabilities[DFC_EV2_CAPABILITY_LENGTH] = {0};
        DfcReaderExchange exchange;
        munit_assert_int(
            dfc_reader_authenticate_ev2_begin(
                &exchange,
                &link.session,
                framing,
                true,
                0,
                AES_KEY_0,
                random_a,
                capabilities,
                sizeof(capabilities)),
            ==,
            DfcReaderOk);
        const size_t first_capacities[] = {
            native_auth_command_capacity(framing, 2 + sizeof(capabilities)),
            native_auth_command_capacity(framing, 2 * DFC_EV2_RANDOM_LENGTH),
        };
        munit_assert_int(
            run_authentication_with_capacity_retries(&link, &exchange, first_capacities, 2),
            ==,
            DfcReaderOk);

        memset(random_a, 0x5A, sizeof(random_a));
        munit_assert_int(
            dfc_reader_authenticate_ev2_begin(
                &exchange, &link.session, framing, false, 1, AES_KEY_1, random_a, NULL, 0),
            ==,
            DfcReaderOk);
        const size_t non_first_capacities[] = {
            native_auth_command_capacity(framing, 1),
            native_auth_command_capacity(framing, 2 * DFC_EV2_RANDOM_LENGTH),
        };
        munit_assert_int(
            run_authentication_with_capacity_retries(&link, &exchange, non_first_capacities, 2),
            ==,
            DfcReaderOk);
        link_close(&link);
    }
#endif
    return MUNIT_OK;
}

static void assert_file_bytes(const uint8_t* data, size_t len, uint8_t number, size_t offset) {
    for(size_t i = 0; i < len; i++)
        munit_assert_uint8(data[i], ==, (uint8_t)(number * 0x10 + offset + i));
}

static MunitResult test_native_command_chaining(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, sizeof(AES_KEY_0)),
        ==,
        DfcReaderOk);

    uint8_t bytes[LONG_FILE_SIZE];
    for(size_t i = 0; i < sizeof(bytes); i++)
        bytes[i] = (uint8_t)(0xA0 + i);
    DfcCommand command;
    DfcReaderExchange ex;
    munit_assert_int(
        dfc_command_write_data(&command, FileLong, 0, bytes, sizeof(bytes)), ==, DfcCommandOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_MAC, &ex), ==, DfcReaderOk);

    DfcFile* file = dfc_credential_find_file_in_app(&link.credential, 0, FileLong);
    munit_assert_not_null(file);
    munit_assert_memory_equal(sizeof(bytes), dfc_file_data(&link.credential, file), bytes);
    link_close(&link);
    return MUNIT_OK;
}

static MunitResult test_multiframe_terminal_response_retires_unsent_command(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    DfcReaderSession session;
    dfc_reader_session_init(&session);

    uint8_t payload[DFC_EV1_MAX_FRAME_PAYLOAD + 16];
    memset(payload, 0xA5, sizeof(payload));
    DfcCommand command;
    munit_assert_int(
        dfc_command_write_data(&command, FileLong, 0, payload, sizeof(payload)), ==, DfcCommandOk);

    DfcReaderExchange exchange;
    munit_assert_int(
        dfc_reader_exchange_begin(&exchange, &session, DfcReaderFramingNative, &command, NULL),
        ==,
        DfcReaderOk);
    uint8_t frame[DFC_EV1_MAX_FRAME_PAYLOAD + 1];
    size_t frame_len = 0;
    munit_assert_int(
        dfc_reader_step(&exchange, NULL, 0, frame, sizeof(frame), &frame_len),
        ==,
        DfcReaderPending);
    munit_assert_size(exchange.frame_offset, <, exchange.frame_len);

    const uint8_t malformed_terminal[] = {DFC_STATUS_PERMISSION_DENIED, 0x5A};
    munit_assert_int(
        dfc_reader_step(
            &exchange,
            malformed_terminal,
            sizeof(malformed_terminal),
            frame,
            sizeof(frame),
            &frame_len),
        ==,
        DfcReaderProtocolError);

    size_t response_len = 0;
    const uint8_t* response = dfc_reader_result_data(&exchange, &response_len);
    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, 0x5A);
    for(size_t i = response_len; i < sizeof(exchange.frame); i++)
        munit_assert_uint8(exchange.frame[i], ==, 0);
    return MUNIT_OK;
}

static MunitResult
    test_command_output_capacity_retries(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    DfcCommand command;
    DfcReaderExchange ex;
    size_t retries = 0;

    link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
    munit_assert_int(dfc_command_get_version(&command), ==, DfcCommandOk);
    munit_assert_int(
        dfc_reader_exchange_begin(&ex, &link.session, link.framing, &command, NULL),
        ==,
        DfcReaderOk);
    munit_assert_int(run_with_output_capacity_retries(&link, &ex, &retries), ==, DfcReaderOk);
    munit_assert_size(retries, >=, 3);

    select_app(&link, AID_AES);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, sizeof(AES_KEY_0)),
        ==,
        DfcReaderOk);
    retries = 0;
    munit_assert_int(
        dfc_reader_exchange_begin(&ex, &link.session, link.framing, &command, NULL),
        ==,
        DfcReaderOk);
    munit_assert_int(run_with_output_capacity_retries(&link, &ex, &retries), ==, DfcReaderOk);
    munit_assert_size(retries, >=, 3);

    DfcFile* file = dfc_credential_find_file_in_app(&link.credential, 0, FileLong);
    munit_assert_not_null(file);
    munit_assert_true(dfc_file_resize(&link.credential, file, 300));
    uint8_t written[300];
    for(size_t i = 0; i < sizeof(written); i++)
        written[i] = (uint8_t)(i ^ 0x6D);
    retries = 0;
    munit_assert_int(
        dfc_reader_write_data_begin(
            &ex, &link.session, link.framing, FileLong, 0, written, sizeof(written), DFC_COMM_MAC),
        ==,
        DfcReaderOk);
    munit_assert_int(run_with_output_capacity_retries(&link, &ex, &retries), ==, DfcReaderOk);
    munit_assert_size(retries, >=, 5);
    munit_assert_memory_equal(sizeof(written), dfc_file_data(&link.credential, file), written);
    link_close(&link);
    return MUNIT_OK;
}

static MunitResult
    test_authenticated_directory_framing(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);

    for(size_t i = link.credential.num_apps; i < DFC_MAX_APPS; i++) {
        uint8_t aid[3] = {(uint8_t)(0x40 + i), 0x55, 0x66};
        DfcApplication* app = dfc_credential_create_application_desfire_order(
            &link.credential, aid, 0x0F, DFC_KEY_TYPE_AES | 1);
        munit_assert_not_null(app);
    }
    for(size_t i = 0; i < link.credential.num_apps; i++) {
        DfcApplication* app = &link.credential.apps[i];
        app->has_iso_file_id = true;
        app->iso_file_id = (uint16_t)(0xE100 + i);
        app->iso_aid_len = 16;
        for(size_t n = 0; n < app->iso_aid_len; n++)
            app->iso_aid[n] = (uint8_t)(i + n);
    }

    munit_assert_true(dfc_credential_keys_resize(&link.credential, NULL, 1, 16));
    link.credential.picc_key_settings_2 = DFC_KEY_TYPE_AES | 1;
    link.credential.picc_auth_command = DFC_CMD_AUTHENTICATE_AES;
    memcpy(dfc_credential_key(&link.credential, NULL, 0), AES_KEY_0, sizeof(AES_KEY_0));
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, sizeof(AES_KEY_0)),
        ==,
        DfcReaderOk);

    DfcCommand command;
    DfcReaderExchange ex;
    munit_assert_int(dfc_command_get_application_ids(&command), ==, DfcCommandOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderOk);
    size_t length = 0;
    dfc_reader_result_data(&ex, &length);
    munit_assert_size(length, ==, DFC_MAX_APPS * 3);

    munit_assert_int(dfc_command_get_df_names(&command), ==, DfcCommandOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderOk);
    const uint8_t* names = dfc_reader_result_data(&ex, &length);
    munit_assert_size(length, ==, DFC_MAX_APPS * 21);
    for(size_t i = 0; i < DFC_MAX_APPS; i++) {
        munit_assert_uint8(names[i * 21 + 5], ==, (uint8_t)i);
    }

    link_close(&link);
    return MUNIT_OK;
}

static MunitResult test_long_plain_read(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
    add_data_file(&link.credential, 0, 7, DFC_COMM_PLAIN, 300);
    select_app(&link, AID_AES);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, sizeof(AES_KEY_0)),
        ==,
        DfcReaderOk);

    DfcCommand command;
    DfcReaderExchange ex;
    munit_assert_int(dfc_command_read_data(&command, 7, 0, 300), ==, DfcCommandOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderOk);
    size_t length = 0;
    const uint8_t* clear = dfc_reader_result_data(&ex, &length);
    munit_assert_size(length, ==, 300);
    assert_file_bytes(clear, length, 7, 0);
    link_close(&link);
    return MUNIT_OK;
}

static MunitResult test_streamed_secure_write(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
    add_data_file(&link.credential, 0, 7, DFC_COMM_ENCIPHERED, 300);
    select_app(&link, AID_AES);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, sizeof(AES_KEY_0)),
        ==,
        DfcReaderOk);

    uint8_t written[300];
    for(size_t i = 0; i < sizeof(written); i++)
        written[i] = (uint8_t)(i ^ 0xA5);
    DfcReaderExchange ex;
    munit_assert_int(
        dfc_reader_write_data_begin(
            &ex, &link.session, link.framing, 7, 0, written, sizeof(written), DFC_COMM_ENCIPHERED),
        ==,
        DfcReaderOk);
    munit_assert_int(link_run(&link, &ex), ==, DfcReaderOk);
    DfcFile* file = dfc_credential_find_file_in_app(&link.credential, 0, 7);
    munit_assert_not_null(file);
    munit_assert_memory_equal(sizeof(written), dfc_file_data(&link.credential, file), written);
    for(size_t i = 0; i < sizeof(link.picc->emulator->pending_chain); i++)
        munit_assert_uint8(link.picc->emulator->pending_chain[i], ==, 0);

    uint8_t mismatched_header[8] = {DFC_CMD_WRITE_DATA, 7, 0, 0, 0, 16, 0, 0};
    uint8_t mismatched_clear[17];
    memset(mismatched_clear, 0xC7, sizeof(mismatched_clear));
    uint8_t mismatched_wrapped[48];
    size_t mismatched_wrapped_len = dfc_secure_messaging_wrap(
        &link.session.sm,
        DFC_COMM_ENCIPHERED,
        mismatched_header,
        sizeof(mismatched_header),
        mismatched_clear,
        sizeof(mismatched_clear),
        mismatched_wrapped,
        sizeof(mismatched_wrapped));
    munit_assert_size(mismatched_wrapped_len, >, 0);
    uint8_t apdu[5 + 7 + sizeof(mismatched_wrapped) + 1] = {0x90, DFC_CMD_WRITE_DATA, 0, 0};
    apdu[4] = (uint8_t)(7 + mismatched_wrapped_len);
    memcpy(apdu + 5, mismatched_header + 1, 7);
    memcpy(apdu + 12, mismatched_wrapped, mismatched_wrapped_len);
    uint8_t response[64];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, apdu, 13 + mismatched_wrapped_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_BOUNDARY_ERROR);
    for(size_t i = 0; i < sizeof(link.picc->emulator->pending_chain); i++)
        munit_assert_uint8(link.picc->emulator->pending_chain[i], ==, 0);

    link_close(&link);
    return MUNIT_OK;
}

static MunitResult test_streamed_secure_record(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    DfcFile* file = dfc_credential_create_file(&link.credential, 0, 7);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_LINEAR_RECORD;
    file->comm_settings = DFC_COMM_ENCIPHERED;
    file->access_rights = 0x0000;
    file->state.record.size = 300;
    file->state.record.max_records = 2;
    munit_assert_true(dfc_file_resize(&link.credential, file, 600));
    select_app(&link, AID_AES);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, sizeof(AES_KEY_0)),
        ==,
        DfcReaderOk);

    uint8_t written[300];
    for(size_t i = 0; i < sizeof(written); i++)
        written[i] = (uint8_t)(i ^ 0x5A);
    DfcReaderExchange ex;
    munit_assert_int(
        dfc_reader_write_record_begin(
            &ex, &link.session, link.framing, 7, 0, written, sizeof(written), DFC_COMM_ENCIPHERED),
        ==,
        DfcReaderOk);
    munit_assert_int(link_run(&link, &ex), ==, DfcReaderOk);
    munit_assert_uint32(file->state.record.count, ==, 1);
    munit_assert_memory_equal(sizeof(written), dfc_file_data(&link.credential, file), written);

    DfcCommand command;
    munit_assert_int(dfc_command_commit_transaction(&command), ==, DfcCommandOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderOk);

    uint8_t updated[300];
    for(size_t i = 0; i < sizeof(updated); i++)
        updated[i] = (uint8_t)(i ^ 0xC3);
    munit_assert_int(
        dfc_reader_update_record_begin(
            &ex,
            &link.session,
            link.framing,
            7,
            0,
            0,
            updated,
            sizeof(updated),
            DFC_COMM_ENCIPHERED),
        ==,
        DfcReaderOk);
    munit_assert_int(link_run(&link, &ex), ==, DfcReaderOk);
    munit_assert_int(dfc_command_commit_transaction(&command), ==, DfcCommandOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderOk);

    munit_assert_int(dfc_command_read_records(&command, 7, 0, 1, false), ==, DfcCommandOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_ENCIPHERED, &ex), ==, DfcReaderOk);
    size_t read_len = 0;
    const uint8_t* read_data = dfc_reader_result_data(&ex, &read_len);
    munit_assert_size(read_len, ==, sizeof(updated));
    munit_assert_memory_equal(read_len, read_data, updated);
    link_close(&link);
    return MUNIT_OK;
}

static void read_file(Link* link, uint8_t number, uint8_t comm, uint32_t offset, uint32_t length) {
    DfcCommand command;
    DfcReaderExchange ex;
    munit_assert_int(dfc_command_read_data(&command, number, offset, length), ==, DfcCommandOk);
    DfcReaderStatus st = link_send(link, &command, comm, &ex);
    if(st != DfcReaderOk) {
        munit_logf(
            MUNIT_LOG_WARNING,
            "read %02X: %s, status %02X",
            number,
            dfc_reader_status_name(st),
            dfc_reader_result_status(&ex));
    }
    munit_assert_int(st, ==, DfcReaderOk);
    size_t len = 0;
    const uint8_t* data = dfc_reader_result_data(&ex, &len);
    munit_assert_size(len, ==, length);
    assert_file_bytes(data, len, number, offset);
}

static void write_then_read(Link* link, uint8_t number, uint8_t comm) {
    const uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};
    DfcCommand command;
    DfcReaderExchange ex;
    munit_assert_int(
        dfc_command_write_data(&command, number, 4, payload, sizeof(payload)), ==, DfcCommandOk);
    DfcReaderStatus st = link_send(link, &command, comm, &ex);
    if(st != DfcReaderOk) {
        munit_logf(
            MUNIT_LOG_WARNING,
            "write %02X: %s, status %02X",
            number,
            dfc_reader_status_name(st),
            dfc_reader_result_status(&ex));
    }
    munit_assert_int(st, ==, DfcReaderOk);
    munit_assert_true(dfc_reader_session_is_authenticated(&link->session));

    munit_assert_int(
        dfc_command_read_data(&command, number, 4, sizeof(payload)), ==, DfcCommandOk);
    munit_assert_int(link_send(link, &command, comm, &ex), ==, DfcReaderOk);
    size_t len = 0;
    const uint8_t* data = dfc_reader_result_data(&ex, &len);
    munit_assert_size(len, ==, sizeof(payload));
    munit_assert_memory_equal(len, data, payload);
}

static int32_t get_value(Link* link, uint8_t number, uint8_t comm) {
    DfcCommand command;
    DfcReaderExchange ex;
    munit_assert_int(dfc_command_get_value(&command, number), ==, DfcCommandOk);
    DfcReaderStatus st = link_send(link, &command, comm, &ex);
    if(st != DfcReaderOk) {
        munit_logf(
            MUNIT_LOG_WARNING,
            "get value %02X: %s, status %02X",
            number,
            dfc_reader_status_name(st),
            dfc_reader_result_status(&ex));
    }
    munit_assert_int(st, ==, DfcReaderOk);
    size_t len = 0;
    const uint8_t* data = dfc_reader_result_data(&ex, &len);
    munit_assert_size(len, ==, 4);
    return (int32_t)((uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) |
                     ((uint32_t)data[3] << 24));
}

static void credit_and_commit(Link* link, uint8_t number, uint8_t comm) {
    int32_t before = get_value(link, number, comm);
    DfcCommand command;
    DfcReaderExchange ex;
    munit_assert_int(dfc_command_credit(&command, number, 25), ==, DfcCommandOk);
    DfcReaderStatus st = link_send(link, &command, comm, &ex);
    if(st != DfcReaderOk) {
        munit_logf(
            MUNIT_LOG_WARNING,
            "credit %02X: %s, status %02X",
            number,
            dfc_reader_status_name(st),
            dfc_reader_result_status(&ex));
    }
    munit_assert_int(st, ==, DfcReaderOk);
    munit_assert_int(dfc_command_commit_transaction(&command), ==, DfcCommandOk);
    munit_assert_int(link_send(link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderOk);
    munit_assert_int(get_value(link, number, comm), ==, before + 25);
}

static void exercise_files(Link* link) {
    read_file(link, FilePlain, DFC_COMM_PLAIN, 0, 32);
    read_file(link, FileMac, DFC_COMM_MAC, 2, 20);
    read_file(link, FileFull, DFC_COMM_ENCIPHERED, 0, 32);
    write_then_read(link, FilePlain, DFC_COMM_PLAIN);
    write_then_read(link, FileMac, DFC_COMM_MAC);
    write_then_read(link, FileFull, DFC_COMM_ENCIPHERED);
    credit_and_commit(link, FileValueMac, DFC_COMM_MAC);
    credit_and_commit(link, FileValueFull, DFC_COMM_ENCIPHERED);
    munit_assert_true(dfc_reader_session_is_authenticated(&link->session));
}

static MunitResult
    test_internal_response_overflow_is_terminal(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcCommand command;
    {
        static Link link;
        link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
        munit_assert_int(dfc_command_get_version(&command), ==, DfcCommandOk);
        assert_internal_response_overflow_is_terminal(&link, &command, DFC_COMM_PLAIN);
        link_close(&link);
    }
    {
        static Link link;
        link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
        select_app(&link, AID_AES);
        munit_assert_int(
            authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, sizeof(AES_KEY_0)),
            ==,
            DfcReaderOk);
        munit_assert_int(dfc_command_get_version(&command), ==, DfcCommandOk);
        assert_internal_response_overflow_is_terminal(&link, &command, DFC_COMM_PLAIN);
        munit_assert_int(dfc_command_read_data(&command, FileFull, 0, 1), ==, DfcCommandOk);
        assert_internal_response_overflow_is_terminal(&link, &command, DFC_COMM_ENCIPHERED);
        link_close(&link);
    }
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    {
        static Link link;
        link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
        select_app(&link, AID_AES);
        munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);
        munit_assert_int(dfc_command_get_version(&command), ==, DfcCommandOk);
        assert_internal_response_overflow_is_terminal(&link, &command, DFC_COMM_MAC);
        munit_assert_int(dfc_command_read_data(&command, FileFull, 0, 1), ==, DfcCommandOk);
        assert_internal_response_overflow_is_terminal(&link, &command, DFC_COMM_ENCIPHERED);
        link_close(&link);
    }
#endif
    return MUNIT_OK;
}

static MunitResult test_aes_session(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, 16), ==, DfcReaderOk);
    munit_assert_uint8(link.session.auth_mode, ==, DFC_CMD_AUTHENTICATE_AES);
    exercise_files(&link);
    // A chained answer carries one CMAC over the whole of it.
    read_file(&link, FileLong, DFC_COMM_MAC, 0, LONG_FILE_SIZE);
    link_close(&link);
    return MUNIT_OK;
}

static MunitResult test_iso_session(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
    select_app(&link, AID_ISO);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_ISO, 0, TDES_KEY_0, 16), ==, DfcReaderOk);
    exercise_files(&link);
    read_file(&link, FileLong, DFC_COMM_MAC, 0, LONG_FILE_SIZE);
    link_close(&link);
    return MUNIT_OK;
}

#if DFC_ENABLE_ISO7816_AUTH
static MunitResult test_iso7816_mutual_authentication(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static const struct {
        const uint8_t* aid;
        const uint8_t* key;
        size_t key_len;
        uint8_t algorithm;
        size_t challenge_len;
    } cases[] = {
        {AID_ISO,
         TDES_KEY_0,
         sizeof(TDES_KEY_0),
         DFC_ISO7816_AUTH_ALGORITHM_2TDEA,
         DFC_ISO7816_AUTH_CHALLENGE_2TDEA},
        {AID_3K,
         TDES3_KEY_0,
         sizeof(TDES3_KEY_0),
         DFC_ISO7816_AUTH_ALGORITHM_3TDEA,
         DFC_ISO7816_AUTH_CHALLENGE_LONG},
        {AID_AES,
         AES_KEY_0,
         sizeof(AES_KEY_0),
         DFC_ISO7816_AUTH_ALGORITHM_AES,
         DFC_ISO7816_AUTH_CHALLENGE_LONG},
    };
    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        static Link link;
        link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
        select_app(&link, cases[i].aid);
        uint8_t first[DFC_ISO7816_AUTH_CHALLENGE_LONG];
        uint8_t second[DFC_ISO7816_AUTH_CHALLENGE_LONG];
        for(size_t j = 0; j < cases[i].challenge_len; j++) {
            first[j] = (uint8_t)(0xA0 + j);
            second[j] = (uint8_t)(0xB0 + j);
        }
        DfcReaderExchange ex;
        munit_assert_int(
            dfc_reader_authenticate_iso7816_begin(
                &ex,
                &link.session,
                DFC_ISO7816_AUTH_APP_REFERENCE,
                cases[i].key,
                cases[i].key_len,
                cases[i].algorithm,
                first,
                second,
                cases[i].challenge_len),
            ==,
            DfcReaderOk);
        munit_assert_int(link_run(&link, &ex), ==, DfcReaderOk);
        munit_assert_true(dfc_reader_session_is_authenticated(&link.session));
        DfcCommand command;
        munit_assert_int(dfc_command_get_key_settings(&command), ==, DfcCommandOk);
        munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderOk);
        link_close(&link);
    }
    return MUNIT_OK;
}

typedef enum {
    IsoAuthExternalShort,
    IsoAuthExternalWrongReference,
    IsoAuthExternalWrongAlgorithm,
    IsoAuthExternalWrongCryptogram,
    IsoAuthExternalUnexpectedInternal,
    IsoAuthInternalShort,
    IsoAuthInternalWrongReference,
    IsoAuthInternalWrongAlgorithm,
    IsoAuthInternalUnexpectedExternal,
    IsoAuthInternalUnrelatedCommand,
} IsoAuthRejectedTransition;

static void iso7816_authenticate_begin(
    Link* link,
    DfcReaderExchange* exchange,
    uint8_t* command,
    size_t* command_len) {
    static const uint8_t random_a[DFC_ISO7816_AUTH_CHALLENGE_LONG] = {0xA1};
    static const uint8_t random_second[DFC_ISO7816_AUTH_CHALLENGE_LONG] = {0xB2};
    munit_assert_int(
        dfc_reader_authenticate_iso7816_begin(
            exchange,
            &link->session,
            DFC_ISO7816_AUTH_APP_REFERENCE,
            AES_KEY_0,
            sizeof(AES_KEY_0),
            DFC_ISO7816_AUTH_ALGORITHM_AES,
            random_a,
            random_second,
            sizeof(random_a)),
        ==,
        DfcReaderOk);
    munit_assert_int(
        dfc_reader_step(exchange, NULL, 0, command, DFC_COMMAND_MAX_APDU, command_len),
        ==,
        DfcReaderPending);
}

static void iso7816_advance_authentication(
    Link* link,
    DfcReaderExchange* exchange,
    uint8_t* command,
    size_t* command_len,
    uint8_t* response,
    size_t* response_len) {
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link->picc, command, *command_len, response, 64, response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_int(
        dfc_reader_step(
            exchange, response, *response_len, command, DFC_COMMAND_MAX_APDU, command_len),
        ==,
        DfcReaderPending);
}

static void assert_iso7816_authentication_restarts(Link* link) {
    static const uint8_t random_a[DFC_ISO7816_AUTH_CHALLENGE_LONG] = {0xA1};
    static const uint8_t random_second[DFC_ISO7816_AUTH_CHALLENGE_LONG] = {0xB2};
    DfcReaderExchange fresh;
    munit_assert_int(
        dfc_reader_authenticate_iso7816_begin(
            &fresh,
            &link->session,
            DFC_ISO7816_AUTH_APP_REFERENCE,
            AES_KEY_0,
            sizeof(AES_KEY_0),
            DFC_ISO7816_AUTH_ALGORITHM_AES,
            random_a,
            random_second,
            sizeof(random_a)),
        ==,
        DfcReaderOk);
    munit_assert_int(link_run(link, &fresh), ==, DfcReaderOk);
}

static MunitResult
    test_iso7816_rejected_authentication_transitions(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static const IsoAuthRejectedTransition cases[] = {
        IsoAuthExternalShort,
        IsoAuthExternalWrongReference,
        IsoAuthExternalWrongAlgorithm,
        IsoAuthExternalWrongCryptogram,
        IsoAuthExternalUnexpectedInternal,
        IsoAuthInternalShort,
        IsoAuthInternalWrongReference,
        IsoAuthInternalWrongAlgorithm,
        IsoAuthInternalUnexpectedExternal,
        IsoAuthInternalUnrelatedCommand,
    };
    static Link link;

    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
        select_app(&link, AID_AES);

        DfcReaderExchange exchange;
        uint8_t command[DFC_COMMAND_MAX_APDU];
        uint8_t valid_command[DFC_COMMAND_MAX_APDU];
        uint8_t response[64];
        size_t command_len = 0;
        size_t response_len = 0;
        iso7816_authenticate_begin(&link, &exchange, command, &command_len);
        iso7816_advance_authentication(
            &link, &exchange, command, &command_len, response, &response_len);

        bool internal = cases[i] >= IsoAuthInternalShort;
        if(internal) {
            iso7816_advance_authentication(
                &link, &exchange, command, &command_len, response, &response_len);
        }
        memcpy(valid_command, command, command_len);
        size_t valid_command_len = command_len;

        switch(cases[i]) {
        case IsoAuthExternalShort:
        case IsoAuthInternalShort:
            command_len--;
            break;
        case IsoAuthExternalWrongReference:
        case IsoAuthInternalWrongReference:
            command[3] ^= 1;
            break;
        case IsoAuthExternalWrongAlgorithm:
        case IsoAuthInternalWrongAlgorithm:
            command[2] = DFC_ISO7816_AUTH_ALGORITHM_2TDEA;
            break;
        case IsoAuthExternalWrongCryptogram:
            command[5] ^= 1;
            break;
        case IsoAuthExternalUnexpectedInternal:
            command[1] = DFC_ISO7816_INS_INTERNAL_AUTHENTICATE;
            break;
        case IsoAuthInternalUnexpectedExternal:
            command[1] = DFC_ISO7816_INS_EXTERNAL_AUTHENTICATE;
            break;
        case IsoAuthInternalUnrelatedCommand: {
            static const uint8_t unrelated[] = {0x90, DFC_CMD_GET_KEY_SETTINGS, 0, 0, 0};
            memcpy(command, unrelated, sizeof(unrelated));
            command_len = sizeof(unrelated);
            break;
        }
        }

        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link.picc, command, command_len, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        if(cases[i] == IsoAuthInternalUnrelatedCommand) {
            munit_assert_size(response_len, >=, DFC_ISO7816_STATUS_WORD_LENGTH);
            munit_assert_uint8(response[response_len - 2], ==, 0x91);
            munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_OK);
        } else if(cases[i] == IsoAuthExternalShort || cases[i] == IsoAuthInternalShort) {
            munit_assert_size(response_len, ==, DFC_ISO7816_STATUS_WORD_LENGTH);
            munit_assert_uint8(response[0], ==, DFC_ISO7816_SW_WRONG_LENGTH_HI);
            munit_assert_uint8(response[1], ==, DFC_ISO7816_SW_WRONG_LENGTH_LO);
        } else if(
            cases[i] == IsoAuthExternalUnexpectedInternal ||
            cases[i] == IsoAuthInternalUnexpectedExternal) {
            munit_assert_size(response_len, ==, DFC_ISO7816_STATUS_WORD_LENGTH);
            munit_assert_uint8(response[0], ==, DFC_ISO7816_SW_INSTRUCTION_HI);
            munit_assert_uint8(response[1], ==, DFC_ISO7816_SW_INSTRUCTION_LO);
        } else {
            munit_assert_size(response_len, ==, DFC_ISO7816_STATUS_WORD_LENGTH);
            munit_assert_uint8(response[0], ==, DFC_ISO7816_SW_SECURITY_HI);
            munit_assert_uint8(response[1], ==, DFC_ISO7816_SW_SECURITY_LO);
        }

        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link.picc,
                valid_command,
                valid_command_len,
                response,
                sizeof(response),
                &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(response_len, ==, DFC_ISO7816_STATUS_WORD_LENGTH);
        munit_assert_uint8(response[0], ==, DFC_ISO7816_SW_INSTRUCTION_HI);
        munit_assert_uint8(response[1], ==, DFC_ISO7816_SW_INSTRUCTION_LO);

        assert_iso7816_authentication_restarts(&link);
        link_close(&link);
    }

    // An unexpected command cannot abort a pending handshake until its status
    // word can be delivered.
    link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    DfcReaderExchange capacity_exchange;
    uint8_t capacity_command[DFC_COMMAND_MAX_APDU];
    uint8_t capacity_response[64];
    size_t capacity_command_len = 0;
    size_t capacity_response_len = 0;
    iso7816_authenticate_begin(&link, &capacity_exchange, capacity_command, &capacity_command_len);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc,
            capacity_command,
            capacity_command_len,
            capacity_response,
            sizeof(capacity_response),
            &capacity_response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint8(link.picc->emulator->iso_auth_phase, ==, 1);
    const uint8_t select_parent[] = {
        DFC_ISO7816_CLA_STANDARD, DFC_ISO7816_INS_SELECT, DFC_ISO7816_SELECT_PARENT, 0, 0};
    DfcVirtualPiccSession capacity_session_before = *link.picc;
    DfcEmulator capacity_emulator_before = *link.picc->emulator;
    for(size_t capacity = 0; capacity < DFC_ISO7816_STATUS_WORD_LENGTH; capacity++) {
        capacity_response_len = SIZE_MAX;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link.picc,
                select_parent,
                sizeof(select_parent),
                capacity_response,
                capacity,
                &capacity_response_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        munit_assert_size(capacity_response_len, ==, 0);
        munit_assert_memory_equal(
            sizeof(capacity_session_before), &capacity_session_before, link.picc);
        munit_assert_memory_equal(
            sizeof(capacity_emulator_before), &capacity_emulator_before, link.picc->emulator);
    }
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc,
            select_parent,
            sizeof(select_parent),
            capacity_response,
            DFC_ISO7816_STATUS_WORD_LENGTH,
            &capacity_response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint8(link.picc->emulator->iso_auth_phase, ==, 0);
    link_close(&link);

    // A malformed final authentication step likewise remains retryable when
    // the caller supplies no room for its error status.
    link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    iso7816_authenticate_begin(&link, &capacity_exchange, capacity_command, &capacity_command_len);
    iso7816_advance_authentication(
        &link,
        &capacity_exchange,
        capacity_command,
        &capacity_command_len,
        capacity_response,
        &capacity_response_len);
    iso7816_advance_authentication(
        &link,
        &capacity_exchange,
        capacity_command,
        &capacity_command_len,
        capacity_response,
        &capacity_response_len);
    munit_assert_uint8(link.picc->emulator->iso_auth_phase, ==, 2);
    capacity_session_before = *link.picc;
    capacity_emulator_before = *link.picc->emulator;
    for(size_t capacity = 0; capacity < DFC_ISO7816_STATUS_WORD_LENGTH; capacity++) {
        capacity_response_len = SIZE_MAX;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link.picc,
                capacity_command,
                capacity_command_len - 1,
                capacity_response,
                capacity,
                &capacity_response_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        munit_assert_size(capacity_response_len, ==, 0);
        munit_assert_memory_equal(
            sizeof(capacity_session_before), &capacity_session_before, link.picc);
        munit_assert_memory_equal(
            sizeof(capacity_emulator_before), &capacity_emulator_before, link.picc->emulator);
    }
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc,
            capacity_command,
            capacity_command_len - 1,
            capacity_response,
            DFC_ISO7816_STATUS_WORD_LENGTH,
            &capacity_response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(
        DFC_ISO7816_STATUS_WORD_LENGTH,
        capacity_response,
        ((uint8_t[]){DFC_ISO7816_SW_WRONG_LENGTH_HI, DFC_ISO7816_SW_WRONG_LENGTH_LO}));
    munit_assert_uint8(link.picc->emulator->iso_auth_phase, ==, 0);
    link_close(&link);

    link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    DfcReaderExchange exchange;
    uint8_t command[DFC_COMMAND_MAX_APDU];
    uint8_t response[64];
    uint8_t short_random[DFC_ISO7816_AUTH_CHALLENGE_LONG - 1] = {0};
    size_t command_len = 0;
    size_t response_len = 0;
    iso7816_authenticate_begin(&link, &exchange, command, &command_len);
    iso7816_advance_authentication(
        &link, &exchange, command, &command_len, response, &response_len);
    iso7816_advance_authentication(
        &link, &exchange, command, &command_len, response, &response_len);
    DfcEmulator before_capacity = *link.picc->emulator;
    size_t required_capacity =
        DFC_ISO7816_AUTH_CHALLENGE_LONG * 2 + DFC_ISO7816_STATUS_WORD_LENGTH;
    response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, command, command_len, response, required_capacity - 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    assert_emulator_unchanged(&before_capacity, &link);
    DfcEmulator before = *link.picc->emulator;
    dfc_host_set_random_buffer(short_random, sizeof(short_random));
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_size(response_len, ==, 0);
    assert_emulator_unchanged(&before, &link);
    dfc_host_clear_random_buffer();
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_int(
        dfc_reader_step(&exchange, response, response_len, command, sizeof(command), &command_len),
        ==,
        DfcReaderOk);
    link_close(&link);
    return MUNIT_OK;
}
#endif

static MunitResult
    test_virtual_picc_output_capacity_retries(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    uint8_t response[64];
    size_t response_len = 0;
    const uint16_t ACCESS_FREE = 0xEEEE;

    // A native mutation whose response does not fit is executed once. Retrying
    // the same APDU retrieves that response instead of executing it again.
    link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
    link.credential.picc_key_settings_1 |= DFC_KS1_FREE_CREATE_DELETE;
    const uint8_t picc_aid[3] = {0};
    select_app(&link, picc_aid);
    const uint8_t create_application[] = {
        0x90, DFC_CMD_CREATE_APPLICATION, 0x00, 0x00, 0x05, 0x66, 0x55, 0x44, 0x0F, 0x81, 0x00};
    size_t app_count_before = link.credential.num_apps;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, create_application, sizeof(create_application), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_size(link.credential.num_apps, ==, app_count_before + 1);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, create_application, sizeof(create_application), response, 2, &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));
    munit_assert_size(link.credential.num_apps, ==, app_count_before + 1);
    link_close(&link);

    // UPDATE BINARY does not write or dirty the credential until its status
    // word can be delivered.
    link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    DfcFile* file = dfc_credential_find_file_in_app(&link.credential, 0, FilePlain);
    munit_assert_not_null(file);
    // This capacity-retry check exercises the mutation path without authentication.
    file->access_rights = ACCESS_FREE;
    link.picc->iso_file_selected = true;
    link.picc->iso_file_index = (size_t)(file - link.credential.files);
    uint8_t original[2];
    memcpy(original, dfc_file_data(&link.credential, file) + 1, sizeof(original));
    bool dirty_before = link.credential.dirty;
    const uint8_t update_binary[] = {
        DFC_ISO7816_CLA_STANDARD, DFC_ISO7816_INS_UPDATE_BINARY, 0x00, 0x01, 0x02, 0xA5, 0x5A};
    response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc,
            update_binary,
            sizeof(update_binary),
            response,
            DFC_ISO7816_STATUS_WORD_LENGTH - 1,
            &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_memory_equal(
        sizeof(original), dfc_file_data(&link.credential, file) + 1, original);
    munit_assert_int(link.credential.dirty, ==, dirty_before);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc,
            update_binary,
            sizeof(update_binary),
            response,
            DFC_ISO7816_STATUS_WORD_LENGTH,
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x90, 0x00}));
    munit_assert_memory_equal(
        2, dfc_file_data(&link.credential, file) + 1, ((uint8_t[]){0xA5, 0x5A}));
    link_close(&link);

#if DFC_ENABLE_SDM
    // READ BINARY must reject malformed requests and short output before SDM
    // renders, because rendering commits its counter and cache.
    link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    file = dfc_credential_find_file_in_app(&link.credential, 0, FileLong);
    munit_assert_not_null(file);
    file->access_rights = ACCESS_FREE;
    dfc_file_sdm_flag_set(file, DfcSdmFlagEnabled, true);
    dfc_file_sdm_flag_set(file, DfcSdmFlagPiccDataOffset, true);
    file->state.data.sdm.picc_data_offset = 0;
    file->state.data.sdm_read_counter = 41;
    link.picc->iso_file_selected = true;
    link.picc->iso_file_index = (size_t)(file - link.credential.files);

    uint8_t cache_before[DFC_SDM_READ_CACHE_SIZE];
    memcpy(cache_before, link.picc->emulator->sdm_read_cache, sizeof(cache_before));
    bool cache_valid_before = link.picc->emulator->sdm_read_cache_valid;
    uint32_t counter_before = file->state.data.sdm_read_counter;
    dirty_before = link.credential.dirty;
    const uint8_t read_binary[] = {
        DFC_ISO7816_CLA_STANDARD, DFC_ISO7816_INS_READ_BINARY, 0x00, 0x00, 0x10};
    const uint8_t read_binary_short[] = {
        DFC_ISO7816_CLA_STANDARD, DFC_ISO7816_INS_READ_BINARY, 0x00, 0x00};
    const uint8_t read_binary_long[] = {
        DFC_ISO7816_CLA_STANDARD, DFC_ISO7816_INS_READ_BINARY, 0x00, 0x00, 0x10, 0x00};
    const uint8_t read_binary_bad_range[] = {
        DFC_ISO7816_CLA_STANDARD, DFC_ISO7816_INS_READ_BINARY, 0x00, LONG_FILE_SIZE + 1, 0x01};
    const uint8_t read_binary_at_end[] = {
        DFC_ISO7816_CLA_STANDARD, DFC_ISO7816_INS_READ_BINARY, 0x00, LONG_FILE_SIZE, 0x01};

    const struct {
        const uint8_t* command;
        size_t command_len;
        size_t response_capacity;
        DfcVirtualPiccStatus expected;
    } rejected_reads[] = {
        {read_binary, sizeof(read_binary), 1, DfcVirtualPiccStatusBufferTooSmall},
        {read_binary_short, sizeof(read_binary_short), sizeof(response), DfcVirtualPiccStatusOk},
        {read_binary_long, sizeof(read_binary_long), sizeof(response), DfcVirtualPiccStatusOk},
        {read_binary_bad_range,
         sizeof(read_binary_bad_range),
         sizeof(response),
         DfcVirtualPiccStatusOk},
    };
    for(size_t i = 0; i < sizeof(rejected_reads) / sizeof(rejected_reads[0]); i++) {
        response_len = SIZE_MAX;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link.picc,
                rejected_reads[i].command,
                rejected_reads[i].command_len,
                response,
                rejected_reads[i].response_capacity,
                &response_len),
            ==,
            rejected_reads[i].expected);
        munit_assert_uint32(file->state.data.sdm_read_counter, ==, counter_before);
        munit_assert_int(link.picc->emulator->sdm_read_cache_valid, ==, cache_valid_before);
        munit_assert_memory_equal(
            sizeof(cache_before), link.picc->emulator->sdm_read_cache, cache_before);
        munit_assert_int(link.credential.dirty, ==, dirty_before);
        if(rejected_reads[i].command == read_binary_bad_range) {
            munit_assert_size(response_len, ==, DFC_ISO7816_STATUS_WORD_LENGTH);
            munit_assert_memory_equal(
                response_len,
                response,
                ((uint8_t[]){
                    DFC_ISO7816_SW_CONDITIONS_NOT_SATISFIED_HI,
                    DFC_ISO7816_SW_CONDITIONS_NOT_SATISFIED_LO}));
        }
    }

    // Measured on a genuine EV3: an offset equal to the file size is refused
    // with 6985, so it renders nothing and consumes no read count.
    response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc,
            read_binary_at_end,
            sizeof(read_binary_at_end),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, DFC_ISO7816_STATUS_WORD_LENGTH);
    munit_assert_memory_equal(
        response_len,
        response,
        ((uint8_t[]){
            DFC_ISO7816_SW_CONDITIONS_NOT_SATISFIED_HI,
            DFC_ISO7816_SW_CONDITIONS_NOT_SATISFIED_LO}));
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, counter_before);
    munit_assert_int(link.picc->emulator->sdm_read_cache_valid, ==, cache_valid_before);

    // Free read access keeps this ISO response plain, so its length is the
    // requested body plus the status word, without a secure-messaging MAC.
    response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, read_binary, sizeof(read_binary), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 0x10 + DFC_ISO7816_STATUS_WORD_LENGTH);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, counter_before + 1);
    munit_assert_true(link.picc->emulator->sdm_read_cache_valid);
    link_close(&link);
#endif
    return MUNIT_OK;
}

static MunitResult test_3k3des_session(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
    select_app(&link, AID_3K);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_ISO, 0, TDES3_KEY_0, 24), ==, DfcReaderOk);
    munit_assert_size(link.session.sm.session_key_len, ==, 24);
    exercise_files(&link);
    link_close(&link);
    return MUNIT_OK;
}

static MunitResult test_d40_session(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
    select_app(&link, AID_D40);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_LEGACY, 0, DES_KEY_0, 16), ==, DfcReaderOk);
    munit_assert_uint8(link.session.auth_mode, ==, DFC_CMD_AUTHENTICATE_LEGACY);
    exercise_files(&link);
    DfcApplication* app = dfc_credential_find_application(&link.credential, AID_D40);
    munit_assert_not_null(app);
    size_t app_index = dfc_credential_application_index(&link.credential, app);
    DfcFile* long_file = dfc_credential_find_file_in_app(&link.credential, app_index, FileLong);
    munit_assert_not_null(long_file);
    munit_assert_true(dfc_file_resize(&link.credential, long_file, D40_LONG_READ_SIZE));
    uint8_t* long_bytes = dfc_file_data(&link.credential, long_file);
    for(size_t index = 0; index < D40_LONG_READ_SIZE; index++) {
        long_bytes[index] = (uint8_t)(FileLong * 0x10 + index);
    }
    read_file(&link, FileLong, DFC_COMM_MAC, 0, D40_LONG_READ_SIZE);
    link_close(&link);
    return MUNIT_OK;
}

static DfcReaderStatus finish_d40_mac_command_response(
    Link* link,
    const DfcCommand* command,
    const uint8_t* response_data,
    size_t response_data_len,
    size_t* clear_len) {
    DfcReaderExchange exchange;
    DfcReaderOptions options = {.comm_mode = DFC_COMM_MAC};
    munit_assert_int(
        dfc_reader_exchange_begin(&exchange, &link->session, link->framing, command, &options),
        ==,
        DfcReaderOk);
    uint8_t request[DFC_COMMAND_MAX_APDU];
    size_t request_len = 0;
    munit_assert_int(
        dfc_reader_step(&exchange, NULL, 0, request, sizeof(request), &request_len),
        ==,
        DfcReaderPending);

    uint8_t response[16] = {0};
    munit_assert_size(response_data_len, <=, sizeof(response) - 2);
    memcpy(response, response_data, response_data_len);
    response[response_data_len] = 0x91;
    response[response_data_len + 1] = DFC_STATUS_OK;
    size_t ignored = 0;
    DfcReaderStatus status = dfc_reader_step(
        &exchange, response, response_data_len + 2, request, sizeof(request), &ignored);
    (void)dfc_reader_result_data(&exchange, clear_len);
    return status;
}

static DfcReaderStatus finish_d40_mac_response(
    Link* link,
    uint32_t requested_length,
    const uint8_t* response_data,
    size_t response_data_len,
    size_t* clear_len) {
    DfcCommand command;
    munit_assert_int(
        dfc_command_read_data(&command, FileMac, 0, requested_length), ==, DfcCommandOk);
    return finish_d40_mac_command_response(
        link, &command, response_data, response_data_len, clear_len);
}

static size_t generate_d40_mac_response(
    const Link* link,
    const uint8_t* plain,
    size_t plain_len,
    uint8_t* response,
    size_t response_capacity) {
    DfcSecureMessaging card = link->session.sm;
    card.pcd = false;
    return dfc_secure_messaging_generate_d40_response_mac(
        &card, plain, plain_len, response, response_capacity);
}

static MunitResult
    test_d40_reader_rejects_empty_mac_response(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    const uint8_t valid_empty_mac[DFC_SM_LEGACY_MAC_LENGTH] = {0};
    {
        Link link;
        link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
        select_app(&link, AID_D40);
        munit_assert_int(
            authenticate(&link, DFC_CMD_AUTHENTICATE_LEGACY, 0, DES_KEY_0, 16), ==, DfcReaderOk);
        size_t clear_len = SIZE_MAX;
        munit_assert_int(
            finish_d40_mac_response(&link, 0, valid_empty_mac, sizeof(valid_empty_mac), &clear_len),
            ==,
            DfcReaderOk);
        munit_assert_size(clear_len, ==, 0);
        munit_assert_true(dfc_reader_session_is_authenticated(&link.session));
        link_close(&link);
    }

    {
        Link link;
        link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
        select_app(&link, AID_D40);
        munit_assert_int(
            authenticate(&link, DFC_CMD_AUTHENTICATE_LEGACY, 0, DES_KEY_0, 16), ==, DfcReaderOk);
        size_t clear_len = SIZE_MAX;
        munit_assert_int(
            finish_d40_mac_response(&link, 1, valid_empty_mac, sizeof(valid_empty_mac), &clear_len),
            ==,
            DfcReaderProtocolError);
        munit_assert_size(clear_len, ==, 0);
        munit_assert_false(dfc_reader_session_is_authenticated(&link.session));
        link_close(&link);
    }

    const uint8_t nonempty[] = {0x5A};
    {
        Link link;
        link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
        select_app(&link, AID_D40);
        munit_assert_int(
            authenticate(&link, DFC_CMD_AUTHENTICATE_LEGACY, 0, DES_KEY_0, 16), ==, DfcReaderOk);
        uint8_t response[sizeof(nonempty) + DFC_SM_LEGACY_MAC_LENGTH];
        size_t response_len = generate_d40_mac_response(
            &link, nonempty, sizeof(nonempty), response, sizeof(response));
        size_t clear_len = SIZE_MAX;
        munit_assert_int(
            finish_d40_mac_response(&link, 1, response, response_len, &clear_len),
            ==,
            DfcReaderOk);
        munit_assert_size(clear_len, ==, sizeof(nonempty));
        munit_assert_true(dfc_reader_session_is_authenticated(&link.session));
        link_close(&link);
    }

    for(size_t mac_index = 0; mac_index < DFC_SM_LEGACY_MAC_LENGTH; mac_index++) {
        Link link;
        link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
        select_app(&link, AID_D40);
        munit_assert_int(
            authenticate(&link, DFC_CMD_AUTHENTICATE_LEGACY, 0, DES_KEY_0, 16), ==, DfcReaderOk);
        uint8_t response[sizeof(nonempty) + DFC_SM_LEGACY_MAC_LENGTH];
        size_t response_len = generate_d40_mac_response(
            &link, nonempty, sizeof(nonempty), response, sizeof(response));
        response[sizeof(nonempty) + mac_index] ^= 0x01;
        size_t clear_len = SIZE_MAX;
        munit_assert_int(
            finish_d40_mac_response(&link, 1, response, response_len, &clear_len),
            ==,
            DfcReaderIntegrityError);
        munit_assert_false(dfc_reader_session_is_authenticated(&link.session));
        link_close(&link);
    }

    for(size_t mac_index = 0; mac_index < sizeof(valid_empty_mac); mac_index++) {
        Link link;
        link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
        select_app(&link, AID_D40);
        munit_assert_int(
            authenticate(&link, DFC_CMD_AUTHENTICATE_LEGACY, 0, DES_KEY_0, 16), ==, DfcReaderOk);
        uint8_t invalid_mac[sizeof(valid_empty_mac)] = {0};
        invalid_mac[mac_index] = 1;
        size_t clear_len = SIZE_MAX;
        munit_assert_int(
            finish_d40_mac_response(&link, 1, invalid_mac, sizeof(invalid_mac), &clear_len),
            ==,
            DfcReaderProtocolError);
        munit_assert_false(dfc_reader_session_is_authenticated(&link.session));
        link_close(&link);
    }

    for(size_t truncated_len = 0; truncated_len < sizeof(valid_empty_mac); truncated_len++) {
        Link link;
        link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
        select_app(&link, AID_D40);
        munit_assert_int(
            authenticate(&link, DFC_CMD_AUTHENTICATE_LEGACY, 0, DES_KEY_0, 16), ==, DfcReaderOk);
        size_t clear_len = SIZE_MAX;
        munit_assert_int(
            finish_d40_mac_response(&link, 1, valid_empty_mac, truncated_len, &clear_len),
            ==,
            DfcReaderIntegrityError);
        munit_assert_false(dfc_reader_session_is_authenticated(&link.session));
        link_close(&link);
    }
    return MUNIT_OK;
}

static MunitResult test_d40_reader_rejects_empty_read_all_records_response(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;

    enum {
        RecordFile = 0x0E
    };
    const uint8_t empty_mac[DFC_SM_LEGACY_MAC_LENGTH] = {0};
    const bool iso_chaining_cases[] = {false, true};
    for(size_t i = 0; i < sizeof(iso_chaining_cases) / sizeof(iso_chaining_cases[0]); i++) {
        Link link;
        link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
        select_app(&link, AID_D40);
        munit_assert_int(
            authenticate(&link, DFC_CMD_AUTHENTICATE_LEGACY, 0, DES_KEY_0, 16), ==, DfcReaderOk);

        DfcCommand command;
        munit_assert_int(
            dfc_command_read_records(&command, RecordFile, 0, 0, iso_chaining_cases[i]),
            ==,
            DfcCommandOk);
        size_t clear_len = SIZE_MAX;
        munit_assert_int(
            finish_d40_mac_command_response(
                &link, &command, empty_mac, sizeof(empty_mac), &clear_len),
            ==,
            DfcReaderProtocolError);
        munit_assert_size(clear_len, ==, 0);
        munit_assert_false(dfc_reader_session_is_authenticated(&link.session));

        munit_assert_int(
            authenticate(&link, DFC_CMD_AUTHENTICATE_LEGACY, 0, DES_KEY_0, 16), ==, DfcReaderOk);
        const uint8_t record[] = {0x11, 0x22, 0x33, 0x44};
        uint8_t response[sizeof(record) + DFC_SM_LEGACY_MAC_LENGTH];
        size_t response_len =
            generate_d40_mac_response(&link, record, sizeof(record), response, sizeof(response));
        munit_assert_size(response_len, ==, sizeof(response));
        clear_len = SIZE_MAX;
        munit_assert_int(
            finish_d40_mac_command_response(&link, &command, response, response_len, &clear_len),
            ==,
            DfcReaderOk);
        munit_assert_size(clear_len, ==, sizeof(record));
        munit_assert_true(dfc_reader_session_is_authenticated(&link.session));
        link_close(&link);
    }
    return MUNIT_OK;
}

static MunitResult test_native_framing(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv1, DfcReaderFramingNative);
    select_app(&link, AID_AES);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, 16), ==, DfcReaderOk);
    read_file(&link, FileMac, DFC_COMM_MAC, 0, 32);
    write_then_read(&link, FileFull, DFC_COMM_ENCIPHERED);
    link_close(&link);
    return MUNIT_OK;
}

static MunitResult test_get_version_under_session(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);

    DfcCommand command;
    DfcReaderExchange ex;
    munit_assert_int(dfc_command_get_version(&command), ==, DfcCommandOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderOk);
    size_t plain_len = 0;
    const uint8_t* plain = dfc_reader_result_data(&ex, &plain_len);
    uint8_t expected[64];
    munit_assert_size(plain_len, <=, sizeof(expected));
    memcpy(expected, plain, plain_len);

    const struct {
        const uint8_t* aid;
        uint8_t auth_command;
        const uint8_t* key;
        size_t key_len;
    } cases[] = {
        {AID_D40, DFC_CMD_AUTHENTICATE_ISO, DES_KEY_0, 8},
        {AID_ISO, DFC_CMD_AUTHENTICATE_ISO, TDES_KEY_0, sizeof(TDES_KEY_0)},
        {AID_3K, DFC_CMD_AUTHENTICATE_ISO, TDES3_KEY_0, sizeof(TDES3_KEY_0)},
        {AID_AES, DFC_CMD_AUTHENTICATE_AES, AES_KEY_0, sizeof(AES_KEY_0)},
    };
    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        select_app(&link, cases[i].aid);
        munit_assert_int(
            authenticate(&link, cases[i].auth_command, 0, cases[i].key, cases[i].key_len),
            ==,
            DfcReaderOk);
        munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderOk);
        size_t secured_len = 0;
        const uint8_t* secured = dfc_reader_result_data(&ex, &secured_len);
        munit_assert_size(secured_len, ==, plain_len);
        munit_assert_memory_equal(plain_len, secured, expected);
        // A protected command after the chain proves both sides kept the same IV.
        read_file(&link, FileMac, DFC_COMM_MAC, 0, 8);
    }
    link_close(&link);
    return MUNIT_OK;
}

static MunitResult test_wrong_key_clears_session(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, 16), ==, DfcReaderOk);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_1, 16), ==, DfcReaderCardError);
    munit_assert_false(dfc_reader_session_is_authenticated(&link.session));
    munit_assert_not_null(link.picc->emulator->secure_messaging);
    munit_assert_false(dfc_emulator_native_authentication_active(link.picc->emulator));
    munit_assert_memory_equal(
        sizeof(*link.picc->emulator->secure_messaging),
        link.picc->emulator->secure_messaging,
        ((uint8_t[sizeof(*link.picc->emulator->secure_messaging)]){0}));
    link_close(&link);
    return MUNIT_OK;
}

static MunitResult test_change_key(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, 16), ==, DfcReaderOk);

    // Another key: the session carries on, chained from the cryptogram.
    const uint8_t new_key_1[16] = {
        0x5A,
        0x5A,
        0x5A,
        0x5A,
        0x5A,
        0x5A,
        0x5A,
        0x5A,
        0xA5,
        0xA5,
        0xA5,
        0xA5,
        0xA5,
        0xA5,
        0xA5,
        0xA5};
    uint8_t cryptogram[48];
    size_t cryptogram_len = 0;
    munit_assert_int(
        dfc_reader_change_key_cryptogram(
            &link.session,
            1,
            new_key_1,
            16,
            AES_KEY_1,
            true,
            0x07,
            cryptogram,
            sizeof(cryptogram),
            &cryptogram_len),
        ==,
        DfcReaderOk);
    DfcCommand command;
    DfcReaderExchange ex;
    munit_assert_int(
        dfc_command_change_key(&command, 1, cryptogram, cryptogram_len), ==, DfcCommandOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderOk);
    munit_assert_true(dfc_reader_session_is_authenticated(&link.session));
    read_file(&link, FileMac, DFC_COMM_MAC, 0, 8);

    // The authenticated key: the card ends the session.
    const uint8_t new_key_0[16] = {
        0x0F,
        0x0E,
        0x0D,
        0x0C,
        0x0B,
        0x0A,
        0x09,
        0x08,
        0x07,
        0x06,
        0x05,
        0x04,
        0x03,
        0x02,
        0x01,
        0x00};
    munit_assert_int(
        dfc_reader_change_key_cryptogram(
            &link.session,
            0,
            new_key_0,
            16,
            NULL,
            true,
            0x01,
            cryptogram,
            sizeof(cryptogram),
            &cryptogram_len),
        ==,
        DfcReaderOk);
    munit_assert_int(
        dfc_command_change_key(&command, 0, cryptogram, cryptogram_len), ==, DfcCommandOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderOk);
    munit_assert_false(dfc_reader_session_is_authenticated(&link.session));

    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 1, new_key_1, 16), ==, DfcReaderOk);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, new_key_0, 16), ==, DfcReaderOk);
    link_close(&link);
    return MUNIT_OK;
}

static MunitResult test_d40_change_key(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv1, DfcReaderFramingIso7816);
    select_app(&link, AID_D40);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_LEGACY, 0, DES_KEY_0, 16), ==, DfcReaderOk);
    const uint8_t new_key[16] = {
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        0xEE,
        0xF0,
        0x0F};
    uint8_t cryptogram[48];
    size_t cryptogram_len = 0;
    munit_assert_int(
        dfc_reader_change_key_cryptogram(
            &link.session,
            1,
            new_key,
            16,
            (const uint8_t[16]){0},
            false,
            0x00,
            cryptogram,
            sizeof(cryptogram),
            &cryptogram_len),
        ==,
        DfcReaderOk);
    DfcCommand command;
    DfcReaderExchange ex;
    munit_assert_int(
        dfc_command_change_key(&command, 1, cryptogram, cryptogram_len), ==, DfcCommandOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderOk);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_LEGACY, 1, new_key, 16), ==, DfcReaderOk);
    link_close(&link);
    return MUNIT_OK;
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING
static void assert_zero_bytes(const uint8_t* bytes, size_t len) {
    for(size_t i = 0; i < len; i++)
        munit_assert_uint8(bytes[i], ==, 0);
}

static void assert_ev2_emulator_session_wiped(const DfcEmulator* emulator) {
    munit_assert_false(emulator->ev2_response_plain);
    munit_assert_false(emulator->ev2_authentication_pending);
    munit_assert_false(emulator->ev2_authentication_non_first);
    munit_assert_false(emulator->ev2_session_active);
    munit_assert_uint8(emulator->ev2_authenticated_key_no, ==, 0);
    munit_assert_uint8(emulator->ev2_pending_authenticated_key_no, ==, 0);
    munit_assert_uint16(emulator->ev2_command_counter, ==, 0);
    assert_zero_bytes(
        emulator->pending_authentication.ev2.static_key,
        sizeof(emulator->pending_authentication.ev2.static_key));
    assert_zero_bytes(
        emulator->pending_authentication.ev2.random_b,
        sizeof(emulator->pending_authentication.ev2.random_b));
    assert_zero_bytes(
        emulator->ev2_transaction_identifier, sizeof(emulator->ev2_transaction_identifier));
    assert_zero_bytes(
        emulator->pending_authentication.ev2.transaction_identifier,
        sizeof(emulator->pending_authentication.ev2.transaction_identifier));
    assert_zero_bytes(emulator->ev2_card_capabilities, sizeof(emulator->ev2_card_capabilities));
    assert_zero_bytes(
        emulator->ev2_reader_capabilities, sizeof(emulator->ev2_reader_capabilities));
    assert_zero_bytes(
        emulator->pending_authentication.ev2.card_capabilities,
        sizeof(emulator->pending_authentication.ev2.card_capabilities));
    assert_zero_bytes(
        emulator->pending_authentication.ev2.reader_capabilities,
        sizeof(emulator->pending_authentication.ev2.reader_capabilities));
    assert_zero_bytes(
        emulator->ev2_session_encryption_key, sizeof(emulator->ev2_session_encryption_key));
    assert_zero_bytes(emulator->ev2_session_mac_key, sizeof(emulator->ev2_session_mac_key));
}

static size_t prepare_ev2_apdu(
    Link* link,
    const DfcCommand* command,
    uint8_t comm,
    DfcReaderExchange* exchange,
    uint8_t apdu[DFC_COMMAND_MAX_APDU]) {
    DfcReaderOptions options = {.comm_mode = comm};
    munit_assert_int(
        dfc_reader_exchange_begin(exchange, &link->session, link->framing, command, &options),
        ==,
        DfcReaderOk);
    size_t apdu_len = 0;
    munit_assert_int(
        dfc_reader_step(exchange, NULL, 0, apdu, DFC_COMMAND_MAX_APDU, &apdu_len),
        ==,
        DfcReaderPending);
    return apdu_len;
}

static void begin_open_transaction(Link* link, uint8_t backup_before[32]) {
    size_t app_index = link->picc->emulator->selected_app_index;
    DfcFile* backup = dfc_credential_find_file_in_app(&link->credential, app_index, FileFull);
    DfcFile* value = dfc_credential_find_file_in_app(&link->credential, app_index, FileValueFull);
    munit_assert_not_null(backup);
    munit_assert_not_null(value);
    backup->type = DFC_FILE_TYPE_BACKUP_DATA;
    memcpy(backup_before, dfc_file_data(&link->credential, backup), 32);
    dfc_credential_clear_dirty(&link->credential);

    const uint8_t replacement[] = {0xDE, 0xAD, 0xBE, 0xEF};
    DfcCommand command;
    DfcReaderExchange exchange;
    munit_assert_int(
        dfc_command_write_data(&command, FileFull, 0, replacement, sizeof(replacement)),
        ==,
        DfcCommandOk);
    munit_assert_int(link_send(link, &command, DFC_COMM_ENCIPHERED, &exchange), ==, DfcReaderOk);
    munit_assert_int(dfc_command_credit(&command, FileValueFull, 25), ==, DfcCommandOk);
    munit_assert_int(link_send(link, &command, DFC_COMM_ENCIPHERED, &exchange), ==, DfcReaderOk);

    DfcEmulator* emulator = link->picc->emulator;
    memset(&emulator->transaction_mac, 0xD4, sizeof(emulator->transaction_mac));
    emulator->transaction_mac.initialized = true;
    emulator->transaction_mac.has_pending = true;
    munit_assert_true(emulator->transaction_snapshot_active);
    munit_assert_true(backup->transaction_pending);
    munit_assert_true(value->state.value.pending);
    munit_assert_int32(value->state.value.pending_delta, ==, 25);
}

static void assert_transaction_aborted(Link* link, const uint8_t backup_before[32]) {
    const DfcEmulator* emulator = link->picc->emulator;
    size_t app_index = emulator->selected_app_index;
    const DfcFile* backup =
        dfc_credential_find_file_in_app(&link->credential, app_index, FileFull);
    const DfcFile* value =
        dfc_credential_find_file_in_app(&link->credential, app_index, FileValueFull);
    munit_assert_false(emulator->transaction_snapshot_active);
    munit_assert_null(emulator->transaction_snapshot_pool);
    munit_assert_false(backup->transaction_pending);
    munit_assert_memory_equal(32, dfc_file_data_const(&link->credential, backup), backup_before);
    munit_assert_false(value->state.value.pending);
    munit_assert_int32(value->state.value.pending_delta, ==, 0);
    assert_zero_bytes(
        (const uint8_t*)&emulator->transaction_mac, sizeof(emulator->transaction_mac));
    munit_assert_false(link->credential.dirty);
}

static void assert_plain_native_status(
    DfcReaderFraming framing,
    const uint8_t* response,
    size_t response_len,
    uint8_t expected_status) {
    if(framing == DfcReaderFramingIso7816) {
        munit_assert_size(response_len, ==, 2);
        munit_assert_memory_equal(response_len, response, ((uint8_t[]){0x91, expected_status}));
    } else {
        munit_assert_size(response_len, ==, 1);
        munit_assert_uint8(response[0], ==, expected_status);
    }
}

static void assert_native_session_wiped(const DfcEmulator* emulator) {
    munit_assert_false(dfc_emulator_native_authentication_active(emulator));
    munit_assert_uint8(emulator->auth_cipher, ==, 0);
    munit_assert_uint8(emulator->auth_key_no, ==, 0);
    munit_assert_not_null(emulator->secure_messaging);
    munit_assert_memory_equal(
        sizeof(*emulator->secure_messaging),
        emulator->secure_messaging,
        ((uint8_t[sizeof(*emulator->secure_messaging)]){0}));
}

static MunitResult
    test_authenticated_errors_are_plain_terminal(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    enum {
        AuthEv1Aes,
        AuthEv1Iso,
#if DFC_ENABLE_EV2_SECURE_MESSAGING
        AuthEv2,
#endif
    };
    static const unsigned auth_cases[] = {
        AuthEv1Aes,
        AuthEv1Iso,
#if DFC_ENABLE_EV2_SECURE_MESSAGING
        AuthEv2,
#endif
    };
    static const DfcReaderFraming framings[] = {
        DfcReaderFramingNative,
        DfcReaderFramingIso7816,
    };

    for(size_t framing_index = 0; framing_index < sizeof(framings) / sizeof(framings[0]);
        framing_index++) {
        for(size_t auth_index = 0; auth_index < sizeof(auth_cases) / sizeof(auth_cases[0]);
            auth_index++) {
            static Link link;
            DfcReaderFraming framing = framings[framing_index];
            unsigned auth = auth_cases[auth_index];
            link_open(&link, DfcGenerationEv2, framing);

            uint8_t comm = DFC_COMM_MAC;
            select_app(&link, auth == AuthEv1Iso ? AID_ISO : AID_AES);
            if(auth == AuthEv1Iso) {
                munit_assert_int(
                    authenticate(
                        &link, DFC_CMD_AUTHENTICATE_ISO, 0, TDES_KEY_0, sizeof(TDES_KEY_0)),
                    ==,
                    DfcReaderOk);
            } else if(auth == AuthEv1Aes) {
                munit_assert_int(
                    authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, sizeof(AES_KEY_0)),
                    ==,
                    DfcReaderOk);
#if DFC_ENABLE_EV2_SECURE_MESSAGING
            } else {
                munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);
#endif
            }

            uint8_t backup_before[32];
            begin_open_transaction(&link, backup_before);

            DfcCommand command;
            DfcReaderExchange exchange;
            munit_assert_int(dfc_command_read_data(&command, 0x1E, 0, 1), ==, DfcCommandOk);
            DfcReaderOptions options = {.comm_mode = comm};
            munit_assert_int(
                dfc_reader_exchange_begin(&exchange, &link.session, framing, &command, &options),
                ==,
                DfcReaderOk);
            uint8_t apdu[DFC_COMMAND_MAX_APDU];
            size_t apdu_len = 0;
            munit_assert_int(
                dfc_reader_step(&exchange, NULL, 0, apdu, sizeof(apdu), &apdu_len),
                ==,
                DfcReaderPending);

            uint8_t response[16];
            memset(response, 0xA5, sizeof(response));
            size_t response_len = SIZE_MAX;
            size_t exact_capacity = framing == DfcReaderFramingIso7816 ? 2 : 1;
            munit_assert_int(
                dfc_virtual_picc_iso_dep_exchange(
                    link.picc, apdu, apdu_len, response, exact_capacity - 1, &response_len),
                ==,
                DfcVirtualPiccStatusBufferTooSmall);
            munit_assert_size(response_len, ==, 0);
            munit_assert_uint8(response[0], ==, 0xA5);
            assert_transaction_aborted(&link, backup_before);
#if DFC_ENABLE_EV2_SECURE_MESSAGING
            if(auth == AuthEv2) {
                assert_ev2_emulator_session_wiped(link.picc->emulator);
            } else
#endif
            {
                assert_native_session_wiped(link.picc->emulator);
            }

            DfcEmulator emulator_after_error = *link.picc->emulator;
            response_len = SIZE_MAX;
            munit_assert_int(
                dfc_virtual_picc_iso_dep_exchange(
                    link.picc, apdu, apdu_len, response, exact_capacity, &response_len),
                ==,
                DfcVirtualPiccStatusOk);
            assert_plain_native_status(framing, response, response_len, DFC_STATUS_FILE_NOT_FOUND);
            munit_assert_memory_equal(
                sizeof(emulator_after_error), &emulator_after_error, link.picc->emulator);

            uint8_t ignored_output[DFC_COMMAND_MAX_APDU];
            size_t ignored = SIZE_MAX;
            munit_assert_int(
                dfc_reader_step(
                    &exchange,
                    response,
                    response_len,
                    ignored_output,
                    sizeof(ignored_output),
                    &ignored),
                ==,
                DfcReaderCardError);
            munit_assert_size(ignored, ==, 0);
            munit_assert_uint8(dfc_reader_result_status(&exchange), ==, DFC_STATUS_FILE_NOT_FOUND);
            munit_assert_false(dfc_reader_session_is_authenticated(&link.session));
            link_close(&link);
        }
    }

    static Link legacy;
    link_open(&legacy, DfcGenerationEv2, DfcReaderFramingNative);
    select_app(&legacy, AID_D40);
    munit_assert_int(
        authenticate(&legacy, DFC_CMD_AUTHENTICATE_LEGACY, 0, DES_KEY_0, sizeof(DES_KEY_0)),
        ==,
        DfcReaderOk);
    DfcCommand command;
    DfcReaderExchange exchange;
    munit_assert_int(dfc_command_read_data(&command, 0x1E, 0, 1), ==, DfcCommandOk);
    munit_assert_int(
        link_send(&legacy, &command, DFC_COMM_PLAIN, &exchange), ==, DfcReaderCardError);
    munit_assert_true(dfc_reader_session_is_authenticated(&legacy.session));
    munit_assert_true(dfc_emulator_native_authentication_active(legacy.picc->emulator));
    munit_assert_uint8(
        legacy.picc->emulator->secure_messaging->cipher, ==, DFC_CMD_AUTHENTICATE_LEGACY);
    read_file(&legacy, FilePlain, DFC_COMM_PLAIN, 0, 1);
    link_close(&legacy);
    return MUNIT_OK;
}

static MunitResult test_interrupted_authenticated_chains_are_plain_terminal(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    enum {
        AuthEv1Aes,
        AuthEv1Iso,
#if DFC_ENABLE_EV2_SECURE_MESSAGING
        AuthEv2,
#endif
    };
    static const unsigned auth_cases[] = {
        AuthEv1Aes,
        AuthEv1Iso,
#if DFC_ENABLE_EV2_SECURE_MESSAGING
        AuthEv2,
#endif
    };
    static const DfcReaderFraming framings[] = {
        DfcReaderFramingNative,
        DfcReaderFramingIso7816,
    };

    for(size_t framing_index = 0; framing_index < sizeof(framings) / sizeof(framings[0]);
        framing_index++) {
        for(size_t auth_index = 0; auth_index < sizeof(auth_cases) / sizeof(auth_cases[0]);
            auth_index++) {
            static Link link;
            DfcReaderFraming framing = framings[framing_index];
            unsigned auth = auth_cases[auth_index];
            bool is_ev2 = false;
#if DFC_ENABLE_EV2_SECURE_MESSAGING
            is_ev2 = auth == AuthEv2;
#endif
            link_open(&link, DfcGenerationEv2, framing);
            select_app(&link, auth == AuthEv1Iso ? AID_ISO : AID_AES);
            if(auth == AuthEv1Iso) {
                munit_assert_int(
                    authenticate(
                        &link, DFC_CMD_AUTHENTICATE_ISO, 0, TDES_KEY_0, sizeof(TDES_KEY_0)),
                    ==,
                    DfcReaderOk);
            } else if(auth == AuthEv1Aes) {
                munit_assert_int(
                    authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, sizeof(AES_KEY_0)),
                    ==,
                    DfcReaderOk);
#if DFC_ENABLE_EV2_SECURE_MESSAGING
            } else {
                munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);
#endif
            }

            uint8_t backup_before[32];
            begin_open_transaction(&link, backup_before);

            DfcCommand version;
            DfcReaderExchange version_exchange;
            DfcReaderOptions plain = {
                .comm_mode = is_ev2 ? DFC_COMM_MAC : DFC_COMM_PLAIN,
            };
            munit_assert_int(dfc_command_get_version(&version), ==, DfcCommandOk);
            munit_assert_int(
                dfc_reader_exchange_begin(
                    &version_exchange, &link.session, framing, &version, &plain),
                ==,
                DfcReaderOk);
            uint8_t version_apdu[DFC_COMMAND_MAX_APDU];
            size_t version_apdu_len = 0;
            munit_assert_int(
                dfc_reader_step(
                    &version_exchange,
                    NULL,
                    0,
                    version_apdu,
                    sizeof(version_apdu),
                    &version_apdu_len),
                ==,
                DfcReaderPending);
            uint8_t response[64];
            size_t response_len = 0;
            munit_assert_int(
                dfc_virtual_picc_iso_dep_exchange(
                    link.picc,
                    version_apdu,
                    version_apdu_len,
                    response,
                    sizeof(response),
                    &response_len),
                ==,
                DfcVirtualPiccStatusOk);
            munit_assert_size(response_len, >, framing == DfcReaderFramingIso7816 ? 2 : 1);
            munit_assert_true(dfc_reader_session_is_authenticated(&link.session));
#if DFC_ENABLE_EV2_SECURE_MESSAGING
            if(is_ev2) {
                munit_assert_true(link.picc->emulator->ev2_session_active);
            } else
#endif
            {
                munit_assert_true(dfc_emulator_native_authentication_active(link.picc->emulator));
            }

#if DFC_ENABLE_EV2_SECURE_MESSAGING
            if(is_ev2) {
                size_t status_tail = framing == DfcReaderFramingIso7816 ? 2 : 0;
                size_t status_head = framing == DfcReaderFramingNative ? 1 : 0;
                size_t body_len = response_len - status_head - status_tail;
                munit_assert_size(body_len, >=, DFC_WIRE_MAC_LENGTH);
                size_t clear_len = body_len - DFC_WIRE_MAC_LENGTH;
                const uint8_t* body = response + status_head;
                uint16_t next = (uint16_t)(link.session.ev2_command_counter + 1);
                uint8_t expected_mac[DFC_WIRE_MAC_LENGTH];
                munit_assert_true(dfc_ev2_mac(
                    link.session.ev2_mac_key,
                    DFC_CMD_ADDITIONAL_FRAME,
                    next,
                    link.session.ev2_transaction_identifier,
                    body,
                    clear_len,
                    NULL,
                    0,
                    expected_mac));
                munit_assert_memory_equal(sizeof(expected_mac), body + clear_len, expected_mac);
                link.session.ev2_command_counter = next;
            } else
#endif
            {
                uint8_t continuation[DFC_COMMAND_MAX_APDU];
                size_t continuation_len = 0;
                munit_assert_int(
                    dfc_reader_step(
                        &version_exchange,
                        response,
                        response_len,
                        continuation,
                        sizeof(continuation),
                        &continuation_len),
                    ==,
                    DfcReaderPending);
                munit_assert_size(continuation_len, >, 0);
            }
            munit_assert_true(dfc_reader_session_is_authenticated(&link.session));

            DfcCommand read;
            DfcReaderExchange read_exchange;
            munit_assert_int(dfc_command_read_data(&read, FileMac, 0, 1), ==, DfcCommandOk);
            DfcReaderOptions read_options = {
                .comm_mode = is_ev2 ? DFC_COMM_MAC : DFC_COMM_PLAIN,
            };
            munit_assert_int(
                dfc_reader_exchange_begin(
                    &read_exchange, &link.session, framing, &read, &read_options),
                ==,
                DfcReaderOk);
            uint8_t read_apdu[DFC_COMMAND_MAX_APDU];
            size_t read_apdu_len = 0;
            munit_assert_int(
                dfc_reader_step(
                    &read_exchange, NULL, 0, read_apdu, sizeof(read_apdu), &read_apdu_len),
                ==,
                DfcReaderPending);

            size_t exact_capacity = framing == DfcReaderFramingIso7816 ? 2 : 1;
            memset(response, 0xA5, sizeof(response));
            response_len = SIZE_MAX;
            munit_assert_int(
                dfc_virtual_picc_iso_dep_exchange(
                    link.picc,
                    read_apdu,
                    read_apdu_len,
                    response,
                    exact_capacity - 1,
                    &response_len),
                ==,
                DfcVirtualPiccStatusBufferTooSmall);
            munit_assert_size(response_len, ==, 0);
            munit_assert_uint8(response[0], ==, 0xA5);
            assert_transaction_aborted(&link, backup_before);
#if DFC_ENABLE_EV2_SECURE_MESSAGING
            if(is_ev2) {
                assert_ev2_emulator_session_wiped(link.picc->emulator);
            } else
#endif
            {
                assert_native_session_wiped(link.picc->emulator);
            }

            DfcEmulator emulator_after_error = *link.picc->emulator;
            response_len = SIZE_MAX;
            munit_assert_int(
                dfc_virtual_picc_iso_dep_exchange(
                    link.picc, read_apdu, read_apdu_len, response, exact_capacity, &response_len),
                ==,
                DfcVirtualPiccStatusOk);
            assert_plain_native_status(
                framing, response, response_len, DFC_STATUS_COMMAND_ABORTED);
            munit_assert_memory_equal(
                sizeof(emulator_after_error), &emulator_after_error, link.picc->emulator);

            uint8_t ignored_output[DFC_COMMAND_MAX_APDU];
            size_t ignored = SIZE_MAX;
            munit_assert_int(
                dfc_reader_step(
                    &read_exchange,
                    response,
                    response_len,
                    ignored_output,
                    sizeof(ignored_output),
                    &ignored),
                ==,
                DfcReaderCardError);
            munit_assert_size(ignored, ==, 0);
            munit_assert_uint8(
                dfc_reader_result_status(&read_exchange), ==, DFC_STATUS_COMMAND_ABORTED);
            munit_assert_false(dfc_reader_session_is_authenticated(&link.session));
            link_close(&link);
        }
    }

    static Link legacy;
    link_open(&legacy, DfcGenerationEv2, DfcReaderFramingIso7816);
    select_app(&legacy, AID_D40);
    munit_assert_int(
        authenticate(&legacy, DFC_CMD_AUTHENTICATE_LEGACY, 0, DES_KEY_0, sizeof(DES_KEY_0)),
        ==,
        DfcReaderOk);
    uint8_t backup_before[32];
    begin_open_transaction(&legacy, backup_before);

    DfcCommand version;
    DfcReaderExchange version_exchange;
    DfcReaderOptions plain = {.comm_mode = DFC_COMM_PLAIN};
    munit_assert_int(dfc_command_get_version(&version), ==, DfcCommandOk);
    munit_assert_int(
        dfc_reader_exchange_begin(
            &version_exchange, &legacy.session, legacy.framing, &version, &plain),
        ==,
        DfcReaderOk);
    uint8_t version_apdu[DFC_COMMAND_MAX_APDU];
    size_t version_apdu_len = 0;
    munit_assert_int(
        dfc_reader_step(
            &version_exchange, NULL, 0, version_apdu, sizeof(version_apdu), &version_apdu_len),
        ==,
        DfcReaderPending);
    uint8_t response[64];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            legacy.picc, version_apdu, version_apdu_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    uint8_t continuation[DFC_COMMAND_MAX_APDU];
    size_t continuation_len = 0;
    munit_assert_int(
        dfc_reader_step(
            &version_exchange,
            response,
            response_len,
            continuation,
            sizeof(continuation),
            &continuation_len),
        ==,
        DfcReaderPending);

    DfcCommand read;
    DfcReaderExchange read_exchange;
    munit_assert_int(dfc_command_read_data(&read, FilePlain, 0, 1), ==, DfcCommandOk);
    munit_assert_int(
        dfc_reader_exchange_begin(&read_exchange, &legacy.session, legacy.framing, &read, &plain),
        ==,
        DfcReaderOk);
    uint8_t read_apdu[DFC_COMMAND_MAX_APDU];
    size_t read_apdu_len = 0;
    munit_assert_int(
        dfc_reader_step(&read_exchange, NULL, 0, read_apdu, sizeof(read_apdu), &read_apdu_len),
        ==,
        DfcReaderPending);
    response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            legacy.picc, read_apdu, read_apdu_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    assert_plain_native_status(legacy.framing, response, response_len, DFC_STATUS_COMMAND_ABORTED);
    assert_transaction_aborted(&legacy, backup_before);
    munit_assert_true(dfc_emulator_native_authentication_active(legacy.picc->emulator));

    uint8_t ignored_output[DFC_COMMAND_MAX_APDU];
    size_t ignored = SIZE_MAX;
    munit_assert_int(
        dfc_reader_step(
            &read_exchange,
            response,
            response_len,
            ignored_output,
            sizeof(ignored_output),
            &ignored),
        ==,
        DfcReaderCardError);
    munit_assert_size(ignored, ==, 0);
    munit_assert_true(dfc_reader_session_is_authenticated(&legacy.session));
    read_file(&legacy, FilePlain, DFC_COMM_PLAIN, 0, 1);
    link_close(&legacy);
    return MUNIT_OK;
}

static MunitResult
    test_reader_rejects_protected_terminal_errors(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static const DfcReaderFraming framings[] = {
        DfcReaderFramingNative,
        DfcReaderFramingIso7816,
    };

    for(size_t i = 0; i < sizeof(framings) / sizeof(framings[0]); i++) {
        static Link link;
        DfcReaderFraming framing = framings[i];
        link_open(&link, DfcGenerationEv2, framing);
        select_app(&link, AID_AES);
        munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);

        DfcCommand command;
        DfcReaderExchange exchange;
        munit_assert_int(dfc_command_read_data(&command, FileMac, 0, 1), ==, DfcCommandOk);
        DfcReaderOptions options = {.comm_mode = DFC_COMM_MAC};
        munit_assert_int(
            dfc_reader_exchange_begin(&exchange, &link.session, framing, &command, &options),
            ==,
            DfcReaderOk);
        uint8_t command_apdu[DFC_COMMAND_MAX_APDU];
        size_t command_apdu_len = 0;
        munit_assert_int(
            dfc_reader_step(
                &exchange, NULL, 0, command_apdu, sizeof(command_apdu), &command_apdu_len),
            ==,
            DfcReaderPending);
        munit_assert_size(command_apdu_len, >, 0);

        uint8_t mac[DFC_WIRE_MAC_LENGTH];
        munit_assert_true(dfc_ev2_mac(
            link.session.ev2_mac_key,
            DFC_STATUS_FILE_NOT_FOUND,
            (uint16_t)(link.session.ev2_command_counter + 1),
            link.session.ev2_transaction_identifier,
            NULL,
            0,
            NULL,
            0,
            mac));
        uint8_t response[DFC_WIRE_MAC_LENGTH + DFC_ISO7816_STATUS_WORD_LENGTH];
        size_t response_len;
        if(framing == DfcReaderFramingIso7816) {
            memcpy(response, mac, sizeof(mac));
            response[sizeof(mac)] = 0x91;
            response[sizeof(mac) + 1] = DFC_STATUS_FILE_NOT_FOUND;
            response_len = sizeof(mac) + DFC_ISO7816_STATUS_WORD_LENGTH;
        } else {
            response[0] = DFC_STATUS_FILE_NOT_FOUND;
            memcpy(response + 1, mac, sizeof(mac));
            response_len = 1 + sizeof(mac);
        }

        uint8_t ignored_output[DFC_COMMAND_MAX_APDU];
        size_t ignored = SIZE_MAX;
        munit_assert_int(
            dfc_reader_step(
                &exchange, response, response_len, ignored_output, sizeof(ignored_output), &ignored),
            ==,
            DfcReaderProtocolError);
        munit_assert_size(ignored, ==, 0);
        munit_assert_false(dfc_reader_session_is_authenticated(&link.session));
        link_close(&link);
    }
    return MUNIT_OK;
}

static MunitResult
    test_ev2_invalid_command_is_plain_terminal(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);

    uint8_t backup_before[32];
    begin_open_transaction(&link, backup_before);

    DfcCommand command;
    DfcReaderExchange exchange;
    uint8_t valid_apdu[DFC_COMMAND_MAX_APDU];
    munit_assert_int(dfc_command_read_data(&command, FileMac, 0, 1), ==, DfcCommandOk);
    size_t apdu_len = prepare_ev2_apdu(&link, &command, DFC_COMM_MAC, &exchange, valid_apdu);
    munit_assert_size(apdu_len, >=, 2);
    uint8_t bad_apdu[DFC_COMMAND_MAX_APDU];
    memcpy(bad_apdu, valid_apdu, apdu_len);
    bad_apdu[apdu_len - 2] ^= 0x80;

    uint8_t response[64];
    memset(response, 0xA5, sizeof(response));
    size_t response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, bad_apdu, apdu_len, response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_uint8(response[0], ==, 0xA5);
    assert_transaction_aborted(&link, backup_before);
    assert_ev2_emulator_session_wiped(link.picc->emulator);

    response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, bad_apdu, apdu_len, response, 2, &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(
        response_len, response, ((uint8_t[]){0x91, DFC_STATUS_INTEGRITY_ERROR}));
    assert_transaction_aborted(&link, backup_before);
    assert_ev2_emulator_session_wiped(link.picc->emulator);

    response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, valid_apdu, apdu_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_uint8(response[0], ==, 0x91);
    munit_assert_uint8(response[1], !=, DFC_STATUS_OK);
    assert_ev2_emulator_session_wiped(link.picc->emulator);

    link_close(&link);
    return MUNIT_OK;
}

static MunitResult
    test_ev2_invalid_full_command_is_plain_terminal(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);

    uint8_t backup_before[32];
    begin_open_transaction(&link, backup_before);

    const uint8_t new_key[DFC_AES_KEY_LENGTH] = {0x71};
    DfcCommand command;
    munit_assert_int(
        dfc_reader_change_key_ev2_command(&link.session, 0, 1, new_key, AES_KEY_1, 0x09, &command),
        ==,
        DfcReaderOk);

    DfcReaderExchange exchange;
    uint8_t apdu[DFC_COMMAND_MAX_APDU];
    size_t apdu_len = prepare_ev2_apdu(&link, &command, DFC_COMM_PLAIN, &exchange, apdu);
    size_t secured_len = apdu[4] - DFC_WIRE_MAC_LENGTH;
    size_t encrypted_header_len = DFC_CHANGE_KEY_EV2_HEADER_LENGTH - 1;
    size_t encrypted_len = secured_len - encrypted_header_len;
    munit_assert_size(encrypted_len, >=, 2 * DFC_AES_KEY_LENGTH);
    apdu[5 + encrypted_header_len + encrypted_len - DFC_AES_KEY_LENGTH - 1] ^= 0x01;
    uint8_t mac[DFC_WIRE_MAC_LENGTH];
    munit_assert_true(dfc_ev2_mac(
        link.session.ev2_mac_key,
        apdu[1],
        link.session.ev2_command_counter,
        link.session.ev2_transaction_identifier,
        apdu + 5,
        secured_len,
        NULL,
        0,
        mac));
    memcpy(apdu + 5 + secured_len, mac, sizeof(mac));
    uint8_t response[64];
    memset(response, 0xA5, sizeof(response));
    size_t response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(link.picc, apdu, apdu_len, response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_uint8(response[0], ==, 0xA5);
    assert_transaction_aborted(&link, backup_before);
    assert_ev2_emulator_session_wiped(link.picc->emulator);

    response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(link.picc, apdu, apdu_len, response, 2, &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(
        response_len, response, ((uint8_t[]){0x91, DFC_STATUS_INTEGRITY_ERROR}));
    assert_transaction_aborted(&link, backup_before);
    assert_ev2_emulator_session_wiped(link.picc->emulator);

    response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, apdu, apdu_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_uint8(response[0], ==, 0x91);
    munit_assert_uint8(response[1], !=, DFC_STATUS_OK);
    assert_ev2_emulator_session_wiped(link.picc->emulator);

    link_close(&link);
    return MUNIT_OK;
}

static MunitResult
    test_ev2_full_read_errors_are_plain_terminal(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    enum {
        FullReadData,
        FullReadRecords,
        FullGetValue,
    };
    const unsigned cases[] = {FullReadData, FullReadRecords, FullGetValue};
    const uint8_t expected_statuses[] = {
        DFC_STATUS_BOUNDARY_ERROR,
        DFC_STATUS_BOUNDARY_ERROR,
        DFC_STATUS_PERMISSION_DENIED,
    };

    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        static Link link;
        link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
        if(cases[i] == FullReadRecords) {
            DfcFile* record = dfc_credential_create_file(&link.credential, 0, FileRecordFull);
            munit_assert_not_null(record);
            record->type = DFC_FILE_TYPE_LINEAR_RECORD;
            record->comm_settings = DFC_COMM_ENCIPHERED;
            record->access_rights = 0x0000;
            record->state.record.size = 4;
            record->state.record.max_records = 1;
            record->state.record.count = 1;
            munit_assert_true(
                dfc_file_resize(&link.credential, record, record->state.record.size));
        }
        select_app(&link, AID_AES);
        munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);

        uint8_t backup_before[32];
        begin_open_transaction(&link, backup_before);

        DfcCommand command;
        if(cases[i] == FullReadData) {
            munit_assert_int(dfc_command_read_data(&command, FileFull, 32, 1), ==, DfcCommandOk);
        } else if(cases[i] == FullReadRecords) {
            munit_assert_int(
                dfc_command_read_records(&command, FileRecordFull, 1, 1, false), ==, DfcCommandOk);
        } else {
            DfcFile* value = dfc_credential_find_file_in_app(&link.credential, 0, FileValueFull);
            munit_assert_not_null(value);
            value->access_rights = 0xFFFF;
            munit_assert_int(dfc_command_get_value(&command, FileValueFull), ==, DfcCommandOk);
        }

        DfcReaderExchange exchange;
        uint8_t apdu[DFC_COMMAND_MAX_APDU];
        size_t apdu_len = prepare_ev2_apdu(&link, &command, DFC_COMM_ENCIPHERED, &exchange, apdu);
        uint8_t response[16];
        memset(response, 0xA5, sizeof(response));
        size_t response_len = SIZE_MAX;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link.picc, apdu, apdu_len, response, 1, &response_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        munit_assert_size(response_len, ==, 0);
        munit_assert_uint8(response[0], ==, 0xA5);
        assert_transaction_aborted(&link, backup_before);
        assert_ev2_emulator_session_wiped(link.picc->emulator);

        response_len = SIZE_MAX;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link.picc, apdu, apdu_len, response, 2, &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(response_len, ==, 2);
        munit_assert_memory_equal(
            response_len, response, ((uint8_t[]){0x91, expected_statuses[i]}));

        response_len = 0;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link.picc, apdu, apdu_len, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(response_len, ==, 2);
        munit_assert_uint8(response[0], ==, 0x91);
        munit_assert_uint8(response[1], !=, DFC_STATUS_OK);
        assert_ev2_emulator_session_wiped(link.picc->emulator);

        link_close(&link);
    }
    return MUNIT_OK;
}

static void assert_get_card_uid(Link* link) {
    DfcCommand command;
    DfcReaderExchange exchange;
    munit_assert_int(dfc_command_get_card_uid(&command), ==, DfcCommandOk);
    // GetCardUID chooses Full response protection itself. Callers do not need
    // to duplicate that rule in the per-command options.
    DfcReaderOptions options = {.comm_mode = DFC_COMM_PLAIN};
    munit_assert_int(
        dfc_reader_exchange_begin(&exchange, &link->session, link->framing, &command, &options),
        ==,
        DfcReaderOk);

    uint8_t request[DFC_COMMAND_MAX_APDU];
    size_t request_len = 0;
    munit_assert_int(
        dfc_reader_step(&exchange, NULL, 0, request, sizeof(request), &request_len),
        ==,
        DfcReaderPending);
    uint8_t response[64];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link->picc, request, request_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    for(size_t offset = 0; offset + link->credential.uid_len <= response_len; offset++) {
        munit_assert_int(
            memcmp(response + offset, link->credential.uid, link->credential.uid_len), !=, 0);
    }

    // A damaged ciphertext must not publish even a partial result, and must
    // retire the reader-side copy of the session.
    DfcReaderSession corrupt_session = link->session;
    DfcReaderExchange corrupt_exchange = exchange;
    corrupt_exchange.session = &corrupt_session;
    uint8_t corrupt_response[sizeof(response)];
    memcpy(corrupt_response, response, response_len);
    corrupt_response[0] ^= 0x01;
    size_t ignored_len = 0;
    munit_assert_int(
        dfc_reader_step(
            &corrupt_exchange,
            corrupt_response,
            response_len,
            request,
            sizeof(request),
            &ignored_len),
        ==,
        DfcReaderIntegrityError);
    munit_assert_size(ignored_len, ==, 0);
    munit_assert_false(dfc_reader_session_is_authenticated(&corrupt_session));

    munit_assert_int(
        dfc_reader_step(&exchange, response, response_len, request, sizeof(request), &request_len),
        ==,
        DfcReaderOk);

    size_t uid_len = 0;
    const uint8_t* uid = dfc_reader_result_data(&exchange, &uid_len);
    munit_assert_size(uid_len, ==, link->credential.uid_len);
    munit_assert_memory_equal(uid_len, uid, link->credential.uid);
}

static void assert_malformed_get_card_uid_session(Link* link, bool retires_session) {
    const uint8_t unexpected_data = 0x00;
    DfcCommand command;
    DfcReaderExchange exchange;
    munit_assert_int(
        dfc_command_encode_raw(
            &command, DFC_CMD_GET_CARD_UID, &unexpected_data, sizeof(unexpected_data)),
        ==,
        DfcCommandOk);
    munit_assert_int(link_send(link, &command, DFC_COMM_PLAIN, &exchange), ==, DfcReaderCardError);
    munit_assert_uint8(dfc_reader_result_status(&exchange), ==, DFC_STATUS_LENGTH_ERROR);
    size_t response_len = SIZE_MAX;
    (void)dfc_reader_result_data(&exchange, &response_len);
    munit_assert_size(response_len, ==, 0);
    munit_assert_int(dfc_reader_session_is_authenticated(&link->session), ==, !retires_session);
}

static MunitResult
    test_get_card_uid_uses_full_response_protection(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;

    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 1, AES_KEY_1, sizeof(AES_KEY_1)),
        ==,
        DfcReaderOk);
    assert_get_card_uid(&link);
    assert_malformed_get_card_uid_session(&link, true);
    link_close(&link);

    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    select_app(&link, AID_ISO);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_ISO, 0, TDES_KEY_0, sizeof(TDES_KEY_0)),
        ==,
        DfcReaderOk);
    assert_get_card_uid(&link);
    assert_malformed_get_card_uid_session(&link, true);
    link_close(&link);

    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    select_app(&link, AID_D40);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_LEGACY, 0, DES_KEY_0, sizeof(DES_KEY_0)),
        ==,
        DfcReaderOk);
    assert_get_card_uid(&link);
    assert_malformed_get_card_uid_session(&link, false);
    link_close(&link);

#if DFC_ENABLE_EV2_SECURE_MESSAGING
    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    munit_assert_int(authenticate_ev2(&link, true, 1, AES_KEY_1), ==, DfcReaderOk);
    assert_get_card_uid(&link);
    munit_assert_uint16(link.session.ev2_command_counter, ==, 1);
    munit_assert_uint16(link.picc->emulator->ev2_command_counter, ==, 1);
    assert_malformed_get_card_uid_session(&link, true);
    link_close(&link);
#endif

    return MUNIT_OK;
}

static MunitResult test_ev2_session(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);
    munit_assert_uint8(link.session.auth_mode, ==, DFC_READER_AUTH_EV2);
    munit_assert_uint16(link.session.ev2_command_counter, ==, 0);

    read_file(&link, FilePlain, DFC_COMM_PLAIN, 0, 32);
    munit_assert_uint16(link.session.ev2_command_counter, ==, 1);
    read_file(&link, FileMac, DFC_COMM_MAC, 0, 32);
    munit_assert_uint16(link.session.ev2_command_counter, ==, 2);
    read_file(&link, FileFull, DFC_COMM_ENCIPHERED, 0, 32);
    write_then_read(&link, FileMac, DFC_COMM_MAC);
    write_then_read(&link, FileFull, DFC_COMM_ENCIPHERED);
    credit_and_commit(&link, FileValueMac, DFC_COMM_MAC);
    credit_and_commit(&link, FileValueFull, DFC_COMM_ENCIPHERED);

    uint8_t transaction[4];
    memcpy(transaction, link.session.ev2_transaction_identifier, sizeof(transaction));
    munit_assert_uint16(link.session.ev2_command_counter, >, 2);
    // Key 1 opens a session but the files name key 0, so the refusal retires
    // the session.
    munit_assert_int(authenticate_ev2(&link, false, 1, AES_KEY_1), ==, DfcReaderOk);
    munit_assert_memory_equal(
        sizeof(transaction), link.session.ev2_transaction_identifier, transaction);
    munit_assert_uint16(link.session.ev2_command_counter, ==, 0);
    munit_assert_uint16(link.picc->emulator->ev2_command_counter, ==, 0);
    DfcCommand command;
    DfcReaderExchange ex;
    munit_assert_int(dfc_command_read_data(&command, FileMac, 0, 16), ==, DfcCommandOk);
    DfcReaderOptions options = {.comm_mode = DFC_COMM_MAC};
    munit_assert_int(
        dfc_reader_exchange_begin(&ex, &link.session, link.framing, &command, &options),
        ==,
        DfcReaderOk);
    uint8_t wire[DFC_COMMAND_MAX_APDU];
    size_t wire_len = 0;
    munit_assert_int(
        dfc_reader_step(&ex, NULL, 0, wire, sizeof(wire), &wire_len), ==, DfcReaderPending);
    const uint8_t expected_frame[] = {
        0x90, 0xBD, 0x00, 0x00, 0x0F, 0x02, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0xA7, 0xA4, 0x8E, 0x18, 0x18, 0xB1, 0xA2, 0xC5, 0x00,
    };
    munit_assert_size(wire_len, ==, sizeof(expected_frame));
    munit_assert_memory_equal(sizeof(expected_frame), wire, expected_frame);

    munit_assert_int(link_send(&link, &command, DFC_COMM_MAC, &ex), ==, DfcReaderCardError);
    munit_assert_uint8(dfc_reader_result_status(&ex), ==, DFC_STATUS_AUTHENTICATION_ERR);
    munit_assert_false(dfc_reader_session_is_authenticated(&link.session));
    munit_assert_uint16(link.session.ev2_command_counter, ==, 0);
    assert_ev2_emulator_session_wiped(link.picc->emulator);

    munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);
    read_file(&link, FileMac, DFC_COMM_MAC, 12, 16);
    link_close(&link);
    return MUNIT_OK;
}

static void assert_commit_reader_id_requires_mac(Link* link) {
    uint8_t reader_id[DFC_COMMAND_READER_ID_LENGTH] = {0};
    DfcCommand command;
    munit_assert_int(dfc_command_commit_reader_id(&command, reader_id), ==, DfcCommandOk);
    const uint8_t rejected_modes[] = {DFC_COMM_PLAIN, DFC_COMM_ENCIPHERED};
    for(size_t index = 0; index < sizeof(rejected_modes); index++) {
        DfcReaderSession before = link->session;
        DfcReaderExchange exchange;
        DfcReaderOptions options = {.comm_mode = rejected_modes[index]};
        munit_assert_int(
            dfc_reader_exchange_begin(&exchange, &link->session, link->framing, &command, &options),
            ==,
            DfcReaderInvalid);
        munit_assert_memory_equal(sizeof(before), &before, &link->session);
    }
    DfcReaderExchange exchange;
    DfcReaderOptions mac = {.comm_mode = DFC_COMM_MAC};
    munit_assert_int(
        dfc_reader_exchange_begin(&exchange, &link->session, link->framing, &command, &mac),
        ==,
        DfcReaderOk);
}

static MunitResult
    test_commit_reader_id_requires_mac_mode(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;

    link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, sizeof(AES_KEY_0)),
        ==,
        DfcReaderOk);
    assert_commit_reader_id_requires_mac(&link);
    link_close(&link);

#if DFC_ENABLE_EV2_SECURE_MESSAGING
    link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);
    assert_commit_reader_id_requires_mac(&link);
    link_close(&link);
#endif
    return MUNIT_OK;
}

static MunitResult
    test_ev2_change_file_settings_effective_comm(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);

    DfcFile* file = dfc_credential_find_file_in_app(&link.credential, 0, FileFull);
    munit_assert_not_null(file);
    DfcCommand command;
    DfcReaderExchange exchange;

    munit_assert_int(
        dfc_command_change_file_settings(&command, FileFull, DFC_COMM_ENCIPHERED, 0x000E, NULL, 0),
        ==,
        DfcCommandOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_ENCIPHERED, &exchange), ==, DfcReaderOk);
    munit_assert_uint16(link.session.ev2_command_counter, ==, 1);
    munit_assert_uint16(link.picc->emulator->ev2_command_counter, ==, 1);
    munit_assert_uint16(file->access_rights, ==, 0x000E);

    munit_assert_int(
        dfc_command_change_file_settings(&command, FileFull, DFC_COMM_MAC, 0x000E, NULL, 0),
        ==,
        DfcCommandOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &exchange), ==, DfcReaderOk);
    munit_assert_uint16(link.session.ev2_command_counter, ==, 2);
    munit_assert_uint16(link.picc->emulator->ev2_command_counter, ==, 2);
    munit_assert_uint8(file->comm_settings, ==, DFC_COMM_MAC);
    munit_assert_uint16(file->access_rights, ==, 0x000E);

    link_close(&link);
    return MUNIT_OK;
}

static MunitResult test_ev2_change_key_settings(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    select_app(&link, AID_AES);
    munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);

    DfcApplication* app = dfc_credential_get_application(&link.credential, 0);
    munit_assert_not_null(app);
    const uint8_t settings = 0x0E;
    DfcCommand command;
    DfcReaderExchange exchange;
    munit_assert_int(
        dfc_command_change_key_settings(&command, &settings, sizeof(settings)), ==, DfcCommandOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_ENCIPHERED, &exchange), ==, DfcReaderOk);
    munit_assert_uint8(app->key_settings_1, ==, settings);
    munit_assert_uint16(link.session.ev2_command_counter, ==, 1);
    munit_assert_uint16(link.picc->emulator->ev2_command_counter, ==, 1);
    link_close(&link);
    return MUNIT_OK;
}

// EV2 ChangeKey must apply the same per-key rules as native ChangeKey. Key 0
// (the application master key) can only be changed by a session authenticated as
// key 0 and only while the master-key-changeable bit is set. Before this was
// enforced, the EV2 path skipped that rule: with the bit cleared the master could
// still change key 0, and a key named in the change-key field could change key 0
// when it knew the old value. In both cases the key must stay as it was.
static MunitResult
    test_ev2_change_key_applies_the_per_key_rules(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    const uint8_t new_key[16] = {
        0x70,
        0x71,
        0x72,
        0x73,
        0x74,
        0x75,
        0x76,
        0x77,
        0x78,
        0x79,
        0x7A,
        0x7B,
        0x7C,
        0x7D,
        0x7E,
        0x7F};
    DfcCommand command;
    DfcReaderExchange ex;

    // Case 1: the master-key-changeable bit is clear, so not even key 0 may do it.
    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    DfcApplication* app = dfc_credential_get_application(&link.credential, 0);
    app->key_settings_1 = 0x0A;
    select_app(&link, AID_AES);
    munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);
    munit_assert_int(
        dfc_reader_change_key_ev2_command(&link.session, 0, 0, new_key, NULL, 0x33, &command),
        ==,
        DfcReaderOk);
    (void)link_send(&link, &command, DFC_COMM_PLAIN, &ex);
    munit_assert_uint8(dfc_reader_result_status(&ex), ==, 0x9D);
    munit_assert_memory_equal(
        sizeof(AES_KEY_0), dfc_credential_key_const(&link.credential, app, 0), AES_KEY_0);
    link_close(&link);

    // Case 2: key 1 is allowed to change keys (change-key field 1) and knows the
    // old value of key 0, but key 0 is only ever changed by key 0.
    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    app = dfc_credential_get_application(&link.credential, 0);
    app->key_settings_1 = 0x1F;
    select_app(&link, AID_AES);
    munit_assert_int(authenticate_ev2(&link, true, 1, AES_KEY_1), ==, DfcReaderOk);
    munit_assert_int(
        dfc_reader_change_key_ev2_command(&link.session, 0, 0, new_key, AES_KEY_0, 0x33, &command),
        ==,
        DfcReaderOk);
    (void)link_send(&link, &command, DFC_COMM_PLAIN, &ex);
    munit_assert_uint8(dfc_reader_result_status(&ex), ==, 0x9D);
    munit_assert_memory_equal(
        sizeof(AES_KEY_0), dfc_credential_key_const(&link.credential, app, 0), AES_KEY_0);
    link_close(&link);
    return MUNIT_OK;
}

static MunitResult test_ev2_change_key(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    DfcApplication* app = dfc_credential_get_application(&link.credential, 0);
    select_app(&link, AID_AES);
    munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);

    const uint8_t new_key_1[16] = {
        0x71,
        0x72,
        0x73,
        0x74,
        0x75,
        0x76,
        0x77,
        0x78,
        0x79,
        0x7A,
        0x7B,
        0x7C,
        0x7D,
        0x7E,
        0x7F,
        0x70};
    DfcCommand command;
    DfcReaderExchange ex;
    munit_assert_int(
        dfc_reader_change_key_ev2_command(
            &link.session, 0, 1, new_key_1, AES_KEY_1, 0x09, &command),
        ==,
        DfcReaderOk);
    uint8_t stored_key_before[DFC_AES_KEY_LENGTH];
    memcpy(
        stored_key_before,
        dfc_credential_key_const(&link.credential, app, 1),
        sizeof(stored_key_before));
    command.data[2 + DFC_AES_KEY_LENGTH + DFC_CHANGE_KEY_EV2_VERSION_LENGTH] ^= 0x01;
    munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderCardError);
    munit_assert_uint8(dfc_reader_result_status(&ex), ==, DFC_STATUS_INTEGRITY_ERROR);
    munit_assert_false(dfc_reader_session_is_authenticated(&link.session));
    assert_ev2_emulator_session_wiped(link.picc->emulator);
    munit_assert_memory_equal(
        sizeof(stored_key_before),
        dfc_credential_key_const(&link.credential, app, 1),
        stored_key_before);
    munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);
    munit_assert_int(
        dfc_reader_change_key_ev2_command(
            &link.session, 0, 1, new_key_1, AES_KEY_1, 0x09, &command),
        ==,
        DfcReaderOk);
    DfcReaderStatus st = link_send(&link, &command, DFC_COMM_PLAIN, &ex);
    if(st != DfcReaderOk)
        munit_logf(MUNIT_LOG_WARNING, "status %02X", dfc_reader_result_status(&ex));
    munit_assert_int(st, ==, DfcReaderOk);
    munit_assert_true(dfc_reader_session_is_authenticated(&link.session));
    read_file(&link, FileMac, DFC_COMM_MAC, 0, 8);
    munit_assert_int(authenticate_ev2(&link, false, 1, new_key_1), ==, DfcReaderOk);

    // Key 1 may not change keys here; the application's ChangeKey key is key 0.
    munit_assert_int(
        dfc_reader_change_key_ev2_command(&link.session, 0, 1, AES_KEY_1, NULL, 0x0A, &command),
        ==,
        DfcReaderOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderCardError);
    munit_assert_uint8(dfc_reader_result_status(&ex), ==, DFC_STATUS_AUTHENTICATION_ERR);
    munit_assert_false(dfc_reader_session_is_authenticated(&link.session));
    assert_ev2_emulator_session_wiped(link.picc->emulator);

    // The authenticated key itself: the card ends the session.
    munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);
    munit_assert_int(
        dfc_reader_change_key_ev2_command(&link.session, 0, 0, AES_KEY_1, NULL, 0x0A, &command),
        ==,
        DfcReaderOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderOk);
    munit_assert_false(dfc_reader_session_is_authenticated(&link.session));
    munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_1), ==, DfcReaderOk);
    link_close(&link);
    return MUNIT_OK;
}
#endif

#if DFC_ENABLE_PROXIMITY_CHECK
static MunitResult test_proximity_check(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
    const uint8_t key[16] = {
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x19};
    link.credential.picc_has_proximity_key = true;
    memcpy(link.credential.picc_proximity_key, key, sizeof(key));
    link.credential.picc_proximity_option = 0x00;
    link.credential.picc_proximity_published_response_time = 0x0102;

    DfcCommand command;
    DfcReaderExchange ex;
    munit_assert_int(dfc_command_prepare_proximity_check(&command), ==, DfcCommandOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderOk);
    munit_assert_uint8(dfc_reader_result_status(&ex), ==, DFC_STATUS_SPECIAL_SUCCESS);
    size_t published_len = 0;
    const uint8_t* published_data = dfc_reader_result_data(&ex, &published_len);
    uint8_t published[4];
    munit_assert_size(published_len, ==, 3);
    memcpy(published, published_data, published_len);

    uint8_t transcript[DFC_PROXIMITY_TRANSCRIPT_MAX];
    size_t transcript_len = 0;
    for(size_t round = 0; round < 2; round++) {
        uint8_t challenge[1 + 4];
        challenge[0] = 4;
        for(size_t i = 0; i < 4; i++)
            challenge[1 + i] = (uint8_t)(0xC0 + round * 4 + i);
        munit_assert_int(
            dfc_command_proximity_check(&command, challenge, sizeof(challenge)), ==, DfcCommandOk);
        munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderOk);
        size_t answer_len = 0;
        const uint8_t* answer = dfc_reader_result_data(&ex, &answer_len);
        munit_assert_size(answer_len, ==, 4);
        memcpy(transcript + transcript_len, answer, 4);
        memcpy(transcript + transcript_len + 4, challenge + 1, 4);
        transcript_len += 8;
    }

    uint8_t mac[8];
    munit_assert_true(dfc_reader_proximity_check_mac(
        key, false, published, published_len, transcript, transcript_len, mac));
    munit_assert_int(
        dfc_command_verify_proximity_check(&command, mac, sizeof(mac)), ==, DfcCommandOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_PLAIN, &ex), ==, DfcReaderOk);
    size_t card_mac_len = 0;
    const uint8_t* card_mac = dfc_reader_result_data(&ex, &card_mac_len);
    munit_assert_true(dfc_reader_proximity_check_mac(
        key, true, published, published_len, transcript, transcript_len, mac));
    munit_assert_size(card_mac_len, ==, sizeof(mac));
    munit_assert_memory_equal(sizeof(mac), card_mac, mac);
    link_close(&link);
    return MUNIT_OK;
}
#endif

#if DFC_ENABLE_VIRTUAL_CARD
static MunitResult test_virtual_card_select(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    DfcCredential* c = &link.credential;
    const uint8_t iid[] = {0xF0, 0x01, 0x02, 0x03, 0x04};
    const uint8_t enc_key[16] = {
        0x21,
        0x22,
        0x23,
        0x24,
        0x25,
        0x26,
        0x27,
        0x28,
        0x29,
        0x2A,
        0x2B,
        0x2C,
        0x2D,
        0x2E,
        0x2F,
        0x20};
    const uint8_t mac_key[16] = {
        0x31,
        0x32,
        0x33,
        0x34,
        0x35,
        0x36,
        0x37,
        0x38,
        0x39,
        0x3A,
        0x3B,
        0x3C,
        0x3D,
        0x3E,
        0x3F,
        0x30};
    c->virtual_card_configured = true;
    c->virtual_card_authentication_mandatory = true;
    memcpy(c->virtual_card_installation_id, iid, sizeof(iid));
    c->virtual_card_installation_id_len = sizeof(iid);
    memcpy(c->virtual_card_select_encryption_key, enc_key, sizeof(enc_key));
    memcpy(c->virtual_card_select_mac_key, mac_key, sizeof(mac_key));
    c->virtual_card_information = 0x5A;
    c->virtual_card_uid_len = 7;
    memcpy(c->virtual_card_uid, c->uid, 7);

    uint8_t apdu[32];
    size_t apdu_len = 0;
    munit_assert_int(
        dfc_reader_virtual_card_select_apdu(iid, sizeof(iid), apdu, sizeof(apdu), &apdu_len),
        ==,
        DfcReaderOk);
    uint8_t rx[64];
    size_t rx_len = 0;
    DfcVirtualPiccSession session_before = *link.picc;
    DfcEmulator emulator_before = *link.picc->emulator;
    for(size_t capacity = 0; capacity < DFC_ISO7816_STATUS_WORD_LENGTH; capacity++) {
        rx_len = SIZE_MAX;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(link.picc, apdu, apdu_len, rx, capacity, &rx_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        munit_assert_size(rx_len, ==, 0);
        munit_assert_memory_equal(sizeof(session_before), &session_before, link.picc);
        munit_assert_memory_equal(sizeof(emulator_before), &emulator_before, link.picc->emulator);
    }
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(link.picc, apdu, apdu_len, rx, sizeof(rx), &rx_len),
        ==,
        DfcVirtualPiccStatusOk);
    uint8_t challenge[16];
    uint8_t clear[16];
    munit_assert_int(
        dfc_reader_virtual_card_open(enc_key, rx, rx_len, challenge, clear), ==, DfcReaderOk);
    munit_assert_uint8(clear[0], ==, 0x5A);
    munit_assert_memory_equal(7, clear + 3, c->uid);

    munit_assert_int(
        dfc_reader_virtual_card_authenticate_apdu(
            mac_key, challenge, clear, apdu, sizeof(apdu), &apdu_len),
        ==,
        DfcReaderOk);
    session_before = *link.picc;
    emulator_before = *link.picc->emulator;
    for(size_t capacity = 0; capacity < DFC_ISO7816_STATUS_WORD_LENGTH; capacity++) {
        rx_len = SIZE_MAX;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(link.picc, apdu, apdu_len, rx, capacity, &rx_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        munit_assert_size(rx_len, ==, 0);
        munit_assert_memory_equal(sizeof(session_before), &session_before, link.picc);
        munit_assert_memory_equal(sizeof(emulator_before), &emulator_before, link.picc->emulator);
    }
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(link.picc, apdu, apdu_len, rx, sizeof(rx), &rx_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(rx_len, ==, 2);
    munit_assert_uint8(rx[0], ==, 0x90);
    munit_assert_true(link.picc->emulator->virtual_card_selected);
    link_close(&link);
    return MUNIT_OK;
}
#endif

#if DFC_ENABLE_DELEGATED_APPLICATIONS
static MunitResult test_delegated_application(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    link_open(&link, DfcGenerationEv2, DfcReaderFramingIso7816);
    DfcCredential* c = &link.credential;
    const uint8_t dam_auth[16] = {
        0x41,
        0x42,
        0x43,
        0x44,
        0x45,
        0x46,
        0x47,
        0x48,
        0x49,
        0x4A,
        0x4B,
        0x4C,
        0x4D,
        0x4E,
        0x4F,
        0x40};
    const uint8_t dam_mac[16] = {
        0x51,
        0x52,
        0x53,
        0x54,
        0x55,
        0x56,
        0x57,
        0x58,
        0x59,
        0x5A,
        0x5B,
        0x5C,
        0x5D,
        0x5E,
        0x5F,
        0x50};
    const uint8_t dam_enc[16] = {
        0x61,
        0x62,
        0x63,
        0x64,
        0x65,
        0x66,
        0x67,
        0x68,
        0x69,
        0x6A,
        0x6B,
        0x6C,
        0x6D,
        0x6E,
        0x6F,
        0x60};
    // EV2 authentication at the PICC level needs an AES master key.
    c->picc_key_settings_2 = DFC_KEY_TYPE_AES | 1;
    c->picc_auth_command = DFC_CMD_AUTHENTICATE_AES;
    c->picc_has_auth_commands = true;
    c->picc_auth_commands = DFC_AUTH_COMMAND_AES | DFC_AUTH_COMMAND_EV2_FIRST;
    munit_assert_true(dfc_credential_keys_resize(c, NULL, 1, 16));
    c->picc_has_dam_keys = true;
    memcpy(c->picc_dam_auth_key, dam_auth, 16);
    memcpy(c->picc_dam_mac_key, dam_mac, 16);
    memcpy(c->picc_dam_encryption_key, dam_enc, 16);

    const uint8_t picc[3] = {0x00, 0x00, 0x00};
    select_app(&link, picc);
    munit_assert_int(
        authenticate_ev2(&link, true, DFC_DAM_AUTH_KEY_NUMBER, dam_auth), ==, DfcReaderOk);
    DfcCommandCreateDelegatedApplication app = {
        {0x0A, 0x0B, 0x0C}, 0x0001, 0x00, 0x0040, 0x0F, DFC_KEY_TYPE_AES | 1};
    const uint8_t prefix[7] = {1, 2, 3, 4, 5, 6, 7};
    const uint8_t initial[16] = {
        0xAB,
        0xAB,
        0xAB,
        0xAB,
        0xAB,
        0xAB,
        0xAB,
        0xAB,
        0xCD,
        0xCD,
        0xCD,
        0xCD,
        0xCD,
        0xCD,
        0xCD,
        0xCD};
    DfcReaderExchange ex;
    munit_assert_int(
        dfc_reader_create_delegated_application_begin(
            &ex,
            &link.session,
            link.framing,
            &app,
            dam_enc,
            dam_mac,
            prefix,
            initial,
            sizeof(initial),
            0x03),
        ==,
        DfcReaderOk);
    const size_t allocations_before = dfc_host_allocation_count(DfcAllocByteBuf);
    // No storage is needed after the two long-lived emulator allocations. If a
    // command-local allocation returns, this injection makes the exchange fail.
    dfc_host_fail_next_allocation(DfcAllocByteBuf);
    DfcReaderStatus st = link_run(&link, &ex);
    if(st != DfcReaderOk)
        munit_logf(MUNIT_LOG_WARNING, "status %02X", dfc_reader_result_status(&ex));
    munit_assert_int(st, ==, DfcReaderOk);
    munit_assert_size(dfc_host_allocation_count(DfcAllocByteBuf), ==, allocations_before);
    // Prove that the injected failure was not consumed by the delegated command.
    munit_assert_null(dfc_platform_alloc(1, DfcAllocByteBuf));
    munit_assert_uint16(link.session.ev2_command_counter, ==, 1);

    const uint8_t aid[3] = {0x0C, 0x0B, 0x0A};
    select_app(&link, aid);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, initial, 16), ==, DfcReaderOk);
    link_close(&link);
    return MUNIT_OK;
}
#endif

static MunitTest tests[] = {
    {"/iso-append-record-helpers",
     test_iso_append_record_helpers,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/command-output-capacity-retries",
     test_command_output_capacity_retries,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/authentication-output-capacity-retries",
     test_authentication_output_capacity_retries,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/authentication-boundaries-match-shared-contract",
     test_authentication_boundaries_match_shared_contract,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/virtual-picc-output-capacity-retries",
     test_virtual_picc_output_capacity_retries,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/stream-state-deterministic-representation",
     test_stream_state_has_deterministic_representation,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/random-failures-are-atomic",
     test_random_failures_are_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/aborted-native-reauthentication-clears-authorization",
     test_aborted_native_reauthentication_clears_authorization,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/rejected-authentication-start-clears-authorization",
     test_rejected_authentication_start_clears_authorization,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/internal-response-overflow-is-terminal",
     test_internal_response_overflow_is_terminal,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/aes-session", test_aes_session, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/iso-session", test_iso_session, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#if DFC_ENABLE_ISO7816_AUTH
    {"/iso7816-mutual-authentication",
     test_iso7816_mutual_authentication,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso7816-rejected-authentication-transitions",
     test_iso7816_rejected_authentication_transitions,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
    {"/3k3des-session", test_3k3des_session, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/d40-session", test_d40_session, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/d40-reader-rejects-empty-mac-response",
     test_d40_reader_rejects_empty_mac_response,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/d40-reader-rejects-empty-read-all-records-response",
     test_d40_reader_rejects_empty_read_all_records_response,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/native-framing", test_native_framing, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/native-command-chaining",
     test_native_command_chaining,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/multiframe-terminal-response-retires-unsent-command",
     test_multiframe_terminal_response_retires_unsent_command,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/authenticated-directory-framing",
     test_authenticated_directory_framing,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/long-plain-read", test_long_plain_read, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/streamed-secure-write", test_streamed_secure_write, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/streamed-secure-record",
     test_streamed_secure_record,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/get-version-under-session",
     test_get_version_under_session,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/wrong-key-clears-session",
     test_wrong_key_clears_session,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/change-key", test_change_key, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/d40-change-key", test_d40_change_key, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/get-card-uid-uses-full-response-protection",
     test_get_card_uid_uses_full_response_protection,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    {"/authenticated-errors-are-plain-terminal",
     test_authenticated_errors_are_plain_terminal,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/interrupted-authenticated-chains-are-plain-terminal",
     test_interrupted_authenticated_chains_are_plain_terminal,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/reader-rejects-protected-terminal-errors",
     test_reader_rejects_protected_terminal_errors,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev2-invalid-command-is-plain-terminal",
     test_ev2_invalid_command_is_plain_terminal,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev2-invalid-full-command-is-plain-terminal",
     test_ev2_invalid_full_command_is_plain_terminal,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev2-full-read-errors-are-plain-terminal",
     test_ev2_full_read_errors_are_plain_terminal,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev2-session", test_ev2_session, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/ev2-change-file-settings-effective-comm",
     test_ev2_change_file_settings_effective_comm,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev2-change-key-settings",
     test_ev2_change_key_settings,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev2-change-key", test_ev2_change_key, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/ev2-change-key-applies-the-per-key-rules",
     test_ev2_change_key_applies_the_per_key_rules,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
    {"/commit-reader-id-requires-mac",
     test_commit_reader_id_requires_mac_mode,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#if DFC_ENABLE_PROXIMITY_CHECK
    {"/proximity-check", test_proximity_check, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if DFC_ENABLE_VIRTUAL_CARD
    {"/virtual-card-select", test_virtual_card_select, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if DFC_ENABLE_DELEGATED_APPLICATIONS
    {"/delegated-application", test_delegated_application, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {"/dfc_reader", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
