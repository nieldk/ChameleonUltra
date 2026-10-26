#include <stdio.h>
#include "../tests/munit/munit.h"
#include "dfc_secure_messaging.h"
#include <stdlib.h>
#include <string.h>

static void hex_to_bytes(const char* hex, uint8_t* out) {
    size_t len = strlen(hex) / 2;
    for(size_t i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex + i * 2, "%2x", &byte);
        out[i] = (uint8_t)byte;
    }
}

static DfcSecureMessaging* alloc_session(uint8_t cipher, size_t key_len) {
    uint8_t key[DFC_MAX_KEY_LEN];
    for(size_t i = 0; i < key_len; i++)
        key[i] = (uint8_t)(0x10 + i);
    return dfc_secure_messaging_alloc(cipher, key, key_len, NULL);
}

static uint32_t test_crc32_dfc(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for(size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for(size_t bit = 0; bit < 8; bit++) {
            uint32_t mask = 0 - (crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }
    return crc;
}

// Reader (PCD) side: wrap() an outgoing command, then verify_command() (the emulator/PICC
// side function) should accept it and recover the original plaintext - these are meant to
// be exact inverses of each other.
static MunitResult
    round_trip_wrap_verify_command(uint8_t cipher, uint8_t comm_mode, size_t key_len) {
    DfcSecureMessaging* sm_reader = alloc_session(cipher, key_len);
    sm_reader->pcd = true;
    DfcSecureMessaging* sm_emulator = alloc_session(cipher, key_len);

    // Cmd || FileNo || Offset(3) || Length(3), then the payload it describes.
    uint8_t header[] = {DFC_CMD_WRITE_DATA, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00};
    uint8_t plain[] = {0xde, 0xad, 0xbe, 0xef};

    uint8_t wrapped[DFC_SM_MAX_SIZE];
    size_t wrapped_len = comm_mode == DFC_COMM_MAC ?
                             dfc_secure_messaging_wrap_d40_command_mac(
                                 sm_reader, plain, sizeof(plain), wrapped, sizeof(wrapped)) :
                             dfc_secure_messaging_wrap(
                                 sm_reader,
                                 comm_mode,
                                 header,
                                 sizeof(header),
                                 plain,
                                 sizeof(plain),
                                 wrapped,
                                 sizeof(wrapped));
    munit_assert_size(wrapped_len, >=, sizeof(plain));

    uint8_t recovered[DFC_SM_MAX_SIZE];
    size_t recovered_len = 0;
    if(comm_mode == DFC_COMM_MAC) {
        munit_assert_true(dfc_secure_messaging_verify_d40_command_mac(
            sm_emulator, wrapped, wrapped_len, recovered, sizeof(recovered), &recovered_len));
    } else {
        recovered_len = dfc_secure_messaging_verify_command(
            sm_emulator,
            comm_mode,
            header,
            sizeof(header),
            wrapped,
            wrapped_len,
            recovered,
            sizeof(recovered));
    }

    munit_assert_size(recovered_len, ==, sizeof(plain));
    munit_assert_memory_equal(sizeof(plain), recovered, plain);

    dfc_secure_messaging_free(sm_reader);
    dfc_secure_messaging_free(sm_emulator);
    return MUNIT_OK;
}

// Emulator (PICC) side: generate_response() a reply, then unwrap() (the reader side
// function) should accept it and recover the original plaintext.
static MunitResult
    round_trip_generate_response_unwrap(uint8_t cipher, uint8_t comm_mode, size_t key_len) {
    DfcSecureMessaging* sm_emulator = alloc_session(cipher, key_len);
    DfcSecureMessaging* sm_reader = alloc_session(cipher, key_len);
    sm_reader->pcd = true;

    uint8_t plain[] = {0x30, 0x0b, 0x81, 0x01, 0x01};
    uint8_t status = DFC_STATUS_OK;

    uint8_t wrapped[DFC_SM_MAX_SIZE];
    size_t wrapped_len =
        comm_mode == DFC_COMM_MAC ?
            dfc_secure_messaging_generate_d40_response_mac(
                sm_emulator, plain, sizeof(plain), wrapped, sizeof(wrapped)) :
            dfc_secure_messaging_generate_response(
                sm_emulator, comm_mode, status, plain, sizeof(plain), wrapped, sizeof(wrapped));
    munit_assert_size(wrapped_len, >=, sizeof(plain));

    uint8_t recovered[DFC_SM_MAX_SIZE];
    size_t recovered_len = 0;
    bool ok =
        comm_mode == DFC_COMM_MAC ?
            dfc_secure_messaging_unwrap_d40_response_mac(
                sm_reader, wrapped, wrapped_len, recovered, sizeof(recovered), &recovered_len) :
            dfc_secure_messaging_unwrap(
                sm_reader,
                comm_mode,
                status,
                wrapped,
                wrapped_len,
                recovered,
                sizeof(recovered),
                &recovered_len);
    munit_assert_true(ok);

    munit_assert_size(recovered_len, ==, sizeof(plain));
    munit_assert_memory_equal(sizeof(plain), recovered, plain);

    dfc_secure_messaging_free(sm_emulator);
    dfc_secure_messaging_free(sm_reader);
    return MUNIT_OK;
}

static MunitResult test_plain_legacy(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    round_trip_wrap_verify_command(DFC_CMD_AUTHENTICATE_LEGACY, DFC_COMM_PLAIN, 8);
    round_trip_generate_response_unwrap(DFC_CMD_AUTHENTICATE_LEGACY, DFC_COMM_PLAIN, 8);
    return MUNIT_OK;
}

static MunitResult test_mac_legacy_single_des(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    round_trip_wrap_verify_command(DFC_CMD_AUTHENTICATE_LEGACY, DFC_COMM_MAC, 8);
    round_trip_generate_response_unwrap(DFC_CMD_AUTHENTICATE_LEGACY, DFC_COMM_MAC, 8);
    return MUNIT_OK;
}

static MunitResult test_mac_legacy_2k3des(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    round_trip_wrap_verify_command(DFC_CMD_AUTHENTICATE_LEGACY, DFC_COMM_MAC, 16);
    round_trip_generate_response_unwrap(DFC_CMD_AUTHENTICATE_LEGACY, DFC_COMM_MAC, 16);
    return MUNIT_OK;
}

static void assert_d40_response_authentication(const uint8_t* plain, size_t plain_len) {
    DfcSecureMessaging* card = alloc_session(DFC_CMD_AUTHENTICATE_LEGACY, 16);
    DfcSecureMessaging* reader = alloc_session(DFC_CMD_AUTHENTICATE_LEGACY, 16);
    reader->pcd = true;

    uint8_t wrapped[32];
    size_t wrapped_len = dfc_secure_messaging_generate_d40_response_mac(
        card, plain, plain_len, wrapped, sizeof(wrapped));
    munit_assert_size(wrapped_len, ==, plain_len + DFC_SM_LEGACY_MAC_LENGTH);

    DfcSecureMessaging reader_before = *reader;
    uint8_t recovered[32];
    memset(recovered, 0xA5, sizeof(recovered));
    size_t recovered_len = SIZE_MAX;
    munit_assert_true(dfc_secure_messaging_unwrap_d40_response_mac(
        reader, wrapped, wrapped_len, recovered, sizeof(recovered), &recovered_len));
    munit_assert_size(recovered_len, ==, plain_len);
    if(plain_len > 0) munit_assert_memory_equal(plain_len, recovered, plain);

    for(size_t mac_index = plain_len; mac_index < wrapped_len; mac_index++) {
        *reader = reader_before;
        uint8_t corrupted[sizeof(wrapped)];
        memcpy(corrupted, wrapped, wrapped_len);
        corrupted[mac_index] ^= 0x01;
        recovered_len = SIZE_MAX;
        munit_assert_false(dfc_secure_messaging_unwrap_d40_response_mac(
            reader, corrupted, wrapped_len, recovered, sizeof(recovered), &recovered_len));
        munit_assert_size(recovered_len, ==, 0);
        munit_assert_memory_equal(sizeof(reader_before.iv), reader->iv, reader_before.iv);
    }

    if(plain_len == 0) {
        for(size_t truncated_len = 0; truncated_len < DFC_SM_LEGACY_MAC_LENGTH; truncated_len++) {
            *reader = reader_before;
            recovered_len = SIZE_MAX;
            munit_assert_false(dfc_secure_messaging_unwrap_d40_response_mac(
                reader, wrapped, truncated_len, recovered, sizeof(recovered), &recovered_len));
            munit_assert_size(recovered_len, ==, 0);
            munit_assert_memory_equal(sizeof(reader_before.iv), reader->iv, reader_before.iv);
        }
    }

    dfc_secure_messaging_free(reader);
    dfc_secure_messaging_free(card);
}

static MunitResult test_d40_empty_response_is_distinct_from_authentication_failure(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    const uint8_t empty = 0;
    const uint8_t nonempty[] = {0x5A, 0xC3, 0x7E};
    assert_d40_response_authentication(&empty, 0);
    assert_d40_response_authentication(nonempty, sizeof(nonempty));
    return MUNIT_OK;
}

static MunitResult test_d40_mac_matches_fixed_vector(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    DfcSecureMessaging* sender = alloc_session(DFC_CMD_AUTHENTICATE_LEGACY, 16);
    DfcSecureMessaging* receiver = alloc_session(DFC_CMD_AUTHENTICATE_LEGACY, 16);
    static const uint8_t plain[] = {0xDE, 0xAD, 0xBE, 0xEF};
    static const uint8_t expected[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x82, 0x44, 0x1B, 0x4F};
    uint8_t wrapped[sizeof(expected)];
    size_t wrapped_len = dfc_secure_messaging_wrap_d40_command_mac(
        sender, plain, sizeof(plain), wrapped, sizeof(wrapped));
    munit_assert_size(wrapped_len, ==, sizeof(expected));
    munit_assert_memory_equal(sizeof(expected), wrapped, expected);

    uint8_t recovered[sizeof(plain)];
    size_t recovered_len = SIZE_MAX;
    munit_assert_true(dfc_secure_messaging_verify_d40_command_mac(
        receiver, wrapped, wrapped_len, recovered, sizeof(recovered), &recovered_len));
    munit_assert_size(recovered_len, ==, sizeof(plain));

    static const uint8_t empty_mac[DFC_SM_LEGACY_MAC_LENGTH] = {0};
    recovered_len = SIZE_MAX;
    munit_assert_true(dfc_secure_messaging_verify_d40_command_mac(
        receiver, empty_mac, sizeof(empty_mac), recovered, sizeof(recovered), &recovered_len));
    munit_assert_size(recovered_len, ==, 0);

    wrapped[wrapped_len - 1] ^= 1;
    recovered_len = SIZE_MAX;
    munit_assert_false(dfc_secure_messaging_verify_d40_command_mac(
        receiver, wrapped, wrapped_len, recovered, sizeof(recovered), &recovered_len));
    munit_assert_size(recovered_len, ==, 0);

    dfc_secure_messaging_free(receiver);
    dfc_secure_messaging_free(sender);
    return MUNIT_OK;
}

static void assert_ev1_response_mac_round_trip(uint8_t cipher, size_t key_len) {
    DfcSecureMessaging* card = alloc_session(cipher, key_len);
    DfcSecureMessaging* reader = alloc_session(cipher, key_len);
    static const uint8_t parameters[] = {1, 0, 0, 0, 4, 0, 0};
    static const uint8_t plain[] = {0x30, 0x0B, 0x81, 0x01, 0x01};
    munit_assert_true(dfc_secure_messaging_update_ev1_command(
        card, DFC_CMD_READ_DATA, parameters, sizeof(parameters)));
    munit_assert_true(dfc_secure_messaging_update_ev1_command(
        reader, DFC_CMD_READ_DATA, parameters, sizeof(parameters)));

    uint8_t wrapped[sizeof(plain) + DFC_WIRE_MAC_LENGTH];
    size_t wrapped_len = dfc_secure_messaging_generate_ev1_response(
        card, DFC_STATUS_OK, plain, sizeof(plain), wrapped, sizeof(wrapped));
    uint8_t recovered[sizeof(plain)];
    size_t recovered_len = dfc_secure_messaging_unwrap_ev1_response(
        reader, DFC_STATUS_OK, wrapped, wrapped_len, recovered, sizeof(recovered));
    munit_assert_size(recovered_len, ==, sizeof(plain));
    munit_assert_memory_equal(sizeof(plain), recovered, plain);

    dfc_secure_messaging_free(reader);
    dfc_secure_messaging_free(card);
}

static MunitResult test_mac_iso_2k3des(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    assert_ev1_response_mac_round_trip(DFC_CMD_AUTHENTICATE_ISO, 16);
    return MUNIT_OK;
}

static MunitResult test_mac_iso_3k3des(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    assert_ev1_response_mac_round_trip(DFC_CMD_AUTHENTICATE_ISO, 24);
    return MUNIT_OK;
}

static MunitResult test_mac_aes(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    assert_ev1_response_mac_round_trip(DFC_CMD_AUTHENTICATE_AES, 16);
    return MUNIT_OK;
}

static MunitResult test_generic_mac_rejects_all_sessions(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    static const struct {
        uint8_t cipher;
        size_t key_len;
    } sessions[] = {
        {DFC_CMD_AUTHENTICATE_LEGACY, 16},
        {DFC_CMD_AUTHENTICATE_ISO, 8},
        {DFC_CMD_AUTHENTICATE_ISO, 16},
        {DFC_CMD_AUTHENTICATE_ISO, 24},
        {DFC_CMD_AUTHENTICATE_AES, 16},
    };
    static const uint8_t header[] = {DFC_CMD_WRITE_DATA, 1};
    static const uint8_t plain[] = {0xDE, 0xAD};

    for(size_t i = 0; i < sizeof(sessions) / sizeof(sessions[0]); i++) {
        DfcSecureMessaging* sm = alloc_session(sessions[i].cipher, sessions[i].key_len);
        munit_assert_not_null(sm);
        DfcSecureMessaging before = *sm;
        uint8_t output[32];
        memset(output, 0xA5, sizeof(output));

        munit_assert_size(
            dfc_secure_messaging_wrap(
                sm,
                DFC_COMM_MAC,
                header,
                sizeof(header),
                plain,
                sizeof(plain),
                output,
                sizeof(output)),
            ==,
            0);
        munit_assert_memory_equal(sizeof(before), sm, &before);
        for(size_t j = 0; j < sizeof(output); j++)
            munit_assert_uint8(output[j], ==, 0xA5);

        munit_assert_size(
            dfc_secure_messaging_generate_response(
                sm, DFC_COMM_MAC, DFC_STATUS_OK, plain, sizeof(plain), output, sizeof(output)),
            ==,
            0);
        munit_assert_size(
            dfc_secure_messaging_verify_command(
                sm,
                DFC_COMM_MAC,
                header,
                sizeof(header),
                plain,
                sizeof(plain),
                output,
                sizeof(output)),
            ==,
            0);
        size_t output_len = SIZE_MAX;
        munit_assert_false(dfc_secure_messaging_unwrap(
            sm,
            DFC_COMM_MAC,
            DFC_STATUS_OK,
            plain,
            sizeof(plain),
            output,
            sizeof(output),
            &output_len));
        munit_assert_size(output_len, ==, 0);

        if(sessions[i].cipher != DFC_CMD_AUTHENTICATE_LEGACY) {
            munit_assert_size(
                dfc_secure_messaging_wrap_d40_command_mac(
                    sm, plain, sizeof(plain), output, sizeof(output)),
                ==,
                0);
            munit_assert_size(
                dfc_secure_messaging_generate_d40_response_mac(
                    sm, plain, sizeof(plain), output, sizeof(output)),
                ==,
                0);
            static const uint8_t d40_frame[DFC_SM_LEGACY_MAC_LENGTH] = {0};
            output_len = SIZE_MAX;
            munit_assert_false(dfc_secure_messaging_verify_d40_command_mac(
                sm, d40_frame, sizeof(d40_frame), output, sizeof(output), &output_len));
            munit_assert_size(output_len, ==, 0);
            output_len = SIZE_MAX;
            munit_assert_false(dfc_secure_messaging_unwrap_d40_response_mac(
                sm, d40_frame, sizeof(d40_frame), output, sizeof(output), &output_len));
            munit_assert_size(output_len, ==, 0);
        }

        dfc_secure_messaging_free(sm);
    }
    return MUNIT_OK;
}

static MunitResult test_enciphered_legacy(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    round_trip_wrap_verify_command(DFC_CMD_AUTHENTICATE_LEGACY, DFC_COMM_ENCIPHERED, 8);
    round_trip_generate_response_unwrap(DFC_CMD_AUTHENTICATE_LEGACY, DFC_COMM_ENCIPHERED, 8);
    return MUNIT_OK;
}

static MunitResult
    test_legacy_enciphered_rejects_partial_blocks(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    uint8_t wrapped[32];
    uint8_t clear[32];
    uint8_t header[] = {DFC_CMD_WRITE_DATA, 1, 0, 0, 0, 1, 0, 0};
    memset(wrapped, 0x3C, sizeof(wrapped));

    for(size_t length = 1; length < sizeof(wrapped); length++) {
        if(length % DFC_SM_LEGACY_BLOCK_SIZE == 0) continue;
        DfcSecureMessaging* reader = alloc_session(DFC_CMD_AUTHENTICATE_LEGACY, 8);
        DfcSecureMessaging* card = alloc_session(DFC_CMD_AUTHENTICATE_LEGACY, 8);
        reader->pcd = true;
        DfcSecureMessaging reader_before = *reader;
        DfcSecureMessaging card_before = *card;

        memset(clear, 0xA5, sizeof(clear));
        size_t clear_len = SIZE_MAX;
        munit_assert_false(dfc_secure_messaging_unwrap(
            reader,
            DFC_COMM_ENCIPHERED,
            DFC_STATUS_OK,
            wrapped,
            length,
            clear,
            sizeof(clear),
            &clear_len));
        munit_assert_size(clear_len, ==, 0);
        for(size_t i = 0; i < length; i++)
            munit_assert_uint8(clear[i], ==, 0);
        munit_assert_memory_equal(sizeof(reader_before), &reader_before, reader);

        memset(clear, 0xA5, sizeof(clear));
        munit_assert_size(
            dfc_secure_messaging_verify_command(
                card,
                DFC_COMM_ENCIPHERED,
                header,
                sizeof(header),
                wrapped,
                length,
                clear,
                sizeof(clear)),
            ==,
            0);
        for(size_t i = 0; i < length; i++)
            munit_assert_uint8(clear[i], ==, 0);
        munit_assert_memory_equal(sizeof(card_before), &card_before, card);
        dfc_secure_messaging_free(reader);
        dfc_secure_messaging_free(card);
    }

    DfcSecureMessaging* reader = alloc_session(DFC_CMD_AUTHENTICATE_LEGACY, 8);
    reader->pcd = true;
    for(size_t length = 1; length < 16; length++) {
        memset(clear, 0x5A, length);
        size_t wrapped_len = dfc_secure_messaging_wrap(
            reader,
            DFC_COMM_ENCIPHERED,
            header,
            sizeof(header),
            clear,
            length,
            wrapped,
            sizeof(wrapped));
        munit_assert_size(wrapped_len, >, 0);
        munit_assert_size(wrapped_len % DFC_SM_LEGACY_BLOCK_SIZE, ==, 0);
    }
    dfc_secure_messaging_free(reader);
    return MUNIT_OK;
}

static MunitResult test_enciphered_iso(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    round_trip_wrap_verify_command(DFC_CMD_AUTHENTICATE_ISO, DFC_COMM_ENCIPHERED, 16);
    round_trip_generate_response_unwrap(DFC_CMD_AUTHENTICATE_ISO, DFC_COMM_ENCIPHERED, 16);
    return MUNIT_OK;
}

static MunitResult test_enciphered_aes(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    round_trip_wrap_verify_command(DFC_CMD_AUTHENTICATE_AES, DFC_COMM_ENCIPHERED, 16);
    round_trip_generate_response_unwrap(DFC_CMD_AUTHENTICATE_AES, DFC_COMM_ENCIPHERED, 16);
    return MUNIT_OK;
}

static size_t encode_for_overlap_test(
    DfcSecureMessaging* sm,
    bool response,
    const uint8_t* plain,
    size_t plain_len,
    uint8_t* out,
    size_t out_capacity) {
    static const uint8_t header[] = {DFC_CMD_WRITE_DATA, 1, 0, 0, 0, 0, 0, 0};
    if(response) {
        return dfc_secure_messaging_generate_response(
            sm, DFC_COMM_ENCIPHERED, DFC_STATUS_OK, plain, plain_len, out, out_capacity);
    }
    sm->pcd = true;
    return dfc_secure_messaging_wrap(
        sm, DFC_COMM_ENCIPHERED, header, sizeof(header), plain, plain_len, out, out_capacity);
}

static MunitResult
    test_enciphered_encode_accepts_partial_overlap(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    static const struct {
        uint8_t cipher;
        size_t key_len;
    } ciphers[] = {
        {DFC_CMD_AUTHENTICATE_LEGACY, 8},
        {DFC_CMD_AUTHENTICATE_ISO, 16},
        {DFC_CMD_AUTHENTICATE_ISO, 24},
        {DFC_CMD_AUTHENTICATE_AES, 16},
    };
    static const size_t lengths[] = {1, 7, 8, 9, 15, 16, 17};
    static const ptrdiff_t offsets[] = {0, 3, -3};

    for(size_t cipher_index = 0; cipher_index < sizeof(ciphers) / sizeof(ciphers[0]);
        cipher_index++) {
        for(size_t response = 0; response < 2; response++) {
            for(size_t length_index = 0; length_index < sizeof(lengths) / sizeof(lengths[0]);
                length_index++) {
                uint8_t plain[17];
                for(size_t i = 0; i < sizeof(plain); i++)
                    plain[i] = (uint8_t)(0x31u + i);
                DfcSecureMessaging* baseline =
                    alloc_session(ciphers[cipher_index].cipher, ciphers[cipher_index].key_len);
                uint8_t expected[DFC_SM_MAX_SIZE];
                size_t expected_len = encode_for_overlap_test(
                    baseline,
                    response != 0,
                    plain,
                    lengths[length_index],
                    expected,
                    sizeof(expected));
                munit_assert_size(expected_len, >, 0);
                dfc_secure_messaging_free(baseline);

                for(size_t offset_index = 0; offset_index < sizeof(offsets) / sizeof(offsets[0]);
                    offset_index++) {
                    uint8_t workspace[DFC_SM_MAX_SIZE + 32];
                    uint8_t* source = workspace + 16;
                    uint8_t* destination = source + offsets[offset_index];
                    memcpy(source, plain, lengths[length_index]);
                    DfcSecureMessaging* overlap =
                        alloc_session(ciphers[cipher_index].cipher, ciphers[cipher_index].key_len);
                    size_t actual_len = encode_for_overlap_test(
                        overlap,
                        response != 0,
                        source,
                        lengths[length_index],
                        destination,
                        (size_t)(workspace + sizeof(workspace) - destination));
                    munit_assert_size(actual_len, ==, expected_len);
                    munit_assert_memory_equal(expected_len, destination, expected);
                    dfc_secure_messaging_free(overlap);
                }
            }
        }
    }
    return MUNIT_OK;
}

static MunitResult test_command_payload_lengths_match_encoder(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    static const struct {
        uint8_t cipher;
        size_t key_len;
    } ciphers[] = {
        {DFC_CMD_AUTHENTICATE_LEGACY, 8},
        {DFC_CMD_AUTHENTICATE_ISO, 16},
        {DFC_CMD_AUTHENTICATE_ISO, 24},
        {DFC_CMD_AUTHENTICATE_AES, 16},
    };
    static const size_t lengths[] = {0, 1, 7, 8, 9, 15, 16, 17, DFC_MAX_FILE_DATA};
    static const uint8_t modes[] = {DFC_COMM_PLAIN, DFC_COMM_MAC, DFC_COMM_ENCIPHERED};
    static const uint8_t header[] = {DFC_CMD_WRITE_DATA, 1, 0, 0, 0, 0, 0, 0};
    uint8_t plain[DFC_MAX_FILE_DATA] = {0};
    uint8_t encoded[DFC_SM_MAX_CRYPTO_SIZE + DFC_WORKER_CMAC_SIZE];

    for(size_t cipher_index = 0; cipher_index < sizeof(ciphers) / sizeof(ciphers[0]);
        cipher_index++) {
        for(size_t mode_index = 0; mode_index < sizeof(modes) / sizeof(modes[0]); mode_index++) {
            for(size_t length_index = 0; length_index < sizeof(lengths) / sizeof(lengths[0]);
                length_index++) {
                DfcSecureMessaging* sm =
                    alloc_session(ciphers[cipher_index].cipher, ciphers[cipher_index].key_len);
                size_t predicted = dfc_secure_messaging_command_payload_length(
                    sm, false, modes[mode_index], lengths[length_index]);
                munit_assert_size(predicted, !=, SIZE_MAX);
                size_t actual =
                    modes[mode_index] == DFC_COMM_MAC ?
                        (sm->cipher == DFC_CMD_AUTHENTICATE_LEGACY ?
                             dfc_secure_messaging_wrap_d40_command_mac(
                                 sm, plain, lengths[length_index], encoded, sizeof(encoded)) :
                             lengths[length_index] + DFC_WIRE_MAC_LENGTH) :
                        dfc_secure_messaging_wrap(
                            sm,
                            modes[mode_index],
                            header,
                            sizeof(header),
                            plain,
                            lengths[length_index],
                            encoded,
                            sizeof(encoded));
                munit_assert_size(predicted, ==, actual);
                dfc_secure_messaging_free(sm);
            }
        }
    }

    size_t length = dfc_secure_messaging_command_payload_length(NULL, true, DFC_COMM_MAC, 16);
    munit_assert_size(length, ==, 16 + DFC_WIRE_MAC_LENGTH);
    length = dfc_secure_messaging_command_payload_length(NULL, true, DFC_COMM_ENCIPHERED, 15);
    munit_assert_size(length, ==, DFC_AES_KEY_LENGTH + DFC_WIRE_MAC_LENGTH);
    length = dfc_secure_messaging_command_payload_length(NULL, true, DFC_COMM_ENCIPHERED, 16);
    munit_assert_size(length, ==, 2 * DFC_AES_KEY_LENGTH + DFC_WIRE_MAC_LENGTH);
    munit_assert_size(
        dfc_secure_messaging_command_payload_length(NULL, true, DFC_COMM_ENCIPHERED, SIZE_MAX),
        ==,
        SIZE_MAX);
    munit_assert_size(
        dfc_secure_messaging_command_payload_length(NULL, true, DFC_COMM_MAC, SIZE_MAX),
        ==,
        SIZE_MAX);
    munit_assert_size(
        dfc_secure_messaging_command_payload_length(NULL, false, DFC_COMM_MAC, 1), ==, SIZE_MAX);
    DfcSecureMessaging* sm = alloc_session(DFC_CMD_AUTHENTICATE_AES, DFC_AES_KEY_LENGTH);
    munit_assert_size(
        dfc_secure_messaging_command_payload_length(sm, false, 0x02, 1), ==, SIZE_MAX);
    dfc_secure_messaging_free(sm);
    munit_assert_size(
        dfc_secure_messaging_command_payload_length(NULL, true, 0x02, 1), ==, SIZE_MAX);
    munit_assert_size(
        dfc_secure_messaging_command_payload_length(NULL, false, 0xFF, 1), ==, SIZE_MAX);
    return MUNIT_OK;
}

// A corrupted MAC/ciphertext must be rejected (return 0), not silently accepted.
static MunitResult test_mac_tamper_rejected(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    DfcSecureMessaging* sm_reader = alloc_session(DFC_CMD_AUTHENTICATE_AES, 16);
    DfcSecureMessaging* sm_emulator = alloc_session(DFC_CMD_AUTHENTICATE_AES, 16);
    uint8_t parameters[] = {0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00};
    uint8_t plain[] = {0xDE, 0xAD, 0xBE, 0xEF};
    munit_assert_true(dfc_secure_messaging_update_ev1_command(
        sm_reader, DFC_CMD_READ_DATA, parameters, sizeof(parameters)));
    munit_assert_true(dfc_secure_messaging_update_ev1_command(
        sm_emulator, DFC_CMD_READ_DATA, parameters, sizeof(parameters)));
    uint8_t wrapped[DFC_SM_MAX_SIZE];
    size_t wrapped_len = dfc_secure_messaging_generate_ev1_response(
        sm_emulator, DFC_STATUS_OK, plain, sizeof(plain), wrapped, sizeof(wrapped));

    wrapped[wrapped_len - 1] ^= 0xFF; // corrupt the last MAC byte

    uint8_t recovered[DFC_SM_MAX_SIZE];
    size_t recovered_len = dfc_secure_messaging_unwrap_ev1_response(
        sm_reader, DFC_STATUS_OK, wrapped, wrapped_len, recovered, sizeof(recovered));

    munit_assert_size(recovered_len, ==, SIZE_MAX);

    dfc_secure_messaging_free(sm_reader);
    dfc_secure_messaging_free(sm_emulator);
    return MUNIT_OK;
}

static MunitResult
    test_ev1_get_file_settings_response_is_mac_protected(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    DfcSecureMessaging* sm = alloc_session(DFC_CMD_AUTHENTICATE_ISO, 16);

    munit_assert_false(dfc_secure_messaging_applies_ev1(sm, DFC_CMD_SELECT_APPLICATION));
    munit_assert_false(dfc_secure_messaging_applies_ev1(sm, DFC_CMD_AUTHENTICATE_ISO));
    munit_assert_true(dfc_secure_messaging_applies_ev1(sm, DFC_CMD_GET_FILE_SETTINGS));

    uint8_t file_no[] = {0x0f};
    dfc_secure_messaging_update_ev1_command(
        sm, DFC_CMD_GET_FILE_SETTINGS, file_no, sizeof(file_no));

    uint8_t settings[] = {0x00, 0x01, 0x12, 0x30, 0x35, 0x00, 0x00};
    uint8_t wrapped[DFC_SM_MAX_SIZE];
    size_t wrapped_len = dfc_secure_messaging_generate_ev1_response(
        sm, DFC_STATUS_OK, settings, sizeof(settings), wrapped, sizeof(wrapped));

    munit_assert_size(wrapped_len, ==, sizeof(settings) + 8);
    munit_assert_memory_equal(sizeof(settings), wrapped, settings);

    dfc_secure_messaging_free(sm);
    return MUNIT_OK;
}

static MunitResult
    test_ev1_response_unwrap_requires_command_state(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    uint8_t key[16];
    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)(0x20 + i);

    DfcSecureMessaging* sm_reader =
        dfc_secure_messaging_alloc(DFC_CMD_AUTHENTICATE_ISO, key, sizeof(key), NULL);
    DfcSecureMessaging* sm_emulator =
        dfc_secure_messaging_alloc(DFC_CMD_AUTHENTICATE_ISO, key, sizeof(key), NULL);
    DfcSecureMessaging* sm_stale_reader =
        dfc_secure_messaging_alloc(DFC_CMD_AUTHENTICATE_ISO, key, sizeof(key), NULL);

    uint8_t read_params[] = {0x0f, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00};
    dfc_secure_messaging_update_ev1_command(
        sm_reader, DFC_CMD_READ_DATA, read_params, sizeof(read_params));
    dfc_secure_messaging_update_ev1_command(
        sm_emulator, DFC_CMD_READ_DATA, read_params, sizeof(read_params));

    uint8_t plain[] = {0x30, 0x2f, 0x81, 0x02, 0x0c};
    uint8_t wrapped[DFC_SM_MAX_SIZE];
    size_t wrapped_len = dfc_secure_messaging_generate_ev1_response(
        sm_emulator, DFC_STATUS_OK, plain, sizeof(plain), wrapped, sizeof(wrapped));

    uint8_t recovered[DFC_SM_MAX_SIZE];
    size_t recovered_len = dfc_secure_messaging_unwrap_ev1_response(
        sm_reader, DFC_STATUS_OK, wrapped, wrapped_len, recovered, sizeof(recovered));
    munit_assert_size(recovered_len, ==, sizeof(plain));
    munit_assert_memory_equal(sizeof(plain), recovered, plain);

    recovered_len = dfc_secure_messaging_unwrap_ev1_response(
        sm_stale_reader, DFC_STATUS_OK, wrapped, wrapped_len, recovered, sizeof(recovered));
    munit_assert_size(recovered_len, ==, SIZE_MAX);

    dfc_secure_messaging_free(sm_reader);
    dfc_secure_messaging_free(sm_emulator);
    dfc_secure_messaging_free(sm_stale_reader);
    return MUNIT_OK;
}

static MunitResult test_ev1_initial_iv_is_used(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    uint8_t key[16];
    uint8_t initial_iv[16];
    for(size_t i = 0; i < sizeof(key); i++) {
        key[i] = (uint8_t)(0x40 + i);
        initial_iv[i] = (uint8_t)(0xa0 + i);
    }

    DfcSecureMessaging* sm =
        dfc_secure_messaging_alloc(DFC_CMD_AUTHENTICATE_AES, key, sizeof(key), initial_iv);
    munit_assert_memory_equal(sizeof(initial_iv), sm->iv, initial_iv);

    dfc_secure_messaging_free(sm);
    return MUNIT_OK;
}

static MunitResult
    test_ev1_get_file_settings_matches_reference_vector(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;

    uint8_t session_key[16];
    hex_to_bytes("5675F868C28F4D5DAB636D2076B3C764", session_key);
    DfcSecureMessaging* sm = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_ISO, session_key, sizeof(session_key), NULL);
    DfcSecureMessaging* reader = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_ISO, session_key, sizeof(session_key), NULL);

    uint8_t file_no[] = {0x0f};
    dfc_secure_messaging_update_ev1_command(
        sm, DFC_CMD_GET_FILE_SETTINGS, file_no, sizeof(file_no));
    dfc_secure_messaging_update_ev1_command(
        reader, DFC_CMD_GET_FILE_SETTINGS, file_no, sizeof(file_no));

    uint8_t settings[] = {0x00, 0x01, 0x12, 0x30, 0x33, 0x00, 0x00};
    uint8_t wrapped[DFC_SM_MAX_SIZE];
    size_t wrapped_len = dfc_secure_messaging_generate_ev1_response(
        sm, DFC_STATUS_OK, settings, sizeof(settings), wrapped, sizeof(wrapped));

    uint8_t expected[] = {
        0x00, 0x01, 0x12, 0x30, 0x33, 0x00, 0x00, 0xcd, 0x69, 0x3f, 0x57, 0x7b, 0x9a, 0x04, 0xf4};

    munit_assert_size(wrapped_len, ==, sizeof(expected));
    munit_assert_memory_equal(sizeof(expected), wrapped, expected);

    uint8_t recovered[sizeof(settings)];
    size_t recovered_len = dfc_secure_messaging_unwrap_ev1_response(
        reader, DFC_STATUS_OK, expected, sizeof(expected), recovered, sizeof(recovered));
    munit_assert_size(recovered_len, ==, sizeof(settings));
    munit_assert_memory_equal(sizeof(settings), recovered, settings);

    for(size_t index = sizeof(settings); index < sizeof(expected); index++) {
        uint8_t corrupted[sizeof(expected)];
        memcpy(corrupted, expected, sizeof(corrupted));
        corrupted[index] ^= 1;
        DfcSecureMessaging* verifier = dfc_secure_messaging_alloc(
            DFC_CMD_AUTHENTICATE_ISO, session_key, sizeof(session_key), NULL);
        munit_assert_true(dfc_secure_messaging_update_ev1_command(
            verifier, DFC_CMD_GET_FILE_SETTINGS, file_no, sizeof(file_no)));
        munit_assert_size(
            dfc_secure_messaging_unwrap_ev1_response(
                verifier, DFC_STATUS_OK, corrupted, sizeof(corrupted), recovered, sizeof(recovered)),
            ==,
            SIZE_MAX);
        dfc_secure_messaging_free(verifier);
    }

    dfc_secure_messaging_free(reader);
    dfc_secure_messaging_free(sm);
    return MUNIT_OK;
}

static MunitResult
    test_ev1_get_file_settings_matches_second_reference_vector(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;

    uint8_t session_key[16];
    hex_to_bytes("7DCA9F5BD5FEEBE1D837A927ADAD0227", session_key);
    DfcSecureMessaging* sm = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_ISO, session_key, sizeof(session_key), NULL);

    uint8_t file_no[] = {0x0f};
    dfc_secure_messaging_update_ev1_command(
        sm, DFC_CMD_GET_FILE_SETTINGS, file_no, sizeof(file_no));

    uint8_t settings[] = {0x00, 0x01, 0x12, 0x30, 0x33, 0x00, 0x00};
    uint8_t wrapped[DFC_SM_MAX_SIZE];
    size_t wrapped_len = dfc_secure_messaging_generate_ev1_response(
        sm, DFC_STATUS_OK, settings, sizeof(settings), wrapped, sizeof(wrapped));

    uint8_t expected[] = {
        0x00, 0x01, 0x12, 0x30, 0x33, 0x00, 0x00, 0x27, 0xde, 0x15, 0x26, 0xf2, 0xbf, 0x84, 0x0f};

    munit_assert_size(wrapped_len, ==, sizeof(expected));
    munit_assert_memory_equal(sizeof(expected), wrapped, expected);

    dfc_secure_messaging_free(sm);
    return MUNIT_OK;
}

static MunitResult test_ev1_transmitted_command_mac_round_trip(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    uint8_t key[16];
    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)(0x50 + i);

    DfcSecureMessaging* writer =
        dfc_secure_messaging_alloc(DFC_CMD_AUTHENTICATE_AES, key, sizeof(key), NULL);
    DfcSecureMessaging* reader =
        dfc_secure_messaging_alloc(DFC_CMD_AUTHENTICATE_AES, key, sizeof(key), NULL);

    uint8_t body[] = {0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0xDE, 0xAD};
    dfc_secure_messaging_update_ev1_command(writer, DFC_CMD_WRITE_DATA, body, sizeof(body));
    uint8_t mact[8];
    memcpy(mact, writer->iv, 8);

    uint8_t framed[sizeof(body) + 8];
    memcpy(framed, body, sizeof(body));
    memcpy(framed + sizeof(body), mact, 8);

    size_t clear_len = dfc_secure_messaging_verify_ev1_transmitted_command_mac(
        reader, DFC_CMD_WRITE_DATA, framed, sizeof(framed));
    munit_assert_size(clear_len, ==, sizeof(body));
    munit_assert_memory_equal(16, reader->iv, writer->iv);

    framed[0] ^= 0x01;
    DfcSecureMessaging* reader2 =
        dfc_secure_messaging_alloc(DFC_CMD_AUTHENTICATE_AES, key, sizeof(key), NULL);
    munit_assert_size(
        dfc_secure_messaging_verify_ev1_transmitted_command_mac(
            reader2, DFC_CMD_WRITE_DATA, framed, sizeof(framed)),
        ==,
        SIZE_MAX);

    dfc_secure_messaging_free(writer);
    dfc_secure_messaging_free(reader);
    dfc_secure_messaging_free(reader2);
    return MUNIT_OK;
}

static MunitResult
    test_ev1_enciphered_response_crc_covers_plain_and_status(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;

    uint8_t key[16];
    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)(0x10 + i);

    DfcSecureMessaging* sm =
        dfc_secure_messaging_alloc(DFC_CMD_AUTHENTICATE_AES, key, sizeof(key), NULL);

    uint8_t plain[] = {0x30, 0x2F, 0x81, 0x02, 0x0C};
    uint8_t wrapped[DFC_SM_MAX_SIZE];
    size_t wrapped_len = dfc_secure_messaging_generate_response(
        sm, DFC_COMM_ENCIPHERED, DFC_STATUS_OK, plain, sizeof(plain), wrapped, sizeof(wrapped));

    munit_assert_size(wrapped_len, ==, 16);

    uint8_t iv[16] = {0};
    uint8_t clear[16];
    dfc_worker_aes_cbc_decrypt(key, sizeof(key), iv, wrapped_len, wrapped, clear);

    uint8_t crc_input[sizeof(plain) + 1];
    memcpy(crc_input, plain, sizeof(plain));
    crc_input[sizeof(plain)] = DFC_STATUS_OK;
    uint32_t expected_crc = test_crc32_dfc(crc_input, sizeof(crc_input));

    munit_assert_memory_equal(sizeof(plain), clear, plain);
    munit_assert_uint8(clear[sizeof(plain)], ==, (uint8_t)(expected_crc & 0xFF));
    munit_assert_uint8(clear[sizeof(plain) + 1], ==, (uint8_t)((expected_crc >> 8) & 0xFF));
    munit_assert_uint8(clear[sizeof(plain) + 2], ==, (uint8_t)((expected_crc >> 16) & 0xFF));
    munit_assert_uint8(clear[sizeof(plain) + 3], ==, (uint8_t)((expected_crc >> 24) & 0xFF));

    dfc_secure_messaging_free(sm);
    return MUNIT_OK;
}

// An EV1 session covers the command header, so redirecting a write to another
// file, offset or length must not verify. Without header coverage the payload
// alone authenticates and the header is free to rewrite in flight.
static MunitResult header_tamper_rejected(uint8_t comm_mode) {
    DfcSecureMessaging* sm_reader = alloc_session(DFC_CMD_AUTHENTICATE_AES, 16);
    sm_reader->pcd = true;
    DfcSecureMessaging* sm_emulator = alloc_session(DFC_CMD_AUTHENTICATE_AES, 16);

    uint8_t header[] = {DFC_CMD_WRITE_DATA, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00};
    uint8_t plain[] = {0xde, 0xad, 0xbe, 0xef};
    uint8_t wrapped[DFC_SM_MAX_SIZE];
    size_t wrapped_len = dfc_secure_messaging_wrap(
        sm_reader,
        comm_mode,
        header,
        sizeof(header),
        plain,
        sizeof(plain),
        wrapped,
        sizeof(wrapped));

    uint8_t tampered[sizeof(header)];
    memcpy(tampered, header, sizeof(header));
    tampered[1] = 0x02; // same payload, different file

    uint8_t recovered[DFC_SM_MAX_SIZE];
    size_t recovered_len = dfc_secure_messaging_verify_command(
        sm_emulator,
        comm_mode,
        tampered,
        sizeof(tampered),
        wrapped,
        wrapped_len,
        recovered,
        sizeof(recovered));

    munit_assert_size(recovered_len, ==, 0);

    dfc_secure_messaging_free(sm_reader);
    dfc_secure_messaging_free(sm_emulator);
    return MUNIT_OK;
}

static MunitResult test_header_tamper_rejected_mac(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    DfcSecureMessaging* sender = alloc_session(DFC_CMD_AUTHENTICATE_AES, 16);
    DfcSecureMessaging* verifier = alloc_session(DFC_CMD_AUTHENTICATE_AES, 16);
    DfcSecureMessaging* tampered_verifier = alloc_session(DFC_CMD_AUTHENTICATE_AES, 16);
    static const uint8_t command[] = {
        DFC_CMD_WRITE_DATA, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t framed[sizeof(command) - 1 + DFC_WIRE_MAC_LENGTH];

    munit_assert_true(
        dfc_secure_messaging_update_ev1_command_full(sender, command, sizeof(command)));
    memcpy(framed, command + 1, sizeof(command) - 1);
    memcpy(framed + sizeof(command) - 1, sender->iv, DFC_WIRE_MAC_LENGTH);
    munit_assert_size(
        dfc_secure_messaging_verify_ev1_transmitted_command_mac(
            verifier, command[0], framed, sizeof(framed)),
        ==,
        sizeof(command) - 1);

    framed[0] = 0x02; // same payload, different file
    munit_assert_size(
        dfc_secure_messaging_verify_ev1_transmitted_command_mac(
            tampered_verifier, command[0], framed, sizeof(framed)),
        ==,
        SIZE_MAX);

    dfc_secure_messaging_free(tampered_verifier);
    dfc_secure_messaging_free(verifier);
    dfc_secure_messaging_free(sender);
    return MUNIT_OK;
}

static MunitResult test_header_tamper_rejected_enciphered(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    return header_tamper_rejected(DFC_COMM_ENCIPHERED);
}

static MunitResult test_configured_max_boundaries(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const size_t lengths[] = {0, 1, 7, 8, 9, 15, 16, 17, 191, 192, 193, 300, DFC_MAX_FILE_DATA};
    const struct {
        uint8_t cipher;
        size_t key_len;
    } ciphers[] = {
        {DFC_CMD_AUTHENTICATE_LEGACY, 8},
        {DFC_CMD_AUTHENTICATE_ISO, 8},
        {DFC_CMD_AUTHENTICATE_ISO, 16},
        {DFC_CMD_AUTHENTICATE_ISO, 24},
        {DFC_CMD_AUTHENTICATE_AES, 16},
    };
    const uint8_t modes[] = {DFC_COMM_PLAIN, DFC_COMM_MAC, DFC_COMM_ENCIPHERED};
    const size_t buffer_capacity = DFC_SM_MAX_CRYPTO_SIZE + DFC_WIRE_MAC_LENGTH;
    uint8_t* plain = malloc(DFC_MAX_FILE_DATA);
    uint8_t* wrapped = malloc(buffer_capacity);
    uint8_t* recovered = malloc(buffer_capacity);
    munit_assert_not_null(plain);
    munit_assert_not_null(wrapped);
    munit_assert_not_null(recovered);
    for(size_t i = 0; i < DFC_MAX_FILE_DATA; i++)
        plain[i] = (uint8_t)(i * 29u + 7u);
    const uint8_t header[] = {DFC_CMD_WRITE_DATA, 1, 0, 0, 0, 0, 0, 0};

    for(size_t cipher_index = 0; cipher_index < sizeof(ciphers) / sizeof(ciphers[0]);
        cipher_index++) {
        for(size_t mode_index = 0; mode_index < sizeof(modes) / sizeof(modes[0]); mode_index++) {
            for(size_t length_index = 0; length_index < sizeof(lengths) / sizeof(lengths[0]);
                length_index++) {
                size_t length = lengths[length_index];
                DfcSecureMessaging* reader =
                    alloc_session(ciphers[cipher_index].cipher, ciphers[cipher_index].key_len);
                DfcSecureMessaging* card =
                    alloc_session(ciphers[cipher_index].cipher, ciphers[cipher_index].key_len);
                munit_assert_not_null(reader);
                munit_assert_not_null(card);
                reader->pcd = true;

                if(modes[mode_index] == DFC_COMM_MAC &&
                   ciphers[cipher_index].cipher != DFC_CMD_AUTHENTICATE_LEGACY) {
                    dfc_secure_messaging_free(reader);
                    dfc_secure_messaging_free(card);
                    continue;
                }
                size_t wrapped_len = modes[mode_index] == DFC_COMM_MAC ?
                                         dfc_secure_messaging_wrap_d40_command_mac(
                                             reader, plain, length, wrapped, buffer_capacity) :
                                         dfc_secure_messaging_wrap(
                                             reader,
                                             modes[mode_index],
                                             header,
                                             sizeof(header),
                                             plain,
                                             length,
                                             wrapped,
                                             buffer_capacity);
                munit_assert_size(wrapped_len, >=, length);
                size_t recovered_len = 0;
                if(modes[mode_index] == DFC_COMM_MAC) {
                    munit_assert_true(dfc_secure_messaging_verify_d40_command_mac(
                        card, wrapped, wrapped_len, recovered, buffer_capacity, &recovered_len));
                } else {
                    recovered_len = dfc_secure_messaging_verify_command(
                        card,
                        modes[mode_index],
                        header,
                        sizeof(header),
                        wrapped,
                        wrapped_len,
                        recovered,
                        buffer_capacity);
                }
                munit_assert_size(recovered_len, ==, length);
                munit_assert_memory_equal(length, recovered, plain);

                wrapped_len = modes[mode_index] == DFC_COMM_MAC ?
                                  dfc_secure_messaging_generate_d40_response_mac(
                                      card, plain, length, wrapped, buffer_capacity) :
                                  dfc_secure_messaging_generate_response(
                                      card,
                                      modes[mode_index],
                                      DFC_STATUS_OK,
                                      plain,
                                      length,
                                      wrapped,
                                      buffer_capacity);
                munit_assert_size(wrapped_len, >=, length);
                recovered_len = 0;
                bool ok = modes[mode_index] == DFC_COMM_MAC ?
                              dfc_secure_messaging_unwrap_d40_response_mac(
                                  reader,
                                  wrapped,
                                  wrapped_len,
                                  recovered,
                                  buffer_capacity,
                                  &recovered_len) :
                              dfc_secure_messaging_unwrap(
                                  reader,
                                  modes[mode_index],
                                  DFC_STATUS_OK,
                                  wrapped,
                                  wrapped_len,
                                  recovered,
                                  buffer_capacity,
                                  &recovered_len);
                munit_assert_true(ok);
                munit_assert_size(recovered_len, ==, length);
                munit_assert_memory_equal(length, recovered, plain);
                munit_assert_memory_equal(sizeof(reader->iv), reader->iv, card->iv);

                dfc_secure_messaging_free(reader);
                dfc_secure_messaging_free(card);
            }
        }
    }

    // Zero-filled maximum payloads make every old padding candidate look
    // plausible. Keep this worst-case shape in the correctness suite.
    memset(plain, 0, DFC_MAX_FILE_DATA);
    for(size_t cipher_index = 0; cipher_index < sizeof(ciphers) / sizeof(ciphers[0]);
        cipher_index++) {
        DfcSecureMessaging* reader =
            alloc_session(ciphers[cipher_index].cipher, ciphers[cipher_index].key_len);
        DfcSecureMessaging* card =
            alloc_session(ciphers[cipher_index].cipher, ciphers[cipher_index].key_len);
        munit_assert_not_null(reader);
        munit_assert_not_null(card);
        reader->pcd = true;

        size_t wrapped_len = dfc_secure_messaging_wrap(
            reader,
            DFC_COMM_ENCIPHERED,
            header,
            sizeof(header),
            plain,
            DFC_MAX_FILE_DATA,
            wrapped,
            buffer_capacity);
        size_t recovered_len = dfc_secure_messaging_verify_command(
            card,
            DFC_COMM_ENCIPHERED,
            header,
            sizeof(header),
            wrapped,
            wrapped_len,
            recovered,
            buffer_capacity);
        munit_assert_size(recovered_len, ==, DFC_MAX_FILE_DATA);
        munit_assert_memory_equal(DFC_MAX_FILE_DATA, recovered, plain);

        dfc_secure_messaging_free(reader);
        dfc_secure_messaging_free(card);
    }
    free(recovered);
    free(wrapped);
    free(plain);
    return MUNIT_OK;
}

static MunitResult test_initialization_rejects_invalid_cipher_key_pairs(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    static const struct {
        uint8_t cipher;
        size_t key_len;
    } invalid[] = {
        {0x00, 16},
        {DFC_CMD_AUTHENTICATE_LEGACY, 0},
        {DFC_CMD_AUTHENTICATE_LEGACY, 24},
        {DFC_CMD_AUTHENTICATE_ISO, 7},
        {DFC_CMD_AUTHENTICATE_AES, 8},
        {DFC_CMD_AUTHENTICATE_AES, 24},
        // A caller-controlled size must be rejected before it can narrow into
        // the compact session record or copy beyond the fixed key buffer.
        {DFC_CMD_AUTHENTICATE_AES, (size_t)UINT8_MAX + 1u},
    };
    uint8_t key[DFC_MAX_KEY_LEN] = {0};
    for(size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        DfcSecureMessaging sm;
        memset(&sm, 0xA5, sizeof(sm));
        munit_assert_false(
            dfc_secure_messaging_init(&sm, invalid[i].cipher, key, invalid[i].key_len, NULL));
        uint8_t cleared[sizeof(sm)];
        memset(cleared, 0, sizeof(cleared));
        munit_assert_memory_equal(sizeof(sm), &sm, cleared);
        munit_assert_null(
            dfc_secure_messaging_alloc(invalid[i].cipher, key, invalid[i].key_len, NULL));
    }
    munit_assert_false(dfc_secure_messaging_init(NULL, DFC_CMD_AUTHENTICATE_AES, key, 16, NULL));
    return MUNIT_OK;
}

static MunitResult test_output_capacity_fails_before_writes_or_state_changes(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    static const uint8_t header[] = {DFC_CMD_WRITE_DATA, 1};
    static const uint8_t plain[] = {1, 2, 3};
    static const uint8_t modes[] = {DFC_COMM_PLAIN, DFC_COMM_MAC, DFC_COMM_ENCIPHERED};

    for(size_t mode_index = 0; mode_index < sizeof(modes); mode_index++) {
        size_t required = dfc_secure_messaging_command_payload_length(
            &(DfcSecureMessaging){.cipher = DFC_CMD_AUTHENTICATE_AES,
                                  .session_key_len = DFC_AES_KEY_LENGTH},
            false,
            modes[mode_index],
            sizeof(plain));
        for(size_t capacity = 0; capacity <= required; capacity++) {
            DfcSecureMessaging* sm = alloc_session(DFC_CMD_AUTHENTICATE_AES, 16);
            munit_assert_not_null(sm);
            sm->pcd = true;
            DfcSecureMessaging before = *sm;
            uint8_t output[32];
            memset(output, 0xA5, sizeof(output));
            size_t result = dfc_secure_messaging_wrap(
                sm,
                modes[mode_index],
                header,
                sizeof(header),
                plain,
                sizeof(plain),
                output,
                capacity);
            if(modes[mode_index] == DFC_COMM_MAC || capacity < required) {
                munit_assert_size(result, ==, 0);
                munit_assert_memory_equal(sizeof(before), sm, &before);
                uint8_t untouched[sizeof(output)];
                memset(untouched, 0xA5, sizeof(untouched));
                munit_assert_memory_equal(sizeof(output), output, untouched);
            } else {
                munit_assert_size(result, ==, required);
            }
            dfc_secure_messaging_free(sm);
        }
    }

    size_t out_len = 9;
    munit_assert_false(dfc_secure_messaging_unwrap(
        NULL, DFC_COMM_PLAIN, DFC_STATUS_OK, NULL, 0, NULL, 0, &out_len));
    munit_assert_size(out_len, ==, 0);
    munit_assert_size(
        dfc_secure_messaging_unwrap_ev1_response(NULL, DFC_STATUS_OK, NULL, 0, NULL, 0),
        ==,
        SIZE_MAX);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/enciphered/legacy-partial-block-rejection",
     test_legacy_enciphered_rejects_partial_blocks,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/tamper/header_mac",
     test_header_tamper_rejected_mac,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/tamper/header_enciphered",
     test_header_tamper_rejected_enciphered,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/plain/legacy", test_plain_legacy, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/mac/legacy_single_des", test_mac_legacy_single_des, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/mac/legacy_2k3des", test_mac_legacy_2k3des, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/mac/d40-empty-response-authentication",
     test_d40_empty_response_is_distinct_from_authentication_failure,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/mac/d40-fixed-vector",
     test_d40_mac_matches_fixed_vector,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/mac/iso_2k3des", test_mac_iso_2k3des, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/mac/iso_3k3des", test_mac_iso_3k3des, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/mac/aes", test_mac_aes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/mac/generic-rejects-all-sessions",
     test_generic_mac_rejects_all_sessions,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/enciphered/legacy", test_enciphered_legacy, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/enciphered/iso", test_enciphered_iso, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/enciphered/aes", test_enciphered_aes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/enciphered/partial-overlap",
     test_enciphered_encode_accepts_partial_overlap,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/boundaries/command-payload-lengths",
     test_command_payload_lengths_match_encoder,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/mac/tamper_rejected", test_mac_tamper_rejected, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/ev1/get_file_settings_response",
     test_ev1_get_file_settings_response_is_mac_protected,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev1/response_unwrap_requires_command_state",
     test_ev1_response_unwrap_requires_command_state,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev1/initial_iv", test_ev1_initial_iv_is_used, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/ev1/get_file_settings_reference_vector",
     test_ev1_get_file_settings_matches_reference_vector,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev1/get_file_settings_second_reference_vector",
     test_ev1_get_file_settings_matches_second_reference_vector,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev1/enciphered_response_crc_plain_and_status",
     test_ev1_enciphered_response_crc_covers_plain_and_status,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev1/transmitted_command_mac_round_trip",
     test_ev1_transmitted_command_mac_round_trip,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/boundaries/configured-max",
     test_configured_max_boundaries,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/contracts/initialization",
     test_initialization_rejects_invalid_cipher_key_pairs,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/contracts/output-capacity",
     test_output_capacity_fails_before_writes_or_state_changes,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {"", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
