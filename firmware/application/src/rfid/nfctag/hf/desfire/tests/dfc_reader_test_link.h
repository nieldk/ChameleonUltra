// Shared fixture for the reader tests: one virtual card holding an application
// per authentication family, and a loopback that carries every frame the reader
// builds to it, so tests exercise the reader against the card, not a script.

#pragma once

#include "munit/munit.h"

#include "dfc_credential.h"
#include "dfc_reader.h"
#include "dfc_virtual_picc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

extern const uint8_t AID_AES[3];
extern const uint8_t AID_ISO[3];
extern const uint8_t AID_3K[3];
extern const uint8_t AID_D40[3];

extern const uint8_t AES_KEY_0[16];
extern const uint8_t AES_KEY_1[16];
extern const uint8_t TDES_KEY_0[16];
extern const uint8_t TDES3_KEY_0[24];
extern const uint8_t DES_KEY_0[16];

enum {
    FilePlain = 0x01,
    FileMac = 0x02,
    FileFull = 0x03,
    FileValueMac = 0x04,
    FileValueFull = 0x05,
    FileLong = 0x06,
    FileRecordFull = 0x07,
};

#define LONG_FILE_SIZE     100
#define D40_LONG_READ_SIZE 300

typedef struct {
    DfcCredential credential;
    DfcVirtualPiccSession* picc;
    DfcReaderSession session;
    DfcReaderFraming framing;
} Link;

void add_data_file(DfcCredential* c, size_t app, uint8_t number, uint8_t comm, size_t size);
void link_open(Link* link, DfcGeneration generation, DfcReaderFraming framing);
void link_close(Link* link);
// Run an exchange to completion against the card. Set DFC_READER_TRACE to print
// every frame the loopback carries.
DfcReaderStatus link_run(Link* link, DfcReaderExchange* ex);
DfcReaderStatus
    link_send(Link* link, const DfcCommand* command, uint8_t comm, DfcReaderExchange* ex);
void select_app(Link* link, const uint8_t aid[3]);
DfcReaderStatus
    authenticate(Link* link, uint8_t cipher, uint8_t key_no, const uint8_t* key, size_t key_len);

#if DFC_ENABLE_EV2_SECURE_MESSAGING
DfcReaderStatus authenticate_ev2(Link* link, bool first, uint8_t key_no, const uint8_t key[16]);
#endif
