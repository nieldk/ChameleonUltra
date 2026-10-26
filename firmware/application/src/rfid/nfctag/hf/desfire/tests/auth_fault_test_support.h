#pragma once

#include "dfc_emulator_i.h"
#include "dfc_virtual_picc.h"

typedef struct {
    DfcCredential credential;
    DfcVirtualPiccSession* session;
    DfcFile* value_file;
} AuthFixture;

typedef struct {
    uint8_t command;
    uint8_t key_type;
    bool ev2;
    bool non_first;
} AuthCase;

extern const AuthCase auth_cases[];
extern const size_t auth_case_count;

extern size_t fail_aes_block_call;
extern size_t fail_des_block_call;
extern size_t fail_aes_cbc_call;
extern size_t fail_des_cbc_call;
extern bool fail_random;
extern bool fail_secure_messaging_allocation;

void auth_faults_clear(void);
void auth_fixture_open(AuthFixture* fixture, const AuthCase* auth_case);
void auth_fixture_close(AuthFixture* fixture);
