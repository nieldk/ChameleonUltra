#include "munit.h"

#include "dfc_crypto_internal.h"

#include <string.h>

static size_t crypt_call;
static size_t clear_call;
static size_t wipe_call;
static size_t fail_at;

void dfc_secure_wipe(void* data, size_t len) {
    memset(data, 0, len);
    wipe_call++;
}

bool dfc_crypto_des_block_init(
    DfcCryptoDesBlock* block,
    bool encrypt,
    const uint8_t* key,
    size_t key_len) {
    memset(block, 0x5a, sizeof(*block));
    block->encrypt = encrypt;
    block->key_len = key_len;
    block->initialized = key && (key_len == 8 || key_len == 16 || key_len == 24);
    crypt_call = 0;
    return block->initialized;
}

bool dfc_crypto_des_block_crypt(
    DfcCryptoDesBlock* block,
    const uint8_t input[8],
    uint8_t output[8]) {
    munit_assert_true(block->initialized);
    crypt_call++;
    if(crypt_call == fail_at) return false;
    for(size_t i = 0; i < 8; i++)
        output[i] = input[i] ^ (uint8_t)(0x31 + crypt_call);
    return true;
}

void dfc_crypto_des_block_clear(DfcCryptoDesBlock* block) {
    memset(block, 0, sizeof(*block));
    clear_call++;
}

static MunitResult
    test_failure_positions_wipe_output(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    const uint8_t key[24] = {0};
    const uint8_t iv[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const uint8_t input[24] = {0};
    uint8_t output[24];
    const uint8_t zero[24] = {0};

    for(size_t key_len = 8; key_len <= sizeof(key); key_len += 8) {
        for(size_t encrypt = 0; encrypt < 2; encrypt++) {
            for(size_t direction = DfcCryptoDesChainForward; direction <= DfcCryptoDesChainReverse;
                direction++) {
                for(fail_at = 1; fail_at <= 3; fail_at++) {
                    clear_call = 0;
                    wipe_call = 0;
                    memset(output, 0xa5, sizeof(output));
                    munit_assert_false(dfc_crypto_des_chain(
                        encrypt, direction, key, key_len, iv, input, output, sizeof(output)));
                    munit_assert_memory_equal(sizeof(output), output, zero);
                    munit_assert_size(clear_call, ==, 1);
                    munit_assert_size(wipe_call, ==, 3);
                }
            }
        }
    }
    return MUNIT_OK;
}

static MunitResult test_invalid_init_wipes_output_and_clears_state(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    const uint8_t key[12] = {0};
    const uint8_t iv[8] = {0};
    const uint8_t input[8] = {0};
    const uint8_t zero[8] = {0};
    uint8_t output[8];

    clear_call = 0;
    wipe_call = 0;
    fail_at = 0;
    memset(output, 0xa5, sizeof(output));
    munit_assert_false(dfc_crypto_des_chain(
        true, DfcCryptoDesChainForward, key, sizeof(key), iv, input, output, sizeof(output)));
    munit_assert_memory_equal(sizeof(output), output, zero);
    munit_assert_size(clear_call, ==, 1);
    munit_assert_size(wipe_call, ==, 3);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/all-blocks", test_failure_positions_wipe_output, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/init",
     test_invalid_init_wipes_output_and_clears_state,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {"/des-chain-failure", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
