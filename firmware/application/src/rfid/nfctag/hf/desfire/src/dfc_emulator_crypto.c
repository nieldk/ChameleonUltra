#include "dfc_emulator_i.h"
#include "dfc_crypto_internal.h"

#include <string.h>

#if DFC_ENABLE_EMULATOR

uint32_t dfc_emulator_read_uint24_le(const uint8_t* data) {
#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(_WIN32)
    uint16_t low;
    memcpy(&low, data, sizeof(low));
    return (uint32_t)low | ((uint32_t)data[2] << 16);
#else
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16);
#endif
}

bool dfc_emulator_d40_receive_plain(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* encrypted,
    size_t encrypted_len,
    uint8_t* plain) {
    uint8_t previous[8] = {0};
    uint8_t block[8] = {0};
    DfcCryptoDesBlock cipher = {0};
    bool ok = false;
    if(!key || !encrypted || !plain || encrypted_len % 8 != 0) goto cleanup;
    ok = dfc_crypto_des_block_init(&cipher, true, key, key_len);
    if(!ok) {
        dfc_secure_wipe(plain, encrypted_len);
        goto cleanup;
    }
    for(size_t offset = 0; offset < encrypted_len; offset += 8) {
        ok = dfc_crypto_des_block_crypt(&cipher, encrypted + offset, block);
        if(!ok) break;
        for(size_t i = 0; i < 8; i++) {
            plain[offset + i] = block[i] ^ previous[i];
        }
        memcpy(previous, encrypted + offset, sizeof(previous));
    }
    if(!ok) dfc_secure_wipe(plain, encrypted_len);
cleanup:
    dfc_crypto_des_block_clear(&cipher);
    dfc_secure_wipe(previous, sizeof(previous));
    dfc_secure_wipe(block, sizeof(block));
    return ok;
}

uint8_t dfc_emulator_des_key_version(const uint8_t* key) {
    uint8_t version = 0;
    for(size_t i = 0; i < 8; i++) {
        version |= (key[i] & 0x01) << (7 - i);
    }
    return version;
}

#endif // DFC_ENABLE_EMULATOR
