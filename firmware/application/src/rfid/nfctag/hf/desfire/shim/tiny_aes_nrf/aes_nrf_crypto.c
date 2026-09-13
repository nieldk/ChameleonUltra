/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2026 CinderSocket
 *
 * AES-128 CBC over nrf_crypto (CC310 hardware), exposed under tiny-aes-c's
 * native call surface so dfc_crypto.c needs no changes. Same nrf_crypto_aes_crypt
 * one-shot pattern already used in nfc_seos.c and in ../mbedtls_compat.c's
 * (unused, mbedTLS-shaped) AES path -- this is that same backend, renamed to
 * the symbols dfc_crypto.c actually calls.
 */

#include "aes.h"

#include <string.h>

#include "nrf_crypto_init.h"
#include "nrf_crypto_aes.h"
#include "sdk_errors.h"

/* Single card emulated at a time, same assumption ../mbedtls_compat.c made. */
static nrf_crypto_aes_context_t s_aes_ctx;

static void aes_ensure_init(void) {
    static bool ready = false;
    if (ready) return;
    ret_code_t rc = nrf_crypto_init();
    /* Already initialised elsewhere (e.g. SEOS/boot) is fine. */
    if (rc == NRF_SUCCESS || rc == NRF_ERROR_MODULE_ALREADY_INITIALIZED) {
        ready = true;
    }
}

void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv) {
    aes_ensure_init();
    memcpy(ctx->key, key, AES_KEYLEN);
    memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}

static int aes_cbc(struct AES_ctx *ctx, uint8_t *buf, size_t length, nrf_crypto_operation_t op) {
    if (length == 0) return AES_OK;
    if (length % AES_BLOCKLEN != 0) return -1;

    /* nrf_crypto_aes_crypt is one-shot per call and does not reliably hand
     * back an updated IV, so -- exactly as in ../mbedtls_compat.c -- compute
     * the next IV ourselves. For decrypt, the trailing ciphertext is the last
     * INPUT block, which must be captured before the in-place transform
     * overwrites it. */
    uint8_t next_iv[AES_BLOCKLEN];
    if (op == NRF_CRYPTO_DECRYPT) {
        memcpy(next_iv, buf + length - AES_BLOCKLEN, AES_BLOCKLEN);
    }

    uint8_t iv_local[AES_BLOCKLEN];
    memcpy(iv_local, ctx->Iv, AES_BLOCKLEN);

    size_t out_len = length;
    ret_code_t rc = nrf_crypto_aes_crypt(
        &s_aes_ctx, &g_nrf_crypto_aes_cbc_128_info, op,
        ctx->key, iv_local,
        buf, length,
        buf, &out_len);
    if (rc != NRF_SUCCESS) return -1;

    if (op == NRF_CRYPTO_ENCRYPT) {
        memcpy(ctx->Iv, buf + length - AES_BLOCKLEN, AES_BLOCKLEN);
    } else {
        memcpy(ctx->Iv, next_iv, AES_BLOCKLEN);
    }
    return AES_OK;
}

int AES_CBC_encrypt(struct AES_ctx *ctx, uint8_t *buf, size_t length) {
    return aes_cbc(ctx, buf, length, NRF_CRYPTO_ENCRYPT);
}

int AES_CBC_decrypt(struct AES_ctx *ctx, uint8_t *buf, size_t length) {
    return aes_cbc(ctx, buf, length, NRF_CRYPTO_DECRYPT);
}

void AES_ctx_clear(struct AES_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}
