/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2026 CinderSocket
 *
 * Drop-in replacement for the mistial-dev/tiny-aes-c header dfc_crypto.c
 * includes, backed by the nRF5 SDK's nrf_crypto (CC310 hardware AES) instead
 * of a software implementation. This is NOT the mbedTLS-shaped shim in
 * ../mbedtls/aes.h -- dfc_crypto.c calls tiny-aes-c's native names directly
 * (AES_init_ctx_iv, AES_CBC_encrypt, ...), never anything mbedtls_*, so that
 * shim is never on this backend's include path.
 *
 * AES-128 CBC only, matching the DFC_BUILD_PROFILE this firmware ships:
 * dfc_crypto.c static-asserts AES_KEYLEN == 16 and never references AES192 /
 * AES256, so no 192/256 path is implemented here.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCKLEN 16u
#define AES_KEYLEN   16u

/* Success code for AES_CBC_encrypt/AES_CBC_decrypt's int return, which
 * dfc_crypto.c compares against directly. */
#define AES_OK 0

/* Holds only what a CC310 one-shot crypt call needs per operation: the raw
 * key and the running IV. There is no precomputed round-key schedule here
 * (unlike software tiny-aes-c) since nrf_crypto derives it internally. */
struct AES_ctx {
    uint8_t key[AES_KEYLEN];
    uint8_t Iv[AES_BLOCKLEN];
};

/* Initializes ctx with key + iv. There is no plain AES_init_ctx (no-IV) here
 * because dfc_crypto.c only ever calls the _iv form. */
void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv);

/* In-place CBC transform of `buf`, `length` bytes (must be a multiple of
 * AES_BLOCKLEN). On return, ctx->Iv holds the trailing ciphertext block, so
 * the caller can chain another call or read it back out as the new IV --
 * mirroring what dfc_crypto.c does via `memcpy(iv, ctx.Iv, AES_BLOCKLEN)`.
 * Returns AES_OK on success. */
int AES_CBC_encrypt(struct AES_ctx *ctx, uint8_t *buf, size_t length);
int AES_CBC_decrypt(struct AES_ctx *ctx, uint8_t *buf, size_t length);

/* Zeroes the key and IV. dfc_crypto.c calls this on every path (success and
 * failure) so key material never lingers on the stack. */
void AES_ctx_clear(struct AES_ctx *ctx);
