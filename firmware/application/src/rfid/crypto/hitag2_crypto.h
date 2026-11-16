#ifndef HITAG2_CRYPTO_H
#define HITAG2_CRYPTO_H

#include <stdbool.h>
#include <stdint.h>

/* -----------------------------------------------------------------------
 * Hitag2's crypto-mode stream cipher: a 48-bit LFSR with a nonlinear
 * filter function, the same one Verdult/Garcia/Balasch broke in 2012
 * ("Gone in 360 Seconds"). This is only the bit-by-bit/byte generator --
 * the simple, real-time path a reader or an emulated tag needs with a
 * KNOWN key -- not the rollback/fast-nstep machinery proxmark3 also
 * carries for offline key recovery.
 *
 * Ported from RfidResearchGroup/proxmark3's common/hitag2/hitag2_crypto.c
 * (functions ht2_hitag2_init/bit/byte/cipher_authenticate/cipher_transcrypt),
 * which itself credits "a modified version of cryptolib.com/ciphers/hitag2/,
 * software optimized 48-bit Philips/NXP Hitag2 stream cipher by I.C. Wiener
 * 2006-2007, released into the public domain". Not derived from a datasheet
 * guess.
 * --------------------------------------------------------------------- */

/* Initialises a cipher state from the shared 48-bit key, the tag's 32-bit
 * UID and a 32-bit nonce (IV). All three must already be bit-reversed
 * (hitag2_rev32/hitag2_rev64 below) from their on-the-wire/stored byte
 * order -- the published algorithm numbers the LFSR MSB-first, opposite of
 * how this codebase (and the wire protocol) keeps a page's bytes. */
uint64_t hitag2_crypto_init(uint64_t key, uint32_t uid, uint32_t iv);

/* Advances the state by one bit and returns that bit of keystream. */
int hitag2_crypto_bit(uint64_t *state);

/* Advances the state by 8 bits and returns them as one keystream byte,
 * MSB first (same bit order cipher_transcrypt's byte loop consumes). */
uint8_t hitag2_crypto_byte(uint64_t *state);

/* Checks a 4-byte authenticator (the tag's expected Ar, or the reader's
 * expected tag-password echo) against ~keystream -- Hitag2 sends the
 * bit-complement of the first 4 keystream bytes as the authenticator.
 * Always advances the state by 32 bits, whether or not it matches. */
bool hitag2_crypto_check_auth(uint64_t *state, const uint8_t authenticator[4]);

/* Writes a 4-byte authenticator (the complement of the next 4 keystream
 * bytes) into out. Always advances the state by 32 bits. */
void hitag2_crypto_build_auth(uint64_t *state, uint8_t out[4]);

/* XORs `bytes` whole bytes and then `bits` further bits of `data` in place
 * with the next keystream bits -- the same operation encrypts or decrypts,
 * since XOR is its own inverse. `data` must hold at least bytes + (bits
 * ? 1 : 0) bytes. */
void hitag2_crypto_transcrypt(uint64_t *state, uint8_t *data, uint16_t bytes, uint16_t bits);

/* Full bit reversal (not byte-swap) of a 32/64-bit word, built from this
 * codebase's own byte_mirror table (byte_mirror.h). proxmark3's REV32/REV64
 * macros do the same thing; this just gets there with the per-byte
 * reversal table this tree already has instead of re-deriving one. */
uint32_t hitag2_rev32(uint32_t x);
uint64_t hitag2_rev64(uint64_t x);

#endif
