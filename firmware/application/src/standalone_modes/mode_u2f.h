/*
 * mode_u2f.h — FIDO U2F standalone mode: runtime attestation provisioning.
 */
#ifndef MODE_U2F_H
#define MODE_U2F_H

#include <stdint.h>
#include <stdbool.h>

/* Store the attestation private key (32 bytes) and cert (DER, <= 512 bytes)
 * into FDS so they override the compiled fallback — no recompile needed.
 * Returns false on bad length or FDS failure. */
bool u2f_set_attestation(const uint8_t *priv, const uint8_t *cert, uint16_t cert_len);

#endif /* MODE_U2F_H */
