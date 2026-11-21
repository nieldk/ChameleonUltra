#ifndef ESB_UNIFYING_H__
#define ESB_UNIFYING_H__

#include <stdbool.h>
#include <stdint.h>

/* Logitech Unifying crypto + HID keymap, on-device. Ported from cli_esb.py
 * (host, verified) and mame82's LOGITacker. AES-128-ECB uses the SoftDevice
 * ECB (sd_ecb_block_encrypt). Used by the esb-prx receiver-emulation mode.
 */

/* Per-frame AES key = AES-ECB(device_key, secret) with the 4-byte counter
 * (frame bytes [10:14], big-endian) spliced into the fixed secret at offset 7. */
void esb_unifying_frame_key(const uint8_t device_key[16], const uint8_t counter[4],
                            uint8_t out[16]);

/* Decrypt a 22-byte encrypted-keyboard payload to its 8-byte HID report.
 * Returns false if it is not an encrypted keyboard frame (type 0xD3). */
bool esb_unifying_decrypt_keyboard(const uint8_t device_key[16],
                                   const uint8_t *payload, uint8_t len,
                                   uint8_t report_out[8]);

/* Map a HID keycode to its US-layout character given the modifier byte.
 * Returns 0 for keys with no printable character. Enter/tab/space come back as
 * '\n' / '\t' / ' '. */
char esb_unifying_keycode_char(uint8_t code, uint8_t mod);

#endif
