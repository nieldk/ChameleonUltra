#ifndef GDB_RSP_H
#define GDB_RSP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* GDB "memory/flash gateway": a GDB Remote Serial Protocol server that runs on
 * the device's USB-CDC or BLE NUS link, whichever is up. It exposes memory
 * read/write and flash programming (gdb `load`, `dump`, `x`, `set`) to
 * arm-none-eabi-gdb over `target remote` - no SWD probe and no external
 * connections. There is NO execution control: no breakpoints, single-step or
 * run; the core keeps running the firmware while gdb pokes at it. Flash
 * writes go through the SoftDevice (nrf_fstorage) and are bounded by ACL and
 * by the obvious hazard that erasing the running app's own pages is
 * self-destructive. */

/* Driven by the gdb_gateway standalone mode: on_enter -> gdb_rsp_enter(),
 * on_exit -> gdb_rsp_leave(). While entered, the active link (USB-CDC or BLE
 * NUS) is parsed as GDB RSP instead of the framed CLI protocol; replies go
 * out the same link they came in on (usb_main.c / ble_main.c pick the
 * transport, same as the normal CLI's auto_response_data). Arming/disarming
 * is the normal standalone workflow: a both-buttons long press
 * (app_standalone_on_button), or the host commands STANDALONE_TRIGGER/
 * STANDALONE_DISARM (app_standalone_trigger()/_disarm(), app_standalone.c)
 * -- the latter is how the web terminal's `hw gdb arm`/`disarm` work with no
 * button press at all. Detaching gdb just leaves the link idle, ready to
 * reconnect, until the mode is disarmed. */
void gdb_rsp_enter(void);
void gdb_rsp_leave(void);

/* True while the active link should be treated as GDB RSP. */
bool gdb_rsp_active(void);

/* Feed received bytes from whichever link is active. Called from the
 * USB-CDC or BLE NUS RX handler when active. */
void gdb_rsp_rx(const uint8_t *data, size_t len);

#endif
