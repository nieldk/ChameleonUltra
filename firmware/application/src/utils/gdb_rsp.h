#ifndef GDB_RSP_H
#define GDB_RSP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* GDB "memory/flash gateway": a GDB Remote Serial Protocol server that runs on
 * the device's own USB-CDC link. It exposes memory read/write and flash
 * programming (gdb `load`, `dump`, `x`, `set`) to arm-none-eabi-gdb over
 * `target remote` - no SWD probe and no external connections. There is NO
 * execution control: no breakpoints, single-step or run; the core keeps
 * running the firmware while gdb pokes at it. Flash writes go through the
 * SoftDevice (nrf_fstorage) and are bounded by ACL and by the obvious hazard
 * that erasing the running app's own pages is self-destructive. */

/* Driven by the gdb_gateway standalone mode: on_enter -> gdb_rsp_enter(),
 * on_exit -> gdb_rsp_leave(). While entered, the CDC link is parsed as GDB
 * RSP instead of the framed CLI protocol. The mode is armed/disarmed through
 * the normal standalone workflow (both-button long press), so the gateway
 * never self-disarms; detaching gdb just leaves the link idle, ready to
 * reconnect, until the mode is disarmed. */
void gdb_rsp_enter(void);
void gdb_rsp_leave(void);

/* True while the CDC link should be treated as GDB RSP. */
bool gdb_rsp_active(void);

/* Feed received CDC bytes. Called from the CDC RX handler when active. */
void gdb_rsp_rx(const uint8_t *data, size_t len);

#endif
