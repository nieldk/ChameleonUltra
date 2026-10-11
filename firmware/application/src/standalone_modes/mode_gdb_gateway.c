/*
 * mode_gdb_gateway.c
 *
 * Standalone mode: a GDB memory/flash gateway on the device's own USB-CDC link.
 * While armed, the CDC link speaks the GDB Remote Serial Protocol instead of
 * the framed CLI protocol (see utils/gdb_rsp.c), so arm-none-eabi-gdb can
 * `target remote` this Chameleon and read/write memory and program flash
 * (gdb `load`/`dump`/`x`/`set`). No SWD, no external connections, no execution
 * control (no breakpoints/step) -- the firmware keeps running while gdb pokes.
 *
 * Arm/disarm through the normal standalone workflow (both-button long press).
 * Arming requires the host opt-in flag because the gateway can program
 * arbitrary flash (writes_slot is set purely to force that gate).
 *
 * Danger: `load` to the running app's own pages, or to an ACL-locked region,
 * behaves exactly as everywhere else -- self-erase crashes, ACL refuses.
 */

#include "app_standalone.h"
#include "gdb_rsp.h"

#include "nrf_log.h"

static standalone_rc_t on_enter(const uint8_t *cfg, size_t cfg_len) {
    (void)cfg;
    (void)cfg_len;
    gdb_rsp_enter();
    NRF_LOG_INFO("gdb_gateway: armed, CDC is now GDB RSP");
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_exit(void) {
    gdb_rsp_leave();
    NRF_LOG_INFO("gdb_gateway: disarmed, CDC back to CLI");
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_button(standalone_button_evt_t evt) {
    (void)evt;   /* no on-device action; all work is over USB */
    return STANDALONE_RC_OK;
}

const standalone_mode_iface_t mode_gdb_gateway_iface = {
    .id              = STANDALONE_MODE_GDB_GATEWAY,
    .name            = "gdb_gateway",
    .writes_tag      = false,
    .writes_slot     = true,    /* forces host opt-in; the gateway can flash */
    .wants_tick      = false,
    .on_enter        = on_enter,
    .on_exit         = on_exit,
    .on_button       = on_button,
    .on_tick         = NULL,
    .get_result_size = NULL,
    .read_result     = NULL,
    .clear_result    = NULL,
    .ensure_loaded   = NULL,
};
