/*
 * mode_usb_net.c
 *
 * Standalone mode: USB Ethernet (CDC-ECM or RNDIS). While armed the device re-enumerates
 * with an extra network interface; the host gets 192.168.16.2 over DHCP and the
 * device answers at 192.168.16.1. TCP port 18888 carries the normal framed CLI
 * protocol, so the python CLI connects with
 *
 *     hw connect -p tcp:192.168.16.1:18888
 *
 * The CDC serial port stays available. While a TCP client is connected it owns
 * the command link and replies go to it. Disarm (TOGGLE button, `standalone
 * disarm` over TCP or BLE) re-enumerates back to the serial-only device.
 *
 * Needs STANDALONE_USB_NET=1 (TinyUSB + lwIP build, see usb_main_tusb.c).
 */

#include "app_standalone.h"
#include "usb_main.h"

#include "nrf_log.h"

static standalone_rc_t on_enter(const uint8_t *cfg, size_t cfg_len) {
    (void)cfg;
    (void)cfg_len;
    usbnet_enable(true);
    NRF_LOG_INFO("usb_net: armed, USB Ethernet after re-enumeration");
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_exit(void) {
    usbnet_enable(false);
    NRF_LOG_INFO("usb_net: disarmed, back to serial only");
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_button(standalone_button_evt_t evt) {
    (void)evt;   /* no on-device action */
    return STANDALONE_RC_OK;
}

const standalone_mode_iface_t mode_usb_net_iface = {
    .id              = STANDALONE_MODE_USB_NET,
    .name            = "usb_net",
    .writes_tag      = false,
    .writes_slot     = false,
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
