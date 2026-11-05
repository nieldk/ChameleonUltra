/* usb_net: lwIP on the TinyUSB ECM/RNDIS interface; CLI frames over one TCP stream. */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define USBNET_TCP_PORT 18888   /* default; see usbnet_set_port() */

void usbnet_set_port(uint16_t port);   /* 0 = default; moves a running listener */
void usbnet_start(void);        /* init lwIP/DHCP/TCP once, then run */
void usbnet_stop(void);         /* drop the client, stop servicing */
void usbnet_link_down(void);    /* host detached or reconfigured the USB device */
void usbnet_poll(void);         /* main loop: frames, timers, TCP -> data frames */
bool usbnet_running(void);
size_t usbnet_get_status(char *out, size_t out_max);   /* "key=value\n" lines */
