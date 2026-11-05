#ifndef USB_MAIN_H
#define USB_MAIN_H

#include <stdint.h>
#include <stdbool.h>

void usb_cdc_init(void);
void usb_cdc_write(const void *p_buf, uint16_t length);
bool is_usb_working(void);

/* Called from main(): enable USB power events once the SoftDevice is up, and
 * service the USB stack from the main loop. */
void usb_power_events_enable(void);
void usb_poll(void);

/* usb_net standalone mode: CLI frames over a TCP stream on USB Ethernet. */
#if CONFIG_STANDALONE_USB_NET
void usbnet_enable(bool on);          /* switch USB profile; applied from usb_poll() */
bool usbnet_client_active(void);      /* a TCP client is connected */
void usbnet_write(const void *p_buf, uint16_t length);
#else
#define usbnet_client_active() false
#define usbnet_write(buf, len) ((void)0)
#endif

#endif
