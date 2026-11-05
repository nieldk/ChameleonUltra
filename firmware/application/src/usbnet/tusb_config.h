/* TinyUSB configuration for the usb_net build (STANDALONE_USB_NET=1). */
#pragma once

#define CFG_TUSB_MCU             OPT_MCU_NRF5X
#define CFG_TUSB_OS              OPT_OS_NONE
#define CFG_TUSB_DEBUG           0
/* nRF5 SDK 17.1 ships MDK 8.40.3 = nrfx 1.9.x */
#define CFG_TUD_NRF_NRFX_VERSION 1

#define CFG_TUD_ENABLED          1
#define CFG_TUD_MAX_SPEED        OPT_MODE_FULL_SPEED
#define CFG_TUD_ENDPOINT0_SIZE   64

#define CFG_TUD_CDC              1
#define CFG_TUD_CDC_EP_BUFSIZE   64
#define CFG_TUD_CDC_RX_BUFSIZE   256
#define CFG_TUD_CDC_TX_BUFSIZE   512

#define CFG_TUD_ECM_RNDIS        1
#define CFG_TUD_NCM              0
/* Frame size reported to the host. 600 holds a full TCP segment (MSS 536 + 40
 * + 14) and saves ~1.8 KB; the Makefile sets 1514 for RNDIS, which Windows
 * needs. Override with USBNET_MTU. */
#ifndef CFG_TUD_NET_MTU
#define CFG_TUD_NET_MTU          600
#endif

#define CFG_TUD_MSC              0
#define CFG_TUD_HID              0
#define CFG_TUD_MIDI             0
#define CFG_TUD_VENDOR           0
