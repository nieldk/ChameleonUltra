/*
 * usb_main_tusb.c - USB device on TinyUSB, used instead of usb_main.c when
 * STANDALONE_USB_NET=1.
 *
 * Normal profile: one CDC-ACM serial port, same VID/PID and API as usb_main.c.
 * usb_net profile: CDC-ACM + CDC-ECM or RNDIS Ethernet. Entering or leaving the mode
 * re-enumerates the device with the other configuration descriptor.
 */

#include "usb_main.h"
#include "usbnet/usbnet.h"
#include "syssleep.h"
#include "dataframe.h"
#if CONFIG_STANDALONE_GDB_GATEWAY
#include "gdb_rsp.h"
#endif

#include "tusb.h"
#include "nrf.h"
#include "nrf_soc.h"
#include "nrf_drv_clock.h"
#include "nrf_drv_power.h"
#include "app_timer.h"
#include "app_util_platform.h"

#define NRF_LOG_MODULE_NAME usb_tusb
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
NRF_LOG_MODULE_REGISTER();

extern char g_extern_product_str[];
extern void tusb_hal_nrf_power_event(uint32_t event);   /* tinyusb dcd_nrf5x.c */

volatile bool g_usb_connected = false;
volatile bool g_usb_port_opened = false;
volatile bool g_usb_led_marquee_enable = true;

/* Host-side MAC of the ECM/RNDIS interface; lwIP uses the same with the last bit flipped */
uint8_t tud_network_mac_address[6] = {0x02, 0x43, 0x55, 0x00, 0x00, 0x00};

void USBD_IRQHandler(void) {
    tud_int_handler(0);
}

/* ------------------------------------------------------------------------ */
/* Descriptors                                                               */
/* ------------------------------------------------------------------------ */

enum { STR_LANG = 0, STR_MANUFACTURER, STR_PRODUCT, STR_SERIAL, STR_NET, STR_MAC };

static const tusb_desc_device_t k_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,
    .bDeviceClass       = TUSB_CLASS_MISC,
    .bDeviceSubClass    = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol    = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor           = 0x6868,
    .idProduct          = 0x8686,
    .bcdDevice          = 0x0100,
    .iManufacturer      = STR_MANUFACTURER,
    .iProduct           = STR_PRODUCT,
    .iSerialNumber      = STR_SERIAL,
    .bNumConfigurations = 1,
};

enum { EP_CDC_NOTIF = 0x82, EP_CDC_OUT = 0x01, EP_CDC_IN = 0x81,
       EP_NET_NOTIF = 0x83, EP_NET_OUT = 0x04, EP_NET_IN = 0x84 };

static const uint8_t k_cfg_cdc[] = {
    TUD_CONFIG_DESCRIPTOR(1, 2, 0, TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN,
                          TUSB_DESC_CONFIG_ATT_SELF_POWERED, 100),
    TUD_CDC_DESCRIPTOR(0, 0, EP_CDC_NOTIF, 8, EP_CDC_OUT, EP_CDC_IN, 64),
};

#if USBNET_RNDIS
static const uint8_t k_cfg_net[] = {
    TUD_CONFIG_DESCRIPTOR(1, 4, 0, TUD_CONFIG_DESC_LEN + TUD_RNDIS_DESC_LEN + TUD_CDC_DESC_LEN,
                          TUSB_DESC_CONFIG_ATT_SELF_POWERED, 100),
    TUD_RNDIS_DESCRIPTOR(0, STR_NET, EP_NET_NOTIF, 8, EP_NET_OUT, EP_NET_IN,
                         CFG_TUD_NET_ENDPOINT_SIZE),
    TUD_CDC_DESCRIPTOR(2, 0, EP_CDC_NOTIF, 8, EP_CDC_OUT, EP_CDC_IN, 64),
};
#else
static const uint8_t k_cfg_net[] = {
    TUD_CONFIG_DESCRIPTOR(1, 4, 0, TUD_CONFIG_DESC_LEN + TUD_CDC_ECM_DESC_LEN + TUD_CDC_DESC_LEN,
                          TUSB_DESC_CONFIG_ATT_SELF_POWERED, 100),
    TUD_CDC_ECM_DESCRIPTOR(0, STR_NET, STR_MAC, EP_NET_NOTIF, 64, EP_NET_OUT, EP_NET_IN,
                           CFG_TUD_NET_ENDPOINT_SIZE, CFG_TUD_NET_MTU),
    TUD_CDC_DESCRIPTOR(2, 0, EP_CDC_NOTIF, 8, EP_CDC_OUT, EP_CDC_IN, 64),
};
#endif

static bool m_net_profile;                   /* descriptor set the host currently sees */

const uint8_t *tud_descriptor_device_cb(void) {
    return (const uint8_t *)&k_device;
}

const uint8_t *tud_descriptor_configuration_cb(uint8_t index) {
    if (index) return NULL;
    return m_net_profile ? k_cfg_net : k_cfg_cdc;
}

static void hex(char *out, uint32_t v, int digits) {
    static const char h[] = "0123456789ABCDEF";
    for (int i = 0; i < digits; i++) out[i] = h[(v >> (4 * (digits - 1 - i))) & 0xF];
}

const uint16_t *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void)langid;
    static uint16_t text[40];
    char tmp[32];
    const char *s;

    if (index == STR_LANG) {
        text[0] = (TUSB_DESC_STRING << 8) | 4;
        text[1] = 0x0409;
        return text;
    }
    switch (index) {
        case STR_MANUFACTURER: s = "Proxgrind"; break;
        case STR_PRODUCT:      s = g_extern_product_str; break;
        case STR_SERIAL:       /* same text as the nRF SDK USB serial number */
            hex(tmp, (uint16_t)NRF_FICR->DEVICEADDR[1] | 0xC000, 4);
            hex(tmp + 4, NRF_FICR->DEVICEADDR[0], 8);
            tmp[12] = 0;
            s = tmp;
            break;
        case STR_NET:          s = "Chameleon USB Ethernet"; break;
        case STR_MAC:
            for (int i = 0; i < 6; i++) hex(tmp + 2 * i, tud_network_mac_address[i], 2);
            tmp[12] = 0;
            s = tmp;
            break;
        default:               return NULL;
    }
    uint8_t n = 0;
    while (s[n] && n < 39) {
        text[1 + n] = (uint8_t)s[n];
        n++;
    }
    text[0] = (TUSB_DESC_STRING << 8) | (2 * n + 2);
    return text;
}

/* ------------------------------------------------------------------------ */
/* Power events (SoftDevice owns POWER_CLOCK; nrf_drv_power forwards them)   */
/* ------------------------------------------------------------------------ */

static volatile uint32_t m_power_evts;       /* bit per nrf_drv_power_usb_evt_t, set from IRQ */

static void power_evt(nrf_drv_power_usb_evt_t evt) {
    tusb_hal_nrf_power_event((uint32_t)evt);
    m_power_evts |= 1u << evt;
}

static void power_evts_apply(void) {
    uint32_t evts;
    CRITICAL_REGION_ENTER();
    evts = m_power_evts;
    m_power_evts = 0;
    CRITICAL_REGION_EXIT();
    if (!evts) return;

    if (evts & (1u << NRF_DRV_POWER_USB_EVT_DETECTED)) {
        sleep_timer_stop();
        g_usb_led_marquee_enable = true;
    }
    if (evts & (1u << NRF_DRV_POWER_USB_EVT_READY)) {
        g_usb_connected = true;
    }
    if (evts & (1u << NRF_DRV_POWER_USB_EVT_REMOVED)) {
        sleep_timer_start(SLEEP_DELAY_MS_USB_POWER_DISCONNECTED);
        g_usb_connected = false;
        g_usb_port_opened = false;
        g_usb_led_marquee_enable = false;
        usbnet_link_down();
    }
}

/* ------------------------------------------------------------------------ */
/* CDC                                                                       */
/* ------------------------------------------------------------------------ */

void tud_cdc_line_state_cb(uint8_t itf, bool dtr, bool rts) {
    (void)itf;
    (void)rts;
    g_usb_port_opened = dtr;
    if (!dtr) g_usb_led_marquee_enable = true;
}

void tud_umount_cb(void) {
    g_usb_port_opened = false;
    usbnet_link_down();
}

/* Bytes go to the frame parser one at a time so nothing is dropped while a
 * frame waits for processing; unread bytes stay in the CDC FIFO. */
static void cdc_pump(void) {
    uint8_t b;
    if (usbnet_client_active()) {            /* TCP owns the command link */
        tud_cdc_read_flush();
        return;
    }
    while (tud_cdc_available()) {
#if CONFIG_STANDALONE_GDB_GATEWAY
        if (gdb_rsp_active()) {
            uint8_t buf[64];
            uint32_t n = tud_cdc_read(buf, sizeof(buf));
            gdb_rsp_rx(buf, n);
            continue;
        }
#endif
        if (data_frame_rx_busy()) break;
        if (tud_cdc_read(&b, 1) != 1) break;
        data_frame_receive(&b, 1);
    }
}

void usb_cdc_write(const void *p_buf, uint16_t length) {
    const uint8_t *p = (const uint8_t *)p_buf;
    uint32_t last = app_timer_cnt_get();
    while (length) {
        uint32_t n = tud_cdc_write(p, length);
        if (n) {
            p += n;
            length -= n;
            last = app_timer_cnt_get();
        }
        tud_cdc_write_flush();
        if (!n) {
            if (!tud_cdc_connected() ||
                app_timer_cnt_diff_compute(app_timer_cnt_get(), last) > APP_TIMER_TICKS(1000)) {
                NRF_LOG_WARNING("usb: CDC write stalled, dropping %u bytes", length);
                return;
            }
            tud_task();                      /* let the host drain the FIFO */
        }
    }
}

bool is_usb_working(void) {
    return g_usb_port_opened;
}

/* ------------------------------------------------------------------------ */
/* usb_net profile switch                                                    */
/* ------------------------------------------------------------------------ */

enum { SW_IDLE, SW_WAIT_DISCONNECT, SW_WAIT_CONNECT };
static volatile bool m_want_net;
static volatile bool m_switch_req;
static uint8_t       m_switch_state = SW_IDLE;
static uint32_t      m_switch_t;

#define SWITCH_FLUSH_MS    300u              /* let the command ack leave first */
#define SWITCH_DETACH_MS   500u              /* host must see the detach */

void usbnet_enable(bool on) {
    m_want_net = on;
    m_switch_req = true;
}

static bool elapsed(uint32_t since, uint32_t ms) {
    return app_timer_cnt_diff_compute(app_timer_cnt_get(), since) >= APP_TIMER_TICKS(ms);
}

static void apply_profile(void) {
    m_net_profile = m_want_net;
    if (m_net_profile) usbnet_start(); else usbnet_stop();
}

static void switch_step(void) {
    switch (m_switch_state) {
        case SW_IDLE:
            if (!m_switch_req) return;
            m_switch_req = false;
            if (m_want_net == m_net_profile) return;
            if (!g_usb_connected) {          /* no host on the cable: nothing to re-enumerate */
                apply_profile();
                return;
            }
            m_switch_t = app_timer_cnt_get();
            m_switch_state = SW_WAIT_DISCONNECT;
            break;
        case SW_WAIT_DISCONNECT:
            if (!elapsed(m_switch_t, SWITCH_FLUSH_MS)) return;
            usbnet_stop();
            tud_disconnect();
            m_switch_t = app_timer_cnt_get();
            m_switch_state = SW_WAIT_CONNECT;
            break;
        case SW_WAIT_CONNECT:
            if (!elapsed(m_switch_t, SWITCH_DETACH_MS)) return;
            apply_profile();
            tud_connect();
            m_switch_state = SW_IDLE;
            break;
    }
}

/* ------------------------------------------------------------------------ */
/* Init and main-loop service                                                */
/* ------------------------------------------------------------------------ */

void usb_cdc_init(void) {
    if (!nrf_drv_clock_init_check()) APP_ERROR_CHECK(nrf_drv_clock_init());
    if (!nrf_drv_power_init_check()) APP_ERROR_CHECK(nrf_drv_power_init(NULL));
    /* ECM host MAC: locally administered, unique per device */
    tud_network_mac_address[2] = (uint8_t)(NRF_FICR->DEVICEADDR[1]);
    tud_network_mac_address[3] = (uint8_t)(NRF_FICR->DEVICEADDR[0] >> 16);
    tud_network_mac_address[4] = (uint8_t)(NRF_FICR->DEVICEADDR[0] >> 8);
    tud_network_mac_address[5] = (uint8_t)(NRF_FICR->DEVICEADDR[0] & 0xFE);
}

void usb_power_events_enable(void) {
    NVIC_SetPriority(USBD_IRQn, 6);
    APP_ERROR_CHECK_BOOL(tud_init(0));
    static const nrf_drv_power_usbevt_config_t cfg = { .handler = power_evt };
    APP_ERROR_CHECK(nrf_drv_power_usbevt_init(&cfg));

    uint32_t status;
    APP_ERROR_CHECK(sd_power_usbregstatus_get(&status));
    if (status & POWER_USBREGSTATUS_VBUSDETECT_Msk) power_evt(NRF_DRV_POWER_USB_EVT_DETECTED);
    if (status & POWER_USBREGSTATUS_OUTPUTRDY_Msk)  power_evt(NRF_DRV_POWER_USB_EVT_READY);
}

void usb_poll(void) {
    power_evts_apply();
    tud_task();
    cdc_pump();
    switch_step();
    usbnet_poll();
}
