/*
 * usbnet.c - usb_net standalone mode transport.
 *
 * lwIP (NO_SYS) runs on the TinyUSB CDC-ECM (or RNDIS) interface. The host gets
 * 192.168.16.2 from the built-in DHCP server; the device is 192.168.16.1.
 * TCP port USBNET_TCP_PORT carries the same framed CLI protocol as the CDC
 * serial port (python CLI: `hw connect -p tcp:192.168.16.1:18888`). One client
 * at a time; a new connection replaces the old one.
 *
 * Everything here runs from the main loop (usb_poll); nothing touches lwIP
 * from interrupt context.
 */

#include "usbnet.h"
#include "usb_main.h"
#include "dataframe.h"
#include "app_standalone.h"

#include "tusb.h"
#include "dhserver.h"
#include "app_timer.h"

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
#include "lwip/apps/mdns.h"
#include "nrf.h"
#include "netif/ethernet.h"

#include <string.h>

#define NRF_LOG_MODULE_NAME usbnet
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
NRF_LOG_MODULE_REGISTER();

#define INIT_IP4(a, b, c, d) { PP_HTONL(LWIP_MAKEU32(a, b, c, d)) }

#define WRITE_STALL_MS   2000u
#define WAKE_PERIOD_MS   100u

static const ip4_addr_t k_ip   = INIT_IP4(192, 168, 16, 1);
static const ip4_addr_t k_mask = INIT_IP4(255, 255, 255, 0);
static const ip4_addr_t k_gw   = INIT_IP4(0, 0, 0, 0);

/* The DHCP server stores the lease owner here, so it must live in RAM */
static dhcp_entry_t m_leases[] = {
    {{0}, INIT_IP4(192, 168, 16, 2), 24 * 60 * 60},
};
static dhcp_config_t m_dhcp = {
    .router    = INIT_IP4(0, 0, 0, 0),
    .port      = 67,
    .dns       = INIT_IP4(0, 0, 0, 0),
    .domain    = "usb",
    .num_entry = TU_ARRAY_SIZE(m_leases),
    .entries   = m_leases,
};

extern uint8_t tud_network_mac_address[6];

static struct netif     m_netif;
static struct pbuf     *m_rx_frame;      /* from tud_network_recv_cb */
static struct tcp_pcb  *m_listen;
static struct tcp_pcb  *m_client;
static struct pbuf     *m_rx_q;          /* TCP payload not yet in the frame parser */
static uint16_t         m_rx_off;
static bool             m_inited;
static bool             m_running;
static bool             m_timer_on;      /* wake timer runs only while a host is enumerated */

static uint16_t m_port = USBNET_TCP_PORT;

static uint32_t m_st_rx_frames, m_st_tx_frames, m_st_drops, m_st_stalls;
static uint32_t m_st_clients, m_st_tcp_rx, m_st_tcp_tx;

APP_TIMER_DEF(m_wake_timer);

/* Random numbers for mDNS probing: xorshift seeded from the device address */
unsigned long usbnet_rand(void) {
    static uint32_t x;
    if (x == 0) x = NRF_FICR->DEVICEADDR[0] ^ (NRF_FICR->DEVICEADDR[1] << 16) ^ app_timer_cnt_get() ^ 0x9e3779b9u;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

/* lwIP time base: ms since boot from the app timer RTC */
u32_t sys_now(void) {
    static uint32_t prev;
    static uint64_t ticks;
    uint32_t now = app_timer_cnt_get();
    ticks += app_timer_cnt_diff_compute(now, prev);
    prev = now;
    return (u32_t)(ticks * 1000u / APP_TIMER_TICKS(1000));
}

/* ------------------------------------------------------------------------ */
/* Ethernet side                                                             */
/* ------------------------------------------------------------------------ */

static err_t linkoutput_fn(struct netif *netif, struct pbuf *p) {
    (void)netif;
    uint32_t start = sys_now();
    for (;;) {
        if (!tud_ready()) return ERR_USE;
        if (tud_network_can_xmit(p->tot_len)) {
            tud_network_xmit(p, 0);
            m_st_tx_frames++;
            return ERR_OK;
        }
        if (sys_now() - start > 100u) return ERR_USE;
        tud_task();
    }
}

static err_t netif_init_cb(struct netif *netif) {
    netif->mtu        = CFG_TUD_NET_MTU;
    netif->flags      = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP |
                        NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;
    netif->state      = NULL;
    netif->name[0]    = 'E';
    netif->name[1]    = 'X';
    netif->linkoutput = linkoutput_fn;
    netif->output     = etharp_output;
    return ERR_OK;
}

bool tud_network_recv_cb(const uint8_t *src, uint16_t size) {
    if (m_rx_frame) return false;            /* previous frame not handled yet */
    if (size) {
        struct pbuf *p = pbuf_alloc(PBUF_RAW, size, PBUF_POOL);
        if (p) {
            /* the pool is smaller than the MTU, so the frame can be chained */
            pbuf_take(p, src, size);
            m_rx_frame = p;
            m_st_rx_frames++;
        } else {
            m_st_drops++;
        }
    }
    return true;
}

uint16_t tud_network_xmit_cb(uint8_t *dst, void *ref, uint16_t arg) {
    (void)arg;
    struct pbuf *p = (struct pbuf *)ref;
    return pbuf_copy_partial(p, dst, p->tot_len, 0);
}

void tud_network_init_cb(void) {
    if (m_rx_frame) {
        pbuf_free(m_rx_frame);
        m_rx_frame = NULL;
    }
}

/* ------------------------------------------------------------------------ */
/* TCP client                                                                */
/* ------------------------------------------------------------------------ */

static void rx_queue_drop(void) {
    if (m_rx_q) {
        pbuf_free(m_rx_q);
        m_rx_q = NULL;
    }
    m_rx_off = 0;
}

static void client_detach(struct tcp_pcb *c) {
    tcp_arg(c, NULL);
    tcp_recv(c, NULL);
    tcp_err(c, NULL);
}

static void client_gone(void) {
    m_client = NULL;
    rx_queue_drop();
    data_frame_reset();                      /* no half frame from a dead client */
}

static void client_abort(void) {
    if (m_client) {
        struct tcp_pcb *c = m_client;
        client_detach(c);
        tcp_abort(c);
    }
    client_gone();
}

static void client_close(void) {
    if (m_client) {
        struct tcp_pcb *c = m_client;
        client_detach(c);
        if (tcp_close(c) != ERR_OK) tcp_abort(c);
    }
    client_gone();
}

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    (void)arg;
    if (p == NULL) {                         /* remote closed */
        if (pcb == m_client) client_close();
        return ERR_OK;
    }
    if (err != ERR_OK || pcb != m_client) {
        pbuf_free(p);
        return ERR_OK;
    }
    if (m_rx_q) {
        pbuf_cat(m_rx_q, p);
    } else {
        m_rx_q = p;
        m_rx_off = 0;
    }
    return ERR_OK;
}

static void on_err(void *arg, err_t err) {
    (void)arg;
    (void)err;
    client_gone();                           /* lwIP already freed the pcb */
}

static err_t on_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
    (void)arg;
    if (err != ERR_OK || newpcb == NULL) return ERR_VAL;
    if (m_client) client_abort();            /* a stale session must not block a new one */
    m_client = newpcb;
    tcp_nagle_disable(newpcb);               /* small request/response frames */
    tcp_arg(newpcb, NULL);
    tcp_recv(newpcb, on_recv);
    tcp_err(newpcb, on_err);
    data_frame_reset();
    m_st_clients++;
    NRF_LOG_INFO("usbnet: client connected");
    return ERR_OK;
}

/* Feed received TCP bytes to the frame parser. It drops bytes while a frame
 * waits for data_frame_process(), so go one byte at a time and stop there. */
static void rx_drain(void) {
    uint16_t consumed = 0;
    while (m_rx_q && !data_frame_rx_busy()) {
        struct pbuf *p = m_rx_q;
        uint8_t b = ((const uint8_t *)p->payload)[m_rx_off++];
        data_frame_receive(&b, 1);
        consumed++;
        if (m_rx_off >= p->len) {
            struct pbuf *next = p->next;
            if (next) pbuf_ref(next);
            pbuf_free(p);
            m_rx_q = next;
            m_rx_off = 0;
        }
    }
    m_st_tcp_rx += consumed;
    if (consumed && m_client) tcp_recved(m_client, consumed);
}

bool usbnet_client_active(void) {
    return m_running && m_client != NULL;
}

/* ------------------------------------------------------------------------ */
/* Servicing                                                                 */
/* ------------------------------------------------------------------------ */

static void service_io(void) {
    if (m_rx_frame) {
        struct pbuf *p = m_rx_frame;
        m_rx_frame = NULL;
        ethernet_input(p, &m_netif);         /* consumes p */
        tud_network_recv_renew();
    }
    sys_check_timeouts();
}

void usbnet_write(const void *buf, uint16_t length) {
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t last = sys_now();
    while (length && m_client) {
        u16_t room = tcp_sndbuf(m_client);
        if (room) {
            u16_t n = room < length ? room : length;
            if (tcp_write(m_client, p, n, TCP_WRITE_FLAG_COPY) == ERR_OK) {
                p += n;
                length -= n;
                m_st_tcp_tx += n;
                tcp_output(m_client);
                last = sys_now();
                continue;
            }
        }
        /* send window or memory full: let the USB side drain and ACKs arrive */
        tud_task();
        service_io();
        if (sys_now() - last > WRITE_STALL_MS) {
            m_st_stalls++;
            NRF_LOG_WARNING("usbnet: write stalled, dropping client");
            client_abort();
            return;
        }
    }
    if (m_client) tcp_output(m_client);
}

void usbnet_poll(void) {
    if (!m_running) return;
    if (!tud_ready()) {                      /* no host: no periodic wake-ups either */
        if (m_client) client_abort();
        if (m_timer_on) {
            (void)app_timer_stop(m_wake_timer);
            m_timer_on = false;
        }
        return;
    }
    if (!m_timer_on) {
        APP_ERROR_CHECK(app_timer_start(m_wake_timer, APP_TIMER_TICKS(WAKE_PERIOD_MS), NULL));
        m_timer_on = true;
        mdns_resp_restart(&m_netif);         /* host just enumerated: announce again */
    }
    service_io();
    rx_drain();
}

bool usbnet_running(void) {
    return m_running;
}

static void wake_handler(void *ctx) {
    (void)ctx;                               /* the interrupt wakes the main loop */
}

#define MDNS_HOSTNAME "chameleon"
static s8_t m_mdns_svc = -1;

static void mdns_publish(void) {
    if (m_mdns_svc >= 0) mdns_resp_del_service(&m_netif, (u8_t)m_mdns_svc);
    m_mdns_svc = mdns_resp_add_service(&m_netif, MDNS_HOSTNAME, "_chameleon", DNSSD_PROTO_TCP, m_port, NULL, NULL);
}

static void listen_start(void) {
    struct tcp_pcb *l = tcp_new();
    if (l && tcp_bind(l, IP_ADDR_ANY, m_port) == ERR_OK) {
        m_listen = tcp_listen_with_backlog(l, 1);
    }
    if (m_listen) {
        tcp_accept(m_listen, on_accept);
    } else {
        NRF_LOG_ERROR("usbnet: tcp listen failed");
        if (l) tcp_close(l);
    }
}

void usbnet_set_gateway(bool on) {
    m_dhcp.router = on ? k_ip : (ip4_addr_t)INIT_IP4(0, 0, 0, 0);   /* sent with the next lease */
}

void usbnet_set_port(uint16_t port) {
    if (port == 0) port = USBNET_TCP_PORT;
    if (port == m_port) return;
    m_port = port;
    if (m_inited) {                          /* already listening: move the listener */
        mdns_publish();
        if (m_client) client_abort();
        if (m_listen) {
            tcp_close(m_listen);
            m_listen = NULL;
        }
        listen_start();
    }
}

void usbnet_link_down(void) {
    if (m_client) client_abort();
    tud_network_init_cb();
}

void usbnet_start(void) {
    if (m_running) return;

    if (!m_inited) {
        lwip_init();
        m_netif.hwaddr_len = sizeof(tud_network_mac_address);
        memcpy(m_netif.hwaddr, tud_network_mac_address, sizeof(tud_network_mac_address));
        m_netif.hwaddr[5] ^= 0x01;           /* must differ from the host's MAC */
        netif_add(&m_netif, &k_ip, &k_mask, &k_gw, NULL, netif_init_cb, ethernet_input);
        netif_set_default(&m_netif);
        netif_set_up(&m_netif);

        if (dhserv_init(&m_dhcp) != ERR_OK) NRF_LOG_ERROR("usbnet: dhcp server init failed");

        listen_start();
        mdns_resp_init();
        if (mdns_resp_add_netif(&m_netif, MDNS_HOSTNAME) == ERR_OK) mdns_publish();
        APP_ERROR_CHECK(app_timer_create(&m_wake_timer, APP_TIMER_MODE_REPEATED, wake_handler));
        m_inited = true;
    }

    m_running = true;
    NRF_LOG_INFO("usbnet: up, 192.168.16.1:%d", m_port);
}

void usbnet_stop(void) {
    if (!m_running) return;
    m_running = false;
    if (m_timer_on) {
        (void)app_timer_stop(m_wake_timer);
        m_timer_on = false;
    }
    if (m_client) client_abort();
    if (m_rx_frame) {
        pbuf_free(m_rx_frame);
        m_rx_frame = NULL;
    }
    NRF_LOG_INFO("usbnet: down");
}

size_t usbnet_get_status(char *out, size_t out_max) {
    size_t len = 0;
    const uint8_t *mac = m_leases[0].mac;
    bool leased = false;
    for (int i = 0; i < 6; i++) leased |= mac[i] != 0;

    uint8_t src = usbnet_sources();
    STATUS_KV(out, out_max, len, "usb=%s on=%s%s%s\n", m_running ? "ethernet" : "serial-only (re-enumerating)",
              (src & 1) ? "mode" : "", (src == 3) ? "+" : "", (src & 2) ? "auto" : "");
    STATUS_KV(out, out_max, len, "class=%s mtu=%u\n", usbnet_class_rndis() ? "rndis" : "ecm",
              (unsigned)CFG_TUD_NET_MTU);
    STATUS_KV(out, out_max, len, "host_usb=%s%s\n", tud_mounted() ? "configured" : "not configured",
              tud_suspended() ? " (suspended)" : "");
    STATUS_KV(out, out_max, len, "name=%s.local\n", MDNS_HOSTNAME);
    STATUS_KV(out, out_max, len, "addr=192.168.16.1:%u gateway=%s\n", (unsigned)m_port,
              m_dhcp.router.addr ? "offered" : "none");
    if (leased) {
        STATUS_KV(out, out_max, len, "lease=192.168.16.2 %02x:%02x:%02x:%02x:%02x:%02x\n",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        STATUS_KV(out, out_max, len, "lease=none\n");
    }
    STATUS_KV(out, out_max, len, "tcp_client=%s accepted=%lu rx=%lu tx=%lu bytes\n",
              m_client ? "connected" : "none", (unsigned long)m_st_clients,
              (unsigned long)m_st_tcp_rx, (unsigned long)m_st_tcp_tx);
    STATUS_KV(out, out_max, len, "frames=rx %lu tx %lu\n", (unsigned long)m_st_rx_frames,
              (unsigned long)m_st_tx_frames);
    STATUS_KV(out, out_max, len, "errors=rx_drops %lu write_stalls %lu\n", (unsigned long)m_st_drops,
              (unsigned long)m_st_stalls);
    return len;
}
