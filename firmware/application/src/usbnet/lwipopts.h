/* lwIP options for usb_net: one ECM/RNDIS netif, DHCP server, one TCP listener. */
#pragma once

#define NO_SYS                  1
#define SYS_LIGHTWEIGHT_PROT    0
#define LWIP_NOASSERT           1
#define MEM_ALIGNMENT           4
#define MEM_SIZE                3072

#define LWIP_SINGLE_NETIF       1
#define LWIP_IPV4               1
#define LWIP_IPV6               0
#define LWIP_ARP                1
#define LWIP_ETHERNET           1
#define LWIP_ICMP               1
#define LWIP_TCP                1
#define LWIP_UDP                1
#define LWIP_RAW                0
#define LWIP_DHCP               0
#define LWIP_AUTOIP             0
#define LWIP_DNS                0
#define LWIP_IGMP               0
#define LWIP_NETCONN            0
#define LWIP_SOCKET             0
#define LWIP_STATS              0
#define ETH_PAD_SIZE            0

/* The DHCP server must see broadcasts addressed to port 67 */
#define LWIP_IP_ACCEPT_UDP_PORT(p)  ((p) == PP_NTOHS(67))

#define MEMP_NUM_TCP_PCB        3
#define MEMP_NUM_TCP_PCB_LISTEN 1
#define MEMP_NUM_TCP_SEG        8
#define MEMP_NUM_UDP_PCB        1

#define PBUF_POOL_SIZE          4
#define PBUF_POOL_BUFSIZE       600

#define TCP_MSS                 536
#define TCP_WND                 (2 * TCP_MSS)
#define TCP_SND_BUF             (3 * TCP_MSS)
#define TCP_SND_QUEUELEN        8
