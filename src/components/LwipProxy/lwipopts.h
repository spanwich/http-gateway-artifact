/*
 * lwipopts.h — lwIP configuration for LwipProxy component (x86)
 *
 * TLS-terminating proxy: needs TCP for TLS server on external side.
 * Internal side is raw frame forwarding (no lwIP TCP needed there).
 * NO_SYS=1 (bare-metal). No httpd, no UDP, no DHCP.
 *
 * x86 port: Same configuration as BCM2837 LwipProxy.
 */

#ifndef LWIPOPTS_H
#define LWIPOPTS_H

/* ---------- Core / OS ---------- */
#define NO_SYS                      1
#define NO_SYS_NO_TIMERS            0
#define LWIP_TIMERS                 1
#define SYS_LIGHTWEIGHT_PROT        0
#define LWIP_NETCONN                0
#define LWIP_SOCKET                 0

/* ---------- Memory ---------- */
#define MEM_ALIGNMENT               8    /* x86_64 alignment */
#define MEM_SIZE                    (128 * 1024)  /* 128 KB heap for lwIP */
#define MEM_LIBC_MALLOC             0
#define MEMP_OVERFLOW_CHECK         0
#define MEMP_SANITY_CHECK           0

/* ---------- Pool sizes ---------- */
#define MEMP_NUM_PBUF               32
#define PBUF_POOL_SIZE              32
#define PBUF_POOL_BUFSIZE           1536
#define MEMP_NUM_TCP_PCB            16
#define MEMP_NUM_TCP_PCB_LISTEN     2
#define MEMP_NUM_TCP_SEG            64
#define MEMP_NUM_UDP_PCB            0
#define MEMP_NUM_RAW_PCB            0
#define MEMP_NUM_ARP_QUEUE          8
#define MEMP_NUM_NETBUF             0
#define MEMP_NUM_NETCONN            0

/* ---------- ARP ---------- */
#define LWIP_ARP                    1
#define ARP_TABLE_SIZE              10
#define ARP_QUEUEING                1
#define ETHARP_SUPPORT_STATIC_ENTRIES 1

/* ---------- IP ---------- */
#define LWIP_IPV4                   1
#define LWIP_IPV6                   0
#define IP_FORWARD                  0
#define IP_REASSEMBLY               0
#define IP_FRAG                     0

/* ---------- ICMP ---------- */
#define LWIP_ICMP                   1

/* ---------- UDP ---------- */
#define LWIP_UDP                    0

/* ---------- TCP ---------- */
#define LWIP_TCP                    1
#define TCP_MSS                     1460
#define TCP_SND_BUF                 (8 * TCP_MSS)
#define TCP_SND_QUEUELEN            (4 * TCP_SND_BUF / TCP_MSS)
#define TCP_WND                     (8 * TCP_MSS)
#define LWIP_WND_SCALE              0
#define TCP_QUEUE_OOSEQ             1
#define LWIP_TCP_KEEPALIVE          1

/* ---------- DHCP / Autoip ---------- */
#define LWIP_DHCP                   0
#define LWIP_AUTOIP                 0

/* ---------- DNS ---------- */
#define LWIP_DNS                    0

/* ---------- HTTPD ---------- */
#define LWIP_HTTPD                  0

/* ---------- Netif ---------- */
#define LWIP_NETIF_STATUS_CALLBACK  0
#define LWIP_NETIF_LINK_CALLBACK    0
#define LWIP_SINGLE_NETIF          0   /* Dual netif: ext + int */

/* ---------- Stats ---------- */
#define LWIP_STATS                  0
#define LWIP_STATS_DISPLAY          0

/* ---------- Checksum ---------- */
#define LWIP_CHKSUM_ALGORITHM       2

/* ---------- Debug ---------- */
#define LWIP_DEBUG                  0

/* ---------- Rand ---------- */
#define LWIP_RAND                   rand

#endif /* LWIPOPTS_H */
