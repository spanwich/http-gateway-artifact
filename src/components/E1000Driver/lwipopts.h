/*
 * lwipopts.h — lwIP configuration for E1000Driver
 *
 * E1000Driver uses ethdrivers library which requires lwIP.
 * This configuration enables IPv4 for compatibility with the
 * global lwip library built by LibLwip.
 *
 * Based on ics_gateway_x86 Net0_Driver configuration.
 */

#ifndef LWIPOPTS_H
#define LWIPOPTS_H

/* ---------- Core / OS ---------- */
#define NO_SYS                      1       /* No OS threading */
#define LWIP_TIMERS                 1       /* Enable timers for TCP */
#define SYS_LIGHTWEIGHT_PROT        0
#define LWIP_NETCONN                0       /* Disable netconn API */
#define LWIP_SOCKET                 0       /* Disable socket API */
#define LWIP_RAND                   rand

/* ---------- Memory ---------- */
#define MEM_ALIGNMENT               4
#define MEM_SIZE                    (1024 * 1024)   /* 1MB for E1000 driver */
#define MEM_LIBC_MALLOC             0

/* ---------- Pool sizes ---------- */
#define MEMP_NUM_PBUF               64
#define PBUF_POOL_SIZE              128
#define PBUF_POOL_BUFSIZE           2048

/* TCP pools */
#define MEMP_NUM_TCP_PCB            32
#define MEMP_NUM_TCP_PCB_LISTEN     4
#define MEMP_NUM_TCP_SEG            256

/* UDP pools */
#define MEMP_NUM_UDP_PCB            4

/* Other pools */
#define MEMP_NUM_RAW_PCB            4
#define MEMP_NUM_ARP_QUEUE          16
#define MEMP_NUM_NETBUF             0
#define MEMP_NUM_NETCONN            0

/* ---------- Protocol configuration ---------- */
#define LWIP_ARP                    1
#define ETHARP_SUPPORT_STATIC_ENTRIES 1
#define LWIP_IPV4                   1
#define LWIP_IPV6                   0       /* Disable IPv6 for simplicity */
#define LWIP_ICMP                   1       /* Enable ping */
#define LWIP_UDP                    1
#define LWIP_TCP                    1
#define LWIP_DHCP                   0       /* Static IP for gateway */
#define LWIP_AUTOIP                 0
#define LWIP_DNS                    0
#define LWIP_HTTPD                  0

/* ---------- TCP configuration ---------- */
#define TCP_MSS                     1460
#define TCP_SND_BUF                 (8 * TCP_MSS)
#define TCP_SND_QUEUELEN            ((4 * TCP_SND_BUF) / TCP_MSS)
#define TCP_WND                     (8 * TCP_MSS)

/* ---------- Checksum ---------- */
#define CHECKSUM_GEN_IP             1
#define CHECKSUM_GEN_UDP            1
#define CHECKSUM_GEN_TCP            1
#define CHECKSUM_CHECK_IP           1
#define CHECKSUM_CHECK_UDP          1
#define CHECKSUM_CHECK_TCP          1

/* ---------- Stats / Debug ---------- */
#define LWIP_STATS                  0
#define LWIP_DEBUG                  0

/* ---------- Netif ---------- */
#define LWIP_NETIF_STATUS_CALLBACK  1

#endif /* LWIPOPTS_H */
