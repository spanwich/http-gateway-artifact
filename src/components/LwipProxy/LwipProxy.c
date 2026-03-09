/*
 * LwipProxy.c -- TLS-terminating proxy (Stage 2: raw HTTP ring I/O)
 *
 * Single-netif architecture:
 *   ext_nif (192.168.1.10/24) -- external side, TLS server on :443
 *     RX/TX: TlsValidator ring buffers (Ethernet frames)
 *
 * After TLS decryption, raw HTTP bytes are written to Link 3 forward ring
 * (to FStarExtractor). HTTP response bytes arrive on Link 3 reverse ring.
 *
 * Stage 2 changes from Stage 1:
 *   - Removed internal netif (int_nif) -- no more dual-netif
 *   - Removed backend TCP client -- no more connect_backend()
 *   - Decrypted HTTP -> Link 3 ring (raw bytes, not Ethernet frames)
 *   - Response from Link 3 ring -> TLS encrypt -> client
 *   - Simplified state machine: ACCEPTED -> ESTABLISHED -> DRAINING
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <camkes.h>
#include <sel4/sel4.h>

#include "web_common.h"

/* mbedTLS */
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"

/* lwIP */
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "netif/ethernet.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
#include "lwip/pbuf.h"

/* Forward declarations */
extern void entropy_x86_init(void);

/* ================================================================
 * sys_now() -- required by lwIP timers (NO_SYS=1)
 * Uses x86 TSC (Time Stamp Counter) for millisecond timing.
 * ================================================================ */

static uint64_t tsc_freq_khz = 0;  /* TSC frequency in kHz */

static inline uint64_t read_tsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static void calibrate_tsc(void)
{
    tsc_freq_khz = 2000000;  /* 2 GHz = 2,000,000 kHz (QEMU default) */
    printf("[LwipProxy] TSC calibrated: ~%lu MHz\n",
           (unsigned long)(tsc_freq_khz / 1000));
}

u32_t sys_now(void)
{
    if (tsc_freq_khz == 0) {
        calibrate_tsc();
    }
    return (u32_t)(read_tsc() / tsc_freq_khz);
}

/* ================================================================
 * Embedded self-signed certificate and private key (ECDSA P-256)
 * ================================================================ */

static const char srv_cert_pem[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIBgTCCASegAwIBAgIUEcXSAc1ErmVdHy6WJH4So7QtE0owCgYIKoZIzj0EAwIw\n"
"FjEUMBIGA1UEAwwLaWNzLWdhdGV3YXkwHhcNMjYwMjAzMTkwNjAxWhcNMzYwMjAx\n"
"MTkwNjAxWjAWMRQwEgYDVQQDDAtpY3MtZ2F0ZXdheTBZMBMGByqGSM49AgEGCCqG\n"
"SM49AwEHA0IABNjOsAchfcuDOoeFjOruunPK52AuYM7HnZbiKBPkXokN4WA/quk4\n"
"OwL7eaqQgwTdZR8FgrZx8pCcfpbMGrnvdqOjUzBRMB0GA1UdDgQWBBSzjO6lWgM+\n"
"oVNbuDkU/DrDwqDznDAfBgNVHSMEGDAWgBSzjO6lWgM+oVNbuDkU/DrDwqDznDAP\n"
"BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCCQuWZhM59Kp4mF7xZ\n"
"vK4ekHYIxnHfqxlFl+WuPdtA2wIgQCpHgvuQ5uNO+QO4/50xLRshCE+lXUV2GueO\n"
"j/0BRSM=\n"
"-----END CERTIFICATE-----\n";

static const char srv_key_pem[] =
"-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEIH7fwsqoWa5QhPrDVsfCCAmUJ0/D2QeZA+vXmyVA3uf2oAoGCCqGSM49\n"
"AwEHoUQDQgAE2M6wByF9y4M6h4WM6u66c8rnYC5gzsedluIoE+ReiQ3hYD+q6Tg7\n"
"Avt5qpCDBN1lHwWCtnHykJx+lswaue92ow==\n"
"-----END EC PRIVATE KEY-----\n";

/* ================================================================
 * External netif (TlsValidator side) -- single netif now
 * ================================================================ */

static struct netif ext_nif;

/* Diagnostic counters */
static uint32_t g_tx_pkts = 0;
static uint32_t g_tx_full = 0;
static uint32_t g_lp_loops = 0;
static uint32_t g_last_rx = 0;
static uint32_t g_last_tx = 0;
static uint32_t g_last_full = 0;

static err_t ext_netif_output(struct netif *netif, struct pbuf *p)
{
    (void)netif;
    volatile struct ring_dataport *out = (volatile struct ring_dataport *)tls_out;

    u16_t total = p->tot_len;
    if (total == 0 || total > WEB_FRAME_MTU) return ERR_BUF;

    struct frame_entry *slot = ring_produce(out);
    if (!slot) { g_tx_full++; return ERR_MEM; }

    pbuf_copy_partial(p, slot->data, total, 0);
    slot->len = total;
    ring_commit(out);
    to_tls_ready_emit();
    g_tx_pkts++;

    return ERR_OK;
}

static err_t ext_netif_init_cb(struct netif *netif)
{
    netif->name[0] = 'e';
    netif->name[1] = 'x';
    netif->mtu = 1500;
    netif->hwaddr_len = 6;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
    netif->hwaddr[0] = 0x52; netif->hwaddr[1] = 0x54;
    netif->hwaddr[2] = 0x00; netif->hwaddr[3] = 0x12;
    netif->hwaddr[4] = 0x34; netif->hwaddr[5] = 0x56;
    netif->linkoutput = ext_netif_output;
    netif->output = etharp_output;
    return ERR_OK;
}

/* Inject frame from ring buffer into ext_nif */
static void netif_inject_rx(struct netif *nif, const void *data, uint16_t len)
{
    if (len == 0 || len > WEB_FRAME_MTU) return;
    struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (!p) return;
    pbuf_take(p, data, len);
    if (nif->input(p, nif) != ERR_OK) {
        pbuf_free(p);
    }
}

/* ================================================================
 * TLS connection state (Stage 2: simplified, no backend TCP)
 * ================================================================ */

#define MAX_TLS_CONNECTIONS  4

typedef enum {
    CONN_FREE = 0,
    CONN_ACCEPTED,          /* TLS accept, handshake in progress */
    CONN_ESTABLISHED,       /* TLS handshake done, forwarding data */
    CONN_DRAINING,          /* Response received, draining via TLS */
    CONN_TERMINATING,
} conn_state_t;

struct tls_conn {
    conn_state_t state;
    struct tcp_pcb *ext_pcb;
    mbedtls_ssl_context ssl;

    /* TLS receive buffer (encrypted data from client) */
    uint8_t rxbuf[4096];
    uint16_t rxbuf_len;
    uint16_t rxbuf_off;

    /* Response buffer (HTTP response bytes from FStarExtractor) */
    uint8_t respbuf[4096];
    uint16_t respbuf_len;

    int last_ssl_state;
    uint32_t hs_start_ms;
    uint32_t last_activity_ms;
};

static struct tls_conn conns[MAX_TLS_CONNECTIONS];

/*
 * Active connection tracking.
 * Points to the connection whose request is currently being processed
 * by FStarExtractor/PolicyGate. Response from the reverse ring is
 * directed to this connection.
 */
static struct tls_conn *active_conn = NULL;

/* Global mbedTLS objects */
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_ssl_config ssl_conf;
static mbedtls_x509_crt srv_cert;
static mbedtls_pk_context srv_pk;

/* ================================================================
 * mbedTLS BIO callbacks
 * ================================================================ */

static int tls_bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    struct tls_conn *c = (struct tls_conn *)ctx;
    if (!c->ext_pcb) return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;

    u16_t sndbuf = tcp_sndbuf(c->ext_pcb);
    if (sndbuf == 0) return MBEDTLS_ERR_SSL_WANT_WRITE;

    u16_t to_write = (len > sndbuf) ? sndbuf : (u16_t)len;
    err_t err = tcp_write(c->ext_pcb, buf, to_write, TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;

    tcp_output(c->ext_pcb);
    return (int)to_write;
}

static int tls_bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    struct tls_conn *c = (struct tls_conn *)ctx;

    uint16_t avail = c->rxbuf_len - c->rxbuf_off;
    if (avail == 0) return MBEDTLS_ERR_SSL_WANT_READ;

    uint16_t to_read = (len > avail) ? avail : (uint16_t)len;
    memcpy(buf, c->rxbuf + c->rxbuf_off, to_read);
    c->rxbuf_off += to_read;

    if (c->rxbuf_off >= c->rxbuf_len) {
        c->rxbuf_len = 0;
        c->rxbuf_off = 0;
    }

    return (int)to_read;
}

/* ================================================================
 * Connection management
 * ================================================================ */

static struct tls_conn *conn_alloc(void)
{
    for (int i = 0; i < MAX_TLS_CONNECTIONS; i++) {
        if (conns[i].state == CONN_FREE) {
            memset(&conns[i], 0, sizeof(conns[i]));
            conns[i].state = CONN_ACCEPTED;
            return &conns[i];
        }
    }
    return NULL;
}

#define CONN_IDLE_TIMEOUT_MS  30000

static void conn_free(struct tls_conn *c)
{
    if (!c || c->state == CONN_FREE) return;

    c->state = CONN_TERMINATING;

    /* Clear active_conn if this is it */
    if (active_conn == c) {
        active_conn = NULL;
    }

    mbedtls_ssl_free(&c->ssl);

    if (c->ext_pcb) {
        tcp_arg(c->ext_pcb, NULL);
        tcp_recv(c->ext_pcb, NULL);
        tcp_err(c->ext_pcb, NULL);
        tcp_close(c->ext_pcb);
        c->ext_pcb = NULL;
    }

    c->state = CONN_FREE;
}

/* ================================================================
 * External (TLS) TCP callbacks
 * ================================================================ */

static err_t ext_tcp_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    struct tls_conn *c = (struct tls_conn *)arg;

    if (!p || err != ERR_OK) {
        conn_free(c);
        return ERR_OK;
    }

    c->last_activity_ms = sys_now();

    uint16_t space = sizeof(c->rxbuf) - c->rxbuf_len;
    uint16_t copy = (p->tot_len > space) ? space : (uint16_t)p->tot_len;

    if (copy > 0) {
        pbuf_copy_partial(p, c->rxbuf + c->rxbuf_len, copy, 0);
        c->rxbuf_len += copy;
        tcp_recved(pcb, copy);
    }

    pbuf_free(p);
    return ERR_OK;
}

static void ext_tcp_err(void *arg, err_t err)
{
    struct tls_conn *c = (struct tls_conn *)arg;
    (void)err;
    if (c) {
        c->ext_pcb = NULL;
        conn_free(c);
    }
}

static err_t ext_tcp_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    (void)arg;
    if (err != ERR_OK || !newpcb) return ERR_VAL;

    struct tls_conn *c = conn_alloc();
    if (!c) {
        printf("[LwipProxy] Max TLS connections, rejecting\n");
        tcp_close(newpcb);
        return ERR_OK;
    }

    c->ext_pcb = newpcb;
    tcp_arg(newpcb, c);
    tcp_recv(newpcb, ext_tcp_recv);
    tcp_err(newpcb, ext_tcp_err);

    c->hs_start_ms = sys_now();
    c->last_activity_ms = sys_now();
    c->last_ssl_state = -1;
    printf("[%lu] TLS accept\n", (unsigned long)sys_now());

    mbedtls_ssl_init(&c->ssl);
    int ret = mbedtls_ssl_setup(&c->ssl, &ssl_conf);
    if (ret != 0) {
        printf("[LwipProxy] ssl_setup failed: -0x%04x\n", -ret);
        conn_free(c);
        return ERR_OK;
    }
    mbedtls_ssl_set_bio(&c->ssl, c, tls_bio_send, tls_bio_recv, NULL);

    return ERR_OK;
}

/* ================================================================
 * Main loop processing
 * ================================================================ */

static bool process_tls_connections(void)
{
    bool did_work = false;

    volatile struct ring_dataport *http_tx =
        (volatile struct ring_dataport *)http_out;

    for (int i = 0; i < MAX_TLS_CONNECTIONS; i++) {
        struct tls_conn *c = &conns[i];
        if (c->state == CONN_FREE || c->state == CONN_TERMINATING)
            continue;

        /* Idle timeout check */
        if (c->state == CONN_ESTABLISHED) {
            uint32_t now = sys_now();
            if (now - c->last_activity_ms > CONN_IDLE_TIMEOUT_MS) {
                printf("[LwipProxy] Idle timeout slot=%d (%lu ms)\n",
                       i, (unsigned long)(now - c->last_activity_ms));
                conn_free(c);
                did_work = true;
                continue;
            }
        }

        /* Drive TLS handshake */
        if (c->state == CONN_ACCEPTED) {
            int ret = mbedtls_ssl_handshake(&c->ssl);

            if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                continue;
            }

            if (ret != 0) {
                printf("[%lu] TLS handshake error: -0x%04x\n",
                       (unsigned long)sys_now(), -ret);
                conn_free(c);
                did_work = true;
                continue;
            }

            printf("[%lu] TLS established (+%lu ms)\n", (unsigned long)sys_now(),
                   (unsigned long)(sys_now() - c->hs_start_ms));
            c->state = CONN_ESTABLISHED;
            did_work = true;
        }

        /* Read decrypted application data and forward to FStarExtractor */
        if (c->state == CONN_ESTABLISHED) {
            uint8_t buf[4096];
            int ret = mbedtls_ssl_read(&c->ssl, buf, sizeof(buf));

            if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                /* No data available */
            } else if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0) {
                conn_free(c);
                did_work = true;
                continue;
            } else if (ret < 0) {
                conn_free(c);
                did_work = true;
                continue;
            } else {
                /* Got decrypted HTTP bytes -- write to Link 3 forward ring */
                did_work = true;
                c->last_activity_ms = sys_now();

                struct frame_entry *slot = ring_produce(http_tx);
                if (slot) {
                    uint16_t len = ((uint16_t)ret > WEB_FRAME_MTU)
                                   ? WEB_FRAME_MTU : (uint16_t)ret;
                    slot->len = len;
                    memcpy(slot->data, buf, len);
                    ring_commit(http_tx);
                    to_http_ready_emit();

                    /* Track this as the active connection waiting for response */
                    active_conn = c;
                } else {
                    printf("[LwipProxy] WARN: http_out ring full, dropping %d bytes\n", ret);
                }
            }
        }

        /* Encrypt and send response data */
        if ((c->state == CONN_ESTABLISHED || c->state == CONN_DRAINING)
            && c->respbuf_len > 0) {
            int ret = mbedtls_ssl_write(&c->ssl, c->respbuf, c->respbuf_len);
            if (ret > 0) {
                uint16_t sent = (uint16_t)ret;
                if (sent < c->respbuf_len) {
                    memmove(c->respbuf, c->respbuf + sent,
                            c->respbuf_len - sent);
                }
                c->respbuf_len -= sent;
                c->last_activity_ms = sys_now();
                did_work = true;
            }
        }

        /* DRAINING: response fully sent -- close TLS connection */
        if (c->state == CONN_DRAINING && c->respbuf_len == 0) {
            conn_free(c);
            did_work = true;
            continue;
        }
    }

    return did_work;
}

/* ================================================================
 * Initialization
 * ================================================================ */

static int tls_server_init(void)
{
    int ret;

    entropy_x86_init();

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                 (const unsigned char *)"lwipproxy", 9);
    if (ret != 0) {
        printf("[LwipProxy] ctr_drbg_seed failed: -0x%04x\n", -ret);
        return -1;
    }

    mbedtls_x509_crt_init(&srv_cert);
    ret = mbedtls_x509_crt_parse(&srv_cert,
                                  (const unsigned char *)srv_cert_pem,
                                  strlen(srv_cert_pem) + 1);
    if (ret != 0) {
        printf("[LwipProxy] cert parse failed: -0x%04x\n", -ret);
        return -1;
    }

    mbedtls_pk_init(&srv_pk);
    ret = mbedtls_pk_parse_key(&srv_pk,
                                (const unsigned char *)srv_key_pem,
                                strlen(srv_key_pem) + 1,
                                NULL, 0,
                                mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        printf("[LwipProxy] key parse failed: -0x%04x\n", -ret);
        return -1;
    }

    mbedtls_ssl_config_init(&ssl_conf);
    ret = mbedtls_ssl_config_defaults(&ssl_conf,
                                       MBEDTLS_SSL_IS_SERVER,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        printf("[LwipProxy] ssl_config_defaults failed: -0x%04x\n", -ret);
        return -1;
    }

    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_ca_chain(&ssl_conf, srv_cert.next, NULL);

    ret = mbedtls_ssl_conf_own_cert(&ssl_conf, &srv_cert, &srv_pk);
    if (ret != 0) {
        printf("[LwipProxy] ssl_conf_own_cert failed: -0x%04x\n", -ret);
        return -1;
    }

    printf("[LwipProxy] mbedTLS initialized (TLS 1.2 server)\n");
    return 0;
}

static struct tcp_pcb *tls_listen_pcb;

static int tls_tcp_listen_init(void)
{
    tls_listen_pcb = tcp_new();
    if (!tls_listen_pcb) return -1;

    err_t err = tcp_bind(tls_listen_pcb, IP_ADDR_ANY, 443);
    if (err != ERR_OK) {
        printf("[LwipProxy] tcp_bind :443 failed: %d\n", err);
        return -1;
    }

    tls_listen_pcb = tcp_listen(tls_listen_pcb);
    if (!tls_listen_pcb) return -1;

    tcp_accept(tls_listen_pcb, ext_tcp_accept);
    printf("[LwipProxy] Listening on :443 (TLS)\n");
    return 0;
}

/* ================================================================
 * mbedTLS platform shims
 * ================================================================ */

static void *platform_calloc(size_t n, size_t size) { return calloc(n, size); }
static void platform_free(void *ptr) { free(ptr); }

#include "mbedtls/platform_time.h"

mbedtls_time_t mbedtls_time(mbedtls_time_t *timer)
{
    mbedtls_time_t t = (mbedtls_time_t)(sys_now() / 1000) + 1735689600;
    if (timer) *timer = t;
    return t;
}

/* ================================================================
 * Main
 * ================================================================ */

#define EXT_IP_STR   "192.168.1.10"
#define EXT_MASK_STR "255.255.255.0"
#define EXT_GW_STR   "192.168.1.1"

int run(void)
{
    printf("[LwipProxy] x86 TLS terminating proxy (Stage 2)\n");

    mbedtls_platform_set_calloc_free(platform_calloc, platform_free);

    /* Initialize lwIP */
    lwip_init();

    /* External netif (single netif -- no internal netif in Stage 2) */
    {
        ip4_addr_t ip, mask, gw;
        ip4addr_aton(EXT_IP_STR, &ip);
        ip4addr_aton(EXT_MASK_STR, &mask);
        ip4addr_aton(EXT_GW_STR, &gw);

        if (!netif_add(&ext_nif, &ip, &mask, &gw, NULL, ext_netif_init_cb, ethernet_input)) {
            printf("[LwipProxy] FATAL: ext netif_add failed\n");
            goto halt;
        }
        netif_set_default(&ext_nif);
        netif_set_up(&ext_nif);
        printf("[LwipProxy] ext netif: %s\n", EXT_IP_STR);
    }

    /* Initialize mbedTLS */
    if (tls_server_init() != 0) {
        printf("[LwipProxy] FATAL: TLS init failed\n");
        goto halt;
    }

    /* Start TLS listener */
    if (tls_tcp_listen_init() != 0) {
        printf("[LwipProxy] FATAL: TCP listen failed\n");
        goto halt;
    }

    printf("[LwipProxy] Ready: https://%s:443/\n", EXT_IP_STR);

    volatile struct ring_dataport *tls_rx  = (volatile struct ring_dataport *)tls_in;
    volatile struct ring_dataport *http_rx = (volatile struct ring_dataport *)http_in;

    uint32_t rx_pkts = 0;
    uint32_t last_hb = 0;

    while (1) {
        bool did_work = false;
        g_lp_loops++;

        /* Heartbeat every 5s */
        uint32_t now = sys_now();
        if (now - last_hb >= 5000) {
            uint32_t elapsed = now - last_hb;
            uint32_t delta_rx = rx_pkts - g_last_rx;
            uint32_t delta_tx = g_tx_pkts - g_last_tx;
            uint32_t delta_full = g_tx_full - g_last_full;

            uint32_t rx_pps = elapsed ? (delta_rx * 1000 / elapsed) : 0;
            uint32_t tx_pps = elapsed ? (delta_tx * 1000 / elapsed) : 0;

            printf("[%lu] HB rx:%lu/s tx:%lu/s full:%lu\n",
                   (unsigned long)now,
                   (unsigned long)rx_pps, (unsigned long)tx_pps,
                   (unsigned long)delta_full);

            g_last_rx = rx_pkts;
            g_last_tx = g_tx_pkts;
            g_last_full = g_tx_full;
            last_hb = now;
        }

        /* Drain external RX (TlsValidator -> ext_nif) */
        {
            struct frame_entry *slot;
            while ((slot = ring_consume(tls_rx)) != NULL) {
                uint16_t len = slot->len;
                if (len > 0 && len <= WEB_FRAME_MTU) {
                    static unsigned char buf[WEB_FRAME_MTU];
                    memcpy(buf, slot->data, len);
                    ring_release(tls_rx);
                    netif_inject_rx(&ext_nif, buf, len);
                    rx_pkts++;
                    did_work = true;
                } else {
                    ring_release(tls_rx);
                }
            }
        }

        /*
         * Drain response ring (FStarExtractor -> LwipProxy).
         * Raw HTTP response bytes. Route to active_conn's respbuf.
         */
        {
            struct frame_entry *slot;
            while ((slot = ring_consume(http_rx)) != NULL) {
                if (slot->len > 0 && active_conn &&
                    (active_conn->state == CONN_ESTABLISHED ||
                     active_conn->state == CONN_DRAINING)) {
                    uint16_t space = sizeof(active_conn->respbuf) - active_conn->respbuf_len;
                    uint16_t copy = (slot->len > space) ? space : slot->len;
                    if (copy > 0) {
                        memcpy(active_conn->respbuf + active_conn->respbuf_len,
                               slot->data, copy);
                        active_conn->respbuf_len += copy;
                    }
                    /* Response received -- enter draining state */
                    active_conn->state = CONN_DRAINING;
                    active_conn = NULL;
                    did_work = true;
                }
                ring_release(http_rx);
            }
        }

        /* Process TLS connections */
        if (process_tls_connections()) {
            did_work = true;
        }

        /* lwIP timers */
        sys_check_timeouts();

        if (!did_work) {
            seL4_Yield();
        }
    }

halt:
    printf("[LwipProxy] Halted.\n");
    while (1) { }
    return 0;
}
