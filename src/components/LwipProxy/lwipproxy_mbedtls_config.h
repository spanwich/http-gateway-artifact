/*
 * lwipproxy_mbedtls_config.h — Minimal TLS 1.2 server config for LwipProxy on seL4 x86
 *
 * Targets: x86_64, bare-metal (NO_SYS=1).
 * TLS 1.2 server only, no client auth, no DTLS.
 * Uses x86 RDRAND for entropy.
 * Max content length 16384 (standard TLS).
 *
 * Ciphersuite: TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
 * Key exchange: ECDHE (forward secrecy)
 * Authentication: ECDSA with P-256 (secp256r1)
 * Encryption: AES-128-GCM
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* ---- Platform ---- */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_NO_PLATFORM_ENTROPY      /* No /dev/urandom - use RDRAND */
#define MBEDTLS_ENTROPY_HARDWARE_ALT     /* We provide mbedtls_hardware_poll() */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY          /* Use custom calloc/free */

/* ---- System ---- */
#define MBEDTLS_HAVE_TIME                /* We provide mbedtls_time() */

/* ---- Crypto primitives ---- */
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_MD_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C

/* ---- Elliptic Curve Crypto (replaces RSA) ---- */
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED /* P-256 / prime256v1 */
#define MBEDTLS_ECDH_C                   /* ECDHE key exchange */
#define MBEDTLS_ECDSA_C                  /* ECDSA signatures */
#define MBEDTLS_ECP_WITH_MPI_UINT        /* Use optimized ECP implementation */
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C

/* ---- X.509 / Certs ---- */
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_PEM_PARSE_C

/* ---- Entropy / RNG ---- */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C

/* ---- TLS ---- */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_SRV_C               /* Server only - no client */
#define MBEDTLS_SSL_PROTO_TLS1_2        /* TLS 1.2 only */

/* ---- Ciphersuite: TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256 ---- */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

/* ---- Memory limits ---- */
#define MBEDTLS_SSL_MAX_CONTENT_LEN     16384  /* Standard TLS record size */
#define MBEDTLS_SSL_IN_CONTENT_LEN      16384
#define MBEDTLS_SSL_OUT_CONTENT_LEN     16384
#define MBEDTLS_MPI_MAX_SIZE            1024   /* Generous for all ECC operations */
#define MBEDTLS_ECP_MAX_BITS            521    /* Support up to P-521 if needed */
#define MBEDTLS_ECP_WINDOW_SIZE         4      /* Larger window = faster ECC */
#define MBEDTLS_ECP_FIXED_POINT_OPTIM   1      /* Pre-computed points for speed */

/* ---- Disable features we don't need ---- */
/* No RSA (replaced by ECDSA) */
/* No TLS 1.3 */
/* No DTLS */
/* No client mode */
/* No PSK, DHE */

#endif /* MBEDTLS_CONFIG_H */
