#
# Copyright 2025
# HTTP Gateway x86 - Pure CAmkES Application (Stage 2)
#
# 5-component HTTP gateway on x86_64:
#   E1000Driver <-> TlsValidator <-> LwipProxy <-> FStarExtractor <-> PolicyGate
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.8.2)

project(http_gateway_x86 C ASM)

# Include settings
include(settings.cmake)

# Find lwIP for network stack
set(projects_dir "${CMAKE_CURRENT_LIST_DIR}/../")
find_file(LWIP_PATH lwip PATHS ${projects_dir} CMAKE_FIND_ROOT_PATH_BOTH)
if("${LWIP_PATH}" STREQUAL "LWIP_PATH-NOTFOUND")
    message(FATAL_ERROR "Failed to find lwIP")
endif()

# Include lwIP helpers
include(${projects_dir}/util_libs/liblwip/lwip_helpers.cmake)

# Configure lwIP with E1000Driver's lwipopts.h
AddLWIPConfiguration(${CMAKE_CURRENT_LIST_DIR}/components/E1000Driver)

# mbedTLS sources
set(MBEDTLS_DIR "${CMAKE_CURRENT_LIST_DIR}/external/mbedtls")

# mbedTLS sources for TLS 1.2 server
set(MBEDTLS_SOURCES
    ${MBEDTLS_DIR}/library/aes.c
    ${MBEDTLS_DIR}/library/asn1parse.c
    ${MBEDTLS_DIR}/library/asn1write.c
    ${MBEDTLS_DIR}/library/base64.c
    ${MBEDTLS_DIR}/library/bignum.c
    ${MBEDTLS_DIR}/library/bignum_core.c
    ${MBEDTLS_DIR}/library/bignum_mod.c
    ${MBEDTLS_DIR}/library/bignum_mod_raw.c
    ${MBEDTLS_DIR}/library/block_cipher.c
    ${MBEDTLS_DIR}/library/cipher.c
    ${MBEDTLS_DIR}/library/cipher_wrap.c
    ${MBEDTLS_DIR}/library/constant_time.c
    ${MBEDTLS_DIR}/library/ctr_drbg.c
    ${MBEDTLS_DIR}/library/debug.c
    ${MBEDTLS_DIR}/library/ecdh.c
    ${MBEDTLS_DIR}/library/ecdsa.c
    ${MBEDTLS_DIR}/library/ecp.c
    ${MBEDTLS_DIR}/library/ecp_curves.c
    ${MBEDTLS_DIR}/library/ecp_curves_new.c
    ${MBEDTLS_DIR}/library/entropy.c
    ${MBEDTLS_DIR}/library/entropy_poll.c
    ${MBEDTLS_DIR}/library/error.c
    ${MBEDTLS_DIR}/library/gcm.c
    ${MBEDTLS_DIR}/library/md.c
    ${MBEDTLS_DIR}/library/oid.c
    ${MBEDTLS_DIR}/library/pem.c
    ${MBEDTLS_DIR}/library/pk.c
    ${MBEDTLS_DIR}/library/pk_ecc.c
    ${MBEDTLS_DIR}/library/pk_wrap.c
    ${MBEDTLS_DIR}/library/pkparse.c
    ${MBEDTLS_DIR}/library/platform.c
    ${MBEDTLS_DIR}/library/platform_util.c
    ${MBEDTLS_DIR}/library/sha256.c
    ${MBEDTLS_DIR}/library/sha512.c
    ${MBEDTLS_DIR}/library/ssl_cache.c
    ${MBEDTLS_DIR}/library/ssl_ciphersuites.c
    ${MBEDTLS_DIR}/library/ssl_debug_helpers_generated.c
    ${MBEDTLS_DIR}/library/ssl_msg.c
    ${MBEDTLS_DIR}/library/ssl_tls.c
    ${MBEDTLS_DIR}/library/ssl_tls12_server.c
    ${MBEDTLS_DIR}/library/version.c
    ${MBEDTLS_DIR}/library/x509.c
    ${MBEDTLS_DIR}/library/x509_crt.c
)

# lwIP sources for LwipProxy (single-netif, no httpd, no UDP)
set(LWIP_PROXY_SOURCES
    ${LWIP_PATH}/src/core/altcp.c
    ${LWIP_PATH}/src/core/altcp_alloc.c
    ${LWIP_PATH}/src/core/altcp_tcp.c
    ${LWIP_PATH}/src/core/def.c
    ${LWIP_PATH}/src/core/inet_chksum.c
    ${LWIP_PATH}/src/core/init.c
    ${LWIP_PATH}/src/core/ip.c
    ${LWIP_PATH}/src/core/mem.c
    ${LWIP_PATH}/src/core/memp.c
    ${LWIP_PATH}/src/core/netif.c
    ${LWIP_PATH}/src/core/pbuf.c
    ${LWIP_PATH}/src/core/raw.c
    ${LWIP_PATH}/src/core/stats.c
    ${LWIP_PATH}/src/core/sys.c
    ${LWIP_PATH}/src/core/tcp.c
    ${LWIP_PATH}/src/core/tcp_in.c
    ${LWIP_PATH}/src/core/tcp_out.c
    ${LWIP_PATH}/src/core/timeouts.c
    ${LWIP_PATH}/src/core/ipv4/etharp.c
    ${LWIP_PATH}/src/core/ipv4/icmp.c
    ${LWIP_PATH}/src/core/ipv4/ip4.c
    ${LWIP_PATH}/src/core/ipv4/ip4_addr.c
    ${LWIP_PATH}/src/core/ipv4/ip4_frag.c
    ${LWIP_PATH}/src/netif/ethernet.c
    ${LWIP_PATH}/src/api/err.c
)

# ---- E1000Driver: Intel 82540EM standalone driver ----
DeclareCAmkESComponent(E1000Driver
    SOURCES
        components/E1000Driver/E1000Driver.c
    INCLUDES
        components/E1000Driver
        components/include
        ${LWIP_PATH}/src/include
        ${projects_dir}/util_libs/liblwip/include
    LIBS
        lwip
        sel4_autoconf
        utils
)

# ---- TlsValidator: bidirectional passthrough ----
DeclareCAmkESComponent(TlsValidator
    SOURCES components/TlsValidator/TlsValidator.c
    INCLUDES components/include
)

# ---- LwipProxy: TLS-terminating proxy (single-netif, Stage 2) ----
DeclareCAmkESComponent(LwipProxy
    SOURCES
        components/LwipProxy/LwipProxy.c
        components/LwipProxy/entropy_x86.c
        ${LWIP_PROXY_SOURCES}
        ${MBEDTLS_SOURCES}
    INCLUDES
        components/LwipProxy
        components/include
        ${LWIP_PATH}/src/include
        ${projects_dir}/util_libs/liblwip/include
        ${projects_dir}/util_libs/liblwip/include/lwip
        ${MBEDTLS_DIR}/include
    C_FLAGS
        -DMBEDTLS_CONFIG_FILE=\"lwipproxy_mbedtls_config.h\"
)

# ---- FStarExtractor: verified HTTP extractor + response formatting ----
# Generate dashboard HTML header at configure time
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/components/FStarExtractor/dashboard.html" _dashboard_hex HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," _dashboard_bytes "${_dashboard_hex}")
string(LENGTH "${_dashboard_hex}" _hex_len)
math(EXPR _dashboard_len "${_hex_len} / 2")
set(_gen_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${_gen_dir}")
file(WRITE "${_gen_dir}/dashboard_html.h"
    "/* Auto-generated from dashboard.html -- do not edit */\n"
    "static const unsigned char dashboard_html[] = {\n    ${_dashboard_bytes}0x00\n};\n"
    "static const unsigned int dashboard_html_len = ${_dashboard_len};\n"
)

DeclareCAmkESComponent(FStarExtractor
    SOURCES
        components/FStarExtractor/FStarExtractor.c
        components/FStarExtractor/http_response.c
        components/FStarExtractor/IPC_Extract.c
        components/FStarExtractor/HTTP_Extract_Types.c
        components/FStarExtractor/HTTP_Extract_Scan.c
        components/FStarExtractor/HTTP_Extract_Method.c
        components/FStarExtractor/HTTP_Extract_Path.c
        components/FStarExtractor/HTTP_Extract_Header.c
        components/FStarExtractor/HTTP_Extract_Bearer.c
        components/FStarExtractor/HTTP_Extract_Complete.c
    INCLUDES
        components/FStarExtractor
        components/FStarExtractor/krml_include
        components/include
        ${CMAKE_CURRENT_BINARY_DIR}/generated
)

# ---- Authenticator: IdP + PIP (passive, RPC-driven) ----
# HACL* (F*/KreMLin-verified) SHA-256 + HMAC-SHA256 from Project Everest
set(HACL_DIR ${CMAKE_CURRENT_LIST_DIR}/components/Authenticator/hacl)
DeclareCAmkESComponent(Authenticator
    SOURCES
        components/Authenticator/Authenticator.c
        components/Authenticator/credential_store.c
        components/Authenticator/token_generate.c
        components/Authenticator/token_validate.c
        ${HACL_DIR}/Hacl_Hash_SHA2.c
        ${HACL_DIR}/Hacl_HMAC.c
        ${HACL_DIR}/Hacl_Hash_SHA3.c
        ${HACL_DIR}/Hacl_Hash_Blake2b.c
        ${HACL_DIR}/Hacl_Hash_Blake2s.c
        ${HACL_DIR}/Hacl_Hash_SHA1.c
        ${HACL_DIR}/Hacl_Hash_MD5.c
        ${HACL_DIR}/Lib_Memzero0.c
    INCLUDES
        components/Authenticator/hacl
        components/Authenticator
        components/include
        components/FStarExtractor/krml_include
    C_FLAGS
        -ffunction-sections -fdata-sections
)

# ---- RateLimiter: per-subject rate counter (passive, RPC-driven) ----
DeclareCAmkESComponent(RateLimiter
    SOURCES
        components/RateLimiter/RateLimiter.c
    INCLUDES
        components/include
)

# ---- PolicyGate: pure PDP + PAP with EverParse (Phase 4) ----
# Default -std=gnu11 supports le32toh from <endian.h> (do NOT override).
# No session.c -- sessions removed in Phase 4 (stateless bearer token auth).
DeclareCAmkESComponent(PolicyGate
    SOURCES
        components/PolicyGate/PolicyGate.c
        components/PolicyGate/control_pipeline.c
        components/PolicyGate/everparse_generated/RbacPolicy.c
        components/PolicyGate/everparse_generated/RbacPolicyWrapper.c
    INCLUDES
        components/PolicyGate
        components/PolicyGate/everparse_generated
        components/include
)

# ---- ProtectedApp: resource server (Phase 4) ----
DeclareCAmkESComponent(ProtectedApp
    SOURCES
        components/ProtectedApp/ProtectedApp.c
    INCLUDES
        components/include
)

# Declare root server
DeclareCAmkESRootserver(http_gateway_x86.camkes)

# Generate final bootable image
GenerateCAmkESRootserver()
