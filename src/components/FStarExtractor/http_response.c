/*
 * http_response.c -- HTTP response formatting for FStarExtractor
 *
 * Maps GateResponse status codes and extraction errors to HTTP responses.
 * This is the ONLY file in the system that produces HTTP response bytes.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "http_response.h"
#include <string.h>
#include <stdio.h>

/* HTTP status line + headers templates */
static const char RESP_200[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n"
    "\r\n";

static const char RESP_400[] =
    "HTTP/1.1 400 Bad Request\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n"
    "\r\n";

static const char RESP_401[] =
    "HTTP/1.1 401 Unauthorized\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n"
    "\r\n";

static const char RESP_403[] =
    "HTTP/1.1 403 Forbidden\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n"
    "\r\n";

static const char RESP_404[] =
    "HTTP/1.1 404 Not Found\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n"
    "\r\n";

static const char RESP_405[] =
    "HTTP/1.1 405 Method Not Allowed\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n"
    "\r\n";

static const char RESP_413[] =
    "HTTP/1.1 413 Payload Too Large\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n"
    "\r\n";

static const char RESP_429[] =
    "HTTP/1.1 429 Too Many Requests\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n"
    "\r\n";

static const char RESP_500[] =
    "HTTP/1.1 500 Internal Server Error\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n"
    "\r\n";

/* Write status line + headers + JSON body into resp_buf */
static void write_response(const char *status_hdr, const char *json_body,
                            uint8_t *resp_buf, uint32_t *resp_len)
{
    uint32_t hdr_len = (uint32_t)strlen(status_hdr);
    uint32_t body_len = json_body ? (uint32_t)strlen(json_body) : 0;

    memcpy(resp_buf, status_hdr, hdr_len);
    if (body_len > 0) {
        memcpy(resp_buf + hdr_len, json_body, body_len);
    }
    *resp_len = hdr_len + body_len;
}

void format_gate_response(const GateResponse *gresp,
                          uint8_t *resp_buf, uint32_t *resp_len)
{
    const char *status_hdr;

    switch (gresp->status) {
    case GATE_STATUS_OK:
        status_hdr = RESP_200;
        break;
    case GATE_STATUS_DENIED:
        status_hdr = RESP_403;
        break;
    case GATE_STATUS_RATE_LIMITED:
        status_hdr = RESP_429;
        break;
    case GATE_STATUS_NO_AUTH:
        status_hdr = RESP_401;
        break;
    case GATE_STATUS_NOT_FOUND:
        status_hdr = RESP_404;
        break;
    case GATE_STATUS_ERROR:
    default:
        status_hdr = RESP_500;
        break;
    }

    uint32_t hdr_len = (uint32_t)strlen(status_hdr);
    memcpy(resp_buf, status_hdr, hdr_len);

    if (gresp->body_len > 0) {
        memcpy(resp_buf + hdr_len, gresp->body, gresp->body_len);
        *resp_len = hdr_len + gresp->body_len;
    } else {
        *resp_len = hdr_len;
    }
}

void format_extraction_error(ExtractionResult err,
                             uint8_t *resp_buf, uint32_t *resp_len)
{
    switch (err) {
    case EXTRACT_MALFORMED:
        write_response(RESP_400, "{\"status\":\"error\",\"message\":\"malformed request\"}",
                       resp_buf, resp_len);
        break;
    case EXTRACT_METHOD_UNKNOWN:
        write_response(RESP_405, "{\"status\":\"error\",\"message\":\"method not allowed\"}",
                       resp_buf, resp_len);
        break;
    case EXTRACT_BODY_TOO_LARGE:
        write_response(RESP_413, "{\"status\":\"error\",\"message\":\"payload too large\"}",
                       resp_buf, resp_len);
        break;
    case EXTRACT_PATH_TRAVERSAL:
        write_response(RESP_400, "{\"status\":\"error\",\"message\":\"path traversal rejected\"}",
                       resp_buf, resp_len);
        break;
    default:
        write_response(RESP_500, "{\"status\":\"error\",\"message\":\"internal error\"}",
                       resp_buf, resp_len);
        break;
    }
}

void format_login_response(int valid, const char *token, uint8_t token_len,
                           uint8_t *resp_buf, uint32_t *resp_len)
{
    if (!valid) {
        write_response(RESP_401,
            "{\"status\":\"error\",\"message\":\"invalid credentials\"}",
            resp_buf, resp_len);
        return;
    }

    /* Build: {"status":"ok","token":"<token>"} */
    char body[256];
    int pos = 0;
    const char *prefix = "{\"status\":\"ok\",\"token\":\"";
    int plen = (int)strlen(prefix);
    memcpy(body + pos, prefix, plen);
    pos += plen;
    if (token_len > 0 && token_len < (int)(sizeof(body) - pos - 3)) {
        memcpy(body + pos, token, token_len);
        pos += token_len;
    }
    body[pos++] = '"';
    body[pos++] = '}';
    body[pos] = '\0';

    write_response(RESP_200, body, resp_buf, resp_len);
}

void format_unauthorized(uint8_t *resp_buf, uint32_t *resp_len)
{
    write_response(RESP_401,
        "{\"status\":\"error\",\"message\":\"authentication required\"}",
        resp_buf, resp_len);
}

void format_forbidden(uint8_t *resp_buf, uint32_t *resp_len)
{
    write_response(RESP_403,
        "{\"status\":\"error\",\"message\":\"invalid token\"}",
        resp_buf, resp_len);
}

void format_ok_json(const char *json_body,
                    uint8_t *resp_buf, uint32_t *resp_len)
{
    write_response(RESP_200, json_body, resp_buf, resp_len);
}
