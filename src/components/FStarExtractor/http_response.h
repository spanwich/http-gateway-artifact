/*
 * http_response.h -- HTTP response formatting for FStarExtractor
 *
 * The ONLY place in the system that produces HTTP response bytes.
 * Maps GateResponse status codes and extraction errors to HTTP responses.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

#include <stdint.h>
#include "extract.h"
#include "gate_response_wire.h"

/*
 * Format an HTTP response from a GateResponse (PolicyGate result).
 * Writes HTTP status line + headers + body into resp_buf.
 * Sets *resp_len to total bytes written.
 */
void format_gate_response(const GateResponse *gresp,
                          uint8_t *resp_buf, uint32_t *resp_len);

/*
 * Format an HTTP error response from an extraction error.
 * Used when extract_security_params() fails (malformed, too large, etc.).
 */
void format_extraction_error(ExtractionResult err,
                             uint8_t *resp_buf, uint32_t *resp_len);

/*
 * Format login response: HTTP 200 + token JSON, or HTTP 401 + error.
 * If valid=1, produces: {"status":"ok","token":"<token>"}
 * If valid=0, produces: {"status":"error","message":"invalid credentials"}
 */
void format_login_response(int valid, const char *token, uint8_t token_len,
                           uint8_t *resp_buf, uint32_t *resp_len);

/*
 * Format a simple HTTP 401 Unauthorized response.
 */
void format_unauthorized(uint8_t *resp_buf, uint32_t *resp_len);

/*
 * Format a simple HTTP 403 Forbidden response.
 */
void format_forbidden(uint8_t *resp_buf, uint32_t *resp_len);

/*
 * Format a simple HTTP 200 OK with JSON body.
 */
void format_ok_json(const char *json_body,
                    uint8_t *resp_buf, uint32_t *resp_len);

#endif /* HTTP_RESPONSE_H */
