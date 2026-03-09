/*
 * Batch C: Mock HTTP Security Extractor Implementation
 *
 * Bounds validation + field extraction.
 * Includes pipeline.h for PATH_LOGIN/PATH_POLICY/METHOD_* constants
 * (needed to determine which requests require a body).
 */

#include "mock_extractor.h"
#include "pipeline.h"
#include <stddef.h>

ExtractionResult mock_extract(const MockHTTPRequest *req, SecurityParams *out)
{
    /* Check 1: method in {1,2,3} */
    if (req->method < 1 || req->method > 3) {
        return EXTRACT_MALFORMED;
    }

    /* Check 2: path_hash != 0 */
    if (req->path_hash == 0) {
        return EXTRACT_MALFORMED;
    }

    /* Check 3: content_length bound */
    if (req->content_length > 65536) {
        return EXTRACT_BODY_TOO_LARGE;
    }

    /* Check 4: body_len bound */
    if (req->body_len > 65536) {
        return EXTRACT_BODY_TOO_LARGE;
    }

    /* Check 5: login and policy-update require non-NULL body */
    if (req->path_hash == PATH_LOGIN && req->method == METHOD_POST) {
        if (req->body == NULL) return EXTRACT_MALFORMED;
    }
    if (req->path_hash == PATH_POLICY && req->method == METHOD_PUT) {
        if (req->body == NULL) return EXTRACT_MALFORMED;
    }

    /* Extract */
    out->path_hash = req->path_hash;
    out->method = req->method;
    out->content_length = req->content_length;
    out->body = req->body;
    out->body_len = req->body_len;

    return EXTRACT_OK;
}
