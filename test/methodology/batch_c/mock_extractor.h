/*
 * Batch C: Mock HTTP Security Extractor
 *
 * Self-contained header — no dependency on pipeline.h.
 * Mimics what a verified HTTP extractor would do:
 * validate bounds, extract security-relevant fields.
 */

#ifndef MOCK_EXTRACTOR_H
#define MOCK_EXTRACTOR_H

#include <stdint.h>

typedef struct {
    uint32_t       path_hash;
    uint8_t        method;           /* 1=GET, 2=POST, 3=PUT */
    uint32_t       content_length;
    const uint8_t *body;
    uint32_t       body_len;
} MockHTTPRequest;

typedef struct {
    uint32_t       path_hash;
    uint8_t        method;
    uint32_t       content_length;
    const uint8_t *body;             /* Points into original request */
    uint32_t       body_len;
} SecurityParams;

typedef enum {
    EXTRACT_OK,
    EXTRACT_BODY_TOO_LARGE,
    EXTRACT_MALFORMED
} ExtractionResult;

ExtractionResult mock_extract(const MockHTTPRequest *req, SecurityParams *out);

#endif /* MOCK_EXTRACTOR_H */
