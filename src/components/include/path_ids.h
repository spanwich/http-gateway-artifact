/*
 * path_ids.h -- Single source of truth for path identifier constants.
 *
 * Sentinel path identifier constants -- MUST match HTTP.Extract.Types.fst.
 * These are NOT computed hashes. They are fixed lookup values assigned
 * by the F*-verified extractor for known endpoints.
 * DO NOT CHANGE without re-verifying HTTP.Extract.Path.fst.
 *
 * HTTP method codes -- MUST match HTTP.Extract.Types.fst.
 * Role levels -- MUST match RbacPolicy.3d.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef PATH_IDS_H
#define PATH_IDS_H

#include <stdint.h>

/* Sentinel path identifier constants */
#define PATH_LOGIN    0x11111111u
#define PATH_LOGOUT   0x22222222u
#define PATH_STATUS   0x33333333u
#define PATH_POLICY   0x44444444u
#define INACTIVE_PATH_ID     0xDEADDEADu  /* unused rule slot sentinel */

/* Scope capability bits (UINT16 bitfield).
 * Bits 3-15 are reserved for future use.
 */
#define SCOPE_READ_SENSORS   0x0001u   /* bit 0: read sensor data        */
#define SCOPE_WRITE_SENSORS  0x0002u   /* bit 1: write actuator commands */
#define SCOPE_CONFIGURE      0x0004u   /* bit 2: modify configuration    */

/* HTTP method codes */
#define METHOD_GET    1
#define METHOD_POST   2
#define METHOD_PUT    3

/* Role levels */
#define ROLE_NONE     0
#define ROLE_OPERATOR 1
#define ROLE_ADMIN    2

#endif /* PATH_IDS_H */
