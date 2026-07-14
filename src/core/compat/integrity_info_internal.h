/*
 * integrity_info_internal.h — declarations shared between the two halves of the
 * checksum metadata service after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the record-DIGEST fallback functions that the xattr-cache
 *       orchestrator in integrity_info.c calls across the file boundary into
 *       integrity_info_record.c, plus the xattr/record value-buffer size used by
 *       both translation units.
 * WHY:  integrity_info.c (xattr cache layer, XrdCksData binary codec, and the
 *       public get/format/invalidate orchestrator) and integrity_info_record.c
 *       (the §8.2 record-DIGEST fallback for exports without user xattrs) were
 *       one 587-line file; splitting keeps each focused and under the 500-line
 *       cap. The orchestrator's cache lookup/persist steps call
 *       integrity_record_read / integrity_record_write (now in the record file),
 *       so exactly those two functions become non-static.
 * HOW:  Both translation units include this header; neither symbol is exported
 *       beyond the checksum metadata module.
 */
#ifndef BRIX_CORE_COMPAT_INTEGRITY_INFO_INTERNAL_H
#define BRIX_CORE_COMPAT_INTEGRITY_INFO_INTERNAL_H

#include "integrity_info.h"   /* brix_integrity_info_t */

/* Format: "<hexval> <mtime_sec> <mtime_nsec> <size>" — 64 hex + " " + 3×20 + 3 seps + NUL */
#define INTEGRITY_XATTR_VAL_MAX  160

/* Defined in integrity_info_record.c; called by the xattr-cache orchestrator in
 * integrity_info.c. Reads a still-current cached checksum from a DIGEST entry in
 * the file's unified xmeta record (the §8.2 fallback for exports without user
 * xattrs); returns 1 and populates out on a fresh hit, 0 otherwise. */
int integrity_record_read(const char *path, const char *algo,
    brix_integrity_info_t *out);

/* Defined in integrity_info_record.c; called by the xattr-cache orchestrator in
 * integrity_info.c. Persists a freshly computed checksum as a DIGEST entry in the
 * file's unified xmeta record (best-effort). */
void integrity_record_write(const char *path, const char *algo,
    const char *hexval);

#endif /* BRIX_CORE_COMPAT_INTEGRITY_INFO_INTERNAL_H */
