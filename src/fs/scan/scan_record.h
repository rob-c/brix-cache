/*
 * scan_record.h — NDJSON record formatting for the storage-scan engine.
 *
 * WHAT: pure, ngx-free formatters that render one engine result as a single
 *       NDJSON line (file / cursor / summary). Strings are JSON-escaped.
 * WHY:  the engine streams one object per line to an admin; isolating the
 *       formatting keeps it allocation-free, protocol-agnostic, and unit-testable
 *       standalone (no nginx, no server) — see scan_unittest.c.
 * HOW:  each formatter writes a NUL-terminated line (no trailing newline; the
 *       caller appends '\n' when framing) into a caller buffer and returns the
 *       length written, or -1 if the buffer was too small (never truncates).
 */
#ifndef BRIX_SCAN_RECORD_H
#define BRIX_SCAN_RECORD_H

#include <stddef.h>
#include <stdint.h>

/* Run totals carried by the final "summary" record. */
typedef struct {
    uint64_t files;
    uint64_t bytes;
    uint64_t ok;
    uint64_t mismatch;
    uint64_t missing;
    uint64_t unreadable;
    uint64_t filled;
    uint64_t already;
    double   elapsed_s;
} brix_scan_summary_t;

/* JSON-escape `in` (len bytes) into out[cap] as a NUL-terminated string WITHOUT
 * surrounding quotes. Escapes ", \\, and control bytes (< 0x20) as \uXXXX / the
 * short forms. Returns bytes written (excl. NUL) or -1 if it would overflow. */
int brix_scan_json_escape(const char *in, size_t len, char *out, size_t cap);

/* {"t":"file","path":..,"size":..,"mtime":..,"alg":..,"stored":..,"computed":..,"status":..}
 * stored == NULL ⇒ "stored":null. computed == NULL ⇒ the field is omitted
 * (dump/compare never recompute). */
int brix_scan_record_file(char *buf, size_t cap,
                            const char *path, int64_t size, int64_t mtime,
                            const char *alg, const char *stored,
                            const char *computed, const char *status);

/* {"t":"inspect","path":..,"backend":..,"size":..,"mtime":..,"stored_src":..,
 *  "namespace_consistent":true|false} — single-path backend introspection (A2). */
int brix_scan_record_inspect(char *buf, size_t cap, const char *path,
                               const char *backend, int64_t size, int64_t mtime,
                               const char *stored_src, int ns_consistent);

/* {"t":"health","backend":..,"total_bytes":..,"free_bytes":..,"used_bytes":..}
 * — backend capacity/health (C1). */
int brix_scan_record_health(char *buf, size_t cap, const char *backend,
                              uint64_t total_bytes, uint64_t free_bytes,
                              uint64_t used_bytes);

/* {"t":"object","key":..,"path":..,"size":..,"mtime":..,"orphan":true|false}
 * — one backend-catalog object (E1 inventory). `key` is the backend object key
 * (required). `path` is the recovered logical path, or NULL ⇒ "path":null and an
 * orphan candidate (set `orphan` accordingly). */
int brix_scan_record_object(char *buf, size_t cap, const char *key,
                              const char *path, int64_t size, int64_t mtime,
                              int orphan);

/* {"t":"drift","key":..,"path":..,"class":..,"size":..}
 * — one namespace↔catalog reconciliation result (D2 drift). `class` is one of
 * "in_both" / "size_mismatch" / "orphan_object" / "namespace_only". `key` is NULL
 * for namespace_only (no backing object) and `path` is NULL for orphan_object
 * (no namespace entry); each NULL renders as JSON null. */
int brix_scan_record_drift(char *buf, size_t cap, const char *key,
                             const char *path, const char *cls, int64_t size);

/* {"t":"cursor","after":<path>} */
int brix_scan_record_cursor(char *buf, size_t cap, const char *after);

/* {"t":"summary",...totals...} */
int brix_scan_record_summary(char *buf, size_t cap,
                               const brix_scan_summary_t *s);

#endif /* BRIX_SCAN_RECORD_H */
