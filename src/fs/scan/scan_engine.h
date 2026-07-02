/*
 * scan_engine.h — VFS-driven walk + per-object action for the storage scan.
 *
 * WHAT: xrootd_scan_run() walks a confined subtree (xrootd_vfs_walk), runs one
 *       mode action per regular file, and appends one NDJSON record per file to
 *       a growing heap buffer, accumulating run totals.
 * WHY:  this is the engine body the HTTP endpoint (scan_http.c) drives on a
 *       thread-pool worker; it depends on the VFS (and thus nginx types) but
 *       never on a protocol — a future root:// scan opcode can drive it too.
 * HOW:  mode action = xrootd_integrity_get_fd over the read-only fd the walk
 *       hands us (dump = cache-only, verify = stored-vs-computed, fill =
 *       compute+persist on miss); the fd/open/traversal stay inside the VFS.
 */
#ifndef XROOTD_SCAN_ENGINE_H
#define XROOTD_SCAN_ENGINE_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "scan_record.h"
#include "fs/backend/sd.h"   /* xrootd_sd_instance_t (catalog-backed inventory) */

typedef enum {
    XROOTD_SCAN_DUMP = 0,   /* read stored checksum (no byte read)              */
    XROOTD_SCAN_VERIFY,     /* recompute, compare to stored                     */
    XROOTD_SCAN_FILL,       /* compute + persist when no stored checksum exists */
    XROOTD_SCAN_COMPARE,    /* server-side identical to dump (client diffs)     */
    XROOTD_SCAN_INSPECT,    /* per-file backend introspection (A2; no byte read)*/
    XROOTD_SCAN_INVENTORY,  /* backend-catalog dump → "object" records (E1)     */
    XROOTD_SCAN_DRIFT       /* namespace↔catalog reconcile → "drift" records(D2)*/
} xrootd_scan_mode_t;

typedef struct {
    xrootd_scan_mode_t mode;
    char               alg[16];   /* algorithm name (adler32/crc32c/crc64/...)  */
    ngx_uint_t         max_depth;
    ngx_uint_t         max_files;
} xrootd_scan_opts_t;

/* Map a mode name → enum. NGX_OK / NGX_ERROR. */
ngx_int_t xrootd_scan_mode_parse(const char *name, xrootd_scan_mode_t *out);

/* Walk `logical` under rootfd, run the mode action per regular file, append one
 * NDJSON "file" record per file into the heap buffer (buf/cap/used; grown via
 * ngx_alloc — the caller frees it), and accumulate totals in *summary (its
 * elapsed_s is the caller's to set). NGX_OK or NGX_ERROR (err_code/err_msg set).
 * Thread-safe: no pool allocation, no metrics — runs on a thread-pool worker. */
ngx_int_t xrootd_scan_run(ngx_log_t *log, int rootfd, const char *logical,
    const xrootd_scan_opts_t *opts, u_char **buf, size_t *cap, size_t *used,
    xrootd_scan_summary_t *summary,
    uint16_t *err_code, char *err_msg, size_t err_sz);

/* Catalog-native inventory (E1) for a backend that advertises XROOTD_SD_CAP_CATALOG
 * (e.g. Ceph/RADOS): enumerate the bound instance's OWN object catalog via
 * xrootd_vfs_enumerate_catalog() and append one NDJSON "object" record per stored
 * object (recovered logical path, or orphan when none) into the heap buffer.
 * Independent of any POSIX rootfd/namespace walk — the answer to "dump the object
 * paths physically on the backend". NGX_OK, or NGX_ERROR (err_code/err_msg set;
 * kXR_Unsupported when the backend has no catalog verb). */
ngx_int_t xrootd_scan_run_inventory(ngx_log_t *log, xrootd_sd_instance_t *sd,
    const xrootd_scan_opts_t *opts, u_char **buf, size_t *cap, size_t *used,
    xrootd_scan_summary_t *summary,
    uint16_t *err_code, char *err_msg, size_t err_sz);

/* Catalog-native verify (the "verify their checksums on the backend" ask) for a
 * CAP_CATALOG backend: enumerate the bound instance's object catalog and, per
 * object, recompute the checksum over the backend bytes (Ceph: reassembled via
 * libradosstriper → byte-identical to stock XrdCeph) and compare to the stored
 * XrdCks value, appending one NDJSON "file" record (ok/mismatch/missing/
 * unreadable) per object. NGX_OK, or NGX_ERROR (err_code/err_msg set). */
ngx_int_t xrootd_scan_run_verify_catalog(ngx_log_t *log, xrootd_sd_instance_t *sd,
    const xrootd_scan_opts_t *opts, u_char **buf, size_t *cap, size_t *used,
    xrootd_scan_summary_t *summary,
    uint16_t *err_code, char *err_msg, size_t err_sz);

#endif /* XROOTD_SCAN_ENGINE_H */
