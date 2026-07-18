/*
 * pblock_ctl.h — Phase-83 lab control plane for the pblock storage driver.
 *
 * WHAT: The static + runtime control surface that turns pblock into a
 *       fault-capable lab filesystem. Two tiers:
 *         (1) STATIC opts, a query tail on the backend root
 *             (…/root?lab=1&caps=-sendfile,+memfile&mem=1), stripped at config
 *             parse time and handed to the driver as a one-line sidecar
 *             (<root>/pblock.opts). Consumed once at instance init — it selects
 *             the fail-closed master gate (lab), the F2 capability mask, and the
 *             F16 in-memory catalog mode.
 *         (2) RUNTIME rules, rows in a `ctl(key TEXT PRIMARY KEY, value TEXT,
 *             epoch INTEGER)` table inside the export's catalog.db, driven by
 *             tests via the sqlite3 CLI. The driver re-reads them ONLY when
 *             MAX(epoch) changes and ONLY at a metadata boundary (open); the hot
 *             byte path never touches SQLite — it sees a per-object snapshot
 *             resolved at open (pblock_fault.h).
 *
 * WHY:  Every behaviour-altering lab feature is fail-closed behind the single
 *       `lab` gate (default OFF): with the gate off pblock is byte-for-byte the
 *       production driver — one cached flag test on the metadata path, zero cost
 *       on the byte path. The ctl table keeps test control out of the config
 *       file (no reload to inject a fault) while the epoch cache keeps the common
 *       case (no rules set) to a single MAX(epoch) probe per open.
 *
 * HOW:  ngx-free (libc + sqlite3), malloc-owned. Reaches the catalog's sqlite3
 *       connection through the non-static cat_exec/cat_prepare primitives
 *       (sd_pblock_catalog_internal.h). Gated by BRIX_HAVE_SQLITE like the rest
 *       of the backend.
 *
 * Requires: sd_pblock_catalog.h (pblock_catalog) before inclusion.
 */
#ifndef BRIX_FS_BACKEND_PBLOCK_CTL_H
#define BRIX_FS_BACKEND_PBLOCK_CTL_H

#include <stddef.h>
#include <stdint.h>

#include "sd_pblock_catalog.h"

/* Static per-export options parsed from the backend root's query tail. */
typedef struct {
    int      lab;         /* master fail-closed gate for all behaviour features  */
    int      mem;         /* F16: MEMORY-journal catalog (ephemeral lab export)  */
    int      audit;       /* F17: append-only oplog of metadata-boundary ops     */
    int      csi;         /* F3: per-block CRC32c integrity (csi catalog table)  */
    int      nearline;    /* F4: nearline/tape residency simulation              */
    int      locks;       /* F15: mandatory byte-range/whole-file lease enforce  */
    int      dedup;       /* F10: refcounted blobs + content-addressed dedup     */
    int      snapshots;   /* F6: named snapshots / instant fixture reset (⇒ refs) */
    int      versions;    /* F11: prior-blob generations to keep on overwrite     */
    int      trash;       /* F11: unlink → trash instead of free (⇒ refs)         */
    int64_t  trash_ttl;   /* F11: trash retention seconds (0 = keep until --gc)   */
    int64_t  quota_bytes; /* F5: export byte quota (0 = off); suffix k/m/g/t     */
    int64_t  quota_inodes;/* F5: export inode (catalog row) quota (0 = off)      */
    uint32_t caps_add;    /* F2: capability bits to OR into the driver caps      */
    uint32_t caps_drop;   /* F2: capability bits to AND out of the driver caps   */
    int      has_caps;    /* 1 iff a caps= token was present                     */
    char     xform[256];  /* F12/F13: transform spec ("crypt:<keyfile>"/"zstd")  */
    size_t   xform_len;   /* length of xform[] (0 = none)                        */
} pblock_opts_t;

/* Parse a query string ("lab=1&caps=-sendfile,+memfile&mem=1"; may be NULL or
 * empty) into *out (zeroed first). Unknown keys are ignored (forward-compatible
 * with later waves); a malformed caps token returns -1 with errno=EINVAL. */
int pblock_opts_parse(const char *query, pblock_opts_t *out);

/* Parse a size value ("10G"/"512m"/"1234"; suffix k/m/g/t, case-insensitive)
 * into a count of bytes. 0 on empty/garbage (⇒ the quota stays off). */
int64_t pblock_parse_size(const char *val, size_t vlen);

/* Map one pblock capability name to its BRIX_SD_CAP_* bit, or 0 for an unknown
 * name. Recognised: fd, sendfile, random_write, range_read, truncate, append,
 * iouring, server_copy, xattr, xattr_write, hard_rename, dirs, dirs_write,
 * memfile, nearline, catalog. */
uint32_t pblock_cap_bit(const char *name, size_t len);

/* Apply a parsed caps mask over a driver caps word: (caps | add) & ~drop.
 * A dropped bit always wins over an added one. */
uint32_t pblock_caps_apply(uint32_t caps, const pblock_opts_t *o);

/* Read the static opts sidecar (<root>/pblock.opts, one query-string line — the
 * pblock `?tail`, written by the config finaliser) into *out. Returns 0 (parsed,
 * or file absent → all-zero opts ⇒ lab OFF), or -1/errno on a malformed sidecar. */
int pblock_opts_load_sidecar(const char *root, pblock_opts_t *out);

/* ctl table -------------------------------------------------------------- */

/* Ensure the ctl table exists (idempotent). 0 or -1/errno. */
int pblock_ctl_init(pblock_catalog *cat);

/* Current control epoch = MAX(epoch) over ctl, or 0 when the table is empty.
 * Returns -1/errno on error. Cheap: one indexed aggregate, the per-open probe. */
int64_t pblock_ctl_epoch(pblock_catalog *cat);

/* Fetch one ctl value by key into buf (NUL-terminated, truncated to buflen).
 * Returns 1 (found), 0 (absent), or -1/errno. */
int pblock_ctl_get(pblock_catalog *cat, const char *key, char *buf, size_t buflen);

/* F16: switch the catalog to a non-durable in-memory journal
 * (PRAGMA journal_mode=MEMORY; synchronous=OFF) — ephemeral lab exports where
 * catalog durability is not wanted. Best-effort; returns 0 or -1/errno. */
int pblock_ctl_mem_pragmas(pblock_catalog *cat);

/* F17: op audit log ------------------------------------------------------ *
 * With `audit=1` set in the static opts, the driver appends one row per
 * metadata-boundary op (open/close/namespace/staged-commit — NOT per byte-I/O;
 * per-handle byte totals are folded into the close record's aux) to an
 * append-only `oplog(seq, ts, op, path, aux, uid, gid, result, errno)` table.
 * The uid/gid recorded are the catalog-internal synthetic identity (P80 ids),
 * so multiuser tests can assert attribution. Audit is deliberately best-effort:
 * a failed oplog write never fails the user op (pblock_audit_log returns void). */

/* Ensure the oplog table exists (idempotent). 0 or -1/errno. */
int pblock_audit_init(pblock_catalog *cat);

/* Append one op record. Best-effort — errors are swallowed so audit can never
 * change the outcome of the op it is recording. `aux` may be NULL/"". */
void pblock_audit_log(pblock_catalog *cat, const char *op, const char *path,
    const char *aux, uint32_t uid, uint32_t gid, int result, int err);

#endif /* BRIX_FS_BACKEND_PBLOCK_CTL_H */
