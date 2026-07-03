#ifndef XROOTD_FS_LIST_H
#define XROOTD_FS_LIST_H

/*
 * fs_list.h — THE single declaration of every filesystem/storage driver.
 *
 * WHAT: the storage-plane sibling of proto_list.h: one X-macro row per
 *       xrootd_sd_driver_t the module ships, plus the store-URL scheme
 *       alias table. The mechanical enumerations generate from here: the
 *       name→driver registry table (fs/backend/sd_registry.c), the
 *       registry extern declarations (fs/backend/sd.h), and the tier
 *       store scheme table (fs/tier/tier_config.c).
 * WHY:  before this header the census lived in four hand-maintained
 *       places (registry table, sd.h externs, tier_schemes[], and each
 *       driver's .name) — adding a backend was an archaeology exercise,
 *       and nothing tracked WHICH filesystems exist at all.
 * HOW:  X(ID, sym, name, kind)
 *         ID    uppercase identity (reserved for future enum surfaces)
 *         sym   the symbol fragment: the driver struct is
 *               xrootd_sd_<sym>_driver in fs/backend/<dir>/sd_<sym>.c
 *         name  the driver's .name string — the config backend name,
 *               xrootd_sd_backend_name() (metric/log label: bounded,
 *               INVARIANT #8), and the tier scheme "driver" column
 *         kind  dispatch filter, consumed as XROOTD_FS_ROW_<kind>:
 *                 BACKEND   name-resolvable primary store (registry row +
 *                           extern; selected by xrootd_storage_backend)
 *                 ORIGIN    remote source driver composed under a cache/
 *                           stage tier (created directly, not by name)
 *                 DECORATOR wraps another instance (cache/stage/remote)
 *                 NEARLINE  offline/HSM plane (frm)
 *
 *       Build-gated rows live in gated sublists so consumers inherit the
 *       #if structure for free. Rows are append-only within their list.
 *
 * Adding a filesystem — the full checklist (X = generated from here):
 *   1. write fs/backend/<dir>/sd_<sym>.c implementing xrootd_sd_driver_t
 *      (tier-1 rule: ALL raw byte-I/O syscalls live in fs/backend/)
 *   2. append the row here [X: registry table + census]; declare the
 *      extern + its driver_conf contract in fs/backend/sd.h (hand-written
 *      on purpose — each extern carries the driver's documentation)
 *   3. add its sources to ./config (+ feature gate if the build must
 *      probe for a library — cf. XROOTD_HAVE_CEPH/XROOTD_HAVE_SQLITE),
 *      then rm -rf objs && ./configure && make
 *   4. teach the config-string grammar: bespoke parser branch in
 *      fs/vfs/vfs_backend_config.c (each scheme owns its syntax) and/or
 *      a scheme alias row in XROOTD_FS_SCHEME_LIST below [X: tier table]
 *   5. if tier stores must compose it: creation branch in
 *      fs/tier/tier_build.c (synthesizes the driver conf — semantic,
 *      not generatable)
 *   6. capability flags honest in sd.h (CAP_FD/SENDFILE/NEARLINE/...) —
 *      the VFS gates paths on them
 *   7. docs: fs/backend/README.md matrix + CLAUDE.md OP→FILE
 *   8. tests: data-plane byte-exact PUT/GET + stat/ns + one
 *      security-negative (cf. tests/run_pblock_*.sh, tests/ceph/)
 */

/* ---- drivers always in the build ---------------------------------------- */
#define XROOTD_FS_DRIVER_LIST_CORE(X)                                         \
    X(POSIX,     posix,     "posix",    BACKEND)   /* reference store      */ \
    X(BLOCK,     block,     "block",    BACKEND)   /* fixed-extent blocks  */ \
    X(HTTP,      http,      "http",     ORIGIN)    /* HTTP(S) Stratum/DAV  */ \
    X(XROOT,     xroot,     "xroot",    ORIGIN)    /* root:// origin       */ \
    X(CACHE,     cache,     "cache",    DECORATOR) /* read-through cache   */ \
    X(STAGE,     stage,     "stage",    DECORATOR) /* write-back stage     */ \
    X(REMOTE,    remote,    "remote",   DECORATOR) /* broker/impersonate   */ \
    X(FRM,       frm,       "frm",      NEARLINE)  /* HSM/MSS recall plane */

/* ---- drivers present only when ./configure found their library ---------- */
#if XROOTD_HAVE_CEPH
#define XROOTD_FS_DRIVER_LIST_CEPH(X)                                         \
    X(CEPH,      ceph,      "ceph",     BACKEND)   /* librados objects     */ \
    X(CEPHFS_RO, cephfs_ro, "cephfsro", BACKEND)   /* CephFS-via-RADOS ro  */
#else
#define XROOTD_FS_DRIVER_LIST_CEPH(X)
#endif

#if XROOTD_HAVE_SQLITE
#define XROOTD_FS_DRIVER_LIST_SQLITE(X)                                       \
    X(PBLOCK,    pblock,    "pblock",   BACKEND)   /* packed-block sqlite  */
#else
#define XROOTD_FS_DRIVER_LIST_SQLITE(X)
#endif

#define XROOTD_FS_DRIVER_LIST(X)                                              \
    XROOTD_FS_DRIVER_LIST_CORE(X)                                             \
    XROOTD_FS_DRIVER_LIST_CEPH(X)                                             \
    XROOTD_FS_DRIVER_LIST_SQLITE(X)

/* Kind-filter helper: consumers define XROOTD_FS_ROW_BACKEND(...) etc. to a
 * row and the rest to nothing, then pass XROOTD_FS_ROW as the X. */
#define XROOTD_FS_ROW(ID, sym, name, kind) XROOTD_FS_ROW_##kind(ID, sym, name)

/* ---- store-URL scheme aliases (tier cache/stage stores) ------------------
 * S(scheme, driver_name, tls, nearline): how a cache_store/stage/backend URL
 * scheme selects a driver ("https" is the http driver with TLS; "davs" is
 * WebDAV-over-TLS = http; "frm" is the tape/HSM alias). The bespoke per-
 * scheme VALUE grammar stays in vfs_backend_config.c / tier_build.c —
 * this table is only the scheme→driver dispatch (fs/tier/tier_config.c). */
#define XROOTD_FS_SCHEME_LIST(S)                                              \
    S("posix",  "posix",  0, 0)                                               \
    S("pblock", "pblock", 0, 0)                                               \
    S("root",   "xroot",  0, 0)                                               \
    S("roots",  "xroot",  1, 0)                                               \
    S("http",   "http",   0, 0)                                               \
    S("https",  "http",   1, 0)                                               \
    S("webdav", "http",   0, 0)                                               \
    S("davs",   "http",   1, 0)                                               \
    S("s3",     "s3",     0, 0)                                               \
    S("rados",  "rados",  0, 0)                                               \
    S("ceph",   "ceph",   0, 0)                                               \
    S("tape",   "tape",   0, 1)                                               \
    S("frm",    "frm",    0, 1)

/* ---- backend identity enum (activates the reserved ID column) ------------
 * One id per census row, generated from the same gated lists — a build
 * without CEPH/SQLITE simply has a smaller XROOTD_FS_ID_COUNT. Consumers:
 * the per-backend SHM byte counters (observability/metrics/metrics.h) index
 * by these ids; the exporters label by xrootd_fs_id_name(). The gate macros
 * are global -D CFLAGS (repo ./config), so every server TU agrees on
 * XROOTD_FS_ID_COUNT and the SHM layout stays consistent within a build. */
typedef enum {
#define XROOTD_FS_ROW_ENUM_ID(ID, sym, name, kind) XROOTD_FS_ID_##ID,
    XROOTD_FS_DRIVER_LIST(XROOTD_FS_ROW_ENUM_ID)
#undef XROOTD_FS_ROW_ENUM_ID
    XROOTD_FS_ID_COUNT
} xrootd_fs_id_t;

/* Name <-> id lookups over the census (fs/backend/sd_fs_id.c — ngx-free,
 * no driver externs, unit-testable standalone).
 * xrootd_fs_id_name: bounded label for exporters; "?" for out-of-range.
 * xrootd_fs_id_from_name: exact-match scan; -1 for NULL/unknown. */
const char *xrootd_fs_id_name(int id);
int xrootd_fs_id_from_name(const char *name);

#endif /* XROOTD_FS_LIST_H */
