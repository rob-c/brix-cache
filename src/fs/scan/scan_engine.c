/*
 * scan_engine.c — VFS-driven walk + per-object action (see scan_engine.h).
 *
 * Mirrors the proven brix_ckscan_run() shape: a confined brix_vfs_walk fires
 * a per-file callback that runs the mode action and appends one NDJSON record to
 * a growing heap buffer. Runs on a thread-pool worker (heap, not pool).
 */
#include "scan_engine.h"

#include "core/compat/integrity_info.h"
#include "fs/vfs/vfs.h"
#include "protocols/root/protocol/opcodes.h"

#include <limits.h>
#include <string.h>
#include <strings.h>

/* One NDJSON line = JSON record (≤ SCAN record sizing) + '\n'. */
#define SCAN_LINE_MAX 3072

/* Render the walk's internal logical path (anchored at "." or a relative
 * subdir) as a clean, root-relative display path: "." → "/", "./a/b" → "/a/b",
 * "sub/x" → "/sub/x". The integrity layer keys on the fd, not this string. */
static void
scan_display_path(const char *logical, char *out, size_t outsz)
{
    const char *p = logical;

    if (p[0] == '.' && p[1] == '/') {
        p += 2;
    } else if (p[0] == '.' && p[1] == '\0') {
        p += 1;
    }
    snprintf(out, outsz, "/%s", p);
}

ngx_int_t
brix_scan_mode_parse(const char *name, brix_scan_mode_t *out)
{
    if (strcmp(name, "dump") == 0)    { *out = BRIX_SCAN_DUMP;    return NGX_OK; }
    if (strcmp(name, "verify") == 0)  { *out = BRIX_SCAN_VERIFY;  return NGX_OK; }
    if (strcmp(name, "fill") == 0)    { *out = BRIX_SCAN_FILL;    return NGX_OK; }
    if (strcmp(name, "compare") == 0) { *out = BRIX_SCAN_COMPARE; return NGX_OK; }
    if (strcmp(name, "inspect") == 0) { *out = BRIX_SCAN_INSPECT; return NGX_OK; }
    if (strcmp(name, "inventory") == 0) { *out = BRIX_SCAN_INVENTORY; return NGX_OK; }
    if (strcmp(name, "drift") == 0)   { *out = BRIX_SCAN_DRIFT;   return NGX_OK; }
    return NGX_ERROR;
}

/* Append a ready NDJSON line (llen bytes) plus a newline to the growing heap
 * buffer. Returns 1 ok, -1 OOM (caller owns *buf on failure). Mirrors
 * brix_ckscan_append's exponential growth. */
static int
scan_append(u_char **buf, size_t *cap, size_t *used, const char *line, size_t llen)
{
    if (*used + llen + 2 > *cap) {
        size_t  new_cap = *cap * 2 + llen + 2;
        u_char *nb = ngx_alloc(new_cap, ngx_cycle->log);

        if (nb == NULL) {
            return -1;
        }
        if (*buf != NULL) {
            ngx_memcpy(nb, *buf, *used);
            ngx_free(*buf);
        }
        *buf = nb;
        *cap = new_cap;
    }
    ngx_memcpy(*buf + *used, line, llen);
    *used += llen;
    (*buf)[(*used)++] = '\n';
    return 0;
}

typedef struct {
    ngx_log_t                  *log;
    const brix_scan_opts_t   *opts;
    u_char                    **buf;
    size_t                     *cap;
    size_t                     *used;
    brix_scan_summary_t      *sum;
    int                         oom;
} scan_walk_ctx_t;

/*
 * WHAT: per-file action context — the walk cookie plus the one file the action
 *       is currently building a record for (its display path, stat facts, and
 *       read-only fd) and the caller's output line buffer.
 * WHY:  every mode action threads the identical (walk-state, this-file, output)
 *       triple; bundling it keeps each action at ≤ 2 params (ctx + info out)
 *       and makes the shared data flow explicit instead of a wide argument list.
 * HOW:  scan_walk_file fills one on the stack per file and hands its address to
 *       the selected action; the action never mutates it, only reads.
 */
typedef struct {
    scan_walk_ctx_t *cc;
    const char       *logical;   /* clean display path for this file           */
    off_t             size;
    time_t            mtime;
    int               fd;        /* read-only fd from the walk                 */
    char             *line;      /* output record buffer                       */
    size_t            linesz;
} scan_action_ctx_t;

/* Look up the stored (cached) checksum without computing. Returns the hex on a
 * cache hit (into `info`), or NULL on miss. */
static const char *
scan_stored(scan_action_ctx_t *a, brix_integrity_info_t *info)
{
    brix_integrity_opts_t io;

    ngx_memzero(&io, sizeof(io));
    io.allow_xattr_cache = 1;
    io.no_compute = 1;
    if (brix_integrity_get_fd(a->cc->log, a->fd, NULL, a->logical,
                                a->cc->opts->alg, &io, info) == NGX_OK)
    {
        return info->hex;
    }
    return NULL;
}

/* dump / compare: emit stored checksum (or null), never read bytes. */
static int
scan_action_dump(scan_action_ctx_t *a)
{
    brix_integrity_info_t info;
    const char             *stored = scan_stored(a, &info);
    int                     n;

    n = brix_scan_record_file(a->line, a->linesz, a->logical, (int64_t) a->size,
                                (int64_t) a->mtime, a->cc->opts->alg, stored,
                                NULL, "ok");
    a->cc->sum->ok++;
    return n;
}

/* verify: recompute and compare to stored. */
static int
scan_action_verify(scan_action_ctx_t *a)
{
    brix_integrity_info_t stored_info, comp_info;
    const char             *stored;
    brix_integrity_opts_t io;
    const char             *status;
    const char             *computed = NULL;
    char                    stored_copy[129];

    stored = scan_stored(a, &stored_info);
    if (stored != NULL) {
        ngx_memcpy(stored_copy, stored, ngx_strlen(stored) + 1);
        stored = stored_copy;   /* survive the second get_fd's info reuse */
    }

    ngx_memzero(&io, sizeof(io));
    io.allow_xattr_cache = 0;   /* force a fresh compute over the bytes */
    io.no_compute = 0;
    if (brix_integrity_get_fd(a->cc->log, a->fd, NULL, a->logical,
                                a->cc->opts->alg, &io, &comp_info) != NGX_OK)
    {
        status = "unreadable";
        a->cc->sum->unreadable++;
    } else {
        computed = comp_info.hex;
        a->cc->sum->bytes += (uint64_t) a->size;
        if (stored == NULL) {
            status = "missing";
            a->cc->sum->missing++;
        } else if (strcasecmp(stored, computed) == 0) {
            status = "ok";
            a->cc->sum->ok++;
        } else {
            status = "mismatch";
            a->cc->sum->mismatch++;
        }
    }
    return brix_scan_record_file(a->line, a->linesz, a->logical,
                                   (int64_t) a->size, (int64_t) a->mtime,
                                   a->cc->opts->alg, stored, computed, status);
}

/* fill: persist a checksum only when none is stored. */
static int
scan_action_fill(scan_action_ctx_t *a)
{
    brix_integrity_info_t info;
    brix_integrity_opts_t io;
    const char             *status;
    const char             *stored;

    stored = scan_stored(a, &info);
    if (stored != NULL) {
        status = "already";
        a->cc->sum->already++;
        return brix_scan_record_file(a->line, a->linesz, a->logical,
                                       (int64_t) a->size, (int64_t) a->mtime,
                                       a->cc->opts->alg, stored, NULL, status);
    }

    ngx_memzero(&io, sizeof(io));
    io.allow_xattr_cache = 1;   /* required alongside update for the persist path */
    io.update_xattr_cache = 1;
    io.no_compute = 0;
    if (brix_integrity_get_fd(a->cc->log, a->fd, NULL, a->logical,
                                a->cc->opts->alg, &io, &info) != NGX_OK)
    {
        status = "unreadable";
        stored = NULL;
        a->cc->sum->unreadable++;
    } else {
        status = "filled";
        stored = info.hex;
        a->cc->sum->filled++;
        a->cc->sum->bytes += (uint64_t) a->size;
    }
    return brix_scan_record_file(a->line, a->linesz, a->logical,
                                   (int64_t) a->size, (int64_t) a->mtime,
                                   a->cc->opts->alg, stored, NULL, status);
}

/* inspect (A2): per-file backend introspection. The scan endpoint walks the
 * export root via POSIX openat2 (not the SD-driver seam), so the backend is
 * "posix" and namespace==backend by construction; the driver-bound view
 * (Ceph object key, cluster facts) is a Phase-4 prerequisite. */
static int
scan_action_inspect(scan_action_ctx_t *a)
{
    brix_integrity_info_t info;
    const char             *stored = scan_stored(a, &info);

    a->cc->sum->ok++;
    return brix_scan_record_inspect(a->line, a->linesz, a->logical, "posix",
                                      (int64_t) a->size, (int64_t) a->mtime,
                                      stored != NULL ? "xattr" : "none",
                                      1 /* posix: namespace == backend */);
}

/* inventory (E1): one "object" record per stored object. The scan endpoint walks
 * the export via POSIX (namespace == catalog), so the logical path IS the backend
 * key and every entry is backed (orphan=false). A catalog-native backend's
 * inventory runs through brix_vfs_enumerate_catalog (the SD enumerate verb)
 * instead — the seam is in place; threading a bound instance into the endpoint is
 * the Ceph follow-on. */
static int
scan_action_inventory(scan_action_ctx_t *a)
{
    a->cc->sum->ok++;
    return brix_scan_record_object(a->line, a->linesz, a->logical, a->logical,
                                     (int64_t) a->size, (int64_t) a->mtime, 0);
}

/* drift (D2): one "drift" record per entry. Over a namespace walk the catalog and
 * namespace coincide, so every entry is "in_both"; orphan_object / namespace_only
 * arise only when a native catalog verb (brix_vfs_enumerate_catalog) supplies a
 * backend-object set to reconcile against (scan_drift) — the Ceph follow-on. */
static int
scan_action_drift(scan_action_ctx_t *a)
{
    a->cc->sum->ok++;
    return brix_scan_record_drift(a->line, a->linesz, a->logical, a->logical,
                                    "in_both", (int64_t) a->size);
}

/* Run the mode's per-file action against the assembled action context. Split out
 * so scan_walk_file stays a thin fill-and-append shell around the dispatch. */
static int
scan_dispatch_action(scan_action_ctx_t *a)
{
    switch (a->cc->opts->mode) {
    case BRIX_SCAN_VERIFY:
        return scan_action_verify(a);
    case BRIX_SCAN_FILL:
        return scan_action_fill(a);
    case BRIX_SCAN_INSPECT:
        return scan_action_inspect(a);
    case BRIX_SCAN_INVENTORY:
        return scan_action_inventory(a);
    case BRIX_SCAN_DRIFT:
        return scan_action_drift(a);
    case BRIX_SCAN_DUMP:
    case BRIX_SCAN_COMPARE:
    default:
        return scan_action_dump(a);
    }
}

static ngx_int_t
scan_walk_file(void *cookie, const char *logical, const brix_vfs_stat_t *st,
               int fd)
{
    scan_walk_ctx_t  *cc = cookie;
    scan_action_ctx_t a;
    char              line[SCAN_LINE_MAX];
    char              disp[PATH_MAX];
    int               n;

    scan_display_path(logical, disp, sizeof(disp));

    ngx_memzero(&a, sizeof(a));
    a.cc = cc;
    a.logical = disp;
    a.size = st->size;
    a.mtime = st->mtime;
    a.fd = fd;
    a.line = line;
    a.linesz = sizeof(line);

    n = scan_dispatch_action(&a);

    if (n < 0) {
        return NGX_OK;   /* path too long to format — soft skip */
    }
    cc->sum->files++;
    if (scan_append(cc->buf, cc->cap, cc->used, line, (size_t) n) < 0) {
        cc->oom = 1;
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
brix_scan_run(ngx_log_t *log, int rootfd, const char *logical,
    const brix_scan_opts_t *opts, u_char **buf, size_t *cap, size_t *used,
    brix_scan_summary_t *summary, uint16_t *err_code, char *err_msg,
    size_t err_sz)
{
    scan_walk_ctx_t          cc;
    brix_vfs_walk_opts_t   wopts;
    brix_vfs_walk_target_t target = BRIX_VFS_WALK_NONE;
    char                     walkmsg[128] = "";
    ngx_int_t                rc;

    ngx_memzero(&cc, sizeof(cc));
    cc.log = log;
    cc.opts = opts;
    cc.buf = buf;
    cc.cap = cap;
    cc.used = used;
    cc.sum = summary;

    ngx_memzero(&wopts, sizeof(wopts));
    wopts.max_depth = opts->max_depth;
    wopts.max_files = opts->max_files;
    wopts.open_files = 1;   /* the walk hands each regular file a read-only fd */

    rc = brix_vfs_walk(log, rootfd, logical, &wopts, scan_walk_file, &cc,
                         &target, walkmsg, sizeof(walkmsg));

    if (rc == NGX_DECLINED) {
        *err_code = kXR_NotFound;
        snprintf(err_msg, err_sz, "target not found");
        return NGX_ERROR;
    }
    if (rc != NGX_OK) {
        if (cc.oom) {
            *err_code = kXR_NoMemory;
            snprintf(err_msg, err_sz, "out of memory");
        } else {
            *err_code = kXR_IOError;
            snprintf(err_msg, err_sz, "%s", walkmsg[0] ? walkmsg : "I/O error");
        }
        return NGX_ERROR;
    }
    if (target == BRIX_VFS_WALK_OTHER) {
        *err_code = kXR_ArgInvalid;
        snprintf(err_msg, err_sz, "not a file or directory");
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* Cookie for the catalog-enumeration callback: the same growing heap buffer the
 * walk path uses, plus an OOM flag that aborts the enumeration. */
typedef struct {
    u_char                **buf;
    size_t                 *cap;
    size_t                 *used;
    brix_scan_summary_t  *sum;
    int                     oom;
} scan_catalog_ctx_t;

/* Emit one "object" record per enumerated backend object. A driver-recovered
 * logical path of NULL marks an orphan (a stored object with no namespace entry).
 * Returns 0 to continue the enumeration, 1 to abort (only on OOM). */
static int
scan_catalog_emit_object(void *ctx, const brix_sd_catalog_ent_t *ent)
{
    scan_catalog_ctx_t *cc = ctx;
    char                line[SCAN_LINE_MAX];
    int                 n;

    n = brix_scan_record_object(line, sizeof(line), ent->key, ent->path,
                                  ent->have_stat ? (int64_t) ent->size : 0,
                                  ent->have_stat ? (int64_t) ent->mtime : 0,
                                  ent->path == NULL ? 1 : 0);
    if (n < 0) {
        return 0;                        /* unrepresentable key → soft skip */
    }
    cc->sum->files++;
    cc->sum->ok++;
    if (scan_append(cc->buf, cc->cap, cc->used, line, (size_t) n) < 0) {
        cc->oom = 1;
        return 1;                        /* abort enumeration */
    }
    return 0;
}

ngx_int_t
brix_scan_run_inventory(ngx_log_t *log, brix_sd_instance_t *sd,
    const brix_scan_opts_t *opts, u_char **buf, size_t *cap, size_t *used,
    brix_scan_summary_t *summary, uint16_t *err_code, char *err_msg,
    size_t err_sz)
{
    scan_catalog_ctx_t cc;
    ngx_int_t          rc;

    (void) log;    /* enumeration runs through the SD verb (no log needed here) */
    (void) opts;   /* catalog inventory is whole-pool; alg/depth do not apply */

    ngx_memzero(&cc, sizeof(cc));
    cc.buf = buf;
    cc.cap = cap;
    cc.used = used;
    cc.sum = summary;

    rc = brix_vfs_enumerate_catalog(sd, 1 /* want_stat */,
                                      scan_catalog_emit_object, &cc);

    if (rc == NGX_DECLINED) {
        *err_code = kXR_Unsupported;
        snprintf(err_msg, err_sz, "backend does not support catalog enumeration");
        return NGX_ERROR;
    }
    if (rc != NGX_OK || cc.oom) {
        *err_code = cc.oom ? kXR_NoMemory : kXR_IOError;
        snprintf(err_msg, err_sz, "%s",
                 cc.oom ? "out of memory" : "catalog enumeration failed");
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* Cookie for the catalog-verify callback: the bound instance + algorithm, plus
 * the growing heap buffer / summary the records land in. */
typedef struct {
    ngx_log_t              *log;
    brix_sd_instance_t   *sd;
    const char             *alg;
    u_char                **buf;
    size_t                 *cap;
    size_t                 *used;
    brix_scan_summary_t  *sum;
    int                     oom;
} scan_verify_ctx_t;

/*
 * WHAT: per-object context for the catalog-verify action — the enumeration
 *       cookie plus the one OPEN driver object being verified and the caller's
 *       output line buffer.
 * WHY:  mirrors scan_action_ctx_t on the POSIX walk side; keeps the verify
 *       record builder at ≤ 5 params with the shared state passed explicitly.
 * HOW:  scan_catalog_verify_one fills one on the stack after a successful
 *       driver open and hands its address to scan_verify_obj_record.
 */
typedef struct {
    scan_verify_ctx_t             *cc;
    const char                     *logical;   /* recovered logical path      */
    const brix_sd_catalog_ent_t  *ent;        /* enumeration entry (stat)    */
    brix_sd_obj_t                *obj;        /* OPEN driver object (fd = -1)*/
    char                           *line;      /* output record buffer        */
    size_t                          linesz;
} scan_verify_obj_ctx_t;

/* Build one verify "file" record for an OPEN catalog object: read the stored
 * XrdCks value (xattr, no byte read), recompute over the object's bytes, compare.
 * Reuses the integrity layer exactly as the POSIX verify path does — the only
 * difference is the source is a driver object (fd = -1) instead of a POSIX fd, so
 * the recompute reads through obj->driver->pread (which, for Ceph, reassembles
 * the libradosstriper layout → byte-identical to stock XrdCeph). */
static int
scan_verify_obj_record(scan_verify_obj_ctx_t *v)
{
    scan_verify_ctx_t     *cc = v->cc;
    brix_integrity_info_t stored_info, comp_info;
    brix_integrity_opts_t io;
    const char             *stored = NULL;
    const char             *computed = NULL;
    const char             *status;
    char                    stored_copy[129];
    int64_t                 size = v->ent->have_stat ? (int64_t) v->ent->size : 0;
    int64_t                 mtime = v->ent->have_stat ? (int64_t) v->ent->mtime : 0;

    ngx_memzero(&io, sizeof(io));
    io.allow_xattr_cache = 1;
    io.no_compute = 1;                    /* stored value only — no byte read */
    if (brix_integrity_get_fd(cc->log, -1, v->obj, v->logical, cc->alg, &io,
                                &stored_info) == NGX_OK)
    {
        ngx_memcpy(stored_copy, stored_info.hex, ngx_strlen(stored_info.hex) + 1);
        stored = stored_copy;             /* survive the recompute's info reuse */
    }

    ngx_memzero(&io, sizeof(io));
    io.allow_xattr_cache = 0;             /* force a fresh compute over the bytes */
    io.no_compute = 0;
    if (brix_integrity_get_fd(cc->log, -1, v->obj, v->logical, cc->alg, &io,
                                &comp_info) != NGX_OK)
    {
        status = "unreadable";
        cc->sum->unreadable++;
    } else {
        computed = comp_info.hex;
        cc->sum->bytes += (uint64_t) size;
        if (stored == NULL) {
            status = "missing";
            cc->sum->missing++;
        } else if (strcasecmp(stored, computed) == 0) {
            status = "ok";
            cc->sum->ok++;
        } else {
            status = "mismatch";
            cc->sum->mismatch++;
        }
    }
    return brix_scan_record_file(v->line, v->linesz, v->logical, size, mtime,
                                   cc->alg, stored, computed, status);
}

/* Verify one enumerated catalog object: open it through the bound driver, build
 * the record, close. An open failure is reported as "unreadable" (the scan keeps
 * going). Returns 0 to continue the enumeration, 1 to abort (OOM only). */
static int
scan_catalog_verify_one(void *ctx, const brix_sd_catalog_ent_t *ent)
{
    scan_verify_ctx_t *cc = ctx;
    const char        *logical = ent->path ? ent->path : ent->key;
    brix_sd_obj_t   *obj;
    char               line[SCAN_LINE_MAX];
    int                err = 0;
    int                n;

    obj = cc->sd->driver->open(cc->sd, logical, BRIX_SD_O_READ, 0, &err);
    if (obj == NULL) {
        cc->sum->unreadable++;
        n = brix_scan_record_file(line, sizeof(line), logical,
                                    ent->have_stat ? (int64_t) ent->size : 0,
                                    ent->have_stat ? (int64_t) ent->mtime : 0,
                                    cc->alg, NULL, NULL, "unreadable");
    } else {
        scan_verify_obj_ctx_t v;

        ngx_memzero(&v, sizeof(v));
        v.cc = cc;
        v.logical = logical;
        v.ent = ent;
        v.obj = obj;
        v.line = line;
        v.linesz = sizeof(line);
        n = scan_verify_obj_record(&v);
        (void) cc->sd->driver->close(obj);
    }

    if (n < 0) {
        return 0;                          /* unrepresentable → soft skip */
    }
    cc->sum->files++;
    if (scan_append(cc->buf, cc->cap, cc->used, line, (size_t) n) < 0) {
        cc->oom = 1;
        return 1;
    }
    return 0;
}

ngx_int_t
brix_scan_run_verify_catalog(ngx_log_t *log, brix_sd_instance_t *sd,
    const brix_scan_opts_t *opts, u_char **buf, size_t *cap, size_t *used,
    brix_scan_summary_t *summary, uint16_t *err_code, char *err_msg,
    size_t err_sz)
{
    scan_verify_ctx_t cc;
    ngx_int_t         rc;

    ngx_memzero(&cc, sizeof(cc));
    cc.log = log;
    cc.sd = sd;
    cc.alg = opts->alg;
    cc.buf = buf;
    cc.cap = cap;
    cc.used = used;
    cc.sum = summary;

    rc = brix_vfs_enumerate_catalog(sd, 1 /* want_stat */,
                                      scan_catalog_verify_one, &cc);

    if (rc == NGX_DECLINED) {
        *err_code = kXR_Unsupported;
        snprintf(err_msg, err_sz, "backend does not support catalog enumeration");
        return NGX_ERROR;
    }
    if (rc != NGX_OK || cc.oom) {
        *err_code = cc.oom ? kXR_NoMemory : kXR_IOError;
        snprintf(err_msg, err_sz, "%s",
                 cc.oom ? "out of memory" : "catalog verify failed");
        return NGX_ERROR;
    }
    return NGX_OK;
}
