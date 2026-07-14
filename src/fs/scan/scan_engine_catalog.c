/*
 * scan_engine_catalog.c — catalog-enumeration scan path (split from
 * scan_engine.c). Whole-pool inventory + verify over a catalog-native backend's
 * enumerate verb (brix_vfs_enumerate_catalog), landing records in the same
 * growing heap buffer the POSIX walk uses via the shared scan_append helper.
 */
#include "scan_engine.h"
#include "scan_engine_internal.h"

#include "core/compat/integrity_info.h"
#include "fs/vfs/vfs.h"
#include "protocols/root/protocol/opcodes.h"

#include <limits.h>
#include <string.h>
#include <strings.h>

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
