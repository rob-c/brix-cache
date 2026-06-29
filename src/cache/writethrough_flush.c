#include "cache_internal.h"
#include "cinfo.h"              /* unified cache-state record (dirty/clean) */
#include "cache_storage.h"   /* write-back staging instance + key */
#include "../fs/backend/sd.h"   /* phase-55: route raw fd I/O through the SD seam */
#include "../fs/vfs_backend_registry.h" /* resolve a driver-backed primary export */
#include "../fs/vfs_internal.h"          /* xrootd_vfs_export_relative_root */
#include "../fs/xfer/xfer_spawn.h"  /* crash-safe reparented origin-client runner */
#include "../fs/xfer/xfer.h"        /* unified transfer audit ledger (kind=wt)    */
#include "../frm/frm.h"             /* shared durable journal (wt async durability)*/
#include "writethrough_metrics.h"
#include "../aio/aio.h"
#include "../path/path.h"   /* xrootd_open_confined — root-confined read-back */


#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

/* ---- durable-async journal (Phase 4b-2) ----------------------------------
 * Record an in-flight async WT flush in the shared durable journal (the FRM
 * queue) so a crash mid-flush leaves a recoverable record. Gated on a journal
 * being configured; without one, async stays best-effort exactly as before. The
 * record is keyed by kind=wt, so it never collides with a tape recall and is
 * skipped by the tape drain. */

/* Enqueue a wt record for wt->local_path and mark it in-flight (STAGING). Stores
 * the reqid in wt->xfer_reqid, or leaves it "" when no journal is available. */
static void
xrootd_wt_journal_begin(xrootd_wt_flush_t *wt)
{
    frm_queue_t   *q = frm_singleton_queue();
    frm_req_view_t v;
    char           reqid[sizeof(wt->xfer_reqid)];

    wt->xfer_reqid[0] = '\0';
    if (q == NULL || wt->local_path[0] == '\0') {
        return;                      /* no journal → non-durable, as before */
    }

    ngx_memzero(&v, sizeof(v));
    v.lfn            = wt->local_path;
    v.selector       = "wt";
    v.xfer_kind      = FRM_XFER_WT;
    v.xfer_mode_bits = wt->mode_bits;

    if (frm_request_add(q, &v, reqid, sizeof(reqid), wt->log) != NGX_OK) {
        return;                      /* dedup/full/error → skip journaling */
    }
    (void) frm_request_set_status(q, reqid, FRM_ST_STAGING, 0, wt->log);
    ngx_cpystrn((u_char *) wt->xfer_reqid, (u_char *) reqid,
                sizeof(wt->xfer_reqid));
}

/* Resolve a journaled flush: delete on success, mark FAILED (left for replay) on
 * failure. No-op when the flush was not journaled. */
static void
xrootd_wt_journal_finish(const xrootd_wt_flush_t *wt, int ok)
{
    frm_queue_t *q;

    if (wt->xfer_reqid[0] == '\0') {
        return;
    }
    q = frm_singleton_queue();
    if (q == NULL) {
        return;
    }
    if (ok) {
        (void) frm_request_delete(q, wt->xfer_reqid, wt->log);
    } else {
        (void) frm_request_set_status(q, wt->xfer_reqid, FRM_ST_FAILED,
                                      wt->sys_errno, wt->log);
    }
}

/* Cancel a journaled record — used when the async post fails and we fall back to
 * the synchronous path, which does not use the journal. */
static void
xrootd_wt_journal_cancel(xrootd_wt_flush_t *wt)
{
    frm_queue_t *q = frm_singleton_queue();

    if (wt->xfer_reqid[0] != '\0' && q != NULL) {
        (void) frm_request_delete(q, wt->xfer_reqid, wt->log);
        wt->xfer_reqid[0] = '\0';
    }
}

/* xrootd_wt_origin_path_from_local — map a local cache filesystem path to the
 * origin server path by stripping the cache_root (then xrootd_root) prefix, since
 * the origin expects a path relative to its own root. NGX_OK with origin_path, or
 * NGX_ERROR if neither prefix matches (file not in the managed namespace). */
static ngx_int_t
xrootd_wt_origin_path_from_local(ngx_stream_xrootd_srv_conf_t *conf,
    const char *local_path, char *origin_path, size_t origin_path_size)
{
    const ngx_str_t *prefixes[2];
    ngx_uint_t       i;

    if (local_path == NULL || origin_path == NULL || origin_path_size < 2) {
        return NGX_ERROR;
    }

    prefixes[0] = &conf->cache_root;
    prefixes[1] = &conf->common.root;

    for (i = 0; i < 2; i++) {
        const ngx_str_t *prefix = prefixes[i];
        size_t           plen;
        const char      *rel;

        if (prefix == NULL || prefix->data == NULL || prefix->len == 0) {
            continue;
        }

        plen = prefix->len;
        while (plen > 1 && prefix->data[plen - 1] == '/') {
            plen--;
        }

        if (ngx_strncmp((u_char *) local_path, prefix->data, plen) != 0) {
            continue;
        }

        if (plen == 1 && prefix->data[0] == '/') {
            if (ngx_strlen(local_path) + 1 > origin_path_size) {
                return NGX_ERROR;
            }
            ngx_cpystrn((u_char *) origin_path, (u_char *) local_path,
                        origin_path_size);
            return NGX_OK;
        }

        rel = local_path + plen;
        if (*rel == '\0') {
            ngx_cpystrn((u_char *) origin_path, (u_char *) "/",
                        origin_path_size);
            return NGX_OK;
        }

        if (*rel == '/') {
            if (ngx_strlen(rel) + 1 > origin_path_size) {
                return NGX_ERROR;
            }
            ngx_cpystrn((u_char *) origin_path, (u_char *) rel,
                        origin_path_size);
            return NGX_OK;
        }

        continue;
    }

    return NGX_ERROR;
}

/* xrootd_wt_open_local_confined — open wt->local_path under the export-root
 * confinement cascade (openat2 RESOLVE_BENEATH, O_NOFOLLOW fallback), picking the
 * root the path lives under (cache_root first, then the export root) the same way
 * xrootd_wt_origin_path_from_local does. This replaces a raw open() of an absolute
 * path, so a symlink/parent swap can no longer redirect the read-back outside the
 * managed namespace. Syscall-only (no pool/metrics/log), so it is safe from the
 * async flush worker as well as the event loop. Returns the fd (caller closes) or
 * -1 (EXDEV when no root matches). */
static int
xrootd_wt_open_local_confined(const xrootd_wt_flush_t *wt, int flags)
{
    const ngx_str_t *roots[2];
    ngx_uint_t       i;

    if (wt == NULL || wt->conf == NULL || wt->local_path[0] != '/') {
        errno = EINVAL;
        return -1;
    }

    roots[0] = &wt->conf->cache_root;
    roots[1] = &wt->conf->common.root;

    for (i = 0; i < 2; i++) {
        const ngx_str_t *root = roots[i];
        size_t           plen;

        if (root == NULL || root->data == NULL || root->len == 0) {
            continue;
        }

        plen = root->len;
        while (plen > 1 && root->data[plen - 1] == '/') {
            plen--;
        }

        /* local_path must be the root itself or a path beneath it. */
        if (ngx_strncmp((u_char *) wt->local_path, root->data, plen) != 0) {
            continue;
        }
        if (!(plen == 1 || wt->local_path[plen] == '/'
              || wt->local_path[plen] == '\0')) {
            continue;
        }

        return xrootd_open_confined(wt->log, root, wt->local_path, flags, 0);
    }

    errno = EXDEV;
    return -1;
}

/* xrootd_wt_copy_error — normalize a failed cache_fill_t (used internally for the
 * origin-side I/O) into the flush task's error fields (result/xrd_error/sys_errno/
 * err_msg) so the public flush API reports it consistently. */
static void
xrootd_wt_copy_error(xrootd_wt_flush_t *wt, xrootd_cache_fill_t *fill)
{
    wt->result = NGX_ERROR;
    wt->xrd_error = fill->xrd_error ? fill->xrd_error : kXR_ServerError;
    wt->sys_errno = fill->sys_errno;
    ngx_cpystrn((u_char *) wt->err_msg,
                (u_char *) (fill->err_msg[0] ? fill->err_msg
                                              : "write-through flush failed"),
                sizeof(wt->err_msg));
}

/* xrootd_wt_init_task — validate the flush request (idx, fd, wt_enabled, dirty
 * offset) and populate the xrootd_wt_flush_t (conf, log, mode bits, local/origin
 * paths) shared by the sync and async entry points. NGX_DECLINED when there is no
 * dirty data, NGX_OK on success, NGX_ERROR on validation or origin-path failure. */
static ngx_int_t
xrootd_wt_init_task(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int idx, const char *local_path,
    xrootd_wt_flush_t *wt)
{
    const char *path;

    ngx_memzero(wt, sizeof(*wt));

    if (idx < 0 || idx >= XROOTD_MAX_FILES
        || ctx->files[idx].fd < 0
        || !ctx->files[idx].wt_enabled
        || ctx->files[idx].wt_dirty_offset < 0)
    {
        return NGX_DECLINED;
    }

    path = (local_path != NULL) ? local_path : ctx->files[idx].path;
    if (path == NULL || path[0] == '\0') {
        return NGX_ERROR;
    }

    wt->conf = conf;
    wt->log = c->log;
    wt->metrics = (ctx != NULL) ? ctx->metrics : NULL;
    wt->mode_bits = ctx->files[idx].wt_mode_bits;
    wt->result = NGX_OK;

    ngx_cpystrn((u_char *) wt->local_path, (u_char *) path,
                sizeof(wt->local_path));

    if (xrootd_wt_origin_path_from_local(conf, path, wt->origin_path,
                                         sizeof(wt->origin_path))
        != NGX_OK)
    {
        ngx_cpystrn((u_char *) wt->err_msg,
                    (u_char *) "write-through origin path derivation failed",
                    sizeof(wt->err_msg));
        wt->xrd_error = kXR_ArgInvalid;
        return NGX_ERROR;
    }

    /* Driver-backed primary (cache fronts a VFS backend): when the export uses a
     * non-POSIX storage driver (pblock/object/tape) and `path` is under the export
     * root, the local bytes are block-striped — open a READ object through the
     * driver HERE (main thread, so a pblock catalog lookup never runs on the async
     * worker). The flush worker reads it via sd_obj.driver->pread (block-aware) and
     * closes it after. A file under cache_root (not the export root) keeps the raw
     * POSIX read-back (cache storage is POSIX). */
    {
        xrootd_sd_instance_t *sd =
            xrootd_vfs_backend_resolve(conf->common.root_canon, c->log);
        const char *key =
            xrootd_vfs_export_relative_root(path, conf->common.root_canon);

        if (sd != NULL && sd->driver->open != NULL && key != path) {
            xrootd_sd_obj_t *wh = &ctx->files[idx].sd_obj;
            int              derr = 0;
            xrootd_sd_obj_t *o;

            /* The still-open WRITE handle holds the just-written size in memory,
             * not yet committed to the catalog (the flush runs before the handle's
             * close). fsync it here — pblock's fsync flushes the block data AND
             * commits the catalog size/mtime — so the fresh READ object opened
             * below sees the live size (its pread clamps to the recorded size).
             * Best-effort: a fsync failure just leaves a possibly-short read. */
            if (wh->driver != NULL && wh->driver->fsync != NULL) {
                (void) wh->driver->fsync(wh);
            }

            o = sd->driver->open(sd, key, XROOTD_SD_O_READ, 0, &derr);
            if (o == NULL) {
                ngx_cpystrn((u_char *) wt->err_msg,
                    (u_char *) "write-through driver open of local file failed",
                    sizeof(wt->err_msg));
                wt->xrd_error = kXR_IOError;
                wt->sys_errno = derr;
                return NGX_ERROR;
            }
            wt->sd_obj = *o;               /* adopt by value */
            if (o->heap_shell) {
                free(o);
            }
            wt->sd_obj.heap_shell = 0;
            wt->sd_size = (off_t) wt->sd_obj.snap.size;   /* committed size */
            wt->sd_has_obj = 1;
        }
    }

    return NGX_OK;
}

/*
 * xrootd_wt_copy_body — stream the local file to an already-open origin handle.
 *
 * With the origin write handle already open, reads [0, file_size) from fd in
 * XROOTD_CACHE_FETCH_CHUNK windows (caller-provided buf), writing each chunk to
 * the origin, then truncates + syncs the origin to file_size. Returns 0 on
 * success, -1 on any failure with *fill populated (kXR error / errno / message).
 *
 * The origin/local handles and buf are owned by the caller and released there;
 * keeping that cleanup at the edge lets this worker use flat early returns.
 */
static int
xrootd_wt_copy_body(xrootd_cache_fill_t *fill, xrootd_cache_origin_conn_t *oc,
    xrootd_sd_obj_t *obj, off_t file_size, const u_char *fhandle, u_char *buf)
{
    off_t offset = 0;

    /* Read through the bound storage object: a driver-backed primary's blocks, or
     * a POSIX wrap of the confined fd for the default export. */
    while (offset < file_size) {
        size_t  want;
        ssize_t nread;

        want = (size_t) (file_size - offset);
        if (want > XROOTD_CACHE_FETCH_CHUNK) {
            want = XROOTD_CACHE_FETCH_CHUNK;
        }

        nread = obj->driver->pread(obj, buf, want, offset);
        if (nread < 0) {
            xrootd_cache_set_error(fill, kXR_IOError, errno,
                                   "write-through local read failed");
            return -1;
        }
        if (nread == 0) {
            xrootd_cache_set_error(fill, kXR_IOError, 0,
                                   "write-through local file changed during flush");
            return -1;
        }

        if (xrootd_cache_origin_write_chunk(fill, oc, fhandle,
                                            (uint64_t) offset, buf,
                                            (size_t) nread)
            != 0)
        {
            return -1;
        }

        offset += nread;
    }

    if (xrootd_cache_origin_truncate(fill, oc, fhandle,
                                     (uint64_t) file_size) != 0
        || xrootd_cache_origin_sync(fill, oc, fhandle) != 0)
    {
        return -1;
    }

    return 0;
}

/* The core flush engine (both sync and async paths call it after init): the full
 * write-back of dirty cached data to the origin — connect + login, open a writable
 * handle on origin_path, chunked pread of the local file with
 * xrootd_cache_origin_write_chunk per chunk, then truncate + sync + close.
 * wt->result = NGX_OK on success; failure routes through xrootd_wt_copy_error and
 * the unified close-handles cleanup. */
/* xrootd_wt_run_flush_exec — mirror the local file to a GSI origin (e.g. EOS) by
 * fork/exec'ing the native client (cache_origin_client, default "xrdcp") to upload
 * local_path → root[s]://host:port//origin_path with X509_USER_PROXY +
 * X509_CERT_DIR overridden. The built-in write-back only does an anonymous
 * kXR_login, which a GSI origin rejects; this is the write-side mirror of the
 * read-fetch GSI exec path. The client is run via the shared crash-safe
 * reparented runner (xrootd_xfer_run_reparented) so nginx never reaps it; this
 * blocks the caller (event loop in sync mode, thread-pool worker in async mode).
 * A clean exit(0) records bytes_flushed from the local size. */
static void
xrootd_wt_run_flush_exec(xrootd_wt_flush_t *wt)
{
    ngx_stream_xrootd_srv_conf_t *conf = wt->conf;
    const ngx_str_t *host;
    uint16_t         port;
    char        url[XROOTD_MAX_PATH + 320];
    char        proxy_env[XROOTD_MAX_PATH + 32];
    char        cadir_env[XROOTD_MAX_PATH + 32];
    const char *client;
    char      **envp;
    char       *argv[6];
    struct stat st;
    int         n, rc, ai;
    size_t      envn, ei;

    host = conf->wt_origin_host.len > 0 ? &conf->wt_origin_host
                                        : &conf->cache_origin_host;
    port = conf->wt_origin_host.len > 0 ? conf->wt_origin_port
                                        : conf->cache_origin_port;

    if (host->len == 0 || port == 0) {
        wt->result = NGX_ERROR;
        wt->xrd_error = kXR_ServerError;
        ngx_cpystrn((u_char *) wt->err_msg,
                    (u_char *) "write-through origin not configured",
                    sizeof(wt->err_msg));
        return;
    }

    /*
     * Validate the local file under root confinement (O_NOFOLLOW + RESOLVE_BENEATH)
     * rather than a raw path stat(): the result (S_ISREG + size for bytes_flushed)
     * is taken from an fstat on the confined fd, so a symlink/parent swap under the
     * cache/export root cannot point the validation (or the size we later report)
     * at a file outside the managed namespace. The fd is closed immediately — the
     * upload itself is performed by the spawned client against local_path.
     */
    {
        int sfd = xrootd_wt_open_local_confined(wt, O_RDONLY | O_NOFOLLOW);

        if (sfd < 0 || fstat(sfd, &st) != 0 || !S_ISREG(st.st_mode)) {
            wt->result = NGX_ERROR;
            wt->sys_errno = errno;
            wt->xrd_error = kXR_IOError;
            ngx_cpystrn((u_char *) wt->err_msg,
                        (u_char *) "write-through local file invalid",
                        sizeof(wt->err_msg));
            if (sfd >= 0) {
                close(sfd);
            }
            return;
        }
        close(sfd);
    }

    /* root[s]://host:port//<origin_path>  (origin_path carries its leading '/') */
    n = snprintf(url, sizeof(url), "%s://%s:%u/%s",
                 conf->cache_origin_tls ? "roots" : "root",
                 (char *) host->data, (unsigned) port, wt->origin_path);
    if (n < 0 || (size_t) n >= sizeof(url)) {
        wt->result = NGX_ERROR;
        wt->xrd_error = kXR_ArgInvalid;
        ngx_cpystrn((u_char *) wt->err_msg,
                    (u_char *) "write-through origin URL too long",
                    sizeof(wt->err_msg));
        return;
    }

    snprintf(proxy_env, sizeof(proxy_env), "X509_USER_PROXY=%s",
             (char *) conf->cache_origin_proxy.data);
    snprintf(cadir_env, sizeof(cadir_env), "X509_CERT_DIR=%s",
             (char *) conf->cache_origin_cadir.data);

    client = conf->cache_origin_client.len
             ? (char *) conf->cache_origin_client.data : "xrdcp";

    for (envn = 0; environ[envn] != NULL; envn++) { /* count */ }
    envp = malloc((envn + 3) * sizeof(char *));
    if (envp == NULL) {
        wt->result = NGX_ERROR;
        wt->xrd_error = kXR_NoMemory;
        ngx_cpystrn((u_char *) wt->err_msg,
                    (u_char *) "write-through envp alloc failed",
                    sizeof(wt->err_msg));
        return;
    }
    ei = 0;
    for (n = 0; (size_t) n < envn; n++) {
        if (strncmp(environ[n], "X509_USER_PROXY=", 16) == 0
            || strncmp(environ[n], "X509_CERT_DIR=", 14) == 0) {
            continue;
        }
        envp[ei++] = environ[n];
    }
    envp[ei++] = proxy_env;
    envp[ei++] = cadir_env;
    envp[ei]   = NULL;

    ai = 0;
    argv[ai++] = (char *) client;
    argv[ai++] = (char *) "-f";          /* overwrite the origin object */
    argv[ai++] = wt->local_path;
    argv[ai++] = url;
    argv[ai]   = NULL;

    /* Run the client through the shared crash-safe reparented runner instead of
     * posix_spawn: the upload process becomes a descendant of init, so nginx
     * never reaps it (the posix_spawn child was a direct worker child — the same
     * SIGCHLD/SHM master-crash hazard the FRM agent was built to avoid). Blocking
     * here is unchanged: sync mode runs on the flush call, async mode in the
     * thread-pool worker. */
    rc = xrootd_xfer_run_reparented((const char *const *) argv, envp);
    free(envp);
    if (rc < 0) {
        wt->result = NGX_ERROR;
        wt->sys_errno = errno;
        wt->xrd_error = kXR_ServerError;
        ngx_cpystrn((u_char *) wt->err_msg,
                    (u_char *) "write-through origin client spawn failed",
                    sizeof(wt->err_msg));
        return;
    }
    if (rc != 0) {
        wt->result = NGX_ERROR;
        wt->xrd_error = kXR_AuthFailed;
        snprintf(wt->err_msg, sizeof(wt->err_msg),
                 "origin GSI write-back via %s failed (exit %d)", client, rc);
        return;
    }

    wt->bytes_flushed = (st.st_size > 0) ? (size_t) st.st_size : 0;
    wt->result = NGX_OK;
}

/* Best-effort: mirror the local file's dirty/clean state into the unified cache
 * state record (.cinfo). Marking it dirty keeps the eviction guard from
 * reclaiming an un-flushed file and lets the stale-dirty reaper bound an
 * abandoned write-back; marking it clean on a successful flush releases both.
 * No-op when no state root is configured, or when the local file is not under
 * the export root (the state path is keyed off root_canon). Failures are logged
 * implicitly by the cinfo layer and never affect the flush result. */
static void
xrootd_wt_state_mark_dirty(const xrootd_wt_flush_t *wt)
{
    char        sp[PATH_MAX];
    struct stat st;

    if (wt == NULL || xrootd_cache_state_root(wt->conf) == NULL) {
        return;
    }
    if (xrootd_cache_state_path(wt->conf, wt->local_path, sp, sizeof(sp))
        != NGX_OK)
    {
        return;
    }
    if (stat(wt->local_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return;
    }
    (void) xrootd_cache_cinfo_mark_dirty(sp, (uint64_t) st.st_size,
        XROOTD_CACHE_DIRTY_BLOCK, (uint64_t) st.st_mtime, 0,
        (uint64_t) (st.st_size > 0 ? st.st_size : 1), wt->log);
}

static void
xrootd_wt_state_mark_clean(const xrootd_wt_flush_t *wt)
{
    char sp[PATH_MAX];

    if (wt == NULL || xrootd_cache_state_root(wt->conf) == NULL) {
        return;
    }
    if (xrootd_cache_state_path(wt->conf, wt->local_path, sp, sizeof(sp))
        != NGX_OK)
    {
        return;
    }
    (void) xrootd_cache_cinfo_mark_clean(sp, (uint64_t) wt->bytes_flushed,
                                         wt->log);
}

/* Release the driver-backed local read object (no-op for a POSIX export). */
static void
xrootd_wt_close_local_obj(xrootd_wt_flush_t *wt)
{
    if (wt->sd_has_obj) {
        (void) wt->sd_obj.driver->close(&wt->sd_obj);
        wt->sd_has_obj = 0;
        wt->sd_obj.driver = NULL;
    }
}

static void
xrootd_wt_close_stage_obj(xrootd_wt_flush_t *wt)
{
    if (wt->has_stage_obj) {
        (void) wt->stage_obj.driver->close(&wt->stage_obj);
        wt->has_stage_obj = 0;
        wt->stage_obj.driver = NULL;
    }
}

/* Copy [0,size) from `src` into staging instance `si` under `key` via staged_*.
 * Returns NGX_OK on a committed copy. The staged content becomes the durable,
 * immutable bytes the flush (and any replay) mirrors from. */
static ngx_int_t
xrootd_wt_stage_copy(xrootd_sd_instance_t *si, const char *key,
    xrootd_sd_obj_t *src, off_t size)
{
    xrootd_sd_staged_t *staged;
    u_char             *buf;
    off_t               off = 0;
    int                 e = 0;

    staged = si->driver->staged_open(si, key, 0644, &e);
    if (staged == NULL) {
        return NGX_ERROR;
    }
    buf = malloc(XROOTD_CACHE_FETCH_CHUNK);
    if (buf == NULL) {
        si->driver->staged_abort(staged);
        return NGX_ERROR;
    }
    while (off < size) {
        size_t  want = (size_t) (size - off);
        ssize_t n;

        if (want > XROOTD_CACHE_FETCH_CHUNK) {
            want = XROOTD_CACHE_FETCH_CHUNK;
        }
        n = src->driver->pread(src, buf, want, off);
        if (n <= 0
            || si->driver->staged_write(staged, buf, (size_t) n, off)
               != (ssize_t) n)
        {
            free(buf);
            si->driver->staged_abort(staged);
            return NGX_ERROR;
        }
        off += n;
    }
    free(buf);
    return si->driver->staged_commit(staged, 0);
}

static void
xrootd_wt_run_flush(xrootd_wt_flush_t *wt)
{
    xrootd_cache_fill_t        fill;
    xrootd_cache_origin_conn_t oc;
    const ngx_str_t           *host;
    uint16_t                   port;
    u_char                     fhandle[XRD_FHANDLE_LEN];
    u_char                    *buf;
    struct stat                st;
    int                        fd = -1;
    xrootd_sd_obj_t            posix_obj;
    xrootd_sd_obj_t           *read_obj;
    off_t                      file_size;
    int                        opened_origin;
    int                        rc;

    wt->bytes_flushed = 0;

    /* Record the local file dirty in the unified state engine before the mirror
     * starts: the eviction guard then protects it, and an abandoned flush is
     * bounded by the stale-dirty reaper. Cleared on success at the call sites. */
    xrootd_wt_state_mark_dirty(wt);

    /* GSI/X.509 origin (e.g. EOS): the built-in write-back only does an
     * anonymous login, which such an origin rejects. Delegate to the native
     * client with the configured proxy (write-side mirror of the read fetch). */
    if (wt->conf->cache_origin_proxy.len > 0) {
        if (wt->sd_has_obj) {
            /* The proxy path spawns an external client that reads the LOCAL path
             * directly — it cannot read a driver backend's blocks. Unsupported
             * combo; fail clearly rather than mirror nothing. (Materialising the
             * driver file to a POSIX scratch copy first is the follow-on.) */
            xrootd_wt_close_local_obj(wt);
            wt->result = NGX_ERROR;
            wt->xrd_error = kXR_Unsupported;
            ngx_cpystrn((u_char *) wt->err_msg,
                (u_char *) "write-through via GSI/proxy origin unsupported for a "
                           "driver-backed export",
                sizeof(wt->err_msg));
            return;
        }
        xrootd_wt_run_flush_exec(wt);
        return;
    }

    ngx_memzero(&fill, sizeof(fill));
    fill.conf = wt->conf;
    fill.result = NGX_OK;
    ngx_cpystrn((u_char *) fill.clean_path, (u_char *) wt->origin_path,
                sizeof(fill.clean_path));

    host = wt->conf->wt_origin_host.len > 0 ? &wt->conf->wt_origin_host
                                            : &wt->conf->cache_origin_host;
    port = wt->conf->wt_origin_host.len > 0 ? wt->conf->wt_origin_port
                                            : wt->conf->cache_origin_port;

    if (host->len == 0 || port == 0) {
        fill.xrd_error = kXR_ServerError;
        ngx_cpystrn((u_char *) fill.err_msg,
                    (u_char *) "write-through origin not configured",
                    sizeof(fill.err_msg));
        xrootd_wt_close_local_obj(wt);
        xrootd_wt_copy_error(wt, &fill);
        return;
    }

    if (wt->sd_has_obj) {
        /* Driver-backed primary: read the block-striped/object data through the
         * driver object opened on the main thread (init_task). The size is the
         * driver's open snapshot. */
        read_obj = &wt->sd_obj;
        file_size = wt->sd_size;
    } else {
        /* Default POSIX export: confined read-back of the raw local file. */
        fd = xrootd_wt_open_local_confined(wt, O_RDONLY | O_NOFOLLOW);
        if (fd < 0) {
            fill.sys_errno = errno;
            fill.xrd_error = kXR_IOError;
            ngx_cpystrn((u_char *) fill.err_msg,
                        (u_char *) "write-through local open failed",
                        sizeof(fill.err_msg));
            xrootd_wt_copy_error(wt, &fill);
            return;
        }
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
            fill.sys_errno = errno;
            fill.xrd_error = kXR_IOError;
            ngx_cpystrn((u_char *) fill.err_msg,
                        (u_char *) "write-through local file invalid",
                        sizeof(fill.err_msg));
            close(fd);
            xrootd_wt_copy_error(wt, &fill);
            return;
        }
        xrootd_sd_posix_wrap(&posix_obj, fd);
        read_obj = &posix_obj;
        file_size = st.st_size;
    }

    /* Write-back staging cache: when a staging role is configured, mirror FROM a
     * durable staged copy keyed by the logical path (not the live primary), so a
     * flush re-driven by writethrough_replay after a restart reads immutable bytes.
     * The copy is made once (a replay reuses an existing stage). The FRM journal
     * stays the write-back state engine; on success mark_clean lets the reaper
     * reclaim the stage. */
    {
        xrootd_sd_instance_t *si = xrootd_cache_wt_stage(wt->conf);
        const char           *skey = (si != NULL)
            ? xrootd_vfs_export_relative_root(wt->local_path,
                                              wt->conf->common.root_canon)
            : NULL;

        if (si != NULL && si->driver->open != NULL && skey != NULL
            && skey != wt->local_path)
        {
            xrootd_sd_stat_t sst;
            int              e = 0;
            xrootd_sd_obj_t *so;

            if (si->driver->stat(si, skey, &sst) != NGX_OK) {
                if (xrootd_wt_stage_copy(si, skey, read_obj, file_size)
                    != NGX_OK)
                {
                    xrootd_cache_set_error(&fill, kXR_IOError, errno,
                                           "write-through stage copy failed");
                    if (wt->sd_has_obj) { xrootd_wt_close_local_obj(wt); }
                    else if (fd >= 0) { close(fd); }
                    xrootd_wt_copy_error(wt, &fill);
                    return;
                }
            }
            so = si->driver->open(si, skey, XROOTD_SD_O_READ, 0, &e);
            if (so != NULL) {
                if (wt->sd_has_obj) { xrootd_wt_close_local_obj(wt); }
                else if (fd >= 0) { close(fd); fd = -1; }
                wt->stage_obj = *so;
                if (so->heap_shell) { free(so); }
                wt->stage_obj.heap_shell = 0;
                wt->has_stage_obj = 1;
                read_obj = &wt->stage_obj;
                if (si->driver->stat(si, skey, &sst) == NGX_OK) {
                    file_size = (off_t) sst.size;
                }
            }
        }
    }

    oc.fd = -1;
    oc.ssl_ctx = NULL;
    oc.ssl = NULL;
    opened_origin = 0;
    buf = NULL;
    rc = -1;

    if (xrootd_cache_origin_connect_addr(&fill, &oc, host, port) == 0
        && xrootd_cache_origin_bootstrap(&fill, &oc) == 0
        && xrootd_cache_origin_open_write(&fill, &oc, wt->origin_path,
                                          wt->mode_bits, fhandle) == 0)
    {
        opened_origin = 1;

        buf = malloc(XROOTD_CACHE_FETCH_CHUNK);
        if (buf == NULL) {
            xrootd_cache_set_error(&fill, kXR_NoMemory, 0,
                                   "write-through buffer allocation failed");
        } else {
            rc = xrootd_wt_copy_body(&fill, &oc, read_obj, file_size, fhandle,
                                     buf);
        }
    }

    /* Unified cleanup for success and every failure: close the origin file
     * (only when it was actually opened), the origin link, the transfer buffer,
     * and the local read object — a driver object via its driver->close, else the
     * raw confined fd — then report the outcome. */
    if (opened_origin) {
        xrootd_cache_origin_close_file(&oc, fhandle);
    }
    xrootd_cache_origin_close(&oc);
    free(buf);
    xrootd_wt_close_stage_obj(wt);
    if (wt->sd_has_obj) {
        xrootd_wt_close_local_obj(wt);
    } else if (fd >= 0) {
        close(fd);
    }

    if (rc != 0) {
        xrootd_wt_copy_error(wt, &fill);
        return;
    }

    wt->bytes_flushed = (file_size > 0) ? (size_t) file_size : 0;
    wt->result = NGX_OK;
}

/* xrootd_wt_flush_sync_handle — init a flush task and run it synchronously,
 * reporting only a STATUS (never the wire) so the *caller* (kXR_sync / kXR_close)
 * owns the single response and a failure surfaces exactly once as kXR_error.
 * `fail_status` only selects the dashboard event's error label. Returns NGX_OK on
 * success or no-dirty-data, NGX_ERROR on init/write-back failure (caller must then
 * send an error). On success it clears the handle's dirty marker. */
ngx_int_t
xrootd_wt_flush_sync_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int idx, const char *local_path,
    uint16_t fail_status)
{
    xrootd_wt_flush_t wt;
    ngx_int_t         rc;

    rc = xrootd_wt_init_task(ctx, c, conf, idx, local_path, &wt);
    if (rc == NGX_DECLINED) {
        return NGX_OK;
    }
    if (rc != NGX_OK) {
        xrootd_wt_metric_flush_error(ctx ? ctx->metrics : NULL);
        xrootd_dashboard_event_add(XROOTD_DASH_EVENT_IO, XROOTD_XFER_PROTO_ROOT,
                                   fail_status ? fail_status : kXR_ServerError,
                                   wt.err_msg[0] ? wt.err_msg
                                                 : "write-through flush init failed",
                                   local_path ? local_path : "-");
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "wt: %s",
                      wt.err_msg[0] ? wt.err_msg
                                    : "write-through flush init failed");
        return NGX_ERROR;
    }

    xrootd_wt_run_flush(&wt);
    if (wt.result == NGX_OK) {
        xrootd_wt_mark_clean(ctx, idx);
        xrootd_wt_state_mark_clean(&wt);   /* clear the durable dirty record */
        xrootd_wt_metric_flush_success(wt.metrics, wt.bytes_flushed);
        xrootd_log_access(ctx, c, "WT", wt.origin_path, "flush",
                          1, 0, NULL, 0);
        xrootd_xfer_finish(XROOTD_XFER_WT, "out", wt.origin_path, NULL,
                           wt.bytes_flushed, XROOTD_XFER_OK, 0, c->log);
        return NGX_OK;
    }

    xrootd_wt_metric_flush_error(wt.metrics);
    xrootd_dashboard_event_add(XROOTD_DASH_EVENT_IO, XROOTD_XFER_PROTO_ROOT,
                               fail_status ? fail_status
                                           : (wt.xrd_error ? wt.xrd_error
                                                           : kXR_ServerError),
                               wt.err_msg[0] ? wt.err_msg
                                             : "write-through flush failed",
                               wt.origin_path[0] ? wt.origin_path
                                                 : wt.local_path);

    ngx_log_error(NGX_LOG_ERR, c->log, wt.sys_errno,
                  "wt: flush failed local=\"%s\" origin=\"%s\": %s",
                  wt.local_path, wt.origin_path,
                  wt.err_msg[0] ? wt.err_msg : "write-through flush failed");
    xrootd_log_access(ctx, c, "WT", wt.origin_path, "flush",
                      0, wt.xrd_error ? wt.xrd_error : kXR_ServerError,
                      wt.err_msg[0] ? wt.err_msg : "write-through flush failed",
                      0);
    xrootd_xfer_finish(XROOTD_XFER_WT, "out",
                       wt.origin_path[0] ? wt.origin_path : wt.local_path,
                       NULL, 0, XROOTD_XFER_DST_ERR, wt.sys_errno, c->log);

    return NGX_ERROR;
}

/* xrootd_wt_flush_on_close — kXR_close flush entry point: init a task, then run it
 * async (nginx thread pool) or sync per wt_mode. A flush can block for large files,
 * so async mode (when a thread pool is available) keeps the connection responsive
 * — it sets wt_flush_pending and returns; sync mode and any post/fallback failure
 * delegate to xrootd_wt_flush_sync_handle. NGX_OK with no dirty data. */
ngx_int_t
xrootd_wt_flush_on_close(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int idx, const char *local_path)
{
    xrootd_wt_flush_t     wt;
    ngx_thread_task_t    *task;
    ngx_int_t             rc;

    rc = xrootd_wt_init_task(ctx, c, conf, idx, local_path, &wt);
    if (rc == NGX_DECLINED) {
        return NGX_OK;
    }
    if (rc != NGX_OK) {
        xrootd_wt_metric_flush_error(ctx ? ctx->metrics : NULL);
        xrootd_dashboard_event_add(XROOTD_DASH_EVENT_IO, XROOTD_XFER_PROTO_ROOT,
                                   kXR_ServerError,
                                   wt.err_msg[0] ? wt.err_msg
                                                 : "write-through flush init failed",
                                   local_path ? local_path : "-");
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "wt: %s",
                      wt.err_msg[0] ? wt.err_msg
                                    : "write-through flush init failed");
        /* Sync mode must surface the failure to the client's close; async is
         * fire-and-forget and returns OK (the failure is logged + metered). */
        return (conf->wt_mode == XROOTD_WT_MODE_ASYNC) ? NGX_OK : NGX_ERROR;
    }

    if (conf->wt_mode == XROOTD_WT_MODE_ASYNC && conf->common.thread_pool != NULL) {
        task = ngx_calloc(sizeof(ngx_thread_task_t) + sizeof(xrootd_wt_flush_t),
                          c->log);
        if (task != NULL) {
            xrootd_wt_flush_t *async_wt;

            task->ctx = task + 1;
            async_wt = task->ctx;
            /* Durably record the in-flight flush BEFORE the copy, so the worker
             * task carries the reqid and a crash leaves a recoverable record. */
            xrootd_wt_journal_begin(&wt);
            ngx_memcpy(async_wt, &wt, sizeof(wt));

            xrootd_task_bind(task, xrootd_wt_flush_thread, xrootd_wt_flush_done);

            if (ngx_thread_task_post(conf->common.thread_pool, task) == NGX_OK) {
                ctx->files[idx].wt_flush_pending = 1;
                xrootd_wt_metric_pending_inc(async_wt->metrics);
                xrootd_log_access(ctx, c, "WT", wt.origin_path, "async",
                                  1, 0, NULL, 0);
                return NGX_OK;
            }

            /* post failed → drop the journal record and fall back to sync. */
            xrootd_wt_journal_cancel(&wt);
            ngx_free(task);
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "wt: async flush post failed, falling back to sync");
        }
    }

    return xrootd_wt_flush_sync_handle(ctx, c, conf, idx, local_path, 0);
}

/* xrootd_wt_flush_thread — nginx thread-pool worker callback for an async flush:
 * cast data → xrootd_wt_flush_t and delegate to xrootd_wt_run_flush, blocking on
 * origin I/O in the worker thread while the event loop stays free. */
void
xrootd_wt_flush_thread(void *data, ngx_log_t *log)
{
    xrootd_wt_flush_t *wt = data;

    (void) log;
    xrootd_wt_run_flush(wt);
}

/* Async flush completion callback (event loop) — invoked when the thread pool
 * finishes the task: log success/failure with local/origin paths + error message,
 * then free the ngx_thread_task. */
void
xrootd_wt_flush_done(ngx_event_t *ev)
{
    ngx_thread_task_t *task = ev->data;
    xrootd_wt_flush_t *wt = task->ctx;

    xrootd_wt_metric_pending_dec(wt->metrics);

    /* Resolve the durable record: delete on success, leave FAILED for replay. */
    xrootd_wt_journal_finish(wt, wt->result == NGX_OK);

    if (wt->result == NGX_OK) {
        xrootd_wt_state_mark_clean(wt);    /* clear the durable dirty record */
        xrootd_wt_metric_flush_success(wt->metrics, wt->bytes_flushed);
        ngx_log_error(NGX_LOG_INFO, wt->log, 0,
                      "wt: async flush completed local=\"%s\" origin=\"%s\"",
                      wt->local_path, wt->origin_path);
        xrootd_xfer_finish(XROOTD_XFER_WT, "out", wt->origin_path, NULL,
                           wt->bytes_flushed, XROOTD_XFER_OK, 0, wt->log);
    } else {
        xrootd_wt_metric_flush_error(wt->metrics);
        xrootd_dashboard_event_add(XROOTD_DASH_EVENT_IO, XROOTD_XFER_PROTO_ROOT,
                                   wt->xrd_error ? wt->xrd_error
                                                 : kXR_ServerError,
                                   wt->err_msg[0] ? wt->err_msg
                                                  : "write-through flush failed",
                                   wt->origin_path[0] ? wt->origin_path
                                                      : wt->local_path);
        ngx_log_error(NGX_LOG_ERR, wt->log, wt->sys_errno,
                      "wt: async flush failed local=\"%s\" origin=\"%s\": %s",
                      wt->local_path, wt->origin_path,
                      wt->err_msg[0] ? wt->err_msg
                                     : "write-through flush failed");
        xrootd_xfer_finish(XROOTD_XFER_WT, "out",
                           wt->origin_path[0] ? wt->origin_path : wt->local_path,
                           NULL, 0, XROOTD_XFER_DST_ERR, wt->sys_errno, wt->log);
    }

    ngx_free(task);
}

/*
 * xrootd_wt_flush_post_replay — re-drive a journaled WT flush recovered on
 * restart (Phase 4b-2b-ii). Builds a flush task from a recovered record (local
 * path + origin mode bits + its reqid) and posts it to the thread pool; the
 * normal completion path (xrootd_wt_flush_done) deletes the record on success or
 * marks it FAILED for a bounded later retry. Runs detached from any client —
 * there is no ctx/connection, so metrics are skipped (NULL). Returns NGX_OK
 * posted, NGX_ERROR on origin-path derivation / alloc / post failure.
 */
ngx_int_t
xrootd_wt_flush_post_replay(ngx_stream_xrootd_srv_conf_t *conf,
    ngx_thread_pool_t *tp, const char *local_path, const char *reqid,
    uint16_t mode_bits, ngx_log_t *log)
{
    xrootd_wt_flush_t  wt;
    ngx_thread_task_t *task;
    xrootd_wt_flush_t *async_wt;

    if (conf == NULL || tp == NULL || local_path == NULL
        || local_path[0] == '\0')
    {
        return NGX_ERROR;
    }

    ngx_memzero(&wt, sizeof(wt));
    wt.conf      = conf;
    wt.log       = log;
    wt.metrics   = NULL;
    wt.mode_bits = mode_bits;
    wt.result    = NGX_OK;
    ngx_cpystrn((u_char *) wt.local_path, (u_char *) local_path,
                sizeof(wt.local_path));
    if (xrootd_wt_origin_path_from_local(conf, local_path, wt.origin_path,
                                         sizeof(wt.origin_path)) != NGX_OK)
    {
        return NGX_ERROR;
    }
    ngx_cpystrn((u_char *) wt.xfer_reqid, (u_char *) reqid,
                sizeof(wt.xfer_reqid));

    task = ngx_calloc(sizeof(ngx_thread_task_t) + sizeof(xrootd_wt_flush_t), log);
    if (task == NULL) {
        return NGX_ERROR;
    }
    task->ctx = task + 1;
    async_wt = task->ctx;
    ngx_memcpy(async_wt, &wt, sizeof(wt));
    xrootd_task_bind(task, xrootd_wt_flush_thread, xrootd_wt_flush_done);

    if (ngx_thread_task_post(tp, task) != NGX_OK) {
        ngx_free(task);
        return NGX_ERROR;
    }
    return NGX_OK;
}
