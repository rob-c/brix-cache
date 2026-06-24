#include "cache_internal.h"
#include "writethrough_metrics.h"
#include "../aio/aio.h"
#include "../path/path.h"   /* xrootd_open_confined — root-confined read-back */


#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

/* ---- Origin path derivation from local filesystem path ----

 * WHAT: Translates a local cache filesystem path into the corresponding origin XRootD
 *       server path by stripping either the cache_root or xrootd_root prefix. Returns
 *       NGX_OK with the derived origin_path, or NGX_ERROR if neither prefix matches.

 * WHY: Write-through flush needs to know where on the origin server to write back data.
 *       The local file lives under cache_root (or root in non-cache mode), but the origin
 *       server expects a path relative to its own root. This function computes that mapping.

 * HOW: 1) Try cache_root prefix — strip it, return remainder as origin_path;
 *      2) If no match, try xrootd_root prefix — same logic;
 *      3) If neither matches → NGX_ERROR (file not in managed namespace).
 */
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

/* ---- Root-confined read-back open of the local cache file ----
 *
 * WHAT: Open wt->local_path O_RDONLY|O_NOFOLLOW under the export-root confinement
 *       cascade (openat2 RESOLVE_BENEATH, O_NOFOLLOW fallback), selecting whichever
 *       configured root the path lives under (cache_root first, then the export
 *       root) — mirroring the prefix match in xrootd_wt_origin_path_from_local.
 *       Returns the fd (caller closes it) or -1 with errno set.
 *
 * WHY:  The write-back read-back used a raw open() of an absolute path with no
 *       confinement, so a symlink or parent swap under the cache/export root could
 *       redirect the read outside the managed namespace. Routing it through the
 *       confined-open primitive enforces kernel-level RESOLVE_BENEATH the same way
 *       every other namespace read does. This helper is syscall-only (no nginx
 *       pool, no per-op metrics/log emission), so it is safe to call from the async
 *       flush worker thread as well as the synchronous event-loop path.
 *
 * HOW:  Try conf->cache_root, then conf->common.root: skip empty roots and roots
 *       the absolute local_path is not lexically under; for the first match, call
 *       xrootd_open_confined() (which canonicalises the ngx_str_t root and resolves
 *       local_path relative to it). On no match, EXDEV. O_CLOEXEC is added by the
 *       confined-open helper itself. */
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

/* ---- Error propagation from fill operation to flush task ----

 * WHAT: Copies error fields (result, xrd_error, sys_errno, err_msg) from a
 *       xrootd_cache_fill_t structure into the caller's xrootd_wt_flush_t.

 * WHY: The write-through flush uses cache_fill_t internally to perform origin-side
 *       I/O. When that operation fails, this helper normalizes the error into the
 *       wt structure so the public API (xrootd_wt_flush_sync_handle / flush_on_close)
 *       can report it consistently.

 * HOW: Direct field copy — result set to NGX_ERROR; xrd_error from fill or default
 *      kXR_ServerError; sys_errno and err_msg copied verbatim via ngx_cpystrn.
 */
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

/* ---- Flush task initialization and validation ----

 * WHAT: Validates the flush request parameters (file index, dirty offset, path)
 *       initializes an xrootd_wt_flush_t structure with configuration, logging context,
 *       mode bits, local/origin paths. Returns NGX_DECLINED if no dirty data needs flushing.
 *       NGX_OK on success, NGX_ERROR if validation or origin-path derivation fails.

 * WHY: Both sync and async flush entry points (xrootd_wt_flush_sync_handle /
 *       xrootd_wt_flush_on_close) share this initialization logic. Centralizing it avoids
 *       duplication and ensures consistent validation before the actual flush runs.

 * HOW: 1) Zero-fill wt structure;
 *      2) Validate idx range, fd >= 0, wt_enabled flag, dirty offset >= 0 → NGX_DECLINED if any fail;
 *      3) Copy conf, log, mode_bits, local_path;
 *      4) Derive origin path via xrootd_wt_origin_path_from_local — error here → NGX_ERROR.
 */
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
    int fd, off_t file_size, const u_char *fhandle, u_char *buf)
{
    off_t offset = 0;

    while (offset < file_size) {
        size_t  want;
        ssize_t nread;

        want = (size_t) (file_size - offset);
        if (want > XROOTD_CACHE_FETCH_CHUNK) {
            want = XROOTD_CACHE_FETCH_CHUNK;
        }

        nread = pread(fd, buf, want, offset);
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

/* ---- Complete write-through flush cycle: connect → chunked pread + origin_write → truncate/sync/close ----

 * WHAT: Executes the full write-back of dirty cached data to the origin XRootD server.
 *       Connects to origin → opens a writable handle on origin_path → reads local file in chunks via
 *       pread → writes each chunk via xrootd_cache_origin_write_chunk → truncates + syncs + closes.
 *       Sets wt->result = NGX_OK on success, or propagates error via xrootd_wt_copy_error on failure.

 * WHY: This is the core flush engine. Both sync and async paths call it after task initialization.
 *       It handles all origin-side I/O (connect, bootstrap, open-write, chunked write, truncate/sync),
 *       local file reads (open + pread loop), buffer allocation, and cleanup on both success and failure.

 * HOW: 1) Validate host/port configured; early exit if missing;
 *      2) Open local file O_RDONLY, fstat to get size;
 *      3) Connect origin → bootstrap login → open writable handle (mode_bits);
 *      4) Chunked pread loop: read XROOTD_CACHE_FETCH_CHUNK bytes, write_chunk each chunk;
 *      5) Truncate to st.st_size + sync on origin; close all handles;
 *      6) On any failure → unified cleanup: close handles, copy error into wt.
 */
/* ---- xrootd_wt_run_flush_exec — GSI/X.509-proxy write-back to origin ----
 *
 * WHAT: Mirror the authoritative local file to a GSI origin (e.g. EOS) by
 *       fork/exec'ing the native client (cache_origin_client, default "xrdcp")
 *       to upload local_path → root[s]://host:port//origin_path, authenticating
 *       with X509_USER_PROXY=cache_origin_proxy + X509_CERT_DIR=cache_origin_cadir.
 * WHY:  The built-in write-back (xrootd_wt_run_flush) only does an anonymous
 *       kXR_login, which a GSI origin rejects. This is the write-side mirror of
 *       the read-fetch GSI exec path — reusing the native client as the PSS.
 * HOW:  Build the upload URL + an env overriding the two X509_* vars; on a clean
 *       exit(0) record bytes_flushed from the local size. Runs in the flush
 *       worker (sync or thread-pool), so posix_spawn + waitpid is fine. */
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
    int         n, rc, wstatus, ai;
    size_t      envn, ei;
    pid_t       pid;

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

    rc = posix_spawnp(&pid, client, NULL, NULL, argv, envp);
    free(envp);
    if (rc != 0) {
        wt->result = NGX_ERROR;
        wt->sys_errno = rc;
        wt->xrd_error = kXR_ServerError;
        ngx_cpystrn((u_char *) wt->err_msg,
                    (u_char *) "write-through origin client spawn failed",
                    sizeof(wt->err_msg));
        return;
    }

    while (waitpid(pid, &wstatus, 0) < 0 && errno == EINTR) { /* retry */ }

    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
        wt->result = NGX_ERROR;
        wt->xrd_error = kXR_AuthFailed;
        snprintf(wt->err_msg, sizeof(wt->err_msg),
                 "origin GSI write-back via %s failed (exit %d)",
                 client, WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1);
        return;
    }

    wt->bytes_flushed = (st.st_size > 0) ? (size_t) st.st_size : 0;
    wt->result = NGX_OK;
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
    int                        fd;
    int                        opened_origin;
    int                        rc;

    wt->bytes_flushed = 0;

    /* GSI/X.509 origin (e.g. EOS): the built-in write-back only does an
     * anonymous login, which such an origin rejects. Delegate to the native
     * client with the configured proxy (write-side mirror of the read fetch). */
    if (wt->conf->cache_origin_proxy.len > 0) {
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
        xrootd_wt_copy_error(wt, &fill);
        return;
    }

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
            rc = xrootd_wt_copy_body(&fill, &oc, fd, st.st_size, fhandle, buf);
        }
    }

    /* Unified cleanup for success and every failure: close the origin file
     * (only when it was actually opened), the origin link, the transfer buffer,
     * and the local fd — then report the outcome. */
    if (opened_origin) {
        xrootd_cache_origin_close_file(&oc, fhandle);
    }
    xrootd_cache_origin_close(&oc);
    free(buf);
    close(fd);

    if (rc != 0) {
        xrootd_wt_copy_error(wt, &fill);
        return;
    }

    wt->bytes_flushed = (st.st_size > 0) ? (size_t) st.st_size : 0;
    wt->result = NGX_OK;
}

/* ---- Synchronous write-through flush at kXR_sync / kXR_close time ----
 *
 * WHAT: Initialise a flush task and run it synchronously via xrootd_wt_run_flush,
 *       reporting only a STATUS — it never writes to the wire. On success it clears
 *       the handle's dirty marker; on failure it logs + records metrics/dashboard.
 * WHY:  This is a pure status helper so the *caller* (kXR_sync handler or kXR_close)
 *       owns the single wire response. That avoids double-responding for one
 *       streamid: a sync flush failure must surface to the client exactly once, as
 *       a kXR_error, and the caller is the one positioned to send it after its own
 *       cleanup. `fail_status` only selects the dashboard event's error label.
 * RETURNS: NGX_OK     — flush succeeded, or there was no dirty data (no-op);
 *          NGX_ERROR  — init or origin write-back failed; caller must send an error.
 * HOW:  1) Init task; NGX_DECLINED (no dirty data) → NGX_OK;
 *       2) init error → metrics/log → NGX_ERROR;
 *       3) run flush; success → mark clean → NGX_OK; failure → metrics/log → NGX_ERROR. */
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
        xrootd_wt_metric_flush_success(wt.metrics, wt.bytes_flushed);
        xrootd_log_access(ctx, c, "WT", wt.origin_path, "flush",
                          1, 0, NULL, 0);
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

    return NGX_ERROR;
}

/* ---- Write-through flush entry point at kXR_close — async or sync mode selection ----

 * WHAT: Initializes a flush task, then dispatches it either asynchronously (via nginx
 *       thread pool) or synchronously based on wt_mode configuration. On async success,
 *       sets wt_flush_pending flag and returns immediately; on fallback/post failure runs
 *       sync via xrootd_wt_flush_sync_handle.

 * WHY: Write-through flush can block for large files. When configured as async mode
 *       (XROOTD_WT_MODE_ASYNC) with a thread pool available, the flush runs off the event
 *       loop so the client connection stays responsive. Async failures fall back to sync.

 * HOW: 1) Init task via xrootd_wt_init_task;
 *      2) If NGX_DECLINED → no dirty data, return NGX_OK;
 *      3) If wt_mode == async + thread_pool available → allocate ngx_thread_task,
 *         memcpy wt into task->ctx, post handler=xrootd_wt_flush_thread;
 *      4) On post failure or sync mode → delegate to xrootd_wt_flush_sync_handle.
 */
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
            ngx_memcpy(async_wt, &wt, sizeof(wt));

            xrootd_task_bind(task, xrootd_wt_flush_thread, xrootd_wt_flush_done);

            if (ngx_thread_task_post(conf->common.thread_pool, task) == NGX_OK) {
                ctx->files[idx].wt_flush_pending = 1;
                xrootd_wt_metric_pending_inc(async_wt->metrics);
                xrootd_log_access(ctx, c, "WT", wt.origin_path, "async",
                                  1, 0, NULL, 0);
                return NGX_OK;
            }

            ngx_free(task);
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "wt: async flush post failed, falling back to sync");
        }
    }

    return xrootd_wt_flush_sync_handle(ctx, c, conf, idx, local_path, 0);
}

/* ---- nginx thread-pool worker callback for async write-through flush ----

 * WHAT: Entry point executed by the nginx thread pool when an async flush task is
 *       dispatched. Casts data to xrootd_wt_flush_t and delegates to xrootd_run_flush.

 * WHY: The async flush path (xrootd_wt_flush_on_close) allocates an ngx_thread_task
 *       with this handler. It runs in a worker thread, blocking on origin I/O while the
 *       event-loop stays free for other connections.

 * HOW: Single-line delegation — casts void* data → xrootd_wt_flush_t, calls run_flush.
 */
void
xrootd_wt_flush_thread(void *data, ngx_log_t *log)
{
    xrootd_wt_flush_t *wt = data;

    (void) log;
    xrootd_wt_run_flush(wt);
}

/* ---- Async flush completion callback — logs result, frees task ----

 * WHAT: Event-loop callback invoked when the nginx thread pool finishes an async flush
 *       task. Logs success or failure with local/origin paths and error message.
 *       Frees the allocated ngx_thread_task structure.

 * WHY: The async flush path (xrootd_wt_flush_on_close) posts a task with this event
 *       handler. When the worker thread completes xrootd_run_flush, the event-loop receives
 *       this callback to finalize logging and memory cleanup.

 * HOW: 1) Extract task from ev->data, wt from task->ctx;
 *      2) Log INFO on success (result == NGX_OK), ERROR on failure with sys_errno + err_msg;
 *      3) Free the task via ngx_free.
 */
void
xrootd_wt_flush_done(ngx_event_t *ev)
{
    ngx_thread_task_t *task = ev->data;
    xrootd_wt_flush_t *wt = task->ctx;

    xrootd_wt_metric_pending_dec(wt->metrics);

    if (wt->result == NGX_OK) {
        xrootd_wt_metric_flush_success(wt->metrics, wt->bytes_flushed);
        ngx_log_error(NGX_LOG_INFO, wt->log, 0,
                      "wt: async flush completed local=\"%s\" origin=\"%s\"",
                      wt->local_path, wt->origin_path);
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
    }

    ngx_free(task);
}
