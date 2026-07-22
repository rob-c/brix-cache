#include "query_internal.h"
#include "checksum_qcksum_internal.h"
#include "core/compat/checksum.h"
#include "core/compat/integrity_info.h"
#include "protocols/root/response/response.h"
#include "core/aio/aio.h"
#include "fs/vfs/vfs.h"   /* confined read-open via the VFS seam */
#include "protocols/root/path/op_path.h"  /* brix_root_vfs_bind_deleg (phase-70) */
#include "net/manager/registry.h"
#include "net/manager/pending.h"
#include "net/cms/cms_internal.h"

#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>

/*
 * WHAT: kXR_Qcksum path variant — algorithm selection, the full security chain
 *       (algo select + path extract + manager bounce + beneath canon + auth gate),
 *       the confined VFS open (or cache-origin redirect), and the async-offload /
 *       synchronous-compute tail for a checksum requested by path.
 *
 * WHY:  This is the heavier of the two kXR_Qcksum variants — a bare path carries no
 *       open fd, so the entire pre-open security chain plus a confined origin fetch
 *       must run here before any bytes are read. Splitting it off keeps the
 *       dispatcher + handle variant in checksum_qcksum.c small and keeps every
 *       resulting translation unit under the file-size guard.
 *
 * HOW:  brix_query_cksum_path() (the sole cross-file entry, prototyped in
 *       checksum_qcksum_internal.h) composes the file-local helpers below:
 *       resolve → open → try_async, else compute_sync. The shared algorithm parser
 *       (brix_query_parse_algorithm) and checksum builder (brix_query_build_checksum)
 *       live in checksum_qcksum.c and are reached via the internal header.
 */

/* defined in checksum_qcksum_async.c */
extern void brix_cksum_aio_thread(void *data, ngx_log_t *log);
extern void brix_cksum_aio_done(ngx_event_t *ev);

/*
 * WHAT: Locate the "algo:path"/"algo path" prefix separator (':' or ' ') within the NUL-bounded
 *      leading run of the payload, reporting the algorithm length and the separator offset.
 * WHY:  The legacy non-standard wire form places the algorithm as a "<algo><sep><path>" prefix;
 *      it must be distinguished from a bare path before the path is extracted. Isolating the scan
 *      keeps qcksum_select_algo linear and free of the raw index loop.
 * HOW:  strnlen bounds the scan to the printable prefix, then a single forward pass returns the
 *      first ':'/' ' offset (also the algorithm length) via *alg_len; returns 1 iff a separator
 *      was found, 0 otherwise (out-params zeroed).
 */
static ngx_flag_t
brix_qcksum_find_algo_sep(const u_char *payload, size_t payload_len,
    size_t *sep_off, size_t *alg_len)
{
    size_t wire_len = strnlen((const char *) payload, payload_len);

    *sep_off = 0;
    *alg_len = 0;

    for (size_t i = 0; i < wire_len; i++) {
        if (payload[i] == ':' || payload[i] == ' ') {
            *sep_off = i;
            *alg_len = i;
            return 1;
        }
    }
    return 0;
}

/*
 * WHAT: Parse the standard "?cks.type=<algo>" CGI field off the request path, overriding any
 *      legacy prefix algorithm. Writes the algorithm into *algo; sets *bad_algo=1 on an
 *      unrecognized value.
 * WHY:  Stock XRootD clients and EOS request the algorithm via a "?cks.type=<algo>" CGI (XrdCl
 *      appends exactly "?cks.type=<algo>"); honoring it makes `xrdfs ... cksum -a <algo>` and
 *      `xrdcp --cksum` select correctly here, not only via the non-standard prefix form.
 * HOW:  Find '?', then walk '&'-separated fields; for the "cks.type=" field trim the trailing wire
 *      NUL/CR/LF (last-field form has no '&', so the NUL lands inside the value and would corrupt
 *      "adler32\0" → unknown algorithm) before parsing. *bad_algo distinguishes "no cks.type"
 *      (leave algo untouched) from "cks.type present but unknown" (caller must reject).
 */
static void
brix_qcksum_apply_cks_type_cgi(const u_char *path_payload,
    size_t path_payload_len, char *algo, size_t algo_sz, ngx_flag_t *bad_algo)
{
    static const char key[] = "cks.type=";
    const u_char     *qmark;
    const u_char     *p;
    const u_char     *end;

    *bad_algo = 0;

    qmark = memchr(path_payload, '?', path_payload_len);
    if (qmark == NULL) {
        return;
    }

    p   = qmark + 1;
    end = path_payload + path_payload_len;
    while (p < end) {
        const u_char *amp  = memchr(p, '&', (size_t) (end - p));
        size_t        flen = amp ? (size_t) (amp - p) : (size_t) (end - p);

        while (flen > 0 && (p[flen - 1] == '\0'
                            || p[flen - 1] == '\r'
                            || p[flen - 1] == '\n')) {
            flen--;
        }
        if (flen > sizeof(key) - 1
            && ngx_strncmp(p, key, sizeof(key) - 1) == 0) {
            if (!brix_query_parse_algorithm(p + sizeof(key) - 1,
                    flen - (sizeof(key) - 1), algo, algo_sz)) {
                *bad_algo = 1;
            }
            return;
        }
        if (amp == NULL) {
            return;
        }
        p = amp + 1;
    }
}

/*
 * WHAT: Select the checksum algorithm for a path-based Qcksum and split the payload into the
 *      path portion. On success returns NGX_OK with the path_payload / path_payload_len out-params
 *      pointing at the request path; on an unknown algorithm sends kXR_ArgInvalid, sets *out_rc to
 *      that send result, and returns NGX_DECLINED.
 * WHY:  Two independent algorithm sources feed one selection: the legacy "<algo><sep><path>"
 *      prefix and the standard "?cks.type=<algo>" CGI (which overrides the prefix). INVARIANT 9:
 *      crc64 (CRC-64/XZ) and crc64nvme (CRC-64/NVME) are DISTINCT names to brix_checksum_parse —
 *      this selector never conflates them; it only forwards the wire token to the parser.
 * HOW:  Detect the prefix separator (brix_qcksum_find_algo_sep) and, when present and non-empty,
 *      parse the prefix algorithm and advance the path payload past it. Then apply the CGI
 *      override (brix_qcksum_apply_cks_type_cgi), which wins. Any unknown token → error send.
 */
static ngx_int_t
brix_qcksum_select_algo(brix_qcksum_req_t *rq, const u_char **path_payload,
    size_t *path_payload_len, ngx_int_t *out_rc)
{
    const u_char *payload     = rq->ctx->recv.payload;
    size_t        payload_len = (size_t) rq->ctx->recv.cur_dlen;
    size_t        sep_off     = 0;
    size_t        alg_len     = 0;
    ngx_flag_t    bad_algo    = 0;

    *path_payload     = payload;
    *path_payload_len = payload_len;

    if (brix_qcksum_find_algo_sep(payload, payload_len, &sep_off, &alg_len)
        && alg_len > 0 && alg_len + 1 < payload_len)
    {
        if (!brix_query_parse_algorithm(payload, alg_len, rq->algo,
                                          sizeof(rq->algo))) {
            BRIX_OP_ERR(rq->ctx, BRIX_OP_QUERY_CKSUM);
            *out_rc = brix_send_error(rq->ctx, rq->c, kXR_ArgInvalid,
                                        "unknown checksum algorithm");
            return NGX_DECLINED;
        }
        *path_payload     = payload + sep_off + 1;
        *path_payload_len = payload_len - (alg_len + 1);
    }

    brix_qcksum_apply_cks_type_cgi(*path_payload, *path_payload_len,
                                     rq->algo, sizeof(rq->algo), &bad_algo);
    if (bad_algo) {
        BRIX_OP_ERR(rq->ctx, BRIX_OP_QUERY_CKSUM);
        *out_rc = brix_send_error(rq->ctx, rq->c, kXR_ArgInvalid,
                                    "unknown checksum algorithm");
        return NGX_DECLINED;
    }
    return NGX_OK;
}

/*
 * WHAT: Manager / redirector bounce for a path-based Qcksum. Returns NGX_DECLINED when the caller
 *      should proceed with the local resolve; otherwise sets *out_rc to the terminal result
 *      (redirect sent, not-found sent, NGX_AGAIN for an async CMS locate) and returns NGX_OK.
 * WHY:  A pure redirector keeps no local copy, so a kXR_Qcksum — file metadata about one path —
 *      must be bounced to the data server that authoritatively holds it, exactly as kXR_stat and
 *      kXR_open do. Isolating the bounce keeps the orchestrator's happy path flat.
 * HOW:  tried/triedrc convergence → not-found once every holder was visited; registry hit →
 *      redirect; registry miss with a CMS parent → async kYR_locate (NGX_AGAIN); all misses →
 *      NGX_DECLINED so the caller falls through to the local resolve (404).
 */
static ngx_int_t
brix_qcksum_manager_bounce(brix_qcksum_req_t *rq, ngx_int_t *out_rc)
{
    brix_ctx_t                 *ctx  = rq->ctx;
    ngx_connection_t           *c    = rq->c;
    ngx_stream_brix_srv_conf_t *conf = rq->conf;
    const char                 *pathbuf = rq->pathbuf;
    char     redir_host[256];
    uint16_t redir_port;

    if (!conf->manager_mode) {
        return NGX_DECLINED;
    }

    /* tried/triedrc: converge to not-found once the client has visited
     * every server holding this path (avoids the redirect-limit loop).
     * Terminal outcomes are reported to the caller via *out_rc (mirroring
     * BRIX_RETURN_ERR / BRIX_RETURN_REDIR, whose embedded `return` cannot be
     * used from a helper that also signals "declined → local resolve"). */
    if (brix_manager_tried_exhausted(ctx->recv.payload, ctx->recv.cur_dlen,
                                       pathbuf)) {
        brix_log_access(ctx, c, "QUERY", pathbuf, "cksum",
                          0, kXR_NotFound, "file not found on any data server",
                          0);
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_CKSUM);
        *out_rc = brix_send_error(ctx, c, kXR_NotFound,
                                    "file not found on any data server");
        return NGX_OK;
    }

    if (brix_srv_select(pathbuf, 0, redir_host,
                          sizeof(redir_host), &redir_port)) {
        brix_log_access(ctx, c, "QUERY", pathbuf, "registry",
                          1, kXR_ok, NULL, 0);
        BRIX_OP_OK(ctx, BRIX_OP_QUERY_CKSUM);
        *out_rc = brix_send_redirect(ctx, c, redir_host, redir_port);
        return NGX_OK;
    }

    /* Registry miss — ask the CMS parent via kYR_locate (async). */
    if (conf->cms.ctx != NULL) {
        uint32_t streamid;

        streamid = ngx_brix_cms_next_streamid(conf->cms.ctx);
        if (brix_pending_insert(streamid, ngx_pid, c->fd, c->number,
                                  ctx->recv.cur_streamid,
                                  conf->cms.locate_timeout) == NGX_OK)
        {
            ctx->cms_wait_streamid = streamid;
            ctx->state = XRD_ST_WAITING_CMS;
            ngx_add_timer(c->read, conf->cms.locate_timeout);
            if (ngx_brix_cms_send_locate(conf->cms.ctx, streamid,
                                           pathbuf) == NGX_OK)
            {
                *out_rc = NGX_AGAIN;
                return NGX_OK;
            }
            ngx_del_timer(c->read);
            ctx->state = XRD_ST_REQ_HEADER;
            brix_pending_remove(streamid, ngx_pid);
        }
    }
    /* Registry + CMS miss: fall through to the local resolve (404). */
    return NGX_DECLINED;
}

/*
 * WHAT: Resolve a path-based Qcksum from wire payload to an authorized, confinement-canonical
 *      full_path (and the request-relative pathbuf). Returns NGX_OK when the caller may open the
 *      file; otherwise sets *out_rc to the terminal result (algo error, redirect, not-found,
 *      denied) and returns NGX_DECLINED.
 * WHY:  Algorithm selection, path extraction, manager bounce, beneath-path canonicalization, and
 *      the read auth gate form the entire security chain that must run before any filesystem
 *      access. Composing them in one resolver keeps the open/compute stage strictly post-auth.
 * HOW:  select_algo → extract_path → manager_bounce → beneath_full_path → auth_gate, each with
 *      early-return on its terminal outcome. The phase74-fp NOLINT on the beneath call is
 *      preserved verbatim (pathbuf=request path, full_path=output buffer — not swapped).
 */
static ngx_int_t
brix_qcksum_resolve(brix_qcksum_req_t *rq, ngx_int_t *out_rc)
{
    brix_ctx_t                 *ctx  = rq->ctx;
    ngx_connection_t           *c    = rq->c;
    ngx_stream_brix_srv_conf_t *conf = rq->conf;
    const u_char               *path_payload     = NULL;
    size_t                      path_payload_len = 0;
    ngx_int_t                   rc;

    rc = brix_qcksum_select_algo(rq, &path_payload, &path_payload_len, out_rc);
    if (rc != NGX_OK) {
        return NGX_DECLINED;
    }

    if (!brix_extract_path(c->log, path_payload, path_payload_len,
                             rq->pathbuf, sizeof(rq->pathbuf), 1)) {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_CKSUM);
        *out_rc = brix_send_error(ctx, c, kXR_ArgInvalid,
                                    "invalid path payload");
        return NGX_DECLINED;
    }

    /*
     * Manager / redirector mode: a kXR_Qcksum is metadata about one specific
     * file, and a pure redirector keeps no local copy.  Bounce the query to the
     * data server that authoritatively holds the path — exactly as kXR_stat and
     * kXR_open do — so a client behind the redirector still gets a checksum.
     */
    if (brix_qcksum_manager_bounce(rq, out_rc) == NGX_OK) {
        return NGX_DECLINED;
    }

    /* phase74-fp: pathbuf is the request path, full_path the output buf. */
    brix_beneath_full_path(conf->common.root_canon, rq->pathbuf,  /* NOLINT(readability-suspicious-call-argument) */
                              rq->full_path, sizeof(rq->full_path));

    if (brix_auth_gate(ctx, c, BRIX_OP_QUERY_CKSUM, "QUERY",
                         rq->pathbuf, rq->full_path, conf,
                         BRIX_AUTH_READ, 0) != NGX_OK) {
        *out_rc = ctx->write_rc;
        return NGX_DECLINED;
    }
    return NGX_OK;
}

/*
 * WHAT: Open the resolved path through the VFS seam for checksum computation, returning the open
 *      handle. On failure returns NULL and sets *out_rc to the terminal result (cache-origin
 *      redirect on a read-through miss, otherwise an errno-mapped error send).
 * WHY:  A checksum read is a full-content origin fetch, so the open mirrors the davs/S3 GET
 *      confinement + credential-bind path exactly (impersonation-aware, metered, opt-in mint).
 *      Keeping the cache-miss redirect beside the open localizes the "not yet pulled" decision.
 * HOW:  Init a VFS ctx bound to the storage credential dir + mint CA + delegation, open O_READ.
 *      On ENOENT with a configured cache origin → redirect the metadata query there (the origin
 *      holds the authoritative bytes); otherwise map errno → kXR and send.
 */
static brix_vfs_file_t *
brix_qcksum_open(brix_qcksum_req_t *rq, ngx_int_t *out_rc)
{
    brix_ctx_t                 *ctx  = rq->ctx;
    ngx_connection_t           *c    = rq->c;
    ngx_stream_brix_srv_conf_t *conf = rq->conf;
    const char                 *pathbuf   = rq->pathbuf;
    const char                 *full_path = rq->full_path;
    brix_vfs_ctx_t   vctx;
    brix_vfs_file_t *fh;
    int              vfs_err = 0;

    /* Confined read-open through the VFS seam (impersonation-aware, metered).
     * The fd backs the backend-agnostic checksum kernel; the handle is closed
     * via brix_vfs_close on every exit (sync below, or the aio done cb). */
    brix_vfs_ctx_init(&vctx, c->pool, c->log, BRIX_PROTO_ROOT,
        conf->common.root_canon, NULL, conf->common.allow_write,
        0 /* is_tls */, ctx->identity, full_path);
    brix_vfs_ctx_bind_backend_cred(&vctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    /* Phase-3 T1: opt-in credential minting, mirroring the davs/S3 GET
     * mint bind — a checksum read is a full-content origin fetch. */
    brix_vfs_ctx_bind_backend_mint(&vctx,
        &conf->common.storage_credential_mint_ca_cert,
        &conf->common.storage_credential_mint_ca_key,
        conf->common.storage_credential_mint_ttl);
    brix_root_vfs_bind_deleg(ctx, conf, &vctx);
    fh = brix_vfs_open(&vctx, BRIX_VFS_O_READ, &vfs_err);
    errno = vfs_err;

    if (fh != NULL) {
        return fh;
    }

    /*
     * Read-through cache miss: the file has not been pulled from the origin
     * yet (a cached hit is computed locally above).  The origin holds the
     * authoritative bytes — identical to anything we would later cache — so
     * redirect the metadata query there rather than returning "not found".
     */
    if (errno == ENOENT && conf->cache_origin_host.len > 0) {
        char   origin_host[256];
        size_t hlen = conf->cache_origin_host.len < sizeof(origin_host)
                      ? conf->cache_origin_host.len : sizeof(origin_host) - 1;

        ngx_memcpy(origin_host, conf->cache_origin_host.data, hlen);
        origin_host[hlen] = '\0';
        /* Equivalent to BRIX_RETURN_REDIR but through the *out_rc out-param
         * (the macro embeds its own `return`, which cannot leave a helper that
         * signals failure by returning NULL). */
        brix_log_access(ctx, c, "QUERY", pathbuf, "cache-origin",
                          1, kXR_ok, NULL, 0);
        BRIX_OP_OK(ctx, BRIX_OP_QUERY_CKSUM);
        *out_rc = brix_send_redirect(ctx, c, origin_host,
                                       conf->cache_origin_port);
        return NULL;
    }
    /* Equivalent to BRIX_RETURN_ERR via the *out_rc out-param. */
    {
        uint16_t code = brix_kxr_from_errno(errno);
        brix_log_access(ctx, c, "QUERY", full_path, "cksum",
                          0, code, strerror(errno), 0);
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_CKSUM);
        *out_rc = brix_send_error(ctx, c, code, strerror(errno));
    }
    return NULL;
}

/*
 * WHAT: Try to offload a whole-object checksum to the thread pool from an open VFS handle.
 *      Returns NGX_OK when the task was posted (*handled=1) OR the fall-through-to-sync case
 *      (*handled=0); returns a terminal rc with *handled=1 when the task could not be created or
 *      posted (the handle is closed on those failure exits).
 * WHY:  Async execution prevents the event loop blocking on large-file checksums. The path
 *      variant owns the handle (close_fd=1: the done cb releases the VFS handle), unlike the
 *      handle variant which computes on an already-open fd it does not own.
 * HOW:  Alloc the task, populate the brix_cksum_aio_t (fd/fh/obj/streamid/algo/resolved), bind
 *      the thread + done callbacks, then brix_aio_post_task. A full queue leaves *handled=0 so
 *      the caller reuses the still-open handle for a synchronous compute.
 */
static ngx_int_t
brix_qcksum_try_async(brix_qcksum_req_t *rq, brix_vfs_file_t *fh, int fd,
    ngx_flag_t *handled)
{
    brix_ctx_t                 *ctx  = rq->ctx;
    ngx_connection_t           *c    = rq->c;
    ngx_stream_brix_srv_conf_t *conf = rq->conf;
    brix_cksum_aio_t  *t;
    ngx_thread_task_t *task;
    ngx_flag_t         posted = 0;

    *handled = 0;

    if (conf->common.thread_pool == NULL) {
        return NGX_OK;
    }

    task = ngx_thread_task_alloc(c->pool, sizeof(brix_cksum_aio_t));
    if (task == NULL) {
        brix_vfs_close(fh, c->log);
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_CKSUM);
        *handled = 1;
        return brix_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }

    t = task->ctx;
    t->ctx      = ctx;
    t->c        = c;
    t->conf     = conf;
    t->fd       = fd;
    t->fh       = fh;        /* done cb releases the VFS handle */
    t->close_fd = 1;
    brix_vfs_file_sd_obj(fh, &t->obj); /* Layer 3: whole-object checksum */
    ngx_memcpy(t->streamid, ctx->recv.cur_streamid, 2);
    ngx_cpystrn((u_char *) t->algo, (u_char *) rq->algo, sizeof(t->algo));
    ngx_cpystrn((u_char *) t->resolved, (u_char *) rq->full_path,
                sizeof(t->resolved));
    t->error_code = 0;

    brix_task_bind(task, brix_cksum_aio_thread, brix_cksum_aio_done);
    task->ctx = t;

    if (brix_aio_post_task(ctx, c, conf->common.thread_pool, task,
                             "cksum thread pool queue full, using sync",
                             &posted) != NGX_OK)
    {
        brix_vfs_close(fh, c->log);
        *handled = 1;
        return NGX_ERROR;
    }

    if (posted) {
        *handled = 1;
        return NGX_OK;
    }
    /* not posted → fall through to the sync path, reusing the open handle. */
    return NGX_OK;
}

/*
 * WHAT: Synchronously compute the checksum on an open VFS handle, close the handle, and on
 *      success emit the access log + OK reply. Returns the terminal result of the request.
 * WHY:  The sync path runs when no thread pool is configured or the pool queue was full; it
 *      shares the format/reply tail with the async done callback's success shape.
 * HOW:  Snapshot the sd_obj for the whole-object checksum, build the "algo hex" response, close
 *      the handle unconditionally, then map NGX_DONE (error already sent) / non-OK / OK → send_ok.
 */
static ngx_int_t
brix_qcksum_compute_sync(brix_qcksum_req_t *rq, brix_vfs_file_t *fh, int fd)
{
    brix_ctx_t       *ctx = rq->ctx;
    ngx_connection_t *c   = rq->c;
    brix_sd_obj_t     cobj;
    char              resp[256];
    ngx_int_t         rc;

    brix_vfs_file_sd_obj(fh, &cobj);
    rc = brix_query_build_checksum(ctx, c, fd, &cobj, rq->full_path, rq->algo,
                                     resp, sizeof(resp));
    brix_vfs_close(fh, c->log);
    if (rc == NGX_DONE) {
        return NGX_OK;
    }
    if (rc != NGX_OK) {
        return rc;
    }

    brix_log_access(ctx, c, "QUERY", rq->full_path, "cksum", 1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_QUERY_CKSUM);
    return brix_send_ok(ctx, c, resp, (uint32_t) (strlen(resp) + 1));
}

/* WHAT: Parses a payload containing "algo:path", resolves the path through security checks (authdb, VO ACL, token scope),
 *      opens the file confined, and delegates checksum computation to brix_query_build_checksum(). Returns hex-formatted result.
 * WHY: kXR_Qcksum can query either open-file handles or arbitrary paths; this handler implements the path-based variant with
 *      full security chain verification before accessing any filesystem resource.
 * HOW: resolve (algo select + path extract + manager bounce + auth gate) → VFS open (or cache-origin redirect) →
 *      try async offload, else compute synchronously + reply. Each stage early-returns on its terminal outcome. */

ngx_int_t
brix_query_cksum_path(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    brix_qcksum_req_t  rq;
    brix_vfs_file_t   *fh;
    int                fd;
    ngx_int_t          rc = NGX_ERROR;
    ngx_flag_t         handled = 0;

    ngx_memzero(&rq, sizeof(rq));
    rq.ctx  = ctx;
    rq.c    = c;
    rq.conf = conf;
    ngx_cpystrn((u_char *) rq.algo, (u_char *) BRIX_QCKSUM_DEFAULT_ALGO,
                sizeof(rq.algo));

    if (brix_qcksum_resolve(&rq, &rc) != NGX_OK) {
        return rc;
    }

    fh = brix_qcksum_open(&rq, &rc);
    if (fh == NULL) {
        return rc;
    }
    fd = brix_vfs_file_fd(fh);

    rc = brix_qcksum_try_async(&rq, fh, fd, &handled);
    if (handled) {
        return rc;
    }

    return brix_qcksum_compute_sync(&rq, fh, fd);
}
