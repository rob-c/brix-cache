#include "query_internal.h"
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
 * WHAT: kXR_Qcksum — compute single-file checksum (adler32/crc32c/md5/sha1/sha256) by path or open file handle.
 *       Dispatches to path-based handler (full security chain + confined open) or handle-based handler (already-open fd).
 *       Supports async execution via thread pool when configured; falls back to synchronous event-loop computation otherwise.
 *
 * WHY:  Qcksum is the most common XRootD query opcode — clients need file integrity verification before transfer, after staging,
 *       and for checksum-based deduplication. Multiple algorithm support (adler32/crc32c/md5/sha1/sha256) covers legacy HEP tools
 *       (xrdcp uses adler32) alongside modern requirements (SHA256 for cloud storage). Async execution prevents blocking on large files.
 *
 * HOW:  brix_query_cksum() routes by payload prefix byte: non-zero → path-based handler (cksum_path); zero or empty → handle-based
 *       handler (cksum_handle). cksum_path parses algo:path from wire, resolves path, checks authdb/VO/token scope, opens confined fd,
 *       then either posts thread task or computes sync. cksum_handle validates fhandle index, optionally extracts algo prefix, delegates to
 *       build_checksum which dispatches via checksum_parse to specialized helper functions per algorithm. Both paths log access + increment metric.
 */

/* defined in checksum_qcksum_async.c */
extern void brix_cksum_aio_thread(void *data, ngx_log_t *log);
extern void brix_cksum_aio_done(ngx_event_t *ev);

/* Default kXR_Qcksum algorithm — xrdcp's historical default; a leading "algo:"
 * prefix or a "?cks.type=" CGI on the request overrides it downstream. */
#define BRIX_QCKSUM_DEFAULT_ALGO "adler32"
#define BRIX_QCKSUM_ALGO_SZ      32

/*
 * WHAT: Per-request scope shared by every kXR_Qcksum decomposition helper — the connection/config
 *      trio plus the selected algorithm buffer and the resolved paths.
 * WHY:  Threading (ctx, c, conf, algo) through each stage as discrete parameters pushed several
 *      helpers past the 5-argument budget; a single scope struct keeps the data flow explicit
 *      while every helper stays within the argument gate. It is a plain value bundle — no hidden
 *      global state — constructed fresh per request in the two variant entry points.
 * HOW:  `algo` is seeded to BRIX_QCKSUM_DEFAULT_ALGO and may be overridden by algo selection;
 *      `full_path`/`pathbuf` are populated by the resolver (path variant) or the fhandle lookup
 *      (handle variant). Buffers are inline so the struct owns their storage for the request.
 */
typedef struct {
    brix_ctx_t                 *ctx;
    ngx_connection_t           *c;
    ngx_stream_brix_srv_conf_t *conf;
    char                        algo[BRIX_QCKSUM_ALGO_SZ];
    char                        full_path[PATH_MAX];
    char                        pathbuf[BRIX_MAX_PATH + 1];
} brix_qcksum_req_t;

static ngx_flag_t
brix_query_parse_algorithm(const u_char *src, size_t len, char *algo,
    size_t algo_sz)
{
    brix_checksum_alg_t alg;

    return brix_checksum_parse((const char *) src, len, &alg, algo,
                                 algo_sz) == NGX_OK;
}

/* WHAT: Wraps brix_send_error() and returns NGX_DONE if the error was successfully sent (NGX_OK), otherwise
 *      propagates the original return value. This ensures callers receive consistent result semantics.
 * WHY: kXR_Qcksum must distinguish between "error sent to client" vs "send failed internally"; NGX_DONE signals
 *      that the error response reached the wire while NGX_ERROR indicates a transport failure. Callers use this
 *      distinction for different retry/failure handling strategies.
 * HOW: Single wrapper — call brix_send_error(), return NGX_DONE if result was NGX_OK, else propagate original value. */

static ngx_int_t
brix_query_cksum_send_error(brix_ctx_t *ctx, ngx_connection_t *c,
    uint16_t errcode, const char *errmsg)
{
    ngx_int_t rc;

    rc = brix_send_error(ctx, c, errcode, errmsg);
    return (rc == NGX_OK) ? NGX_DONE : rc;
}

/* WHAT: Computes a file checksum using one of six supported algorithms: adler32, crc32, crc32c, md5, sha1, or sha256.
 *      All algorithms dispatch through brix_integrity_get_fd() → brix_checksum_hex_fd().
 * WHY: kXR_Qcksum supports multiple hash algorithms for client flexibility and cross-platform compatibility.
 *      HEP clients historically use adler32/crc32c; modern tools prefer SHA1/SHA256. MD5 is retained for legacy support.
 * HOW: Sequential strcmp checks against supported algo strings, dispatching to specialized helper functions per algorithm. */

static ngx_int_t
brix_query_build_checksum(brix_ctx_t *ctx, ngx_connection_t *c,
    int fd, brix_sd_obj_t *obj, const char *resolved, const char *algo,
    char *resp, size_t resp_sz)
{
    brix_integrity_info_t  info;
    brix_integrity_opts_t  iopts;
    char                     token[256];

    ngx_memzero(&iopts, sizeof(iopts));
    iopts.allow_xattr_cache  = 1;
    iopts.update_xattr_cache = 1;

    if (brix_integrity_get_fd(c->log, fd, obj, resolved, algo, &iopts, &info)
        != NGX_OK)
    {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_CKSUM);
        return brix_query_cksum_send_error(ctx, c, kXR_IOError,
                                             "checksum computation failed");
    }

    /* kXR_Qcksum wire format: "algo hexvalue" (space-separated) */
    snprintf(token, sizeof(token), "%s %s", info.alg_name, info.hex);
    ngx_cpystrn((u_char *) resp, (u_char *) token, resp_sz);
    return NGX_OK;
}

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

static ngx_int_t
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

/*
 * WHAT: Extract the optional algorithm carried on a handle-based Qcksum payload (prefix byte 0,
 *      followed by a NUL-bounded algorithm name) into *algo. A missing/empty/unknown name leaves
 *      *algo at its default.
 * WHY:  Clients may pin the algorithm for a handle checksum by prefixing the fhandle payload with
 *      a zero byte + "<algo>". Unlike the path variant, an unknown name here is silently ignored
 *      (the original handler discarded the parse result) — the default algorithm still applies.
 * HOW:  Guard on payload[0]==0 with at least one following byte, strnlen the algorithm run, and
 *      forward it to brix_query_parse_algorithm (whose failure is intentionally ignored).
 */
static void
brix_qcksum_handle_extract_algo(brix_ctx_t *ctx, char *algo, size_t algo_sz)
{
    const u_char *ap;
    size_t        alen;

    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen <= 1
        || ctx->recv.payload[0] != 0)
    {
        return;
    }

    ap   = ctx->recv.payload + 1;
    alen = strnlen((const char *) ap, (size_t) (ctx->recv.cur_dlen - 1));
    if (alen > 0) {
        (void) brix_query_parse_algorithm(ap, alen, algo, algo_sz);
    }
}

/*
 * WHAT: Try to offload a whole-object checksum on an already-open fhandle fd to the thread pool.
 *      Returns NGX_OK with *handled=1 when posted, *handled=0 for the fall-through-to-sync case,
 *      or a terminal rc with *handled=1 on task-alloc/post failure.
 * WHY:  The handle variant computes on an fd it does NOT own (close_fd=0, no VFS handle to
 *      release) — so, unlike the path variant, its failure exits never close anything. Keeping
 *      the two async posters separate avoids a conditional-ownership branch that would re-inflate
 *      the complexity both splits are removing.
 * HOW:  Alloc the task, populate brix_cksum_aio_t from the files[] slot (fd + snapshotted sd_obj),
 *      bind the callbacks, and brix_aio_post_task; a full queue leaves *handled=0 for sync.
 */
static ngx_int_t
brix_qcksum_handle_try_async(brix_qcksum_req_t *rq, int idx,
    const char *resolved, ngx_flag_t *handled)
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
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_CKSUM);
        *handled = 1;
        return brix_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }

    t = task->ctx;
    t->ctx      = ctx;
    t->c        = c;
    t->conf     = conf;
    t->fd       = ctx->files[idx].fd;
    t->close_fd = 0;
    t->obj      = ctx->files[idx].sd_obj; /* Layer 3: whole-object checksum */
    ngx_memcpy(t->streamid, ctx->recv.cur_streamid, 2);
    ngx_cpystrn((u_char *) t->algo, (u_char *) rq->algo, sizeof(t->algo));
    ngx_cpystrn((u_char *) t->resolved, (u_char *) resolved,
                sizeof(t->resolved));
    t->error_code = 0;

    brix_task_bind(task, brix_cksum_aio_thread, brix_cksum_aio_done);
    task->ctx = t;

    if (brix_aio_post_task(ctx, c, conf->common.thread_pool, task,
                             "cksum thread pool queue full, using sync",
                             &posted) != NGX_OK)
    {
        *handled = 1;
        return NGX_ERROR;
    }

    if (posted) {
        *handled = 1;
        return NGX_OK;
    }
    return NGX_OK;
}

/* WHAT: Computes checksum on an already-open file using its stored fhandle index. Extracts optional algo from payload (prefix byte=0),
 *      validates the handle index, and delegates to brix_query_build_checksum(). Returns hex-formatted result.
 * WHY: kXR_Qcksum can query either open-file handles or arbitrary paths; this handler implements the handle-based variant where
 *      the file is already opened (lower overhead than re-opening). Clients use handles for repeated checksum queries on same file.
 * HOW: extract optional algo → validate fhandle index range + fd → try async offload, else build checksum synchronously + reply. */

static ngx_int_t
brix_query_cksum_handle(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const xrdw_query_req_t *req)
{
    brix_qcksum_req_t rq;
    char       resolved[PATH_MAX];
    char       resp[256];
    int        idx;
    ngx_int_t  rc;
    ngx_flag_t handled = 0;

    ngx_memzero(&rq, sizeof(rq));
    rq.ctx  = ctx;
    rq.c    = c;
    rq.conf = conf;
    ngx_cpystrn((u_char *) rq.algo, (u_char *) BRIX_QCKSUM_DEFAULT_ALGO,
                sizeof(rq.algo));
    brix_qcksum_handle_extract_algo(ctx, rq.algo, sizeof(rq.algo));

    idx = (int) (unsigned char) req->fhandle[0];
    if (idx < 0 || idx >= BRIX_MAX_FILES || ctx->files[idx].fd < 0) {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_CKSUM);
        return brix_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    ngx_cpystrn((u_char *) resolved,
                (u_char *) (ctx->files[idx].path != NULL
                            ? ctx->files[idx].path : "-"),
                sizeof(resolved));

    rc = brix_qcksum_handle_try_async(&rq, idx, resolved, &handled);
    if (handled) {
        return rc;
    }

    rc = brix_query_build_checksum(ctx, c, ctx->files[idx].fd,
                                     &ctx->files[idx].sd_obj, resolved,
                                     rq.algo, resp, sizeof(resp));
    if (rc == NGX_DONE) {
        return NGX_OK;
    }
    if (rc != NGX_OK) {
        return rc;
    }

    BRIX_OP_OK(ctx, BRIX_OP_QUERY_CKSUM);
    brix_log_access(ctx, c, "QUERY", resolved, "cksum", 1, 0, NULL, 0);
    return brix_send_ok(ctx, c, resp, (uint32_t) (strlen(resp) + 1));
}

/* public API: brix_query_cksum() — kXR_Qcksum dispatch entry point * WHAT: Main dispatcher for Qcksum requests. Routes by payload prefix byte: non-zero → path-based handler (cksum_path with full security chain); zero or empty → handle-based handler (cksum_handle with already-open fd). Default algo is adler32. Both paths support async thread pool execution and synchronous fallback. */

ngx_int_t
brix_query_cksum(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const xrdw_query_req_t *req)
{
    /*
     * Wire-format routing on the payload's first byte:
     *   non-zero first byte → payload is a printable "[algo:]path" string, so
     *     take the path-based variant (full auth chain + confined open).
     *   zero or empty payload → no path on the wire; use the fhandle index from
     *     the request header (handle-based variant on an already-open fd).
     * The default algorithm is adler32 (xrdcp's default) in either variant; a
     * leading "algo:" prefix in the path payload overrides it downstream (each
     * variant seeds its own algo buffer from BRIX_QCKSUM_DEFAULT_ALGO).
     */
    if (ctx->recv.cur_dlen > 0 && ctx->recv.payload != NULL && ctx->recv.payload[0] != 0) {
        return brix_query_cksum_path(ctx, c, conf);
    }

    return brix_query_cksum_handle(ctx, c, conf, req);
}
