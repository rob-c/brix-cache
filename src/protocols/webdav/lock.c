/*
 * lock.c — WebDAV LOCK handler (RFC 4918 §9.10).
 *
 * Lock state is stored as a single xattr on the locked resource
 * (see prop_xattr.c).  No shared memory or mutex is needed:
 * XATTR_CREATE provides kernel-serialized atomic lock creation;
 * expiry cleanup is lazy (on next access to that path).
 *
 * The lock-conflict walk (webdav_check_locks / _tree) lives in lock_check.c;
 * UNLOCK, the startup sweep and PROPFIND lock-discovery XML live in
 * lock_discovery.c.  The confined-ctx helper (webdav_lock_vfs_ctx) and the
 * lock-null reaper (webdav_lock_reap_null) are defined here and shared with
 * those siblings via lock_internal.h.
 */
#include "webdav.h"
#include "fs/path/path.h"
#include "fs/vfs/vfs.h"   /* lock-DB namespace ops via the VFS seam */
#include "auth/impersonate/lifecycle.h"
#include "protocols/webdav/locks/request.h"
#include "core/http/http_xml.h"
#include "core/compat/fs_walk.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <time.h>

#include "lock_internal.h"

/* RFC 4918 §11.1: 423 Locked */
#ifndef NGX_HTTP_LOCKED
#define NGX_HTTP_LOCKED 423
#endif

/*
 * Generate Version 4 UUID for WebDAV lock token (`opaquelocktoken:` prefix).
 * OpenSSL RAND_bytes provides collision-resistant identifiers.
 */
static void
webdav_generate_uuid(char *buf, size_t bufsz)
{
    u_char bytes[16];
    (void) RAND_bytes(bytes, 16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;   /* Version 4 */
    bytes[8] = (bytes[8] & 0x3f) | 0x80;   /* Variant */

    snprintf(buf, bufsz,
             "opaquelocktoken:%02x%02x%02x%02x-%02x%02x-%02x%02x"
             "-%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5],
             bytes[6], bytes[7],
             bytes[8], bytes[9],
             bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
}

/*
 * Build and send the RFC 4918 §9.10 LOCK response body (activelock XML)
 * plus Lock-Token response header.
 */
static void
webdav_lock_xml_response(ngx_http_request_t *r, webdav_lock_xattr_t *e)
{
    ngx_chain_t     *head = NULL, *tail = NULL;
    char             timeout_buf[32];
    char            *safe_owner;
    int64_t          now = (int64_t) ngx_time();
    ngx_uint_t       remaining;
    off_t            total_len = 0;
    ngx_chain_t     *lc;
    ngx_table_elt_t *h;

    /* expires is absolute wall-clock seconds → remaining is a plain subtraction. */
    remaining = (e->expires > now) ? (ngx_uint_t) (e->expires - now) : 0;
    ngx_sprintf((u_char *) timeout_buf, "Second-%ui", remaining);

    safe_owner = webdav_escape_xml_text(r->pool, e->owner);
    if (safe_owner == NULL) {
        safe_owner = "anonymous";
    }

    brix_http_chain_appendf(r->pool, &head, &tail,
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
        "<D:prop xmlns:D=\"DAV:\">"
        "<D:lockdiscovery>"
        "<D:activelock>"
        "<D:locktype><D:write/></D:locktype>"
        "<D:lockscope>%s</D:lockscope>"
        "<D:depth>%s</D:depth>"
        "<D:owner>%s</D:owner>"
        "<D:timeout>%s</D:timeout>"
        "<D:locktoken><D:href>%s</D:href></D:locktoken>"
        "</D:activelock>"
        "</D:lockdiscovery>"
        "</D:prop>",
        e->exclusive ? "<D:exclusive/>" : "<D:shared/>",
        e->depth_infinity ? "infinity" : "0",
        safe_owner, timeout_buf, e->token);

    if (tail != NULL) {
        tail->buf->last_buf = 1;
        tail->buf->last_in_chain = 1;
    }

    for (lc = head; lc != NULL; lc = lc->next) {
        total_len += lc->buf->last - lc->buf->pos;
    }

    r->headers_out.content_length_n = total_len;

    h = ngx_list_push(&r->headers_out.headers);
    if (h != NULL) {
        h->hash = 1;
        ngx_str_set(&h->key, "Content-Type");
        ngx_str_set(&h->value, "application/xml; charset=\"utf-8\"");
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h != NULL) {
        h->hash = 1;
        ngx_str_set(&h->key, "Lock-Token");
        h->value.len = strlen(e->token) + 2;
        h->value.data = ngx_pnalloc(r->pool, h->value.len);
        if (h->value.data != NULL) {
            ngx_sprintf(h->value.data, "<%s>", e->token);
        }
    }

    ngx_http_send_header(r);
    ngx_http_output_filter(r, head);
}

/*
 * webdav_lock_reap_null — release a lock-null placeholder.
 *
 * WHAT: If `e` recorded a lock-null lock (the LOCK created a zero-byte resource
 *       to reserve a name, RFC 4918 §9.10.1) AND the resource is still an empty
 *       regular file, unlink it so the reserved name disappears with the lock.
 * WHY:  Without this, UNLOCK (or expiry) of a never-PUT lock-null resource would
 *       leave an orphaned 0-byte file behind. A resource the client PUT data into
 *       is non-empty and is never reaped, so the is_null flag becomes inert once
 *       real content exists — no need to clear it on PUT.
 * HOW:  Confined no-follow lstat; only a regular, zero-length file is unlinked,
 *       via the confined unlink. Best-effort — failures are ignored. MUST NOT be
 *       called on a path that is about to be re-locked (it would remove the file
 *       out from under a follow-up XATTR_CREATE).
 */
/* Build a confined VFS ctx for a lock-DB namespace op on `path` (mirrors the
 * canonical webdav construction). Identity comes from the request ctx so the op
 * runs as the mapped user under impersonation. */
void
webdav_lock_vfs_ctx(ngx_http_request_t *r, const char *path,
    brix_vfs_ctx_t *vctx)
{
    ngx_http_brix_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    ngx_http_brix_webdav_req_ctx_t  *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    int is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    brix_vfs_ctx_init(vctx, r->pool, r->connection->log, BRIX_PROTO_WEBDAV,
        conf->common.root_canon, conf->cache_root_canon, conf->common.allow_write,
        is_tls, (rx != NULL) ? rx->identity : NULL, path);
}

void
webdav_lock_reap_null(ngx_http_request_t *r, const char *path,
                      const webdav_lock_xattr_t *e)
{
    brix_vfs_ctx_t  vctx;
    brix_vfs_stat_t vst;

    if (!e->is_null) {
        return;
    }

    /* Confined no-follow probe; only a regular, zero-length file is unlinked,
     * through the VFS. Best-effort — failures are ignored. */
    webdav_lock_vfs_ctx(r, path, &vctx);
    if (brix_vfs_probe(&vctx, 1 /* no-follow */, &vst) == NGX_OK
        && vst.is_regular && vst.size == 0)
    {
        (void) brix_vfs_unlink(&vctx);
    }
}

static void webdav_handle_lock_inner(ngx_http_request_t *r);

/*
 * LOCK body-ready callback.  Phase 40: the lockinfo body is read asynchronously,
 * so the dispatch wrapper already cleared the impersonation principal.
 * Re-establish it (mirrors PUT/PROPFIND/PROPPATCH) so the lock xattr AND any
 * zero-byte resource creation happen AS THE MAPPED USER via the broker; without
 * it the worker (svc) cannot setxattr the user-owned lock target (EACCES) and
 * LOCK fails 500.  No-op unless map mode is active.
 */
void
webdav_handle_lock(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    brix_imp_request_begin(rx != NULL ? rx->identity : NULL);
    webdav_handle_lock_inner(r);
    brix_imp_request_end();
}

/*
 * webdav_lock_create_null — RFC 4918 §9.10.1 lock-null placeholder creation.
 *
 * WHAT: If `path` does not exist, atomically create a zero-byte resource to
 *       host the lock, and report via *created_null whether we made it.
 * WHY:  A LOCK on a non-existent resource MUST reserve the name; the placeholder
 *       is reaped on UNLOCK/expiry if never converted by a PUT/MKCOL.
 * HOW:  Confined no-follow probe; on ENOENT do an O_CREATE|O_EXCL open. A race
 *       loser (EEXIST) is not an error and leaves created_null clear. Returns
 *       NGX_OK on success (whether or not a file was created) or
 *       NGX_HTTP_INTERNAL_SERVER_ERROR when the create fails for another reason.
 */
static ngx_int_t
webdav_lock_create_null(ngx_http_request_t *r, const char *path,
    int *created_null)
{
    brix_vfs_ctx_t  vctx;
    brix_vfs_stat_t vst;
    brix_vfs_file_t *fh;
    int              verr = 0;

    *created_null = 0;

    webdav_lock_vfs_ctx(r, path, &vctx);
    if (brix_vfs_probe(&vctx, 1 /* no-follow */, &vst) != NGX_DECLINED
        || errno != ENOENT)
    {
        return NGX_OK;
    }

    fh = brix_vfs_open(&vctx,
        BRIX_VFS_O_WRITE | BRIX_VFS_O_CREATE | BRIX_VFS_O_EXCL, &verr);
    if (fh == NULL) {
        return (verr == EEXIST) ? NGX_OK : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    brix_vfs_close(fh, r->connection->log);
    /* We created the resource solely to host this lock: it is a lock-null
     * placeholder, reaped on UNLOCK/expiry if still empty. */
    *created_null = 1;
    return NGX_OK;
}

/* Parsed inputs for a fresh lock, threaded from the handler into
 * webdav_lock_create so its signature stays small. */
typedef struct {
    const char *owner;
    int         exclusive;
    int         depth_infinity;
    int         created_null;   /* lock-null placeholder was created */
} webdav_lock_new_t;

/*
 * webdav_lock_owner_set — choose the <D:owner> value for a fresh lock.
 *
 * WHAT: Copies, in priority order, the request-supplied owner, else the
 *       authenticated DN, else the literal "anonymous", into e->owner.
 * WHY:  Keeps owner-selection out of the create path so its intent is explicit
 *       and unchanged. HOW: bounded ngx_cpystrn into the fixed owner buffer.
 */
static void
webdav_lock_owner_set(webdav_lock_xattr_t *e, const char *owner,
    const ngx_http_brix_webdav_req_ctx_t *ctx)
{
    if (owner[0] != '\0') {
        ngx_cpystrn((u_char *) e->owner, (u_char *) owner, sizeof(e->owner));
    } else if (ctx != NULL && ctx->dn[0] != '\0') {
        ngx_cpystrn((u_char *) e->owner, (u_char *) ctx->dn, sizeof(e->owner));
    } else {
        ngx_cpystrn((u_char *) e->owner, (u_char *) "anonymous",
                    sizeof(e->owner));
    }
}

/*
 * webdav_lock_write_status — map an XATTR_CREATE lock-write result to a status.
 *
 * WHAT: Translates the write rc/errno into the wire status for the new-lock
 *       path: NGX_HTTP_LOCKED on a lost race (NGX_DECLINED), 403 vs 500 on
 *       failure, or NGX_OK on success.
 * WHY:  The two-EACCES-source disambiguation is subtle and load-bearing; giving
 *       it its own function keeps the create path readable while preserving the
 *       exact policy-vs-syscall distinction documented below.
 * HOW:  See the inline rationale — a remote-backed export's credential gate
 *       (drv != NULL) yields 403; a plain local-syscall EACCES stays 500.
 */
static ngx_int_t
webdav_lock_write_status(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, ngx_int_t rc)
{
    if (rc == NGX_DECLINED) {
        /* Another worker created the lock between our read and write. */
        return NGX_HTTP_LOCKED;
    }
    if (rc == NGX_OK) {
        return NGX_OK;
    }

    /* Two DIFFERENT EACCES sources land here, and they must map to
     * different statuses (phase-3 T1):
     *   (a) the per-user backend credential gate (brix_vfs_ns_cred,
     *       src/fs/vfs/vfs_xattr.c) denying a no-cred user in deny
     *       mode on a REMOTE-BACKED export — the gate runs and fails
     *       BEFORE brix_vfs_setxattr ever reaches a syscall, and only
     *       engages when the lock ctx's vctx->sd is a non-NULL backend
     *       instance (webdav_lock_vfs_ctx_init in prop_xattr.c binds
     *       it via brix_webdav_backend_instance). This is a policy
     *       refusal -> 403.
     *   (b) the impersonation broker's setxattr on a user-owned file
     *       failing EACCES on a LOCAL POSIX export (vctx->sd stays
     *       NULL there, so the gate path above is never taken and
     *       this EACCES can only come from the raw syscall) -- the
     *       service worker genuinely could not perform the op. This
     *       is intentionally left 500 (documented at
     *       webdav_handle_lock's WHAT/WHY/HOW comment above).
     * The two cases are structurally distinguishable at this callsite
     * because vfs_xattr.c sets errno = EACCES from the gate check
     * (source a) using a DIFFERENT code path (drv != NULL) than the
     * plain-syscall EACCES (source b, drv == NULL) -- but distinguishing
     * *here* would require re-deriving whether the export is remote-
     * backed, duplicating prop_xattr.c's internal ctx-driver logic.
     * brix_webdav_backend_instance(conf, log) is idempotent and cheap
     * (a config-scoped cached instance, not a fresh connection), so
     * calling it again here to re-derive "remote-backed?" is safe and
     * avoids threading a new out-parameter through webdav_lock_xattr_write. */
    if ((errno == EACCES || errno == EPERM)
        && brix_webdav_backend_instance(conf, r->connection->log) != NULL)
    {
        return NGX_HTTP_FORBIDDEN;
    }
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * webdav_lock_refresh — refresh an existing active lock (RFC 4918 §9.10).
 *
 * WHAT: If the client owns the lock, extend its timeout and rewrite the xattr;
 *       otherwise report 423 Locked.
 * WHY:  Splits the "existing lock" branch out of the handler so both branches
 *       read as a single decision each. HOW: token match via the If header,
 *       XATTR_REPLACE rewrite; sets 200 OK on success. Returns NGX_OK when the
 *       caller should proceed to emit the XML body, else a finalized status.
 */
static ngx_int_t
webdav_lock_refresh(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    webdav_lock_xattr_t *e)
{
    if (!webdav_lock_if_header_matches(r, e->token)) {
        return NGX_HTTP_LOCKED;
    }
    e->expires = webdav_lock_parse_timeout(r, conf);
    if (webdav_lock_xattr_write(r, path, e, XATTR_REPLACE) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    r->headers_out.status = NGX_HTTP_OK;
    return NGX_OK;
}

/*
 * webdav_lock_create — create a new lock atomically (RFC 4918 §9.10).
 *
 * WHAT: Builds a fresh lock record (new token, owner, scope, depth, timeout,
 *       lock-null flag) and writes it with XATTR_CREATE.
 * WHY:  Splits the "no existing lock" branch out of the handler. HOW: delegates
 *       owner selection and write-result mapping to helpers; sets 201 Created on
 *       success. Returns NGX_OK when the caller should emit the XML body, else a
 *       finalized status.
 */
static ngx_int_t
webdav_lock_create(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    const webdav_lock_new_t *nl, webdav_lock_xattr_t *e)
{
    ngx_http_brix_webdav_req_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    ngx_int_t rc;

    ngx_memzero(e, sizeof(*e));
    webdav_generate_uuid(e->token, sizeof(e->token));
    webdav_lock_owner_set(e, nl->owner, ctx);

    e->exclusive      = nl->exclusive;
    e->depth_infinity = nl->depth_infinity;
    e->is_null        = nl->created_null;
    e->expires        = webdav_lock_parse_timeout(r, conf);

    rc = webdav_lock_xattr_write(r, path, e, XATTR_CREATE);
    rc = webdav_lock_write_status(r, conf, rc);
    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.status = NGX_HTTP_CREATED;
    return NGX_OK;
}

static void
webdav_handle_lock_inner(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    char                               path[WEBDAV_MAX_PATH];
    ngx_int_t                          rc;
    webdav_lock_xattr_t                e;
    webdav_lock_new_t                  nl;
    char                               owner[256];

    ngx_memzero(&nl, sizeof(nl));
    nl.depth_infinity = 1;
    nl.exclusive = 1;
    nl.owner = owner;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    rc = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon,
                                              path, sizeof(path));
    if (rc != NGX_OK) {
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    rc = webdav_lock_parse_depth(r, &nl.depth_infinity);
    if (rc != NGX_OK) {
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    webdav_lock_parse_body(r, owner, sizeof(owner), &nl.exclusive);

    /* RFC 4918 §9.10.1: LOCK on non-existent resource MUST create zero-byte resource. */
    rc = webdav_lock_create_null(r, path, &nl.created_null);
    if (rc != NGX_OK) {
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    rc = webdav_lock_xattr_read(r, path, &e);
    if (rc == NGX_ERROR) {
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* Treat expired lock as absent. */
    if (rc == NGX_OK && e.expires <= (int64_t) ngx_time()) {
        (void) webdav_lock_xattr_delete(r, path);
        rc = NGX_DECLINED;
    }

    if (rc == NGX_OK) {
        /* Existing active lock: refresh if token matches, else 423. */
        rc = webdav_lock_refresh(r, conf, path, &e);
    } else {
        /* No lock: create atomically with XATTR_CREATE. */
        rc = webdav_lock_create(r, conf, path, &nl, &e);
    }

    if (rc != NGX_OK) {
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    webdav_lock_xml_response(r, &e);
}
