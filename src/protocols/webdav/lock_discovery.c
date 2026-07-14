/*
 * lock_discovery.c — WebDAV UNLOCK, startup lock sweep, and PROPFIND
 * lock-discovery/supportedlock XML (RFC 4918 §9.11, §10.1, §15.8/§15.10).
 *
 * Split from lock.c (mechanical, zero behaviour change): the read/release side
 * of the lock database — releasing a lock on UNLOCK, wiping persisted locks at
 * startup, and emitting the <D:lockdiscovery>/<D:supportedlock> XML that
 * PROPFIND reports.  Lock state is stored as a single xattr on each resource
 * (see prop_xattr.c).
 *
 * The confined-ctx helper (webdav_lock_vfs_ctx) and the lock-null reaper
 * (webdav_lock_reap_null) are defined in lock.c and shared via lock_internal.h.
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
 * Startup lock sweep — remove every persisted lock xattr under the export
 * root.  Locks are stored as the WEBDAV_LOCK_XATTR_KEY xattr on each resource
 * (prop_xattr.c), so they normally survive an nginx restart.  When
 * brix_webdav_lock_startup_sweep is on, this walk restores ephemeral
 * RFC 4918 §10.1 semantics by clearing them once at startup.
 *
 * removexattr is idempotent: a node with no lock returns ENODATA/ENOATTR,
 * which is not counted and not an error.  The walk continues past per-node
 * failures so one unreadable subtree cannot abort the sweep.
 */
/* Sweep state threaded to the walk callback so each node can build a transient,
 * confined VFS ctx for its lock-xattr removal (the sweep runs at config-merge
 * time, so it carries its own pool/log/root_canon rather than a request ctx). */
typedef struct {
    ngx_uint_t  removed;
    ngx_pool_t *pool;
    ngx_log_t  *log;
    const char *root_canon;
} webdav_lock_sweep_ctx_t;

/* Remove the lock xattr on one absolute path through the VFS seam. removexattr
 * via the VFS is idempotent for our purposes: ENODATA/ENOATTR (no lock) returns
 * NGX_ERROR but is simply not counted, so a node without a lock is a no-op. */
static void
webdav_lock_sweep_remove(webdav_lock_sweep_ctx_t *sw, const char *path)
{
    brix_vfs_ctx_t vctx;

    brix_vfs_ctx_init(&vctx, sw->pool, sw->log, BRIX_PROTO_WEBDAV,
        sw->root_canon, NULL, 1 /* allow_write */, 0 /* is_tls */, NULL, path);

    if (brix_vfs_removexattr(&vctx, WEBDAV_LOCK_XATTR_KEY) == NGX_OK) {
        sw->removed++;
    }
}

static ngx_int_t
webdav_lock_sweep_cb(const brix_fs_walk_entry_t *entry, void *data)
{
    webdav_lock_sweep_remove(data, entry->path);
    return NGX_OK;   /* continue regardless of per-node result */
}

ngx_uint_t
webdav_lock_startup_sweep(ngx_pool_t *pool, ngx_log_t *log,
    const char *root_canon)
{
    brix_fs_walk_options_t opts;
    webdav_lock_sweep_ctx_t  sw;

    if (root_canon == NULL || root_canon[0] == '\0') {
        return 0;
    }

    ngx_memzero(&sw, sizeof(sw));
    sw.pool = pool;
    sw.log = log;
    sw.root_canon = root_canon;

    /* The tree walk visits children only; clear a lock on the root itself. */
    webdav_lock_sweep_remove(&sw, root_canon);

    ngx_memzero(&opts, sizeof(opts));
    opts.include_files = 1;   /* locks may sit on files ... */
    opts.include_dirs  = 1;   /* ... and on collections (Depth: infinity) */

    (void) brix_fs_walk(log, root_canon, &opts, webdav_lock_sweep_cb, &sw);
    return sw.removed;
}

ngx_int_t
webdav_handle_unlock(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    char                               path[WEBDAV_MAX_PATH];
    ngx_int_t                          rc;
    ngx_table_elt_t                   *h;
    webdav_lock_xattr_t                e;
    const u_char                      *lock_val;
    size_t                             lock_len, token_len;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    h = webdav_tpc_find_header(r, "Lock-Token", sizeof("Lock-Token") - 1);
    if (h == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    rc = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon,
                                              path, sizeof(path));
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_lock_xattr_read(r, path, &e);
    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (rc == NGX_DECLINED || e.expires <= (int64_t) ngx_time()) {
        /* No active lock on this path. */
        if (rc == NGX_OK) {
            (void) webdav_lock_xattr_delete(r, path);
            webdav_lock_reap_null(r, path, &e);
        }
        return NGX_HTTP_CONFLICT;
    }

    /* Strip angle brackets from Lock-Token header: <opaquelocktoken:...> → token */
    lock_val = h->value.data;
    lock_len = (size_t) h->value.len;
    if (lock_len > 0 && lock_val[0] == '<') {
        lock_val++;
        lock_len--;
        if (lock_len > 0 && lock_val[lock_len - 1] == '>') {
            lock_len--;
        }
    }

    token_len = strlen(e.token);
    if (lock_len != token_len
        || CRYPTO_memcmp(lock_val, (u_char *) e.token, token_len) != 0)
    {
        return NGX_HTTP_CONFLICT;   /* token mismatch — not our lock */
    }

    /*
     * Remove the lock xattr and HONOUR the result.  Under impersonation the
     * removexattr runs (via the broker) as the requester's mapped user, so a
     * NON-OWNER who presents a valid (e.g. stolen/leaked) lock token cannot
     * actually clear the lock on another user's file — the broker returns EACCES.
     * Returning 204 unconditionally would falsely report success for that denied
     * removal; surface it as 403 instead so the lock state and the response agree.
     * (ENODATA/ENOENT collapse to NGX_OK inside the helper — idempotent unlock.)
     */
    if (webdav_lock_xattr_delete(r, path) != NGX_OK) {
        return NGX_HTTP_FORBIDDEN;
    }

    /* RFC 4918 §9.10.1: a lock-null resource that was never converted by a PUT/
     * MKCOL disappears when its lock is removed.  Reap the empty placeholder. */
    webdav_lock_reap_null(r, path, &e);

    return webdav_send_no_body(r, NGX_HTTP_NO_CONTENT);
}

/*
 * webdav_lock_append_supported — emit static <D:supportedlock> XML.
 * Unchanged from SHM implementation.
 */
ngx_int_t
webdav_lock_append_supported(ngx_http_request_t *r,
                             ngx_chain_t **head, ngx_chain_t **tail)
{
    if (brix_http_chain_appendf(r->pool, head, tail,
            "<D:supportedlock>"
            "<D:lockentry>"
            "<D:lockscope><D:exclusive/></D:lockscope>"
            "<D:locktype><D:write/></D:locktype>"
            "</D:lockentry>"
            "<D:lockentry>"
            "<D:lockscope><D:shared/></D:lockscope>"
            "<D:locktype><D:write/></D:locktype>"
            "</D:lockentry>"
            "</D:supportedlock>") == NULL)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * webdav_lock_append_discovery — emit <D:lockdiscovery> XML for PROPFIND.
 * Reads the xattr on path; emits an empty element if no active lock.
 */
ngx_int_t
webdav_lock_append_discovery(ngx_http_request_t *r, const char *path,
                             ngx_chain_t **head, ngx_chain_t **tail)
{
    webdav_lock_xattr_t  e;
    ngx_int_t            rc;
    int64_t              now;
    ngx_uint_t           remaining;
    char                *safe_owner;

    if (brix_http_chain_appendf(r->pool, head, tail,
                                  "<D:lockdiscovery>") == NULL)
    {
        return NGX_ERROR;
    }

    rc = webdav_lock_xattr_read(r, path, &e);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    now = (int64_t) ngx_time();

    if (rc == NGX_OK && e.expires > now) {
        remaining  = (ngx_uint_t) (e.expires - now);
        safe_owner = webdav_escape_xml_text(r->pool,
            (e.owner[0] != '\0') ? e.owner : "anonymous");
        if (safe_owner == NULL) {
            safe_owner = "anonymous";
        }

        if (brix_http_chain_appendf(r->pool, head, tail,
                "<D:activelock>"
                "<D:locktype><D:write/></D:locktype>"
                "<D:lockscope>%s</D:lockscope>"
                "<D:depth>%s</D:depth>"
                "<D:owner>%s</D:owner>"
                "<D:timeout>Second-%lu</D:timeout>"
                "<D:locktoken>"
                "<D:href>%s</D:href>"
                "</D:locktoken>"
                "</D:activelock>",
                e.exclusive ? "<D:exclusive/>" : "<D:shared/>",
                e.depth_infinity ? "infinity" : "0",
                safe_owner, (unsigned long) remaining, e.token) == NULL)
        {
            return NGX_ERROR;
        }
    } else if (rc == NGX_OK) {
        /* Expired lock — clean up lazily (and reap a lock-null placeholder). */
        (void) webdav_lock_xattr_delete(r, path);
        webdav_lock_reap_null(r, path, &e);
    }

    if (brix_http_chain_appendf(r->pool, head, tail,
                                  "</D:lockdiscovery>") == NULL)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
