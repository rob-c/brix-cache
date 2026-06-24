/*
 * lock.c — WebDAV LOCK and UNLOCK handler (RFC 4918 §9.10, §9.11).
 *
 * Lock state is stored as a single xattr on the locked resource
 * (see prop_xattr.c).  No shared memory or mutex is needed:
 * XATTR_CREATE provides kernel-serialized atomic lock creation;
 * expiry cleanup is lazy (on next access to that path).
 *
 * Lock check walks from the target path up to the export root,
 * O(path_depth) xattr reads rather than O(1024) SHM slot scans.
 */
#include "webdav.h"
#include "../path/path.h"
#include "../impersonate/lifecycle.h"
#include "locks/request.h"
#include "../compat/http_xml.h"
#include "../compat/fs_walk.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <time.h>

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
 * Startup lock sweep — remove every persisted lock xattr under the export
 * root.  Locks are stored as the WEBDAV_LOCK_XATTR_KEY xattr on each resource
 * (prop_xattr.c), so they normally survive an nginx restart.  When
 * xrootd_webdav_lock_startup_sweep is on, this walk restores ephemeral
 * RFC 4918 §10.1 semantics by clearing them once at startup.
 *
 * removexattr is idempotent: a node with no lock returns ENODATA/ENOATTR,
 * which is not counted and not an error.  The walk continues past per-node
 * failures so one unreadable subtree cannot abort the sweep.
 */
static ngx_int_t
webdav_lock_sweep_cb(const xrootd_fs_walk_entry_t *entry, void *data)
{
    ngx_uint_t *removed = data;

    if (removexattr(entry->path, WEBDAV_LOCK_XATTR_KEY) == 0) {
        (*removed)++;
    }
    return NGX_OK;   /* continue regardless of per-node result */
}

ngx_uint_t
webdav_lock_startup_sweep(ngx_log_t *log, const char *root_canon)
{
    xrootd_fs_walk_options_t opts;
    ngx_uint_t               removed = 0;

    if (root_canon == NULL || root_canon[0] == '\0') {
        return 0;
    }

    /* The tree walk visits children only; clear a lock on the root itself. */
    if (removexattr(root_canon, WEBDAV_LOCK_XATTR_KEY) == 0) {
        removed++;
    }

    ngx_memzero(&opts, sizeof(opts));
    opts.include_files = 1;   /* locks may sit on files ... */
    opts.include_dirs  = 1;   /* ... and on collections (Depth: infinity) */

    (void) xrootd_fs_walk(log, root_canon, &opts, webdav_lock_sweep_cb,
                          &removed);
    return removed;
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
    ngx_msec_t       now = ngx_current_msec;
    ngx_uint_t       remaining;
    off_t            total_len = 0;
    ngx_chain_t     *lc;
    ngx_table_elt_t *h;

    remaining = (e->expires > now) ? (ngx_uint_t) ((e->expires - now) / 1000) : 0;
    ngx_sprintf((u_char *) timeout_buf, "Second-%ui", remaining);

    safe_owner = webdav_escape_xml_text(r->pool, e->owner);
    if (safe_owner == NULL) {
        safe_owner = "anonymous";
    }

    xrootd_http_chain_appendf(r->pool, &head, &tail,
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
 * webdav_check_locks — walk from path up to export root, checking for active
 * xattr locks at each level.  O(path_depth) xattr reads.
 *
 * Returns NGX_HTTP_LOCKED if an active, client-unowned lock blocks this
 * operation; NGX_OK otherwise.
 */
ngx_int_t
webdav_check_locks(ngx_http_request_t *r, const char *path, int need_write)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char               check[PATH_MAX];
    char              *slash;
    size_t             root_len, check_len, path_len;
    webdav_lock_xattr_t e;
    ngx_int_t          rc;

    (void) need_write;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    root_len = strlen(conf->common.root_canon);
    path_len = strlen(path);

    ngx_cpystrn((u_char *) check, (u_char *) path, sizeof(check));

    for (;;) {
        check_len = strlen(check);

        rc = webdav_lock_xattr_read(r, check, &e);
        if (rc == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rc == NGX_OK) {
            if (e.expires > ngx_current_msec) {
                /* Lock covers path if: exact match or depth-infinity ancestor. */
                int covers = (check_len == path_len)
                             || (e.depth_infinity
                                 && check_len < path_len
                                 && (check[check_len - 1] == '/'
                                     || path[check_len] == '/'));
                if (covers && !webdav_lock_if_header_matches(r, e.token)) {
                    return NGX_HTTP_LOCKED;
                }
            } else {
                (void) webdav_lock_xattr_delete(r, check);
            }
        }

        /* Stop at or above export root. */
        if (check_len <= root_len) {
            break;
        }

        /* Strip trailing slashes then the last path component. */
        slash = check + check_len - 1;
        while (slash > check && *slash == '/') {
            slash--;
        }
        while (slash > check && *slash != '/') {
            slash--;
        }
        if (*slash != '/') {
            break;
        }
        *slash = '\0';

        if (strlen(check) < root_len) {
            break;
        }
    }

    return NGX_OK;
}

/*
 * check_locks_descendants — scan direct and recursive children of a directory
 * for unexpired xattr locks not covered by the client's If header.
 * Does NOT walk upward; the caller is responsible for checking ancestors.
 */
static ngx_int_t
check_locks_descendants(ngx_http_request_t *r, const char *dir)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    DIR                *dp;
    struct dirent      *de;
    struct stat         sb;
    char                child[PATH_MAX];
    size_t              dir_len;
    webdav_lock_xattr_t e;
    ngx_int_t           rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    /* Confined opendir (openat2 RESOLVE_BENEATH) so a planted in-export symlink
     * cannot redirect the recursive lock scan out of the export root. */
    dp = xrootd_opendir_confined_canon(r->connection->log,
                                       conf->common.root_canon, dir);
    if (dp == NULL) {
        return NGX_OK;
    }

    dir_len = strlen(dir);
    rc = NGX_OK;

    while ((de = readdir(dp)) != NULL) {
        ngx_int_t xrc;

        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0'
                || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
        {
            continue;
        }

        if (dir_len + 1 + strlen(de->d_name) + 1 > sizeof(child)) {
            continue;   /* path too long — skip */
        }
        snprintf(child, sizeof(child), "%s/%s", dir, de->d_name);

        /* Check lock xattr directly on this child. */
        xrc = webdav_lock_xattr_read(r, child, &e);
        if (xrc == NGX_ERROR) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (xrc == NGX_OK) {
            if (e.expires > ngx_current_msec) {
                if (!webdav_lock_if_header_matches(r, e.token)) {
                    rc = NGX_HTTP_LOCKED;
                    break;
                }
            } else {
                (void) webdav_lock_xattr_delete(r, child);
            }
        }
        /* xrc == NGX_DECLINED: no lock xattr on this child — OK */

        /* Recurse into subdirectories (confined, no-follow). */
        if (xrootd_lstat_confined_canon(r->connection->log,
                                        conf->common.root_canon, child, &sb, 1)
                == 0
            && S_ISDIR(sb.st_mode))
        {
            rc = check_locks_descendants(r, child);
            if (rc != NGX_OK) {
                break;
            }
        }
    }

    closedir(dp);
    return rc;
}

/*
 * webdav_check_locks_tree — check locks on a path and all its descendants.
 * Use this instead of webdav_check_locks() for DELETE/COPY/MOVE on
 * collections, where a lock on any child must block the operation.
 */
ngx_int_t
webdav_check_locks_tree(ngx_http_request_t *r, const char *path)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    struct stat sb;
    ngx_int_t   rc;

    rc = webdav_check_locks(r, path, 1);
    if (rc != NGX_OK) {
        return rc;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    if (xrootd_lstat_confined_canon(r->connection->log, conf->common.root_canon,
                                    path, &sb, 1) == 0
        && S_ISDIR(sb.st_mode))
    {
        rc = check_locks_descendants(r, path);
    }

    return rc;
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
    ngx_http_xrootd_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);

    xrootd_imp_request_begin(rx != NULL ? rx->identity : NULL);
    webdav_handle_lock_inner(r);
    xrootd_imp_request_end();
}

static void
webdav_handle_lock_inner(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char                               path[WEBDAV_MAX_PATH];
    ngx_int_t                          rc;
    webdav_lock_xattr_t                e;
    ngx_http_xrootd_webdav_req_ctx_t  *ctx;
    int                                depth_infinity = 1;
    char                               owner[256];
    int                                exclusive = 1;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->common.root_canon,
                                              path, sizeof(path));
    if (rc != NGX_OK) {
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    rc = webdav_lock_parse_depth(r, &depth_infinity);
    if (rc != NGX_OK) {
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    webdav_lock_parse_body(r, owner, sizeof(owner), &exclusive);

    /* RFC 4918 §9.10.1: LOCK on non-existent resource MUST create zero-byte resource. */
    {
        struct stat sb;
        if (xrootd_lstat_confined_canon(r->connection->log,
                                        conf->common.root_canon, path, &sb, 1)
                != 0
            && errno == ENOENT)
        {
            int fd = xrootd_open_confined_canon(r->connection->log,
                                                conf->common.root_canon, path,
                                                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                                                0644);
            if (fd < 0 && errno != EEXIST) {
                webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
            if (fd >= 0) {
                (void) close(fd);
            }
        }
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);

    rc = webdav_lock_xattr_read(r, path, &e);
    if (rc == NGX_ERROR) {
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* Treat expired lock as absent. */
    if (rc == NGX_OK && e.expires <= ngx_current_msec) {
        (void) webdav_lock_xattr_delete(r, path);
        rc = NGX_DECLINED;
    }

    if (rc == NGX_OK) {
        /* Existing active lock: refresh if token matches, else 423. */
        if (!webdav_lock_if_header_matches(r, e.token)) {
            webdav_metrics_finalize_request(r, NGX_HTTP_LOCKED);
            return;
        }
        e.expires = webdav_lock_parse_timeout(r, conf);
        if (webdav_lock_xattr_write(r, path, &e,
                                    XATTR_REPLACE) != NGX_OK) {
            webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        r->headers_out.status = NGX_HTTP_OK;

    } else {
        /* No lock: create atomically with XATTR_CREATE. */
        ngx_memzero(&e, sizeof(e));
        webdav_generate_uuid(e.token, sizeof(e.token));

        if (owner[0] != '\0') {
            ngx_cpystrn((u_char *) e.owner, (u_char *) owner, sizeof(e.owner));
        } else if (ctx != NULL && ctx->dn[0] != '\0') {
            ngx_cpystrn((u_char *) e.owner, (u_char *) ctx->dn, sizeof(e.owner));
        } else {
            ngx_cpystrn((u_char *) e.owner, (u_char *) "anonymous",
                        sizeof(e.owner));
        }

        e.exclusive      = exclusive;
        e.depth_infinity = depth_infinity;
        e.expires        = webdav_lock_parse_timeout(r, conf);

        rc = webdav_lock_xattr_write(r, path, &e, XATTR_CREATE);
        if (rc == NGX_DECLINED) {
            /* Another worker created the lock between our read and write. */
            webdav_metrics_finalize_request(r, NGX_HTTP_LOCKED);
            return;
        }
        if (rc != NGX_OK) {
            webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        r->headers_out.status = NGX_HTTP_CREATED;
    }

    webdav_lock_xml_response(r, &e);
}

ngx_int_t
webdav_handle_unlock(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char                               path[WEBDAV_MAX_PATH];
    ngx_int_t                          rc;
    ngx_table_elt_t                   *h;
    webdav_lock_xattr_t                e;
    const u_char                      *lock_val;
    size_t                             lock_len, token_len;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    h = webdav_tpc_find_header(r, "Lock-Token", sizeof("Lock-Token") - 1);
    if (h == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->common.root_canon,
                                              path, sizeof(path));
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_lock_xattr_read(r, path, &e);
    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (rc == NGX_DECLINED || e.expires <= ngx_current_msec) {
        /* No active lock on this path. */
        if (rc == NGX_OK) {
            (void) webdav_lock_xattr_delete(r, path);
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
    if (xrootd_http_chain_appendf(r->pool, head, tail,
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
    ngx_msec_t           now;
    ngx_uint_t           remaining;
    char                *safe_owner;

    if (xrootd_http_chain_appendf(r->pool, head, tail,
                                  "<D:lockdiscovery>") == NULL)
    {
        return NGX_ERROR;
    }

    rc = webdav_lock_xattr_read(r, path, &e);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    now = ngx_current_msec;

    if (rc == NGX_OK && e.expires > now) {
        remaining  = (ngx_uint_t) ((e.expires - now) / 1000);
        safe_owner = webdav_escape_xml_text(r->pool,
            (e.owner[0] != '\0') ? e.owner : "anonymous");
        if (safe_owner == NULL) {
            safe_owner = "anonymous";
        }

        if (xrootd_http_chain_appendf(r->pool, head, tail,
                "<D:activelock>"
                "<D:locktype><D:write/></D:locktype>"
                "<D:lockscope>%s</D:lockscope>"
                "<D:depth>%s</D:depth>"
                "<D:owner>%s</D:owner>"
                "<D:timeout>Second-%ui</D:timeout>"
                "<D:locktoken>"
                "<D:href>%s</D:href>"
                "</D:locktoken>"
                "</D:activelock>",
                e.exclusive ? "<D:exclusive/>" : "<D:shared/>",
                e.depth_infinity ? "infinity" : "0",
                safe_owner, remaining, e.token) == NULL)
        {
            return NGX_ERROR;
        }
    } else if (rc == NGX_OK) {
        /* Expired lock — clean up lazily. */
        (void) webdav_lock_xattr_delete(r, path);
    }

    if (xrootd_http_chain_appendf(r->pool, head, tail,
                                  "</D:lockdiscovery>") == NULL)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
