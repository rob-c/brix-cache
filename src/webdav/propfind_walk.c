/*
 * propfind_walk.c - extracted concern
 * Phase-38 split of propfind.c; behavior-identical.
 */
#include "propfind_internal.h"
#include "../fs/vfs.h"   /* directory listing via the VFS seam (impersonation-aware) */


/* Adapt the VFS stat (returned per-entry by xrootd_vfs_readdir, a no-follow
 * lstat) to the struct stat propfind_entry consumes (it reads only
 * mode/size/mtime/ctime). */
static void
propfind_vfs_to_stat(const xrootd_vfs_stat_t *vs, struct stat *st)
{
    ngx_memzero(st, sizeof(*st));
    st->st_mode  = (mode_t) vs->mode;
    st->st_size  = vs->size;
    st->st_mtime = vs->mtime;
    st->st_ctime = vs->ctime;
    st->st_ino   = vs->ino;
}

/* Build a read-only VFS ctx for a directory path (impersonation is ambient, so
 * identity is not threaded here; allow_write/cache_root are irrelevant to a
 * listing). */
static void
propfind_dir_ctx(ngx_http_request_t *r, const char *root_canon,
    const char *dir_path, xrootd_vfs_ctx_t *vctx)
{
    int is_tls = 0;
#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
    xrootd_vfs_ctx_init(vctx, r->pool, r->connection->log, XROOTD_PROTO_WEBDAV,
        root_canon, NULL, 0 /* allow_write */, is_tls, NULL, dir_path);
}


/*
 * Depth: infinity recursive walk
 * */

/* Hard ceiling on entries emitted for a Depth: infinity PROPFIND so a deep or
 * wide tree cannot generate an unbounded response / runaway recursion. */

/*
 * Recursively emit D:response elements for every descendant of dir_path
 * (Depth: infinity).  entry_count is shared across the whole walk and checked
 * against max_entries before each entry; once the cap is hit the walk stops and
 * logs a warning (the response is still well-formed, just truncated).  An
 * unreadable directory is skipped, not fatal.  On any propfind_entry error the
 * open DIR is closed before returning NGX_ERROR (no fd leak on the error path).
 */
ngx_int_t
propfind_walk(ngx_http_request_t *r,
              ngx_chain_t **head, ngx_chain_t **tail,
              const char *dir_path, const char *base_href,
              ngx_uint_t *entry_count, ngx_uint_t max_entries,
              const propfind_req_t *req)
{
    ngx_http_xrootd_webdav_loc_conf_t *wdcf =
        ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    const char       *root_canon = wdcf->common.root_canon;
    xrootd_vfs_ctx_t  vctx;
    xrootd_vfs_dir_t *dh;
    ngx_str_t         name;
    xrootd_vfs_stat_t vst;

    /*
     * Impersonation read-gate: verify the MAPPED user may READ this directory
     * (kept as an explicit pre-check; xrootd_vfs_opendir below also opens AS that
     * user via the broker, so an unreadable dir is skipped either way). No-op
     * when impersonation is off; a denied dir is skipped, request not failed.
     */
    if (xrootd_dirlist_access_ok(r->connection->log, root_canon, dir_path)
        != NGX_OK)
    {
        return NGX_OK;
    }

    /* Enumerate through the VFS: xrootd_vfs_opendir is impersonation-aware
     * (broker fdopendir as the mapped user) and xrootd_vfs_readdir returns each
     * name with a no-follow lstat — so a symlink lists as a plain resource and is
     * never recursed, exactly as before. */
    propfind_dir_ctx(r, root_canon, dir_path, &vctx);
    dh = xrootd_vfs_opendir(&vctx, NULL);
    if (dh == NULL) {
        return NGX_OK;   /* unreadable subtree: skip, do not fail the request */
    }

    while (xrootd_vfs_readdir(dh, &name, &vst) == NGX_OK) {
        char        child_path[WEBDAV_MAX_PATH];
        char        child_href[WEBDAV_MAX_PATH + 2];
        struct stat csb;

        /* readdir already skips "."/".."; drop any other dotfile (not listed). */
        if (name.data[0] == '.') {
            continue;
        }

        if (*entry_count >= max_entries) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrootd: PROPFIND Depth:infinity capped at %ui entries "
                          "for \"%s\"", max_entries, dir_path);
            break;
        }

        if (xrootd_fs_join_path(dir_path, (char *) name.data, child_path,
                                sizeof(child_path)) != NGX_OK)
        {
            continue;
        }

        propfind_vfs_to_stat(&vst, &csb);   /* no-follow lstat from readdir */

        /* Build child href = base_href + name, inserting a single '/' only if
         * base_href is not already slash-terminated.  snprintf returns the
         * would-be length; >= buffer size means it was truncated, so skip the
         * entry rather than emit a corrupted href. */
        {
            size_t blen = strlen(base_href);
            if (blen == 0 || base_href[blen - 1] != '/') {
                if ((size_t) snprintf(child_href, sizeof(child_href),
                                      "%s/%s", base_href, (char *) name.data)
                    >= sizeof(child_href))
                    continue;
            } else if ((size_t) snprintf(child_href, sizeof(child_href),
                                         "%s%s", base_href, (char *) name.data)
                       >= sizeof(child_href))
            {
                continue;
            }
        }

        if (propfind_entry(r, head, tail, child_href, child_path, &csb, req)
            != NGX_OK)
        {
            xrootd_vfs_closedir(dh, r->connection->log);
            return NGX_ERROR;
        }
        (*entry_count)++;

        /* Recurse into subdirectories (with a trailing-slash href). Re-check
         * the cap first so a balanced tree cannot blow past max_entries via
         * nested calls before the per-entry check fires. */
        if (S_ISDIR(csb.st_mode) && *entry_count < max_entries) {
            char subdir_href[WEBDAV_MAX_PATH + 3];
            if ((size_t) snprintf(subdir_href, sizeof(subdir_href),
                                  "%s/", child_href)
                < sizeof(subdir_href))
            {
                if (propfind_walk(r, head, tail, child_path, subdir_href,
                                  entry_count, max_entries, req) != NGX_OK)
                {
                    xrootd_vfs_closedir(dh, r->connection->log);
                    return NGX_ERROR;
                }
            }
        }
    }

    xrootd_vfs_closedir(dh, r->connection->log);
    return NGX_OK;
}


/*
 * Core PROPFIND logic (called from body-ready callback)
 * */

/*
 * Build and send the complete 207 Multi-Status response.
 * Runs after the request body has been read (see propfind_body_handler), so it
 * may resolve/stat the target and parse the body synchronously.  Assembles the
 * XML as an ngx_chain_t, sums the body length for Content-Length, marks the last
 * buffer, then sends headers + body.  Returns an HTTP status / NGX_* code.
 */
ngx_int_t
propfind_do(ngx_http_request_t *r)
{
    char             path[WEBDAV_MAX_PATH];
    struct stat      sb;
    ngx_int_t        rc;
    int              depth;
    ngx_chain_t     *head = NULL;
    ngx_chain_t     *tail = NULL;
    off_t            total_len = 0;
    ngx_chain_t     *lc;
    ngx_table_elt_t *h;
    ngx_uint_t       entry_count = 0;
    propfind_req_t   req;

    rc = webdav_resolve_stat(r, path, sizeof(path), &sb);
    if (rc != NGX_OK) {
        return rc;
    }

    propfind_parse_request(r, &req);

    depth = propfind_parse_depth(r);
    {
        ngx_uint_t depth_slot = (depth == 0)  ? XROOTD_WEBDAV_PROPFIND_DEPTH_0
                              : (depth == 1)  ? XROOTD_WEBDAV_PROPFIND_DEPTH_1
                              :                 XROOTD_WEBDAV_PROPFIND_DEPTH_INF;
        XROOTD_WEBDAV_METRIC_INC(propfind_depth_total[depth_slot]);
    }

    if (xrootd_http_chain_appendf(r->pool, &head, &tail,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<D:multistatus xmlns:D=\"DAV:\""
            " xmlns:xrd=\"http://xrootd.org/2010/ns/dav\">") == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* First D:response is always the request target itself (Depth 0/1/inf). */
    {
        char   href[WEBDAV_MAX_PATH + 2];
        size_t uri_len = r->uri.len;

        /* r->uri is not NUL-terminated; copy a bounded, terminated href. */
        if (uri_len >= sizeof(href) - 1) {
            uri_len = sizeof(href) - 2;
        }
        ngx_memcpy(href, r->uri.data, uri_len);
        href[uri_len] = '\0';

        if (propfind_entry(r, &head, &tail, href, path, &sb, &req) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        entry_count++;
    }

    /* Depth 1 or infinity on a collection: emit each immediate child. For
     * infinity we additionally recurse into each child directory via
     * propfind_walk (the top level is unrolled here so the shared entry_count
     * cap is threaded through). */
    if ((depth == 1 || depth == -1) && S_ISDIR(sb.st_mode)) {
        ngx_http_xrootd_webdav_loc_conf_t *wdcf =
            ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
        xrootd_vfs_ctx_t  vctx;
        xrootd_vfs_dir_t *dh;
        ngx_str_t         name;
        xrootd_vfs_stat_t vst;

        /* Impersonation read-gate (kept); xrootd_vfs_opendir also opens the dir
         * O_RDONLY AS the mapped user via the broker, so a worker that itself
         * cannot read still lists for the legitimate owner — and never leaks
         * entries the user has no permission to see. No-op when impersonation off. */
        if (xrootd_dirlist_access_ok(r->connection->log,
                                     wdcf->common.root_canon, path) != NGX_OK)
        {
            dh = NULL;
        } else {
            propfind_dir_ctx(r, wdcf->common.root_canon, path, &vctx);
            dh = xrootd_vfs_opendir(&vctx, NULL);
        }

        if (dh != NULL) {
            while (xrootd_vfs_readdir(dh, &name, &vst) == NGX_OK) {
                char        child_path[WEBDAV_MAX_PATH];
                struct stat csb;
                char        href[WEBDAV_MAX_PATH + 2];
                const char *base;
                size_t      blen;

                if (name.data[0] == '.') {
                    continue;
                }

                if (xrootd_fs_join_path(path, (char *) name.data, child_path,
                                        sizeof(child_path)) != NGX_OK)
                {
                    continue;
                }

                propfind_vfs_to_stat(&vst, &csb);   /* no-follow lstat */

                base = (const char *) r->uri.data;
                blen = r->uri.len;
                if (blen == 0 || base[blen - 1] != '/') {
                    if ((size_t) snprintf(href, sizeof(href), "%.*s/%s",
                                          (int) blen, base, (char *) name.data)
                        >= sizeof(href))
                    {
                        continue;
                    }
                } else if ((size_t) snprintf(href, sizeof(href), "%.*s%s",
                                             (int) blen, base, (char *) name.data)
                           >= sizeof(href))
                {
                    continue;
                }

                if (propfind_entry(r, &head, &tail, href, child_path,
                                   &csb, &req) != NGX_OK)
                {
                    xrootd_vfs_closedir(dh, r->connection->log);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                entry_count++;

                if (depth == -1 && S_ISDIR(csb.st_mode)) {
                    char subdir_href[WEBDAV_MAX_PATH + 3];
                    if ((size_t) snprintf(subdir_href, sizeof(subdir_href),
                                          "%s/", href)
                        < sizeof(subdir_href))
                    {
                        if (propfind_walk(r, &head, &tail,
                                          child_path, subdir_href,
                                          &entry_count,
                                          PROPFIND_INFINITY_MAX_ENTRIES,
                                          &req) != NGX_OK)
                        {
                            xrootd_vfs_closedir(dh, r->connection->log);
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }
                    }
                }
            }
            xrootd_vfs_closedir(dh, r->connection->log);
        }
    }

    if (xrootd_http_chain_appendf(r->pool, &head, &tail,
            "</D:multistatus>") == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Mark end-of-response on the final buffer so the output filter flushes. */
    if (tail != NULL) {
        tail->buf->last_buf = 1;
        tail->buf->last_in_chain = 1;
    }

    /* Content-Length = sum of all buffer payloads in the chain. */
    for (lc = head; lc != NULL; lc = lc->next) {
        total_len += lc->buf->last - lc->buf->pos;
    }

    XROOTD_WEBDAV_METRIC_ADD(propfind_entries_total, entry_count);

    r->headers_out.status = 207;
    r->headers_out.content_length_n = total_len;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Content-Type");
    ngx_str_set(&h->value, "application/xml; charset=\"utf-8\"");

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || r->header_only) {
        return rc;
    }

    XROOTD_WEBDAV_METRIC_ADD(bytes_tx_total, (size_t) total_len);
    if (r->connection && r->connection->sockaddr
        && r->connection->sockaddr->sa_family == AF_INET6) {
        XROOTD_WEBDAV_METRIC_ADD(bytes_tx_ipv6_total, (size_t) total_len);
    } else {
        XROOTD_WEBDAV_METRIC_ADD(bytes_tx_ipv4_total, (size_t) total_len);
    }

    return ngx_http_output_filter(r, head);
}
