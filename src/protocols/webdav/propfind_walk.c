/*
 * propfind_walk.c - extracted concern
 * Phase-38 split of propfind.c; behavior-identical.
 */
#include "propfind_internal.h"
#include "fs/vfs/vfs.h"   /* directory listing via the VFS seam (impersonation-aware) */
#include "fs/path/reserved_names.h"   /* brix_is_internal_name — hide sidecars */


/* Adapt the VFS stat (returned per-entry by brix_vfs_readdir, a no-follow
 * lstat) to the struct stat propfind_entry consumes (it reads only
 * mode/size/mtime/ctime). */
static void
propfind_vfs_to_stat(const brix_vfs_stat_t *vs, struct stat *st)
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
    const char *dir_path, brix_vfs_ctx_t *vctx)
{
    int is_tls = 0;
#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
    brix_vfs_ctx_init(vctx, r->pool, r->connection->log, BRIX_PROTO_WEBDAV,
        root_canon, NULL, 0 /* allow_write */, is_tls, NULL, dir_path);
}


/*
 * Depth: infinity recursive walk
 * */

/* Hard ceiling on entries emitted for a Depth: infinity PROPFIND so a deep or
 * wide tree cannot generate an unbounded response / runaway recursion. */

/*
 * WHAT: Immutable per-walk context — the request, output chain, request-props,
 *   entry cap/counter and recursion flag that every level of the walk shares.
 * WHY: propfind_walk's signature is frozen (declared extern in
 *   propfind_internal.h with 9 params), but its helpers must not each re-take
 *   that many arguments; bundling the shared state into one file-local struct
 *   keeps each helper at =5 params and makes the data flow explicit.
 * HOW: Populated once at the top of propfind_walk and passed by pointer to the
 *   per-entry helpers; entry_count is a live pointer so nested levels update a
 *   single shared counter.
 */
typedef struct {
    ngx_http_request_t   *r;
    ngx_chain_t         **head;
    ngx_chain_t         **tail;
    const propfind_req_t *req;
    ngx_uint_t           *entry_count;
    ngx_uint_t            max_entries;
    ngx_flag_t            recurse;
} propfind_walk_ctx_t;

/*
 * WHAT: Decide whether a readdir entry is emitted at all.
 * WHY: readdir already drops "."/".."; PROPFIND additionally hides every other
 *   dotfile and every internal metadata/staging artifact (sidecars like
 *   "f.dat.cinfo" or upload temps are not dotfiles, so the leading-'.' test
 *   misses them and the suffix/infix predicate catches them).
 * HOW: Pure predicate over the entry name; returns 1 to keep, 0 to skip.
 */
static int
propfind_child_visible(const ngx_str_t *name)
{
    if (name->data[0] == '.') {
        return 0;
    }
    if (brix_is_internal_name((const char *) name->data)) {
        return 0;
    }
    return 1;
}

/*
 * WHAT: Build the child href = base_href + name into out (size out_sz).
 * WHY: A single '/' separator is inserted only when base_href is not already
 *   slash-terminated; a truncated result must be discarded rather than emitted
 *   as a corrupted href.
 * HOW: snprintf returns the would-be length; >= out_sz means truncation, in
 *   which case NGX_ERROR is returned so the caller skips the entry (NGX_OK on
 *   success — bytes identical to the original inline logic).
 */
static ngx_int_t
propfind_build_child_href(const char *base_href, const char *name,
    char *out, size_t out_sz)
{
    size_t blen = strlen(base_href);
    size_t n;

    if (blen == 0 || base_href[blen - 1] != '/') {
        n = (size_t) snprintf(out, out_sz, "%s/%s", base_href, name);
    } else {
        n = (size_t) snprintf(out, out_sz, "%s%s", base_href, name);
    }
    return (n >= out_sz) ? NGX_ERROR : NGX_OK;
}

/*
 * WHAT: Recurse into a subdirectory child during a Depth: infinity walk.
 * WHY: Only directories are descended, only when recursion is enabled, and only
 *   while the cap has not been hit (re-checked here so a balanced tree cannot
 *   blow past max_entries via nested calls before the per-entry check fires).
 * HOW: Builds the trailing-slash subdir href; a truncated href is skipped
 *   (NGX_OK, matching the original). Delegates to propfind_walk and propagates
 *   its NGX_ERROR so the caller can close the open DIR without an fd leak.
 */
static ngx_int_t
propfind_recurse_child(const propfind_walk_ctx_t *w,
    const char *child_path, const char *child_href, const struct stat *csb)
{
    char subdir_href[WEBDAV_MAX_PATH + 3];

    if (!w->recurse || !S_ISDIR(csb->st_mode)
        || *w->entry_count >= w->max_entries)
    {
        return NGX_OK;
    }
    if ((size_t) snprintf(subdir_href, sizeof(subdir_href), "%s/", child_href)
        >= sizeof(subdir_href))
    {
        return NGX_OK;
    }
    return propfind_walk(w->r, w->head, w->tail, child_path, subdir_href,
                         w->entry_count, w->max_entries, w->req, w->recurse);
}

/*
 * WHAT: Emit the D:response for one visible readdir entry and recurse into it
 *   if it is a subdirectory.
 * WHY: Splits the per-entry work (join path, adapt stat, build href, emit,
 *   count, recurse) out of the enumeration loop so neither exceeds the CCN cap;
 *   the visibility/cap checks stay in the loop, this handles a kept entry.
 * HOW: A path/href that would truncate is skipped (NGX_OK, no entry emitted),
 *   exactly as before. propfind_entry increments the shared counter on success;
 *   a propfind_entry / recursion failure returns NGX_ERROR so the caller closes
 *   the DIR before propagating it.
 */
static ngx_int_t
propfind_walk_emit(const propfind_walk_ctx_t *w, const char *dir_path,
    const char *base_href, const ngx_str_t *name, const brix_vfs_stat_t *vst)
{
    char        child_path[WEBDAV_MAX_PATH];
    char        child_href[WEBDAV_MAX_PATH + 2];
    struct stat csb;

    if (brix_fs_join_path(dir_path, (char *) name->data, child_path,
                          sizeof(child_path)) != NGX_OK)
    {
        return NGX_OK;
    }

    propfind_vfs_to_stat(vst, &csb);   /* no-follow lstat from readdir */

    if (propfind_build_child_href(base_href, (char *) name->data,
                                  child_href, sizeof(child_href)) != NGX_OK)
    {
        return NGX_OK;   /* truncated href: skip this entry, do not corrupt it */
    }

    if (propfind_entry(w->r, w->head, w->tail, child_href, child_path, &csb,
                       w->req) != NGX_OK)
    {
        return NGX_ERROR;
    }
    (*w->entry_count)++;

    return propfind_recurse_child(w, child_path, child_href, &csb);
}

/*
 * Emit D:response elements for the children of dir_path — one level when
 * recurse is 0 (Depth: 1), every descendant when recurse is 1 (Depth:
 * infinity).  entry_count is shared across the whole walk and checked against
 * max_entries before each entry; once the cap is hit the walk stops and logs a
 * warning (the response is still well-formed, just truncated).  An unreadable
 * directory is skipped, not fatal.  On any propfind_entry error the open DIR
 * is closed before returning NGX_ERROR (no fd leak on the error path).
 */
ngx_int_t
propfind_walk(ngx_http_request_t *r,
              ngx_chain_t **head, ngx_chain_t **tail,
              const char *dir_path, const char *base_href,
              ngx_uint_t *entry_count, ngx_uint_t max_entries,
              const propfind_req_t *req, ngx_flag_t recurse)
{
    ngx_http_brix_webdav_loc_conf_t *wdcf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    const char         *root_canon = wdcf->common.root_canon;
    brix_vfs_ctx_t      vctx;
    brix_vfs_dir_t     *dh;
    ngx_str_t           name;
    brix_vfs_stat_t     vst;
    propfind_walk_ctx_t w;

    /*
     * Impersonation read-gate: verify the MAPPED user may READ this directory
     * (kept as an explicit pre-check; brix_vfs_opendir below also opens AS that
     * user via the broker, so an unreadable dir is skipped either way). No-op
     * when impersonation is off; a denied dir is skipped, request not failed.
     */
    if (brix_dirlist_access_ok(r->connection->log, root_canon, dir_path)
        != NGX_OK)
    {
        return NGX_OK;
    }

    /* Enumerate through the VFS: brix_vfs_opendir is impersonation-aware
     * (broker fdopendir as the mapped user) and brix_vfs_readdir returns each
     * name with a no-follow lstat — so a symlink lists as a plain resource and is
     * never recursed, exactly as before. */
    propfind_dir_ctx(r, root_canon, dir_path, &vctx);
    dh = brix_vfs_opendir(&vctx, NULL);
    if (dh == NULL) {
        return NGX_OK;   /* unreadable subtree: skip, do not fail the request */
    }

    w.r = r;
    w.head = head;
    w.tail = tail;
    w.req = req;
    w.entry_count = entry_count;
    w.max_entries = max_entries;
    w.recurse = recurse;

    while (brix_vfs_readdir(dh, &name, &vst) == NGX_OK) {
        if (!propfind_child_visible(&name)) {
            continue;
        }

        if (*entry_count >= max_entries) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "brix: PROPFIND Depth:infinity capped at %ui entries "
                          "for \"%s\"", max_entries, dir_path);
            break;
        }

        if (propfind_walk_emit(&w, dir_path, base_href, &name, &vst)
            != NGX_OK)
        {
            brix_vfs_closedir(dh, r->connection->log);
            return NGX_ERROR;
        }
    }

    brix_vfs_closedir(dh, r->connection->log);
    return NGX_OK;
}


/*
 * Core PROPFIND logic (called from body-ready callback)
 * */

/*
 * WHAT: Response-building plumbing shared across propfind_do's body stage — the
 *   request, the growing output chain (head/tail), the running entry counter,
 *   and the caller-owned href scratch buffer used for the target and as the
 *   walk's base href.
 * WHY: Bundling this state lets propfind_build_body stay at =5 params (and keeps
 *   head/tail/entry_count as live pointers into propfind_do's locals so the
 *   finalize/metric stages see the final values).
 * HOW: Filled once in propfind_do; href points at a stack buffer of href_sz.
 */
typedef struct {
    ngx_http_request_t *r;
    ngx_chain_t       **head;
    ngx_chain_t       **tail;
    ngx_uint_t         *entry_count;
    char               *href;
    size_t              href_sz;
} propfind_resp_t;

/*
 * WHAT: Record the propfind_depth_total metric for the requested Depth.
 * WHY: Depth 0/1/infinity map to three fixed low-cardinality slots; isolating
 *   the slot selection keeps the ternary out of propfind_do's CCN.
 * HOW: depth==0→0, depth==1→1, else (infinity)→INF, then increment.
 */
static void
propfind_count_depth(int depth)
{
    ngx_uint_t depth_slot = (depth == 0) ? BRIX_WEBDAV_PROPFIND_DEPTH_0
                          : (depth == 1) ? BRIX_WEBDAV_PROPFIND_DEPTH_1
                          :                BRIX_WEBDAV_PROPFIND_DEPTH_INF;
    BRIX_WEBDAV_METRIC_INC(propfind_depth_total[depth_slot]);
}

/*
 * WHAT: Copy the (non-NUL-terminated) request URI into a bounded href buffer.
 * WHY: The first D:response is always the request target, and its bounded href
 *   then serves as the walk's base; r->uri.data has no terminator so it must be
 *   length-clamped and NUL-terminated by hand.
 * HOW: Clamps to out_sz-1, memcpy, terminate — identical bytes to the original
 *   inline copy.
 */
static void
propfind_target_href(ngx_http_request_t *r, char *out, size_t out_sz)
{
    size_t uri_len = r->uri.len;

    if (uri_len >= out_sz - 1) {
        uri_len = out_sz - 2;
    }
    ngx_memcpy(out, r->uri.data, uri_len);
    out[uri_len] = '\0';
}

/*
 * WHAT: Emit the multistatus prologue, the target's D:response, and (for Depth
 *   1/infinity on a collection) the child responses.
 * WHY: Groups the body-building stage so its several NULL/NGX_OK checks do not
 *   inflate propfind_do's complexity; entry_count/href are passed by pointer as
 *   they are consumed by the finalize stage.
 * HOW: Prologue → target entry (always) → propfind_walk children when the
 *   target is a directory and Depth is 1 (uncapped) or infinity (capped).
 *   Returns NGX_HTTP_INTERNAL_SERVER_ERROR on any allocation/emit failure,
 *   else NGX_OK — the walk itself is behavior-identical to the prior inline
 *   version.
 */
static ngx_int_t
propfind_build_body(const propfind_resp_t *rb, const char *path,
    struct stat *sb, const propfind_req_t *req, int depth)
{
    ngx_http_request_t *r = rb->r;

    if (brix_http_chain_appendf(r->pool, rb->head, rb->tail,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<D:multistatus xmlns:D=\"DAV:\""
            " xmlns:xrd=\"http://xrootd.org/2010/ns/dav\">") == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    propfind_target_href(r, rb->href, rb->href_sz);
    if (propfind_entry(r, rb->head, rb->tail, rb->href, path, sb, req)
        != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    (*rb->entry_count)++;

    if ((depth == 1 || depth == -1) && S_ISDIR(sb->st_mode)) {
        ngx_uint_t cap = (depth == -1) ? PROPFIND_INFINITY_MAX_ENTRIES
                                       : (ngx_uint_t) -1;
        if (propfind_walk(r, rb->head, rb->tail, path, rb->href,
                          rb->entry_count, cap, req, depth == -1) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (brix_http_chain_appendf(r->pool, rb->head, rb->tail,
            "</D:multistatus>") == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return NGX_OK;
}

/*
 * WHAT: Mark end-of-response on the last buffer and sum the chain's payload.
 * WHY: The output filter needs last_buf/last_in_chain on the final buffer, and
 *   Content-Length is the sum of every buffer's [pos,last).
 * HOW: Sets the flags on tail (if any) then accumulates the byte total.
 */
static off_t
propfind_finalize_chain(ngx_chain_t *head, ngx_chain_t *tail)
{
    off_t        total_len = 0;
    ngx_chain_t *lc;

    if (tail != NULL) {
        tail->buf->last_buf = 1;
        tail->buf->last_in_chain = 1;
    }
    for (lc = head; lc != NULL; lc = lc->next) {
        total_len += lc->buf->last - lc->buf->pos;
    }
    return total_len;
}

/*
 * WHAT: Set the 207 status + Content-Type/Content-Length headers and send them.
 * WHY: Header assembly is a distinct stage from body building; splitting it out
 *   keeps propfind_do below the CCN cap.
 * HOW: Pushes the Content-Type header, writing NGX_HTTP_INTERNAL_SERVER_ERROR
 *   to *out_rc and returning NGX_ERROR on list failure so the caller aborts
 *   before sending; otherwise sets the send-header result in *out_rc and
 *   returns NGX_OK, leaving the NGX_ERROR / header_only decision to the caller
 *   exactly as the original inline code.
 */
static ngx_int_t
propfind_send_headers(ngx_http_request_t *r, off_t total_len, ngx_int_t *out_rc)
{
    ngx_table_elt_t *h;

    r->headers_out.status = 207;
    r->headers_out.content_length_n = total_len;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        *out_rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Content-Type");
    ngx_str_set(&h->value, "application/xml; charset=\"utf-8\"");

    *out_rc = ngx_http_send_header(r);
    return NGX_OK;
}

/*
 * WHAT: Record the transmitted-bytes metrics (total + per address family).
 * WHY: Keeps the AF_INET6/AF_INET branch out of propfind_do; labels stay
 *   low-cardinality (family only, never paths).
 * HOW: Always adds to the total, then to the v6 or v4 bucket by sockaddr family
 *   — identical to the prior inline logic.
 */
static void
propfind_count_tx(ngx_http_request_t *r, off_t total_len)
{
    BRIX_WEBDAV_METRIC_ADD(bytes_tx_total, (size_t) total_len);
    if (r->connection && r->connection->sockaddr
        && r->connection->sockaddr->sa_family == AF_INET6)
    {
        BRIX_WEBDAV_METRIC_ADD(bytes_tx_ipv6_total, (size_t) total_len);
    } else {
        BRIX_WEBDAV_METRIC_ADD(bytes_tx_ipv4_total, (size_t) total_len);
    }
}

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
    char             href[WEBDAV_MAX_PATH + 2];
    struct stat      sb;
    ngx_int_t        rc;
    int              depth;
    ngx_chain_t     *head = NULL;
    ngx_chain_t     *tail = NULL;
    off_t            total_len;
    ngx_uint_t       entry_count = 0;
    propfind_req_t   req;

    rc = webdav_resolve_stat(r, path, sizeof(path), &sb);
    if (rc != NGX_OK) {
        return rc;
    }

    propfind_parse_request(r, &req);

    depth = propfind_parse_depth(r);
    propfind_count_depth(depth);

    {
        propfind_resp_t rb = {
            .r = r, .head = &head, .tail = &tail,
            .entry_count = &entry_count,
            .href = href, .href_sz = sizeof(href)
        };
        rc = propfind_build_body(&rb, path, &sb, &req, depth);
    }
    if (rc != NGX_OK) {
        return rc;
    }

    total_len = propfind_finalize_chain(head, tail);
    BRIX_WEBDAV_METRIC_ADD(propfind_entries_total, entry_count);

    if (propfind_send_headers(r, total_len, &rc) != NGX_OK) {
        return rc;   /* header list allocation failed → 500 */
    }
    if (rc == NGX_ERROR || r->header_only) {
        return rc;
    }

    propfind_count_tx(r, total_len);
    return ngx_http_output_filter(r, head);
}
