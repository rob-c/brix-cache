/*
 * get_directory.c — §6.6 GET-on-a-directory: listingredir / HTML listing /
 * listingdeny.  Split from the 793-line get.c at phase-103, with the CCN-19
 * get_serve_directory decomposed into redirect / enumerate / footer helpers;
 * responses are byte-identical.
 */

#include "webdav.h"
#include "fs/vfs/vfs.h"
#include "core/compat/xml.h"               /* HTML-escape listing entries */
#include "fs/path/reserved_names.h"        /* brix_is_internal_name — hide sidecars */
#include "get_internal.h"

/* ---- §6.6 GET-on-a-directory: listingredir / HTML listing / listingdeny ----
 *
 * One escaped listing row: an <a href> plus a size and mtime column. The name
 * is HTML-escaped through the shared XML escaper (& < > " ' → entities), and a
 * subdirectory gets a trailing '/'. Appends into the request-pool chain `tail`.
 */
static ngx_int_t
get_listing_emit_row(ngx_http_request_t *r, ngx_chain_t ***tail,
    const ngx_str_t *name, const brix_vfs_stat_t *vst)
{
    u_char       esc[512 * 6 + 8];   /* worst-case XML expansion of a 512B name */
    size_t       esc_written = 0;
    ngx_buf_t   *b;
    ngx_chain_t *cl;
    u_char      *line;
    size_t       cap;
    const char  *slash = vst->is_directory ? "/" : "";

    if (brix_xml_escape(name->data, name->len, 0, esc, sizeof(esc),
                        &esc_written) != 0) {
        return NGX_OK;   /* name too long to escape safely: skip this entry */
    }

    cap = esc_written * 2 + 160;
    line = ngx_pnalloc(r->pool, cap);
    b = ngx_pcalloc(r->pool, sizeof(*b));
    cl = ngx_alloc_chain_link(r->pool);
    if (line == NULL || b == NULL || cl == NULL) {
        return NGX_ERROR;
    }

    b->pos = line;
    b->last = ngx_slprintf(line, line + cap,
        "<tr><td><a href=\"%s%s\">%s%s</a></td>"
        "<td class=\"s\">%O</td><td class=\"m\">%T</td></tr>\n",
        esc, slash, esc, slash,
        vst->is_directory ? (off_t) 0 : vst->size, (time_t) vst->mtime);
    b->memory = 1;
    cl->buf = b;
    cl->next = NULL;
    **tail = cl;
    *tail = &cl->next;
    return NGX_OK;
}

/* Escape the request URI once for the page's <h1> and its parent link. */
static ngx_int_t
get_listing_head_tail(ngx_http_request_t *r, ngx_chain_t **head,
    ngx_chain_t ***tailp)
{
    u_char       esc_uri[1024 * 6 + 8];
    size_t       esc_written = 0;
    ngx_buf_t   *b;
    ngx_chain_t *cl;
    u_char      *buf;
    size_t       cap;

    if (brix_xml_escape(r->uri.data, r->uri.len, 0, esc_uri, sizeof(esc_uri),
                        &esc_written) != 0) {
        esc_uri[0] = '/';
        esc_uri[1] = '\0';
    }

    cap = esc_written + 512;
    buf = ngx_pnalloc(r->pool, cap);
    b = ngx_pcalloc(r->pool, sizeof(*b));
    cl = ngx_alloc_chain_link(r->pool);
    if (buf == NULL || b == NULL || cl == NULL) {
        return NGX_ERROR;
    }
    b->pos = buf;
    b->last = ngx_slprintf(buf, buf + cap,
        "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">"
        "<title>Index of %s</title></head><body>\n"
        "<h1>Index of %s</h1>\n"
        "<table><tr><th>Name</th><th>Size</th><th>Modified</th></tr>\n"
        "<tr><td><a href=\"../\">../</a></td><td></td><td></td></tr>\n",
        esc_uri, esc_uri);
    b->memory = 1;
    cl->buf = b;
    cl->next = NULL;
    *head = cl;
    *tailp = &cl->next;
    return NGX_OK;
}

/* listingredir: 301 with Location: <redirect><request-uri>. */
static ngx_int_t
get_listing_redirect(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_table_elt_t *loc;
    u_char          *dst;
    size_t           cap = conf->listing_redirect.len + r->uri.len + 1;

    loc = ngx_list_push(&r->headers_out.headers);
    dst = ngx_pnalloc(r->pool, cap);
    if (loc == NULL || dst == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    loc->hash = 1;
    ngx_str_set(&loc->key, "Location");
    loc->value.data = dst;
    loc->value.len = ngx_slprintf(dst, dst + cap, "%V%V",
                                  &conf->listing_redirect, &r->uri) - dst;
    r->headers_out.location = loc;
    return NGX_HTTP_MOVED_PERMANENTLY;
}

/* Enumerate dh, appending one escaped row per visible entry (dotfiles and
 * internal sidecars hidden).  NGX_ERROR only on allocation failure. */
static ngx_int_t
get_listing_emit_entries(ngx_http_request_t *r, brix_vfs_dir_t *dh,
    ngx_chain_t ***tail)
{
    ngx_str_t        name;
    brix_vfs_stat_t  vst;

    while (brix_vfs_readdir(dh, &name, &vst) == NGX_OK) {
        if (name.len == 0 || name.data[0] == '.'
            || brix_is_internal_name((const char *) name.data)) {
            continue;                          /* dotfiles + internal sidecars */
        }
        if (get_listing_emit_row(r, tail, &name, &vst) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

/* Terminal </table></body></html> buffer, appended at *tail. */
static ngx_int_t
get_listing_footer(ngx_http_request_t *r, ngx_chain_t **tail)
{
    ngx_buf_t   *foot;
    ngx_chain_t *foot_cl;
    ngx_str_t    footer = ngx_string("</table></body></html>\n");

    foot = ngx_pcalloc(r->pool, sizeof(*foot));
    foot_cl = ngx_alloc_chain_link(r->pool);
    if (foot == NULL || foot_cl == NULL) {
        return NGX_ERROR;
    }
    foot->pos = footer.data;
    foot->last = footer.data + footer.len;
    foot->memory = 1;
    foot->last_buf = 1;
    foot_cl->buf = foot;
    foot_cl->next = NULL;
    *tail = foot_cl;
    return NGX_OK;
}

/* WHAT: Render an escaped HTML directory index for `path` and send it, or —
 *       per config — 301-redirect (listingredir) or 403 (listingdeny default).
 *       Returns the send result or a terminal HTTP status.
 * WHY:  §6.6 parity: XrdHttp serves a browsable listing on a directory GET
 *       when enabled; the two guard directives (listing_redirect first, then
 *       html_listing) mirror listingredir / listingdeny.
 * HOW:  1. listing_redirect set → 301 Location: <redirect><request-uri>.
 *       2. html_listing off → 403 (the stock default; unchanged behaviour).
 *       3. else enumerate via the same impersonation-aware VFS opendir/readdir
 *          PROPFIND uses, HTML-escaping every name and hiding dotfiles and
 *          internal sidecars, then send the memory-backed page.
 */
ngx_int_t
webdav_get_serve_directory(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path)
{
    brix_vfs_ctx_t   vctx;
    brix_vfs_dir_t  *dh;
    ngx_chain_t     *head = NULL, **tail = NULL;
    ngx_int_t        rc;

    if (conf->listing_redirect.len > 0) {
        return get_listing_redirect(r, conf);
    }

    if (!conf->html_listing) {
        return NGX_HTTP_FORBIDDEN;              /* listingdeny default */
    }

    webdav_vfs_ctx_build(r, path, &vctx);

    dh = brix_vfs_opendir(&vctx, NULL);
    if (dh == NULL) {
        return NGX_HTTP_FORBIDDEN;              /* unreadable as the mapped user */
    }

    if (get_listing_head_tail(r, &head, &tail) != NGX_OK) {
        brix_vfs_closedir(dh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (get_listing_emit_entries(r, dh, &tail) != NGX_OK) {
        brix_vfs_closedir(dh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    brix_vfs_closedir(dh, r->connection->log);

    if (get_listing_footer(r, tail) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = -1;      /* chunked / connection-close */
    ngx_str_set(&r->headers_out.content_type, "text/html; charset=utf-8");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    return ngx_http_output_filter(r, head);
}
