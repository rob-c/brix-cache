/*
 * lock.c - WebDAV LOCK and UNLOCK handler (RFC 4918 §9.10, §9.11).
 */

#include "webdav.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* RFC 4918 §11.1: 423 Locked */
#ifndef NGX_HTTP_LOCKED
#define NGX_HTTP_LOCKED 423
#endif

static ngx_shmtx_t  webdav_lock_mutex;

static void
webdav_generate_uuid(char *buf)
{
    u_char bytes[16];
    (void) RAND_bytes(bytes, 16);
    /* Version 4 UUID: bits 12-15 are 0100 */
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    /* Variant: bits 64-65 are 10 */
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    sprintf(buf, "opaquelocktoken:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5],
            bytes[6], bytes[7],
            bytes[8], bytes[9],
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
}

ngx_int_t
webdav_lock_init_shm(ngx_shm_zone_t *shm_zone, void *data)
{
    webdav_lock_table_t *tbl;

    if (data) {
        shm_zone->data = data;
        tbl = (webdav_lock_table_t *) data;
        if (ngx_shmtx_create(&webdav_lock_mutex, &tbl->lock,
                             shm_zone->shm.name.data) != NGX_OK)
        {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    tbl = (webdav_lock_table_t *) shm_zone->shm.addr;
    ngx_memzero(tbl, sizeof(*tbl));

    if (ngx_shmtx_create(&webdav_lock_mutex, &tbl->lock,
                         shm_zone->shm.name.data) != NGX_OK)
    {
        return NGX_ERROR;
    }

    shm_zone->data = tbl;
    return NGX_OK;
}

static ngx_msec_t
webdav_parse_timeout(ngx_http_request_t *r,
                     ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    ngx_table_elt_t *h;
    u_char          *p, *end;
    ngx_uint_t       timeout = 3600; /* default 1 hour if not bounded */

    h = webdav_tpc_find_header(r, "Timeout", sizeof("Timeout") - 1);
    if (h == NULL) {
        timeout = 3600;
    } else {
        p = h->value.data;
        end = p + h->value.len;

        if (ngx_strncasecmp(p, (u_char *) "Second-", 7) == 0) {
            p += 7;
            timeout = ngx_atoi(p, end - p);
            if (timeout == (ngx_uint_t) NGX_ERROR) {
                timeout = 3600;
            }
        } else if (ngx_strncasecmp(p, (u_char *) "Infinite", 8) == 0) {
            timeout = conf->lock_timeout;
        }
    }

    /* Bound timeout to reasonable range [1, conf->lock_timeout] */
    if (timeout < 1) timeout = 1;
    if (timeout > conf->lock_timeout) timeout = conf->lock_timeout;

    return ngx_current_msec + timeout * 1000;
}

static int
webdav_check_if_header(ngx_http_request_t *r, const char *token)
{
    ngx_table_elt_t *h;

    h = webdav_tpc_find_header(r, "If", sizeof("If") - 1);
    if (h == NULL) {
        /* Also check Lock-Token header which some clients use incorrectly for refreshes */
        h = webdav_tpc_find_header(r, "Lock-Token", sizeof("Lock-Token") - 1);
        if (h == NULL) return 0;
    }

    if (ngx_strstr(h->value.data, (u_char *) token) != NULL) {
        return 1;
    }

    return 0;
}

ngx_int_t
webdav_check_locks(ngx_http_request_t *r, const char *path, int need_write)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    webdav_lock_table_t              *tbl;
    ngx_uint_t                         i;
    size_t                             path_len;
    ngx_int_t                          rc = NGX_OK;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    if (conf->lock_shm_zone == NULL) {
        return NGX_OK;
    }

    tbl = conf->lock_shm_zone->data;
    path_len = strlen(path);

    ngx_shmtx_lock(&webdav_lock_mutex);

    for (i = 0; i < WEBDAV_LOCK_TABLE_SIZE; i++) {
        webdav_lock_entry_t *e = &tbl->slots[i];

        if (!e->in_use) {
            continue;
        }

        if (e->expires <= ngx_current_msec) {
            e->in_use = 0;
            continue;
        }

        size_t lock_len = strlen(e->path);

        /* Case 1: The resource we are checking is under a locked path.
         * Match exact path or parent path (for deep locks). */
        if (path_len >= lock_len && ngx_strncmp(path, e->path, lock_len) == 0) {
            if (lock_len == path_len) {
                if (!webdav_check_if_header(r, e->token)) {
                    rc = NGX_HTTP_LOCKED;
                    break;
                }
            } else if (e->depth_infinity && (e->path[lock_len - 1] == '/'
                       || path[lock_len] == '/'))
            {
                if (!webdav_check_if_header(r, e->token)) {
                    rc = NGX_HTTP_LOCKED;
                    break;
                }
            }
        }

        /* Case 2: The resource we are checking is a directory that contains 
         * a locked path (recursive check).  This is required for DELETE, 
         * MOVE, and COPY (when overwriting). */
        if (lock_len > path_len && ngx_strncmp(e->path, path, path_len) == 0) {
            if (path[path_len - 1] == '/' || e->path[path_len] == '/') {
                if (!webdav_check_if_header(r, e->token)) {
                    rc = NGX_HTTP_LOCKED;
                    break;
                }
            }
        }
    }

    ngx_shmtx_unlock(&webdav_lock_mutex);

    return rc;
}

static void
webdav_lock_xml_response(ngx_http_request_t *r, webdav_lock_entry_t *e)
{
    ngx_chain_t *head = NULL, *tail = NULL;
    char         timeout_buf[32];
    ngx_msec_t   now = ngx_current_msec;
    ngx_uint_t   remaining;
    off_t        total_len = 0;
    ngx_chain_t *lc;
    ngx_table_elt_t *h;

    remaining = (e->expires > now) ? (ngx_uint_t) ((e->expires - now) / 1000) : 0;
    ngx_sprintf((u_char *) timeout_buf, "Second-%ui", remaining);

    webdav_propfind_append(r->pool, &head, &tail,
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
        "<D:prop xmlns:D=\"DAV:\">"
        "<D:lockdiscovery>"
        "<D:activelock>"
        "<D:locktype><D:write/></D:locktype>"
        "<D:lockscope>%s</D:lockscope>"
        "<D:depth>%s</D:depth>"
        "<D:owner>%s</D:owner>"
        "<D:timeout>%s</D:timeout>"
        "<D:locktoken><D:href>opaquelocktoken:%s</D:href></D:locktoken>"
        "</D:activelock>"
        "</D:lockdiscovery>"
        "</D:prop>",
        e->exclusive ? "<D:exclusive/>" : "<D:shared/>",
        e->depth_infinity ? "infinity" : "0",
        e->owner, timeout_buf, e->token);

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

void
webdav_handle_lock(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    webdav_lock_table_t              *tbl;
    char                               path[WEBDAV_MAX_PATH];
    ngx_int_t                          rc;
    ngx_uint_t                         i, free_slot = WEBDAV_LOCK_TABLE_SIZE;
    webdav_lock_entry_t               *e = NULL;
    ngx_http_xrootd_webdav_req_ctx_t *ctx;
    ngx_table_elt_t                   *depth_hdr;
    int                                depth_infinity = 1;
    char                               owner[WEBDAV_LOCK_OWNER_LEN];
    char                              *body_data = NULL;
    int                                exclusive = 1;  /* default to exclusive per RFC 4918 §9.10 */

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    if (conf->lock_shm_zone == NULL) {
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    tbl = conf->lock_shm_zone->data;

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->root_canon,
                                              path, sizeof(path));
    if (rc != NGX_OK) {
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    /* Parse Depth header (RFC 4918 §9.10.2) */
    depth_hdr = webdav_tpc_find_header(r, "Depth", sizeof("Depth") - 1);
    if (depth_hdr != NULL) {
        if (depth_hdr->value.len == 1 && depth_hdr->value.data[0] == '0') {
            depth_infinity = 0;
        } else if (ngx_strncasecmp(depth_hdr->value.data, (u_char *) "infinity", 8) != 0) {
            webdav_metrics_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return;
        }
    }
    
    /* Extract owner from request body if present */
    owner[0] = '\0';
    if (r->request_body != NULL && r->request_body->bufs != NULL) {
        ngx_chain_t *cl = r->request_body->bufs;
        if (cl->buf != NULL) {
            body_data = (char *) cl->buf->pos;
            size_t blen = cl->buf->last - cl->buf->pos;

            /* Simple XML extraction for <D:owner>...<D:href>...</D:href>...</D:owner> 
             * or just <D:owner>text</D:owner>. */
            char *o_start = webdav_strnstr(body_data, "<D:owner>", blen);
            if (o_start == NULL) o_start = webdav_strnstr(body_data, "<owner>", blen);
            
            if (o_start != NULL) {
                size_t o_rem = blen - (o_start - body_data);
                char *o_end = webdav_strnstr(o_start, "</D:owner>", o_rem);
                if (o_end == NULL) o_end = webdav_strnstr(o_start, "</owner>", o_rem);

                if (o_end != NULL) {
                    size_t in_o_len = o_end - o_start;
                    char *h_start = webdav_strnstr(o_start, "<D:href>", in_o_len);
                    if (h_start == NULL) h_start = webdav_strnstr(o_start, "<href>", in_o_len);

                    if (h_start != NULL && h_start < o_end) {
                        size_t in_h_len = o_end - h_start;
                        char *h_end = webdav_strnstr(h_start, "</D:href>", in_h_len);
                        if (h_end == NULL) h_end = webdav_strnstr(h_start, "</href>", in_h_len);

                        if (h_end != NULL && h_end < o_end) {
                            h_start = (char *) ngx_strlchr((u_char *) h_start, (u_char *) h_end, '>') + 1;
                            size_t len = h_end - h_start;
                            if (len >= sizeof(owner)) len = sizeof(owner) - 1;
                            ngx_memcpy(owner, h_start, len);
                            owner[len] = '\0';
                        }
                    } else {
                        o_start = (char *) ngx_strlchr((u_char *) o_start, (u_char *) o_end, '>') + 1;
                        size_t len = o_end - o_start;
                        if (len >= sizeof(owner)) len = sizeof(owner) - 1;
                        ngx_memcpy(owner, o_start, len);
                        owner[len] = '\0';
                    }
                }
            }

            /* RFC 4918 §9.10: parse <D:lockscope> to determine exclusive vs shared.
             * Default is exclusive if no <D:lockscope> element is present. */
            {
                char *scope_start = webdav_strnstr(body_data, "<D:lockscope>", blen);
                if (scope_start == NULL)
                    scope_start = webdav_strnstr(body_data, "<lockscope>", blen);

                if (scope_start != NULL) {
                    size_t scope_rem = blen - (scope_start - body_data);
                    /* If <D:shared/> appears before </D:lockscope>, it is a shared lock. */
                    char *scope_end = webdav_strnstr(scope_start, "</D:lockscope>", scope_rem);
                    if (scope_end == NULL)
                        scope_end = webdav_strnstr(scope_start, "</lockscope>", scope_rem);

                    if (scope_end != NULL) {
                        size_t in_scope = scope_end - scope_start;
                        if (webdav_strnstr(scope_start, "<D:shared/>", in_scope) != NULL
                            || webdav_strnstr(scope_start, "<shared/>", in_scope) != NULL)
                        {
                            exclusive = 0;
                        }
                        /* <D:exclusive/> leaves the default exclusive = 1 unchanged. */
                    }
                }
            }
        }
    }

    /* RFC 4918 §9.10.1: LOCK on non-existent resource MUST create zero-byte resource */
    {
        struct stat sb;
        if (stat(path, &sb) != 0) {
            if (errno == ENOENT) {
                int fd = xrootd_open_confined_canon(r->connection->log,
                                                    conf->root_canon, path,
                                                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                                                    0644);
                if (fd < 0) {
                    if (errno != EEXIST) {
                        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                        return;
                    }
                } else {
                    (void) close(fd);
                }
            }
        }
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);

    ngx_shmtx_lock(&webdav_lock_mutex);

    /* Look for existing lock to refresh or conflicts */
    for (i = 0; i < WEBDAV_LOCK_TABLE_SIZE; i++) {
        if (!tbl->slots[i].in_use) {
            if (free_slot == WEBDAV_LOCK_TABLE_SIZE) free_slot = i;
            continue;
        }

        if (tbl->slots[i].expires <= ngx_current_msec) {
            tbl->slots[i].in_use = 0;
            if (free_slot == WEBDAV_LOCK_TABLE_SIZE) free_slot = i;
            continue;
        }

        if (strcmp(tbl->slots[i].path, path) == 0) {
            if (webdav_check_if_header(r, tbl->slots[i].token)) {
                e = &tbl->slots[i];
                break;
            }
            /*
             * RFC 4918 §7.5 conflict rules:
             *   - An exclusive lock request conflicts with ANY existing lock.
             *   - A shared lock request conflicts only with an exclusive lock.
             * (Multiple shared locks on the same path are permitted.)
             */
            if (exclusive || tbl->slots[i].exclusive) {
                ngx_shmtx_unlock(&webdav_lock_mutex);
                webdav_metrics_finalize_request(r, NGX_HTTP_LOCKED);
                return;
            }
        }
    }

    if (e != NULL) {
        /* Refresh existing lock */
        e->expires = webdav_parse_timeout(r, conf);
        r->headers_out.status = NGX_HTTP_OK;
    } else {
        /* Create new lock */
        if (free_slot == WEBDAV_LOCK_TABLE_SIZE) {
            ngx_shmtx_unlock(&webdav_lock_mutex);
            webdav_metrics_finalize_request(r, NGX_HTTP_INSUFFICIENT_STORAGE);
            return;
        }

        e = &tbl->slots[free_slot];
        ngx_memzero(e, sizeof(*e));
        ngx_cpystrn((u_char *) e->path, (u_char *) path, sizeof(e->path));
        webdav_generate_uuid(e->token);
        
        if (owner[0] != '\0') {
            ngx_cpystrn((u_char *) e->owner, (u_char *) owner, sizeof(e->owner));
        } else if (ctx != NULL && ctx->dn[0] != '\0') {
            ngx_cpystrn((u_char *) e->owner, (u_char *) ctx->dn, sizeof(e->owner));
        } else {
            ngx_cpystrn((u_char *) e->owner, (u_char *) "anonymous", sizeof(e->owner));
        }
        
        e->exclusive = exclusive;
        e->depth_infinity = depth_infinity;
        e->expires = webdav_parse_timeout(r, conf);
        e->in_use = 1;

        r->headers_out.status = NGX_HTTP_CREATED;
    }

    /* We need a local copy for the response after releasing the shm lock */
    webdav_lock_entry_t res = *e;

    ngx_shmtx_unlock(&webdav_lock_mutex);

    webdav_lock_xml_response(r, &res);
}

ngx_int_t
webdav_handle_unlock(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    webdav_lock_table_t              *tbl;
    char                               path[WEBDAV_MAX_PATH];
    ngx_int_t                          rc;
    ngx_uint_t                         i;
    ngx_table_elt_t                   *h;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    if (conf->lock_shm_zone == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    tbl = conf->lock_shm_zone->data;

    h = webdav_tpc_find_header(r, "Lock-Token", sizeof("Lock-Token") - 1);
    if (h == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->root_canon,
                                              path, sizeof(path));
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_shmtx_lock(&webdav_lock_mutex);

    for (i = 0; i < WEBDAV_LOCK_TABLE_SIZE; i++) {
        if (!tbl->slots[i].in_use) continue;

        if (strcmp(tbl->slots[i].path, path) == 0) {
            /* Check if token matches (handle <token> format) */
            if (ngx_strstr(h->value.data, (u_char *) tbl->slots[i].token) != NULL) {
                tbl->slots[i].in_use = 0;
                ngx_shmtx_unlock(&webdav_lock_mutex);

                r->headers_out.status = NGX_HTTP_NO_CONTENT;
                r->headers_out.content_length_n = 0;
                ngx_http_send_header(r);
                return ngx_http_send_special(r, NGX_HTTP_LAST);
            }
        }
    }

    ngx_shmtx_unlock(&webdav_lock_mutex);

    return NGX_HTTP_CONFLICT; /* Lock not found or token mismatch */
}

ngx_int_t
webdav_lock_append_supported(ngx_http_request_t *r,
                             ngx_chain_t **head, ngx_chain_t **tail)
{
    if (webdav_propfind_append(r->pool, head, tail,
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

ngx_int_t
webdav_lock_append_discovery(ngx_http_request_t *r, const char *path,
                             ngx_chain_t **head, ngx_chain_t **tail)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    webdav_lock_table_t              *tbl;
    ngx_uint_t                         i;
    ngx_msec_t                         now = ngx_current_msec;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    if (conf->lock_shm_zone == NULL) {
        return NGX_OK;
    }
    tbl = conf->lock_shm_zone->data;

    if (webdav_propfind_append(r->pool, head, tail, "<D:lockdiscovery>") == NULL) {
        return NGX_ERROR;
    }

    ngx_shmtx_lock(&webdav_lock_mutex);

    for (i = 0; i < WEBDAV_LOCK_TABLE_SIZE; i++) {
        webdav_lock_entry_t *entry = &tbl->slots[i];

        if (!entry->in_use || entry->expires <= now) continue;

        if (strcmp(entry->path, path) == 0) {
            ngx_uint_t remaining;

            remaining = (ngx_uint_t) ((entry->expires - now) / 1000);

            if (webdav_propfind_append(r->pool, head, tail,
                    "<D:activelock>"
                    "<D:locktype><D:write/></D:locktype>"
                    "<D:lockscope>%s</D:lockscope>"
                    "<D:depth>%s</D:depth>"
                    "<D:owner>%s</D:owner>"
                    "<D:timeout>Second-%ui</D:timeout>"
                    "<D:locktoken><D:href>opaquelocktoken:%s</D:href></D:locktoken>"
                    "</D:activelock>",
                    entry->exclusive ? "<D:exclusive/>" : "<D:shared/>",
                    entry->depth_infinity ? "infinity" : "0",
                    (entry->owner[0] != '\0') ? (char *) entry->owner : "anonymous",
                    remaining,
                    entry->token) == NULL)
            {
                ngx_shmtx_unlock(&webdav_lock_mutex);
                return NGX_ERROR;
            }
        }
    }

    ngx_shmtx_unlock(&webdav_lock_mutex);

    if (webdav_propfind_append(r->pool, head, tail, "</D:lockdiscovery>") == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
