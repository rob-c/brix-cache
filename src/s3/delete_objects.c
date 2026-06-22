/*
 * delete_objects.c — S3 DeleteObjects handler (POST /bucket/?delete).
 *
 * Parses a list of <Object><Key>…</Key></Object> entries from the request
 * body, deletes each key, and returns a <DeleteResult> XML response with
 * <Deleted> or <Error> entries for each object.
 *
 * The body XML parser uses libxml2 with network access disabled, so XML
 * entities in <Key> values are decoded correctly before filesystem resolution.
 * Non-regular objects (directories) that fail with EISDIR/EPERM are retried
 * as rmdir.  ENOENT is treated as success per S3 idempotency rules.
 */
/* WHY: S3 DeleteObjects supports batch deletion in a single POST request —
 * far more efficient than individual DELETE calls for pipelines that need to
 * remove hundreds or thousands of objects. Non-regular-object fallback
 * (unlink → rmdir) handles directories transparently; ENOENT is treated as
 * success per S3 idempotency semantics. */

#include "s3.h"
#include "../compat/http_body.h"
#include "../impersonate/lifecycle.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

#define S3_DEL_MAX_KEYS  1000
#define S3_DEL_MAX_BODY  (1024 * 1024)   /* 1 MiB cap on XML body */
#define S3_DEL_XML_MAX   (2 * 1024 * 1024) /* max output XML */
/* WHY: S3 DeleteObjects supports batch deletion — a single POST request can remove
 * up to 1000 keys. The body XML cap (1 MiB) prevents oversized payloads; the output
 * buffer is sized to hold escaped per-key <Deleted>/<Error> entries for the
 * capped request body without reallocating. */


static ngx_int_t
s3_delete_xml_append_raw(ngx_buf_t *xml_buf, size_t *xml_len, const char *text)
{
    size_t len;
    size_t cap;

    len = strlen(text);
    cap = (size_t) (xml_buf->end - xml_buf->start);
    if (*xml_len > cap || len > cap - *xml_len) {
        return NGX_ERROR;
    }

    ngx_memcpy(xml_buf->start + *xml_len, text, len);
    *xml_len += len;
    return NGX_OK;
}

static ngx_int_t
s3_delete_xml_append_elem(ngx_buf_t *xml_buf, size_t *xml_len,
    const char *name, const u_char *value, size_t value_len)
{
    size_t room;
    size_t written;

    if (*xml_len > (size_t) (xml_buf->end - xml_buf->start)) {
        return NGX_ERROR;
    }

    room = (size_t) (xml_buf->end - xml_buf->start) - *xml_len;
    if (xrootd_xml_write_text_element(name, value, value_len,
            XROOTD_XML_ESCAPE_APOS_ENTITY | XROOTD_XML_ESCAPE_CONTROL_PERCENT,
            xml_buf->start + *xml_len, room, &written) != 0)
    {
        return NGX_ERROR;
    }

    *xml_len += written;
    return NGX_OK;
}

static ngx_int_t
s3_delete_xml_append_deleted(ngx_buf_t *xml_buf, size_t *xml_len,
    const u_char *key, size_t key_len)
{
    return s3_delete_xml_append_raw(xml_buf, xml_len, "<Deleted>") == NGX_OK
           && s3_delete_xml_append_elem(xml_buf, xml_len, "Key", key, key_len)
              == NGX_OK
           && s3_delete_xml_append_raw(xml_buf, xml_len, "</Deleted>")
              == NGX_OK
           ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
s3_delete_xml_append_error(ngx_buf_t *xml_buf, size_t *xml_len,
    const u_char *key, size_t key_len, const char *code, const char *message)
{
    return s3_delete_xml_append_raw(xml_buf, xml_len, "<Error>") == NGX_OK
           && s3_delete_xml_append_elem(xml_buf, xml_len, "Key", key, key_len)
              == NGX_OK
           && s3_delete_xml_append_elem(xml_buf, xml_len, "Code",
                                        (const u_char *) code, strlen(code))
              == NGX_OK
           && s3_delete_xml_append_elem(xml_buf, xml_len, "Message",
                                        (const u_char *) message,
                                        strlen(message)) == NGX_OK
           && s3_delete_xml_append_raw(xml_buf, xml_len, "</Error>")
              == NGX_OK
           ? NGX_OK : NGX_ERROR;
}

static ngx_flag_t
s3_delete_xml_name_is(xmlNodePtr node, const char *name)
{
    return node != NULL
           && node->type == XML_ELEMENT_NODE
           && xmlStrcmp(node->name, BAD_CAST name) == 0;
}

static xmlNodePtr
s3_delete_xml_find_child(xmlNodePtr node, const char *name)
{
    xmlNodePtr cur;

    for (cur = node == NULL ? NULL : node->children; cur != NULL;
         cur = cur->next)
    {
        if (s3_delete_xml_name_is(cur, name)) {
            return cur;
        }
    }

    return NULL;
}

/*
 * s3_delete_objects_finish — write the buffered DeleteResult XML and finalise
 * the response.
 */
/* WHAT: Append the closing </DeleteResult> tag to the buffered XML, create a final
 * memory-backed buf_t from it, and send the response as application/xml with HTTP 200.
 *
 * WHY: The XML buffer was pre-allocated during parsing (xml_buf->start/end). We append
 *   the closing tag in-place if there is room, then wrap the completed XML into a
 *   ngx_create_temp_buf() for the nginx output filter. Metrics are finalised via
 *   s3_metrics_finalize_request_method().
 *
 * HOW: memcpy trailer → create temp buf → ngx_memcpy copy → last_buf=1 → send header
 *   + output filter. On allocation failure, metrics finalise with 500 and return.
 */

static void
s3_delete_objects_finish(ngx_http_request_t *r,
                         ngx_uint_t method_slot,
                         ngx_buf_t *xml_buf,
                         size_t xml_len)
{
    ngx_buf_t  *b;
    const char  trailer[] = "</DeleteResult>";

    if (s3_delete_xml_append_raw(xml_buf, &xml_len, trailer) != NGX_OK) {
        s3_metrics_finalize_request_method(r, method_slot,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    b = ngx_create_temp_buf(r->pool, xml_len);
    if (b == NULL) {
        s3_metrics_finalize_request_method(r, method_slot,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    ngx_memcpy(b->pos, xml_buf->start, xml_len);
    b->last     = b->pos + xml_len;
    b->last_buf = 1;

    s3_metrics_finalize_request_method(r, method_slot,
        xrootd_http_send_xml_buffer(r, NGX_HTTP_OK,
            (ngx_str_t) ngx_string("application/xml"), b));
}

/*
 * s3_delete_objects_body — body callback invoked by nginx after the POST body
 * has been fully buffered.
 */
/* WHAT: Parse the POST body XML to extract <Object><Key>…</Key></Object> entries,
 * delete each key from the filesystem, and build a DeleteResult XML response with
 * <Deleted> or <Error> entries per object.
 *
 * WHY: S3 clients send DeleteObjects as a single POST with an XML body listing all
 *   keys to remove. libxml2 is used because real clients may XML-escape key
 *   names; string scanning would delete the wrong key and emit malformed XML.
 *
 *   Per S3 semantics:
 *     - ENOENT → success (idempotent: deleting something that doesn't exist is fine)
 *     - EISDIR/EPERM on unlink → retry with rmdir flag for directories
 *     - AccessDenied → path escaped outside root_canon via s3_resolve_key()
 *
 * HOW:
 *   1. Read body via xrootd_http_body_read_all() (cap: S3_DEL_MAX_BODY)
 *   2. Allocate XML output buffer (S3_DEL_XML_MAX)
 *   3. Write XML header
 *   4. Parse <Delete><Object><Key> entries with libxml2, resolve fs_path
 *   5. Attempt unlink → fallback rmdir on EISDIR/EPERM
 *   6. Emit <Deleted> (success/ENOENT) or <Error> (AccessDenied/BucketNotEmpty/InternalError)
 *   7. Finalise response via s3_delete_objects_finish()
 *
 * Constraints:
 *   - Max keys: S3_DEL_MAX_KEYS (1000) — rejects XML that exceeds the limit
 *   - Body cap: S3_DEL_MAX_BODY (1 MiB) — rejects oversized XML as MalformedXML
 *   - Key length: < S3_MAX_KEY — reports InvalidArgument per offending object
 */

static void s3_delete_objects_body_handler_inner(ngx_http_request_t *r);

/*
 * Phase 40: the DeleteObjects body is read asynchronously, so the dispatch
 * wrapper already cleared the impersonation principal.  Re-establish it (mirrors
 * s3_put_body_handler) so each unlink/rmdir runs under the mapped user's DAC via
 * the broker rather than the unprivileged worker.  No-op unless map mode.
 */
void
s3_delete_objects_body_handler(ngx_http_request_t *r)
{
    ngx_http_s3_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);

    xrootd_imp_request_begin(rx != NULL ? rx->identity : NULL);
    s3_delete_objects_body_handler_inner(r);
    xrootd_imp_request_end();
}

static void
s3_delete_objects_body_handler_inner(ngx_http_request_t *r)
{
    ngx_http_s3_loc_conf_t  *cf;
    ngx_uint_t               method_slot;
    u_char                  *body_buf;
    size_t                   body_len;
    u_char                  *xml_out;
    size_t                   xml_len;
    ngx_buf_t                xml_buf_obj;
    ngx_buf_t               *xml_buf = &xml_buf_obj;
    xmlDocPtr                doc;
    xmlNodePtr               root;
    xmlNodePtr               obj;
    ngx_int_t                rc;

    cf          = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_s3_module);
    method_slot = s3_metrics_method_slot(r);

    if (r->request_body == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        s3_metrics_finalize_request_method(r, method_slot,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    rc = xrootd_http_body_read_all(r, S3_DEL_MAX_BODY, &body_buf, &body_len);
    if (rc == NGX_DECLINED) {
        s3_metrics_finalize_request_method(r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                              "MalformedXML",
                              "Request body too large."));
        return;
    }
    if (rc != NGX_OK) {
        s3_metrics_finalize_request_method(r, method_slot,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    {
        /* Match the hardened libxml2 posture used by the WebDAV parsers
         * (propfind/proppatch/search/lockinfo): NONET blocks network entity
         * fetches; NO_XXE (libxml2 >= 2.13, when available) refuses external
         * entity loading outright.  NOENT/DTDLOAD are deliberately NOT set, so
         * external entities are never substituted (no file:// XXE), and HUGE is
         * omitted so libxml2 keeps its billion-laughs amplification cap. */
        int opts = XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
#if defined(XML_PARSE_NO_XXE)
        opts |= XML_PARSE_NO_XXE;
#endif
        doc = xmlReadMemory((const char *) body_buf, (int) body_len,
                            "delete_objects.xml", NULL, opts);
    }
    if (doc == NULL) {
        s3_metrics_finalize_request_method(r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                              "MalformedXML",
                              "Request body is not valid DeleteObjects XML."));
        return;
    }

    root = xmlDocGetRootElement(doc);
    if (!s3_delete_xml_name_is(root, "Delete")) {
        xmlFreeDoc(doc);
        s3_metrics_finalize_request_method(r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                              "MalformedXML",
                              "DeleteObjects root element must be Delete."));
        return;
    }

    /* Allocate XML output buffer */
    xml_out = ngx_palloc(r->pool, S3_DEL_XML_MAX);
    if (xml_out == NULL) {
        xmlFreeDoc(doc);
        s3_metrics_finalize_request_method(r, method_slot,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    xml_buf->start = xml_out;
    xml_buf->end   = xml_out + S3_DEL_XML_MAX;

    {
        const char header[] =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<DeleteResult "
            "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">";
        xml_len = sizeof(header) - 1;
        memcpy(xml_out, header, xml_len);
    }

    {
        ngx_uint_t nkeys = 0;

        for (obj = root->children; obj != NULL; obj = obj->next) {
            xmlNodePtr key_node;
            xmlChar   *key_text;
            size_t     key_len;
            char       key_str[S3_MAX_KEY];
            char       fs_path[PATH_MAX];

            if (!s3_delete_xml_name_is(obj, "Object")) {
                continue;
            }

            if (nkeys >= S3_DEL_MAX_KEYS) {
                xmlFreeDoc(doc);
                s3_metrics_finalize_request_method(r, method_slot,
                    s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                      "MalformedXML",
                                      "DeleteObjects request contains too "
                                      "many keys."));
                return;
            }
            nkeys++;

            key_node = s3_delete_xml_find_child(obj, "Key");
            if (key_node == NULL) {
                xmlFreeDoc(doc);
                s3_metrics_finalize_request_method(r, method_slot,
                    s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                      "MalformedXML",
                                      "DeleteObjects object is missing Key."));
                return;
            }

            key_text = xmlNodeGetContent(key_node);
            if (key_text == NULL) {
                xmlFreeDoc(doc);
                s3_metrics_finalize_request_method(r, method_slot,
                                                   NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
            key_len = (size_t) xmlStrlen(key_text);

            if (key_len == 0 || key_len >= S3_MAX_KEY) {
                if (s3_delete_xml_append_error(
                        xml_buf, &xml_len, (const u_char *) key_text, key_len,
                        "InvalidArgument", "Object key is empty or too long.")
                    != NGX_OK)
                {
                    xmlFree(key_text);
                    xmlFreeDoc(doc);
                    s3_metrics_finalize_request_method(
                        r, method_slot, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }
                xmlFree(key_text);
                continue;
            }

            ngx_memcpy(key_str, key_text, key_len);
            key_str[key_len] = '\0';

            if (!s3_resolve_key(cf->common.root_canon, key_str, fs_path,
                                sizeof(fs_path)))
            {
                if (s3_delete_xml_append_error(
                        xml_buf, &xml_len, (const u_char *) key_text, key_len,
                        "AccessDenied", "Access Denied.") != NGX_OK)
                {
                    xmlFree(key_text);
                    xmlFreeDoc(doc);
                    s3_metrics_finalize_request_method(
                        r, method_slot, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }
                xmlFree(key_text);
                continue;
            }

            {
                xrootd_ns_delete_opts_t d_opts;
                xrootd_ns_result_t      d_res;

                ngx_memzero(&d_opts, sizeof(d_opts));
                d_opts.idempotent_missing = 1;
                d_res = xrootd_ns_delete(r->connection->log,
                                         cf->common.root_canon,
                                         fs_path, &d_opts);
                if (d_res.status == XROOTD_NS_OK) {
                    if (s3_delete_xml_append_deleted(
                            xml_buf, &xml_len,
                            (const u_char *) key_text, key_len) != NGX_OK)
                    {
                        xmlFree(key_text);
                        xmlFreeDoc(doc);
                        s3_metrics_finalize_request_method(
                            r, method_slot, NGX_HTTP_INTERNAL_SERVER_ERROR);
                        return;
                    }
                } else {
                    const char *code;
                    const char *msg;
                    if (d_res.status == XROOTD_NS_DENIED) {
                        code = "AccessDenied";
                        msg  = "Access Denied.";
                    } else if (d_res.status == XROOTD_NS_NOT_EMPTY) {
                        code = "BucketNotEmpty";
                        msg  = "The directory is not empty.";
                    } else {
                        code = "InternalError";
                        msg  = "Internal server error.";
                    }
                    if (s3_delete_xml_append_error(
                            xml_buf, &xml_len,
                            (const u_char *) key_text, key_len,
                            code, msg) != NGX_OK)
                    {
                        xmlFree(key_text);
                        xmlFreeDoc(doc);
                        s3_metrics_finalize_request_method(
                            r, method_slot, NGX_HTTP_INTERNAL_SERVER_ERROR);
                        return;
                    }
                }
            }

            xmlFree(key_text);
        }

        if (nkeys == 0) {
            xmlFreeDoc(doc);
            s3_metrics_finalize_request_method(r, method_slot,
                s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                  "MalformedXML",
                                  "DeleteObjects request has no Object entries."));
            return;
        }
    }

    xmlFreeDoc(doc);
    s3_delete_objects_finish(r, method_slot, xml_buf, xml_len);
}
