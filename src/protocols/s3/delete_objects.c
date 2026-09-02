/*
 * delete_objects.c — S3 DeleteObjects handler (POST /bucket/?delete).
 *
 * Parses a list of <Object><Key>…</Key></Object> entries from the request
 * body, deletes them, and returns a <DeleteResult> XML response with
 * <Deleted> or <Error> entries for each object.
 *
 * The body XML parser uses libxml2 with network access disabled, so XML
 * entities in <Key> values are decoded correctly before filesystem resolution.
 * ENOENT is treated as success per S3 idempotency rules.
 */
/* WHY: S3 DeleteObjects supports batch deletion in a single POST request —
 * far more efficient than individual DELETE calls for pipelines that need to
 * remove hundreds or thousands of objects. Phase-107 C4 makes the server side
 * match: every key is collected and CONFINED first, then disposed by ONE
 * brix_vfs_delete_many() call (one write gate, one OP_DELETE observation, and
 * over a remote backend one signed DeleteObjects round trip per 1,000-key
 * window instead of 1,000). The per-object stages live in
 * delete_objects_batch.c; the XML rendering in delete_objects_xml.c. */

#include "s3.h"
#include "core/http/http_body.h"
#include "core/http/http_headers.h"   /* brix_http_request_is_tls */
#include "auth/impersonate/lifecycle.h"
#include "fs/vfs/vfs.h"   /* per-object delete via the VFS unlink surface */

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

#include "delete_objects_internal.h"   /* s3_del_err_t + DeleteResult XML seam */

#define S3_DEL_MAX_KEYS  1000
#define S3_DEL_MAX_BODY  (1024 * 1024)   /* 1 MiB cap on XML body */
#define S3_DEL_XML_MAX   (2 * 1024 * 1024) /* max output XML */
/* WHY: S3 DeleteObjects supports batch deletion — a single POST request can remove
 * up to 1000 keys. The body XML cap (1 MiB) prevents oversized payloads; the output
 * buffer is sized to hold escaped per-key <Deleted>/<Error> entries for the
 * capped request body without reallocating. */

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
        brix_http_send_xml_buffer(r, NGX_HTTP_OK,
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
 *   1. Read body via brix_http_body_read_all() (cap: S3_DEL_MAX_BODY)
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
 * s3_delete_parse_body — read the buffered POST body and parse it into a
 * validated <Delete> document.
 *
 * WHAT: Reads the body (cap S3_DEL_MAX_BODY), parses it with the hardened
 *   libxml2 posture, and confirms the root element is <Delete>; on success
 *   *doc_out owns the parsed document (caller must xmlFreeDoc it).
 * WHY: Body read and XML validation are one cohesive precondition stage; the
 *   client-facing MalformedXML / body-too-large errors and the 500 paths are
 *   all resolved here so the batch loop only runs on a good document.
 * HOW: Returns NGX_OK with a document, or NGX_DONE after finalising the
 *   response with the appropriate error (nothing left for the caller to do).
 */
static ngx_int_t
s3_delete_parse_body(ngx_http_request_t *r, ngx_uint_t method_slot,
    xmlDocPtr *doc_out)
{
    u_char     *body_buf;
    size_t      body_len;
    xmlDocPtr   doc;
    xmlNodePtr  root;
    ngx_int_t   rc;

    *doc_out = NULL;

    if (r->request_body == NULL) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        s3_metrics_finalize_request_method(r, method_slot,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;
    }

    rc = brix_http_body_read_all(r, S3_DEL_MAX_BODY, &body_buf, &body_len);
    if (rc == NGX_DECLINED) {
        s3_metrics_finalize_request_method(r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                              "MalformedXML",
                              "Request body too large."));
        return NGX_DONE;
    }
    if (rc != NGX_OK) {
        s3_metrics_finalize_request_method(r, method_slot,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;
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
        return NGX_DONE;
    }

    root = xmlDocGetRootElement(doc);
    if (!s3_delete_xml_name_is(root, "Delete")) {
        xmlFreeDoc(doc);
        s3_metrics_finalize_request_method(r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                              "MalformedXML",
                              "DeleteObjects root element must be Delete."));
        return NGX_DONE;
    }

    *doc_out = doc;
    return NGX_OK;
}

/*
 * s3_delete_result_init — allocate the output XML buffer and write the
 * <DeleteResult> preamble.
 *
 * WHAT: Allocates S3_DEL_XML_MAX from the request pool, points xml_buf at it,
 *   and seeds *xml_len with the length of the XML header prefix.
 * WHY: The batch loop appends per-key elements into a fixed, pre-sized buffer
 *   (no reallocation mid-stream); this stage establishes that buffer once.
 * HOW: Returns NGX_OK on success or NGX_ERROR on allocation failure (the
 *   caller maps that to a 500).
 */
static ngx_int_t
s3_delete_result_init(ngx_http_request_t *r, ngx_buf_t *xml_buf,
    size_t *xml_len)
{
    static const char header[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<DeleteResult "
        "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">";
    u_char *xml_out;

    xml_out = ngx_palloc(r->pool, S3_DEL_XML_MAX);
    if (xml_out == NULL) {
        return NGX_ERROR;
    }

    xml_buf->start = xml_out;
    xml_buf->end   = xml_out + S3_DEL_XML_MAX;

    *xml_len = sizeof(header) - 1;
    memcpy(xml_out, header, *xml_len);
    return NGX_OK;
}

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
        ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);

    brix_imp_request_begin(rx != NULL ? rx->identity : NULL);
    s3_delete_objects_body_handler_inner(r);
    brix_imp_request_end();
}

/*
 * s3_delete_run_batch — collect the <Object> children of <Delete>, dispose
 * them through ONE VFS batch call, and render a per-key result for each.
 *
 * WHAT: Enforces the S3_DEL_MAX_KEYS cap, requires at least one <Object>,
 *   collects every key via s3_delete_collect_one() (validate + confine — no
 *   deletes yet), then s3_delete_execute() (one brix_vfs_delete_many) and
 *   s3_delete_render() (client-ordered <Deleted>/<Error> elements).
 * WHY: Collect-before-execute means a malformed <Object> anywhere in the body
 *   now rejects the request BEFORE anything is deleted (the old
 *   parse-and-delete loop had already removed the keys ahead of it), and the
 *   batch runs under exactly one write gate and one metric observation
 *   (phase-107 C4).
 * HOW: Returns NGX_OK once every result element is appended (caller sends the
 *   buffered response). On any error it finalises the response here and
 *   returns NGX_DONE — the malformed sub-cases pick the exact message.
 */
static ngx_int_t
s3_delete_run_batch(s3_del_ctx_t *dc, ngx_uint_t method_slot, xmlNodePtr root)
{
    ngx_http_request_t *r = dc->r;
    s3_del_item_t      *items;
    xmlNodePtr           obj;
    ngx_uint_t           nkeys = 0;

    items = ngx_palloc(r->pool, S3_DEL_MAX_KEYS * sizeof(s3_del_item_t));
    if (items == NULL) {
        s3_metrics_finalize_request_method(r, method_slot,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;
    }

    for (obj = root->children; obj != NULL; obj = obj->next) {
        int malformed_500 = 0;

        if (!s3_delete_xml_name_is(obj, "Object")) {
            continue;
        }

        if (nkeys >= S3_DEL_MAX_KEYS) {
            s3_metrics_finalize_request_method(r, method_slot,
                s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                  "MalformedXML",
                                  "DeleteObjects request contains too "
                                  "many keys."));
            return NGX_DONE;
        }

        if (s3_delete_collect_one(dc, obj, &items[nkeys], &malformed_500)
            != NGX_OK)
        {
            if (malformed_500) {
                s3_metrics_finalize_request_method(r, method_slot,
                                                   NGX_HTTP_INTERNAL_SERVER_ERROR);
            } else {
                s3_metrics_finalize_request_method(r, method_slot,
                    s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                      "MalformedXML",
                                      "DeleteObjects object is missing Key."));
            }
            return NGX_DONE;
        }
        nkeys++;
    }

    if (nkeys == 0) {
        s3_metrics_finalize_request_method(r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                              "MalformedXML",
                              "DeleteObjects request has no Object entries."));
        return NGX_DONE;
    }

    if (s3_delete_execute(dc, items, nkeys) != NGX_OK) {
        return NGX_DONE;   /* response finalised (EROFS 403 or alloc 500) */
    }

    if (s3_delete_render(dc, items, nkeys) != NGX_OK) {
        s3_metrics_finalize_request_method(r, method_slot,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;   /* output buffer overflow */
    }

    return NGX_OK;
}

static void
s3_delete_objects_body_handler_inner(ngx_http_request_t *r)
{
    ngx_http_s3_loc_conf_t  *cf;
    ngx_uint_t               method_slot;
    size_t                   xml_len;
    ngx_buf_t                xml_buf_obj;
    ngx_buf_t               *xml_buf = &xml_buf_obj;
    xmlDocPtr                doc;
    s3_del_ctx_t             dc;

    cf          = ngx_http_get_module_loc_conf(r, ngx_http_brix_s3_module);
    method_slot = s3_metrics_method_slot(r);

    if (s3_delete_parse_body(r, method_slot, &doc) != NGX_OK) {
        return;   /* response already finalised */
    }

    if (s3_delete_result_init(r, xml_buf, &xml_len) != NGX_OK) {
        xmlFreeDoc(doc);
        s3_metrics_finalize_request_method(r, method_slot,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    dc.r           = r;
    dc.cf          = cf;
    dc.method_slot = method_slot;
    dc.xml_buf     = xml_buf;
    dc.xml_len     = &xml_len;

    if (s3_delete_run_batch(&dc, method_slot, xmlDocGetRootElement(doc))
        != NGX_OK)
    {
        xmlFreeDoc(doc);
        return;   /* response already finalised */
    }

    xmlFreeDoc(doc);
    s3_delete_objects_finish(r, method_slot, xml_buf, xml_len);
}
