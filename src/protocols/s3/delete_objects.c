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
#include "core/http/http_body.h"
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

#define S3_DEL_MAX_KEYS  1000
#define S3_DEL_MAX_BODY  (1024 * 1024)   /* 1 MiB cap on XML body */
#define S3_DEL_XML_MAX   (2 * 1024 * 1024) /* max output XML */
/* WHY: S3 DeleteObjects supports batch deletion — a single POST request can remove
 * up to 1000 keys. The body XML cap (1 MiB) prevents oversized payloads; the output
 * buffer is sized to hold escaped per-key <Deleted>/<Error> entries for the
 * capped request body without reallocating. */

/*
 * s3_del_err_t — the (Code, Message) S3 error pair emitted in a per-key
 * <Error> element. Bundling the two strings keeps the XML-append helper at or
 * below the five-parameter limit and travels as one value from the delete/auth
 * stages that decide the pair to the XML stage that renders it.
 */
typedef struct {
    const char *code;
    const char *message;
} s3_del_err_t;


/*
 * s3_delete_one — remove one resolved object through the VFS unlink surface
 * (OP_DELETE metric + access-log + write gate + confinement). S3 DeleteObjects
 * is idempotent, so a missing key (ENOENT) is reported as success. On a real
 * failure returns NGX_ERROR and fills *err with the S3 error pair (errno is
 * mapped the same way the old brix_ns_delete status was: EACCES/EPERM →
 * AccessDenied, ENOTEMPTY → BucketNotEmpty, else InternalError).
 */
static ngx_int_t
s3_delete_one(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const char *fs_path, s3_del_err_t *err)
{
    ngx_http_s3_req_ctx_t *s3ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);
    brix_vfs_ctx_t       vctx;
    int                    is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log, BRIX_PROTO_S3,
        cf->common.root_canon, cf->cache_root_canon, cf->common.allow_write,
        is_tls, (s3ctx != NULL) ? s3ctx->identity : NULL, fs_path);

    if (brix_vfs_unlink(&vctx) == NGX_OK || errno == ENOENT) {
        return NGX_OK;   /* deleted, or idempotent-missing */
    }

    if (errno == EACCES || errno == EPERM) {
        err->code    = "AccessDenied";
        err->message = "Access Denied.";
    } else if (errno == ENOTEMPTY) {
        err->code    = "BucketNotEmpty";
        err->message = "The directory is not empty.";
    } else {
        err->code    = "InternalError";
        err->message = "Internal server error.";
    }
    return NGX_ERROR;
}

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
    if (brix_xml_write_text_element(name, value, value_len,
            BRIX_XML_ESCAPE_APOS_ENTITY | BRIX_XML_ESCAPE_CONTROL_PERCENT,
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

/*
 * s3_delete_xml_append_error — append one per-key <Error> element (Key/Code/
 * Message) to the buffered DeleteResult XML.
 *
 * WHY: S3 DeleteObjects reports per-key failures inline in the batch result
 *   rather than aborting the whole request; each failed key contributes an
 *   <Error> block with its escaped key plus the S3 code/message pair.
 * HOW: Emit the open tag, the escaped Key/Code/Message text elements, then the
 *   close tag — short-circuiting to NGX_ERROR if any append overflows the
 *   pre-sized buffer.
 */
static ngx_int_t
s3_delete_xml_append_error(ngx_buf_t *xml_buf, size_t *xml_len,
    const u_char *key, size_t key_len, const s3_del_err_t *err)
{
    return s3_delete_xml_append_raw(xml_buf, xml_len, "<Error>") == NGX_OK
           && s3_delete_xml_append_elem(xml_buf, xml_len, "Key", key, key_len)
              == NGX_OK
           && s3_delete_xml_append_elem(xml_buf, xml_len, "Code",
                                        (const u_char *) err->code,
                                        strlen(err->code)) == NGX_OK
           && s3_delete_xml_append_elem(xml_buf, xml_len, "Message",
                                        (const u_char *) err->message,
                                        strlen(err->message)) == NGX_OK
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
 * s3_del_ctx_t — the state a single per-<Object> stage needs to render its
 * result: the request (for metrics/pool/identity), the location config (root
 * confinement + write gate), and the shared output-XML buffer plus its running
 * length. Passing it as one value keeps the per-object helpers under the
 * five-parameter limit and makes the data flow through the batch loop explicit.
 */
typedef struct {
    ngx_http_request_t      *r;
    ngx_http_s3_loc_conf_t  *cf;
    ngx_buf_t               *xml_buf;
    size_t                  *xml_len;
} s3_del_ctx_t;

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
 * s3_delete_dispose_key — resolve one already-extracted key and render its
 * batch result (<Deleted> or <Error>).
 *
 * WHAT: Confines the key to root_canon via s3_resolve_key(), and on success
 *   deletes it through s3_delete_one(); appends the matching per-key XML.
 * WHY: This is the per-key auth+delete stage. The path-escape (AccessDenied)
 *   check runs BEFORE any unlink — a key that resolves outside the export root
 *   is rejected without ever touching the filesystem, which is
 *   security-load-bearing and must precede the delete.
 * HOW: Returns NGX_OK once a result element has been appended, or NGX_ERROR if
 *   the output buffer overflowed (fatal → caller maps to 500).
 */
static ngx_int_t
s3_delete_dispose_key(s3_del_ctx_t *dc, const xmlChar *key_text, size_t key_len)
{
    char         fs_path[PATH_MAX];
    s3_del_err_t err;
    char         key_str[S3_MAX_KEY];

    ngx_memcpy(key_str, key_text, key_len);
    key_str[key_len] = '\0';

    if (!s3_resolve_key(dc->cf->common.root_canon, key_str, fs_path,
                        sizeof(fs_path)))
    {
        err.code    = "AccessDenied";
        err.message = "Access Denied.";
        return s3_delete_xml_append_error(dc->xml_buf, dc->xml_len,
                                          key_text, key_len, &err);
    }

    if (s3_delete_one(dc->r, dc->cf, fs_path, &err) == NGX_OK) {
        return s3_delete_xml_append_deleted(dc->xml_buf, dc->xml_len,
                                            key_text, key_len);
    }

    return s3_delete_xml_append_error(dc->xml_buf, dc->xml_len,
                                      key_text, key_len, &err);
}

/*
 * s3_delete_process_object — process one <Object> node end to end.
 *
 * WHAT: Extracts and length-validates the object's <Key>, then either appends
 *   a per-key InvalidArgument <Error> (empty/too-long key) or dispatches the
 *   key to s3_delete_dispose_key() for confinement, deletion and result XML.
 * WHY: One object is one loop iteration; isolating it flattens the batch loop
 *   and keeps every xmlFree paired with its xmlNodeGetContent on all exits.
 * HOW: Returns NGX_OK (result appended — continue the batch), NGX_ERROR
 *   (output buffer overflow — fatal), or NGX_ABORT (malformed object: missing
 *   <Key> or unreadable content — whole request is MalformedXML/500). The
 *   *malformed_500 out-flag distinguishes the two NGX_ABORT sub-cases.
 */
static ngx_int_t
s3_delete_process_object(s3_del_ctx_t *dc, xmlNodePtr obj, int *malformed_500)
{
    xmlNodePtr key_node;
    xmlChar   *key_text;
    size_t     key_len;
    ngx_int_t  rc;

    *malformed_500 = 0;

    key_node = s3_delete_xml_find_child(obj, "Key");
    if (key_node == NULL) {
        return NGX_ABORT;   /* missing <Key> → MalformedXML */
    }

    key_text = xmlNodeGetContent(key_node);
    if (key_text == NULL) {
        *malformed_500 = 1;
        return NGX_ABORT;   /* unreadable content → 500 */
    }
    key_len = (size_t) xmlStrlen(key_text);

    if (key_len == 0 || key_len >= S3_MAX_KEY) {
        s3_del_err_t err = { "InvalidArgument",
                             "Object key is empty or too long." };
        rc = s3_delete_xml_append_error(dc->xml_buf, dc->xml_len,
                                        key_text, key_len, &err);
    } else {
        rc = s3_delete_dispose_key(dc, key_text, key_len);
    }

    xmlFree(key_text);
    return rc;
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
 * s3_delete_run_batch — iterate the <Object> children of <Delete>, rendering a
 * per-key result for each into the output XML.
 *
 * WHAT: Enforces the S3_DEL_MAX_KEYS cap, requires at least one <Object>, and
 *   delegates each object to s3_delete_process_object(); non-<Object> children
 *   are skipped.
 * WHY: Separating the loop from the surrounding setup/teardown keeps this
 *   function's only concern the batch iteration and its client-facing
 *   MalformedXML edge cases (too many keys / no objects).
 * HOW: Returns NGX_OK once every object has an appended result (caller sends
 *   the buffered response). On any error it finalises the response here and
 *   returns NGX_DONE — the malformed sub-cases pick the exact message.
 */
static ngx_int_t
s3_delete_run_batch(s3_del_ctx_t *dc, ngx_uint_t method_slot, xmlNodePtr root)
{
    ngx_http_request_t *r = dc->r;
    xmlNodePtr          obj;
    ngx_uint_t          nkeys = 0;

    for (obj = root->children; obj != NULL; obj = obj->next) {
        int       malformed_500 = 0;
        ngx_int_t rc;

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
        nkeys++;

        rc = s3_delete_process_object(dc, obj, &malformed_500);
        if (rc == NGX_OK) {
            continue;
        }
        if (rc == NGX_ERROR) {
            s3_metrics_finalize_request_method(r, method_slot,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_DONE;
        }
        /* rc == NGX_ABORT: malformed object */
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

    if (nkeys == 0) {
        s3_metrics_finalize_request_method(r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                              "MalformedXML",
                              "DeleteObjects request has no Object entries."));
        return NGX_DONE;
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

    dc.r       = r;
    dc.cf      = cf;
    dc.xml_buf = xml_buf;
    dc.xml_len = &xml_len;

    if (s3_delete_run_batch(&dc, method_slot, xmlDocGetRootElement(doc))
        != NGX_OK)
    {
        xmlFreeDoc(doc);
        return;   /* response already finalised */
    }

    xmlFreeDoc(doc);
    s3_delete_objects_finish(r, method_slot, xml_buf, xml_len);
}
