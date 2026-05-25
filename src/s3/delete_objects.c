/*
 * delete_objects.c — S3 DeleteObjects handler (POST /bucket/?delete).
 *
 * Parses a list of <Object><Key>…</Key></Object> entries from the request
 * body, deletes each key, and returns a <DeleteResult> XML response with
 * <Deleted> or <Error> entries for each object.
 *
 * The body XML parser is a simple forward-scan (no full XML library needed
 * for this well-defined format).  Non-regular objects (directories) that
 * fail with EISDIR/EPERM are retried as rmdir.  ENOENT is treated as success
 * per S3 idempotency rules.
 */
/* WHY: S3 DeleteObjects supports batch deletion in a single POST request —
14#SB| * far more efficient than individual DELETE calls for pipelines that need to
15#PN| * remove hundreds or thousands of objects. Forward-scan parsing avoids pulling
16#MS| * in a full XML library for the well-defined <Object><Key>…</Key></Object>
17#QH| * format. Non-regular-object fallback (unlink → rmdir) handles directories
18#XM| * transparently; ENOENT is treated as success per S3 idempotency semantics. */

#include "s3.h"
#include "../compat/http_body.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

#define S3_DEL_MAX_KEYS  1000
#define S3_DEL_MAX_BODY  (1024 * 1024)   /* 1 MiB cap on XML body */
#define S3_DEL_XML_MAX   (128 * 1024)    /* max output XML (generous) */
/* WHY: S3 DeleteObjects supports batch deletion — a single POST request can remove
 * up to 1000 keys. The body XML cap (1 MiB) prevents oversized payloads; the output
 * buffer (128 KiB) is generous enough for ~500 <Deleted>/<Error> entries without
 * reallocating. */


/*
 * s3_del_find_tag — locate the content of the first occurrence of <tag>…</tag>
 * within [src, src+slen).  Sets *val and *vlen on success and returns 1.
 * Returns 0 if the open tag is not found; the search stops at the first match
 * so callers must advance past the returned span to find subsequent values.
 */
static int
s3_del_find_tag(const char *src, size_t slen,
                const char *tag, size_t tlen,
                const char **val, size_t *vlen)
{
    size_t      i;
    const char *open_end;
    const char *close_start;
    char        close_tag[128];

    if (tlen + 3 >= sizeof(close_tag)) {
        return 0;
    }
    close_tag[0] = '<';
    close_tag[1] = '/';
    memcpy(close_tag + 2, tag, tlen);
    close_tag[tlen + 2] = '>';
    close_tag[tlen + 3] = '\0';

    /* Find the opening tag (ignoring any XML namespace prefix) */
    for (i = 0; i + tlen + 1 < slen; i++) {
        if (src[i] == '<') {
            /* Accept <Tag> or <ns:Tag> — skip to last ':' or stay at src[i+1] */
            size_t j = i + 1;
            const char *colon = memchr(src + j, ':', tlen + 4);
            if (colon && (size_t)(colon - (src + j)) < tlen + 2) {
                j = (size_t)(colon - src) + 1;
            }
            if (j + tlen < slen
                && memcmp(src + j, tag, tlen) == 0
                && (src[j + tlen] == '>' || src[j + tlen] == ' '))
            {
                /* Advance to the '>' */
                const char *gt = memchr(src + j + tlen, '>', slen - j - tlen);
                if (gt == NULL) {
                    return 0;
                }
                open_end = gt + 1;
                /* Body is NUL-terminated; strstr works here */
                close_start = strstr(open_end, close_tag);
                if (close_start == NULL
                    || (size_t)(close_start - src) > slen) {
                    return 0;
                }
                *val  = open_end;
                *vlen = (size_t)(close_start - open_end);
                return 1;
            }
        }
    }
    return 0;
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

    /* Append closing tag */
    if (xml_len + sizeof(trailer) - 1 <= (size_t)(xml_buf->end - xml_buf->start)) {
        memcpy(xml_buf->start + xml_len, trailer, sizeof(trailer) - 1);
        xml_len += sizeof(trailer) - 1;
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
 *   keys to remove. We parse it with a lightweight forward-scan (s3_del_find_tag())
 *   rather than pulling in a full XML library — the format is well-defined and small.
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
 *   4. Loop through <Object> blocks, extract <Key>, resolve fs_path
 *   5. Attempt unlink → fallback rmdir on EISDIR/EPERM
 *   6. Emit <Deleted> (success/ENOENT) or <Error> (AccessDenied/BucketNotEmpty/InternalError)
 *   7. Finalise response via s3_delete_objects_finish()
 *
 * Constraints:
 *   - Max keys: S3_DEL_MAX_KEYS (1000) — stops parsing if exceeded
 *   - Body cap: S3_DEL_MAX_BODY (1 MiB) — rejects oversized XML as MalformedXML
 *   - Key length: < S3_MAX_KEY — skips too-long keys silently
 */

void
s3_delete_objects_body_handler(ngx_http_request_t *r)
{
    ngx_http_s3_loc_conf_t  *cf;
    ngx_uint_t               method_slot;
    char                    *body;
    u_char                  *body_buf;
    size_t                   body_len;
    const char              *cursor;
    size_t                   remain;
    u_char                  *xml_out;
    size_t                   xml_len;
    ngx_buf_t                xml_buf_obj;
    ngx_buf_t               *xml_buf = &xml_buf_obj;
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
    body = (char *) body_buf;

    /* Allocate XML output buffer */
    xml_out = ngx_palloc(r->pool, S3_DEL_XML_MAX);
    if (xml_out == NULL) {
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

    /* Walk through <Object> blocks in the body */
    cursor = body;
    remain = body_len;

    {
        ngx_uint_t  nkeys    = 0;
        const char *obj_val;
        size_t      obj_vlen;

        while (nkeys < S3_DEL_MAX_KEYS
               && s3_del_find_tag(cursor, remain,
                                  "Object", sizeof("Object") - 1,
                                  &obj_val, &obj_vlen))
        {
            const char *key_val;
            size_t      key_vlen;

            /* Advance cursor past this <Object> block */
            remain -= (size_t)(obj_val + obj_vlen - cursor);
            cursor  = obj_val + obj_vlen;

            if (!s3_del_find_tag(obj_val, obj_vlen,
                                 "Key", sizeof("Key") - 1,
                                 &key_val, &key_vlen))
            {
                continue;
            }

            if (key_vlen == 0 || key_vlen >= S3_MAX_KEY) {
                continue;
            }

            /* NUL-terminate the key */
            char key_str[S3_MAX_KEY];
            memcpy(key_str, key_val, key_vlen);
            key_str[key_vlen] = '\0';

            /* Resolve the filesystem path */
            char fs_path[PATH_MAX];
            if (!s3_resolve_key(cf->common.root_canon, key_str, fs_path,
                                sizeof(fs_path)))
            {
                /* Emit <Error><Code>AccessDenied</Code> */
                size_t room = (size_t)(xml_buf->end - xml_buf->start) - xml_len;
                int    n    = snprintf((char *)(xml_out + xml_len), room,
                    "<Error><Key>%.*s</Key>"
                    "<Code>AccessDenied</Code>"
                    "<Message>Access Denied.</Message></Error>",
                    (int) key_vlen, key_val);
                if (n > 0 && (size_t) n < room) {
                    xml_len += (size_t) n;
                }
                continue;
            }

            /* Attempt deletion */
            int del_rc = xrootd_unlink_confined_canon(r->connection->log,
                                                       cf->common.root_canon,
                                                       fs_path, 0);
            if (del_rc != 0 && (errno == EISDIR || errno == EPERM)) {
                del_rc = xrootd_unlink_confined_canon(r->connection->log,
                                                      cf->common.root_canon,
                                                      fs_path, 1);
            }
/* WHY: unlink() works for regular files but returns EISDIR/EPERM on directories.
 * S3 DeleteObjects should delete both — so we retry with the rmdir flag (1) when
 * unlink fails with those errno values. This provides transparent directory deletion
 * without requiring the client to call Rmdir separately. */


            size_t room = (size_t)(xml_buf->end - xml_buf->start) - xml_len;
            int    n;

            if (del_rc == 0 || errno == ENOENT) {
                /* Success (or already gone — S3 is idempotent) */
/* WHY: S3 DeleteObjects is idempotent — deleting an object that doesn't exist returns
 * <Deleted> (not <Error>). This matches AWS behaviour and prevents pipeline retries
 * from producing error noise. */

                n = snprintf((char *)(xml_out + xml_len), room,
                             "<Deleted><Key>%.*s</Key></Deleted>",
                             (int) key_vlen, key_val);
            } else {
                const char *code;
                const char *msg;
                if (errno == EACCES || errno == EPERM) {
                    code = "AccessDenied";
                    msg  = "Access Denied.";
                } else if (errno == ENOTEMPTY) {
                    code = "BucketNotEmpty";
                    msg  = "The directory is not empty.";
                } else {
                    code = "InternalError";
                    msg  = "Internal server error.";
                }
/* WHY: errno mapping to S3 error codes:
 *   - EACCES/EPERM → AccessDenied (file permissions or ACL deny)
 *   - ENOTEMPTY → BucketNotEmpty (non-empty directory — S3 requires empty dirs)
 *   - anything else → InternalError (fallback for unexpected failures) */

                n = snprintf((char *)(xml_out + xml_len), room,
                             "<Error><Key>%.*s</Key>"
                             "<Code>%s</Code>"
                             "<Message>%s</Message></Error>",
                             (int) key_vlen, key_val, code, msg);
            }

            if (n > 0 && (size_t) n < room) {
                xml_len += (size_t) n;
            }

            nkeys++;
        }
    }

    s3_delete_objects_finish(r, method_slot, xml_buf, xml_len);
}
