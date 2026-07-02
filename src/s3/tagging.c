/*
 * tagging.c — S3 object tagging + canned bucket/object subresources (phase-43 W5).
 *
 * WHAT:
 *   - Object tagging: x-amz-tagging on PutObject, and GET/PUT/DELETE
 *     /<key>?tagging.  The tag set is stored as a single "k1=v1&k2=v2"
 *     (URL-encoded) blob in a dedicated xattr beside the object — no new on-disk
 *     structures, and it is invisible to every other code path.
 *   - Canned probe-satisfiers: GetBucketVersioning (disabled),
 *     GetBucketAcl / GetObjectAcl (owner FULL_CONTROL), and
 *     GET ?cors (NoSuchCORSConfiguration).  Mutating those subresources
 *     (PUT ?versioning / ?acl) is explicitly answered 501 NotImplemented rather
 *     than silently accepted (see the phase-43 non-goals).
 *
 * WHY: Rucio and data-management tooling label objects with tags, and many SDKs
 *   probe the canned subresources during setup; answering them well-formed (or
 *   with an honest error) keeps unmodified clients working.
 */

#include "s3.h"
#include "fs/path/path.h"
#include "tagging.h"
#include "core/compat/http_body.h"
#include "core/compat/http_headers.h"
#include "core/compat/http_query.h"
#include "core/compat/uri.h"
#include "core/compat/xml.h"
#include "fs/vfs.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include "core/compat/alloc_guard.h"

#define S3_TAG_XATTR    "user.s3.tagging"
#define S3_TAG_MAX      4096   /* AWS: <=10 tags, key<=128, value<=256 */
#define S3_TAG_XML_MAX  8192

/* xattr-backed tag store */
/*
 * s3_tag_vfs_ctx — build a transient VFS request descriptor for the (already
 * resolved, confined) object path.  Replicates the reference helper in object.c
 * (s3_vfs_ctx) so the tag xattr ops route through the VFS xattr surface
 * (metrics + access-log) while delegating the same brokered confined-xattr
 * syscalls underneath.
 */
static void
s3_tag_vfs_ctx(ngx_http_request_t *r, const char *fs_path,
    ngx_http_s3_loc_conf_t *cf, xrootd_vfs_ctx_t *vctx)
{
    ngx_http_s3_req_ctx_t *s3ctx;
    int                    is_tls = 0;

    s3ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    xrootd_vfs_ctx_init(vctx, r->pool, r->connection->log, XROOTD_PROTO_S3,
        cf->common.root_canon, cf->cache_root_canon, cf->common.allow_write,
        is_tls, (s3ctx != NULL) ? s3ctx->identity : NULL, fs_path);
}

/* Read the stored tag blob into out (NUL-terminated). Returns length, 0 if
 * none, -1 on error. */
static ssize_t
s3_tag_load(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const char *fs_path, char *out, size_t outsz)
{
    xrootd_vfs_ctx_t vctx;
    ssize_t          n;

    /*
     * Impersonation: read the tag xattr AS THE MAPPED USER via the VFS xattr
     * surface, which delegates to the brokered confined-xattr helper — NOT a
     * worker-side fgetxattr on a broker-opened fd, which would evaluate the
     * xattr-read DAC as the unprivileged worker (svc).  Mirrors the WebDAV
     * LOCK/PROPPATCH path (webdav/prop_xattr.c).  Off impersonation the helper
     * is a plain path-based getxattr.
     */
    s3_tag_vfs_ctx(r, fs_path, cf, &vctx);
    n = xrootd_vfs_getxattr(&vctx, S3_TAG_XATTR, out, outsz - 1);
    if (n < 0) {
        if (errno == ENODATA || errno == ENOTSUP || errno == EOPNOTSUPP) {
            return 0;   /* object readable, just carries no tags */
        }
        return -1;      /* denied / missing object → caller maps 403/404 */
    }
    out[n] = '\0';
    return n;
}

/* Persist (or, when blob_len==0, remove) the tag blob. Returns NGX_OK/ERROR. */
static ngx_int_t
s3_tag_store(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const char *fs_path, const char *blob, size_t blob_len, int remove_it)
{
    xrootd_vfs_ctx_t vctx;

    /*
     * Impersonation (the bug this fixes): the old path opened O_RDONLY via the
     * broker (READ-checked) then did a worker-side fsetxattr/fremovexattr — so the
     * xattr WRITE DAC was evaluated as the unprivileged worker (svc), NOT the
     * mapped user.  Effect: (a) the legitimate owner's PutObjectTagging failed
     * (svc is "other" on the owner's file), and (b) on a permissive backing FS a
     * requester who could merely READ another tenant's object could mutate/remove
     * its tags.  Route the MUTATION through the VFS xattr surface, which delegates
     * to the brokered confined-xattr helper (broker setfsuid -> f{set,remove}xattr
     * as the mapped user, user.* namespace filter), exactly like WebDAV
     * LOCK/PROPPATCH.  Off impersonation it is a plain path-based syscall
     * (unchanged behaviour).  Note: VFS set/remove xattr are intentionally NOT
     * allow_write-gated, matching the prior direct-helper behaviour.
     */
    s3_tag_vfs_ctx(r, fs_path, cf, &vctx);

    if (remove_it) {
        if (xrootd_vfs_removexattr(&vctx, S3_TAG_XATTR) == NGX_OK) {
            return NGX_OK;
        }
        return (errno == ENODATA) ? NGX_OK : NGX_ERROR;
    }

    return xrootd_vfs_setxattr(&vctx, S3_TAG_XATTR, blob, blob_len, 0) == NGX_OK
           ? NGX_OK : NGX_ERROR;
}

/* validation */
/* A tag blob is "k=v&k=v..."; reject control bytes (defends the GET XML emit and
 * keeps the stored form a clean query string). */
static int
s3_tag_blob_valid(const char *s, size_t len)
{
    size_t i;
    if (len > S3_TAG_MAX) {
        return 0;
    }
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char) s[i];
        if (c < 0x20 || c == 0x7f) {
            return 0;
        }
    }
    return 1;
}

/* GET /<key>?tagging */
ngx_int_t
s3_handle_get_object_tagging(ngx_http_request_t *r, const char *fs_path,
    ngx_http_s3_loc_conf_t *cf)
{
    char       blob[S3_TAG_MAX + 1];
    ssize_t    blen;
    u_char    *xml;
    size_t     xml_len = 0;
    size_t     xml_capacity = S3_TAG_XML_MAX;
    ngx_buf_t *buf;
    char      *p, *amp;

    blen = s3_tag_load(r, cf, fs_path, blob, sizeof(blob));
    if (blen < 0) {
        return s3_fail(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                       "The specified key does not exist.",
                       XROOTD_S3_EVENT_NO_SUCH_KEY);
    }

    xml = ngx_palloc(r->pool, xml_capacity);
    if (xml == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    XML_APPEND("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    XML_APPEND("<Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
               "<TagSet>");

    /* Walk "k=v&k=v", URL-decoding each component, emit <Tag><Key/><Value/>. */
    p = blob;
    while (blen > 0 && p != NULL && *p != '\0') {
        char  kbuf[512], vbuf[512];
        char *eq;
        size_t klen, vlen;

        amp = strchr(p, '&');
        if (amp != NULL) {
            *amp = '\0';
        }
        eq = strchr(p, '=');
        if (eq != NULL) {
            *eq = '\0';
            klen = xrootd_http_urldecode((u_char *) p, ngx_strlen(p),
                       kbuf, sizeof(kbuf), XROOTD_URLDECODE_PLUS_TO_SPACE)
                   == XROOTD_URLDECODE_OK ? ngx_strlen(kbuf) : 0;
            vlen = xrootd_http_urldecode((u_char *) (eq + 1),
                       ngx_strlen(eq + 1), vbuf, sizeof(vbuf),
                       XROOTD_URLDECODE_PLUS_TO_SPACE)
                   == XROOTD_URLDECODE_OK ? ngx_strlen(vbuf) : 0;
            XML_APPEND("<Tag>");
            XML_APPEND_ELEM("Key", kbuf, klen);
            XML_APPEND_ELEM("Value", vbuf, vlen);
            XML_APPEND("</Tag>");
        }
        if (amp == NULL) {
            break;
        }
        p = amp + 1;
    }

    XML_APPEND("</TagSet></Tagging>");

    buf = ngx_create_temp_buf(r->pool, xml_len + 4);
    if (buf == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    buf->last = ngx_cpymem(buf->last, xml, xml_len);
    buf->last_buf = 1;
    return xrootd_http_send_xml_buffer(r, NGX_HTTP_OK,
        (ngx_str_t) ngx_string("application/xml"), buf);
}

/* DELETE /<key>?tagging */
ngx_int_t
s3_handle_delete_object_tagging(ngx_http_request_t *r, const char *fs_path,
    ngx_http_s3_loc_conf_t *cf)
{
    if (s3_tag_store(r, cf, fs_path, NULL, 0, 1 /* remove */) != NGX_OK) {
        return s3_fail(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                       "The specified key does not exist.",
                       XROOTD_S3_EVENT_NO_SUCH_KEY);
    }
    r->headers_out.status           = NGX_HTTP_NO_CONTENT;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

/* x-amz-tagging header (on PutObject) */
ngx_int_t
s3_apply_put_tagging_header(ngx_http_request_t *r, const char *fs_path,
    const char *root_canon)
{
    ngx_table_elt_t        *h;
    ngx_http_s3_loc_conf_t *cf =
        ngx_http_get_module_loc_conf(r, ngx_http_xrootd_s3_module);

    h = xrootd_http_find_header(r, "x-amz-tagging",
                                sizeof("x-amz-tagging") - 1);
    if (h == NULL || h->value.len == 0) {
        return NGX_OK;
    }
    if (!s3_tag_blob_valid((const char *) h->value.data, h->value.len)) {
        return NGX_ERROR;
    }
    (void) root_canon;   /* cf carries the canonical root */
    return s3_tag_store(r, cf, fs_path, (const char *) h->value.data,
                        h->value.len, 0);
}

/* PUT /<key>?tagging (XML body) */
/*
 * Parse <Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag>...> into the
 * stored "k=v&k=v" form (URL-encoded), via libxml2 with the same hardened
 * posture as the DeleteObjects parser.
 */
static ngx_int_t
s3_tag_blob_from_xml(ngx_http_request_t *r, const u_char *body, size_t len,
    char *out, size_t outsz, size_t *out_len)
{
    xmlDocPtr   doc;
    xmlNodePtr  root, tagset, tag, kv;
    size_t      pos = 0;
    int         options = XML_PARSE_NONET | XML_PARSE_NOBLANKS;

    doc = xmlReadMemory((const char *) body, (int) len, "tagging.xml", NULL,
                        options);
    if (doc == NULL) {
        return NGX_ERROR;
    }

    root = xmlDocGetRootElement(doc);
    if (root == NULL || xmlStrcmp(root->name, (const xmlChar *) "Tagging") != 0) {
        xmlFreeDoc(doc);
        return NGX_ERROR;
    }

    for (tagset = root->children; tagset != NULL; tagset = tagset->next) {
        if (tagset->type != XML_ELEMENT_NODE
            || xmlStrcmp(tagset->name, (const xmlChar *) "TagSet") != 0)
        {
            continue;
        }
        for (tag = tagset->children; tag != NULL; tag = tag->next) {
            char  enc[512];
            const xmlChar *key = NULL, *val = NULL;

            if (tag->type != XML_ELEMENT_NODE
                || xmlStrcmp(tag->name, (const xmlChar *) "Tag") != 0)
            {
                continue;
            }
            for (kv = tag->children; kv != NULL; kv = kv->next) {
                if (kv->type != XML_ELEMENT_NODE) {
                    continue;
                }
                if (xmlStrcmp(kv->name, (const xmlChar *) "Key") == 0) {
                    key = xmlNodeGetContent(kv);
                } else if (xmlStrcmp(kv->name, (const xmlChar *) "Value") == 0) {
                    val = xmlNodeGetContent(kv);
                }
            }
            if (key != NULL && val != NULL) {
                size_t n;
                if (pos != 0 && pos < outsz) {
                    out[pos++] = '&';
                }
                xrootd_http_urlencode(key, ngx_strlen((char *) key),
                                      enc, sizeof(enc), "");
                n = ngx_strlen(enc);
                if (pos + n < outsz) { ngx_memcpy(out + pos, enc, n); pos += n; }
                if (pos < outsz) { out[pos++] = '='; }
                xrootd_http_urlencode(val, ngx_strlen((char *) val),
                                      enc, sizeof(enc), "");
                n = ngx_strlen(enc);
                if (pos + n < outsz) { ngx_memcpy(out + pos, enc, n); pos += n; }
            }
            if (key != NULL) { xmlFree((void *) key); }
            if (val != NULL) { xmlFree((void *) val); }
        }
    }

    xmlFreeDoc(doc);
    if (pos >= outsz) {
        return NGX_ERROR;
    }
    out[pos] = '\0';
    *out_len = pos;
    return NGX_OK;
}

void
s3_put_object_tagging_body_handler(ngx_http_request_t *r)
{
    ngx_http_s3_req_ctx_t  *rx;
    ngx_http_s3_loc_conf_t *cf;
    u_char                 *body = NULL;
    size_t                  body_len = 0;
    char                    blob[S3_TAG_MAX + 1];
    size_t                  blob_len = 0;
    ngx_int_t               rc;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_s3_module);
    rx = ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);
    if (rx == NULL || rx->fs_path[0] == '\0') {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (xrootd_http_body_read_all(r, S3_TAG_XML_MAX, &body, &body_len) != NGX_OK
        || body == NULL || body_len == 0)
    {
        (void) s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST, "MalformedXML",
                                 "The tagging XML could not be read.");
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }

    if (s3_tag_blob_from_xml(r, body, body_len, blob, sizeof(blob), &blob_len)
            != NGX_OK
        || !s3_tag_blob_valid(blob, blob_len))
    {
        (void) s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST, "MalformedXML",
                                 "The tagging XML is malformed.");
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }

    rc = s3_tag_store(r, cf, rx->fs_path, blob, blob_len, 0);
    if (rc != NGX_OK) {
        (void) s3_send_xml_error(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                                 "The specified key does not exist.");
        ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND);
        return;
    }

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    ngx_http_finalize_request(r, ngx_http_send_special(r, NGX_HTTP_LAST));
}

/* canned subresources */
static ngx_int_t
s3_send_xml_literal(ngx_http_request_t *r, const char *xml)
{
    size_t     len = ngx_strlen(xml);
    ngx_buf_t *buf = ngx_create_temp_buf(r->pool, len + 1);

    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    buf->last = ngx_cpymem(buf->last, xml, len);
    buf->last_buf = 1;
    return xrootd_http_send_xml_buffer(r, NGX_HTTP_OK,
        (ngx_str_t) ngx_string("application/xml"), buf);
}

ngx_int_t
s3_handle_get_bucket_versioning(ngx_http_request_t *r)
{
    /* No <Status> element ⇒ versioning has never been enabled (AWS default). */
    return s3_send_xml_literal(r,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<VersioningConfiguration "
        "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>");
}

ngx_int_t
s3_handle_get_acl(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf)
{
    /* Canned owner-FULL_CONTROL ACL — the gateway authorizes via XrdAcc/tokens,
     * not per-object S3 ACLs, but SDKs probe this and expect a well-formed doc. */
    char        owner[128];
    size_t      n;
    u_char     *xml;
    size_t      xml_len = 0;
    size_t      xml_capacity = 1024;
    ngx_buf_t  *buf;

    if (cf->access_key.len > 0) {
        n = cf->access_key.len < sizeof(owner) - 1
            ? cf->access_key.len : sizeof(owner) - 1;
        ngx_memcpy(owner, cf->access_key.data, n);
    } else {
        n = sizeof("anonymous") - 1;
        ngx_memcpy(owner, "anonymous", n);
    }
    owner[n] = '\0';

    XROOTD_PALLOC_OR_RETURN(xml, r->pool, xml_capacity, NGX_HTTP_INTERNAL_SERVER_ERROR);
    XML_APPEND("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    XML_APPEND("<AccessControlPolicy "
               "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Owner>");
    XML_APPEND_ELEM("ID", owner, n);
    XML_APPEND_ELEM("DisplayName", owner, n);
    XML_APPEND("</Owner><AccessControlList><Grant>"
               "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
               "xsi:type=\"CanonicalUser\">");
    XML_APPEND_ELEM("ID", owner, n);
    XML_APPEND_ELEM("DisplayName", owner, n);
    XML_APPEND("</Grantee><Permission>FULL_CONTROL</Permission></Grant>"
               "</AccessControlList></AccessControlPolicy>");

    buf = ngx_create_temp_buf(r->pool, xml_len + 4);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    buf->last = ngx_cpymem(buf->last, xml, xml_len);
    buf->last_buf = 1;
    return xrootd_http_send_xml_buffer(r, NGX_HTTP_OK,
        (ngx_str_t) ngx_string("application/xml"), buf);
}

ngx_int_t
s3_handle_get_cors(ngx_http_request_t *r)
{
    /* CORS here is static per-location (the OPTIONS preflight); there is no
     * per-bucket CORS document, so report the honest AWS error. */
    return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND, "NoSuchCORSConfiguration",
        "The CORS configuration does not exist.");
}
