/*
 * post_object.c — S3 browser POST Object handler.
 *
 * Implements the multipart/form-data upload path used by browser forms:
 * POST /<bucket>/ with form fields such as key, policy, x-amz-credential,
 * x-amz-signature, success_action_status, and a file part.  Object bytes are
 * committed through the same confined staged-file pattern as PUT.
 */

#include "s3.h"
#include "../compat/crypto.h"
#include "../compat/hex.h"
#include "../compat/http_body.h"
#include "../compat/http_headers.h"
#include "../compat/staged_file.h"
#include "../path/path.h"

#include <jansson.h>
#include <openssl/crypto.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define S3_POST_MAX_BODY    (128 * 1024 * 1024)
#define S3_POST_MAX_FIELD   4096
#define S3_POST_MAX_FIELDS  64
#define S3_POST_MAX_POLICY  65536

typedef struct {
    char name[128];
    char value[S3_POST_MAX_FIELD];
} s3_post_field_t;

typedef struct {
    s3_post_field_t fields[S3_POST_MAX_FIELDS];
    ngx_uint_t      nfields;

    char            key[S3_MAX_KEY];
    char            filename[256];
    char            content_type[256];
    char            policy[S3_POST_MAX_POLICY];
    char            algorithm[64];
    char            credential[256];
    char            amz_date[32];
    char            signature[129];
    char            success_status[8];
    char            success_redirect[2048];

    u_char         *file_data;
    size_t          file_len;
    ngx_flag_t      have_file;
} s3_post_form_t;

static ngx_int_t
s3_post_error(ngx_http_request_t *r, ngx_uint_t status, const char *code,
    const char *message)
{
    return s3_send_xml_error(r, status, code, message);
}

static ngx_int_t
s3_post_copy_text(const u_char *data, size_t len, char *dst, size_t dstsz)
{
    size_t i;

    if (len >= dstsz) {
        return NGX_ERROR;
    }

    for (i = 0; i < len; i++) {
        if (data[i] == '\0') {
            return NGX_ERROR;
        }
    }

    ngx_memcpy(dst, data, len);
    dst[len] = '\0';
    return NGX_OK;
}

static const char *
s3_post_field_value(const s3_post_form_t *form, const char *name)
{
    ngx_uint_t i;

    if (name[0] == '$') {
        name++;
    }

    if (strcmp(name, "key") == 0) {
        return form->key;
    }

    for (i = 0; i < form->nfields; i++) {
        if (strcmp(form->fields[i].name, name) == 0) {
            return form->fields[i].value;
        }
    }

    if (strcmp(name, "Content-Type") == 0) {
        return form->content_type;
    }

    return NULL;
}

static ngx_int_t
s3_post_store_field(s3_post_form_t *form, const char *name,
    const u_char *data, size_t len)
{
    char value[S3_POST_MAX_FIELD];

    if (name == NULL || name[0] == '\0') {
        return NGX_ERROR;
    }

    if (s3_post_copy_text(data, len, value, sizeof(value)) != NGX_OK) {
        return NGX_ERROR;
    }

    if (form->nfields < S3_POST_MAX_FIELDS
        && strlen(name) < sizeof(form->fields[form->nfields].name))
    {
        ngx_cpystrn((u_char *) form->fields[form->nfields].name,
                    (u_char *) name,
                    sizeof(form->fields[form->nfields].name));
        ngx_cpystrn((u_char *) form->fields[form->nfields].value,
                    (u_char *) value,
                    sizeof(form->fields[form->nfields].value));
        form->nfields++;
    }

    if (strcmp(name, "key") == 0) {
        return s3_post_copy_text(data, len, form->key, sizeof(form->key));
    }
    if (strcmp(name, "policy") == 0) {
        return s3_post_copy_text(data, len, form->policy,
                                 sizeof(form->policy));
    }
    if (strcmp(name, "x-amz-algorithm") == 0) {
        return s3_post_copy_text(data, len, form->algorithm,
                                 sizeof(form->algorithm));
    }
    if (strcmp(name, "x-amz-credential") == 0) {
        return s3_post_copy_text(data, len, form->credential,
                                 sizeof(form->credential));
    }
    if (strcmp(name, "x-amz-date") == 0) {
        return s3_post_copy_text(data, len, form->amz_date,
                                 sizeof(form->amz_date));
    }
    if (strcmp(name, "x-amz-signature") == 0) {
        return s3_post_copy_text(data, len, form->signature,
                                 sizeof(form->signature));
    }
    if (strcmp(name, "success_action_status") == 0) {
        return s3_post_copy_text(data, len, form->success_status,
                                 sizeof(form->success_status));
    }
    if (strcmp(name, "success_action_redirect") == 0) {
        return s3_post_copy_text(data, len, form->success_redirect,
                                 sizeof(form->success_redirect));
    }

    return NGX_OK;
}

static ngx_int_t
s3_post_boundary(ngx_http_request_t *r, char *boundary, size_t boundary_sz)
{
    ngx_table_elt_t *ct;
    u_char          *p, *end;
    size_t           len;

    ct = xrootd_http_find_header(r, "Content-Type",
                                 sizeof("Content-Type") - 1);
    if (ct == NULL || ct->value.len == 0) {
        return NGX_DECLINED;
    }

    if (ngx_strncasecmp(ct->value.data, (u_char *) "multipart/form-data",
                        sizeof("multipart/form-data") - 1) != 0)
    {
        return NGX_DECLINED;
    }

    p = ct->value.data;
    end = ct->value.data + ct->value.len;

    while (p < end) {
        while (p < end && (*p == ';' || *p == ' ' || *p == '\t')) {
            p++;
        }
        if ((size_t) (end - p) >= sizeof("boundary=") - 1
            && ngx_strncasecmp(p, (u_char *) "boundary=",
                               sizeof("boundary=") - 1) == 0)
        {
            p += sizeof("boundary=") - 1;
            if (p < end && *p == '"') {
                u_char *q;
                p++;
                q = p;
                while (q < end && *q != '"') {
                    q++;
                }
                if (q == end) {
                    return NGX_ERROR;
                }
                len = (size_t) (q - p);
            } else {
                u_char *q = p;
                while (q < end && *q != ';' && *q != ' '
                       && *q != '\t')
                {
                    q++;
                }
                len = (size_t) (q - p);
            }

            if (len == 0 || len >= boundary_sz || len > 200) {
                return NGX_ERROR;
            }

            ngx_memcpy(boundary, p, len);
            boundary[len] = '\0';
            return NGX_OK;
        }

        while (p < end && *p != ';') {
            p++;
        }
    }

    return NGX_DECLINED;
}

static u_char *
s3_memmem(u_char *hay, size_t hay_len, const u_char *needle,
    size_t needle_len)
{
    size_t i;

    if (needle_len == 0 || hay_len < needle_len) {
        return NULL;
    }

    for (i = 0; i <= hay_len - needle_len; i++) {
        if (hay[i] == needle[0]
            && ngx_memcmp(hay + i, needle, needle_len) == 0)
        {
            return hay + i;
        }
    }

    return NULL;
}

static ngx_int_t
s3_post_extract_param(const char *line, const char *name,
    char *out, size_t outsz)
{
    const char *p;
    size_t      nlen;

    out[0] = '\0';
    nlen = strlen(name);
    p = line;

    while ((p = strchr(p, ';')) != NULL) {
        p++;
        while (*p == ' ' || *p == '\t') {
            p++;
        }

        if (ngx_strncasecmp((u_char *) p, (u_char *) name, nlen) == 0
            && p[nlen] == '=')
        {
            const char *v = p + nlen + 1;
            const char *e;
            size_t      len;

            if (*v == '"') {
                v++;
                e = v;
                while (*e != '\0' && *e != '"') {
                    e++;
                }
            } else {
                e = v;
                while (*e != '\0' && *e != ';' && *e != ' '
                       && *e != '\t')
                {
                    e++;
                }
            }

            len = (size_t) (e - v);
            if (len >= outsz) {
                return NGX_ERROR;
            }
            ngx_memcpy(out, v, len);
            out[len] = '\0';
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}

static void
s3_post_basename(char *s)
{
    char *slash;
    char *bslash;
    char *base;

    slash = strrchr(s, '/');
    bslash = strrchr(s, '\\');
    base = slash > bslash ? slash : bslash;

    if (base != NULL) {
        ngx_memmove(s, base + 1, strlen(base + 1) + 1);
    }
}

static ngx_int_t
s3_post_expand_filename(ngx_http_request_t *r, s3_post_form_t *form)
{
    static const char needle[] = "${filename}";
    char              expanded[S3_MAX_KEY];
    const char       *src;
    char             *dst;
    size_t            left;

    if (strstr(form->key, needle) == NULL) {
        return NGX_OK;
    }

    src = form->key;
    dst = expanded;
    left = sizeof(expanded);

    while (*src != '\0') {
        const char *m = strstr(src, needle);
        size_t      n;

        if (m == NULL) {
            n = strlen(src);
            if (n >= left) {
                return NGX_ERROR;
            }
            ngx_memcpy(dst, src, n + 1);
            break;
        }

        n = (size_t) (m - src);
        if (n + strlen(form->filename) >= left) {
            return NGX_ERROR;
        }
        ngx_memcpy(dst, src, n);
        dst += n;
        left -= n;
        n = strlen(form->filename);
        ngx_memcpy(dst, form->filename, n);
        dst += n;
        left -= n;
        src = m + sizeof(needle) - 1;
    }

    if (xrootd_http_str_has_ctl((u_char *) expanded, strlen(expanded))) {
        return NGX_ERROR;
    }

    ngx_cpystrn((u_char *) form->key, (u_char *) expanded,
                sizeof(form->key));
    (void) r;
    return NGX_OK;
}

static ngx_int_t
s3_post_parse_form(ngx_http_request_t *r, u_char *body, size_t body_len,
    const char *boundary, s3_post_form_t *form)
{
    char     marker[256];
    char     delim[258];
    size_t   marker_len, delim_len;
    u_char  *pos, *end;

    marker_len = (size_t) snprintf(marker, sizeof(marker), "--%s", boundary);
    delim_len = (size_t) snprintf(delim, sizeof(delim), "\r\n--%s", boundary);
    if (marker_len >= sizeof(marker) || delim_len >= sizeof(delim)) {
        return NGX_ERROR;
    }

    pos = body;
    end = body + body_len;

    if ((size_t) (end - pos) < marker_len
        || ngx_memcmp(pos, marker, marker_len) != 0)
    {
        return NGX_ERROR;
    }
    pos += marker_len;
    if ((size_t) (end - pos) < 2 || pos[0] != '\r' || pos[1] != '\n') {
        return NGX_ERROR;
    }
    pos += 2;

    while (pos < end) {
        char    name[128] = "";
        char    filename[256] = "";
        char    content_type[256] = "";
        u_char *content;
        u_char *next;
        size_t  content_len;

        for (;;) {
            u_char *line_end;
            size_t  line_len;
            char    line[1024];

            line_end = s3_memmem(pos, (size_t) (end - pos),
                                 (u_char *) "\r\n", 2);
            if (line_end == NULL) {
                return NGX_ERROR;
            }

            line_len = (size_t) (line_end - pos);
            if (line_len == 0) {
                pos = line_end + 2;
                break;
            }
            if (line_len >= sizeof(line)) {
                return NGX_ERROR;
            }

            ngx_memcpy(line, pos, line_len);
            line[line_len] = '\0';
            pos = line_end + 2;

            if (ngx_strncasecmp((u_char *) line,
                                (u_char *) "Content-Disposition:",
                                sizeof("Content-Disposition:") - 1) == 0)
            {
                if (s3_post_extract_param(line, "name", name, sizeof(name))
                    == NGX_ERROR
                    || s3_post_extract_param(line, "filename", filename,
                                             sizeof(filename)) == NGX_ERROR)
                {
                    return NGX_ERROR;
                }
                if (filename[0] != '\0') {
                    s3_post_basename(filename);
                }
            } else if (ngx_strncasecmp((u_char *) line,
                                       (u_char *) "Content-Type:",
                                       sizeof("Content-Type:") - 1) == 0)
            {
                const char *v = line + sizeof("Content-Type:") - 1;
                while (*v == ' ' || *v == '\t') {
                    v++;
                }
                if (ngx_strlen(v) >= sizeof(content_type)) {
                    return NGX_ERROR;
                }
                ngx_cpystrn((u_char *) content_type, (u_char *) v,
                            sizeof(content_type));
            }
        }

        if (name[0] == '\0') {
            return NGX_ERROR;
        }

        content = pos;
        next = s3_memmem(content, (size_t) (end - content),
                         (u_char *) delim, delim_len);
        if (next == NULL) {
            return NGX_ERROR;
        }

        content_len = (size_t) (next - content);
        if (strcmp(name, "file") == 0) {
            form->file_data = content;
            form->file_len = content_len;
            form->have_file = 1;
            ngx_cpystrn((u_char *) form->filename, (u_char *) filename,
                        sizeof(form->filename));
            ngx_cpystrn((u_char *) form->content_type,
                        (u_char *) content_type,
                        sizeof(form->content_type));
        } else if (s3_post_store_field(form, name, content, content_len)
                   != NGX_OK)
        {
            return NGX_ERROR;
        }

        pos = next + delim_len;
        if ((size_t) (end - pos) >= 2 && pos[0] == '-' && pos[1] == '-') {
            return NGX_OK;
        }
        if ((size_t) (end - pos) < 2 || pos[0] != '\r' || pos[1] != '\n') {
            return NGX_ERROR;
        }
        pos += 2;
    }

    (void) r;
    return NGX_ERROR;
}

static int64_t
s3_post_days_from_civil(int y, unsigned m, unsigned d)
{
    int64_t   era;
    unsigned  yoe, doy, doe;
    int       mp;

    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = (unsigned) (y - era * 400);
    mp = (int) m + (m > 2 ? -3 : 9);
    doy = (153 * (unsigned) mp + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;

    return era * 146097 + (int64_t) doe - 719468;
}

static ngx_int_t
s3_post_parse_iso8601(const char *s, time_t *out)
{
    int y, mo, d, h, mi, se;

    if (sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2dZ",
               &y, &mo, &d, &h, &mi, &se) != 6)
    {
        return NGX_ERROR;
    }

    if (y < 1970 || mo < 1 || mo > 12 || d < 1 || d > 31
        || h < 0 || h > 23 || mi < 0 || mi > 59 || se < 0 || se > 60)
    {
        return NGX_ERROR;
    }

    *out = (time_t) (s3_post_days_from_civil(y, (unsigned) mo, (unsigned) d)
                     * 86400 + h * 3600 + mi * 60 + se);
    return NGX_OK;
}

static ngx_int_t
s3_post_check_field_eq(const char *actual, const char *expected)
{
    if (actual == NULL || expected == NULL || strcmp(actual, expected) != 0) {
        return NGX_DECLINED;
    }
    return NGX_OK;
}

static ngx_int_t
s3_post_policy_condition(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form, json_t *cond)
{
    const char *key;
    json_t     *value;

    if (json_is_object(cond)) {
        json_object_foreach(cond, key, value) {
            const char *expected;
            const char *actual;

            if (!json_is_string(value)) {
                return NGX_ERROR;
            }

            expected = json_string_value(value);
            if (strcmp(key, "bucket") == 0) {
                if (cf->bucket.len != strlen(expected)
                    || ngx_strncmp(cf->bucket.data, (u_char *) expected,
                                   cf->bucket.len) != 0)
                {
                    return NGX_DECLINED;
                }
                continue;
            }

            actual = s3_post_field_value(form, key);
            if (s3_post_check_field_eq(actual, expected) != NGX_OK) {
                return NGX_DECLINED;
            }
        }
        return NGX_OK;
    }

    if (json_is_array(cond) && json_array_size(cond) >= 3) {
        const char *op;

        if (!json_is_string(json_array_get(cond, 0))) {
            return NGX_ERROR;
        }

        op = json_string_value(json_array_get(cond, 0));

        if (strcmp(op, "content-length-range") == 0) {
            json_int_t minv, maxv;

            if (json_array_size(cond) != 3
                || !json_is_integer(json_array_get(cond, 1))
                || !json_is_integer(json_array_get(cond, 2)))
            {
                return NGX_ERROR;
            }

            minv = json_integer_value(json_array_get(cond, 1));
            maxv = json_integer_value(json_array_get(cond, 2));
            if ((json_int_t) form->file_len < minv
                || (json_int_t) form->file_len > maxv)
            {
                return NGX_DECLINED;
            }
            return NGX_OK;
        }

        if ((strcmp(op, "eq") == 0 || strcmp(op, "starts-with") == 0)
            && json_array_size(cond) == 3
            && json_is_string(json_array_get(cond, 1))
            && json_is_string(json_array_get(cond, 2)))
        {
            const char *field = json_string_value(json_array_get(cond, 1));
            const char *expected = json_string_value(json_array_get(cond, 2));
            const char *actual = s3_post_field_value(form, field);

            if (actual == NULL) {
                return NGX_DECLINED;
            }

            if (strcmp(op, "eq") == 0) {
                return strcmp(actual, expected) == 0 ? NGX_OK : NGX_DECLINED;
            }

            return strncmp(actual, expected, strlen(expected)) == 0
                   ? NGX_OK : NGX_DECLINED;
        }
    }

    (void) r;
    return NGX_ERROR;
}

static ngx_int_t
s3_post_validate_policy_json(ngx_http_request_t *r,
    ngx_http_s3_loc_conf_t *cf, const s3_post_form_t *form,
    u_char *policy_json, size_t policy_len)
{
    json_error_t  jerr;
    json_t       *root;
    json_t       *expiration;
    json_t       *conditions;
    size_t        i;
    time_t        exp;

    root = json_loadb((const char *) policy_json, policy_len, 0, &jerr);
    if (root == NULL || !json_is_object(root)) {
        if (root != NULL) {
            json_decref(root);
        }
        return NGX_ERROR;
    }

    expiration = json_object_get(root, "expiration");
    if (!json_is_string(expiration)
        || s3_post_parse_iso8601(json_string_value(expiration), &exp)
           != NGX_OK
        || ngx_time() > exp)
    {
        json_decref(root);
        return NGX_DECLINED;
    }

    conditions = json_object_get(root, "conditions");
    if (!json_is_array(conditions)) {
        json_decref(root);
        return NGX_ERROR;
    }

    for (i = 0; i < json_array_size(conditions); i++) {
        ngx_int_t rc;

        rc = s3_post_policy_condition(r, cf, form,
                                      json_array_get(conditions, i));
        if (rc != NGX_OK) {
            json_decref(root);
            return rc;
        }
    }

    json_decref(root);
    return NGX_OK;
}

static ngx_int_t
s3_post_parse_credential(const char *credential, char *date, size_t date_sz,
    char *region, size_t region_sz, const char **akid)
{
    const char *p1, *p2, *p3, *p4;
    size_t      len;

    p1 = strchr(credential, '/');
    if (p1 == NULL) {
        return NGX_ERROR;
    }
    *akid = credential;

    p2 = strchr(p1 + 1, '/');
    p3 = p2 ? strchr(p2 + 1, '/') : NULL;
    p4 = p3 ? strchr(p3 + 1, '/') : NULL;
    if (p2 == NULL || p3 == NULL || p4 == NULL
        || strcmp(p3 + 1, "s3/aws4_request") != 0)
    {
        return NGX_ERROR;
    }

    len = (size_t) (p2 - (p1 + 1));
    if (len != 8 || len >= date_sz) {
        return NGX_ERROR;
    }
    ngx_memcpy(date, p1 + 1, len);
    date[len] = '\0';

    len = (size_t) (p3 - (p2 + 1));
    if (len == 0 || len >= region_sz) {
        return NGX_ERROR;
    }
    ngx_memcpy(region, p2 + 1, len);
    region[len] = '\0';

    return NGX_OK;
}

static ngx_int_t
s3_post_verify_policy(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form)
{
    char        date[16];
    char        region[64];
    const char *akid;
    u_char      prefix_key[128];
    u_char      k1[32], k2[32], k3[32], k4[32], computed[32];
    char        computed_hex[65];
    ngx_str_t   src, decoded;
    ngx_int_t   rc;

    if (cf->access_key.len == 0) {
        return NGX_OK;
    }

    if (form->policy[0] == '\0' || form->algorithm[0] == '\0'
        || form->credential[0] == '\0' || form->amz_date[0] == '\0'
        || form->signature[0] == '\0')
    {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                             "Missing POST policy signature fields.");
    }

    if (strcmp(form->algorithm, "AWS4-HMAC-SHA256") != 0
        || strlen(form->signature) != 64
        || s3_post_parse_credential(form->credential, date, sizeof(date),
                                    region, sizeof(region), &akid) != NGX_OK)
    {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "InvalidRequest",
                             "Malformed POST policy signature fields.");
    }

    if ((size_t) (strchr(form->credential, '/') - akid) != cf->access_key.len
        || ngx_strncmp(cf->access_key.data, (u_char *) akid,
                       cf->access_key.len) != 0)
    {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "InvalidAccessKeyId",
                             "The access key ID does not exist.");
    }

    if (cf->region.len != strlen(region)
        || ngx_strncmp(cf->region.data, (u_char *) region, cf->region.len) != 0
        || ngx_strncmp((u_char *) form->amz_date, (u_char *) date, 8) != 0)
    {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                             "Credential scope does not match this endpoint.");
    }

    if (cf->secret_key.len + 4 > sizeof(prefix_key)) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(prefix_key, "AWS4", 4);
    ngx_memcpy(prefix_key + 4, cf->secret_key.data, cf->secret_key.len);

    if (!xrootd_hmac_sha256(prefix_key, cf->secret_key.len + 4,
                            (u_char *) date, strlen(date), k1)
        || !xrootd_hmac_sha256(k1, 32, (u_char *) region, strlen(region), k2)
        || !xrootd_hmac_sha256(k2, 32, (u_char *) "s3", 2, k3)
        || !xrootd_hmac_sha256(k3, 32, (u_char *) "aws4_request", 12, k4)
        || !xrootd_hmac_sha256(k4, 32, (u_char *) form->policy,
                               strlen(form->policy), computed))
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    xrootd_hex_encode(computed, 32, computed_hex);
    if (CRYPTO_memcmp(computed_hex, form->signature, 64) != 0) {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "SignatureDoesNotMatch",
                             "The request signature we calculated does not "
                             "match the signature you provided.");
    }

    src.data = (u_char *) form->policy;
    src.len = ngx_strlen(form->policy);
    decoded.len = src.len / 4 * 3 + 4;
    decoded.data = ngx_pnalloc(r->pool, decoded.len + 1);
    if (decoded.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_decode_base64(&decoded, &src) != NGX_OK) {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "InvalidPolicyDocument",
                             "The POST policy document is invalid.");
    }
    decoded.data[decoded.len] = '\0';

    rc = s3_post_validate_policy_json(r, cf, form, decoded.data, decoded.len);
    if (rc == NGX_DECLINED) {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                             "POST policy conditions were not satisfied.");
    }
    if (rc != NGX_OK) {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "InvalidPolicyDocument",
                             "The POST policy document is invalid.");
    }

    return NGX_OK;
}

static ngx_int_t
s3_post_write_object(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form, const char *fs_path, char *etag,
    size_t etag_sz)
{
    xrootd_staged_file_t staged;
    off_t                off = 0;
    size_t               remaining;
    u_char              *p;
    struct stat          sb;

    {
        char   parent[PATH_MAX];
        char  *last_slash;
        size_t flen = strlen(fs_path);

        if (flen < sizeof(parent)) {
            ngx_memcpy(parent, fs_path, flen + 1);
            last_slash = strrchr(parent, '/');
            if (last_slash && last_slash != parent) {
                *last_slash = '\0';
                if (xrootd_mkdir_recursive_confined_canon(
                        r->connection->log, cf->common.root_canon,
                        parent, 0755, NULL) != 0
                    && errno != EEXIST)
                {
                    return NGX_ERROR;
                }
            }
        }
    }

    if (xrootd_staged_open(r->connection->log, cf->common.root_canon,
                           fs_path, O_WRONLY, 0600, 16, &staged) != NGX_OK)
    {
        return NGX_ERROR;
    }

    remaining = form->file_len;
    p = form->file_data;
    while (remaining > 0) {
        ssize_t n = pwrite(staged.fd, p, remaining, off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            xrootd_staged_abort(r->connection->log, cf->common.root_canon,
                                &staged, 1);
            return NGX_ERROR;
        }
        if (n == 0) {
            errno = EIO;
            xrootd_staged_abort(r->connection->log, cf->common.root_canon,
                                &staged, 1);
            return NGX_ERROR;
        }

        p += n;
        off += n;
        remaining -= (size_t) n;
    }

    if (xrootd_staged_commit(r->connection->log, cf->common.root_canon,
                             &staged, fs_path) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (stat(fs_path, &sb) == 0) {
        s3_etag(&sb, etag, etag_sz);
        (void) s3_set_header(r, "ETag", etag);
    } else {
        etag[0] = '\0';
    }

    return NGX_OK;
}

static ngx_int_t
s3_post_send_empty(ngx_http_request_t *r, ngx_uint_t status)
{
    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

static ngx_int_t
s3_post_send_created(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form, const char *etag)
{
    ngx_buf_t    *b;
    ngx_chain_t   out;
    u_char       *xml;
    size_t        xml_capacity = 8192;
    size_t        xml_len = 0;
    ngx_int_t     rc;
    ngx_str_t     host;
    char          location[S3_MAX_KEY + 512];

    xml = ngx_pnalloc(r->pool, xml_capacity);
    if (xml == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    host = r->headers_in.host ? r->headers_in.host->value
                              : (ngx_str_t) ngx_null_string;
    if (host.len > 0) {
        snprintf(location, sizeof(location), "http://%.*s/%.*s/%s",
                 (int) host.len, host.data,
                 (int) cf->bucket.len, cf->bucket.data, form->key);
    } else {
        snprintf(location, sizeof(location), "/%.*s/%s",
                 (int) cf->bucket.len, cf->bucket.data, form->key);
    }

    XML_APPEND("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
               "<PostResponse>");
    XML_APPEND_ELEM("Location", location, strlen(location));
    XML_APPEND_ELEM("Bucket", cf->bucket.data, cf->bucket.len);
    XML_APPEND_ELEM("Key", form->key, strlen(form->key));
    XML_APPEND_ELEM("ETag", etag, strlen(etag));
    XML_APPEND("</PostResponse>");

    b = ngx_create_temp_buf(r->pool, xml_len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(b->pos, xml, xml_len);
    b->last = b->pos + xml_len;
    b->last_buf = 1;

    out.buf = b;
    out.next = NULL;

    r->headers_out.status = NGX_HTTP_CREATED;
    r->headers_out.content_length_n = (off_t) xml_len;
    r->headers_out.content_type.len = sizeof("application/xml") - 1;
    r->headers_out.content_type.data = (u_char *) "application/xml";
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static ngx_int_t
s3_post_send_success(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form, const char *etag)
{
    if (form->success_redirect[0] != '\0') {
        if (xrootd_http_str_has_ctl((u_char *) form->success_redirect,
                                    strlen(form->success_redirect)))
        {
            return s3_post_error(r, NGX_HTTP_BAD_REQUEST, "InvalidArgument",
                                 "success_action_redirect is invalid.");
        }
        if (s3_set_header(r, "Location", form->success_redirect) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return s3_post_send_empty(r, NGX_HTTP_SEE_OTHER);
    }

    if (form->success_status[0] == '\0'
        || strcmp(form->success_status, "204") == 0)
    {
        return s3_post_send_empty(r, NGX_HTTP_NO_CONTENT);
    }

    if (strcmp(form->success_status, "200") == 0) {
        return s3_post_send_empty(r, NGX_HTTP_OK);
    }

    if (strcmp(form->success_status, "201") == 0) {
        return s3_post_send_created(r, cf, form, etag);
    }

    return s3_post_error(r, NGX_HTTP_BAD_REQUEST, "InvalidArgument",
                         "success_action_status must be 200, 201, or 204.");
}

void
s3_post_object_body_handler(ngx_http_request_t *r)
{
    ngx_http_s3_loc_conf_t *cf;
    u_char                 *body;
    size_t                  body_len;
    char                    boundary[256];
    s3_post_form_t          form;
    char                    fs_path[PATH_MAX];
    char                    etag[48];
    ngx_int_t               rc;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_s3_module);
    ngx_memzero(&form, sizeof(form));

    if (s3_post_boundary(r, boundary, sizeof(boundary)) != NGX_OK) {
        s3_metrics_finalize_request_method(
            r, XROOTD_S3_METHOD_POST,
            s3_post_error(r, NGX_HTTP_BAD_REQUEST, "MalformedPOSTRequest",
                          "POST Object requires multipart/form-data."));
        return;
    }

    rc = xrootd_http_body_read_all(r, S3_POST_MAX_BODY, &body, &body_len);
    if (rc == NGX_DECLINED) {
        s3_metrics_finalize_request_method(
            r, XROOTD_S3_METHOD_POST,
            s3_post_error(r, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE,
                          "EntityTooLarge", "POST body is too large."));
        return;
    }
    if (rc != NGX_OK) {
        s3_metrics_finalize_request_method(r, XROOTD_S3_METHOD_POST,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (s3_post_parse_form(r, body, body_len, boundary, &form) != NGX_OK) {
        s3_metrics_finalize_request_method(
            r, XROOTD_S3_METHOD_POST,
            s3_post_error(r, NGX_HTTP_BAD_REQUEST, "MalformedPOSTRequest",
                          "The multipart form-data body is invalid."));
        return;
    }

    if (!form.have_file || form.key[0] == '\0') {
        s3_metrics_finalize_request_method(
            r, XROOTD_S3_METHOD_POST,
            s3_post_error(r, NGX_HTTP_BAD_REQUEST, "InvalidArgument",
                          "POST Object requires key and file fields."));
        return;
    }

    if (s3_post_expand_filename(r, &form) != NGX_OK
        || !s3_resolve_key(cf->common.root_canon, form.key,
                           fs_path, sizeof(fs_path)))
    {
        s3_metrics_finalize_request_method(
            r, XROOTD_S3_METHOD_POST,
            s3_post_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                          "Access Denied."));
        return;
    }

    rc = s3_post_verify_policy(r, cf, &form);
    if (rc != NGX_OK) {
        s3_metrics_finalize_request_method(r, XROOTD_S3_METHOD_POST, rc);
        return;
    }

    if (s3_post_write_object(r, cf, &form, fs_path, etag, sizeof(etag))
        != NGX_OK)
    {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        s3_metrics_finalize_request_method(r, XROOTD_S3_METHOD_POST,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    XROOTD_S3_METRIC_ADD(bytes_rx_total, form.file_len);

    s3_metrics_finalize_request_method(
        r, XROOTD_S3_METHOD_POST,
        s3_post_send_success(r, cf, &form, etag));
}
