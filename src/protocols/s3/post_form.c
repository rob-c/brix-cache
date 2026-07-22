/*
 * post_form.c - extracted concern
 * Phase-38 split of post_object.c; behavior-identical.
 */
#include "s3_post_internal.h"


/*
 * WHAT: Resolve a policy-condition field name to its submitted form value.
 * WHY:  POST-policy conditions reference fields the same way the form submits
 *       them; AWS writes some condition keys with a leading '$' (e.g. "$key"),
 *       which we strip so "$key" and "key" map to the same value. The special
 *       "key" and "Content-Type" fields live in dedicated struct members rather
 *       than the generic fields[] table, so they are checked explicitly.
 * Returns the value string, or NULL if no such field was submitted.
 */
const char *
s3_post_field_value(const s3_post_form_t *form, const char *name)
{
    ngx_uint_t i;

    /* AWS policy syntax writes condition keys as "$name"; normalise to "name". */
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


/*
 * WHAT: Record one submitted form field (non-file part) into `form`.
 * WHY:  Every field is appended to the generic fields[] table (so policy
 *       conditions can later look it up by name), AND the auth-relevant fields
 *       (key, policy, x-amz-*) are mirrored into dedicated struct members for
 *       direct, fast access during signature verification. HOW: validate+copy
 *       once into the table (subject to the 64-field cap), then dispatch on the
 *       known field names to also populate the typed members.
 * Returns NGX_OK, or NGX_ERROR on a missing name or a copy that overflows.
 */
ngx_int_t
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


/*
 * WHAT: Copy the value of a "boundary=" parameter (whose value begins at `p`,
 *       just past the '=') into `boundary`, handling quoted and token forms.
 * WHY:  Isolating the value-extraction keeps the parameter-walk in
 *       s3_post_boundary() flat and under the complexity gate; the two value
 *       encodings (quoted-string / bare token) and the length cap live here.
 * HOW:  A leading '"' selects the quoted form (value up to the closing '"');
 *       otherwise the token runs to the next separator/whitespace. The length
 *       is capped (RFC 2046 limits boundaries to 70 chars, we allow up to 200)
 *       to bound the caller's stack buffer, then copied NUL-terminated.
 * Returns NGX_OK with `boundary` filled; NGX_ERROR if the value is unterminated,
 * empty, or too long.
 */
static ngx_int_t
pf_scan_boundary(u_char *p, u_char *end, char *boundary, size_t boundary_sz)
{
    u_char *q;
    size_t  len;

    if (p < end && *p == '"') {
        /* Quoted form: value is everything up to the closing '"'. */
        p++;
        q = p;
        while (q < end && *q != '"') {
            q++;
        }
        if (q == end) {
            return NGX_ERROR;               /* unterminated quoted boundary */
        }
        len = (size_t) (q - p);
    } else {
        /* Token form: value ends at the next separator/whitespace. */
        q = p;
        while (q < end && *q != ';' && *q != ' ' && *q != '\t') {
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


/*
 * WHAT: Extract the multipart boundary from the request Content-Type header.
 * WHY:  POST Object only accepts "multipart/form-data; boundary=...". The
 *       boundary may be quoted ("...") or a bare token; both forms must be
 *       handled, and length is capped (RFC 2046 limits boundaries to 70 chars,
 *       we allow up to 200) to bound the stack buffer.
 * HOW:  Verify the media type, then walk the ';'-separated parameter list to
 *       find "boundary="; delegate the quoted/token value copy to
 *       pf_scan_boundary().
 * Returns NGX_OK with `boundary` filled; NGX_DECLINED if not multipart / no
 * boundary param; NGX_ERROR if the boundary is malformed or too long.
 */
ngx_int_t
s3_post_boundary(ngx_http_request_t *r, char *boundary, size_t boundary_sz)
{
    ngx_table_elt_t *ct;
    u_char          *p, *end;

    ct = brix_http_find_header(r, "Content-Type",
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

    /* Walk the ';'-separated parameters looking for "boundary=". */
    while (p < end) {
        /* Skip leading separators/whitespace before a parameter token. */
        while (p < end && (*p == ';' || *p == ' ' || *p == '\t')) {
            p++;
        }
        if ((size_t) (end - p) >= sizeof("boundary=") - 1
            && ngx_strncasecmp(p, (u_char *) "boundary=",
                               sizeof("boundary=") - 1) == 0)
        {
            p += sizeof("boundary=") - 1;
            return pf_scan_boundary(p, end, boundary, boundary_sz);
        }

        /* Not this parameter — advance to the next ';' and retry. */
        while (p < end && *p != ';') {
            p++;
        }
    }

    return NGX_DECLINED;
}


/*
 * WHAT: Extract a ';'-delimited parameter (e.g. name= / filename=) from a
 *       Content-Disposition header line into `out`.
 * WHY:  Each multipart part header carries its field name and optional filename
 *       as Content-Disposition parameters; we need them to route the part. Value
 *       may be quoted or a bare token. HOW: scan ';'-separated params for one
 *       whose token equals `name` followed by '='; copy the quoted/token value.
 * Returns NGX_OK if found (out filled), NGX_DECLINED if absent, NGX_ERROR if
 * the value does not fit (out is pre-emptied so callers can ignore DECLINED).
 */
ngx_int_t
s3_post_extract_param(const char *line, const char *name,
    char *out, size_t outsz)
{
    const char *p;
    size_t      nlen;

    out[0] = '\0';
    nlen = strlen(name);
    p = line;

    /* Each iteration positions p at a ';' beginning the next parameter. */
    while ((p = strchr(p, ';')) != NULL) {
        p++;
        while (*p == ' ' || *p == '\t') {
            p++;
        }

        if (ngx_strncasecmp((u_char *) p, (u_char *) name, nlen) == 0
            && p[nlen] == '=')
        {
            const char *v = p + nlen + 1;       /* +1 steps over the '=' */
            const char *e;
            size_t      len;

            if (*v == '"') {
                /* Quoted value: spans to the closing '"'. */
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


/*
 * WHAT: Substitute every "${filename}" token in form->key with the uploaded
 *       part's (already basename-reduced) filename, writing back into form->key.
 * WHY:  The S3 POST API lets the key template reference the upload's filename.
 *       Expansion must be bounded (S3_MAX_KEY) and the result must not contain
 *       control characters, since the key becomes a filesystem path.
 * HOW:  Walk the template; copy literal spans, and at each token emit the
 *       filename instead. Every append is length-checked against `left` so a
 *       too-long result fails cleanly rather than overflowing `expanded`.
 * Returns NGX_OK (form->key updated), or NGX_ERROR on overflow / control chars.
 */
ngx_int_t
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
            /* No further token: copy the remaining literal tail (incl. NUL). */
            n = strlen(src);
            if (n >= left) {
                return NGX_ERROR;
            }
            ngx_memcpy(dst, src, n + 1);
            break;
        }

        /* Copy the literal span before the token, then the filename in its place. */
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

    if (brix_http_str_has_ctl((u_char *) expanded, strlen(expanded))) {
        return NGX_ERROR;
    }

    ngx_cpystrn((u_char *) form->key, (u_char *) expanded,
                sizeof(form->key));
    (void) r;
    return NGX_OK;
}

/*
 * The multipart/form-data wire parser (s3_post_parse_form and its part-framing
 * helpers) lives in the sibling post_form_multipart.c.
 */
