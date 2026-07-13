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
 * WHAT: The three per-part header values a multipart part can declare: the
 *       field `name` and optional `filename` (Content-Disposition parameters)
 *       and the part's `content_type` (Content-Type header).
 * WHY:  Bundling the parsed part-header buffers into one struct lets the header
 *       parser take a single out-parameter instead of threading three pointers
 *       and their sizes, keeping helper signatures under the parameter gate.
 *       The member sizes match the historic stack buffers exactly (behaviour
 *       frozen).
 */
typedef struct {
    char name[128];
    char filename[256];
    char content_type[256];
} pf_part_headers_t;


/*
 * WHAT: Parse one multipart part header line (already NUL-terminated in `line`)
 *       into the part's Content-Disposition name/filename and Content-Type.
 * WHY:  Splitting the per-line header dispatch out of the part loop keeps
 *       pf_parse_part_headers() flat; the two header types we recognise and
 *       their bounds checks live in one place.
 * HOW:  Content-Disposition supplies the field `name` and optional `filename`
 *       (basename-reduced); Content-Type fills `content_type` after skipping
 *       leading whitespace. Unrecognised headers are ignored.
 * Returns NGX_OK on success (hdr possibly updated), NGX_ERROR on an over-long
 * or malformed recognised header value.
 */
static ngx_int_t
pf_parse_header_line(const char *line, pf_part_headers_t *hdr)
{
    if (ngx_strncasecmp((u_char *) line,
                        (u_char *) "Content-Disposition:",
                        sizeof("Content-Disposition:") - 1) == 0)
    {
        if (s3_post_extract_param(line, "name", hdr->name, sizeof(hdr->name))
            == NGX_ERROR
            || s3_post_extract_param(line, "filename", hdr->filename,
                                     sizeof(hdr->filename)) == NGX_ERROR)
        {
            return NGX_ERROR;
        }
        if (hdr->filename[0] != '\0') {
            s3_post_basename(hdr->filename);
        }
        return NGX_OK;
    }

    if (ngx_strncasecmp((u_char *) line, (u_char *) "Content-Type:",
                        sizeof("Content-Type:") - 1) == 0)
    {
        const char *v = line + sizeof("Content-Type:") - 1;
        while (*v == ' ' || *v == '\t') {
            v++;
        }
        if (ngx_strlen(v) >= sizeof(hdr->content_type)) {
            return NGX_ERROR;
        }
        ngx_cpystrn((u_char *) hdr->content_type, (u_char *) v,
                    sizeof(hdr->content_type));
    }

    return NGX_OK;
}


/*
 * WHAT: Read one multipart part's header block (from *pos up to the blank line
 *       separating headers from body) into `hdr`.
 * WHY:  The header block is a bounded CRLF-terminated line loop; keeping it in
 *       its own helper flattens the part loop in s3_post_parse_form().
 * HOW:  Each CRLF-terminated line is copied into a bounded stack buffer and
 *       dispatched via pf_parse_header_line(); a zero-length line ends the
 *       block. On success *pos is advanced past the blank line's CRLF to the
 *       first body byte.
 * Returns NGX_OK (*pos advanced), or NGX_ERROR on a missing CRLF or over-long
 * line/header.
 */
static ngx_int_t
pf_parse_part_headers(u_char **pos, u_char *end, pf_part_headers_t *hdr)
{
    u_char *p = *pos;

    for (;;) {
        u_char *line_end;
        size_t  line_len;
        char    line[1024];

        line_end = s3_memmem(p, (size_t) (end - p), (u_char *) "\r\n", 2);
        if (line_end == NULL) {
            return NGX_ERROR;
        }

        line_len = (size_t) (line_end - p);
        if (line_len == 0) {
            /* Blank line: headers end here; part body starts after CRLF. */
            *pos = line_end + 2;
            return NGX_OK;
        }
        if (line_len >= sizeof(line)) {
            return NGX_ERROR;
        }

        ngx_memcpy(line, p, line_len);
        line[line_len] = '\0';
        p = line_end + 2;

        if (pf_parse_header_line(line, hdr) != NGX_OK) {
            return NGX_ERROR;
        }
    }
}


/*
 * WHAT: Record the single "file" part into `form`, referencing its bytes in
 *       place rather than copying them.
 * WHY:  The file body is potentially large binary content; zero-copy avoids a
 *       second buffer. Keeping this in a helper matches s3_post_store_field()
 *       for the non-file parts and keeps the part loop's dispatch flat.
 * HOW:  form->file_data points into the request body span [content, content+len)
 *       (so `body` must outlive `form` — it does, both live for the request);
 *       filename and content_type are copied into their bounded members.
 */
static void
pf_capture_file(s3_post_form_t *form, u_char *content, size_t content_len,
    const char *filename, const char *content_type)
{
    form->file_data = content;
    form->file_len = content_len;
    form->have_file = 1;
    ngx_cpystrn((u_char *) form->filename, (u_char *) filename,
                sizeof(form->filename));
    ngx_cpystrn((u_char *) form->content_type, (u_char *) content_type,
                sizeof(form->content_type));
}


/*
 * WHAT: Consume one complete multipart part from *pos: its header block, its
 *       body (up to `delim`), and the delimiter that follows.
 * WHY:  Isolating a single part's framing keeps s3_post_parse_form()'s outer
 *       loop short and under the complexity gate; the "another part follows"
 *       vs "closing delimiter" decision lives here in one place.
 * HOW:  Parse headers via pf_parse_part_headers(); the body runs to the next
 *       "\r\n--BOUNDARY"; route the file part via pf_capture_file() and other
 *       fields via s3_post_store_field(); then advance *pos past the delimiter.
 * Returns NGX_OK when a normal inter-part CRLF follows (another part expected),
 * NGX_DONE at the closing "--BOUNDARY--", or NGX_ERROR on any framing violation.
 */
static ngx_int_t
pf_parse_one_part(u_char **pos, u_char *end, const char *delim,
    size_t delim_len, s3_post_form_t *form)
{
    pf_part_headers_t hdr = { "", "", "" };
    u_char           *content;
    u_char           *next;
    size_t            content_len;

    if (pf_parse_part_headers(pos, end, &hdr) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Every part must have declared a field name in its headers. */
    if (hdr.name[0] == '\0') {
        return NGX_ERROR;
    }

    /* Part body runs from *pos up to the next "\r\n--BOUNDARY" delimiter. */
    content = *pos;
    next = s3_memmem(content, (size_t) (end - content),
                     (u_char *) delim, delim_len);
    if (next == NULL) {
        return NGX_ERROR;
    }

    content_len = (size_t) (next - content);
    if (strcmp(hdr.name, "file") == 0) {
        pf_capture_file(form, content, content_len, hdr.filename,
                        hdr.content_type);
    } else if (s3_post_store_field(form, hdr.name, content, content_len)
               != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Advance past the delimiter and decide what follows it. */
    *pos = next + delim_len;
    if ((size_t) (end - *pos) >= 2 && (*pos)[0] == '-' && (*pos)[1] == '-') {
        return NGX_DONE;            /* "--BOUNDARY--": end of the multipart body */
    }
    if ((size_t) (end - *pos) < 2 || (*pos)[0] != '\r' || (*pos)[1] != '\n') {
        return NGX_ERROR;           /* delimiter must be followed by "--" or CRLF */
    }
    *pos += 2;                      /* CRLF: another part follows */
    return NGX_OK;
}


/*
 * WHAT: Parse a multipart/form-data body into `form` — both the named form
 *       fields and the single "file" part (whose bytes are referenced in place).
 * WHY:  This is the wire parser for browser POST uploads; it must handle binary
 *       file content and is hostile-input facing, so every span is bounds-checked.
 * HOW (RFC 2046 framing):
 *   - "--BOUNDARY" CRLF opens the body (marker).
 *   - Each part is a CRLF-terminated header block, a blank line, then the body,
 *     followed by "\r\n--BOUNDARY" (delim) introducing the next part.
 *   - A trailing "--" after a delimiter ("\r\n--BOUNDARY--") closes the body.
 *   Each part is consumed by pf_parse_one_part(); NGX_DONE from it signals the
 *   closing delimiter.
 * Returns NGX_OK when the closing delimiter is reached, NGX_ERROR on any
 * framing violation or oversized header.
 */
ngx_int_t
s3_post_parse_form(ngx_http_request_t *r, u_char *body, size_t body_len,
    const char *boundary, s3_post_form_t *form)
{
    char      marker[256];
    char      delim[258];
    size_t    marker_len, delim_len;
    u_char   *pos, *end;
    ngx_int_t rc;

    /* marker = opening "--BOUNDARY"; delim = inter-part "\r\n--BOUNDARY". */
    marker_len = (size_t) snprintf(marker, sizeof(marker), "--%s", boundary);
    delim_len = (size_t) snprintf(delim, sizeof(delim), "\r\n--%s", boundary);
    if (marker_len >= sizeof(marker) || delim_len >= sizeof(delim)) {
        return NGX_ERROR;
    }

    pos = body;
    end = body + body_len;

    /* Body must begin with the opening marker followed by CRLF. */
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

    /* Outer loop: one iteration consumes one complete part. */
    while (pos < end) {
        rc = pf_parse_one_part(&pos, end, delim, delim_len, form);
        if (rc == NGX_DONE) {
            (void) r;
            return NGX_OK;          /* closing "--BOUNDARY--" reached */
        }
        if (rc != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* Ran off the end without seeing the closing "--BOUNDARY--": malformed. */
    (void) r;
    return NGX_ERROR;
}
