/*
 * post_form_multipart.c - extracted concern
 * Phase-38 split of post_object.c; further split from post_form.c;
 * behavior-identical. Holds the RFC 2046 multipart/form-data wire parser
 * (part-header parsing, file capture, and the outer part loop).
 */
#include "s3_post_internal.h"


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
