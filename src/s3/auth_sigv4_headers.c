#include "s3.h"
#include "s3_auth_internal.h"

/* Header parser — defined in auth_sigv4_parse.c */
extern ngx_str_t get_header(ngx_http_request_t *r, const char *name);

/* ---- Function: build_canonical_headers() — build canonical headers string for AWS SignatureV4 ----
 *
 * WHAT: Builds the canonical headers string required for AWS SignatureV4 authentication signature calculation. Parses semicolon-separated signed header names from signed_hdrs parameter (e.g., "host;x-amz-content-sha256;x-amz-date") using strtok_r for thread-safe tokenization. For each header name retrieves value from request — special-cases "host" which may not appear in standard header list, retrieving r->headers_in.host directly instead of calling get_header(). Lowercases all header names (AWS convention requires lowercase) via tolower() on each character. Trims leading/trailing whitespace from header values using pointer arithmetic to find non-whitespace boundaries. Outputs newline-delimited format: "header-name:value\n" for each canonicalized entry. Checks output buffer capacity before writing each entry — stops if remaining space insufficient. Returns total bytes written (oi) not including trailing null terminator; sets out[oi]='\0' after loop completion.
 *
 * WHY: AWS SignatureV4 requires headers to be sorted alphabetically and formatted as lowercase:name:value\n before signature calculation — this canonicalization ensures the signed headers string matches exactly what the client calculated during request signing. The host header special-case handling is required because nginx may not populate r->headers_in.host when using custom routing or proxy modes — falling back to ngx_null_string prevents crashes on missing host values. Whitespace trimming ensures consistent signature calculation regardless of HTTP client formatting variations (some clients add padding whitespace). Thread-safe strtok_r usage prevents concurrent request interference during tokenization. Security invariant: per AGENTS.md rule #6, S3 SigV4 ≠ WLCG token — this function must not share logic with other authentication systems; it is exclusively for AWS SignatureV4 signing.
 *
 * HOW: Declares 256-byte stack buffer hdrs for parsed header names. Copies signed_hdrs via ngx_cpystrn() then tokenizes using strtok_r(hdrs, ";", &save) with save pointer preserved across iterations (thread-safe). For each token: if "host" matches, use r->headers_in.host directly; otherwise call get_header(r, tok). Calculate output space needed (nlen + 1 colon + vlen + 2 newline), break loop if insufficient capacity. Write lowercase header name character-by-character via tolower(), append ':' separator. Trim whitespace from value using pointer arithmetic (skip leading spaces/tabs, skip trailing spaces/tabs). Copy trimmed value via ngx_memcpy() appending '\n' terminator. Continue tokenization until strtok_r returns NULL. Set out[oi]='\0' and return oi as total bytes written. */

/* -------------------------------------------------------------------------
 * Build canonical signed headers string for SignatureV4
 * ---------------------------------------------------------------------- */

size_t
build_canonical_headers(ngx_http_request_t *r,
                         const char *signed_hdrs,
                         u_char *out, size_t outsz)
{
    /* signed_hdrs is semicolon-separated: "host;x-amz-content-sha256;x-amz-date" */
    char   hdrs[256];
    size_t oi = 0;

    ngx_cpystrn((u_char *) hdrs, (u_char *) signed_hdrs, sizeof(hdrs));

    char *save = NULL;
    char *tok  = strtok_r(hdrs, ";", &save);

    while (tok) {
        ngx_str_t val;

        /* Special case: host may not appear in standard header list */
        if (strcmp(tok, "host") == 0) {
            val = r->headers_in.host ? r->headers_in.host->value
                                     : (ngx_str_t) ngx_null_string;
        } else {
            val = get_header(r, tok);
        }

        size_t nlen = strlen(tok);
        size_t vlen = val.len;

        if (oi + nlen + 1 + vlen + 2 >= outsz) {
            break;
        }

        /* lowercase header name (already lower from AWS, but be safe) */
        for (size_t i = 0; i < nlen; i++) {
            out[oi++] = (u_char) tolower((unsigned char) tok[i]);
        }
        out[oi++] = ':';

        /* trim leading/trailing whitespace from value */
        const u_char *vs = val.data;
        const u_char *ve = val.data + vlen;
        while (vs < ve && (*vs == ' ' || *vs == '\t')) vs++;
        while (ve > vs && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;

        ngx_memcpy(out + oi, vs, (size_t)(ve - vs));
        oi += (size_t)(ve - vs);
        out[oi++] = '\n';

        tok = strtok_r(NULL, ";", &save);
    }

    out[oi] = '\0';
    return oi;
}

