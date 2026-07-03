#include "core/ngx_brix_module.h"

#include <string.h>

/*
 *
 * WHAT: Extracts and sanitizes a filesystem path string from XRootD wire protocol payload. Validates input parameters (non-NULL pointers, minimum buffer size of 2 bytes). Rejects payloads exceeding BRIX_MAX_PATH length with warning log entry. Handles NUL termination detection — if payload contains embedded NUL character not at the end position, rejects it as potentially malicious or corrupted data. When strip_cgi flag is enabled, truncates payload at '?' character to remove CGI query parameters (only keeps path portion before query string). Validates final copy length against output buffer capacity — rejects zero-length or overflow paths with warning log entry. Copies extracted path to output buffer via ngx_memcpy() and null-terminates. Returns 1 on success, 0 on any rejection/validation failure.
 *
 * WHY: Wire protocol payloads may contain embedded NUL characters, CGI query parameters, or oversized strings that must be sanitized before use as filesystem paths. This helper provides a single validation point ensuring all extracted paths are safe for downstream operations (resolve_path, open). The strip_cgi option handles cases where clients send paths with query suffixes — only the path portion is used for filesystem operations. BRIX_MAX_PATH length check prevents buffer overflow attacks on subsequent processing stages. Thread safety: pure function with no shared state — operates only on provided payload and local stack variables. */

int
brix_extract_path(ngx_log_t *log, const u_char *payload, size_t payload_len,
                    char *out, size_t outsz, ngx_flag_t strip_cgi)
{
    const u_char *nul;
    const u_char *qmark;
    size_t        copy_len;

    if (payload == NULL || payload_len == 0 || out == NULL || outsz < 2) {
        return 0;
    }

    if (payload_len > BRIX_MAX_PATH) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: path payload too long (%uz bytes)",
                      payload_len);
        return 0;
    }

    nul = memchr(payload, '\0', payload_len);
    if (nul != NULL) {
        if (nul != payload + payload_len - 1) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: rejecting path payload with embedded NUL");
            return 0;
        }

        payload_len--;
    }

    copy_len = payload_len;

    if (strip_cgi) {
        qmark = memchr(payload, '?', payload_len);
        if (qmark != NULL) {
            copy_len = (size_t) (qmark - payload);
        }
    }

    if (copy_len == 0 || copy_len >= outsz) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: invalid path payload length (%uz bytes)",
                      copy_len);
        return 0;
    }

    ngx_memcpy(out, payload, copy_len);
    out[copy_len] = '\0';

    return 1;
}
/* HOW: Checks payload==NULL || payload_len==0 || out==NULL || outsz<2 → returns 0 (invalid params). If payload_len>BRIX_MAX_PATH → log warn "path payload too long" + returns 0. memchr(payload,'\0',payload_len) — if nul found && nul!=payload+payload_len-1 (embedded NUL not at end) → log warn "rejecting embedded NUL" + returns 0; if nul==last byte payload_len-- to strip trailing NUL. copy_len=payload_len. If strip_cgi: memchr(payload,'?',payload_len) — if qmark found copy_len=qmark-payload (truncates at query string). If copy_len==0 || copy_len>=outsz → log warn "invalid path length" + returns 0. ngx_memcpy(out,payload,copy_len); out[copy_len]='\0' (null-terminates). Returns 1 on success. */
