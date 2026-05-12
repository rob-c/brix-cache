#include "../ngx_xrootd_module.h"

#include <string.h>

int
xrootd_extract_path(ngx_log_t *log, const u_char *payload, size_t payload_len,
                    char *out, size_t outsz, ngx_flag_t strip_cgi)
{
    const u_char *nul;
    const u_char *qmark;
    size_t        copy_len;

    if (payload == NULL || payload_len == 0 || out == NULL || outsz < 2) {
        return 0;
    }

    if (payload_len > XROOTD_MAX_PATH) {
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
