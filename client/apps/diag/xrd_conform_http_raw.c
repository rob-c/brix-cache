/* Phase-118 deliberately malformed HTTP request adapter. */
#include "xrd_conform_internal.h"
#include "core/compat/host_format.h"

/* WHAT: Send one deliberately caller-framed HTTP request through libbrix.
 * WHY: Truncation and malformed-chunk assertions cannot use the normal codec.
 * HOW: Add only safe endpoint/auth headers, charge exact bytes, then delegate
 *      transport, TLS and response parsing to the shared raw-request seam. */
int
xrd_conform_http_raw_request(xrd_conform_execution *execution,
    const brix_weburl *url, const char *token,
    const xrd_conform_raw_http *request, brix_http_resp *response,
    brix_status *status)
{
    char authority[300];
    char proxy[XRDC_PATH_MAX];
    char reason[64];
    char *authentication;
    char *wire;
    const char *header_failure = NULL;
    const char *client_cert = brix_web_proxy_pem(proxy, sizeof(proxy));
    size_t head_length;
    size_t wire_length;
    int needed;
    int rc;

    authentication = xrd_conform_http_headers(url, request->method, token,
        request->fields, &header_failure);
    if (authentication == NULL) {
        brix_status_set(status, XRDC_EAUTH, 0, "%s",
            header_failure == NULL ? "HTTP header allocation failed"
                                   : header_failure);
        return -1;
    }
    brix_format_host_port(url->host, (uint16_t) url->port,
        authority, sizeof(authority));
    needed = snprintf(NULL, 0, "%s %s HTTP/1.1\r\nHost: %s\r\n"
        "Connection: close\r\n%s\r\n", request->method, request->target,
        authority, authentication);
    if (needed < 0 || (size_t) needed > SIZE_MAX - request->body_length) {
        free(authentication);
        brix_status_set(status, XRDC_EUSAGE, 0,
            "raw HTTP request length overflow");
        return -1;
    }
    head_length = (size_t) needed;
    wire_length = head_length + request->body_length;
    if (wire_length > SIZE_MAX - request->expected_bytes
        || !xrd_conform_reserve(execution,
            wire_length + request->expected_bytes, reason, sizeof(reason))) {
        free(authentication);
        brix_status_set(status, XRDC_EUSAGE, 0, "%s",
            wire_length > SIZE_MAX - request->expected_bytes
                ? "raw HTTP request/response length overflow" : reason);
        return -1;
    }
    wire = malloc(wire_length + 1);
    if (wire == NULL) {
        free(authentication);
        brix_status_set(status, XRDC_EPROTO, 0,
            "raw HTTP request allocation failed");
        return -1;
    }
    snprintf(wire, head_length + 1, "%s %s HTTP/1.1\r\nHost: %s\r\n"
        "Connection: close\r\n%s\r\n", request->method, request->target,
        authority, authentication);
    if (request->body_length != 0)
        memcpy(wire + head_length, request->body, request->body_length);
    free(authentication);
    rc = brix_http_raw_req(url->host, url->port, url->tls, wire, wire_length,
        request->finish_write, 2000, execution->run->opts.verify_host,
        brix_resolve_ca_dir(execution->run->opts.ca_dir), client_cert,
        response, status);
    free(wire);
    return rc;
}
