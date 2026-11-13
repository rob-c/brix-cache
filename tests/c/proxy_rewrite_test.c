/* WHAT: Finite wire-buffer driver for the actual proxy path rewriting helpers.
 * WHY: Verify framing, ownership and failed-allocation behavior independently
 *      of a live upstream. No path-rewrite implementation is duplicated here.
 * HOW: Build a marked request, call production, verify untouched header fields,
 *      then return the transformed bytes and buffer identity to pytest. */
#include "net/proxy/proxy_internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *__real_ngx_alloc(size_t size, ngx_log_t *log);

/* WHAT: Inject an explicit allocation failure, otherwise use nginx's allocator.
 * WHY: The failure contract must preserve the caller's original request.
 * HOW: GNU link wrapping selects the failure only in a dedicated test process. */
void *
__wrap_ngx_alloc(size_t size, ngx_log_t *log)
{
    if (getenv("BRIX_TEST_ALLOC_FAIL") != NULL) {
        return NULL;
    }
    return __real_ngx_alloc(size, log);
}

/* WHAT: Verify response framing and print the actual payload as hex bytes.
 * WHY: Prefix changes must not alter stream/opcode bytes or retain a stale dlen.
 * HOW: Compare the sentinel header and decoded dlen before emitting the body. */
static int
report_result(const u_char *result, size_t total, int same)
{
    uint32_t length;
    for (size_t index = 0; index < 20; index++) {
        if (result[index] != 0x5a) {
            return 4;
        }
    }
    memcpy(&length, result + 20, sizeof(length));
    if (ntohl(length) != total - XRD_REQUEST_HDR_LEN) {
        return 5;
    }
    printf("%zu:%d:", total, same);
    for (size_t index = XRD_REQUEST_HDR_LEN; index < total; index++) {
        printf("%02x", result[index]);
    }
    putchar('\n');
    return 0;
}

/* WHAT: Apply the requested operation to a fresh complete wire buffer.
 * WHY: Single-path and prepare rewrites have deliberately different ownership.
 * HOW: Build real configuration, retain identity before cleanup, free according
 *      to the published API, and let assertion failures produce a nonzero exit. */
int
main(int argc, char **argv)
{
    if (argc != 5) {
        return 2;
    }
    ngx_connection_t connection = {0};
    ngx_log_t log = {0};
    connection.log = &log;
    ngx_stream_brix_srv_conf_t config = {0};
    config.proxy.path_strip.data = (u_char *) argv[2];
    config.proxy.path_strip.len = strlen(argv[2]);
    config.proxy.path_add.data = (u_char *) argv[3];
    config.proxy.path_add.len = strlen(argv[3]);
    size_t payload = strlen(argv[4]);
    size_t total = XRD_REQUEST_HDR_LEN + payload, rewritten = 0;
    u_char *request = malloc(total);
    if (request == NULL) {
        return 3;
    }
    memset(request, 0x5a, XRD_REQUEST_HDR_LEN);
    uint32_t length = htonl((uint32_t) payload);
    memcpy(request + 20, &length, sizeof(length));
    memcpy(request + XRD_REQUEST_HDR_LEN, argv[4], payload);
    uintptr_t original_address = (uintptr_t) request;
    u_char *result;
    int prepare = strcmp(argv[1], "prepare") == 0;
    if (prepare) {
        result = proxy_rewrite_prepare_payload(&connection, &config, request,
                                               total, &rewritten);
    } else {
        result = proxy_rewrite_path(&connection, &config, request, total,
                                    XRD_REQUEST_HDR_LEN, payload, &rewritten);
    }
    int same = (uintptr_t) result == original_address;
    int status = report_result(result, rewritten, same);
    if (!prepare && !same) {
        free(request);
    }
    free(result);
    return status;
}
