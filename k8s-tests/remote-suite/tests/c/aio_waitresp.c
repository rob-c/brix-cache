/*
 * aio_waitresp.c — deferred-reply validation for the async engine (aio_io.c).
 *
 * WHAT: Connects to an endpoint, issues ONE kXR_ping through the aio loop with
 *       a caller-chosen deadline, and reports exactly how it completed.
 * WHY:  A server may acknowledge a request with kXR_waitresp and deliver the
 *       real reply later as an unsolicited kXR_attn(asynresp). nginx-xrootd
 *       answers synchronously, so this flow only shows up against a deferring
 *       server — the pytest harness (test_aio_waitresp.py) stands up a mock one
 *       and asserts on this driver's exit code / stderr.
 * HOW:  Standard bring-up (brix_connect, anonymous login) → brix_aconn_attach →
 *       blocking brix_aio_call. Keepalive and transport retries are disabled so
 *       the mock server's scripted frames are the only traffic that matters.
 *
 * Usage: aio_waitresp <endpoint> [deadline_ms]   (default deadline 30000)
 * Exit:  0 = completed kXR_ok; 1 = completed with an error (message on stderr);
 *        2 = harness/bring-up failure.
 */
#include "core/aio/aio.h"
#include "brix.h"
#include "protocols/root/protocol/protocol.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

int
main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: aio_waitresp <endpoint> [deadline_ms]\n");
        return 2;
    }
    const char *endpoint    = argv[1];
    int         deadline_ms = (argc > 2) ? atoi(argv[2]) : 30000;

    signal(SIGPIPE, SIG_IGN);   /* a dropped peer must not kill the process */

    brix_status st;
    brix_url    url;
    if (brix_endpoint_parse(endpoint, &url, &st) != 0) {
        fprintf(stderr, "endpoint parse: %s\n", st.msg);
        return 2;
    }

    brix_conn conn;
    if (brix_connect(&conn, &url, NULL, &st) != 0) {
        fprintf(stderr, "connect: %s\n", st.msg);
        return 2;
    }

    brix_loop *loop = brix_loop_create(&st);
    if (loop == NULL) {
        fprintf(stderr, "loop create: %s\n", st.msg);
        brix_close(&conn);
        return 2;
    }
    brix_aconn *ac = brix_aconn_attach(loop, &conn, &st);
    if (ac == NULL) {
        fprintf(stderr, "attach: %s\n", st.msg);
        brix_loop_destroy(loop);
        brix_close(&conn);
        return 2;
    }
    /* keepalive off + no transport retries: the mock's scripted frames are the
     * whole conversation, and a surprise heartbeat would desynchronize it. */
    brix_aconn_set_resilience(ac, deadline_ms, 0, 0);

    uint8_t hdr[XRD_REQUEST_HDR_LEN];
    memset(hdr, 0, sizeof(hdr));
    uint16_t rid = htons(kXR_ping);
    memcpy(hdr + 2, &rid, 2);

    uint16_t kxr  = 0;
    uint8_t *body = NULL;
    uint32_t blen = 0;
    int rc = brix_aio_call(ac, hdr, NULL, 0, &kxr, &body, &blen,
                           deadline_ms, &st);

    brix_aconn_close(ac);
    brix_loop_destroy(loop);
    brix_close(&conn);

    if (rc == 0 && kxr == kXR_ok) {
        printf("OK blen=%u\n", blen);
        free(body);
        return 0;
    }
    free(body);
    fprintf(stderr, "error: rc=%d kxr=%u %s\n", rc, kxr, st.msg);
    return 1;
}
