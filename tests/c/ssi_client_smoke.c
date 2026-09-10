/*
 * ssi_client_smoke.c — wire driver for the native SSI client
 * (client/lib/protocols/ssi/ssi_client.c).
 *
 * WHAT: opens "/.ssi/<service>", submits a request, prints one line per reply
 *       frame, drains a pending body, and closes. Also carries two deliberate
 *       negatives the library itself cannot express, because the library is
 *       correct by construction: `cancel` and `badcarrier`.
 * WHY:  the SSI plane's only wire client used to be the C++ libXrdSsi
 *       (tests/ssi_client.cc). The pure-C suite could not reach its own
 *       server's SSI surface. test_phase115_ssi_client.py asserts on this
 *       driver's stdout, so the transcript is a contract, not debug output.
 * HOW:  every field is hex so a payload can never be confused with a delimiter
 *       or lost to shell quoting; the pytest side decodes and compares bytes.
 *
 * Usage: ssi_client_smoke <endpoint> <service> <request> [mode]
 *        mode: run (default) | cancel | badcarrier
 * Exit:  0 = the mode's expected outcome; 1 = a protocol/library failure
 *        (message on stderr); 2 = harness/bring-up failure.
 */
#include "brix.h"
#include "protocols/ssi/ssi_client.h"
#include "protocols/root/protocol/protocol.h"
#include "protocols/root/protocol/codec/wire_codec.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
put_hex(const unsigned char *p, uint32_t n)
{
    uint32_t i;

    for (i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }
}

static const char *
ev_name(brix_ssi_ev ev)
{
    if (ev == BRIX_SSI_EV_ALERT) { return "alert"; }
    if (ev == BRIX_SSI_EV_PENDING) { return "pending"; }
    return "response";
}

/*
 * The security negative: the RRInfo control word belongs in the kXR_query
 * PAYLOAD, not in the request body's trailing reserved bytes (its position on
 * the read/write carrier). Put it in the wrong place and the server must refuse
 * — brix_ssi_query rejects a payload shorter than the control word — rather
 * than decode whatever happens to sit in the payload as a command. Built by
 * hand here precisely because ssi_client.c cannot get this wrong.
 */
static int
send_bad_carrier(brix_ssi_sess *s, brix_conn *c)
{
    ClientQueryRequest req;
    unsigned char      off8[BRIX_SSI_RRINFO_LEN];
    uint8_t           *body = NULL;
    uint32_t           blen = 0;
    uint16_t           status = 0;
    brix_status        st;
    brix_resp_out      out = { &status, &body, &blen };

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_query);
    {
        xrdw_query_req_t q = { .infotype = (uint16_t) kXR_Qopaqug };
        memcpy(q.fhandle, s->fhandle, XRDW_FHANDLE_LEN);
        xrdw_query_req_pack(&q, ((ClientRequestHdr *) &req)->body);
    }
    /* The control word, in the body's reserved tail instead of the payload. */
    brix_ssi_rrinfo_encode(BRIX_SSI_CMD_RWT, s->req_id, 0, off8);
    memcpy(((ClientRequestHdr *) &req)->body + 8, off8, BRIX_SSI_RRINFO_LEN);

    if (brix_roundtrip(c, &req, NULL, &out, &st) == 0) {
        free(body);
        fprintf(stderr, "badcarrier: server ACCEPTED a misplaced control word "
                        "(status %u, %u bytes)\n", status, blen);
        return 1;
    }
    printf("badcarrier refused kxr=%d msg=%s\n", st.kxr, st.msg);
    return 0;
}

static int
drain_pending(brix_ssi_sess *s)
{
    unsigned char buf[4096];
    brix_status   st;
    int           n;

    for (;;) {
        n = brix_ssi_read(s, buf, sizeof(buf), &st);
        if (n < 0) {
            fprintf(stderr, "read: %s\n", st.msg);
            return 1;
        }
        printf("read n=%d data=", n);
        put_hex(buf, (uint32_t) n);
        printf("\n");
        if (n == 0) {
            return 0;
        }
    }
}

static int
collect(brix_ssi_sess *s)
{
    brix_status st;

    for (;;) {
        brix_ssi_reply r;

        if (brix_ssi_await(s, &r, &st) != 0) {
            fprintf(stderr, "await: %s\n", st.msg);
            return 1;
        }
        printf("ev=%s meta=", ev_name(r.ev));
        put_hex(r.meta, r.meta_len);
        printf(" data=");
        put_hex(r.data, r.data_len);
        printf("\n");

        if (r.ev == BRIX_SSI_EV_PENDING) {
            brix_ssi_reply_free(&r);
            return drain_pending(s);
        }
        if (r.ev == BRIX_SSI_EV_RESPONSE) {
            brix_ssi_reply_free(&r);
            return 0;
        }
        brix_ssi_reply_free(&r);   /* an alert: keep collecting */
    }
}

int
main(int argc, char **argv)
{
    const char   *mode;
    brix_status   st;
    brix_url      url;
    brix_conn     conn;
    brix_ssi_sess sess;
    int           rc;

    if (argc < 4) {
        fprintf(stderr, "usage: ssi_client_smoke <endpoint> <service> "
                        "<request> [run|cancel|badcarrier]\n");
        return 2;
    }
    mode = (argc > 4) ? argv[4] : "run";

    signal(SIGPIPE, SIG_IGN);   /* a dropped peer must not kill the process */

    if (brix_endpoint_parse(argv[1], &url, &st) != 0) {
        fprintf(stderr, "endpoint parse: %s\n", st.msg);
        return 2;
    }
    if (brix_connect(&conn, &url, NULL, &st) != 0) {
        fprintf(stderr, "connect: %s\n", st.msg);
        return 2;
    }

    if (brix_ssi_sess_open(&sess, &conn, argv[2], &st) != 0) {
        fprintf(stderr, "open: %s\n", st.msg);
        brix_close(&conn);
        return 1;
    }
    printf("open ok\n");

    if (strcmp(mode, "badcarrier") == 0) {
        rc = send_bad_carrier(&sess, &conn);
        brix_ssi_close(&sess);
        brix_close(&conn);
        return rc;
    }

    if (brix_ssi_submit(&sess, argv[3], strlen(argv[3]), &st) != 0) {
        fprintf(stderr, "submit: %s\n", st.msg);
        brix_ssi_close(&sess);
        brix_close(&conn);
        return 1;
    }
    printf("submit deferred=%d\n", sess.deferred);

    if (strcmp(mode, "cancel") == 0) {
        if (brix_ssi_cancel(&sess, &st) != 0) {
            fprintf(stderr, "cancel: %s\n", st.msg);
            rc = 1;
        } else {
            printf("cancel ok\n");
            rc = 0;
        }
    } else {
        rc = collect(&sess);
    }

    brix_ssi_close(&sess);
    printf("close ok\n");
    brix_close(&conn);
    return rc;
}
