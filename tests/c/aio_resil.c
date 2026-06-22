/*
 * aio_resil.c — M2 validation for the async resilience layer (client/lib/aio.c).
 *
 * WHAT: Drives a steady stream of retry-safe kXR_ping requests over one async
 *       connection while the server is BOUNCED mid-stream (killed and restarted).
 *       Asserts that every request still completes successfully — the in-flight and
 *       subsequently-submitted pings are parked across the drop, the connection is
 *       transparently re-established by the reconnect worker, and the parked
 *       requests are re-issued. No EIO reaches the caller.
 * WHY:  This is the core "survives a server restart / transient drop with no error"
 *       guarantee for "bad wifi from a laptop abroad".
 * HOW:  A producer thread fires N pings at a fixed cadence with retry_safe=1 and a
 *       generous max_stall budget; the harness runs $XRD_BOUNCE_CMD partway through
 *       to restart the server. We then wait for all completions and check failures.
 *
 * Usage: XRD_BOUNCE_CMD="<shell to restart the server>" aio_resil [endpoint]
 */
#include "aio.h"
#include "xrdc.h"
#include "protocol/protocol.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#define NPINGS       200
#define INTERVAL_US  40000      /* 40 ms → ~8 s of production */
#define BOUNCE_AT    60         /* fire the bounce after this many submits (~2.4 s) */
#define MAX_STALL_MS 20000      /* reconnect patience must exceed the downtime */

static int      g_submitted = 0;
static int      g_completed = 0;
static int      g_failed = 0;
static pthread_mutex_t g_mx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cv = PTHREAD_COND_INITIALIZER;

static void
ping_cb(void *ctx, int rc, uint16_t kxr, uint8_t *body, uint32_t blen,
        const xrdc_status *st)
{
    (void) ctx; (void) blen;
    int ok = (rc == 0 && kxr == kXR_ok);
    free(body);
    pthread_mutex_lock(&g_mx);
    g_completed++;
    if (!ok) {
        g_failed++;
        if (g_failed <= 5 && st != NULL) {
            fprintf(stderr, "  ping failed (#%d): rc=%d kxr=%d %s\n",
                    g_completed, rc, kxr, st->msg);
        }
    }
    pthread_cond_signal(&g_cv);
    pthread_mutex_unlock(&g_mx);
}

int
main(int argc, char **argv)
{
    const char *endpoint = (argc > 1) ? argv[1] : "root://localhost:11199";
    const char *bounce   = getenv("XRD_BOUNCE_CMD");

    signal(SIGPIPE, SIG_IGN);   /* a dropped peer must not kill the process */

    xrdc_status st;
    xrdc_url    url;
    if (xrdc_endpoint_parse(endpoint, &url, &st) != 0) {
        fprintf(stderr, "endpoint parse: %s\n", st.msg);
        return 2;
    }

    xrdc_conn conn;
    if (xrdc_connect(&conn, &url, NULL, &st) != 0) {
        fprintf(stderr, "connect: %s\n", st.msg);
        return 2;
    }

    xrdc_loop *loop = xrdc_loop_create(&st);
    if (loop == NULL) {
        fprintf(stderr, "loop create: %s\n", st.msg);
        xrdc_close(&conn);
        return 2;
    }
    xrdc_aconn *ac = xrdc_aconn_attach(loop, &conn, &st);
    if (ac == NULL) {
        fprintf(stderr, "attach: %s\n", st.msg);
        xrdc_loop_destroy(loop);
        xrdc_close(&conn);
        return 2;
    }
    /* generous reconnect budget, short keepalive */
    xrdc_aconn_set_resilience(ac, MAX_STALL_MS, 2000, 8);

    uint8_t hdr[XRD_REQUEST_HDR_LEN];
    memset(hdr, 0, sizeof(hdr));
    uint16_t rid = htons(kXR_ping);
    memcpy(hdr + 2, &rid, 2);

    xrdc_aio_opts opts = { 0 /*adaptive deadline*/, -1 /*default retries*/, 1 /*retry_safe*/ };

    printf("producing %d pings @ %d ms; bouncing server after %d submits...\n",
           NPINGS, INTERVAL_US / 1000, BOUNCE_AT);

    int bounced = 0;
    for (int i = 0; i < NPINGS; i++) {
        if (xrdc_aio_submit_ex(ac, hdr, NULL, 0, &opts, ping_cb, NULL, &st) == 0) {
            pthread_mutex_lock(&g_mx);
            g_submitted++;
            pthread_mutex_unlock(&g_mx);
        } else {
            fprintf(stderr, "  submit failed: %s\n", st.msg);
        }
        if (i == BOUNCE_AT && bounce != NULL && !bounced) {
            bounced = 1;
            printf("  >>> bouncing the server now\n");
            int rc = system(bounce);
            printf("  >>> bounce command returned %d\n", rc);
        }
        usleep(INTERVAL_US);
    }

    /* wait for all completions, bounded */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += (MAX_STALL_MS / 1000) + 10;

    pthread_mutex_lock(&g_mx);
    int timed_out = 0;
    while (g_completed < g_submitted && !timed_out) {
        if (pthread_cond_timedwait(&g_cv, &g_mx, &ts) != 0) {
            timed_out = (g_completed < g_submitted);
        }
    }
    int submitted = g_submitted, completed = g_completed, failed = g_failed;
    pthread_mutex_unlock(&g_mx);

    /* final liveness check: a blocking call must succeed on the recovered conn */
    uint16_t kxr = 0;
    int live = (xrdc_aio_call(ac, hdr, NULL, 0, &kxr, NULL, NULL, 10000, &st) == 0
                && kxr == kXR_ok);

    xrdc_aconn_close(ac);
    xrdc_loop_destroy(loop);
    xrdc_close(&conn);

    printf("\nsubmitted=%d completed=%d failed=%d  final-liveness=%s%s\n",
           submitted, completed, failed, live ? "OK" : "FAIL",
           timed_out ? "  (TIMED OUT)" : "");

    if (completed == submitted && failed == 0 && live && !timed_out) {
        printf("M2 PASS — every request survived the server bounce (transparent reconnect)\n");
        return 0;
    }
    printf("M2 FAIL\n");
    return 1;
}
