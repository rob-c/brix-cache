/*
 * diag_misc.c - extracted concern
 * Phase-38 split of xrddiag.c; behavior-identical.
 */
#include "diag_internal.h"


/* ---- probe_p1_path_escape — path-escape robustness probe ----
 *
 * WHAT: Runs probe P1 against urlbuf: opens a session, issues a stat on a
 * well-formed path-escape string, and confirms the escape is refused while the
 * transport stays alive. Records the verdict via probe(); no return value.
 *
 * WHY: A confinement break (serving /etc/passwd) is the single worst outcome for
 * this tool, so it is isolated in its own step with an explicit survive check.
 *
 * HOW:
 *   1. Open a probe session; on failure record a connect error and stop.
 *   2. stat the escape path — "served" iff it succeeds.
 *   3. stat "/" — "alive" iff it still completes (transport intact).
 *   4. Pass iff not served AND alive; close the session.
 */
static void
probe_p1_path_escape(const char *urlbuf, const diag_args *a, int tmo)
{
    brix_conn     c;
    brix_status   cs;
    brix_statinfo si;
    brix_status_clear(&cs);
    if (probe_open(&c, urlbuf, a, tmo, &cs) == 0) {
        brix_status   est;
        brix_statinfo s2;
        brix_status   s2t;
        int           served, alive;
        brix_status_clear(&est);
        brix_status_clear(&s2t);
        served = (brix_stat(&c, "/../../../../../../etc/passwd", &si, &est) == 0);
        /* survive: a normal stat still completes (transport intact). */
        alive = (brix_stat(&c, "/", &s2, &s2t) == 0) || (s2t.kxr > 0);
        probe("path-escape", !served && alive,
              served ? "ESCAPE SERVED — confinement broken!"
                     : "refused (%s), connection alive",
              served ? "" : brix_kxr_name(est.kxr));
        brix_close(&c);
    } else {
        probe("path-escape", 0, "connect: %s", cs.msg);
    }
}


/* ---- probe_p2_bad_opcode — unknown-opcode robustness probe ----
 *
 * WHAT: Runs probe P2 against urlbuf: sends a raw request header carrying an
 * unknown request id (9999) and confirms the server rejects it. Records the
 * verdict via probe(); no return value.
 *
 * WHY: An unknown opcode must never be served; isolating it keeps the raw
 * header construction and its magic bytes local and reviewable.
 *
 * HOW:
 *   1. Open a probe session; on failure record a connect error and stop.
 *   2. Build a zeroed 24-byte header with requestid 9999 (0x270f).
 *   3. raw_send_expect_reject — pass iff it reports a clean reject.
 *   4. Close the session.
 */
static void
probe_p2_bad_opcode(const char *urlbuf, const diag_args *a, int tmo)
{
    brix_conn   c;
    brix_status cs;
    brix_status_clear(&cs);
    if (probe_open(&c, urlbuf, a, tmo, &cs) == 0) {
        uint8_t hdr[24];
        int     v;
        memset(hdr, 0, sizeof(hdr));
        hdr[2] = 0x27; hdr[3] = 0x0f;   /* requestid 9999 = not a kXR_* op */
        v = raw_send_expect_reject(&c, hdr, NULL, 0, 0, 0);
        probe("bad-opcode", v == 1,
              v == 0 ? "SERVED an unknown opcode!" : "rejected");
        brix_close(&c);
    } else {
        probe("bad-opcode", 0, "connect: %s", cs.msg);
    }
}


/* ---- probe_p3_oversized_dlen — oversized-payload robustness probe ----
 *
 * WHAT: Runs probe P3 against urlbuf: sends a kXR_stat header claiming a ~1 GiB
 * dlen with no body and confirms the server rejects/closes rather than
 * buffering it. Records the verdict via probe(); no return value.
 *
 * WHY: A server that buffers an attacker-declared 1 GiB payload is a trivial
 * memory-exhaustion vector; the payload cap must be exercised in isolation.
 *
 * HOW:
 *   1. Open a probe session; on failure record a connect error and stop.
 *   2. Build a zeroed kXR_stat header, declaring dlen 0x40000000 with no body.
 *   3. raw_send_expect_reject — pass iff it reports a clean reject/close.
 *   4. Close the session.
 */
static void
probe_p3_oversized_dlen(const char *urlbuf, const diag_args *a, int tmo)
{
    brix_conn   c;
    brix_status cs;
    brix_status_clear(&cs);
    if (probe_open(&c, urlbuf, a, tmo, &cs) == 0) {
        uint8_t hdr[24];
        int     v;
        memset(hdr, 0, sizeof(hdr));
        hdr[2] = (uint8_t) (kXR_stat >> 8);
        hdr[3] = (uint8_t) (kXR_stat & 0xff);
        v = raw_send_expect_reject(&c, hdr, NULL, 0, 1, 0x40000000u);
        probe("oversized-dlen", v == 1,
              v == 0 ? "accepted a 1 GiB dlen!" : "rejected/closed");
        brix_close(&c);
    } else {
        probe("oversized-dlen", 0, "connect: %s", cs.msg);
    }
}


/* ---- probe_p4_oob_read — out-of-bounds read robustness probe ----
 *
 * WHAT: Runs probe P4 against urlbuf: issues a kXR_read on a never-opened file
 * handle with a huge length and confirms the server rejects it. Records the
 * verdict via probe(); no return value.
 *
 * WHY: Serving a read on a bogus handle would leak memory or crash; the handle
 * and length bounds check is isolated so its magic bytes stay reviewable.
 *
 * HOW:
 *   1. Open a probe session; on failure record a connect error and stop.
 *   2. Build a kXR_read header with fhandle 0xffffffff and rlen 0x7fffffff.
 *   3. raw_send_expect_reject — pass iff it reports a clean reject.
 *   4. Close the session.
 */
static void
probe_p4_oob_read(const char *urlbuf, const diag_args *a, int tmo)
{
    brix_conn   c;
    brix_status cs;
    brix_status_clear(&cs);
    if (probe_open(&c, urlbuf, a, tmo, &cs) == 0) {
        uint8_t hdr[24];
        int     v;
        memset(hdr, 0, sizeof(hdr));
        hdr[2] = (uint8_t) (kXR_read >> 8);
        hdr[3] = (uint8_t) (kXR_read & 0xff);
        memset(hdr + 4, 0xff, 4);            /* fhandle = never-opened */
        hdr[16] = 0x7f; hdr[17] = 0xff;      /* rlen = 0x7fffffff (huge) */
        hdr[18] = 0xff; hdr[19] = 0xff;
        v = raw_send_expect_reject(&c, hdr, NULL, 0, 0, 0);
        probe("oob-read", v == 1,
              v == 0 ? "served a read on a bogus handle!" : "rejected");
        brix_close(&c);
    } else {
        probe("oob-read", 0, "connect: %s", cs.msg);
    }
}


/* ---- probe_p5_partial_frame — truncated-header robustness probe ----
 *
 * WHAT: Runs probe P5 against urlbuf: sends only 12 of a 24-byte kXR_stat
 * header then abandons the connection mid-frame, confirming the server does not
 * crash. Records the verdict via probe(); no return value.
 *
 * WHY: A slowloris-style partial frame must not wedge or crash the server; the
 * step always passes locally because the survive check runs later.
 *
 * HOW:
 *   1. Open a probe session; on failure record a connect error and stop.
 *   2. Write the first 12 bytes of a kXR_stat header.
 *   3. Record the send, then close mid-frame to abandon it.
 */
static void
probe_p5_partial_frame(const char *urlbuf, const diag_args *a, int tmo)
{
    brix_conn   c;
    brix_status cs;
    brix_status_clear(&cs);
    if (probe_open(&c, urlbuf, a, tmo, &cs) == 0) {
        uint8_t half[12] = { 0 };
        half[2] = (uint8_t) (kXR_stat >> 8);
        half[3] = (uint8_t) (kXR_stat & 0xff);
        (void) brix_write_full(&c.io, half, sizeof(half), &cs);
        probe("partial-frame", 1, "sent 12/24 header bytes then closed");
        brix_close(&c);   /* abandon mid-frame */
    } else {
        probe("partial-frame", 0, "connect: %s", cs.msg);
    }
}


/* ---- probe_server_survives — post-battery liveness gate ----
 *
 * WHAT: Opens a fresh session and stats "/" after the probe battery, confirming
 * nothing above crashed or wedged the server. Records the verdict via probe();
 * no return value.
 *
 * WHY: The battery's whole point is that the server survives every hostile
 * frame; this final gate proves the transport is still serviceable.
 *
 * HOW:
 *   1. Open a fresh probe session; on failure record a reconnect error and stop.
 *   2. stat "/" — alive iff it completes or returns a kXR status.
 *   3. Record the verdict and close the session.
 */
static void
probe_server_survives(const char *urlbuf, const diag_args *a, int tmo)
{
    brix_conn     c;
    brix_status   cs;
    brix_statinfo si;
    brix_status_clear(&cs);
    if (probe_open(&c, urlbuf, a, tmo, &cs) == 0) {
        brix_status s2;
        int         alive;
        brix_status_clear(&s2);
        alive = (brix_stat(&c, "/", &si, &s2) == 0) || (s2.kxr > 0);
        probe("server-survives", alive,
              alive ? "fresh session OK after battery"
                    : "server unreachable after battery!");
        brix_close(&c);
    } else {
        probe("server-survives", 0, "reconnect: %s", cs.msg);
    }
}


/* ---- do_probe_robustness — adversarial robustness auditor ----
 *
 * WHAT: Parses and resolves the target endpoint, enforces the loopback safety
 * gate, then runs the P1–P5 hostile-frame battery plus the post-battery
 * survive gate. Returns 50/51 on parse/resolve failure, 3 when refusing a
 * non-loopback target, else 1 if any probe failed or 0 on a clean run.
 *
 * WHY: This is a fuzzing-class tool; it must refuse non-loopback targets unless
 * explicitly authorised, and each probe is a self-contained hostile frame that
 * the server must reject cleanly while staying alive.
 *
 * HOW:
 *   1. Parse the endpoint and resolve it to an IP (with loopback flag).
 *   2. Refuse a non-loopback address unless the operator asserted authorisation.
 *   3. Compute the timeout and build the root(s):// probe URL, print the banner.
 *   4. Run each probe step in order, then the survive gate.
 *   5. Print the failure count and return 1 iff any probe failed.
 */
int
do_probe_robustness(const diag_args *a)
{
    brix_url      u;
    brix_status   st;
    char          ip[128];
    char          urlbuf[300];
    int           is_loop = 0, tmo;

    brix_status_clear(&st);
    if (brix_endpoint_parse(a->url, &u, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        return 50;
    }
    if (resolve_once(u.host, u.port, ip, sizeof(ip), &is_loop, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        return 51;
    }
    /* Safety gate: this is a fuzzing-class tool. Refuse a non-loopback resolved
     * address unless the operator explicitly asserts authorisation. */
    if (!is_loop && !a->authorized) {
        fprintf(stderr,
                "xrddiag: refusing to fuzz non-loopback target %s (%s) — this is "
                "an adversarial auditor; re-run with --i-am-authorized only "
                "against hosts you are authorised to test.\n", u.host, ip);
        return 3;
    }

    tmo = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 5000;
    snprintf(urlbuf, sizeof(urlbuf), "%s://%s:%d/",
             a->conn.want_tls ? "roots" : "root", ip, u.port);
    printf("probe-robustness %s (%s:%d)%s\n", u.host, ip, u.port,
           is_loop ? "" : " [AUTHORISED non-loopback]");
    printf("Probes (each must be REJECTED cleanly, server must survive):\n");

    probe_p1_path_escape(urlbuf, a, tmo);
    probe_p2_bad_opcode(urlbuf, a, tmo);
    probe_p3_oversized_dlen(urlbuf, a, tmo);
    probe_p4_oob_read(urlbuf, a, tmo);
    probe_p5_partial_frame(urlbuf, a, tmo);
    probe_server_survives(urlbuf, a, tmo);

    printf("Result: %d failure(s)\n", g_fails);
    return g_fails ? 1 : 0;
}


/* replay — decode a .xrdcap offline, or re-issue it against a server  */

int
do_replay(const diag_args *a)
{
    brix_status st;
    int         rc;

    brix_status_clear(&st);
    if (a->playback_url != NULL) {
        rc = brix_capture_playback(a->url, a->playback_url, &a->conn, stdout, &st);
    } else {
        rc = brix_capture_replay(a->url, a->conn.wire_trace, stdout, &st);
    }
    if (rc != 0) {
        fprintf(stderr, "xrddiag: replay: %s\n", st.msg);
        return brix_shellcode(&st);
    }
    return 0;
}


/* xrddiag srr <http[s]-url> — fetch the WLCG Storage Resource Reporting document
 * and summarize the site's shares + capacity. Closes the SRR client gap. */
int
do_srr(const diag_args *a)
{
    dx_url_t       u;
    char           name[128];
    brix_http_resp r;
    brix_status    st;
    int            tmo = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 8000;

    if (dx_url_parse(a->url, &u) != 0 || u.proto == DXP_ROOT) {
        fprintf(stderr, "xrddiag: srr needs an http(s):// URL\n");
        return 50;
    }
    if (u.path[0] == '\0' || strcmp(u.path, "/") == 0) {
        snprintf(u.path, sizeof(u.path), "/.well-known/wlcg-storage-resource-reporting");
    }
    brix_status_clear(&st);
    if (brix_http_req(u.host, u.port, u.tls, "GET", u.path, NULL, NULL, 0, tmo,
                      a->verify_tls, NULL, &r, &st) != 0) {
        fprintf(stderr, "xrddiag: srr GET %s:%d%s: %s\n", u.host, u.port, u.path,
                st.msg);
        return 51;
    }
    if (r.status != 200) {
        fprintf(stderr, "xrddiag: srr returned HTTP %d\n", r.status);
        brix_http_resp_free(&r);
        return 51;
    }
    if (a->json) {
        fwrite(r.body, 1, r.body_len, stdout);
    } else {
        long long total = js_sum(r.body, "totalsize");
        long long used  = js_sum(r.body, "usedsize");
        int       shares = js_count(r.body, "totalsize");
        if (js_str(r.body, "implementation", name, sizeof(name))) {
            printf("SRR: implementation=%s", name);
            if (js_str(r.body, "implementationversion", name, sizeof(name))) {
                printf(" %s", name);
            }
            printf("\n");
        }
        printf("  shares:   %d\n", shares);
        printf("  capacity: %lld bytes total, %lld used (%.1f%% full)\n",
               total, used, total > 0 ? 100.0 * (double) used / (double) total : 0.0);
    }
    brix_http_resp_free(&r);
    return 0;
}


/* ---- tape_poll_status — one-shot stage-request status poll ----
 *
 * WHAT: Issues a single GET /api/v1/stage/{reqid} and, on HTTP 200, prints the
 * reported state and onDisk locality. Reuses the caller's response and status
 * buffers; no return value (best-effort poll).
 *
 * WHY: The poll is a self-contained follow-up to the stage POST; isolating it
 * keeps do_tape's control flow flat and its complexity within budget.
 *
 * HOW:
 *   1. Build the poll path from reqid and clear the status.
 *   2. GET the poll URL; on transport failure do nothing (best-effort).
 *   3. On HTTP 200 extract state and onDisk and print them.
 *   4. Free the response on every successful request.
 */
static void
tape_poll_status(const dx_url_t *u, const diag_args *a, int tmo,
                 const char *reqid, brix_http_resp *r, brix_status *st)
{
    char poll[256];
    snprintf(poll, sizeof(poll), "/api/v1/stage/%s", reqid);
    brix_status_clear(st);
    if (brix_http_req(u->host, u->port, u->tls, "GET", poll, NULL, NULL, 0, tmo,
                      a->verify_tls, NULL, r, st) == 0) {
        if (r->status == 200) {
            char state[32];
            char ondisk[16];
            state[0] = '\0';
            (void) js_str(r->body, "state", state, sizeof(state));
            ondisk[0] = '\0';
            (void) js_str(r->body, "onDisk", ondisk, sizeof(ondisk));
            printf("poll: state=%s onDisk=%s\n", state[0] ? state : "?",
                   ondisk[0] ? ondisk : "?");
        }
        brix_http_resp_free(r);   /* free on every successful request */
    }
}


/* xrddiag tape <http[s]-url//path> — drive the WLCG/FRM Tape REST API: POST a stage
 * request for the path, then poll its status once and report locality. Closes the
 * FRM Tape-REST client gap. */
int
do_tape(const diag_args *a)
{
    dx_url_t       u;
    char           body[1024], reqid[128], state[32];
    brix_http_resp r;
    brix_status    st;
    int            tmo = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 8000;

    if (dx_url_parse(a->url, &u) != 0 || u.proto == DXP_ROOT || u.path[0] != '/'
        || u.path[1] == '\0') {
        fprintf(stderr, "xrddiag: tape needs an http(s):// URL with a file path\n");
        return 50;
    }
    /* POST /api/v1/stage {"files":[{"path":"<path>"}]} — reject (don't silently
     * truncate) an over-long path, which would stage the wrong file. */
    if (strlen(u.path) > 900) {
        fprintf(stderr, "xrddiag: tape path too long (max 900 bytes)\n");
        return 50;
    }
    snprintf(body, sizeof(body), "{\"files\":[{\"path\":\"%s\"}]}", u.path);
    brix_status_clear(&st);
    if (brix_http_req(u.host, u.port, u.tls, "POST", "/api/v1/stage",
                      "Content-Type: application/json\r\n", body, strlen(body),
                      tmo, a->verify_tls, NULL, &r, &st) != 0) {
        fprintf(stderr, "xrddiag: tape stage POST: %s\n", st.msg);
        return 51;
    }
    if (r.status != 200 && r.status != 201) {
        fprintf(stderr, "xrddiag: tape stage returned HTTP %d\n", r.status);
        brix_http_resp_free(&r);
        return 51;
    }
    if (!js_str(r.body, "id", reqid, sizeof(reqid))
        && !js_str(r.body, "requestId", reqid, sizeof(reqid))) {
        fprintf(stderr, "xrddiag: tape stage: no request id in response\n");
        brix_http_resp_free(&r);
        return 51;
    }
    state[0] = '\0';
    (void) js_str(r.body, "state", state, sizeof(state));
    printf("stage accepted: request-id=%s state=%s\n", reqid, state[0] ? state : "?");
    brix_http_resp_free(&r);

    /* poll GET /api/v1/stage/{id} once. */
    tape_poll_status(&u, a, tmo, reqid, &r, &st);
    return 0;
}
