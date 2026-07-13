/*
 * diag_misc.c - extracted concern
 * Phase-38 split of xrddiag.c; behavior-identical.
 */
#include "diag_internal.h"


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

    /* P1 — path-escape (well-formed; must be refused AND the conn survive). */
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

    /* P2 — unknown opcode (must be refused). */
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

    /* P3 — oversized dlen (header claims ~1 GiB, no body): must reject/close,
     *      never buffer it (the server caps payload). */
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

    /* P4 — read on a bogus file handle with a huge length (OOB): must reject. */
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

    /* P5 — truncated/slowloris partial header (must not crash the server). */
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

    /* Server-survives gate: a fresh session + stat must still work after the
     * battery — proves nothing above crashed or wedged the server. */
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
    {
        char poll[256];
        snprintf(poll, sizeof(poll), "/api/v1/stage/%s", reqid);
        brix_status_clear(&st);
        if (brix_http_req(u.host, u.port, u.tls, "GET", poll, NULL, NULL, 0, tmo,
                          a->verify_tls, NULL, &r, &st) == 0) {
            if (r.status == 200) {
                char ondisk[16];
                state[0] = '\0';
                (void) js_str(r.body, "state", state, sizeof(state));
                ondisk[0] = '\0';
                (void) js_str(r.body, "onDisk", ondisk, sizeof(ondisk));
                printf("poll: state=%s onDisk=%s\n", state[0] ? state : "?",
                       ondisk[0] ? ondisk : "?");
            }
            brix_http_resp_free(&r);   /* free on every successful request */
        }
    }
    return 0;
}
