/*
 * diag_doctor_probe.c — remote-doctor active-probe battery (Phase-38 split).
 *
 * WHAT: the connection-level diagnosis primitives shared by every endpoint
 *       battery — the raw data-path download, the issue recorder, the
 *       throughput/metrics probes, and the full auth/permissions suite.
 * WHY:  split from diag_doctor.c to hold each TU within the Phase-38 size
 *       budget; these probes are the reusable "what can this open connection
 *       tell us" layer that both doctor_one (root://) and the protocol
 *       batteries build on, so they form one cohesive concern.
 * HOW:  every routine operates on an already-open brix_conn (or a scoped
 *       force-anon session of its own, for the auth suite) and records verdicts
 *       onto the caller's doctor_ep via the extern contract in
 *       diag_internal.h. No reconnect in the timing probes (they measure the
 *       data path itself); no goto; PII-free (verdicts + kXR codes only).
 */
#include "diag_internal.h"


/* Stream a remote file through the live connection into fd; returns 0 / -1 and
 * sets *out_bytes to the number of bytes written. Reuses the authenticated conn
 * (no reconnect), so it measures the data path itself. */
int
download_to_fd(brix_conn *c, const char *path, int fd, int64_t *out_bytes,
               brix_status *st)
{
    brix_file f;
    int64_t   off = 0;
    char     *buf;

    if (brix_file_open_read(c, path, &f, st) != 0) {
        return -1;
    }
    buf = (char *) malloc(1u << 20);
    if (buf == NULL) {
        brix_file_close(c, &f, st);
        brix_status_set(st, XRDC_EPROTO, 0, "download: out of memory");
        return -1;
    }
    for (;;) {
        ssize_t r = brix_file_read(c, &f, off, buf, 1u << 20, st);
        ssize_t w = 0;
        if (r < 0) {
            free(buf);
            brix_file_close(c, &f, st);
            return -1;
        }
        if (r == 0) {
            break;
        }
        while (w < r) {
            ssize_t k = write(fd, buf + w, (size_t) (r - w));
            if (k < 0) {
                free(buf);
                brix_file_close(c, &f, st);
                brix_status_set(st, XRDC_ESOCK, 0, "download: local write failed");
                return -1;
            }
            w += k;
        }
        off += r;
    }
    free(buf);
    if (out_bytes != NULL) {
        *out_bytes = off;
    }
    return brix_file_close(c, &f, st);
}


void
doc_issue(doctor_ep *e, int sev, const char *fmt, ...)
{
    va_list ap;
    if (e->nissues >= DOC_MAXISS) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(e->issues[e->nissues], sizeof(e->issues[0]), fmt, ap);
    va_end(ap);
    e->nissues++;
    if (sev > e->status) {
        e->status = sev;
    }
}


/* Throughput probe over an established conn: TTFB (first read) + MB/s (whole file). */
int
doctor_xfer(brix_conn *c, const char *path, double *ttfb_ms, double *mbps,
            int64_t *bytes)
{
    brix_file   f;
    brix_status st;
    uint8_t    *buf;
    int64_t     off = 0;
    uint64_t    t0, tf = 0, t1;

    brix_status_clear(&st);
    if (brix_file_open_read(c, path, &f, &st) != 0) {
        return -1;
    }
    buf = (uint8_t *) malloc(1u << 20);
    if (buf == NULL) {
        brix_file_close(c, &f, &st);
        return -1;
    }
    t0 = brix_mono_ns();
    for (;;) {
        ssize_t r = brix_file_read(c, &f, off, buf, 1u << 20, &st);
        if (r < 0) { free(buf); brix_file_close(c, &f, &st); return -1; }
        if (tf == 0) { tf = brix_mono_ns(); }     /* time-to-first-byte */
        if (r == 0) { break; }
        off += r;
    }
    t1 = brix_mono_ns();
    free(buf);
    brix_file_close(c, &f, &st);
    *ttfb_ms = (double) (tf - t0) / 1e6;
    *bytes   = off;
    {
        double secs = (double) (t1 - t0) / 1e9;
        if (secs <= 0.0) { secs = 1e-9; }
        *mbps = (double) off / 1e6 / secs;
    }
    return 0;
}


/* /metrics signal: reachable? + any kXR_wait/budget shedding gauge nonzero. */
void
doctor_metrics(const char *host, int port, doctor_ep *e)
{
    char       *body;
    brix_status st;
    int         http = 0;
    char       *line, *save;

    body = (char *) malloc(1u << 20);
    if (body == NULL) {
        return;
    }
    brix_status_clear(&st);
    if (brix_http_get(host, port, "/metrics", 4000, &http, body, 1u << 20, NULL,
                      &st) != 0) {
        free(body);
        return;
    }
    e->metrics_http = http;
    for (line = strtok_r(body, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        if (line[0] == '#') {
            continue;
        }
        if (strstr(line, "kXR_wait") != NULL || strstr(line, "_wait_") != NULL
            || strstr(line, "budget") != NULL || strstr(line, "shed") != NULL) {
            /* nonzero counter at the end of the line ⇒ active shedding */
            char *sp = strrchr(line, ' ');
            if (sp != NULL && strtod(sp + 1, NULL) > 0.0) {
                e->shedding = 1;
            }
        }
    }
    free(body);
}


/*
 * WHAT: forged-credential rejection probes (bad-signature + alg=none JWTs).
 * WHY:  extracted from doctor_auth_suite for the complexity gate; the
 *       forged-token matrix is one self-contained concern.
 * HOW:  build each forged JWT with dx_make_jwt and assert rejection via
 *       dx_authz_forged. Only called when the server advertises ztn.
 */
static void
auth_suite_forged_probes(const diag_args *a, const brix_url *u, doctor_ep *e)
{
    char fsig[1024], fnone[1024];

    /* No kid: a kid the server doesn't know would be rejected at key SELECTION,
     * short-circuiting the signature check — we want the server to reach
     * signature verification (and reject the garbage sig) so the test actually
     * exercises signature verification on typical single-key deployments. */
    if (dx_make_jwt(
            "{\"alg\":\"RS256\",\"typ\":\"JWT\"}",
            "{\"iss\":\"https://xrddiag.invalid\",\"sub\":\"xrddiag-probe\","
            "\"scope\":\"storage.read:/ storage.modify:/\",\"exp\":4102444800}",
            "ZHVtbXktc2lnbmF0dXJlLW5vdC12YWxpZA", fsig, sizeof(fsig)) == 0) {
        dx_authz_forged(a, u, "authz-forgesig", fsig, e);
    }
    if (dx_make_jwt(
            "{\"alg\":\"none\",\"typ\":\"JWT\"}",
            "{\"iss\":\"https://xrddiag.invalid\",\"sub\":\"xrddiag-probe\","
            "\"scope\":\"storage.read:/ storage.modify:/\",\"exp\":4102444800}",
            "", fnone, sizeof(fnone)) == 0) {
        dx_authz_forged(a, u, "authz-algnone", fnone, e);
    }
}


/*
 * WHAT: auth-suite probes that need the operator's real token (expired-token
 *       rejection + read-only-scope write denial).
 * WHY:  extracted from doctor_auth_suite for the complexity gate.
 * HOW:  discover the ambient token, gate each probe on the token's metadata
 *       (the write-scope assertion is gated like the write probe), free it.
 */
static void
auth_suite_token_probes(const diag_args *a, const brix_url *u, int ztn_adv,
                        doctor_ep *e)
{
    char           *tok = brix_token_discover();
    brix_token_meta m;

    if (tok == NULL) {
        return;
    }
    brix_token_meta_get(tok, &m);
    if (ztn_adv && m.valid && m.expired) {
        dx_authz_expired(a, u, tok, e);
    }
    if (a->allow_write && ztn_adv && m.valid && m.has_scope
        && m.has_read && !m.has_write
        && (dx_is_loopback(e->host) || a->authorized)) {
        dx_authz_scope(a, u, tok, e);
    }
    free(tok);
}


/*
 * The full auth/permissions suite. Opens its own scoped connections (the credential
 * matrix) — does not reuse the primary. Read-only assertions always run; the
 * write-scope assertion is gated like the write probe. PII-free: only verdicts +
 * kXR codes are recorded, never token/cert/scope contents.
 */
void
doctor_auth_suite(const diag_args *a, const brix_url *u, const char *target,
                  int have_target, doctor_ep *e)
{
    char sec_list[256];
    int  ztn_adv;

    /* 1) anonymous access must be denied on an auth-required server — this also
     *    discovers the server's advertised auth (&P=) from a force_anon session. */
    dx_authz_anon(a, u, target, have_target, sec_list, sizeof(sec_list), e);
    ztn_adv = (strstr(sec_list, "ztn") != NULL);

    /* 2,3) forged-credential rejection — only if the server takes bearer tokens. */
    if (ztn_adv) {
        auth_suite_forged_probes(a, u, e);
    } else {
        dx_record(e, &(dx_note){ "authz-token", DX_OK, 0,
                  "server does not offer bearer-token auth (forged-token tests N/A)", "" });
    }

    /* 4,5) tests that require the operator's real token. */
    auth_suite_token_probes(a, u, ztn_adv, e);
}


/*
 * Run the active-diagnosis battery over an already-open connection. Read-only probes
 * always run; write/stage probes run only when --allow-write is set AND the target is
 * loopback or the operator passed --i-am-authorized (mutations on a remote server).
 */
void
doctor_diagnose(const diag_args *a, brix_conn *c, const brix_url *u,
                const dx_target *t, doctor_ep *e)
{
    dx_probe_auth(c, e);
    dx_probe_namespace(c, e);
    if (t->have) {
        dx_probe_read(c, t->path, e);
        dx_probe_checksum(c, t->path, e);
    }
    {
        char        loc[2048];
        brix_status lst;
        brix_status_clear(&lst);
        if (brix_locate(c, u->path[0] ? u->path : "/", loc, sizeof(loc), &lst) != 0) {
            dx_record_status(e, "locate", &lst);
        } else {
            char *t, *save;
            for (t = strtok_r(loc, " \t\r\n", &save); t != NULL;
                 t = strtok_r(NULL, " \t\r\n", &save)) {
                if (t[0] == 'S') { e->holders++; }
            }
            if (e->holders == 0) {
                dx_record(e, &(dx_note){ "locate", DX_WARN, 0, "no replica located for the path",
                          "check data-server health and the CMS/manager registry" });
            } else {
                dx_record(e, &(dx_note){ "locate", DX_OK, 0, "replica(s) located", "" });
            }
        }
    }
    if (a->allow_write) {
        int permitted = dx_is_loopback(e->host) || a->authorized;
        if (!permitted) {
            dx_record(e, &(dx_note){ "write", DX_WARN, 0,
                      "write probe skipped on a non-loopback host without --i-am-authorized",
                      "re-run with --i-am-authorized to actively probe the write path" });
        } else {
            dx_probe_write(c, e);
            if (t->have && e->offline_seen) {
                dx_probe_stage(c, t->path, e);
            }
        }
    }
    if (a->auth_suite) {
        doctor_auth_suite(a, u, t->path, t->have, e);
    }
}
