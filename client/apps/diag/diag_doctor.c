/*
 * diag_doctor.c - extracted concern
 * Phase-38 split of xrddiag.c; behavior-identical.
 */
#include "diag_internal.h"


/* shared helpers                                                      */

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


/* remote-doctor — interrogate endpoint(s) to debug transfer problems  */


/* Active-diagnosis verdicts map onto the same severity scale as the status rollup,
 * so a finding's verdict can escalate doctor_ep.status directly. */

/* One classified result of an active probe against a remote subsystem. */

/* Which protocol's transfer this endpoint's battery deep-dives. */


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


/*
 * WHAT: file-local probe context for the HTTP-family deep-dive batteries.
 * WHY:  the static request-build/verdict-render helpers below would otherwise
 *       each need 6-7 parameters (host/port/tls/path/timeout/verify); one ctx
 *       struct keeps them under the parameter gate with explicit data flow.
 * HOW:  filled once by doctor_http/doctor_s3 from their (frozen, extern)
 *       signatures and passed by const pointer to every helper.
 */
typedef struct {
    int         tls;      /* 1 = TLS transport */
    const char *host;
    int         port;
    const char *path;     /* request path (S3: the URI) */
    int         tmo;      /* per-probe timeout, ms */
    int         verify;   /* verify TLS certificates */
} http_probe_ctx;


/*
 * WHAT: record the TLS session facts + the "tls" OK verdict on the endpoint.
 * WHY:  the identical stanza was inlined in both doctor_http and doctor_s3.
 * HOW:  no-op on cleartext; otherwise copy version/cipher off the response
 *       and record the handshake/certificate verdict.
 */
static void
http_record_tls(int tls, const brix_http_resp *r, doctor_ep *e)
{
    if (!tls) {
        return;
    }
    e->tls_active = 1;
    snprintf(e->tls_ver, sizeof(e->tls_ver), "%s", r->tls_ver);
    snprintf(e->tls_cipher, sizeof(e->tls_cipher), "%s", r->tls_cipher);
    dx_record(e, &(dx_note){ "tls", DX_OK, 0, "TLS handshake completed + certificate accepted", "" });
}


/*
 * WHAT: verdict-render half of the generic HTTP battery — classify the
 *       transfer-relevant headers of the already-received response.
 * WHY:  extracted from doctor_http for the complexity gate (request-build vs
 *       verdict-render split); stage numbering/order preserved.
 * HOW:  each stage inspects one response header and records one finding.
 */
static void
http_check_common_headers(doctor_ep *e, const brix_http_resp *r)
{
    char val[512];

    /* Stage 3: byte ranges (partial reads / multi-stream transfers depend on this). */
    if (brix_http_header(r, "Accept-Ranges", val, sizeof(val))
        && strstr(val, "bytes") != NULL) {
        dx_record(e, &(dx_note){ "ranges", DX_OK, 0, "byte-range reads supported (Accept-Ranges: bytes)", "" });
    } else {
        dx_record(e, &(dx_note){ "ranges", DX_WARN, 0,
                  "server did not advertise Accept-Ranges (partial/parallel reads may not work)",
                  "enable range support if clients use partial reads" });
    }

    /* Stage 4: checksum advertisement (RFC-3230 Digest, WLCG transfers rely on it). */
    if (brix_http_header(r, "Digest", val, sizeof(val)) && strchr(val, '=') != NULL) {
        /* RFC-3230 form is "algo=value"; require the '=' so a malformed header
         * isn't counted as a working checksum. */
        dx_record(e, &(dx_note){ "checksum", DX_OK, 0, "server advertises a content Digest (checksum)", "" });
    } else {
        dx_record(e, &(dx_note){ "checksum", DX_WARN, 0,
                  "no Digest header (checksum verification unavailable over HTTP)",
                  "enable Want-Digest/Digest if integrity checks are required" });
    }

    /* Stage 5: content-length present (sized transfers). */
    if (brix_http_header(r, "Content-Length", val, sizeof(val))) {
        dx_record(e, &(dx_note){ "content-length", DX_OK, 0, "response is sized (Content-Length present)", "" });
    }
}


/*
 * WHAT: davs deep-dive extras — OPTIONS (WebDAV class / TPC) + PROPFIND.
 * WHY:  extracted from doctor_http for the complexity gate.
 * HOW:  two bounded requests; each response is rendered into davs-class /
 *       davs-tpc / davs-listing verdicts in the original emission order.
 */
static void
http_davs_extras(const http_probe_ctx *pc, doctor_ep *e)
{
    brix_http_resp r;
    brix_status    st;
    char           val[512];

    brix_status_clear(&st);
    if (brix_http_req(pc->host, pc->port, pc->tls, "OPTIONS", pc->path, NULL,
                      NULL, 0, pc->tmo, pc->verify, NULL, &r, &st) == 0) {
        if (brix_http_header(&r, "DAV", val, sizeof(val))) {
            int class2 = (strstr(val, "2") != NULL);
            dx_record(e, &(dx_note){ "davs-class", DX_OK, r.status,
                      class2 ? "WebDAV class 2 advertised (LOCK supported)"
                             : "WebDAV advertised (DAV header present)", "" });
        } else {
            dx_record(e, &(dx_note){ "davs-class", DX_WARN, r.status,
                      "OPTIONS returned no DAV header (WebDAV may be disabled)",
                      "confirm brix_webdav is on for this location" });
        }
        if (brix_http_header(&r, "Allow", val, sizeof(val))
            && strstr(val, "COPY") != NULL) {
            dx_record(e, &(dx_note){ "davs-tpc", DX_OK, 0,
                      "COPY method allowed (third-party-copy capable)", "" });
        }
        brix_http_resp_free(&r);
    } else {
        dx_record(e, &(dx_note){ "davs-class", DX_WARN, st.kxr,
                  "OPTIONS request failed", "" });
    }
    brix_status_clear(&st);
    if (brix_http_req(pc->host, pc->port, pc->tls, "PROPFIND", pc->path,
                      "Depth: 1\r\n", NULL, 0, pc->tmo, pc->verify, NULL, &r,
                      &st) == 0) {
        if (r.status == 207) {
            dx_record(e, &(dx_note){ "davs-listing", DX_OK, 207,
                      "PROPFIND multistatus listing works", "" });
        } else if (r.status == 401 || r.status == 403) {
            dx_record(e, &(dx_note){ "davs-listing", DX_WARN, r.status,
                      "PROPFIND requires authentication", "provide a credential" });
        } else {
            dx_record(e, &(dx_note){ "davs-listing", DX_WARN, r.status,
                      "PROPFIND did not return 207 multistatus", "" });
        }
        brix_http_resp_free(&r);
    }
}


/*
 * http / https deep-dive: connect (+TLS cert/cipher), HEAD/GET the path, classify
 * the HTTP status, byte-range support, the Digest (checksum) header, and 401 auth
 * posture. For davs, also OPTIONS (WebDAV class) and PROPFIND (listing). Every probe
 * is bounded by the per-probe timeout. PII-free: only statuses/header-names/sizes.
 */
void
doctor_http(const diag_args *a, const dx_url_t *u, doctor_ep *e)
{
    brix_http_resp r;
    brix_status    st;
    http_probe_ctx pc;

    pc.tls = u->tls;
    pc.host = u->host;
    pc.port = u->port;
    pc.path = u->path;
    pc.tmo = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 8000;
    pc.verify = a->verify_tls;

    memset(e, 0, sizeof(*e));
    e->proto = u->proto;
    e->status = DOC_GREEN;
    snprintf(e->host, sizeof(e->host), "%s", u->host);
    e->port = u->port;

    /* Stage 1: reachability + (TLS handshake/cert). Try HEAD; fall back to a 1-byte
     * ranged GET if HEAD is refused, so we still measure connect/TLS. */
    brix_status_clear(&st);
    if (brix_http_req(u->host, u->port, u->tls, "HEAD", u->path, NULL, NULL, 0,
                      pc.tmo, pc.verify, NULL, &r, &st) != 0) {
        brix_status_clear(&st);
        if (brix_http_req(u->host, u->port, u->tls, "GET", u->path,
                          "Range: bytes=0-0\r\n", NULL, 0, pc.tmo, pc.verify,
                          NULL, &r, &st) != 0) {
            dx_http_fail(e, u->tls, &st);
            return;
        }
    }
    e->connected = 1;
    http_record_tls(u->tls, &r, e);

    /* Stage 2: HTTP status. */
    dx_http_status(e, "http", r.status);

    /* Stages 3-5: transfer-relevant response headers. */
    http_check_common_headers(e, &r);
    brix_http_resp_free(&r);

    /* davs extras: OPTIONS (WebDAV class) + PROPFIND (collection listing). */
    if (u->proto == DXP_DAVS) {
        http_davs_extras(&pc, e);
    }
}


/*
 * WHAT: verdict-render half of the anonymous S3 reachability probe.
 * WHY:  extracted from doctor_s3 for the complexity gate.
 * HOW:  map the unauthenticated GET's HTTP status onto the S3 auth-posture
 *       verdicts (enforced / missing / public / other).
 */
static void
s3_classify_anon(doctor_ep *e, const brix_http_resp *r)
{
    if (r->status == 403) {
        dx_record(e, &(dx_note){ "s3-auth", DX_OK, 403,
                  "endpoint enforces S3 authentication (anonymous request denied)", "" });
    } else if (r->status == 404) {
        dx_record(e, &(dx_note){ "s3-bucket", DX_WARN, 404,
                  "bucket/key not found (NoSuchBucket/NoSuchKey)",
                  "verify the bucket and key path" });
    } else if (r->status >= 200 && r->status < 300) {
        dx_record(e, &(dx_note){ "s3-auth", DX_WARN, r->status,
                  "anonymous S3 request SUCCEEDED — the resource is public",
                  "confirm public access is intended; otherwise restrict it" });
    } else {
        dx_http_status(e, "s3-req", r->status);
    }
}


/*
 * WHAT: verdict-render half of the SigV4 probe — classify the signed
 *       request's response.
 * WHY:  extracted from s3_sigv4_probe for the complexity gate.
 * HOW:  2xx = accepted; 403 splits into signature fault vs policy deny by
 *       reading the S3 <Code> element; anything else falls back to the
 *       generic HTTP status classifier.
 */
static void
s3_classify_signed(doctor_ep *e, const brix_http_resp *r)
{
    if (r->status >= 200 && r->status < 300) {
        dx_record(e, &(dx_note){ "s3-sigv4", DX_OK, r->status,
                  "SigV4-signed request accepted (signature/clock/region OK)", "" });
    } else if (r->status == 403) {
        /* read the S3 <Code> element (not a body-wide substring, which
         * could false-match) to tell a signature fault from a policy deny. */
        const char *cs = r->body ? strstr(r->body, "<Code>") : NULL;
        int sig_fault = (cs != NULL
                         && strncmp(cs + 6, "SignatureDoesNotMatch", 21) == 0);
        if (sig_fault) {
            dx_record(e, &(dx_note){ "s3-sigv4", DX_FAIL, 403,
                      "SigV4 signature rejected (SignatureDoesNotMatch — clock skew / region / key mismatch)",
                      "check client clock vs server, the region, and the access key/secret" });
        } else {
            dx_record(e, &(dx_note){ "s3-sigv4", DX_WARN, 403,
                      "signed request denied (access policy, not a signature fault)",
                      "check the bucket/object policy for this identity" });
        }
    } else {
        dx_http_status(e, "s3-sigv4", r->status);
    }
}


/*
 * WHAT: request-build half of the authenticated SigV4 probe.
 * WHY:  extracted from doctor_s3 for the complexity gate; only called when
 *       AWS credentials are present in the environment.
 * HOW:  sign the exact Host header we send, replay the GET with the SigV4
 *       Authorization headers, and hand the response to s3_classify_signed.
 *       PII-free: never emits the key or signature.
 */
static void
s3_sigv4_probe(const http_probe_ctx *pc, const char *ak, const char *sk,
               doctor_ep *e)
{
    brix_http_resp r;
    brix_status    st;
    char           hdrs[1024];
    char           hostport[300];
    const char    *region = getenv("AWS_DEFAULT_REGION");
    s3_sign_req    sq;

    if (region == NULL || region[0] == '\0') { region = "us-east-1"; }
    /* Sign the exact Host header we send (host:port) — the server canonicalises
     * the Host value verbatim, so signing the bare host would mismatch. */
    snprintf(hostport, sizeof(hostport), "%s:%d", pc->host, pc->port);
    sq.method = "GET";
    sq.host   = hostport;
    sq.uri    = pc->path;
    sq.ak     = ak;
    sq.sk     = sk;
    sq.region = region;
    if (s3_sign(&sq, hdrs, sizeof(hdrs)) != 0) {
        dx_record(e, &(dx_note){ "s3-sigv4", DX_WARN, 0, "could not build a SigV4 signature (client)", "" });
        return;
    }
    brix_status_clear(&st);
    if (brix_http_req(pc->host, pc->port, pc->tls, "GET", pc->path, hdrs, NULL,
                      0, pc->tmo, pc->verify, NULL, &r, &st) != 0) {
        dx_record(e, &(dx_note){ "s3-sigv4", DX_WARN, st.kxr, "signed request failed to complete", "" });
        return;
    }
    s3_classify_signed(e, &r);
    brix_http_resp_free(&r);
}


/*
 * s3 deep-dive: connect (+TLS), an UNAUTHENTICATED GET to confirm reachability +
 * that the server enforces auth (403/AccessDenied) vs is public (200) vs missing
 * (404/NoSuchBucket). If AWS_ACCESS_KEY_ID/SECRET are in the environment, also send
 * a SigV4-signed HEAD and confirm the signature is accepted (catches signer/clock/
 * region faults). PII-free: never emits the key or signature.
 */
void
doctor_s3(const diag_args *a, const dx_url_t *u, doctor_ep *e)
{
    brix_http_resp r;
    brix_status    st;
    http_probe_ctx pc;
    const char    *ak = getenv("AWS_ACCESS_KEY_ID");
    const char    *sk = getenv("AWS_SECRET_ACCESS_KEY");

    pc.tls = u->tls;
    pc.host = u->host;
    pc.port = u->port;
    pc.path = u->path;
    pc.tmo = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 8000;
    pc.verify = a->verify_tls;

    memset(e, 0, sizeof(*e));
    e->proto = DXP_S3;
    e->status = DOC_GREEN;
    snprintf(e->host, sizeof(e->host), "%s", u->host);
    e->port = u->port;

    /* Stage 1: reachability + TLS via an unauthenticated GET. */
    brix_status_clear(&st);
    if (brix_http_req(u->host, u->port, u->tls, "GET", u->path, NULL, NULL, 0,
                      pc.tmo, pc.verify, NULL, &r, &st) != 0) {
        dx_http_fail(e, u->tls, &st);
        return;
    }
    e->connected = 1;
    http_record_tls(u->tls, &r, e);
    s3_classify_anon(e, &r);
    brix_http_resp_free(&r);

    /* Stage 2: authenticated SigV4 probe (only if AWS creds are present). */
    if (ak != NULL && sk != NULL && ak[0] != '\0' && sk[0] != '\0') {
        s3_sigv4_probe(&pc, ak, sk, e);
    } else {
        dx_record(e, &(dx_note){ "s3-sigv4", DX_OK, 0,
                  "no AWS credentials in environment — signed-request check skipped (posture only)",
                  "set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY to test SigV4 acceptance" });
    }
}


/*
 * cms deep-dive: a cluster manager (cmsd/redirector) is a root:// endpoint that
 * answers kXR_locate with the data server(s) holding a path and issues kXR_redirect.
 * Connect to the manager, locate the path, and confirm the redirect resolution to a
 * reachable data server; flag no-holder / unreachable-DS (ghost) / redirect issues.
 * Reuses the libbrix locate + reconnect machinery (the redirect loop-guard applies).
 */
void
doctor_cms(const diag_args *a, const char *host, int port, const char *path,
           doctor_ep *e)
{
    brix_url    u;
    brix_conn   c;
    brix_status st;

    memset(e, 0, sizeof(*e));
    e->proto = DXP_CMS;
    e->status = DOC_GREEN;
    snprintf(e->host, sizeof(e->host), "%s", host);
    e->port = port;

    memset(&u, 0, sizeof(u));
    u.scheme = XRDC_SCHEME_ROOT;
    snprintf(u.host, sizeof(u.host), "%s", host);
    u.port = port;
    snprintf(u.path, sizeof(u.path), "%s", path[0] ? path : "/");

    brix_status_clear(&st);
    if (brix_connect(&c, &u, &a->conn, &st) != 0) {
        dx_record(e, &(dx_note){ "cms-connect", DX_FAIL, st.kxr,
                  "could not connect to the cluster manager",
                  "check the manager (cmsd/redirector) is up on this host:port" });
        doc_issue(e, DOC_RED, "manager connect failed");
        return;
    }
    e->connected = 1;
    c.io.timeout_ms = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 8000;
    dx_record(e, &(dx_note){ "cms-connect", DX_OK, 0, "manager reachable + login completed", "" });

    {
        char        loc[2048];
        brix_status lst;
        brix_status_clear(&lst);
        if (brix_locate(&c, u.path, loc, sizeof(loc), &lst) != 0) {
            /* a manager returns NotFound when no server holds the path. */
            dx_record_status(e, "cms-locate", &lst);
        } else {
            char *t, *save;
            for (t = strtok_r(loc, " \t\r\n", &save); t != NULL;
                 t = strtok_r(NULL, " \t\r\n", &save)) {
                if (t[0] == 'S') { e->holders++; }
            }
            if (e->holders == 0) {
                dx_record(e, &(dx_note){ "cms-locate", DX_FAIL, 0,
                          "manager located no data server for the path (no holder)",
                          "check data-server registration and the CMS registry" });
            } else {
                dx_record(e, &(dx_note){ "cms-locate", DX_OK, 0,
                          "manager resolved the path to data server(s)", "" });
            }
        }
    }

    /* Resolution: a stat through the manager must follow the redirect to a live DS.
     * A redirect loop or dead DS surfaces here (the loop-guard returns an error). */
    {
        brix_statinfo si;
        brix_status   rst;
        brix_status_clear(&rst);
        if (brix_stat(&c, u.path, &si, &rst) == 0) {
            dx_record(e, &(dx_note){ "cms-redirect", DX_OK, 0,
                      "manager→data-server redirect resolved to a live server", "" });
        } else if (rst.kxr == kXR_NotFound) {
            dx_record(e, &(dx_note){ "cms-redirect", DX_WARN, rst.kxr,
                      "path not found via the manager (redirect resolved, file absent)",
                      "verify the path exists on a registered data server" });
        } else {
            dx_record(e, &(dx_note){ "cms-redirect", DX_FAIL, rst.kxr,
                      "manager redirect did not resolve to a reachable data server (dead DS / redirect loop)",
                      "check data-server health and the CMS registry for stale entries" });
        }
    }
    brix_close(&c);
}


/*
 * WHAT: classify why the primary connection could not be set up.
 * WHY:  extracted from doctor_one's connect-failure path (complexity gate).
 * HOW:  map errno / status-message onto a fixed cause+remedy pair; the caller
 *       reports the classified cause, not st->msg (wire text may carry PII).
 */
static void
doctor_classify_conn_error(const brix_status *st, const char **cause,
                           const char **remedy)
{
    *cause  = "connection setup failed";
    *remedy = "check the network path and that the server is running";
    if (st->sys_errno == ECONNREFUSED) {
        *cause  = "no listener on host:port (service down or wrong port)";
        *remedy = "start the gateway / verify the port and any firewall";
    } else if (st->sys_errno == ETIMEDOUT || st->sys_errno == EHOSTUNREACH
               || st->sys_errno == ENETUNREACH) {
        *cause  = "host/network unreachable (routing or firewall drop)";
        *remedy = "check routing/firewall and that the host is up";
    } else if (st->msg[0] != '\0' && strstr(st->msg, "resolve") != NULL) {
        *cause  = "DNS resolution failed";
        *remedy = "check the hostname and DNS resolver";
    }
}


/*
 * WHAT: verdict-render half of a failed primary connect — auth rejection vs
 *       transport unreachability, plus the standalone auth-suite.
 * WHY:  extracted from doctor_one for the complexity gate.
 * HOW:  distinguish "server reachable but auth failed" from "couldn't reach
 *       it" by the client's error CODE: XRDC_EAUTH / kXR_NotAuthorized /
 *       kXR_AuthFailed mean auth was attempted and rejected; everything else
 *       is transport.
 */
static void
doctor_one_connect_fail(const diag_args *a, const brix_url *u,
                        const brix_status *st, const char *target,
                        doctor_ep *e)
{
    if (st->kxr == XRDC_EAUTH || st->kxr == kXR_NotAuthorized
        || st->kxr == kXR_AuthFailed) {
        doc_issue(e, DOC_RED, "authentication failed");
        dx_record(e, &(dx_note){ "auth", DX_FAIL, st->kxr,
                  "could not authenticate (credential rejected, or none usable for the server's auth)",
                  "check the credential's validity/scope and that it matches the server's auth mode" });
    } else {
        /* reachability: classify *why* the connection could not be set up. */
        const char *cause, *remedy;
        doctor_classify_conn_error(st, &cause, &remedy);
        /* use the classified cause, not st.msg — wire text may carry PII. */
        doc_issue(e, DOC_RED, "connect failed: %s", cause);
        dx_record(e, &(dx_note){ "reachability", DX_FAIL, st->kxr, cause, remedy });
    }
    /* the auth-suite is self-contained (its own force_anon session) — run it
     * even when our credential could not establish the primary connection. */
    if (a->auth_suite) {
        doctor_auth_suite(a, u, target, 0, e);
    }
}


/*
 * WHAT: session-fact collection over the freshly opened connection —
 *       transport timings, capabilities, TLS state, chosen auth.
 * WHY:  extracted from doctor_one for the complexity gate.
 * HOW:  read the facts off the live conn into *e and flag the
 *       no-silent-downgrade invariant (gotoTLS advertised but cleartext).
 */
static void
doctor_one_session_facts(brix_conn *c, doctor_ep *e)
{
    const char *ver = NULL, *cipher = NULL;

    /* network + transport facts */
    brix_netdiag_facts(c, &e->nf);
    e->caps = (unsigned) c->server_flags;
    e->gototls = (c->server_flags & kXR_gotoTLS) != 0;
    e->tls_active = brix_tls_info(c, &ver, &cipher);
    if (e->tls_active) {
        snprintf(e->tls_ver, sizeof(e->tls_ver), "%s", ver ? ver : "?");
        snprintf(e->tls_cipher, sizeof(e->tls_cipher), "%s", cipher ? cipher : "?");
    }
    snprintf(e->auth, sizeof(e->auth), "%s",
             c->diag.chosen_auth ? c->diag.chosen_auth : "anon");

    /* no-silent-downgrade: gotoTLS advertised but the session is cleartext */
    if (e->gototls && !e->tls_active) {
        doc_issue(e, DOC_RED, "gotoTLS advertised but session is cleartext");
    }
}


/*
 * WHAT: throughput probe over a resolved file.
 * WHY:  extracted from doctor_one for the complexity gate.
 * HOW:  resolve a readable target (skip cleanly if the export is empty),
 *       then time TTFB + MB/s with doctor_xfer. Returns 1 when a target was
 *       resolved (left in `target` for the later probes), else 0.
 */
static int
doctor_one_xfer_probe(brix_conn *c, const brix_url *u, char *target,
                      size_t tsz, doctor_ep *e)
{
    brix_statinfo sti;
    brix_status   rst;

    brix_status_clear(&rst);
    if (resolve_target(c, u, target, tsz, &sti, &rst) != 0) {
        return 0;
    }
    if (doctor_xfer(c, target, &e->ttfb_ms, &e->mbps, &e->xfer_bytes) == 0) {
        e->have_xfer = 1;
    }
    return 1;
}


/*
 * WHAT: post-session load/health signals — /metrics shedding, cwnd/BDP
 *       heuristic, TCP retransmits.
 * WHY:  extracted from doctor_one for the complexity gate.
 * HOW:  best-effort cleartext /metrics scrape (port 0 = skip), then escalate
 *       yellow issues from the facts already collected on *e.
 */
static void
doctor_one_load_signals(const diag_args *a, doctor_ep *e)
{
    /* server-side load signal (cleartext /metrics; best-effort, 0 = skip) */
    if (a->metrics_port > 0) {
        doctor_metrics(e->host, a->metrics_port, e);
    }
    if (e->shedding) {
        doc_issue(e, DOC_YELLOW, "server reports kXR_wait / budget shedding");
    }
    /* cwnd/BDP signal — only meaningful once enough bytes moved to time it. */
    if (e->have_xfer && e->xfer_bytes >= (4 << 20) && e->nf.have_tcpinfo
        && e->nf.rtt_us > 0 && e->nf.rtt_us < 5000 && e->mbps < 5.0) {
        doc_issue(e, DOC_YELLOW, "low throughput (%.1f MB/s) at low RTT — cwnd/BDP?",
                  e->mbps);
    }
    if (e->nf.have_tcpinfo && e->nf.retrans > 0) {
        doc_issue(e, DOC_YELLOW, "%u TCP retransmit(s)", e->nf.retrans);
    }
}


/* Interrogate ONE endpoint into *e. Bounded by the conn timeout (never hangs). */
void
doctor_one(const diag_args *a, const char *url, doctor_ep *e)
{
    brix_url      u;
    brix_conn     c;
    brix_status   st;
    char          target[XRDC_PATH_MAX];
    int           have_target = 0;

    target[0] = '\0';
    memset(e, 0, sizeof(*e));
    e->status = DOC_GREEN;
    brix_status_clear(&st);
    if (brix_endpoint_parse(url, &u, &st) != 0) {
        snprintf(e->host, sizeof(e->host), "%s", url);
        doc_issue(e, DOC_RED, "unparseable URL (bad scheme/host/port)");
        return;
    }
    snprintf(e->host, sizeof(e->host), "%s", u.host);
    e->port = u.port;

    if (brix_connect(&c, &u, &a->conn, &st) != 0) {
        doctor_one_connect_fail(a, &u, &st, target, e);
        return;
    }
    e->connected = 1;
    c.io.timeout_ms = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 8000;

    doctor_one_session_facts(&c, e);

    /* throughput probe over a resolved file (skip cleanly if the export is empty) */
    have_target = doctor_one_xfer_probe(&c, &u, target, sizeof(target), e);

    /* active differential diagnosis — exercise subsystems + classify (incl. locate). */
    doctor_diagnose(a, &c, &u,
                    &(dx_target){ .path = target, .have = have_target }, e);

    brix_close(&c);

    doctor_one_load_signals(a, e);
}


const char *
doc_color(int s)
{
    return s == DOC_RED ? "RED" : s == DOC_YELLOW ? "YELLOW" : "GREEN";
}


/*
 * WHAT: transfer-path diff of one adjacent endpoint pair.
 * WHY:  extracted from doctor_cross for the complexity gate.
 * HOW:  emit TLS-downgrade (critical), auth-fallback, and address-family
 *       asymmetry lines in the original order; returns the number of
 *       critical diffs found (0 or 1).
 */
static int
cross_diff_pair(const doctor_ep *p, const doctor_ep *q, FILE *out)
{
    int crit = 0;

    if (!p->connected || !q->connected) {
        return 0;
    }
    /* TLS-downgrade: a TLS hop followed by a cleartext one */
    if (p->tls_active && !q->tls_active) {
        fprintf(out, "  %s:%d -> %s:%d  TLS DOWNGRADE (encrypted then cleartext)\n",
                p->host, p->port, q->host, q->port);
        crit++;
    }
    /* auth-fallback: the chosen auth weakens across the hop */
    if (strcmp(p->auth, q->auth) != 0) {
        fprintf(out, "  %s:%d -> %s:%d  auth changed %s -> %s\n",
                p->host, p->port, q->host, q->port, p->auth, q->auth);
    }
    /* v4/v6 asymmetry */
    if (p->nf.family && q->nf.family && p->nf.family != q->nf.family) {
        fprintf(out, "  %s:%d -> %s:%d  address-family asymmetry (%s vs %s)\n",
                p->host, p->port, q->host, q->port,
                p->nf.family == 10 ? "IPv6" : "IPv4",
                q->nf.family == 10 ? "IPv6" : "IPv4");
    }
    return crit;
}


/* Cross-endpoint diff engine over the transfer path. Returns #critical diffs. */
int
doctor_cross(const doctor_ep *eps, int n, FILE *out)
{
    int i, crit = 0, connected = 0;
    if (n < 2) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (eps[i].connected) { connected++; }
    }
    if (connected < 2) {
        return 0;   /* fewer than two reachable hops — nothing to compare */
    }
    fprintf(out, "Path analysis (%d hops):\n", n);
    for (i = 1; i < n; i++) {
        crit += cross_diff_pair(&eps[i - 1], &eps[i], out);
    }
    return crit;
}


void
doctor_emit_json(const doctor_ep *eps, int n, FILE *out)
{
    int i, j;
    fprintf(out, "{\"remote_doctor\":{\"endpoints\":[");
    for (i = 0; i < n; i++) {
        const doctor_ep *e = &eps[i];
        fprintf(out, "%s{\"protocol\":\"%s\",\"host\":", i ? "," : "",
                dx_proto_name(e->proto));
        fjson_str(out, e->host);
        fprintf(out, ",\"port\":%d,\"status\":\"%s\","
                "\"connected\":%s,\"facts\":{\"family\":\"%s\","
                "\"tcp_ms\":%.3f,\"tls_ms\":%.3f,\"auth_ms\":%.3f,\"total_ms\":%.3f,"
                "\"rtt_us\":%u,\"retrans\":%u,\"tls\":\"%s\",\"auth\":\"%s\","
                "\"caps\":\"0x%x\",\"ttfb_ms\":%.3f,\"mbps\":%.1f,\"holders\":%d,"
                "\"metrics_http\":%d,\"shedding\":%s},\"issues\":[",
                e->port, doc_color(e->status),
                e->connected ? "true" : "false",
                e->nf.family == 10 ? "IPv6" : e->nf.family == 2 ? "IPv4" : "none",
                e->nf.tcp_ms, e->nf.tls_ms, e->nf.auth_ms, e->nf.total_ms,
                e->nf.rtt_us, e->nf.retrans,
                e->tls_active ? e->tls_ver : "none", e->auth, e->caps,
                e->ttfb_ms, e->mbps, e->holders, e->metrics_http,
                e->shedding ? "true" : "false");
        for (j = 0; j < e->nissues; j++) {
            if (j) { fputc(',', out); }
            fjson_str(out, e->issues[j]);
        }
        fprintf(out, "],\"diagnosis\":[");
        for (j = 0; j < e->ndx; j++) {
            const dx_finding *d = &e->dx[j];
            fprintf(out, "%s{\"probe\":", j ? "," : "");
            fjson_str(out, d->probe);
            fprintf(out, ",\"verdict\":\"%s\",\"kxr\":%d,\"cause\":",
                    dx_verdict_name(d->verdict), d->kxr);
            fjson_str(out, d->cause);
            fprintf(out, ",\"remedy\":");
            fjson_str(out, d->remedy);
            fputc('}', out);
        }
        fprintf(out, "]}");
    }
    fprintf(out, "],\"cross_endpoint_analysis\":{\"hops\":%d}}}\n", n > 1 ? n - 1 : 0);
}


/* Human-readable diagnosis block for one endpoint: each probe's verdict, and for
 * problems the classified cause + remediation. */
void
doctor_print_diagnosis(const doctor_ep *e)
{
    int j;
    if (e->ndx == 0) {
        return;
    }
    printf("  diagnosis:\n");
    for (j = 0; j < e->ndx; j++) {
        const dx_finding *d = &e->dx[j];
        const char       *tag = d->verdict == DX_FAIL ? "FAIL"
                              : d->verdict == DX_WARN ? "WARN" : "ok";
        printf("    [%-4s] %-11s %s\n", tag, d->probe, d->cause);
        if (d->verdict != DX_OK && d->remedy[0] != '\0') {
            printf("           → %s\n", d->remedy);
        }
    }
}


/* Route one URL to its protocol battery by scheme. root:// (and any unrecognized
 * scheme, for back-compat) goes to the full libbrix battery; the rest to their
 * deep-dive batteries. */
void
doctor_dispatch(const diag_args *a, const char *url, doctor_ep *e)
{
    dx_url_t u;

    if (dx_url_parse(url, &u) != 0 || u.proto == DXP_ROOT) {
        doctor_one(a, url, e);
        return;
    }
    switch (u.proto) {
    case DXP_HTTP:
    case DXP_HTTPS:
    case DXP_DAVS:  doctor_http(a, &u, e); break;
    case DXP_S3:    doctor_s3(a, &u, e); break;
    case DXP_CMS:   doctor_cms(a, u.host, u.port, u.path, e); break;
    default:        doctor_one(a, url, e); break;
    }
}


/* Render one endpoint's text report block. WHAT: the [color] header, the
 * per-protocol fact lines, the issue list and the diagnosis block.
 * WHY: the per-endpoint renderer is the bulk of do_remote_doctor's text
 *      path; splitting it keeps the orchestrator under the complexity gate.
 * HOW: verbatim move of the loop body — root/cms print the full libbrix
 *      connect-phase + transport facts, the HTTP family only its TLS line. */
static void
remote_doctor_report_ep(const doctor_ep *e)
{
    int j;

    printf("\n[%s] %s %s:%d\n", doc_color(e->status), dx_proto_name(e->proto),
           e->host, e->port);
    if (!e->connected) {
        for (j = 0; j < e->nissues; j++) { printf("  - %s\n", e->issues[j]); }
        doctor_print_diagnosis(e);
        return;
    }
    /* root/cms use the libbrix connection → full connect-phase + transport facts;
     * the HTTP-family batteries report TLS facts inline + the diagnosis block. */
    if (e->proto == DXP_ROOT) {
        printf("  connect: tcp %.1f / tls %.1f / login+auth %.1f ms  (%s)\n",
               e->nf.tcp_ms, e->nf.tls_ms, e->nf.auth_ms,
               e->nf.family == 10 ? "IPv6" : e->nf.family == 2 ? "IPv4" : "?");
        printf("  auth=%s  tls=%s%s%s  caps=0x%x\n", e->auth,
               e->tls_active ? e->tls_ver : "none",
               e->tls_active ? " " : "", e->tls_active ? e->tls_cipher : "",
               e->caps);
        if (e->nf.have_tcpinfo) {
            printf("  tcp: rtt=%u us retrans=%u\n", e->nf.rtt_us, e->nf.retrans);
        }
        if (e->have_xfer) {
            printf("  xfer: ttfb %.1f ms, %.1f MB/s\n", e->ttfb_ms, e->mbps);
        }
        printf("  holders=%d  metrics=%s%s\n", e->holders,
               e->metrics_http == 200 ? "reachable" : "n/a",
               e->shedding ? " (SHEDDING)" : "");
    } else if (e->tls_active) {
        printf("  tls=%s %s\n", e->tls_ver, e->tls_cipher);
    }
    for (j = 0; j < e->nissues; j++) { printf("  - %s\n", e->issues[j]); }
    doctor_print_diagnosis(e);
}

/* Print the client-side credential validity block. WHAT: token + X509 proxy
 * explanation to stdout, when either is present in the environment.
 * WHY: independent of the per-endpoint loop; the same creds reach every hop.
 * HOW: verbatim move — discover token, read $X509_USER_PROXY, explain both. */
static void
remote_doctor_report_creds(void)
{
    char       *tok = brix_token_discover();
    const char *proxy = getenv("X509_USER_PROXY");

    if (tok != NULL || (proxy != NULL && proxy[0] != '\0')) {
        printf("\nCredentials (in environment):\n");
        if (tok != NULL) { brix_token_explain(tok, stdout); free(tok); }
        if (proxy != NULL && proxy[0] != '\0') {
            brix_gsi_cert_explain(proxy, stdout);
        }
    }
}

int
do_remote_doctor(const diag_args *a)
{
    doctor_ep eps[8];
    int       i, worst = DOC_GREEN, crit;

    if (a->nurls < 1) {
        fprintf(stderr, "xrddiag: remote-doctor needs at least one URL\n");
        return 50;
    }
    for (i = 0; i < a->nurls; i++) {
        doctor_dispatch(a, a->urls[i], &eps[i]);
        if (eps[i].status > worst) {
            worst = eps[i].status;
        }
    }

    if (a->json) {
        doctor_emit_json(eps, a->nurls, stdout);
        return (worst == DOC_RED) ? 1 : 0;
    }

    printf("remote-doctor: %d endpoint(s)\n", a->nurls);
    for (i = 0; i < a->nurls; i++) {
        remote_doctor_report_ep(&eps[i]);
    }

    remote_doctor_report_creds();

    printf("\n");
    crit = doctor_cross(eps, a->nurls, stdout);
    printf("Result: worst=%s, %d critical path issue(s)\n", doc_color(worst), crit);
    return (worst == DOC_RED || crit > 0) ? 1 : 0;
}
