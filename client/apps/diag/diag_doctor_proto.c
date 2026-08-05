/*
 * diag_doctor_proto.c — remote-doctor protocol deep-dive batteries (Phase-38 split).
 *
 * WHAT: the per-protocol endpoint doctors for the HTTP family (http/https/davs),
 *       S3 (anonymous posture + SigV4 signer check), and CMS (cluster-manager
 *       locate/redirect resolution).
 * WHY:  split from diag_doctor.c to hold each TU within the Phase-38 size
 *       budget; these three batteries share the http_probe_ctx request shape
 *       and the TLS-fact recorder, and are dispatched together by scheme, so
 *       they form one cohesive concern distinct from the root:// probe layer.
 * HOW:  each doctor fills a doctor_ep from bounded HTTP/root requests and
 *       records verdicts via the extern contract in diag_internal.h. No goto;
 *       PII-free (statuses / header names / sizes only — never keys or bodies).
 */
#include "diag_internal.h"
#include "core/compat/host_split.h"   /* brix_split_host_port(): DS authority parse */


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
                      NULL, 0, pc->tmo, pc->verify, NULL, NULL, &r, &st) == 0) {
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
                      "Depth: 1\r\n", NULL, 0, pc->tmo, pc->verify, NULL, NULL, &r,
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
                      pc.tmo, pc.verify, NULL, NULL, &r, &st) != 0) {
        brix_status_clear(&st);
        if (brix_http_req(u->host, u->port, u->tls, "GET", u->path,
                          "Range: bytes=0-0\r\n", NULL, 0, pc.tmo, pc.verify,
                          NULL, NULL, &r, &st) != 0) {
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
                      0, pc->tmo, pc->verify, NULL, NULL, &r, &st) != 0) {
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
                      pc.tmo, pc.verify, NULL, NULL, &r, &st) != 0) {
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
 * §5.4 cns-stat-drift: compare the manager's (CNS) view of a path against the
 * data server that holds it. A size/mtime disagreement ⇒ stale/unconverged
 * inventory; a DS that will not connect/stat at all ⇒ a ghost registration.
 * PII-free: records classified cause/remedy only, never the path. */
static void
cms_stat_drift_check(const diag_args *a, const char *ds_auth, const char *path,
                     const brix_statinfo *si_mgr, doctor_ep *e)
{
    brix_url      du;
    brix_conn     dc;
    brix_status   dst;
    brix_statinfo si_ds;
    char          host[256], dsurl[320];
    int           port, v6;

    if (brix_split_host_port(ds_auth, host, sizeof(host), &port, 1094) != 0) {
        return;
    }
    v6 = (strchr(host, ':') != NULL && host[0] != '[');
    snprintf(dsurl, sizeof(dsurl), "root://%s%s%s:%d/",
             v6 ? "[" : "", host, v6 ? "]" : "", port);
    brix_status_clear(&dst);
    if (brix_endpoint_parse(dsurl, &du, &dst) != 0) {
        return;
    }
    snprintf(du.path, sizeof(du.path), "%s", path[0] ? path : "/");
    if (brix_connect(&dc, &du, &a->conn, &dst) != 0) {
        dx_record(e, &(dx_note){ "cms-ghost", DX_FAIL, dst.kxr,
            "located holder does not serve the path (ghost registration)",
            "remove the stale CMS registry entry / restart the data server" });
        return;
    }
    dc.io.timeout_ms = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 8000;
    brix_status_clear(&dst);
    if (brix_stat(&dc, du.path, &si_ds, &dst) == 0) {
        long dm = si_ds.mtime - si_mgr->mtime;
        if (dm < 0) { dm = -dm; }
        if (si_ds.size != si_mgr->size || dm > 2) {
            dx_record(e, &(dx_note){ "cns-stat-drift", DX_WARN, 0,
                "manager (CNS) metadata disagrees with the data server",
                "check the DS emit path / manager inventory convergence" });
        } else {
            dx_record(e, &(dx_note){ "cns-stat-drift", DX_OK, 0,
                "manager (CNS) metadata agrees with the data server", "" });
        }
    } else {
        dx_record(e, &(dx_note){ "cms-ghost", DX_FAIL, dst.kxr,
            "located holder present but does not stat the path (ghost/stale entry)",
            "remove the stale CMS registry entry / restart the data server" });
    }
    brix_close(&dc);
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
    char        ds_auth[288];

    ds_auth[0] = '\0';
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
                if (t[0] == 'S') {
                    e->holders++;
                    if (ds_auth[0] == '\0' && t[1] != '\0') {
                        snprintf(ds_auth, sizeof(ds_auth), "%s", t + 2);
                    }
                }
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
            /* §5.4: with --config-audit, cross-check the manager's (CNS) stat
             * against the data server that holds the path (drift / ghost). */
            e->mgr_stat_size  = si.size;
            e->mgr_stat_mtime = si.mtime;
            e->mgr_stat_have  = 1;
            if ((a->config_audit || a->all_servers) && ds_auth[0] != '\0') {
                cms_stat_drift_check(a, ds_auth, u.path, &si, e);
            }
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
