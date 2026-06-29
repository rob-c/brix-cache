/*
 * xrddiag.c - (kept) routing + shared helpers
 * Phase-38 split of xrddiag.c; behavior-identical.
 */
#include "diag_internal.h"

int g_fails;

const dx_rule DX_RULES[] = {
    /* auth / authorization */    { "auth", kXR_NotAuthorized, DX_FAIL,
      "authentication/authorization rejected",
      "check the client credential and that its auth protocol matches the server's &P= offer" },
    { "auth", kXR_AuthFailed, DX_FAIL,
      "authentication handshake failed (bad/invalid credential)",
      "verify the token signature/issuer or GSI proxy chain; check clock sync" },

    /* namespace (export root) */    { "namespace", kXR_NotFound, DX_FAIL,
      "export root not found (xrootd_root misconfigured or unmounted)",
      "verify xrootd_root points to an existing, mounted, readable directory" },
    { "namespace", kXR_NotAuthorized, DX_FAIL,
      "listing the export root is denied (ACL/scope)",
      "check path ACLs / token scope for the root path" },
    { "namespace", kXR_IOError, DX_FAIL,
      "I/O error reading the export root (filesystem fault)",
      "check server storage health (dmesg/SMART); verify the mount is responsive" },

    /* read path */    { "read", kXR_NotAuthorized, DX_FAIL,
      "read denied (ACL or token read scope)",
      "check the read scope / VO ACL for the path" },
    { "read", kXR_IOError, DX_FAIL,
      "server-side read I/O error",
      "check server storage health; the backing file/device may be faulty" },
    { "read", kXR_NotFound, DX_WARN,
      "file vanished between locate and open (namespace race/inconsistency)",
      "re-check the path; flush any stale redirect/namespace cache" },
    { "read", kXR_NoMemory, DX_FAIL,
      "server out of memory on read (budget shed)",
      "retry later; raise xrootd_memory_pool_size or lower concurrency/read size" },
    { "read", kXR_Overloaded, DX_WARN,
      "server overloaded on read",
      "retry with backoff; the server is at a connection/request cap" },

    /* checksum integrity */    { "checksum", kXR_Unsupported, DX_WARN,
      "server does not support checksum query",
      "informational; checksum verification unavailable on this server" },

    /* locate / replicas */    { "locate", kXR_NotFound, DX_WARN,
      "file not found, or no replica registered for the path",
      "verify the path exists; check the CMS/manager registry for replicas" },
    { "locate", kXR_noserver, DX_FAIL,
      "no data server available for the path",
      "bring a data server online; check the CMS/manager registry" },

    /* write path (gated) */    { "write", kXR_fsReadOnly, DX_FAIL,
      "export is read-only (allow_write off or filesystem mounted ro)",
      "enable xrootd_allow_write, or direct writes to a read-write replica" },
    { "write", kXR_NotAuthorized, DX_FAIL,
      "write denied (token lacks write scope, or ACL)",
      "obtain a credential with write scope; check the write ACL for the path" },
    { "write", kXR_overQuota, DX_FAIL,
      "quota exceeded",
      "free space or raise the user/group quota" },
    { "write", kXR_NoSpace, DX_FAIL,
      "no space left on the export filesystem",
      "free disk space on the server export" },
    { "write", kXR_IOError, DX_FAIL,
      "server-side write I/O error",
      "check server storage health and that the export is writable" },
};

volatile sig_atomic_t g_watch_stop;



void
note(const char *name, const char *fmt, ...)
{
    char    detail[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);
    printf("  [NOTE] %-22s %s\n", name, detail);
}


/* active diagnosis — exercise subsystems, classify symptom → cause    */

/*
 * WHAT: the symptom→cause rule table. Each row maps a (probe, kXR-code) pair to a
 *       verdict + a PII-free root cause + a remediation.
 * WHY:  turns a raw server status ("kXR_NotAuthorized on write") into an actionable
 *       diagnosis ("export is read-only → enable allow_write"). The mapping is keyed on
 *       BOTH the probe and the code because the same code means different things per
 *       subsystem (NotAuthorized on read = ACL; on write = read-only/scope).
 * HOW:  dx_classify scans top-to-bottom for the first row whose probe matches (or is the
 *       NULL wildcard) and whose kxr matches (or is the DX_ANY wildcard). Unmatched codes
 *       fall back to a generic finding so we never invent guidance we are unsure of.
 */



/* Append a classified finding; escalate the endpoint's status to its severity. */
void
dx_record(doctor_ep *e, const char *probe, int verdict, int kxr,
          const char *cause, const char *remedy)
{
    dx_finding *f;
    if (e->ndx >= DOC_MAXDX) {
        return;
    }
    f = &e->dx[e->ndx++];
    snprintf(f->probe, sizeof(f->probe), "%s", probe);
    f->verdict = verdict;
    f->kxr     = kxr;
    snprintf(f->cause, sizeof(f->cause), "%s", cause ? cause : "");
    snprintf(f->remedy, sizeof(f->remedy), "%s", remedy ? remedy : "");
    if (verdict > e->status) {
        e->status = verdict;
    }
}


/*
 * Classify a failed probe (st->kxr) into a finding via DX_RULES, with a graceful
 * generic fallback for codes we have no specific rule for. A successful probe
 * (kxr==0, return 0 → caller records DX_OK) is handled by the caller.
 */
void
dx_record_status(doctor_ep *e, const char *probe, const xrdc_status *st)
{
    size_t i;
    int    kxr = st ? st->kxr : 0;
    for (i = 0; i < sizeof(DX_RULES) / sizeof(DX_RULES[0]); i++) {
        const dx_rule *r = &DX_RULES[i];
        if (r->probe != NULL && strcmp(r->probe, probe) != 0) {
            continue;
        }
        if (r->kxr != DX_ANY && r->kxr != kxr) {
            continue;
        }
        dx_record(e, probe, r->sev, kxr, r->cause, r->remedy);
        return;
    }
    {
        /* generic fallback — name the code, give conservative guidance. */
        char cause[160];
        if (kxr > 0) {
            snprintf(cause, sizeof(cause), "%s probe failed: server returned %s",
                     probe, xrdc_kxr_name(kxr));
        } else {
            /* PII: never echo st->msg — server wire text may carry a path. */
            snprintf(cause, sizeof(cause), "%s probe failed (local/transport error)",
                     probe);
        }
        dx_record(e, probe, DX_FAIL, kxr, cause,
                  "inspect the server logs for this operation");
    }
}


/* Is the target a loopback host? Write-mutation probes run unconditionally only here;
 * for any other host they additionally require the explicit --i-am-authorized gate. */
int
dx_is_loopback(const char *host)
{
    /* Exact match only — a prefix like "127." would match "127.attacker.com" and
     * wrongly enable mutating probes on a remote host. Anything not exactly a
     * loopback literal must pass --i-am-authorized instead. */
    return host != NULL && (strcmp(host, "127.0.0.1") == 0
        || strcmp(host, "localhost") == 0 || strcmp(host, "::1") == 0);
}


/* auth/permissions suite (--auth-suite) — differential authZ testing  */

/* base64url-encode (no padding) into out[outsz] — to assemble synthetic JWTs for
 * negative tests. Returns 0, or -1 if the encoded form would not fit (the caller
 * then skips the test rather than emitting a truncated token). */
int
dx_b64url_enc(const unsigned char *in, size_t n, char *out, size_t outsz)
{
    static const char T[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t i, o = 0;
    if ((n + 2) / 3 * 4 + 1 > outsz) {     /* encoded length + NUL must fit */
        return -1;
    }
    for (i = 0; i + 3 <= n; i += 3) {
        uint32_t v = ((uint32_t) in[i] << 16) | ((uint32_t) in[i+1] << 8) | in[i+2];
        out[o++] = T[(v >> 18) & 63]; out[o++] = T[(v >> 12) & 63];
        out[o++] = T[(v >> 6) & 63];  out[o++] = T[v & 63];
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t) in[i] << 16;
        out[o++] = T[(v >> 18) & 63]; out[o++] = T[(v >> 12) & 63];
    } else if (n - i == 2) {
        uint32_t v = ((uint32_t) in[i] << 16) | ((uint32_t) in[i+1] << 8);
        out[o++] = T[(v >> 18) & 63]; out[o++] = T[(v >> 12) & 63];
        out[o++] = T[(v >> 6) & 63];
    }
    out[o] = '\0';
    return 0;
}


/* Build "<b64url(header)>.<b64url(payload)>.<sig>" into out. 0 / -1 on overflow. */
int
dx_make_jwt(const char *header, const char *payload, const char *sig,
            char *out, size_t outsz)
{
    char h[192], p[320];   /* sized for the short fixed probe header/payload below */
    if (dx_b64url_enc((const unsigned char *) header, strlen(header), h, sizeof(h)) != 0
        || dx_b64url_enc((const unsigned char *) payload, strlen(payload), p, sizeof(p)) != 0) {
        return -1;
    }
    if (strlen(h) + strlen(p) + strlen(sig) + 3 > outsz) {
        return -1;
    }
    snprintf(out, outsz, "%s.%s.%s", h, p, sig);
    return 0;
}


/*
 * Open a scoped diagnostic connection: a copy of the base opts with force_anon
 * and/or a specific bearer token (token_override, NULL = use the env as-is) and
 * an optional forced auth protocol. Saves/restores $BEARER_TOKEN around the call
 * so the credential matrix never leaks between probes. 0 on connect, -1 + *st.
 */
int
dx_connect_as(const diag_args *a, const xrdc_url *u, int force_anon,
              const char *token_override, const char *auth_force,
              xrdc_conn *c, xrdc_status *st)
{
    xrdc_opts opts = a->conn;
    char     *saved = NULL;
    int       had = 0;
    int       rc;

    opts.force_anon = force_anon;
    if (auth_force != NULL) {
        opts.auth_force = auth_force;
    }
    if (token_override != NULL) {
        const char *cur = getenv("BEARER_TOKEN");
        if (cur != NULL) { saved = strdup(cur); had = (saved != NULL); }
        setenv("BEARER_TOKEN", token_override, 1);  /* checked first in discovery */
    }
    xrdc_status_clear(st);
    rc = xrdc_connect(c, u, &opts, st);
    if (token_override != NULL) {
        if (had) { setenv("BEARER_TOKEN", saved, 1); free(saved); }
        else     { unsetenv("BEARER_TOKEN"); }
    }
    return rc;
}


/* ================================================================== */
/* multi-protocol deep-dive: http / https / davs / s3 / cms batteries  */
/* ================================================================== */

const char *
dx_proto_name(dx_proto p)
{
    switch (p) {
    case DXP_HTTP:  return "http";
    case DXP_HTTPS: return "https";
    case DXP_DAVS:  return "davs";
    case DXP_S3:    return "s3";
    case DXP_CMS:   return "cms";
    default:        return "root";
    }
}


/*
 * Parse a scheme://host[:port][/path] URL for the deep-dive router. Recognizes
 * root[s]/xroot[s], http/https, dav/davs, s3/s3s, cms. Fills proto, *tls, host,
 * *port (a per-scheme default if absent), and path. Returns 0, or -1 if the scheme
 * is unknown. IPv6 literals in [..] are accepted.
 */
int
dx_url_parse(const char *url, dx_proto *proto, int *tls, char *host, size_t hsz,
             int *port, char *path, size_t psz)
{
    const char *p = url, *hoststart, *slash;
    int         defport;

    *tls = 0;
    if      (strncmp(p, "roots://", 8) == 0)  { *proto = DXP_ROOT; *tls = 1; defport = 1094; p += 8; }
    else if (strncmp(p, "xroots://", 9) == 0) { *proto = DXP_ROOT; *tls = 1; defport = 1094; p += 9; }
    else if (strncmp(p, "root://", 7) == 0)   { *proto = DXP_ROOT; defport = 1094; p += 7; }
    else if (strncmp(p, "xroot://", 8) == 0)  { *proto = DXP_ROOT; defport = 1094; p += 8; }
    else if (strncmp(p, "https://", 8) == 0)  { *proto = DXP_HTTPS; *tls = 1; defport = 8443; p += 8; }
    else if (strncmp(p, "http://", 7) == 0)   { *proto = DXP_HTTP; defport = 8080; p += 7; }
    else if (strncmp(p, "davs://", 7) == 0)   { *proto = DXP_DAVS; *tls = 1; defport = 8443; p += 7; }
    else if (strncmp(p, "dav://", 6) == 0)    { *proto = DXP_DAVS; defport = 8080; p += 6; }
    else if (strncmp(p, "s3s://", 6) == 0)    { *proto = DXP_S3; *tls = 1; defport = 443; p += 6; }
    else if (strncmp(p, "s3://", 5) == 0)     { *proto = DXP_S3; defport = 9000; p += 5; }
    else if (strncmp(p, "cms://", 6) == 0)    { *proto = DXP_CMS; defport = 1213; p += 6; }
    else { return -1; }

    *port = defport;
    hoststart = p;
    if (*p == '[') {                            /* [IPv6] */
        const char *rb = strchr(p, ']');
        if (rb == NULL) { return -1; }
        {
            size_t n = (size_t) (rb - (p + 1));
            if (n == 0 || n >= hsz) { return -1; }
            memcpy(host, p + 1, n); host[n] = '\0';
        }
        p = rb + 1;
        if (*p == ':') { *port = atoi(p + 1); }
    } else {
        const char *colon = NULL, *e;
        for (e = hoststart; *e != '\0' && *e != '/'; e++) {
            if (*e == ':') { colon = e; }
        }
        {
            const char *hend = colon ? colon : e;
            size_t      n = (size_t) (hend - hoststart);
            if (n == 0 || n >= hsz) { return -1; }
            memcpy(host, hoststart, n); host[n] = '\0';
            if (colon != NULL) { *port = atoi(colon + 1); }
        }
    }
    if (*port <= 0 || *port > 65535) { return -1; }
    slash = strchr(p, '/');
    snprintf(path, psz, "%s", slash ? slash : "/");
    return 0;
}


/* Classify an HTTP status into an "http" finding on e. */
void
dx_http_status(doctor_ep *e, const char *probe, int status)
{
    if (status >= 200 && status < 300) {
        dx_record(e, probe, DX_OK, status, "request succeeded", "");
    } else if (status == 401 || status == 403) {
        dx_record(e, probe, DX_WARN, status,
                  "access requires authentication/authorization (401/403)",
                  "provide a credential (Bearer token / cert) if this object should be reachable");
    } else if (status == 404 || status == 410) {
        dx_record(e, probe, DX_WARN, status, "object not found (404/410)",
                  "verify the path/bucket/key exists on the server");
    } else if (status >= 300 && status < 400) {
        dx_record(e, probe, DX_WARN, status, "server returned a redirect (3xx)",
                  "follow the Location target; check it is intended");
    } else if (status >= 500) {
        dx_record(e, probe, DX_FAIL, status, "server error (5xx) on the request",
                  "check the server logs for this operation");
    } else if (status == 0) {
        dx_record(e, probe, DX_FAIL, 0, "no HTTP status parsed (malformed/partial response)",
                  "the endpoint may not be an HTTP server on this port");
    } else {
        dx_record(e, probe, DX_WARN, status, "unexpected HTTP status", "");
    }
}


/* Classify an HTTP-family transport failure (connect / TLS) on e. */
void
dx_http_fail(doctor_ep *e, int tls, const xrdc_status *st)
{
    const char *cause  = "connection setup failed";
    const char *remedy = "check the endpoint is up and the port is correct";
    if (tls && st->kxr == XRDC_EAUTH) {
        cause  = "TLS verification failed (cert untrusted/expired/wrong host)";
        remedy = "fix the server certificate chain, or pass --no-verify-tls for a self-signed test endpoint";
    } else if (st->sys_errno == ECONNREFUSED) {
        cause  = "no listener on host:port (service down or wrong port)";
        remedy = "start the gateway / verify the port and any firewall";
    } else if (st->sys_errno == ETIMEDOUT || st->sys_errno == EHOSTUNREACH
               || st->sys_errno == ENETUNREACH) {
        cause  = "host/network unreachable";
        remedy = "check routing/firewall and that the host is up";
    }
    doc_issue(e, DOC_RED, "%s", cause);
    dx_record(e, tls ? "tls" : "reachability", DX_FAIL, st->kxr, cause, remedy);
}


/* S3 (SigV4) */
/* Build an AWS SigV4 Authorization header block (path-style URI) via the shared
 * lib signer (lib/s3.c) so xrddiag and xrdcp sign identically. UNSIGNED-PAYLOAD is
 * used as the body hash — accepted by nginx-xrootd's S3 and by real AWS. 0/-1. */
int
s3_sign(const char *method, const char *host, const char *uri,
        const char *ak, const char *sk, const char *region,
        char *hdrs, size_t hdrsz)
{
    return xrdc_s3_sign_v4(method, host, uri, ak, sk, region,
                           "UNSIGNED-PAYLOAD", hdrs, hdrsz);
}


/* Write a JSON-escaped, double-quoted string — strings may carry server-supplied
 * wire text (st->msg), so control bytes / quotes / backslashes must be escaped. */
void
fjson_str(FILE *out, const char *s)
{
    fputc('"', out);
    for (; s != NULL && *s != '\0'; s++) {
        unsigned char ch = (unsigned char) *s;
        switch (ch) {
        case '"':  fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\n': fputs("\\n", out);  break;
        case '\r': fputs("\\r", out);  break;
        case '\t': fputs("\\t", out);  break;
        default:
            /* escape control AND high bytes so the output is always valid JSON,
             * even if a server returned non-ASCII wire text. */
            if (ch < 0x20 || ch >= 0x80) { fprintf(out, "\\u%04x", ch); }
            else                         { fputc((int) ch, out); }
        }
    }
    fputc('"', out);
}


const char *
dx_verdict_name(int v)
{
    return v == DX_FAIL ? "fail" : v == DX_WARN ? "warn" : "ok";
}


/* srr + tape — HTTP/JSON consumers over the general HTTP client        */

/* Scalar JSON scan (flat fields; no nesting awareness — sufficient for the SRR /
 * Tape-REST documents). Extract the string value of "key":"value" into out. 1/0. */
int
js_str(const char *json, const char *key, char *out, size_t osz)
{
    char        pat[64];
    const char *p, *v, *e;
    if (json == NULL) { return 0; }
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(json, pat);
    if (p == NULL) { return 0; }
    p = strchr(p + strlen(pat), ':');
    if (p == NULL) { return 0; }
    p++;
    while (*p == ' ' || *p == '\t') { p++; }
    if (*p != '"') { return 0; }
    v = p + 1;
    /* Find the closing quote, honouring backslash escapes: a '"' preceded by an
     * even number of backslashes is the delimiter; an odd number means it's \". */
    e = v;
    while (*e != '\0') {
        if (*e == '"') {
            const char *bs = e;
            int         nb = 0;
            while (bs > v && bs[-1] == '\\') { nb++; bs--; }
            if ((nb & 1) == 0) { break; }
        }
        e++;
    }
    if (*e != '"') { return 0; }
    {
        size_t n = (size_t) (e - v);
        if (n >= osz) { n = osz - 1; }
        memcpy(out, v, n);
        out[n] = '\0';
    }
    return 1;
}


/* Sum every numeric "key": N occurrence in the document (e.g. all shares' sizes). */
long long
js_sum(const char *json, const char *key)
{
    char        pat[64];
    const char *p;
    long long   sum = 0;
    if (json == NULL) { return 0; }
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = json;
    while ((p = strstr(p, pat)) != NULL) {
        const char *c = strchr(p + strlen(pat), ':');
        p += strlen(pat);
        if (c != NULL) {
            const char *n = c + 1;
            long long   v;
            while (*n == ' ' || *n == '\t') { n++; }
            v = strtoll(n, NULL, 10);
            /* saturating add — a diagnostic total must never wrap to nonsense. */
            if (v > 0 && sum > LLONG_MAX - v)      { sum = LLONG_MAX; }
            else if (v < 0 && sum < LLONG_MIN - v) { sum = LLONG_MIN; }
            else                                   { sum += v; }
        }
    }
    return sum;
}


/* Count occurrences of a key (e.g. number of storage shares). */
int
js_count(const char *json, const char *key)
{
    char        pat[64];
    const char *p;
    int         n = 0;
    if (json == NULL) { return 0; }
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = json;
    while ((p = strstr(p, pat)) != NULL) { n++; p += strlen(pat); }
    return n;
}


void
usage(void)
{
    fprintf(stderr,
        "usage: xrddiag <subcommand> [opts] <url> [...]\n"
        "  subcommands:\n"
        "    check    <url>                        protocol-correctness probes\n"
        "    bench    <url> [-S N] [--sweep]       timed download (single vs streams; knee)\n"
        "    metabench <url> [-S N] [--count N]   concurrent metadata storm: ops/sec + p50/p95/p99\n"
        "    topology <url> [--cluster-url URL]    locate + redirect convergence\n"
        "    status   <url> [--metrics-port N]     pull /metrics and summarise\n"
        "    watch    <url> [url2...] [--interval S] [--count N] [--prometheus[=PATH]] [--json]\n"
        "                       continuous health/SLA probe (connect+read+locate); Ctrl-C to stop\n"
        "    compare  <urlA> --vs-reference <urlB> root-vs-root size/list/md5\n"
        "    compare  <root-url//path> --davs <host[:port]>  cross-protocol oracle\n"
        "    probe-robustness <url> --i-am-authorized  adversarial reject auditor\n"
        "    replay   <file.xrdcap> [--playback <url>]  decode (or re-issue) a capture\n"
        "    srr      <http[s]-url>                 fetch WLCG Storage Resource Reporting\n"
        "    tape     <http[s]-url//path>           drive the WLCG/FRM Tape REST (stage+poll)\n"
        "    remote-doctor <url> [url2 ...] [--json] [--allow-write] [--auth-suite]\n"
        "                       actively diagnose server problems (auth/namespace/read/\n"
        "                       checksum/locate/load; --allow-write adds write+stage probes;\n"
        "                       --auth-suite adds the auth/permissions test-suite:\n"
        "                       anon-bypass, forged/expired-token rejection, scope enforcement)\n"
        "                       MULTI-PROTOCOL: each URL's scheme picks the battery —\n"
        "                       root[s]://, http://, https://, davs://|dav://, s3://|s3s://, cms://\n"
        "                       (every stage: connect/TLS/auth/request/ranges/checksum/listing/\n"
        "                       redirect). [--no-verify-tls] for self-signed HTTPS/davs/s3 endpoints\n"
        "  url: host[:port] or <scheme>://host[:port][/path]\n"
        "  capture a session with: xrdcp/xrdfs --capture <file.xrdcap> ...\n"
        "  opts: --tls --notlsok --noverifyhost --auth <gsi|ztn|unix>\n"
        "        --wire-trace[=N] --timing --probe-timeout <ms>\n");
}


int
main(int argc, char **argv)
{
    diag_args   a;
    const char *sub;
    const char *pos[8] = { NULL };
    int         npos = 0, i;

    if (argc < 2) {
        usage();
        return 50;
    }
    sub = argv[1];
    if (strcmp(sub, "-h") == 0 || strcmp(sub, "--help") == 0) {
        usage();
        return 0;
    }

    memset(&a, 0, sizeof(a));
    a.conn.verify_host = 1;
    a.metrics_port = 9100;
    a.verify_tls = 1;       /* verify HTTPS/davs/s3 peer certs unless --no-verify-tls */
    xrootd_crypto_init();   /* arm libxrdproto SHA-256/HMAC for GSI + sigver */

    for (i = 2; i < argc; i++) {
        const char *p = argv[i];
        if (p[0] == '-' && p[1] != '\0' && strcmp(p, "-") != 0) {
            if (xrdc_opts_parse_arg(&a.conn, argc, argv, &i)) { continue; }
            if ((strcmp(p, "-S") == 0 || strcmp(p, "--streams") == 0) && i + 1 < argc) { a.streams = atoi(argv[++i]); }
            else if (strcmp(p, "--vs-reference") == 0 && i + 1 < argc) { a.ref_url = argv[++i]; }
            else if (strcmp(p, "--metrics-port") == 0 && i + 1 < argc) { a.metrics_port = atoi(argv[++i]); }
            else if (strcmp(p, "--cluster-url") == 0 && i + 1 < argc) { a.cluster_url = argv[++i]; }
            else if (strcmp(p, "--i-am-authorized") == 0 || strcmp(p, "--i-am-authorised") == 0) { a.authorized = 1; }
            else if (strcmp(p, "--probe-timeout") == 0 && i + 1 < argc) { a.probe_timeout_ms = atoi(argv[++i]); }
            else if (strcmp(p, "--playback") == 0 && i + 1 < argc) { a.playback_url = argv[++i]; }
            else if (strcmp(p, "--davs") == 0 && i + 1 < argc) { a.davs = argv[++i]; }
            else if (strcmp(p, "--sweep") == 0) { a.sweep = 1; }
            else if (strcmp(p, "--json") == 0) { a.json = 1; }
            else if (strcmp(p, "--allow-write") == 0) { a.allow_write = 1; }
            else if (strcmp(p, "--auth-suite") == 0) { a.auth_suite = 1; }
            else if (strcmp(p, "--no-verify-tls") == 0) { a.verify_tls = 0; }
            else if (strcmp(p, "--dashboard-port") == 0 && i + 1 < argc) { a.dashboard_port = atoi(argv[++i]); }
            else if (strcmp(p, "--interval") == 0 && i + 1 < argc) { a.interval_s = atoi(argv[++i]); }
            else if (strcmp(p, "--count") == 0 && i + 1 < argc) { a.count = atoi(argv[++i]); }
            else if (strcmp(p, "--prometheus") == 0) { a.watch_prom = 1; }
            else if (strncmp(p, "--prometheus=", 13) == 0) { a.watch_prom = 1; a.prom_path = p + 13; }
            else {
                fprintf(stderr, "xrddiag: unknown option '%s'\n", p);
                usage();
                return 50;
            }
        } else if (npos < (int) (sizeof(pos) / sizeof(pos[0]))) {
            pos[npos++] = p;
        } else {
            fprintf(stderr, "xrddiag: too many arguments (max %zu URLs)\n",
                    sizeof(pos) / sizeof(pos[0]));
            return 50;
        }
    }

    if (npos < 1) {
        usage();
        return 50;
    }
    a.url = pos[0];
    if (a.ref_url == NULL && npos == 2) {
        a.ref_url = pos[1];   /* allow `compare urlA urlB` positional form */
    }
    for (i = 0; i < npos; i++) {       /* remote-doctor: the whole transfer path */
        a.urls[i] = pos[i];
    }
    a.nurls = npos;

    if (strcmp(sub, "remote-doctor") == 0) { return do_remote_doctor(&a); }
    if (strcmp(sub, "watch") == 0)         { return do_watch(&a); }
    if (strcmp(sub, "check") == 0)         { return do_check(&a); }
    if (strcmp(sub, "bench") == 0)         { return do_bench(&a); }
    if (strcmp(sub, "metabench") == 0)     { return do_metabench(&a); }
    if (strcmp(sub, "topology") == 0)      { return do_topology(&a); }
    if (strcmp(sub, "status") == 0)        { return do_status(&a); }
    if (strcmp(sub, "compare") == 0)       { return do_compare(&a); }
    if (strcmp(sub, "probe-robustness") == 0) { return do_probe_robustness(&a); }
    if (strcmp(sub, "replay") == 0)        { return do_replay(&a); }
    if (strcmp(sub, "srr") == 0)           { return do_srr(&a); }
    if (strcmp(sub, "tape") == 0)          { return do_tape(&a); }

    fprintf(stderr, "xrddiag: unknown subcommand '%s'\n", sub);
    usage();
    return 50;
}
