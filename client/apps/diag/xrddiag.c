/*
 * xrddiag.c - (kept) routing + shared helpers
 * Phase-38 split of xrddiag.c; behavior-identical.
 */
#include "diag_internal.h"
#include "cli/jsonout.h"
#include "core/version.h"
#include "core/progname.h"  /* brix_prog_*(): argv[0] identity + brix- strip */
#include "cli/suggest.h"    /* brix_suggest(): did-you-mean at unknown-subcommand sites */
#include "cli/cli_hint.h"   /* brix_cli_hint(): TTY-gated hint output */
#include <stddef.h>         /* offsetof(): option-descriptor field slots */

int g_fails;

const dx_rule DX_RULES[] = {
    /* auth / authorization */    { "auth", kXR_NotAuthorized, DX_FAIL,
      "authentication/authorization rejected",
      "check the client credential and that its auth protocol matches the server's &P= offer" },
    { "auth", kXR_AuthFailed, DX_FAIL,
      "authentication handshake failed (bad/invalid credential)",
      "verify the token signature/issuer or GSI proxy chain; check clock sync" },

    /* namespace (export root) */    { "namespace", kXR_NotFound, DX_FAIL,
      "export root not found (brix_root misconfigured or unmounted)",
      "verify brix_root points to an existing, mounted, readable directory" },
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
      "retry later; raise brix_memory_pool_size or lower concurrency/read size" },
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
      "enable brix_allow_write, or direct writes to a read-write replica" },
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
dx_record(doctor_ep *e, const dx_note *n)
{
    dx_finding *f;
    if (e->ndx >= DOC_MAXDX) {
        return;
    }
    f = &e->dx[e->ndx++];
    snprintf(f->probe, sizeof(f->probe), "%s", n->probe);
    f->verdict = n->verdict;
    f->kxr     = n->kxr;
    snprintf(f->cause, sizeof(f->cause), "%s", n->cause ? n->cause : "");
    snprintf(f->remedy, sizeof(f->remedy), "%s", n->remedy ? n->remedy : "");
    if (n->verdict > e->status) {
        e->status = n->verdict;
    }
}


/*
 * Classify a failed probe (st->kxr) into a finding via DX_RULES, with a graceful
 * generic fallback for codes we have no specific rule for. A successful probe
 * (kxr==0, return 0 → caller records DX_OK) is handled by the caller.
 */
void
dx_record_status(doctor_ep *e, const char *probe, const brix_status *st)
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
        dx_record(e, &(dx_note){ probe, r->sev, kxr, r->cause, r->remedy });
        return;
    }
    {
        /* generic fallback — name the code, give conservative guidance. */
        char cause[160];
        if (kxr > 0) {
            snprintf(cause, sizeof(cause), "%s probe failed: server returned %s",
                     probe, brix_kxr_name(kxr));
        } else {
            /* PII: never echo st->msg — server wire text may carry a path. */
            snprintf(cause, sizeof(cause), "%s probe failed (local/transport error)",
                     probe);
        }
        dx_record(e, &(dx_note){ probe, DX_FAIL, kxr, cause,
                  "inspect the server logs for this operation" });
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
 * Open a scoped diagnostic connection: a copy of the base opts with the
 * credential selection in *sel (force_anon, a specific bearer token, an
 * optional forced auth protocol). Saves/restores $BEARER_TOKEN around the call
 * so the credential matrix never leaks between probes. 0 on connect, -1 + *st.
 */
int
dx_connect_as(const diag_args *a, const brix_url *u, const dx_cred_sel *sel,
              brix_conn *c, brix_status *st)
{
    brix_opts opts = a->conn;
    char     *saved = NULL;
    int       had = 0;
    int       rc;

    opts.force_anon = sel->force_anon;
    if (sel->auth_force != NULL) {
        opts.auth_force = sel->auth_force;
    }
    if (sel->token_override != NULL) {
        const char *cur = getenv("BEARER_TOKEN");
        if (cur != NULL) { saved = strdup(cur); had = (saved != NULL); }
        setenv("BEARER_TOKEN", sel->token_override, 1);  /* checked first in discovery */
    }
    brix_status_clear(st);
    rc = brix_connect(c, u, &opts, st);
    if (sel->token_override != NULL) {
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
 * WHAT: the scheme table for the deep-dive URL parser — one row per recognised
 *       scheme prefix with its protocol, TLS flag, and default port.
 * WHY:  replaces a per-scheme strncmp ladder; adding a scheme is one row.
 * HOW:  dx_scheme_match scans top-to-bottom, first prefix match wins — longer
 *       prefixes ("roots://") MUST precede their proper prefixes ("root://").
 */
typedef struct {
    const char *prefix;    /* scheme prefix including "://"                */
    size_t      len;       /* strlen(prefix), for strncmp + cursor advance */
    dx_proto    proto;     /* protocol battery to route to                 */
    int         tls;       /* scheme implies TLS                           */
    int         defport;   /* default port when the URL names none         */
} dx_scheme_t;

static const dx_scheme_t DX_SCHEMES[] = {
    { "roots://",  8, DXP_ROOT,  1, 1094 },
    { "xroots://", 9, DXP_ROOT,  1, 1094 },
    { "root://",   7, DXP_ROOT,  0, 1094 },
    { "xroot://",  8, DXP_ROOT,  0, 1094 },
    { "https://",  8, DXP_HTTPS, 1, 8443 },
    { "http://",   7, DXP_HTTP,  0, 8080 },
    { "davs://",   7, DXP_DAVS,  1, 8443 },
    { "dav://",    6, DXP_DAVS,  0, 8080 },
    { "s3s://",    6, DXP_S3,    1,  443 },
    { "s3://",     5, DXP_S3,    0, 9000 },
    { "cms://",    6, DXP_CMS,   0, 1213 },
};


/*
 * WHAT: match + consume the URL's scheme prefix against DX_SCHEMES.
 * WHY:  isolates scheme recognition so dx_url_parse stays a small pipeline.
 * HOW:  on the first prefix match, fill proto/tls/port (the scheme default)
 *       and advance *p past the prefix. 0 on match, -1 for an unknown scheme.
 */
static int
dx_scheme_match(const char **p, dx_proto *proto, int *tls, int *port)
{
    size_t k;

    for (k = 0; k < sizeof(DX_SCHEMES) / sizeof(DX_SCHEMES[0]); k++) {
        const dx_scheme_t *s = &DX_SCHEMES[k];
        if (strncmp(*p, s->prefix, s->len) == 0) {
            *proto = s->proto;
            *tls   = s->tls;
            *port  = s->defport;
            *p    += s->len;
            return 0;
        }
    }
    return -1;
}


/*
 * WHAT: parse a bracketed [IPv6] host literal (with optional :port) at *p.
 * WHY:  IPv6 literals embed ':' so they need their own delimiter logic.
 * HOW:  copy the bytes between the brackets into host (must be non-empty and
 *       fit hsz), advance *p past ']', and read a port if ':' follows.
 *       0 on success, -1 on a malformed or over-long literal.
 */
static int
dx_host6_parse(const char **p, char *host, size_t hsz, int *port)
{
    const char *rb = strchr(*p, ']');
    size_t      n;

    if (rb == NULL) {
        return -1;
    }
    n = (size_t) (rb - (*p + 1));
    if (n == 0 || n >= hsz) {
        return -1;
    }
    memcpy(host, *p + 1, n);
    host[n] = '\0';
    *p = rb + 1;
    if (**p == ':') {
        *port = atoi(*p + 1);
    }
    return 0;
}


/*
 * WHAT: parse a plain host name (with optional :port) at *p, up to '/' or NUL.
 * WHY:  companion to dx_host6_parse — the non-bracketed authority form.
 * HOW:  scan to the end of the authority remembering the last ':' (port
 *       separator), copy the host bytes (non-empty, must fit hsz), read the
 *       port if present, and leave *p at the authority end. 0 / -1.
 */
static int
dx_hostname_parse(const char **p, char *host, size_t hsz, int *port)
{
    const char *colon = NULL, *e, *hend;
    size_t      n;

    for (e = *p; *e != '\0' && *e != '/'; e++) {
        if (*e == ':') {
            colon = e;
        }
    }
    hend = colon ? colon : e;
    n = (size_t) (hend - *p);
    if (n == 0 || n >= hsz) {
        return -1;
    }
    memcpy(host, *p, n);
    host[n] = '\0';
    if (colon != NULL) {
        *port = atoi(colon + 1);
    }
    *p = e;
    return 0;
}


/*
 * Parse a scheme://host[:port][/path] URL for the deep-dive router. Recognizes
 * root[s]/xroot[s], http/https, dav/davs, s3/s3s, cms. Fills *u (proto, tls,
 * host, port — a per-scheme default if absent — and path). Returns 0, or -1 if
 * the scheme is unknown. IPv6 literals in [..] are accepted.
 */
int
dx_url_parse(const char *url, dx_url_t *u)
{
    const char *p = url, *slash;
    int         rc;

    u->tls = 0;
    if (dx_scheme_match(&p, &u->proto, &u->tls, &u->port) != 0) {
        return -1;
    }
    rc = (*p == '[') ? dx_host6_parse(&p, u->host, sizeof(u->host), &u->port)
                     : dx_hostname_parse(&p, u->host, sizeof(u->host), &u->port);
    if (rc != 0) {
        return -1;
    }
    if (u->port <= 0 || u->port > 65535) {
        return -1;
    }
    slash = strchr(p, '/');
    snprintf(u->path, sizeof(u->path), "%s", slash ? slash : "/");
    return 0;
}


/* Classify an HTTP status into an "http" finding on e. */
void
dx_http_status(doctor_ep *e, const char *probe, int status)
{
    if (status >= 200 && status < 300) {
        dx_record(e, &(dx_note){ probe, DX_OK, status, "request succeeded", "" });
    } else if (status == 401 || status == 403) {
        dx_record(e, &(dx_note){ probe, DX_WARN, status,
                  "access requires authentication/authorization (401/403)",
                  "provide a credential (Bearer token / cert) if this object should be reachable" });
    } else if (status == 404 || status == 410) {
        dx_record(e, &(dx_note){ probe, DX_WARN, status, "object not found (404/410)",
                  "verify the path/bucket/key exists on the server" });
    } else if (status >= 300 && status < 400) {
        dx_record(e, &(dx_note){ probe, DX_WARN, status, "server returned a redirect (3xx)",
                  "follow the Location target; check it is intended" });
    } else if (status >= 500) {
        dx_record(e, &(dx_note){ probe, DX_FAIL, status, "server error (5xx) on the request",
                  "check the server logs for this operation" });
    } else if (status == 0) {
        dx_record(e, &(dx_note){ probe, DX_FAIL, 0, "no HTTP status parsed (malformed/partial response)",
                  "the endpoint may not be an HTTP server on this port" });
    } else {
        dx_record(e, &(dx_note){ probe, DX_WARN, status, "unexpected HTTP status", "" });
    }
}


/* Classify an HTTP-family transport failure (connect / TLS) on e. */
void
dx_http_fail(doctor_ep *e, int tls, const brix_status *st)
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
    dx_record(e, &(dx_note){ tls ? "tls" : "reachability", DX_FAIL, st->kxr, cause, remedy });
}


/* S3 (SigV4) */
/* Build an AWS SigV4 Authorization header block (path-style URI) via the shared
 * lib signer (lib/s3.c) so xrddiag and xrdcp sign identically. UNSIGNED-PAYLOAD is
 * used as the body hash — accepted by nginx-xrootd's S3 and by real AWS. 0/-1. */
int
s3_sign(const s3_sign_req *q, char *hdrs, size_t hdrsz)
{
    return brix_s3_sign_v4(q->method, q->host, q->uri, q->ak, q->sk, q->region,
                           "UNSIGNED-PAYLOAD", hdrs, hdrsz);
}


/* Write a JSON-escaped, double-quoted string — strings may carry server-supplied
 * wire text (st->msg), so control bytes / quotes / backslashes must be escaped. */
void
fjson_str(FILE *out, const char *s)
{
    brix_json_fputs(out, s);
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


/*
 * usage_fp — print xrddiag usage to the given stream.
 * WHY: --help (WS-2) goes to stdout; no-arg / unknown-subcommand goes to stderr.
 */
static void
usage_fp(FILE *out, const char *prog)
{
    prog = brix_prog_base(prog);   /* display the invoked name, not a path */
    fprintf(out,
        "usage: %s <subcommand> [opts] <url> [...]\n"
        "  subcommands:\n"
        "    check    <url> [--json]               protocol-correctness probes\n"
        "    bench    <url> [-S N] [--sweep]       timed download (single vs streams; knee)\n"
        "    metabench <url> [-S N] [--count N]   concurrent metadata storm: ops/sec + p50/p95/p99\n"
        "    topology <url> [--cluster-url URL] [--json]  locate + redirect convergence\n"
        "    status   <url> [--metrics-port N]     pull /metrics and summarise\n"
        "    watch    <url> [url2...] [--interval S] [--count N] [--prometheus[=PATH]] [--json]\n"
        "                       continuous health/SLA probe (connect+read+locate); Ctrl-C to stop\n"
        "    compare  <urlA> --vs-reference <urlB> root-vs-root size/list/md5\n"
        "    compare  <root-url//path> --davs <host[:port]>  cross-protocol oracle\n"
        "    probe-robustness <url> --i-am-authorized  adversarial reject auditor\n"
        "    replay   <file.xrdcap> [--playback <url>]  decode (or re-issue) a capture\n"
        "    srr      <http[s]-url>                 fetch WLCG Storage Resource Reporting\n"
        "    tape     <http[s]-url//path>           drive the WLCG/FRM Tape REST (stage+poll)\n"
        "    qstats   [-c KEY | -s PATH] host[:port]  kXR_query stats/config/space\n"
        "    wait41   [--timeout S] [--full] host[:port]  wait for server readiness\n"
        "    mpxstats [host | -] [--metrics-port N]  multiplexed mpxstats feed\n"
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
        "        --wire-trace[=N] --timing --probe-timeout <ms>\n"
        "        --version  print version and exit\n",
        prog);
    brix_usage_footer(out, prog);
}

void
usage(const char *prog)
{
    usage_fp(stderr, prog);
}


/*
 * WHAT: the xrddiag option table — every non-connection flag/option as a
 *       {name, kind, diag_args-field-offset} descriptor.
 * WHY:  replaces main()'s 19-arm strcmp ladder; adding an option is one row.
 * HOW:  dx_opt_parse strcmp-matches a row, dx_opt_apply writes the field:
 *       FLAG sets the int to 1, CLEAR to 0, INT/STR consume the next argv
 *       word (a missing value fails the match, so the caller reports the
 *       same "unknown option" error the old fall-through ladder produced).
 */
typedef enum {
    DXO_FLAG,     /* presence flag: int field = 1        */
    DXO_CLEAR,    /* negative flag: int field = 0        */
    DXO_INT,      /* atoi(next argv) into an int field   */
    DXO_STR,      /* next argv into a const char * field */
} dx_opt_kind;

typedef struct {
    const char  *name;    /* exact option spelling                */
    dx_opt_kind  kind;    /* how the value is taken and stored    */
    size_t       off;     /* offsetof(diag_args, <target field>)  */
} dx_opt_t;

static const dx_opt_t DX_OPTS[] = {
    { "-S",                DXO_INT,   offsetof(diag_args, streams) },
    { "--streams",         DXO_INT,   offsetof(diag_args, streams) },
    { "--vs-reference",    DXO_STR,   offsetof(diag_args, ref_url) },
    { "--metrics-port",    DXO_INT,   offsetof(diag_args, metrics_port) },
    { "--cluster-url",     DXO_STR,   offsetof(diag_args, cluster_url) },
    { "--i-am-authorized", DXO_FLAG,  offsetof(diag_args, authorized) },
    { "--i-am-authorised", DXO_FLAG,  offsetof(diag_args, authorized) },
    { "--probe-timeout",   DXO_INT,   offsetof(diag_args, probe_timeout_ms) },
    { "--playback",        DXO_STR,   offsetof(diag_args, playback_url) },
    { "--davs",            DXO_STR,   offsetof(diag_args, davs) },
    { "--sweep",           DXO_FLAG,  offsetof(diag_args, sweep) },
    { "--json",            DXO_FLAG,  offsetof(diag_args, json) },
    { "--allow-write",     DXO_FLAG,  offsetof(diag_args, allow_write) },
    { "--auth-suite",      DXO_FLAG,  offsetof(diag_args, auth_suite) },
    { "--no-verify-tls",   DXO_CLEAR, offsetof(diag_args, verify_tls) },
    { "--dashboard-port",  DXO_INT,   offsetof(diag_args, dashboard_port) },
    { "--interval",        DXO_INT,   offsetof(diag_args, interval_s) },
    { "--count",           DXO_INT,   offsetof(diag_args, count) },
    { "--prometheus",      DXO_FLAG,  offsetof(diag_args, watch_prom) },
};


/*
 * WHAT: apply one matched option descriptor to the args struct.
 * WHY:  keeps the field write (and value consumption) in one place so the
 *       descriptor table stays declarative.
 * HOW:  flags write 1/0 in place; INT/STR advance *i and consume argv[*i].
 *       Returns 0, or -1 when a value-taking option has no next word (the
 *       caller then reports it exactly like an unknown option — the same
 *       behavior the original fall-through ladder had).
 */
static int
dx_opt_apply(diag_args *a, const dx_opt_t *o, int argc, char **argv, int *i)
{
    char *base = (char *) a;

    if (o->kind == DXO_FLAG) {
        *(int *) (base + o->off) = 1;
        return 0;
    }
    if (o->kind == DXO_CLEAR) {
        *(int *) (base + o->off) = 0;
        return 0;
    }
    if (*i + 1 >= argc) {
        return -1;
    }
    ++*i;
    if (o->kind == DXO_INT) {
        *(int *) (base + o->off) = atoi(argv[*i]);
    } else {
        *(const char **) (base + o->off) = argv[*i];
    }
    return 0;
}


/*
 * WHAT: parse one xrddiag-specific option at argv[*i].
 * WHY:  main()'s per-option knowledge lives in DX_OPTS; this is just lookup.
 * HOW:  exact match against the table, then the one prefix-form option
 *       (--prometheus=PATH). Returns 0 on success (advancing *i past any
 *       consumed value), -1 for an unknown option or a missing value.
 */
static int
dx_opt_parse(diag_args *a, int argc, char **argv, int *i)
{
    const char *p = argv[*i];
    size_t      k;

    for (k = 0; k < sizeof(DX_OPTS) / sizeof(DX_OPTS[0]); k++) {
        if (strcmp(p, DX_OPTS[k].name) == 0) {
            return dx_opt_apply(a, &DX_OPTS[k], argc, argv, i);
        }
    }
    if (strncmp(p, "--prometheus=", 13) == 0) {
        a->watch_prom = 1;
        a->prom_path  = p + 13;
        return 0;
    }
    return -1;
}


/*
 * WHAT: collected positional (non-option) arguments — the URL list.
 * WHY:  bundles the array + count so the argv walker stays under the
 *       parameter cap while main keeps ownership of the storage.
 */
typedef struct {
    const char *v[8];    /* positional args in order (URL cap)  */
    int         n;       /* how many of v[] are filled          */
} dx_pos_t;


/*
 * WHAT: walk argv[2..] splitting options from positional URLs.
 * WHY:  isolates the whole option/positional scan (including the shared
 *       connection-option parser and its --help path) out of main.
 * HOW:  option-shaped words go to brix_opts_parse_arg first, then the
 *       DX_OPTS table; everything else lands in pos (capped). Returns 0 to
 *       continue, or 1 with *rc set when main should exit immediately
 *       (--help → 0, unknown option / too many URLs → 50).
 */
static int
dx_parse_argv(diag_args *a, int argc, char **argv, dx_pos_t *pos, int *rc)
{
    int i;

    for (i = 2; i < argc; i++) {
        const char *p = argv[i];
        if (p[0] == '-' && p[1] != '\0' && strcmp(p, "-") != 0) {
            int pr = brix_opts_parse_arg(&a->conn, argc, argv, &i);
            if (pr == 2) {         /* --help */
                usage_fp(stdout, argv[0]);
                *rc = 0;
                return 1;
            }
            if (pr) {
                continue;
            }
            if (dx_opt_parse(a, argc, argv, &i) != 0) {
                fprintf(stderr, "xrddiag: unknown option '%s'\n", p);
                usage(argv[0]);
                *rc = 50;
                return 1;
            }
        } else if (pos->n < (int) (sizeof(pos->v) / sizeof(pos->v[0]))) {
            pos->v[pos->n++] = p;
        } else {
            fprintf(stderr, "xrddiag: too many arguments (max %zu URLs)\n",
                    sizeof(pos->v) / sizeof(pos->v[0]));
            *rc = 50;
            return 1;
        }
    }
    return 0;
}


/*
 * WHAT: route the multi-call personalities before normal parsing.
 * WHY:  the absorbed micro-tools stay invocable via symlinks (argv[0]) and
 *       double as xrddiag subcommands (argv[1]). The installed link names
 *       carry a -brix suffix (wait41-brix, mpxstats-brix) so the client RPM
 *       co-installs with the stock xrootd server RPMs, which own the bare
 *       names; the bare spellings remain reachable as subcommands.
 * HOW:  match argv[0]'s basename against the installed link names, then
 *       argv[1] against the subcommand aliases (shifting argv by one).
 *       Returns 1 with *rc set when a personality ran, 0 to continue as
 *       xrddiag.
 */
static int
dx_personality_route(int argc, char **argv, int *rc)
{
    /* strip any co-install "brix-" prefix so brix-xrdqstats still routes to the
     * xrdqstats personality (busybox dispatch on basename(argv[0])). */
    const char *base = brix_prog_strip_compat(brix_prog_base(argv[0]));

    /* The bare-name personalities carry a -brix suffix in the stock package
     * (wait41-brix); the compat package spells them brix-wait41, which strips to
     * the bare "wait41". Accept both so either install layout routes correctly. */
    if (strcmp(base, "xrdqstats") == 0) { *rc = brix_qstats_main(argc, argv); return 1; }
    if (strcmp(base, "wait41-brix") == 0   || strcmp(base, "wait41") == 0)   { *rc = brix_wait41_main(argc, argv); return 1; }
    if (strcmp(base, "mpxstats-brix") == 0 || strcmp(base, "mpxstats") == 0) { *rc = brix_mpxstats_main(argc, argv); return 1; }
    if (argc >= 2) {
        if (strcmp(argv[1], "qstats") == 0)   { *rc = brix_qstats_main(argc - 1, argv + 1); return 1; }
        if (strcmp(argv[1], "wait41") == 0)   { *rc = brix_wait41_main(argc - 1, argv + 1); return 1; }
        if (strcmp(argv[1], "mpxstats") == 0) { *rc = brix_mpxstats_main(argc - 1, argv + 1); return 1; }
    }
    return 0;
}


/*
 * WHAT: the xrddiag subcommand dispatch table.
 * WHY:  replaces main()'s strcmp ladder; adding a subcommand is one row
 *       (plus its spelling in XRDDIAG_CMDS below for the did-you-mean hint).
 * HOW:  dx_dispatch scans for an exact name match and calls the handler.
 */
typedef struct {
    const char *name;                  /* subcommand spelling  */
    int       (*fn)(const diag_args *); /* handler → exit code */
} dx_cmd_t;

static const dx_cmd_t DX_CMDS[] = {
    { "remote-doctor",    do_remote_doctor },
    { "watch",            do_watch },
    { "check",            do_check },
    { "bench",            do_bench },
    { "metabench",        do_metabench },
    { "topology",         do_topology },
    { "status",           do_status },
    { "compare",          do_compare },
    { "probe-robustness", do_probe_robustness },
    { "replay",           do_replay },
    { "srr",              do_srr },
    { "tape",             do_tape },
};


/*
 * WHAT: report an unrecognised subcommand and exit-code 50.
 * WHY:  spec WS-7: every unknown-command site must suggest a close match
 *       for interactive users (TTY-gated, pipeline-silent per C3).
 * HOW:  static NULL-terminated table of all xrddiag subcommands feeds
 *       brix_suggest for the did-you-mean hint, then usage to stderr.
 */
static int
dx_unknown_sub(const char *sub, const char *prog)
{
    static const char *const XRDDIAG_CMDS[] = {
        "remote-doctor", "watch", "check", "bench", "metabench",
        "topology", "status", "compare", "probe-robustness", "replay",
        "srr", "tape", "qstats", "wait41", "mpxstats", NULL
    };
    const char *suggestion = brix_suggest(sub, XRDDIAG_CMDS);

    fprintf(stderr, "xrddiag: unknown subcommand '%s'\n", sub);
    if (suggestion != NULL) {
        brix_cli_hint("hint: did you mean '%s'?\n", suggestion);
    }
    usage(prog);
    return 50;
}


/*
 * WHAT: run the named subcommand against the parsed args.
 * WHY:  table lookup keeps main a straight parse→dispatch pipeline.
 * HOW:  first exact DX_CMDS match wins; a miss goes through the
 *       did-you-mean reporter.
 */
static int
dx_dispatch(const char *sub, const diag_args *a, const char *prog)
{
    size_t k;

    for (k = 0; k < sizeof(DX_CMDS) / sizeof(DX_CMDS[0]); k++) {
        if (strcmp(sub, DX_CMDS[k].name) == 0) {
            return DX_CMDS[k].fn(a);
        }
    }
    return dx_unknown_sub(sub, prog);
}


int
main(int argc, char **argv)
{
    diag_args   a;
    dx_pos_t    pos;
    const char *sub;
    int         i, rc;

    if (dx_personality_route(argc, argv, &rc)) {
        return rc;
    }
    if (argc < 2) {
        usage(argv[0]);
        return 50;
    }
    sub = argv[1];
    if (strcmp(sub, "--version") == 0) {
        printf("%s (BriX-Cache client) %s\n", brix_prog_base(argv[0]),
               brix_client_version());
        return 0;
    }
    if (strcmp(sub, "-h") == 0) {
        usage(argv[0]);     /* -h → stderr (C1 — keep existing behavior) */
        return 0;
    }
    if (strcmp(sub, "--help") == 0) {
        usage_fp(stdout, argv[0]);   /* --help → stdout (WS-2) */
        return 0;
    }

    memset(&a, 0, sizeof(a));
    a.conn.verify_host = 1;
    a.metrics_port = 9100;
    a.verify_tls = 1;       /* verify HTTPS/davs/s3 peer certs unless --no-verify-tls */
    brix_crypto_init();   /* arm libxrdproto SHA-256/HMAC for GSI + sigver */

    memset(&pos, 0, sizeof(pos));
    if (dx_parse_argv(&a, argc, argv, &pos, &rc)) {
        return rc;
    }

    if (pos.n < 1) {
        usage(argv[0]);
        return 50;
    }
    a.url = pos.v[0];
    if (a.ref_url == NULL && pos.n == 2) {
        a.ref_url = pos.v[1];   /* allow `compare urlA urlB` positional form */
    }
    for (i = 0; i < pos.n; i++) {      /* remote-doctor: the whole transfer path */
        a.urls[i] = pos.v[i];
    }
    a.nurls = pos.n;

    return dx_dispatch(sub, &a, argv[0]);
}
