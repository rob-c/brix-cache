/*
 * diag_authsuite.c - differential authZ suite: JWT/base64url, URL parse, HTTP/S3 sign, JSON scrape.
 * Phase-38 split of xrddiag.c; behavior-identical.
 */
#include "diag_internal.h"
#include "cli/jsonout.h"

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


