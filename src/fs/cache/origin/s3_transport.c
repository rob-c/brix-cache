/*
 * s3_transport.c — server-side libcurl implementation of brix_s3_transport_t.
 * See the header. Runs only on the blocking cache-fill worker thread.
 */

#include "s3_transport.h"

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/path/path.h"                  /* brix_sanitize_log_string */

#include <curl/curl.h>
#include <ctype.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>

/* ---- upstream-request trace (phase-68, optional) --------------------------
 * Every origin request (cvmfs Stratum-1 fills/HEADs, and any other protocol
 * using this shared transport) emits one line naming the upstream host, URL,
 * status, bytes and wall-time. It is logged at NGX_LOG_DEBUG by default (so
 * `error_log … debug` shows it without a --with-debug rebuild) and promoted
 * to NGX_LOG_INFO when an operator turns tracing on for a cvmfs location
 * (brix_cvmfs_trace on → brix_origin_trace_set(1), inherited by workers).
 * Correlation with the client-op line is by PATH: under fill-coalescing one
 * upstream fetch backs many client requests, so path is truer than an id. */
static int  g_origin_trace_info;   /* set pre-fork from the cvmfs merge */

void
brix_origin_trace_set(int info_on)
{
    g_origin_trace_info = info_on ? 1 : 0;
}

/* ---- stall detection (fast-fail bounds) -----------------------------------
 * The shared vtable's per-request `timeout_ms` is only an OUTER ceiling. A
 * connection that blackholes at connect, or opens and then delivers no bytes
 * (DPI on the path, or an origin rate-limiting a single node), otherwise hangs
 * for the whole ceiling — burning a CVMFS client's hold window on one attempt
 * so the retry/failover machinery never runs. These process-global bounds make
 * such a connection fail in SECONDS, converting a hang into a fast transport
 * error the fill loop can retry (with a fresh curl handle = a fresh connection)
 * inside the hold budget. Set pre-fork from the cvmfs merge, inherited by every
 * worker — operator policy, not per-request data, so it rides beside the trace
 * flag rather than widening the transport signature (shared with the client
 * build). 0 = leave libcurl's default (feature off). */
static long  g_origin_connect_ms;      /* CURLOPT_CONNECTTIMEOUT_MS (ms)   */
static long  g_origin_stall_secs;      /* CURLOPT_LOW_SPEED_TIME (seconds) */
static long  g_origin_stall_bytes;     /* CURLOPT_LOW_SPEED_LIMIT (bytes/s) */
static long  g_origin_attempt_ms;      /* CURLOPT_TIMEOUT_MS cap (ms)      */

void
brix_s3_origin_timeouts_set(long connect_ms, long stall_secs,
    long stall_bytes_per_s, long attempt_ms)
{
    g_origin_connect_ms  = connect_ms  > 0 ? connect_ms  : 0;
    g_origin_stall_secs  = stall_secs  > 0 ? stall_secs  : 0;
    g_origin_stall_bytes = stall_bytes_per_s > 0 ? stall_bytes_per_s : 0;
    g_origin_attempt_ms  = attempt_ms  > 0 ? attempt_ms  : 0;
}

/* Connection reuse toggle (default ON = reuse). Reusing one keep-alive
 * connection per fill thread amortizes the handshake + TCP slow-start on a
 * high-latency link — but on a path with a middlebox that silently reaps idle
 * connections, a reused-but-dead connection makes the next request time out
 * (no RST to trigger curl's fresh-connection retry). Set OFF to force a fresh
 * connection per request (the pre-2026-07-03 behaviour) when reuse hurts more
 * than it helps on a hostile network. Set pre-fork from the cvmfs merge. */
static int  g_origin_no_reuse;      /* 0 = reuse (default), 1 = fresh per req */

void
brix_s3_origin_reuse_set(int reuse_on)
{
    g_origin_no_reuse = reuse_on ? 0 : 1;
}

/* Origin HTTP-version policy (phase-85 F11). 0 = unset: never touch
 * CURLOPT_HTTP_VERSION, so libcurl's own default policy stays in force —
 * byte-frozen parity with every build before the directive existed. Non-zero
 * values use the brix_cvmfs_origin_http_e wire encoding (11/20/21/30); see
 * s3_transport.h. Set pre-fork from the cvmfs merge. */
static int  g_origin_http_version;

void
brix_s3_origin_http_version_set(int ver)
{
    g_origin_http_version = ver;
}

int
brix_s3_origin_http_version_supported(int ver)
{
    curl_version_info_data  *vi;

    switch (ver) {
    case 11:
        return 1;                          /* every libcurl speaks HTTP/1.1 */
    case 20:
    case 21:
        vi = curl_version_info(CURLVERSION_NOW);
        return (vi != NULL && (vi->features & CURL_VERSION_HTTP2)) ? 1 : 0;
    case 30:
#ifdef CURL_VERSION_HTTP3
        vi = curl_version_info(CURLVERSION_NOW);
        return (vi != NULL && (vi->features & CURL_VERSION_HTTP3)) ? 1 : 0;
#else
        return 0;                          /* built against pre-H3 headers */
#endif
    default:
        return 0;
    }
}

/* Map the operator policy onto CURLOPT_HTTP_VERSION for this request. Unset
 * (the default) sets nothing — libcurl's own policy stays untouched. */
static void
s3o_apply_http_version(CURL *curl)
{
    switch (g_origin_http_version) {
    case 11:
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                         (long) CURL_HTTP_VERSION_1_1);
        break;
    case 20:
        /* ALPN h2 over TLS / h2c Upgrade over cleartext; libcurl falls back
         * to 1.1 by itself when the origin does not negotiate. */
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                         (long) CURL_HTTP_VERSION_2_0);
        break;
    case 21:
        /* Cleartext h2 with prior knowledge: no Upgrade dance, no fallback —
         * the origin must speak h2c directly (nghttpd/haproxy h2c listener). */
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                         (long) CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
        break;
#ifdef CURL_VERSION_HTTP3
    case 30:
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                         (long) CURL_HTTP_VERSION_3);
        break;
#endif
    default:
        break;                             /* 0 = unset: libcurl default */
    }
}

/* The version the origin ACTUALLY negotiated for a completed transfer, as the
 * short trace token ("1.1", "2", …), or NULL when libcurl cannot say. Makes an
 * HTTP/2→1.1 fallback observable in the trace line instead of silent. */
static const char *
s3o_negotiated_proto(CURL *curl)
{
    long  ver = 0;

    if (curl_easy_getinfo(curl, CURLINFO_HTTP_VERSION, &ver) != CURLE_OK) {
        return NULL;
    }
    switch (ver) {
    case CURL_HTTP_VERSION_1_0: return "1.0";
    case CURL_HTTP_VERSION_1_1: return "1.1";
    case CURL_HTTP_VERSION_2_0: return "2";
#ifdef CURL_VERSION_HTTP3
    case CURL_HTTP_VERSION_3:   return "3";
#endif
    default:                    return NULL;
    }
}

static long
s3o_ms_since(const struct timespec *t0)
{
    struct timespec now;
    long            ms;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    ms = (now.tv_sec - t0->tv_sec) * 1000L
       + (now.tv_nsec - t0->tv_nsec) / 1000000L;
    return ms < 0 ? 0 : ms;
}

/* Transport-private response: the captured body + raw response header block. */
typedef struct {
    char   *body;
    size_t  body_len;
    size_t  body_cap;
    char   *hdrs;          /* raw "Name: value\r\n" lines as received */
    size_t  hdrs_len;
    size_t  hdrs_cap;
} s3o_resp_t;

/* Append `n` bytes to a growable buffer; returns 0 / -1 (OOM). */
static int
s3o_buf_append(char **buf, size_t *len, size_t *cap, const char *src, size_t n)
{
    if (*len + n + 1 > *cap) {
        size_t newcap = (*cap == 0) ? 8192 : *cap;
        char  *nb;

        while (*len + n + 1 > newcap) {
            newcap *= 2;
        }
        nb = realloc(*buf, newcap);
        if (nb == NULL) {
            return -1;
        }
        *buf = nb;
        *cap = newcap;
    }
    memcpy(*buf + *len, src, n);
    *len += n;
    (*buf)[*len] = '\0';
    return 0;
}

static size_t
s3o_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    s3o_resp_t *r = userdata;
    size_t      n = size * nmemb;

    if (s3o_buf_append(&r->body, &r->body_len, &r->body_cap, ptr, n) != 0) {
        return 0;          /* signal write error → libcurl aborts */
    }
    return n;
}

static size_t
s3o_header_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    s3o_resp_t *r = userdata;
    size_t      n = size * nmemb;

    if (s3o_buf_append(&r->hdrs, &r->hdrs_len, &r->hdrs_cap, ptr, n) != 0) {
        return 0;
    }
    return n;
}

/* Split the CRLF-separated header block sd_s3 built into a curl_slist, dropping
 * blank lines and any trailing CR. Returns the list (caller frees) or NULL. */
static struct curl_slist *
s3o_build_slist(const char *headers)
{
    struct curl_slist *list = NULL;
    const char        *p = headers;

    while (p != NULL && *p != '\0') {
        const char *eol = strpbrk(p, "\r\n");
        size_t      linelen = (eol != NULL) ? (size_t) (eol - p) : strlen(p);

        if (linelen > 0) {
            char line[1024];

            if (linelen >= sizeof(line)) {
                linelen = sizeof(line) - 1;
            }
            memcpy(line, p, linelen);
            line[linelen] = '\0';
            list = curl_slist_append(list, line);
        }
        if (eol == NULL) {
            break;
        }
        p = eol + strspn(eol, "\r\n");   /* skip the CR/LF run */
    }
    return list;
}

/* s3o_trace_t — the fields of one upstream-request trace line.
 *
 * WHAT: Bundles the request-identity (method/host/port/path) plus the outcome
 *       (status/bytes/duration/error) that s3o_trace() formats into a single
 *       line.
 * WHY:  The trace inputs were passed as 8 loose params; a small file-local
 *       descriptor keeps the emit signature at one argument and lets the two
 *       call sites (transport failure vs HTTP outcome) fill a stack struct in
 *       place with no behavior change.
 * HOW:  `status` < 0 marks a transport-level failure (curl error text in
 *       `err`); otherwise it is the HTTP status and `err` is NULL. `path` is
 *       wire-derived and gets sanitized by s3o_trace(). */
typedef struct {
    const char *method;
    const char *host;
    int         port;
    const char *path;              /* path_and_query, wire-derived → sanitized */
    int         status;            /* < 0 = transport failure, else HTTP status */
    size_t      bytes;
    long        dur_ms;
    const char *err;               /* curl error text when status < 0, else NULL */
    const char *proto;             /* negotiated HTTP version token, or NULL     */
} s3o_trace_t;

/* Emit one upstream-request trace line from a filled s3o_trace_t. Logged at
 * DEBUG normally, promoted to INFO under brix_cvmfs_trace. */
static void
s3o_trace(const s3o_trace_t *t)
{
    ngx_uint_t level = g_origin_trace_info ? NGX_LOG_INFO : NGX_LOG_DEBUG;
    char       safe[1024];

    if (ngx_cycle == NULL || ngx_cycle->log == NULL
        || ngx_cycle->log->log_level < level)
    {
        return;                          /* below the configured level: cheap */
    }
    brix_sanitize_log_string(t->path != NULL ? t->path : "",
                               safe, sizeof(safe));
    if (t->status < 0) {
        ngx_log_error(level, ngx_cycle->log, 0,
            "cvmfs-trace: upstream %s http://%s:%d%s FAILED (%s) dur_ms=%l",
            t->method, t->host, t->port, safe,
            t->err ? t->err : "transport error", t->dur_ms);
    } else {
        ngx_log_error(level, ngx_cycle->log, 0,
            "cvmfs-trace: upstream %s http://%s:%d%s status=%d bytes=%uz "
            "host=%s:%d dur_ms=%l proto=%s",
            t->method, t->host, t->port, safe, t->status, t->bytes,
            t->host, t->port, t->dur_ms,
            t->proto != NULL ? t->proto : "?");
    }
}

/* ---- connection reuse (one long-lived connection per fill thread) ----------
 * A fresh curl handle per request opened AND tore down a new TCP connection for
 * EVERY origin request — ruinous on a high-latency link, where each object then
 * paid the full TCP+HTTP handshake and a TCP slow-start ramp from a cold
 * congestion window (so small objects finished before reaching full speed).
 * Instead we keep ONE handle per fill thread and curl_easy_reset() it between
 * requests: reset clears the per-request options but PRESERVES the live
 * connection pool and DNS cache, so the 2nd..Nth request to the same Stratum-1
 * reuses the already-open, already-warmed keep-alive connection — no handshake,
 * no re-resolve, no slow-start restart. Per-thread because a curl easy handle
 * cannot be shared across threads concurrently; a handful of warm connections
 * replace thousands of cold ones. The pthread_key destructor cleans the handle
 * up when the fill thread exits. */
static pthread_key_t   g_curl_key;
static pthread_once_t  g_curl_key_once = PTHREAD_ONCE_INIT;

static void
s3o_curl_thread_free(void *handle)
{
    if (handle != NULL) {
        curl_easy_cleanup((CURL *) handle);
    }
}

static void
s3o_curl_key_init(void)
{
    (void) pthread_key_create(&g_curl_key, s3o_curl_thread_free);
}

/* This thread's persistent handle, reset and ready for a new request with its
 * connection pool intact. Creates it on first use; NULL only on alloc failure. */
static CURL *
s3o_curl_acquire(void)
{
    CURL *handle;

    (void) pthread_once(&g_curl_key_once, s3o_curl_key_init);
    handle = (CURL *) pthread_getspecific(g_curl_key);
    if (handle != NULL) {
        curl_easy_reset(handle);       /* keeps live connections + DNS cache */
        return handle;
    }
    handle = curl_easy_init();
    if (handle != NULL) {
        (void) pthread_setspecific(g_curl_key, handle);
    }
    return handle;
}

/* s3o_apply_ca — point libcurl at the operator-configured trusted CA for origin
 * TLS verification.
 *
 * WHAT: When `ca_path` is a non-empty filesystem path, set CURLOPT_CAPATH (for a
 *       hashed CA directory) or CURLOPT_CAINFO (for a single PEM bundle file) so
 *       the origin's server certificate is verified against THAT trust anchor.
 * WHY:  The https backend leg (phase-70) fetches from an origin whose server cert
 *       is signed by an operator/site CA that is NOT in the system bundle (e.g. a
 *       test PKI or a private grid CA). Without this the handshake fails with
 *       "SSL peer certificate was not OK". Mirrors brix_pelican_set_ca().
 * HOW:  A NULL/empty path leaves libcurl's default system bundle untouched, so a
 *       real-S3 / public-https origin (whose cert chains to a public root) keeps
 *       working. The path type is probed with stat(): a directory → CAPATH (a
 *       hashed-symlink CA dir), anything else (a regular file, or unstattable but
 *       operator-supplied) → CAINFO (a bundle). Verification stays ON regardless;
 *       this only widens WHICH roots are trusted, never disables the check. */
static void
s3o_apply_ca(CURL *curl, const char *ca_path)
{
    struct stat st;

    if (ca_path == NULL || ca_path[0] == '\0') {
        return;                          /* keep libcurl's system bundle */
    }
    if (stat(ca_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        curl_easy_setopt(curl, CURLOPT_CAPATH, ca_path);
    } else {
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_path);
    }
}

/* s3o_request_t — one origin request's inputs, shared by the plain and
 * cred-scoped transport slots.
 *
 * WHAT: The immutable inputs of a single synchronous libcurl request: the
 *       target (host/port/tls), the HTTP call (method/path/headers/body), the
 *       caller timeout, the OPTIONAL mutual-TLS client cert, and the operator CA
 *       context (`tctx`).
 * WHY:  Both vtable entry points (s3o_request / s3o_request_cred) pass the same
 *       dozen-plus arguments straight through to one shared body; collapsing
 *       them into a file-local descriptor keeps the shared body and its extracted
 *       helpers at one argument instead of fourteen, with no behavior change.
 * HOW:  `tctx` is the transport's OPTIONAL context — a NUL-terminated CA
 *       file-or-dir PATH (the operator's trusted CA for origin TLS), or NULL for
 *       libcurl's system bundle; applied via s3o_apply_ca(). `client_cert_pem`
 *       is NULL for the plain slot; on a `tls` request a non-empty path is
 *       presented as the mutual-TLS client cert (cert chain + key in one PEM). */
typedef struct {
    void        *tctx;             /* operator CA path (via s3o_apply_ca), or NULL */
    const char  *host;
    int          port;
    int          tls;
    const char  *method;
    const char  *path_and_query;
    const char  *headers;
    const void  *body;
    size_t       body_len;
    int          timeout_ms;
    const char  *client_cert_pem;  /* mutual-TLS client PEM, or NULL (plain slot) */
} s3o_request_t;

/* s3o_build_headers — build the curl_slist for one request.
 *
 * WHAT: Parses the pre-built header block into a curl_slist and appends the
 *       forced Host header plus the Expect-suppression line.
 * WHY:  sd_s3 signs the SigV4 canonical host as "host:port" for EVERY port, so
 *       libcurl's default of dropping the port on 80/443 would break the
 *       signature — the Host header must be sent byte-for-byte as signed. Expect:
 *       100-continue is suppressed because some S3 servers stall on it and sd_s3
 *       does not rely on it.
 * HOW:  Returns the list (caller frees via curl_slist_free_all); byte-identical
 *       to the inlined sequence it replaces. */
static struct curl_slist *
s3o_build_headers(const s3o_request_t *req)
{
    struct curl_slist *slist = s3o_build_slist(req->headers);
    char               host_hdr[300];

    snprintf(host_hdr, sizeof(host_hdr), "Host: %s:%d", req->host, req->port);
    slist = curl_slist_append(slist, host_hdr);
    slist = curl_slist_append(slist, "Expect:");
    return slist;
}

/* s3o_apply_timeouts — apply the per-attempt ceiling and the fast-fail bounds.
 *
 * WHAT: Sets CURLOPT_TIMEOUT_MS (the per-attempt total ceiling) and, when the
 *       operator configured them, CURLOPT_CONNECTTIMEOUT_MS and the low-speed
 *       stall bounds.
 * WHY:  The process-global attempt cap (operator policy) wins over the caller's
 *       timeout so a whole connect+transfer is abandoned promptly and the fill
 *       loop retries on a fresh connection inside the client's window; the
 *       connect and low-speed bounds turn a blackholed connect or a
 *       connected-but-silent origin into a fast transport error.
 * HOW:  A 0 operator value leaves libcurl's default; the stall pair takes effect
 *       only together. Byte-identical to the inlined option sequence. */
static void
s3o_apply_timeouts(CURL *curl, int timeout_ms)
{
    long total_ms = (g_origin_attempt_ms > 0) ? g_origin_attempt_ms
                  : (timeout_ms > 0 ? timeout_ms : 60000);

    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, total_ms);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    if (g_origin_connect_ms > 0) {
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, g_origin_connect_ms);
    }
    if (g_origin_stall_secs > 0 && g_origin_stall_bytes > 0) {
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, g_origin_stall_secs);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, g_origin_stall_bytes);
    }
}

/* s3o_apply_reuse — apply the connection-reuse policy for this request.
 *
 * WHAT: Either forbids reuse (fresh connection per request) or enables warm
 *       keep-alive reuse with the middlebox-death guards (TCP keepalive + a
 *       bounded max-age).
 * WHY:  Reusing one warm connection per fill thread amortizes the handshake and
 *       TCP slow-start on a high-latency link; the no-reuse escape hatch restores
 *       the pre-2026-07-03 one-connection-per-request behaviour on a hostile
 *       network where a reaped-but-reused connection would time out.
 * HOW:  Reads the process-global g_origin_no_reuse flag; byte-identical to the
 *       inlined branch it replaces. */
static void
s3o_apply_reuse(CURL *curl)
{
    if (g_origin_no_reuse) {
        curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);
        curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1L);
        return;
    }
    curl_easy_setopt(curl, CURLOPT_MAXCONNECTS, 16L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 15L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 15L);
#ifdef CURLOPT_MAXAGE_CONN
    curl_easy_setopt(curl, CURLOPT_MAXAGE_CONN, 20L);
#endif
}

/* s3o_apply_method — select the HTTP method and attach any request body.
 *
 * WHAT: For HEAD sets NOBODY; for methods other than GET sets the custom request
 *       verb and, when present, the POST body. GET needs no options (libcurl's
 *       default).
 * WHY:  sd_s3 drives HEAD/GET/PUT/DELETE over this one transport; the verb and
 *       body wiring is the only method-specific curl state.
 * HOW:  Byte-identical to the inlined method dispatch it replaces. */
static void
s3o_apply_method(CURL *curl, const s3o_request_t *req)
{
    if (strcmp(req->method, "HEAD") == 0) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        return;
    }
    if (strcmp(req->method, "GET") == 0) {
        return;
    }
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, req->method);
    if (req->body != NULL && req->body_len > 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                         (curl_off_t) req->body_len);
    } else {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) 0);
    }
}

/* s3o_apply_tls — apply TLS verification, the operator CA, and mutual-TLS cert.
 *
 * WHAT: On a `tls` request, enables peer/host verification, points libcurl at
 *       the operator CA (via s3o_apply_ca), and — when a client PEM was supplied
 *       — presents it as the mutual-TLS client certificate.
 * WHY:  Origin TLS verification is the operator's trust decision (verify by
 *       default so a misconfigured origin fails loudly); the mutual-TLS cert
 *       authenticates the origin hop AS the end user (phase-70 §5.1 GSI
 *       pass-through/select over an https backend leg).
 * HOW:  A non-TLS request is a no-op. Verification stays ON regardless; the CA
 *       context only widens which roots are trusted. The client cert is read
 *       (cert + key) from the one combined PEM and, because the handle is reset
 *       per request, never leaks into a later anonymous/bearer request.
 *       Byte-identical to the inlined TLS block it replaces. */
static void
s3o_apply_tls(CURL *curl, const s3o_request_t *req)
{
    if (!req->tls) {
        return;
    }
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    s3o_apply_ca(curl, (const char *) req->tctx);
    if (req->client_cert_pem != NULL && req->client_cert_pem[0] != '\0') {
        curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
        curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
        curl_easy_setopt(curl, CURLOPT_SSLCERT, req->client_cert_pem);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, req->client_cert_pem);
    }
}

/* s3o_configure — set every per-request curl option for `req` on `curl`.
 *
 * WHAT: Sets the URL, header list, write/header capture callbacks, then the
 *       timeout, reuse, method and TLS option groups.
 * WHY:  Concentrates the whole per-request curl configuration behind one call so
 *       the request body reads as build → configure → perform → finish.
 * HOW:  `r` is the response-capture buffer bound to the write/header callbacks;
 *       `slist` is the caller-owned header list. Option order is byte-identical
 *       to the pre-split sequence. */
static void
s3o_configure(CURL *curl, const s3o_request_t *req, s3o_resp_t *r,
              struct curl_slist *slist)
{
    char url[2048];

    snprintf(url, sizeof(url), "%s://%s:%d%s",
             req->tls ? "https" : "http", req->host, req->port,
             req->path_and_query);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, s3o_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, r);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, s3o_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, r);

    s3o_apply_timeouts(curl, req->timeout_ms);
    s3o_apply_reuse(curl);
    s3o_apply_http_version(curl);
    s3o_apply_method(curl, req);
    s3o_apply_tls(curl, req);
}

/* s3o_request_impl — the shared request body for the plain and cred-scoped
 * transport slots.
 *
 * WHAT: Performs one synchronous libcurl request described by `req`, capturing
 *       the response into a heap s3o_resp_t handed back through `resp->opaque`.
 * WHY:  The GSI-over-https backend leg (phase-70 §5.1) authenticates the origin
 *       hop AS the end user by presenting the user's proxy PEM as the TLS client
 *       cert — the only structural difference from an anonymous/bearer request is
 *       the mutual-TLS options (in req->client_cert_pem), so both entry points
 *       share one body.
 * HOW:  Acquires this thread's persistent warm handle, builds the header list,
 *       configures every per-request option (s3o_configure), performs the
 *       transfer and emits the trace line. A per-request curl handle is reset
 *       between uses, so TLS/cert options do not leak into the next request. */
static int
s3o_request_impl(const s3o_request_t *req, brix_s3_resp_t *resp,
                 char *errbuf, size_t errcap)
{
    CURL              *curl;
    CURLcode           res;
    struct curl_slist *slist = NULL;
    s3o_resp_t        *r;
    long               status = 0;
    struct timespec    t0;
    s3o_trace_t        tr = { 0 };

    (void) clock_gettime(CLOCK_MONOTONIC, &t0);

    curl = s3o_curl_acquire();       /* this thread's persistent, warm handle */
    if (curl == NULL) {
        if (errbuf && errcap) { snprintf(errbuf, errcap, "curl handle unavailable"); }
        return -1;
    }

    r = calloc(1, sizeof(*r));
    if (r == NULL) {
        if (errbuf && errcap) { snprintf(errbuf, errcap, "out of memory"); }
        return -1;                   /* handle stays in TLS, reused next call */
    }

    slist = s3o_build_headers(req);
    s3o_configure(curl, req, r, slist);

    tr.method = req->method;
    tr.host   = req->host;
    tr.port   = req->port;
    tr.path   = req->path_and_query;

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        if (errbuf && errcap) {
            snprintf(errbuf, errcap, "curl: %s", curl_easy_strerror(res));
        }
        tr.status = -1;
        tr.dur_ms = s3o_ms_since(&t0);
        tr.err    = curl_easy_strerror(res);
        s3o_trace(&tr);
        curl_slist_free_all(slist);
        free(r->body);
        free(r->hdrs);
        free(r);
        return -1;                   /* handle persists (curl drops a dead
                                        connection from the pool by itself) */
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(slist);

    resp->status = (int) status;
    resp->opaque = r;
    tr.status = (int) status;
    tr.bytes  = r->body_len;
    tr.dur_ms = s3o_ms_since(&t0);
    tr.proto  = s3o_negotiated_proto(curl);
    s3o_trace(&tr);
    return 0;
}

/* Plain request slot: no client certificate (anonymous or header-borne auth). */
static int
s3o_request(void *tctx, const char *host, int port, int tls,
            const char *method, const char *path_and_query,
            const char *headers, const void *body, size_t body_len,
            int timeout_ms, brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    s3o_request_t req = {
        .tctx           = tctx,
        .host           = host,
        .port           = port,
        .tls            = tls,
        .method         = method,
        .path_and_query = path_and_query,
        .headers        = headers,
        .body           = body,
        .body_len       = body_len,
        .timeout_ms     = timeout_ms,
        .client_cert_pem = NULL,
    };

    return s3o_request_impl(&req, resp, errbuf, errcap);
}

/* Cred-scoped request slot: present `client_cert_pem` (a combined proxy PEM) as
 * the mutual-TLS client cert. NULL cert path degrades to a plain request. */
static int
s3o_request_cred(void *tctx, const char *host, int port, int tls,
                 const char *method, const char *path_and_query,
                 const char *headers, const void *body, size_t body_len,
                 int timeout_ms, const char *client_cert_pem,
                 brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    s3o_request_t req = {
        .tctx           = tctx,
        .host           = host,
        .port           = port,
        .tls            = tls,
        .method         = method,
        .path_and_query = path_and_query,
        .headers        = headers,
        .body           = body,
        .body_len       = body_len,
        .timeout_ms     = timeout_ms,
        .client_cert_pem = client_cert_pem,
    };

    return s3o_request_impl(&req, resp, errbuf, errcap);
}

static int
s3o_resp_header(const brix_s3_resp_t *resp, const char *name,
                char *out, size_t outcap)
{
    const s3o_resp_t *r = resp->opaque;
    size_t            namelen = strlen(name);
    const char       *p;

    if (r == NULL || r->hdrs == NULL) {
        return -1;
    }
    for (p = r->hdrs; *p != '\0'; ) {
        const char *eol = strpbrk(p, "\r\n");
        size_t      linelen = (eol != NULL) ? (size_t) (eol - p) : strlen(p);

        if (linelen > namelen && p[namelen] == ':'
            && strncasecmp(p, name, namelen) == 0)
        {
            const char *v = p + namelen + 1;
            size_t      vlen;

            while (v < p + linelen && (*v == ' ' || *v == '\t')) { v++; }
            vlen = (size_t) (p + linelen - v);
            if (vlen >= outcap) { vlen = outcap - 1; }
            memcpy(out, v, vlen);
            out[vlen] = '\0';
            return 0;
        }
        if (eol == NULL) { break; }
        p = eol + strspn(eol, "\r\n");
    }
    return -1;
}

/* Raw header block for enumeration (generic x-amz-meta-* listxattr). */
static const char *
s3o_resp_headers_raw(const brix_s3_resp_t *resp)
{
    const s3o_resp_t *r = resp->opaque;

    return (r != NULL) ? r->hdrs : NULL;
}

static const void *
s3o_resp_body(const brix_s3_resp_t *resp, size_t *len)
{
    const s3o_resp_t *r = resp->opaque;

    if (r == NULL) {
        if (len) { *len = 0; }
        return NULL;
    }
    if (len) { *len = r->body_len; }
    return r->body;
}

static void
s3o_resp_free(brix_s3_resp_t *resp)
{
    s3o_resp_t *r;

    if (resp == NULL || resp->opaque == NULL) {
        return;
    }
    r = resp->opaque;
    free(r->body);
    free(r->hdrs);
    free(r);
    resp->opaque = NULL;
}

const brix_s3_transport_t brix_s3_origin_curl_transport = {
    .request      = s3o_request,
    .request_cred = s3o_request_cred,
    .resp_header = s3o_resp_header,
    .resp_headers_raw = s3o_resp_headers_raw,
    .resp_body   = s3o_resp_body,
    .resp_free   = s3o_resp_free,
};
