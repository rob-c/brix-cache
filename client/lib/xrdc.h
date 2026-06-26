/*
 * xrdc.h — internal API for the native XRootD root:// client library.
 *
 * WHAT: Connection/session + metadata/file ops over the XRootD binary protocol,
 *       built directly on the project's wire vocabulary (the src/protocol headers,
 *       shared via libxrdproto). This is the spine that xrdcp/xrdfs sit on.
 * WHY:  A pure-C, libXrdCl-free client (phase-37). Blocking sockets + poll(2)
 *       timeouts; one in-flight request per connection for now (the streamid
 *       counter is the seed for future parallel streams).
 * HOW:  Each request builds its packed ClientXxxRequest struct from wire.h, sets
 *       big-endian fields, and exchanges frames via frame.c. No ngx, no XrdCl.
 *
 * Clean-room: wire facts come only from the src/protocol headers (cross-checked
 * against XProtocol.hh). See docs/refactor/phase-37-clean-room-log.md.
 */
#ifndef XRDC_H
#define XRDC_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>               /* FILE* for the explain/trace sinks */
#include <time.h>                /* struct timespec for xrdc_setattr */
#include <sys/types.h>

#include "protocol/protocol.h"   /* wire structs + kXR_* constants (-I src) */

/* Public-API fixed sizes. Kept under their stable libxrdc-public XRDC_* names, but
 * the VALUE is now single-sourced from the shared wire header (protocol/opcodes.h
 * via protocol/protocol.h above) rather than re-spelled as 4 / 16 here. */
#ifndef XRDC_FHANDLE_LEN
#define XRDC_FHANDLE_LEN XRD_FHANDLE_LEN
#endif
#ifndef XRDC_SESSION_ID_LEN
#define XRDC_SESSION_ID_LEN XROOTD_SESSION_ID_LEN
#endif

/* kXR_ExpLogin (ClientProtocolRequest.expect) and kXR_FinalResult/kXR_PartialResult
 * (ServerResponseBody_Status.resptype) are real #defines in the shared
 * protocol/flags.h — reached via protocol/protocol.h above. No local copy. */

#define XRDC_MSG_MAX   512
#define XRDC_PATH_MAX  2048
#define XRDC_DLEN_MAX  (64u * 1024u * 1024u)   /* sanity cap on a response body */
#define XRDC_NAME_MAX  256

/* Last-error carrier (the essentials of XrdCl::XRootDStatus). */
typedef struct {
    int  kxr;        /* kXR_* server error code; 0 = none; <0 = local/socket */
    int  sys_errno;  /* local errno when the failure was a syscall */
    char msg[XRDC_MSG_MAX];
} xrdc_status;

/* Local error sentinels (negative so they never collide with kXR_* codes). */
#define XRDC_ESOCK   (-1)   /* connect/socket/timeout failure */
#define XRDC_EPROTO  (-2)   /* malformed/unexpected server frame */
#define XRDC_EUSAGE  (-3)   /* CLI / argument error */
#define XRDC_EAUTH   (-4)   /* server demanded auth we don't (yet) speak */
#define XRDC_EINTEGRITY (-5)/* data corruption (CRC/checksum mismatch) — NOT
                             * retryable: a re-read yields the same bad bytes, so
                             * the resilient loop MUST fail fast, not spin. */
#define XRDC_EUNSUPPORTED (-6) /* valid protocol feature this client build lacks;
                                * fatal, because reconnecting cannot add support. */
#define XRDC_ERESOLVE (-7)  /* permanent name-resolution failure (NXDOMAIN / no
                             * address) — NOT retryable: the name will not
                             * resolve on a retry, so the resilient loop must
                             * fail fast instead of burning its stall window.
                             * A *transient* resolver failure (EAI_AGAIN) keeps
                             * XRDC_ESOCK so it is still retried. */
#define XRDC_EREDIRECT (-8) /* redirect loop / budget exhausted (self-redirect,
                             * bounce to an already-tried target, too many hops)
                             * — NOT retryable: re-issuing the op just walks into
                             * the same loop, so the resilient wrapper must fail
                             * fast rather than chase it for the whole window. */
#define XRDC_EIO     (-9)   /* local filesystem I/O error (open/read/write/rename/fstat/truncate/alloc) — permanent, NOT retryable */
#define XRDC_ENOENT  (-10)  /* object/path does not exist (HTTP 404 / ENOENT) — permanent, NOT retryable */

typedef enum {
    XRDC_SCHEME_ROOT = 0,   /* root:// / xroot:// */
    XRDC_SCHEME_ROOTS,      /* roots:// / xroots:// (TLS) — declined this pass */
    XRDC_SCHEME_LOCAL,      /* file:// or a bare local path */
    XRDC_SCHEME_STDIO       /* "-" */
} xrdc_scheme;

typedef struct {
    xrdc_scheme scheme;
    char        host[256];
    int         port;
    char        user[64];
    char        path[XRDC_PATH_MAX];   /* absolute for root://, local path otherwise */
} xrdc_url;

/* Web endpoints carried over HTTP (WebDAV + S3) — the non-root transfer surface.
 * davs/s3 are HTTP under the hood; xrdcp uses these for production GET/PUT. */
typedef enum {
    XRDC_WEB_HTTP = 0,   /* http://  */
    XRDC_WEB_HTTPS,      /* https:// */
    XRDC_WEB_DAV,        /* dav://   (cleartext WebDAV) */
    XRDC_WEB_DAVS,       /* davs://  (TLS WebDAV) */
    XRDC_WEB_S3,         /* s3://    (cleartext S3 REST) */
    XRDC_WEB_S3S         /* s3s://   (TLS S3 REST) */
} xrdc_web_proto;
typedef struct {
    xrdc_web_proto proto;
    int            tls;                /* 1 if the scheme implies TLS */
    int            is_s3;             /* 1 for s3/s3s (SigV4); 0 for http/dav family */
    char           host[256];
    int            port;
    char           path[XRDC_PATH_MAX];
} xrdc_weburl;
/* Return 1 if `s` begins with a web scheme (http/https/dav/davs/s3/s3s). */
int xrdc_is_web_url(const char *s);
/* Return 1 if `s` names a block-device endpoint (block:// prefix or /dev/). */
int xrdc_is_block_url(const char *s);
/* Parse a web URL into *out. 0 on success, -1 if not a recognized web URL. */
int xrdc_weburl_parse(const char *s, xrdc_weburl *out);

/* ---- glob.c — client-side wildcard expansion ---- */
/* 1 if `s` contains a glob metacharacter (* ? [). */
int  xrdc_has_glob(const char *s);
/* (xrdc_glob declared below, after xrdc_opts is defined.) */

/* Transport: a socket, optionally wrapped in a TLS session. All byte I/O funnels
 * through xrdc_read_full/xrdc_write_full on this, so TLS is a single branch. We
 * forward-declare struct ssl_st so this header stays OpenSSL-free. */
struct ssl_st;
/* Forward-declare the credential store so xrdc_opts can carry a pointer without
 * pulling cred.h (and its OpenSSL/crypto includes) into every consumer. */
struct xrdc_cred_store;
typedef struct {
    int            fd;
    struct ssl_st *ssl;       /* NULL = cleartext; non-NULL = TLS active */
    int            timeout_ms;
} xrdc_io;

/* Connection options (auth + TLS), supplied by the CLI. NULL ⇒ secure defaults
 * (no TLS unless the scheme/flags demand it; peer + host verification on). */
typedef struct {
    int         want_tls;     /* require in-protocol TLS (roots:// or --tls) */
    int         notlsok;      /* permit cleartext if the server offers no TLS
                               * (always ignored for roots://) */
    int         verify_host;  /* check the server cert name (default 1) */
    int         insecure_tls; /* 0 (default) = verify the peer chain; 1 = skip chain
                               * verification (cert INSPECTION only, e.g. xrd certinfo —
                               * never for data transfer). Zero-init keeps verify on. */
    const char *ca_dir;       /* CA hash dir; NULL ⇒ $X509_CERT_DIR */
    const char *auth_force;   /* "gsi"/"ztn"/"unix" to force, else NULL */
    int         wire_trace;   /* §15: 0=off, 1=decoded frame lines, ≥2 +hexdump */
    int         timing;       /* §15: accumulate per-opcode RTT, report at close */
    const char *capture;      /* §15.1: .xrdcap bundle path to record into (NULL=off) */
    int         redir_trace;  /* §15.4: trace every kXR_redirect hop to stderr */
    int         force_anon;   /* §15.9: log in but present NO credential (auth-suite:
                               * tests the server's own enforcement, not client creds) */
    /* ---- network resilience (xrootdfs parity for the synchronous tools) ---- */
    int         max_stall_ms; /* patience window for reconnect+retry on a transport
                               * sever. 0 with no_retry=0 ⇒ the built-in default
                               * (XRDC_DEFAULT_MAX_STALL_MS). Seeded from
                               * $XRDC_MAX_STALL_MS / --max-stall. */
    int         no_retry;     /* 1 ⇒ resilience off: fail fast (legacy behavior).
                               * Set by --no-retry or $XRDC_MAX_STALL_MS=0. */
    /* ---- credential store (C1) ---- */
    struct xrdc_cred_store *cred; /* optional pre-built credential store; NULL =
                                   * per-handler env/default discovery (today's
                                   * behaviour; C2 will thread this through auth). */
} xrdc_opts;

/* Default reconnect+retry patience window when resilience is on but unspecified. */
#define XRDC_DEFAULT_MAX_STALL_MS 30000

/* Forward decl: the opaque capture sink (capture.c). */
struct xrdc_capture;

/* §15 diagnostics state, embedded in xrdc_conn. Zero-initialised by the conn's
 * memset, so every hook is inert (single load+test) unless armed from opts. */
#define XRDC_NOP 64   /* per-opcode RTT table size; reqid-kXR_1stRequest indexes it */
typedef struct {
    int         wire_trace;       /* mirrors opts.wire_trace (survives reconnect) */
    int         timing;           /* mirrors opts.timing */
    int         redir_trace;      /* mirrors opts.redir_trace (§15.4) */
    const char *chosen_auth;      /* auth proto the driver picked (NULL = anon) */
    uint64_t    t_send_ns;        /* CLOCK_MONOTONIC at the last xrdc_send */
    uint16_t    inflight_reqid;   /* requestid of the in-flight request */
    struct { uint64_t n, tot_ns, min_ns, max_ns; } rtt[XRDC_NOP];
    struct xrdc_capture *cap;     /* §15.1: capture sink (NULL=off; survives reconnect) */
    /* §15.3 connect-phase stamps (CLOCK_MONOTONIC ns), filled by bringup:
     * [0]=start [1]=tcp-connected [2]=tls-done [3]=login+auth-done. 0 = not set. */
    uint64_t    phase_ns[4];
} xrdc_diag;

#define XRDC_REDIR_MAX 16   /* max kXR_redirect hops before giving up (loop/SSRF guard) */
#define XRDC_HOSTPORT_MAX 288  /* "host:port" key: host[256] + ':' + port + NUL, padded */

typedef struct {
    xrdc_io  io;
    uint16_t next_sid;
    uint8_t  sessid[XRDC_SESSION_ID_LEN];
    uint32_t server_flags;   /* ServerProtocolBody.flags, host byte order */
    char     host[256];
    int      port;

    /* --- auth / signing (M4) --- */
    void    *ssl_ctx;            /* SSL_CTX* (owned); freed on close */
    int      sec_level;          /* server's signing security level (0 = none) */
    int      signing_active;     /* GSI established a signing key */
    uint64_t sig_seqno;          /* monotonic kXR_sigver sequence number */
    uint8_t  signing_key[32];    /* SHA256(DH shared secret) */

    /* --- redirect / reconnect (M5) --- */
    xrdc_opts opts;             /* copy of the connect opts, replayed on reconnect */
    int       want_tls;         /* derived at connect; re-applied on reconnect */
    int       tls_strict;       /* roots:// — never downgrade to cleartext */
    int       redir_depth;      /* kXR_redirect hops so far in the current op */
    int       tried_n;
    char      tried[XRDC_REDIR_MAX][XRDC_HOSTPORT_MAX];  /* visited "host:port" (loop guard) */
    /* Phase 40 (a): the ORIGINAL endpoint (manager) the op started against,
     * snapshotted before any redirect clobbers host/port — so a dead redirect
     * target can fall back to the manager for a fresh server selection. */
    char      home_host[256];
    int       home_port;

    /* --- diagnostics (§15) --- */
    xrdc_diag diag;              /* wire-trace / timing state (off unless armed) */
    char      sec_list[256];     /* the login "&P=…" sec list, for `xrdfs explain` */
} xrdc_conn;

typedef struct {
    uint64_t id;
    int64_t  size;
    int      flags;
    long     mtime;
    /* Extended fields: present only when the server sends the long stat form
     * (e.g. EOS appends ctime/atime/mode/owner/group after the 4 mandatory
     * fields). have_ext == 0 for plain XRootD servers that send only 4. */
    int      have_ext;
    long     ctime;
    long     atime;
    unsigned mode;            /* numeric (octal on the wire), e.g. 0750 */
    char     owner[64];
    char     group[64];
} xrdc_statinfo;

typedef struct {
    char          name[XRDC_NAME_MAX];
    int           have_stat;
    xrdc_statinfo st;
} xrdc_dirent;

/* ---- sock.c ---- */
int xrdc_tcp_connect(const char *host, int port, int timeout_ms, xrdc_status *st);
/* Apply TCP_NODELAY + SO_KEEPALIVE (+ keep* triad) to a connected socket. Best-
 * effort; failures ignored. Called by xrdc_tcp_connect; exposed for the async loop. */
void xrdc_sock_tune(int fd);
/* Transfer over io: cleartext when io->ssl is NULL, else TLS. Bounded by
 * io->timeout_ms via poll(2). */
int xrdc_read_full(xrdc_io *io, void *buf, size_t n, xrdc_status *st);
int xrdc_write_full(xrdc_io *io, const void *buf, size_t n, xrdc_status *st);

/* ---- netpref.c — process-wide IPv6→IPv4 auto-downgrade (dual-stack hosts) ---- */
/* getaddrinfo family hint: AF_UNSPEC normally, AF_INET once the session has
 * demoted to IPv4-only after observing a broken IPv6 path. */
int  xrdc_netpref_family(void);
/* 1 if this process has demoted to IPv4-only. */
int  xrdc_netpref_demoted(void);
/* Record that a connection to `host` failed over IPv6 but then succeeded over
 * IPv4 — demote the whole process (mount session) to IPv4-only and log once.
 * Idempotent; a no-op when auto-downgrade is disabled. */
void xrdc_netpref_demote_ipv6(const char *host);
/* Record that an ESTABLISHED connection of the given address family failed over
 * the wire (reset / timeout / truncated read). When family is AF_INET6 this
 * demotes the session to IPv4-only (logged once) so the reconnect skips v6;
 * a no-op for AF_INET / AF_UNSPEC, when already demoted, or when disabled. */
void xrdc_netpref_note_wire_error(int family);
/* Self-heal: clear a demotion when IPv4 turns out not to work after all (e.g.
 * an IPv6-only host that briefly tripped the wire-error trigger), so the next
 * connect tries both families again. Logs once. No-op if not demoted. */
void xrdc_netpref_undo_demote(const char *why);
/* Disable auto-downgrade (default enabled; also off via the XRDC_NO_IPV6_FALLBACK
 * env var — EXPANDED: a client-only extension, not a vanilla XRootD variable).
 * Keeps retrying IPv6 on every connection — for IPv6-only sites or debugging. */
void xrdc_netpref_disable(void);

/* ---- nettmo.c — network timeout tunables + retry backoff ---- */
/* Connect+handshake+login (bring-up) cap, ms. Default 15000; override via the
 * setter (a CLI flag) or the XRDC_CONNECT_TIMEOUT_MS env var (EXPANDED). Keeps a
 * black-holed handshake from hanging the caller for the full I/O timeout. */
int  xrdc_tmo_connect_ms(void);
/* Steady-state per-operation read/write cap, ms. Default 30000; override via the
 * setter or the XRDC_IO_TIMEOUT_MS env var (EXPANDED). */
int  xrdc_tmo_io_ms(void);
/* CLI overrides (ignored when ms <= 0); take precedence over env + default. */
void xrdc_tmo_set_connect_ms(int ms);
void xrdc_tmo_set_io_ms(int ms);
/* Backoff for retry `attempt` (0-based): exponential 100ms<<attempt capped at 5s
 * plus xorshift jitter in [0, base/2]. *seed carries the jitter PRNG state. */
unsigned xrdc_backoff_delay_ms(unsigned attempt, uint64_t *seed);
/* Fast backoff for TRANSPORT faults (reset/EOF — instant, not server overload):
 * 25ms<<attempt capped at 250ms + jitter. The short cap fits many retries in the
 * patience window, which is what rides out a high packet-loss link. */
unsigned xrdc_backoff_delay_fast_ms(unsigned attempt, uint64_t *seed);
/* Sleep one xrdc_backoff_delay_ms / _fast_ms, in short slices so a cooperative
 * cancel (xrdc_copy_quit_requested) is observed promptly. */
void xrdc_backoff_sleep(unsigned attempt);
void xrdc_backoff_sleep_fast(unsigned attempt);

/* ---- tls.c ---- */
/* Upgrade c->io.fd to TLS (after the kXR_protocol reply, before login). When
 * verify_peer, the server cert must chain to ca_dir (a hash dir, e.g.
 * $X509_CERT_DIR); when verify_host, the cert name must match c->host. */
int  xrdc_tls_upgrade(xrdc_conn *c, int verify_peer, int verify_host,
                      const char *ca_dir, xrdc_status *st);
void xrdc_tls_free(xrdc_conn *c);

/* ---- conn.c ---- */
/* Resolve the CA trust dir for TLS verification: explicit arg → $X509_CERT_DIR →
 * /etc/grid-security/certificates → NULL (OpenSSL system defaults). Borrowed
 * string; never allocates. Use everywhere a ca_dir is needed so the client
 * trusts grid (IGTF) CAs without requiring $X509_CERT_DIR to be set. */
const char *xrdc_resolve_ca_dir(const char *opt_ca_dir);
/* Transparent TLS transfer used by sock.c when io->ssl != NULL (0 / -1). */
int xrdc_tls_read(xrdc_io *io, void *buf, size_t n, xrdc_status *st);
int xrdc_tls_write(xrdc_io *io, const void *buf, size_t n, xrdc_status *st);
/* Stream read (up to n bytes) over TLS for the HTTP client; *got=bytes (0=EOF). */
int xrdc_tls_read_some(xrdc_io *io, void *buf, size_t n, size_t *got, xrdc_status *st);
/* §15 explain: if TLS is active, set the ver and cipher out-params to the
 * negotiated protocol version + cipher name (static OpenSSL strings); returns 1
 * if active, 0 if not. Keeps OpenSSL out of the apps. */
int xrdc_tls_info(const xrdc_conn *c, const char **ver, const char **cipher);
/* Server peer-certificate facts, filled by xrdc_tls_peer_cert_info from the live
 * TLS session. Times are epoch seconds; days_left is whole days until not_after
 * (negative once expired). */
typedef struct {
    int  have;            /* 1 if a peer cert was present (TLS active) */
    char subject[512];
    char issuer[512];
    char sans[512];       /* comma-joined DNS subjectAltNames (may be empty) */
    long not_before;      /* epoch seconds (0 if unparsed) */
    long not_after;       /* epoch seconds (0 if unparsed) */
    long days_left;       /* whole days until not_after; negative if expired */
    int  expired;         /* not_after is in the past */
    int  not_yet_valid;   /* not_before is in the future */
    int  host_match;      /* cert matches c->host (X509_check_host) */
    int  self_signed;     /* subject == issuer (self-issued) */
} xrdc_cert_info;
/* Fill *out from the server's leaf certificate (requires TLS active). Returns 0 on
 * success (out->have == 1), -1 if cleartext / no peer cert (out->have == 0). */
int xrdc_tls_peer_cert_info(const xrdc_conn *c, xrdc_cert_info *out);
/* Connect + handshake + (TLS upgrade if offered) but NO kXR_login — for cert
 * inspection (xrd certinfo). Requests TLS, tolerates a cleartext server. The caller
 * reads c->io.ssl via xrdc_tls_peer_cert_info, then xrdc_close. 0 / -1 (st set). */
int xrdc_connect_no_login(xrdc_conn *c, const xrdc_url *u, const xrdc_opts *o,
                          xrdc_status *st);
/* Standalone TLS client handshake on a connected socket (the HTTP(S) client, not the
 * root:// in-protocol upgrade). On success io->ssl is live + *out_ctx is the SSL_CTX. */
int  xrdc_tls_client(xrdc_io *io, const char *host, int verify_peer, int verify_host,
                     const char *ca_dir, void **out_ctx, xrdc_status *st);
void xrdc_tls_client_free(xrdc_io *io, void *ctx);
void xrdc_tls_client_info(const xrdc_io *io, const char **ver, const char **cipher);

/* ---- http.c ---- */
/* A general HTTP/1.1 response: status line code + the raw header block (for header
 * scans) + the body. The TLS facts are filled for https requests. */
typedef struct {
    int    status;             /* HTTP status code, 0 if none parsed */
    char   reason[64];         /* status reason phrase */
    char   headers[8192];      /* raw response header block (NUL-terminated, truncated) */
    char  *body;               /* malloc'd body (NUL-terminated); NULL if none */
    size_t body_len;
    int    tls;                /* 1 if the request used TLS */
    char   tls_ver[24];        /* negotiated TLS version (https) */
    char   tls_cipher[48];     /* negotiated cipher (https) */
} xrdc_http_resp;

/* General HTTP/1.1 request over cleartext (tls=0) or TLS (tls=1). method e.g. "GET"/
 * "HEAD"/"OPTIONS"/"PROPFIND"; extra_headers is a "K: V\r\n…" block or NULL; body/blen
 * optional. verify controls TLS peer+host checking. Fills *resp (free with
 * xrdc_http_resp_free). 0 / -1 (st set). PII-free at the call site's discretion. */
int  xrdc_http_req(const char *host, int port, int tls, const char *method,
                   const char *path, const char *extra_headers,
                   const void *body, size_t blen, int timeout_ms, int verify,
                   const char *ca_dir, xrdc_http_resp *resp, xrdc_status *st);
void xrdc_http_resp_free(xrdc_http_resp *resp);
/* Copy the value of response header `name` (case-insensitive) into out[outsz];
 * 1 if found, 0 if absent. */
int  xrdc_http_header(const xrdc_http_resp *resp, const char *name,
                      char *out, size_t outsz);

/* Streaming transfer (no whole-body buffering — production GET/PUT, any size).
 * xrdc_http_download streams the GET response body straight to out_fd (handles
 * Content-Length, chunked, and connection-close framing). xrdc_http_upload streams
 * exactly `clen` bytes from in_fd as a PUT body. extra_headers is a "K: V\r\n…"
 * block or NULL. Both fill *http_status with the response code. 0 / -1 (st set). */
int  xrdc_http_download(const char *host, int port, int tls, const char *path,
                        const char *extra_headers, int verify, const char *ca_dir,
                        int out_fd, int timeout_ms, int *http_status,
                        long long *body_len, xrdc_status *st);
int  xrdc_http_upload(const char *host, int port, int tls, const char *path,
                      const char *extra_headers, int in_fd, long long clen,
                      int verify, const char *ca_dir, int timeout_ms,
                      int *http_status, xrdc_status *st);

/* Resumable upload: streams the source as Content-Range PUT chunks, each on a
 * fresh connection, reconnecting + resuming from the server's durable offset on
 * a transport sever or 409 within max_stall_ms — so a davs:// upload survives an
 * nginx restart.  Needs server xrootd_webdav_upload_resume for true resume; a
 * plain server commits on the first (whole-range) chunk. 0 / -1 (st set). */
int  xrdc_http_upload_resumable(const char *host, int port, int tls,
                      const char *path, const char *extra_headers, int in_fd,
                      long long clen, int verify, const char *ca_dir,
                      int timeout_ms, int max_stall_ms, int *http_status,
                      xrdc_status *st);

/* ---- s3.c — AWS Signature Version 4 (path-style), lifted to the lib so both
 * xrdcp transfers and xrddiag probes share one signer. ---- */
/* Lowercase sha256-hex of a buffer into out[65]. */
void xrdc_s3_sha256_hex(const void *data, size_t len, char *out);
/* Build the SigV4 header block (x-amz-date + x-amz-content-sha256 + Authorization)
 * for `method` on path-style `uri`, with body hash `payload_hex` (lowercase sha256
 * hex; use xrdc_s3_sha256_hex("",0,..) for an empty body, or the literal
 * "UNSIGNED-PAYLOAD" for a streamed PUT). Region+service "s3". Output is a
 * "K: V\r\n…" block ready as extra_headers. 0 / -1. */
int  xrdc_s3_sign_v4(const char *method, const char *host, const char *uri,
                     const char *ak, const char *sk, const char *region,
                     const char *payload_hex, char *hdrs, size_t hdrsz);
/* As above, but with a canonical query string (already sorted + RFC-3986 encoded)
 * folded into the canonical request — needed to sign ListObjectsV2 (?list-type=2…). */
int  xrdc_s3_sign_v4_q(const char *method, const char *host, const char *uri,
                       const char *canon_qs, const char *ak, const char *sk,
                       const char *region, const char *payload_hex,
                       char *hdrs, size_t hdrsz);

/* ---- url.c ---- */
int xrdc_url_parse(const char *s, xrdc_url *out, xrdc_status *st);
/* Expand a root:// URL whose LAST path component globs into matching full URLs.
 * On success returns the match count (>=0) and sets *out (malloc'd array of malloc'd
 * URLs) + *n_out; free with xrdc_glob_free. Returns -1 if `url` isn't a root:// glob
 * or on error (st set). Declared here, after xrdc_opts, since it takes a *co. */
int  xrdc_glob(const char *url, const xrdc_opts *co, char ***out, size_t *n_out,
               xrdc_status *st);
void xrdc_glob_free(char **arr, size_t n);

/* ---- weblist.c — recursive WebDAV listing (for xrdcp -r over davs/http) ---- */
/* PROPFIND Depth:infinity on a WebDAV collection; returns absolute server paths of
 * every FILE beneath it (subdirs excluded). bearer NULL ⇒ anonymous. 0 / -1 (st set).
 * Free *paths with xrdc_strv_free. */
int  xrdc_webdav_list(const xrdc_weburl *u, const char *bearer, int verify,
                      const char *ca_dir, char ***paths, size_t *n_out, xrdc_status *st);
/* MKCOL a WebDAV collection at `path` on the endpoint `u` (for recursive upload).
 * bearer NULL ⇒ anonymous. Idempotent: an already-existing collection (405/301)
 * is treated as success. 0 / -1 (st set). */
int  xrdc_webdav_mkcol(const xrdc_weburl *u, const char *path, const char *bearer,
                       int verify, const char *ca_dir, xrdc_status *st);
/* List object keys under an s3:// URL's prefix via paginated, SigV4-signed
 * ListObjectsV2. The bucket is the first path component; the prefix is the rest.
 * ak/sk NULL ⇒ anonymous. Returns full object keys. 0 / -1. Free with xrdc_strv_free. */
int  xrdc_s3_list(const xrdc_weburl *u, const char *ak, const char *sk,
                  const char *region, int verify, const char *ca_dir,
                  char ***keys, size_t *n_out, xrdc_status *st);
void xrdc_strv_free(char **arr, size_t n);

/* ---- webfile.c — HTTP(S)/WebDAV transport for the FUSE driver (read path) ---- */
/* Single-resource stat via PROPFIND Depth:0 → size/mtime/is-dir (FUSE getattr).
 * bearer NULL ⇒ anonymous; verify+ca_dir apply to TLS (https/davs). 0 / -1. */
int  xrdc_web_stat(const xrdc_weburl *u, const char *path, const char *bearer,
                   int verify, const char *ca_dir, xrdc_statinfo *si, xrdc_status *st);
/* Directory listing via PROPFIND Depth:1 → child entries with stat (FUSE readdir).
 * Allocates *ents (free with free()); each entry has name + have_stat + st. 0 / -1. */
int  xrdc_web_readdir(const xrdc_weburl *u, const char *path, const char *bearer,
                      int verify, const char *ca_dir, xrdc_dirent **ents,
                      size_t *n, xrdc_status *st);
/* An open-for-read web file whose pread issues a Range GET over a PERSISTENT
 * keep-alive connection (resilient: reconnect + re-issue on a dropped link). */
typedef struct xrdc_webfile xrdc_webfile;
/* Open (stats first; fails if a directory). *si_out (optional) gets the stat. */
xrdc_webfile *xrdc_webfile_open(const xrdc_weburl *u, const char *path,
                                const char *bearer, int verify, const char *ca_dir,
                                int timeout_ms, xrdc_statinfo *si_out,
                                xrdc_status *st);
int64_t  xrdc_webfile_size(const xrdc_webfile *wf);
/* Read up to len bytes at off; returns bytes (0 at EOF), or -1 (st set). */
ssize_t  xrdc_webfile_pread(xrdc_webfile *wf, int64_t off, void *buf, size_t len,
                            xrdc_status *st);
void     xrdc_webfile_close(xrdc_webfile *wf, xrdc_status *st);

/* ---- xrdrc.c — ~/.xrdrc endpoint aliases ---- */
/* Resolve "name:suffix" via $XRDRC (else ~/.xrdrc) into out[outsz]. Always writes
 * the effective string (the input verbatim when it is not a known alias). Returns
 * 1 if an alias was expanded, 0 if not. */
int xrdc_alias_resolve(const char *arg, char *out, size_t outsz);
/* Per-endpoint credentials an alias may carry, so `xrdcp s3lab:/obj .` "just works"
 * with no flags. Empty fields mean "not set"; bearer is the token value (read from
 * the alias's token_file if it gave a path). PII: never log these. */
typedef struct {
    int  found;
    char bearer[8192];          /* WebDAV/HTTP Authorization: Bearer <token> */
    char s3_access[256];
    char s3_secret[256];
    char s3_region[64];
    char proxy[XRDC_PATH_MAX];  /* X.509 proxy path (root:// gsi) */
    char token_file[XRDC_PATH_MAX];  /* the alias's token_file, for diagnostics */
    int  token_file_failed;     /* 1 if token_file was set but unreadable/empty */
} xrdc_alias_info;
/* Look up an alias by NAME (the part before ':' in "name:suffix") and fill its auth
 * hints. *info is zeroed first. Returns 1 if the alias exists, 0 otherwise. Additive
 * companion to xrdc_alias_resolve (which handles the URL). */
int xrdc_alias_lookup(const char *name, xrdc_alias_info *info);
/* Turn a CLI endpoint — "host[:port]" or a root[s]:// URL — into a connectable
 * xrdc_url (default port 1094, scheme XRDC_SCHEME_ROOT/ROOTS). Shared by xrdfs and
 * every tool so the endpoint grammar lives in one place. 0 / -1 (st set). */
int xrdc_endpoint_parse(const char *ep, xrdc_url *out, xrdc_status *st);

/* ---- status.c ---- */
void        xrdc_status_clear(xrdc_status *st);
void        xrdc_status_set(xrdc_status *st, int kxr, int sys_errno, const char *fmt, ...);
const char *xrdc_kxr_name(int kxr);
int         xrdc_shellcode(const xrdc_status *st);
/* 1 if a failed status is transient (reconnect/re-issue may succeed), 0 if fatal.
 * Drives the async resilience layer's transparent retry/reconnect decisions. */
int         xrdc_status_retryable(const xrdc_status *st);
/* Map a failed status to a negative errno (for the FUSE/preload POSIX layers):
 * kXR_NotFound→-ENOENT, NotAuthorized→-EACCES, isDirectory/NotFile→-EISDIR, … */
int         xrdc_kxr_to_errno(const xrdc_status *st);

/* Narrate an established session (endpoint/roles/caps/signing/auth/TLS/sessid) to
 * `out`. Shared by `xrdfs explain` and `xrddiag check`. opts may be NULL (uses
 * c->opts). Read-only over fields conn.c/auth.c populated. */
void xrdc_explain_conn(xrdc_conn *c, const xrdc_opts *opts, FILE *out);

/* ---- netdiag.c (§15.3 networking diagnostics) ---- */
/* Machine-readable network facts for an established conn (PII-free: families,
 * microseconds, counts only — never an IP/path/credential). Used by the bench
 * report and by `xrddiag remote-doctor`'s cross-endpoint diff engine. */
typedef struct {
    double   tcp_ms, tls_ms, auth_ms, total_ms;  /* connect-phase deltas */
    int      family;        /* AF_INET / AF_INET6 / 0 (unknown) */
    uint32_t flow_label;    /* IPv6 flow label (0 = v4 / unset) */
    int      have_tcpinfo;  /* 1 if the rtt/retrans fields below are valid */
    uint32_t rtt_us, rttvar_us, retrans;
} xrdc_netfacts;
/* Fill *f from the live conn (getpeername/getsockopt(TCP_INFO)/getsockname on
 * c->io.fd + diag.phase_ns). Zeroes *f first; safe on a closed conn (all 0). */
void xrdc_netdiag_facts(const xrdc_conn *c, xrdc_netfacts *f);
/* Print the human-readable netdiag block (built on xrdc_netdiag_facts). */
void xrdc_netdiag_report(const xrdc_conn *c, FILE *out);

/* ---- capture.c (§15.1 session capture / offline replay) ---- */
/* Open a .xrdcap bundle for writing (magic + records). NULL on error. */
struct xrdc_capture *xrdc_capture_open(const char *path);
/* Append a metadata key=value record (endpoint, caps, sessid, auth, tls). */
void xrdc_capture_meta(struct xrdc_capture *cap, const char *key, const char *val);
/* Append a frame record (the exact wire bytes = header then body): dir
 * '>'=request '<'=response. hdr is the 24B request / 8B response header. */
void xrdc_capture_frame(struct xrdc_capture *cap, int dir, uint16_t sid, int code,
                        int is_request, const void *hdr, uint32_t hdrlen,
                        const void *body, uint32_t blen);
void xrdc_capture_close(struct xrdc_capture *cap);
/* Offline: decode a .xrdcap to `out` (no server). verbose≥1 adds a body hexdump. */
int xrdc_capture_replay(const char *path, int verbose, FILE *out, xrdc_status *st);
/* Live: re-issue every captured REQUEST frame against `url`, reporting each
 * response status to `out`. 0 / -1 (st set). */
int xrdc_capture_playback(const char *path, const char *url, const xrdc_opts *co,
                          FILE *out, xrdc_status *st);

/* ---- http.c (xrddiag observability pulls) ---- */
/* Minimal cleartext HTTP/1.0 GET: connect host:port, GET path, copy the response
 * body binary-safe into out[outsz] (NUL-terminated for text callers), set
 * *http_status and (if outlen != NULL) the copied body length. 0 / -1 (st set). */
int xrdc_http_get(const char *host, int port, const char *path, int timeout_ms,
                  int *http_status, char *out, size_t outsz, size_t *outlen,
                  xrdc_status *st);

/* ---- trace.c (§15 diagnostics) ---- */
const char *xrdc_reqid_name(int reqid);     /* requestid → "kXR_stat" etc. */
const char *xrdc_status_name(int status);   /* response status → "ok"/"redirect"/… */
uint64_t    xrdc_mono_ns(void);             /* CLOCK_MONOTONIC nanoseconds */
/* Phase 40 (a): pseudo-random value in [0, span_ms) for backoff jitter on the
 * synchronous retry/kXR_wait paths (thundering-herd defense). Lazily seeded from
 * xrdc_mono_ns; a leaf helper with no aio/thread dependency. */
unsigned    xrdc_jitter_ms(unsigned span_ms);
/* Emit one decoded frame line to stderr (dir '>'=request '<'=response). At
 * c->diag.wire_trace>=2 a bounded hexdump of body[0..blen) follows. */
void        xrdc_trace_frame(xrdc_conn *c, int dir, uint16_t sid, int code,
                             int is_request, uint32_t dlen,
                             const void *body, uint32_t blen);
/* Print the accumulated per-opcode RTT summary (if any) to stderr. */
void        xrdc_timing_report(const xrdc_conn *c);

/* ---- frame.c ---- */
/* Assign a fresh streamid into hdr[0..1] and write dlen into hdr[20..23] (the
 * caller has already filled requestid + the 16-byte body). Sends header+payload. */
int xrdc_send(xrdc_conn *c, void *hdr24, const void *payload, uint32_t plen,
              uint16_t *out_sid, xrdc_status *st);
/* Read one response frame for streamid want_sid. Returns 0 with *status set and a
 * malloc'd body/blen (caller frees) for kXR_ok/oksofar/authmore AND kXR_redirect/
 * kXR_wait (so the roundtrip wrapper can act on them). Returns -1 on kXR_error
 * (st filled from errnum+errmsg) or any other status / transport fault. */
int xrdc_recv(xrdc_conn *c, uint16_t want_sid, uint16_t *status,
              uint8_t **body, uint32_t *blen, xrdc_status *st);

/* Send a request and read its reply, transparently following kXR_redirect
 * (reconnect+replay, bounded by XRDC_REDIR_MAX + a visited-set loop guard) and
 * honoring kXR_wait (sleep+resend). Use this for path-based ops so cluster
 * redirectors work. hdr24 is re-stamped (streamid/dlen) on each attempt. Returns 0
 * with *status = kXR_ok/oksofar + body/blen; -1 (st set) on error. */
int xrdc_roundtrip(xrdc_conn *c, void *hdr24, const void *payload, uint32_t plen,
                   uint16_t *status, uint8_t **body, uint32_t *blen,
                   xrdc_status *st);

/* ---- conn.c ---- */
/* connect → handshake → [TLS upgrade] → kXR_protocol → kXR_login → [auth].
 * opts may be NULL (anonymous, no TLS). */
int  xrdc_connect(xrdc_conn *c, const xrdc_url *u, const xrdc_opts *o,
                  xrdc_status *st);
/* Tear down the current transport and re-establish the full session (handshake →
 * [TLS] → login → auth) against host:port, preserving the stored opts/creds. Used
 * by the redirect follower. 0 / -1. */
int  xrdc_reconnect(xrdc_conn *c, const char *host, int port, xrdc_status *st);
void xrdc_close(xrdc_conn *c);

/* ---- pool.c — thread-safe pool of connections for concurrent callers ---- */
/* An xrdc_conn is one-request-in-flight and NOT thread-safe; a multi-threaded
 * consumer (e.g. the FUSE driver) checks out an independent connected conn per
 * operation. The struct is opaque; callers hold only the handle. */
typedef struct xrdc_pool xrdc_pool;
/* Create a pool of `n` connections to `u` (opts `o`, may be NULL). Connects one
 * eagerly so a bad endpoint/auth fails up front; the rest connect on demand.
 * Returns NULL + sets st on failure. */
xrdc_pool *xrdc_pool_create(const xrdc_url *u, const xrdc_opts *o, int n,
                            xrdc_status *st);
/* Borrow a connected conn, blocking until one is free; reconnects a dropped slot
 * transparently. Returns NULL + sets st only if (re)connect fails. */
xrdc_conn *xrdc_pool_checkout(xrdc_pool *p, xrdc_status *st);
/* Return a checked-out conn. healthy==0 (the op hit a connection-level error,
 * i.e. st->kxr == XRDC_ESOCK/XRDC_EPROTO) drops the conn so the next checkout
 * reconnects on a clean session. */
void       xrdc_pool_checkin(xrdc_pool *p, xrdc_conn *c, int healthy);
void       xrdc_pool_destroy(xrdc_pool *p);
/* Establish a secondary data stream bound to `primary`'s session: handshake +
 * kXR_protocol [+ TLS] then kXR_bind{primary->sessid}, skipping kXR_login (the
 * server inherits identity from the primary). `sec` is fully initialised here.
 * Tear it down with xrdc_streams_close (no endsess). 0 / -1. */
int  xrdc_bind(xrdc_conn *sec, const xrdc_conn *primary, xrdc_status *st);

/* ---- streams.c (M8 parallel streams) ---- */
#define XRDC_MAX_STREAMS 16
typedef struct {
    int       n;                              /* secondaries actually bound */
    xrdc_conn sec[XRDC_MAX_STREAMS - 1];
} xrdc_streamset;
/* Best-effort: bind up to (streams-1) secondaries to `primary` (capped at
 * XRDC_MAX_STREAMS-1). Never fails the caller — returns the number bound; a
 * secondary that won't bind is simply skipped. */
int  xrdc_streams_open(xrdc_streamset *ss, xrdc_conn *primary, int streams,
                       xrdc_status *st);
void xrdc_streams_close(xrdc_streamset *ss);

/* ---- auth.c ---- */
/* Drive the kXR_auth/authmore loop for the server's "&P=..." security list. */
int  xrdc_authenticate(xrdc_conn *c, const char *seclist, const xrdc_opts *o,
                       xrdc_status *st);
/* §15 `xrdfs explain`: narrate the &P= list (c->sec_list), which protocol the
 * client would pick and why each other was skipped (no creds / not offered). */
void xrdc_auth_explain(xrdc_conn *c, const xrdc_opts *o, FILE *out);

/* ---- sec/sec_token.c ---- */
/* Discover a bearer token (BEARER_TOKEN / BEARER_TOKEN_FILE / $XDG_RUNTIME_DIR or
 * /tmp/bt_u<uid>); malloc'd string or NULL. Shared with credinfo.c. */
char *xrdc_token_discover(void);

/* ---- credinfo.c (§15.2 credential introspection) ---- */
/* Best-effort decoders for `explain`; each prints to `out` and never fails hard.
 * token: base64url-decode the JWT payload, show iss/sub/aud/scope/exp + EXPIRED
 * (no signature verify). gsi cert: subject/issuer/notAfter + VOMS FQANs + skew. */
void xrdc_token_explain(const char *jwt, FILE *out);
void xrdc_gsi_cert_explain(const char *proxy_path, FILE *out);

/* Machine-readable bearer-token facts (validity + WLCG scope), for the auth-suite
 * to predict whether the server should allow/deny an op. No signature verify. */
typedef struct {
    int  valid;       /* 1 = JWT payload parsed */
    long exp;         /* exp claim (epoch), 0 if absent */
    int  expired;     /* exp present and in the past (local clock) */
    int  has_scope;   /* a scope claim was present */
    int  has_read;    /* scope grants read  (storage.read / read:) */
    int  has_write;   /* scope grants write (storage.write/create/modify) */
} xrdc_token_meta;
void xrdc_token_meta_get(const char *jwt, xrdc_token_meta *m);

/* Phase 40 (c): client-side credential pre-flight / failure diagnostics.
 * xrdc_cred_diagnose inspects whatever credential is present locally (bearer
 * token via xrdc_token_discover, then GSI proxy at the default path) WITHOUT any
 * network call or signature verification, and prints a specific, actionable hint
 * to `out` (each line prefixed by `prefix`) when it finds a likely auth problem:
 * an expired/near-expiry token or proxy, or — when want_write is set — a token
 * that grants read scope only.  Returns 1 if a likely-fatal local problem was
 * found, else 0.  So the user sees "token expired 3m ago" instantly instead of a
 * bare "permission denied".
 * xrdc_cred_hint_for_status calls it (with an indented hint prefix) only when
 * `st` carries an auth/authz wire error (kXR_NotAuthorized / kXR_AuthFailed),
 * for one-line use at an app's error-reporting site. */
int  xrdc_cred_diagnose(int want_write, const char *prefix, FILE *out);
void xrdc_cred_hint_for_status(const xrdc_status *st, int want_write, FILE *out);

/* Phase 40 (b): proactively (re)acquire a stale credential before a transfer —
 * a bearer token via the local oidc-agent (`oidc-token <account>`; account from
 * arg or $OIDC_ACCOUNT) installed into $BEARER_TOKEN, and/or a GSI proxy via
 * xrdc_proxy_create when one is missing/expired/near-expiry and a user cert
 * exists. Best-effort and fail-soft: returns the count refreshed (0 = nothing to
 * do / no source). Opt-in from xrdcp --auto-refresh. (credrefresh.c) */
int  xrdc_cred_autorefresh(int want_write, const char *oidc_account,
                           int verbose, FILE *out);

/* ---- proxy.c (xrdgsiproxy: RFC-3820 X.509 proxy create/info/destroy) ---- */
/* If the session has a signing key and the server's security level requires it
 * for this opcode, send a kXR_sigver frame covering hdr24(+payload) and consume
 * its kXR_ok before the real request. No-op otherwise. 0 / -1. */
int  xrdc_sigver_maybe(xrdc_conn *c, const uint8_t *hdr24, const void *payload,
                       uint32_t plen, xrdc_status *st);

/* ---- ops_meta.c ---- */
int xrdc_stat(xrdc_conn *c, const char *path, xrdc_statinfo *out, xrdc_status *st);
/* lstat — do not follow a final symlink (kXR_statNoFollow). A symlink reports the
 * kXR_other flag with size = target length; against a server without the vendor
 * extension the option is ignored and this behaves like xrdc_stat. */
int xrdc_lstat(xrdc_conn *c, const char *path, xrdc_statinfo *out, xrdc_status *st);
int xrdc_dirlist(xrdc_conn *c, const char *path, int want_stat,
                 xrdc_dirent **ents, size_t *count, xrdc_status *st);

/* ---- ops_file.c ---- */
typedef struct {
    uint8_t fhandle[XRDC_FHANDLE_LEN];
    /* phase-42 W4: inline read-compression codec negotiated at open (the codec
     * ordinal from the kXR_open reply cptype[0]).  0 = plaintext (the default);
     * non-zero means kXR_read responses are codec frames the client inflates.
     * Only set when this client opened with "?xrootd.compress=" against a server
     * that confirmed support; stays 0 for stock servers / plain opens. */
    uint8_t read_codec;
    /* phase-42 W5: inline write-compression codec negotiated at open (write opens
     * only).  0 = plaintext; non-zero means xrdc_file_write compresses each
     * payload as a self-contained frame the server decompresses on ingest. */
    uint8_t write_codec;
} xrdc_file;

int xrdc_file_open_read(xrdc_conn *c, const char *path, xrdc_file *f,
                        xrdc_status *st);
/* force → truncate-on-open (overwrite); posc → persist-on-successful-close. */
int xrdc_file_open_write(xrdc_conn *c, const char *path, int force, int posc,
                         xrdc_file *f, xrdc_status *st);
/* Open an EXISTING file for read+write IN PLACE (no truncate, no create) — enables
 * random writes over existing content (kXR_open_updt only). posc as above. */
int xrdc_file_open_update(xrdc_conn *c, const char *path, int posc,
                          xrdc_file *f, xrdc_status *st);
/* Read up to len bytes at offset; returns bytes read (0 = EOF) or -1. Accumulates
 * any kXR_oksofar partial frames into buf. */
/* phase-42 W4: inflate one inline-compressed kXR_read frame (codec ordinal from
 * the open reply cptype[0]).  Shared by the sync (ops_file.c) and async
 * (aio_mgr.c) read paths.  Returns plaintext length, or -1 on a corrupt/oversized
 * frame.  out_cap bounds the plaintext (it cannot exceed the requested length). */
ssize_t xrdc_inflate_frame(uint8_t codec, const uint8_t *comp, size_t comp_len,
                           void *out, size_t out_cap, xrdc_status *st);

/* phase-42 W5: compress one inline-write frame (codec ordinal from the open reply
 * cptype[0]).  Shared by the sync (ops_file.c) and async (aio_mgr.c) write paths.
 * Returns a malloc'd buffer (caller frees) + sets *out_len, or NULL on failure. */
uint8_t *xrdc_deflate_frame(uint8_t codec, const void *in, size_t in_len,
                            size_t *out_len, xrdc_status *st);

ssize_t xrdc_file_read(xrdc_conn *c, xrdc_file *f, int64_t offset,
                       void *buf, size_t len, xrdc_status *st);
int xrdc_file_write(xrdc_conn *c, xrdc_file *f, int64_t offset,
                    const void *buf, size_t len, xrdc_status *st);
int xrdc_file_close(xrdc_conn *c, xrdc_file *f, xrdc_status *st);

/* Scatter-gather read/write (kXR_readv 3025 / kXR_writev 3031). Each segment names
 * an offset+length on the open file f; readv fills seg.buf, writev sends seg.data.
 * Up to XRDC_VEC_MAXSEGS segments per call. */
#define XRDC_VEC_MAXSEGS 1024
#define XRDC_VEC_MAXBYTES (256u << 20)   /* aggregate readv/writev payload cap */
typedef struct {
    int64_t offset;
    size_t  len;
    void   *buf;          /* caller-supplied, >= len bytes */
    size_t  got;          /* OUT: bytes actually delivered for this segment */
} xrdc_readv_seg;
typedef struct {
    int64_t     offset;
    size_t      len;
    const void *data;     /* caller-supplied, len bytes */
} xrdc_writev_seg;
/* readv: issue one kXR_readv for all segs; fills each seg.buf and sets seg.got to
 * the bytes actually delivered for that segment (which may be < seg.len on a short
 * read past EOF). Returns total bytes read across segments, or -1. */
ssize_t xrdc_file_readv(xrdc_conn *c, xrdc_file *f, xrdc_readv_seg *segs,
                        size_t nseg, xrdc_status *st);
/* writev: issue one kXR_writev for all segs (do_sync → fsync after). 0 / -1. */
int xrdc_file_writev(xrdc_conn *c, xrdc_file *f, const xrdc_writev_seg *segs,
                     size_t nseg, int do_sync, xrdc_status *st);

/* Open with an opaque "?key=val&…" suffix (for TPC tpc.* params). write selects
 * read vs write-create semantics (force/posc as in open_write). Redirect-aware. */
int xrdc_file_open_opaque(xrdc_conn *c, const char *path, const char *opaque,
                          int write, int force, int posc, xrdc_file *f,
                          xrdc_status *st);
/* kXR_sync the handle (also the TPC arm/trigger on a destination handle). Uses a
 * plain send+recv (no redirect follow); the caller may raise c->io.timeout_ms
 * before the trigger sync, whose reply is deferred until the pull completes. */
int xrdc_file_sync(xrdc_conn *c, xrdc_file *f, xrdc_status *st);

/* Paged I/O with per-page CRC32c integrity (kXR_pgread/kXR_pgwrite). pgread reads
 * up to len bytes at offset and verifies every page's CRC32c before returning the
 * decoded bytes (returns bytes read, 0=EOF, -1=error incl. CRC mismatch). pgwrite
 * frames buf into [crc][data] page units and fails (-1) if the server rejects any
 * page's checksum. Both are file-offset aligned (short first/last page). */
ssize_t xrdc_file_pgread(xrdc_conn *c, xrdc_file *f, int64_t offset,
                         void *buf, size_t len, xrdc_status *st);
int     xrdc_file_pgwrite(xrdc_conn *c, xrdc_file *f, int64_t offset,
                          const void *buf, size_t len, xrdc_status *st);

/* ---- resilient.c — network resilience for the synchronous tools ----
 *
 * Brings xrootdfs-style recovery (reconnect + full re-auth + handle reopen +
 * offset resume + bounded backoff) to one-shot CLI flows, lifted from the proven
 * xrdcp pump (copy.c) and the async mfile layer (aio_mgr.c). Two seams:
 *   - xrdc_with_resilience(): wrap any stateless op (stat/ls/query/...) so it is
 *     re-issued after a sever, gated by an idempotency class.
 *   - xrdc_rfile: a synchronous file handle that reopens + resumes mid-transfer.
 * Both are no-ops (single attempt) when the window is 0, so --no-retry restores
 * the exact legacy fail-fast path. Raw ops (and copy.c) are untouched. */

/* Idempotency class for xrdc_with_resilience — governs re-issue after a sever. */
typedef enum {
    XRDC_OP_READONLY,           /* stat/ls/locate/query/statvfs: retry freely */
    XRDC_OP_IDEMPOTENT,         /* chmod: re-apply is harmless — retry freely */
    XRDC_OP_MUTATION_NORMALIZE, /* mkdir/rm/rmdir/mv/prepare: re-issue ONCE, then
                                 * treat benign_errno (EEXIST/ENOENT) as success */
    XRDC_OP_UNSAFE              /* never auto-retry */
} xrdc_op_class;

/* A single logical operation over a connection, re-invocable after a reconnect.
 * Returns 0 on success, -1 with *st set on failure. */
typedef int (*xrdc_op_fn)(xrdc_conn *c, void *arg, xrdc_status *st);

/* Effective resilience window for c (ms): 0 when disabled (opts.no_retry), else
 * opts.max_stall_ms, else XRDC_DEFAULT_MAX_STALL_MS. */
int xrdc_resilient_window_ms(const xrdc_conn *c);

/* Reconnect c to its home endpoint (manager if known, else the current host) with
 * a full re-handshake + re-auth. 0 / -1 (st set). */
int xrdc_reconnect_home(xrdc_conn *c, xrdc_status *st);

/* Like xrdc_connect, but retries the (multi-RTT, loss-fragile) connect+handshake+
 * login within the resilience window with backoff, so a one-shot tool can bring a
 * session up over a lossy link instead of failing on the first severed handshake.
 * A refused connection (nothing listening) still fails fast. Window from o /
 * $XRDC_MAX_STALL_MS; 0 ⇒ a single attempt (legacy). 0 / -1 (st set). */
int xrdc_connect_resilient(xrdc_conn *c, const xrdc_url *u, const xrdc_opts *o,
                           xrdc_status *st);

/* Run op(c,arg,st); on a retryable transport fault, reconnect to home and re-run,
 * bounded by max_stall_ms with backoff. cls governs mutation re-issue; benign_errno
 * (e.g. EEXIST/ENOENT) becomes success for MUTATION_NORMALIZE. max_stall_ms<=0 ⇒ a
 * single attempt (legacy). Returns op's last result; 0 on success. */
int xrdc_with_resilience(xrdc_conn *c, int max_stall_ms, xrdc_op_class cls,
                         int benign_errno, xrdc_op_fn op, void *arg, xrdc_status *st);

/* Resilient single-frame roundtrip: like xrdc_roundtrip (re-sending the same
 * hdr24/payload, which gets a fresh streamid each send) but with reconnect+retry
 * on a transport sever, gated by cls/benign_errno. The window is taken from c
 * (xrdc_resilient_window_ms); 0 ⇒ a single attempt. This is the seam the
 * high-level metadata/fs ops route through, so every tool inherits resilience. */
int xrdc_roundtrip_resilient(xrdc_conn *c, void *hdr24, const void *payload,
                             uint32_t plen, xrdc_op_class cls, int benign_errno,
                             uint16_t *status, uint8_t **body, uint32_t *blen,
                             xrdc_status *st);

/* Resilient synchronous file: the handle plus the state needed to reopen + resume
 * after a sever (path/flags), with an adaptive read size that halves under loss. */
typedef struct {
    xrdc_conn *c;
    xrdc_file  f;
    char       path[XRDC_PATH_MAX];
    char       opaque[256];     /* "?key=val&…" suffix for read opens, or "" */
    int        writable;        /* 1 ⇒ reopen in place (update, no truncate) */
    int        posc;            /* persist-on-successful-close (write opens) */
    int        pgrw;            /* 1 ⇒ paged I/O + per-page CRC (kXR_pgread/pgwrite) */
    int        max_stall_ms;
    size_t     cur_chunk;       /* adaptive read size; halves on each sever to a floor */
    int      (*cancel)(void);   /* optional abort predicate (e.g. SIGINT); NULL = none */
} xrdc_rfile;

/* opaque may be NULL. pgrw selects paged CRC I/O. max_stall_ms<=0 ⇒ pull the
 * window from c (xrdc_resilient_window_ms). The open itself is resilient. 0/-1. */
int     xrdc_rfile_open_read (xrdc_conn *c, const char *path, const char *opaque,
                              int pgrw, int max_stall_ms, xrdc_rfile *rf, xrdc_status *st);
int     xrdc_rfile_open_write(xrdc_conn *c, const char *path, int force, int posc,
                              int pgrw, int max_stall_ms, xrdc_rfile *rf, xrdc_status *st);
/* Read/write at an absolute offset, transparently riding out severs within the
 * window (reconnect + reopen + re-issue at the same offset — idempotent). pread
 * returns bytes read (0=EOF) or -1; pwrite returns 0/-1. */
ssize_t xrdc_rfile_pread (xrdc_rfile *rf, int64_t off, void *buf, size_t len, xrdc_status *st);
int     xrdc_rfile_pwrite(xrdc_rfile *rf, int64_t off, const void *buf, size_t len, xrdc_status *st);
int     xrdc_rfile_close (xrdc_rfile *rf, xrdc_status *st);

/* ---- checksum.c ---- */
typedef enum {
    XRDC_CK_ADLER32 = 0,
    XRDC_CK_CRC32C,
    XRDC_CK_MD5,
    XRDC_CK_CRC64,      /* CRC-64/XZ   */
    XRDC_CK_CRC64NVME,  /* CRC-64/NVME */
    XRDC_CK_ZCRC32      /* zlib CRC-32 — XRootD "zcrc32" (8 hex) */
} xrdc_cksum_algo;

/* Map an algorithm name ("adler32"/"crc32c"/"md5") to the enum. 0 / -1. */
int xrdc_cksum_algo_parse(const char *name, xrdc_cksum_algo *out);
/* Streaming local checksum over a file descriptor; writes a lowercase hex digest
 * (NUL-terminated) into hex[hexsz] (need ≥33 for md5). 0 / -1. */
int xrdc_cksum_fd(int fd, xrdc_cksum_algo algo, char *hex, size_t hexsz,
                  xrdc_status *st);
/* Ask the server for a file's checksum via kXR_query/kXR_Qcksum (redirect-aware).
 * On success writes the server's hex digest into hex[hexsz]. 0 / -1. */
int xrdc_query_cksum(xrdc_conn *c, const char *path, const char *algo_name,
                     char *hex, size_t hexsz, xrdc_status *st);

/* ---- cks_verify.c (verify a file on disk against its recorded checksum) ---- */
#define XRDC_CKV_HEX_MAX 129

/* Which recorded-checksum sources to consult. */
typedef enum {
    XRDC_CKV_AUTO = 0,   /* cache sidecars (.cinfo/.meta) AND storage (xattr/.cks) */
    XRDC_CKV_CACHE,      /* proxy cache only: <file>.cinfo / <file>.meta cks fields */
    XRDC_CKV_STORAGE     /* storage only: user.XrdCks.<alg> xattr + <file>.cks sidecar */
} xrdc_ckv_mode;

/* Outcome of a verification. */
typedef enum {
    XRDC_CKV_OK = 0,        /* a recorded checksum was found and matches */
    XRDC_CKV_MISMATCH,      /* recorded != recomputed (corruption) */
    XRDC_CKV_NO_RECORD,     /* no recorded checksum found for this file/algo */
    XRDC_CKV_UNSUPPORTED,   /* recorded with an algorithm this engine cannot compute */
    XRDC_CKV_ERROR          /* I/O / access error */
} xrdc_ckv_result;

/* Filled with the decisive record (the match, or the mismatch). */
typedef struct {
    char source[16];                 /* "xattr" | "cks" | "cinfo" | "meta" */
    char algo[16];
    char recorded[XRDC_CKV_HEX_MAX];
    char computed[XRDC_CKV_HEX_MAX];
} xrdc_ckv_report;

/* Recompute `path`'s checksum and compare it to the value recorded on disk.
 * want_algo NULL ⇒ verify every recorded checksum; non-NULL ⇒ only that algo.
 * `rep` (may be NULL) receives the decisive record. See cks_verify.c. */
xrdc_ckv_result xrdc_cks_verify_file(const char *path, const char *want_algo,
    xrdc_ckv_mode mode, xrdc_ckv_report *rep, xrdc_status *st);

/* ---- cli_cksum.c (shared checksum-tool front-end) ---- */
/* Process-exit conventions shared by the front-end tools (phase-49):
 *   USAGE — bad arguments / URL parse / local open  (was the bare `return 50`)
 *   IO    — runtime I/O failure
 *   AUTH  — authentication/authorization failure
 * Runtime failures prefer xrdc_shellcode(st), which maps a status to a stable
 * code; these are for the cases that never produced a status. */
#define XRDC_EXIT_USAGE  50
#define XRDC_EXIT_IO     51
#define XRDC_EXIT_AUTH   53

/* The whole body of xrdcrc32c / xrdcrc64 / xrdadler32: checksum a LOCAL file or a
 * root:// file with `algo` (local enum) / `algo_name` (wire name) and print
 * "<hex> <path>". Returns the process exit code. `arg` is the single CLI argument
 * (NULL ⇒ usage). `err_exit` is the tool's process exit code for ANY failure to
 * produce a checksum (connect/query/open/digest), chosen to match the stock tool
 * byte-for-byte: xrdadler32 → 1, xrdcrc32c → 3, xrdcrc64 → 1. Argument/URL-parse
 * errors still return XRDC_EXIT_USAGE. */
int xrdc_cli_cksum_main(const char *prog, const char *algo_name,
                        xrdc_cksum_algo algo, const char *arg, int err_exit);

/* ---- cli_opts.c / cli_conn.c (shared front-end scaffold) ---- */
/* Zero-init connection options to the canonical defaults (verify_host on). */
void xrdc_opts_init(xrdc_opts *o);

/* ---- cli_cred.c — CLI→credential-store builder ---- */
/* Map per-tool CLI values into an xrdc_cred_config and return a live store.
 * NULL/empty arguments fall back to per-handler env/default discovery, preserving
 * today's per-protocol precedence exactly.  Returns NULL only on OOM.
 * Callers free the result with xrdc_cred_store_free. */
struct xrdc_cred_store *
xrdc_cli_cred_store_build(const char *proxy, const char *bearer,
                           const char *bearer_file, const char *s3_access,
                           const char *s3_secret, const char *oidc_account,
                           int auto_refresh);
/* Release a credential store (matches xrdc_cred_store_new / xrdc_cli_cred_store_build).
 * No-op when s is NULL. */
void xrdc_cred_store_free(struct xrdc_cred_store *s);
/* Consume one common connection/trace flag at argv[*i] (--tls/--notlsok/
 * --noverifyhost/--auth <p>/--wire-trace[=N]/--timing/--redirect-trace/--capture
 * <p>), advancing *i past any value. Returns 1 if it recognised the flag (caller
 * should `continue`), 0 if not (caller handles its own flags). */
int  xrdc_opts_parse_arg(xrdc_opts *o, int argc, char **argv, int *i);
/* endpoint_parse → connect with the standard "prog: <msg>" / "prog: connect:
 * <msg>" stderr on failure. Returns 0 (connected, c live) or a process exit code
 * (XRDC_EXIT_USAGE on parse error, xrdc_shellcode(st) on connect failure). */
int  xrdc_cli_connect(const char *endpoint, const xrdc_opts *o, xrdc_conn *c,
                      const char *prog, xrdc_status *st);
/* Emit "tool: op path: msg" + a credential hint and return xrdc_shellcode(st):
 * the per-operation failure idiom shared across the namespace tools. */
int  xrdc_report_err(FILE *out, const char *tool, const char *op,
                     const char *path, const xrdc_status *st, int want_write);

/* ---- path.c / units.c (shared path + byte-count helpers) ---- */
/* Canonicalise `arg` against `cwd` into an absolute server path in out[outsz],
 * collapsing "."/".."/dup-slashes (the xrdfs shell's build_path). */
void    xrdc_path_resolve(const char *cwd, const char *arg, char *out, size_t outsz);
/* Open a credential file safely (O_NOFOLLOW, regular + owned by euid, no
 * group/other write; `secret` also rejects group/other read). Returns an fd the
 * caller closes, or -1; `st` may be NULL for silent probing. See path.c. */
int     xrdc_open_credfile(const char *path, int secret, xrdc_status *st);
/* Open a credential file as an OpenSSL BIO with xrdc_open_credfile's safety
 * checks (no symlink, owned by euid, secret=1 → 0600). NULL on a missing/unsafe
 * file; the caller surfaces its own "no proxy" message. Defined in proxy.c; the
 * opaque forward-decl keeps OpenSSL out of this header. */
struct bio_st;
struct bio_st *xrdc_credfile_bio(const char *path, int secret);
/* Render a byte count: raw decimal, or human ("1.5G") when human!=0. */
void    xrdc_fmt_size(int64_t n, char *out, size_t sz, int human);
/* Parse "4096" / "1.5G" (K/M/G/T suffix) → bytes, or -1 if malformed. */
int64_t xrdc_parse_bytes(const char *s);
/* Token-bucket pacing: sleep off any surplus so the average stays ≤ `rate` B/s
 * (rate ≤ 0 disables). `start` is the transfer's CLOCK_MONOTONIC start. */
struct timespec;
void    xrdc_rate_pace(const struct timespec *start, int64_t sent, double rate);

/* ---- ops_fs.c (xrdfs subcommands) ---- */
/* Mutating namespace ops: 0 / -1 (st set). All are redirect-aware. */
int xrdc_mkdir(xrdc_conn *c, const char *path, int mode, int parents,
               xrdc_status *st);
int xrdc_rm(xrdc_conn *c, const char *path, xrdc_status *st);
int xrdc_rmdir(xrdc_conn *c, const char *path, xrdc_status *st);
int xrdc_mv(xrdc_conn *c, const char *src, const char *dst, xrdc_status *st);
int xrdc_chmod(xrdc_conn *c, const char *path, int mode, xrdc_status *st);
int xrdc_truncate(xrdc_conn *c, const char *path, int64_t size, xrdc_status *st);

/* ---- ops_ext.c — vendor POSIX-completeness ops (kXR_setattr/symlink/readlink/
 * link). Only emit these against a server that advertises them: xrdc_ext_probe
 * queries kXR_Qconfig "xrdfs.ext" and sets the four flags (0 = unsupported). All
 * are redirect-aware; 0 / -1 (st set). ---- */
int xrdc_ext_probe(xrdc_conn *c, int *has_setattr, int *has_symlink,
                   int *has_readlink, int *has_link, xrdc_status *st);
/* set_times applies times[2] (atime,mtime; per-field UTIME_OMIT/UTIME_NOW honoured
 * server-side via utimensat); set_owner applies uid/gid. mode is NOT handled here
 * (use xrdc_chmod). */
int xrdc_setattr(xrdc_conn *c, const char *path, int set_times,
                 const struct timespec times[2], int set_owner,
                 uint32_t uid, uint32_t gid, xrdc_status *st);
int xrdc_symlink(xrdc_conn *c, const char *target, const char *linkpath,
                 xrdc_status *st);
int xrdc_link(xrdc_conn *c, const char *oldpath, const char *newpath,
              xrdc_status *st);
/* Read a symlink target into out[outsz] (NUL-terminated). Returns the target
 * length (bytes, may exceed outsz-1 if truncated) or -1 (st set). */
ssize_t xrdc_readlink(xrdc_conn *c, const char *path, char *out, size_t outsz,
                      xrdc_status *st);

/* ---- fattr.c — extended attributes (kXR_fattr), path-based, one attr at a time.
 * The per-attribute kXR status is reported via st->kxr (e.g. kXR_AttrNotFound →
 * map with xrdc_kxr_to_errno). 0 / -1. ---- */
/* Get: copies up to bufsz bytes of the value into value[]; *out_vlen (may be NULL)
 * gets the true value length (pass value=NULL/bufsz=0 to query the size). */
int xrdc_fattr_get(xrdc_conn *c, const char *path, const char *name,
                   void *value, size_t bufsz, size_t *out_vlen, xrdc_status *st);
/* Set: create_only != 0 → fail if the attribute already exists (kXR_fa_isNew). */
int xrdc_fattr_set(xrdc_conn *c, const char *path, const char *name,
                   const void *value, size_t vlen, int create_only,
                   xrdc_status *st);
int xrdc_fattr_del(xrdc_conn *c, const char *path, const char *name,
                   xrdc_status *st);
/* List: copies up to bufsz bytes of the NUL-separated name list into out[];
 * *out_len (may be NULL) gets the true total length. */
int xrdc_fattr_list(xrdc_conn *c, const char *path, char *out, size_t bufsz,
                    size_t *out_len, xrdc_status *st);
/* Text-reply ops: copy the server's reply into out[outsz] (NUL-terminated). */
int xrdc_query(xrdc_conn *c, int infotype, const char *args, char *out,
               size_t outsz, xrdc_status *st);
int xrdc_statvfs(xrdc_conn *c, const char *path, char *out, size_t outsz,
                 xrdc_status *st);
int xrdc_locate(xrdc_conn *c, const char *path, char *out, size_t outsz,
                xrdc_status *st);
/* options = kXR_stage/cancel/wmode/fresh… (byte); optionX = extended flags
 * (kXR_evict…, uint16); prty = request priority 0-3. */
int xrdc_prepare(xrdc_conn *c, const char *const *paths, int npaths, int options,
                 int optionX, int prty, char *out, size_t outsz, xrdc_status *st);

/* ---- proxy.c (xrdgsiproxy: RFC-3820 X.509 proxy create/info/destroy) ---- */
typedef struct {
    const char *user_cert;   /* NULL ⇒ $X509_USER_CERT else ~/.globus/usercert.pem */
    const char *user_key;    /* NULL ⇒ $X509_USER_KEY  else ~/.globus/userkey.pem  */
    const char *out_path;    /* NULL ⇒ $X509_USER_PROXY else /tmp/x509up_u<uid>    */
    int         valid_hours; /* lifetime; ≤0 ⇒ 12h */
    int         bits;        /* ephemeral RSA size; ≤0 ⇒ 2048 */
} xrdc_proxy_opts;
/* Create an RFC-3820 proxy (proxyCertInfo OID 1.3.6.1.5.5.7.1.14, id-ppl-inheritAll)
 * signed by the user cert/key, written as cert+chain+key (mode 0400). 0 / -1. */
int xrdc_proxy_create(const xrdc_proxy_opts *o, xrdc_status *st);
/* Print subject/issuer/validity of the proxy at `path` (NULL ⇒ default). 0 / -1. */
int xrdc_proxy_info(const char *path, FILE *out, xrdc_status *st);
/* Shred + unlink the proxy at `path` (NULL ⇒ default). 0 / -1. */
int xrdc_proxy_destroy(const char *path, xrdc_status *st);
/* Resolve the default proxy path ($X509_USER_PROXY else /tmp/x509up_u<uid>). */
void xrdc_proxy_default_path(char *out, size_t outsz);
/* Phase 40 (c): seconds of proxy validity remaining (negative if expired) into
 * *secs_left.  0 on success, -1 if no/unparseable proxy at `path` (NULL=default). */
int xrdc_proxy_remaining(const char *path, long *secs_left);

/* ---- copy.c ---- */
/* Progress callback: invoked during a transfer with bytes-so-far and the total
 * (total < 0 = unknown, e.g. stdin); done==total signals completion. NULL = off. */
typedef void (*xrdc_progress_cb)(void *arg, long long done, long long total);
typedef struct {
    int         force;    /* -f: overwrite existing destination */
    int         posc;     /* -P: persist-on-successful-close (upload) */
    int         silent;   /* -s: suppress progress/info */
    int         verbose;  /* -v/-d */
    int         pgrw;     /* --pgrw: use kXR_pgread/pgwrite (per-page CRC32c) */
    const char *cksum;    /* --cksum <type>[:source|:print|:<value>], or NULL */
    const char *compress; /* --compress <codec>: phase-42 W4 root:// inline read
                           * compression — request "?xrootd.compress=<codec>" on
                           * the read open; NULL = plaintext (default). */
    int         zip;      /* --zip: phase-42 W3 — store the local source as a
                           * STORE member of the destination ZIP archive. */
    int         zip_append; /* --zip-append: like --zip but append to an existing
                           * (non-ZIP64) archive instead of overwriting. */
    int         streams;  /* -S/--streams N: attach N-1 kXR_bind secondaries */
    int         tpc_mode; /* --tpc: 0=off, 1=first (fallback), 2=only, 3=delegate */
    const char *tpc_token_mode;  /* --tpc delegate token_mode value (optional) */
    int         recursive;/* -r: copy a directory tree (dirlist walk + mkdir + per-file) */
    /* davs/http(s) + s3 transfer auth (web schemes). NULL fields fall back to the
     * environment (BEARER_TOKEN / AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
     * AWS_DEFAULT_REGION). s3_region defaults to "us-east-1". */
    const char *bearer;    /* -T/--token: WebDAV/HTTP Authorization: Bearer <jwt> */
    const char *s3_access; /* --s3-access: SigV4 access key id */
    const char *s3_secret; /* --s3-secret: SigV4 secret key */
    const char *s3_region; /* --s3-region: SigV4 region (default us-east-1) */
    int         max_stall_ms;  /* download resilience: per-read patience window for
                                * reconnect+reopen+resume on a flaky/lossy link
                                * (0 = default 60000). The read size adapts down to
                                * survive loss; see pump_src_remote. */
    int         no_retry;      /* 1 ⇒ resilience off: every bounded copy loop uses a
                                * zero-stall deadline and fails on the first transport
                                * fault (--no-retry / --retry 0 / --max-stall 0).
                                * Distinguishes "fail fast" from max_stall_ms==0
                                * meaning "use the default". See copy_stall_ms(). */
    xrdc_progress_cb progress;  /* periodic transfer progress, or NULL */
    void            *progress_arg;
    int         io_uring;  /* phase-44 --io-uring: 0=auto, 1=on, 2=off. Selects
                            * the local-disk io_uring overlap ring in copy.c.
                            * auto = use it iff xrdc_uring_available(); on with no
                            * liburing = clean CLI error; off = classic read/write. */
} xrdc_copy_opts;

/* xrdc_copy_opts.io_uring tri-state values (match the server enum spelling). */
#define XRDC_IO_URING_AUTO  0
#define XRDC_IO_URING_ON    1
#define XRDC_IO_URING_OFF   2

/* --tpc mode values for xrdc_copy_opts.tpc_mode. */
#define XRDC_TPC_OFF      0
#define XRDC_TPC_FIRST    1   /* try TPC, fall back to client-mediated on failure */
#define XRDC_TPC_ONLY     2   /* TPC or hard fail */
#define XRDC_TPC_DELEGATE 3   /* TPC with credential delegation (tpc.token_mode) */
/* Copy between a root://[s] URL and a local path (or "-"). Direction is inferred
 * from the schemes: remote→local download, local→remote upload. `co` carries the
 * connection (auth/TLS) options; may be NULL. */
int xrdc_copy(const char *src, const char *dst, const xrdc_copy_opts *o,
              const xrdc_opts *co, xrdc_status *st);

/* Phase 40 (a): install cooperative SIGINT/SIGTERM handlers so an interrupted
 * transfer drops its partial local destination instead of leaving a corrupt
 * file. The handler only sets a flag (async-signal-safe); the transfer loops
 * poll xrdc_copy_quit_requested() and abort, and the normal teardown unlinks the
 * temp. Call once from main() before any transfer. */
void xrdc_copy_install_signal_handlers(void);
int  xrdc_copy_quit_requested(void);

#endif /* XRDC_H */
