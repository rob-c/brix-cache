/*
 * brix_net.h - networking/transport/diagnostics decls (sock/conn/http/s3/tls/pool/streams/…)
 * Phase-38 umbrella split of brix.h; included via brix.h (relies on the
 * core types declared there first).  Do not include this directly.
 */
#ifndef XRDC_NET_H
#define XRDC_NET_H

/* ---- glob.c — client-side wildcard expansion ---- */
/* 1 if `s` contains a glob metacharacter (* ? [). */
int  brix_has_glob(const char *s);
/* (brix_glob declared below, after brix_opts is defined.) */

/* Transport: a socket, optionally wrapped in a TLS session. All byte I/O funnels
 * through brix_read_full/brix_write_full on this, so TLS is a single branch. We
 * forward-declare struct ssl_st so this header stays OpenSSL-free. */
struct ssl_st;
/* Forward-declare the credential store so brix_opts can carry a pointer without
 * pulling cred.h (and its OpenSSL/crypto includes) into every consumer. */
struct brix_cred_store;
typedef struct {
    int            fd;
    struct ssl_st *ssl;       /* NULL = cleartext; non-NULL = TLS active */
    int            timeout_ms;
} brix_io;

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
    struct brix_cred_store *cred; /* optional pre-built credential store; NULL =
                                   * per-handler env/default discovery (today's
                                   * behaviour; C2 will thread this through auth). */
} brix_opts;

/* Default reconnect+retry patience window when resilience is on but unspecified. */
#define XRDC_DEFAULT_MAX_STALL_MS 30000

/* Forward decl: the opaque capture sink (capture.c). */
struct brix_capture;

/* §15 diagnostics state, embedded in brix_conn. Zero-initialised by the conn's
 * memset, so every hook is inert (single load+test) unless armed from opts. */
#define XRDC_NOP 64   /* per-opcode RTT table size; reqid-kXR_1stRequest indexes it */
typedef struct {
    int         wire_trace;       /* mirrors opts.wire_trace (survives reconnect) */
    int         timing;           /* mirrors opts.timing */
    int         redir_trace;      /* mirrors opts.redir_trace (§15.4) */
    const char *chosen_auth;      /* auth proto the driver picked (NULL = anon) */
    uint64_t    t_send_ns;        /* CLOCK_MONOTONIC at the last brix_send */
    uint16_t    inflight_reqid;   /* requestid of the in-flight request */
    struct { uint64_t n, tot_ns, min_ns, max_ns; } rtt[XRDC_NOP];
    struct brix_capture *cap;     /* §15.1: capture sink (NULL=off; survives reconnect) */
    /* §15.3 connect-phase stamps (CLOCK_MONOTONIC ns), filled by bringup:
     * [0]=start [1]=tcp-connected [2]=tls-done [3]=login+auth-done. 0 = not set. */
    uint64_t    phase_ns[4];
} brix_diag;

#define XRDC_REDIR_MAX 16   /* max kXR_redirect hops before giving up (loop/SSRF guard) */
#define XRDC_HOSTPORT_MAX 288  /* "host:port" key: host[256] + ':' + port + NUL, padded */

typedef struct {
    brix_io  io;
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

    /* --- GSI X.509 delegation (client → server), captured in gsi round-2 so the
     * follow-up kXGS_pxyreq round can reuse the agreed session cipher --- */
    int      gsi_deleg_ready;    /* 1 = session cipher below is valid */
    uint8_t  gsi_deleg_key[64];  /* agreed AES session key */
    size_t   gsi_deleg_keylen;
    char     gsi_deleg_cipher[24];
    int      gsi_deleg_use_iv;

    /* --- TPC coordinator open (third-party copy) --- */
    int      tpc_coord_defer;    /* 1 = a kXR_waitresp on this conn means "rendezvous
                                  * registered, final reply deferred"; brix_recv
                                  * surfaces it to the caller instead of blocking for
                                  * the async reply (which only arrives AFTER the
                                  * orchestrator opens the dest + triggers the pull —
                                  * blocking here would deadlock the rendezvous). */

    /* --- redirect / reconnect (M5) --- */
    brix_opts opts;             /* copy of the connect opts, replayed on reconnect */
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
    brix_diag diag;              /* wire-trace / timing state (off unless armed) */
    char      sec_list[256];     /* the login "&P=…" sec list, for `xrdfs explain` */
} brix_conn;

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
} brix_statinfo;

typedef struct {
    char          name[XRDC_NAME_MAX];
    int           have_stat;
    brix_statinfo st;
} brix_dirent;

/* ---- sock.c ---- */
int brix_tcp_connect(const char *host, int port, int timeout_ms, brix_status *st);
/* Apply TCP_NODELAY + SO_KEEPALIVE (+ keep* triad) to a connected socket. Best-
 * effort; failures ignored. Called by brix_tcp_connect; exposed for the async loop. */
void brix_sock_tune(int fd);
/* Transfer over io: cleartext when io->ssl is NULL, else TLS. Bounded by
 * io->timeout_ms via poll(2). */
int brix_read_full(brix_io *io, void *buf, size_t n, brix_status *st);
int brix_write_full(brix_io *io, const void *buf, size_t n, brix_status *st);

/* ---- netpref.c — process-wide IPv6→IPv4 auto-downgrade (dual-stack hosts) ---- */
/* getaddrinfo family hint: AF_UNSPEC normally, AF_INET once the session has
 * demoted to IPv4-only after observing a broken IPv6 path. */
int  brix_netpref_family(void);
/* 1 if this process has demoted to IPv4-only. */
int  brix_netpref_demoted(void);
/* Record that a connection to `host` failed over IPv6 but then succeeded over
 * IPv4 — demote the whole process (mount session) to IPv4-only and log once.
 * Idempotent; a no-op when auto-downgrade is disabled. */
void brix_netpref_demote_ipv6(const char *host);
/* Record that an ESTABLISHED connection of the given address family failed over
 * the wire (reset / timeout / truncated read). When family is AF_INET6 this
 * demotes the session to IPv4-only (logged once) so the reconnect skips v6;
 * a no-op for AF_INET / AF_UNSPEC, when already demoted, or when disabled. */
void brix_netpref_note_wire_error(int family);
/* Self-heal: clear a demotion when IPv4 turns out not to work after all (e.g.
 * an IPv6-only host that briefly tripped the wire-error trigger), so the next
 * connect tries both families again. Logs once. No-op if not demoted. */
void brix_netpref_undo_demote(const char *why);
/* Disable auto-downgrade (default enabled; also off via the XRDC_NO_IPV6_FALLBACK
 * env var — EXPANDED: a client-only extension, not a vanilla XRootD variable).
 * Keeps retrying IPv6 on every connection — for IPv6-only sites or debugging. */
void brix_netpref_disable(void);

/* ---- nettmo.c — network timeout tunables + retry backoff ---- */
/* Connect+handshake+login (bring-up) cap, ms. Default 15000; override via the
 * setter (a CLI flag) or the XRDC_CONNECT_TIMEOUT_MS env var (EXPANDED). Keeps a
 * black-holed handshake from hanging the caller for the full I/O timeout. */
int  brix_tmo_connect_ms(void);
/* Steady-state per-operation read/write cap, ms. Default 30000; override via the
 * setter or the XRDC_IO_TIMEOUT_MS env var (EXPANDED). */
int  brix_tmo_io_ms(void);
/* CLI overrides (ignored when ms <= 0); take precedence over env + default. */
void brix_tmo_set_connect_ms(int ms);
void brix_tmo_set_io_ms(int ms);
/* Backoff for retry `attempt` (0-based): exponential 100ms<<attempt capped at 5s
 * plus xorshift jitter in [0, base/2]. *seed carries the jitter PRNG state. */
unsigned brix_backoff_delay_ms(unsigned attempt, uint64_t *seed);
/* Fast backoff for TRANSPORT faults (reset/EOF — instant, not server overload):
 * 25ms<<attempt capped at 250ms + jitter. The short cap fits many retries in the
 * patience window, which is what rides out a high packet-loss link. */
unsigned brix_backoff_delay_fast_ms(unsigned attempt, uint64_t *seed);
/* Sleep one brix_backoff_delay_ms / _fast_ms, in short slices so a cooperative
 * cancel (brix_copy_quit_requested) is observed promptly. */
void brix_backoff_sleep(unsigned attempt);
void brix_backoff_sleep_fast(unsigned attempt);

/* ---- tls.c ---- */
/* Upgrade c->io.fd to TLS (after the kXR_protocol reply, before login). When
 * verify_peer, the server cert must chain to ca_dir (a hash dir, e.g.
 * $X509_CERT_DIR); when verify_host, the cert name must match c->host. */
int  brix_tls_upgrade(brix_conn *c, int verify_peer, int verify_host,
                      const char *ca_dir, brix_status *st);
void brix_tls_free(brix_conn *c);

/* ---- conn.c ---- */
/* Resolve the CA trust dir for TLS verification: explicit arg → $X509_CERT_DIR →
 * /etc/grid-security/certificates → NULL (OpenSSL system defaults). Borrowed
 * string; never allocates. Use everywhere a ca_dir is needed so the client
 * trusts grid (IGTF) CAs without requiring $X509_CERT_DIR to be set. */
const char *brix_resolve_ca_dir(const char *opt_ca_dir);
/* Transparent TLS transfer used by sock.c when io->ssl != NULL (0 / -1). */
int brix_tls_read(brix_io *io, void *buf, size_t n, brix_status *st);
int brix_tls_write(brix_io *io, const void *buf, size_t n, brix_status *st);
/* Stream read (up to n bytes) over TLS for the HTTP client; *got=bytes (0=EOF). */
int brix_tls_read_some(brix_io *io, void *buf, size_t n, size_t *got, brix_status *st);
/* §15 explain: if TLS is active, set the ver and cipher out-params to the
 * negotiated protocol version + cipher name (static OpenSSL strings); returns 1
 * if active, 0 if not. Keeps OpenSSL out of the apps. */
int brix_tls_info(const brix_conn *c, const char **ver, const char **cipher);
/* Server peer-certificate facts, filled by brix_tls_peer_cert_info from the live
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
} brix_cert_info;
/* Fill *out from the server's leaf certificate (requires TLS active). Returns 0 on
 * success (out->have == 1), -1 if cleartext / no peer cert (out->have == 0). */
int brix_tls_peer_cert_info(const brix_conn *c, brix_cert_info *out);
/* Connect + handshake + (TLS upgrade if offered) but NO kXR_login — for cert
 * inspection (xrd certinfo). Requests TLS, tolerates a cleartext server. The caller
 * reads c->io.ssl via brix_tls_peer_cert_info, then brix_close. 0 / -1 (st set). */
int brix_connect_no_login(brix_conn *c, const brix_url *u, const brix_opts *o,
                          brix_status *st);
/* Standalone TLS client handshake on a connected socket (the HTTP(S) client, not the
 * root:// in-protocol upgrade). On success io->ssl is live + *out_ctx is the SSL_CTX. */
int  brix_tls_client(brix_io *io, const char *host, int verify_peer, int verify_host,
                     const char *ca_dir, void **out_ctx, brix_status *st);
void brix_tls_client_free(brix_io *io, void *ctx);
void brix_tls_client_info(const brix_io *io, const char **ver, const char **cipher);

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
} brix_http_resp;

/* General HTTP/1.1 request over cleartext (tls=0) or TLS (tls=1). method e.g. "GET"/
 * "HEAD"/"OPTIONS"/"PROPFIND"; extra_headers is a "K: V\r\n…" block or NULL; body/blen
 * optional. verify controls TLS peer+host checking. Fills *resp (free with
 * brix_http_resp_free). 0 / -1 (st set). PII-free at the call site's discretion. */
int  brix_http_req(const char *host, int port, int tls, const char *method,
                   const char *path, const char *extra_headers,
                   const void *body, size_t blen, int timeout_ms, int verify,
                   const char *ca_dir, brix_http_resp *resp, brix_status *st);
void brix_http_resp_free(brix_http_resp *resp);
/* Copy the value of response header `name` (case-insensitive) into out[outsz];
 * 1 if found, 0 if absent. */
int  brix_http_header(const brix_http_resp *resp, const char *name,
                      char *out, size_t outsz);

/* Pull-source for an HTTP PUT body: read up to `cap` bytes at absolute offset
 * `off` into buf. Returns bytes read (>0), 0 at EOF, or -1 with *st set. Mirrors
 * the copy-engine pump source signature so the upload body can be backed by a VFS
 * handle (storage routed through the shared SD driver) or a plain seekable fd
 * (anonymous temp / diagnostic) interchangeably — the transport never opens or
 * reads an export file directly. */
typedef ssize_t (*brix_http_body_src_fn)(void *ctx, uint8_t *buf, int64_t off,
                                         size_t cap, brix_status *st);

/* Streaming transfer (no whole-body buffering — production GET/PUT, any size).
 * brix_http_download streams the GET response body straight to out_fd (handles
 * Content-Length, chunked, and connection-close framing). brix_http_upload streams
 * exactly `clen` bytes pulled from `src(src_ctx, …)` as a PUT body. extra_headers
 * is a "K: V\r\n…" block or NULL. Both fill *http_status with the response code.
 * 0 / -1 (st set). */
int  brix_http_download(const char *host, int port, int tls, const char *path,
                        const char *extra_headers, int verify, const char *ca_dir,
                        int out_fd, int timeout_ms, int *http_status,
                        long long *body_len, brix_status *st);
int  brix_http_upload(const char *host, int port, int tls, const char *path,
                      const char *extra_headers, brix_http_body_src_fn src,
                      void *src_ctx, long long clen, int verify,
                      const char *ca_dir, int timeout_ms, int *http_status,
                      brix_status *st);

/* Resumable upload: streams the source as Content-Range PUT chunks, each on a
 * fresh connection, reconnecting + resuming from the server's durable offset on
 * a transport sever or 409 within max_stall_ms — so a davs:// upload survives an
 * nginx restart.  Needs server brix_webdav_upload_resume for true resume; a
 * plain server commits on the first (whole-range) chunk. 0 / -1 (st set). */
int  brix_http_upload_resumable(const char *host, int port, int tls,
                      const char *path, const char *extra_headers,
                      brix_http_body_src_fn src, void *src_ctx,
                      long long clen, int verify, const char *ca_dir,
                      int timeout_ms, int max_stall_ms, int *http_status,
                      brix_status *st);

/* ---- s3.c — AWS Signature Version 4 (path-style), lifted to the lib so both
 * xrdcp transfers and xrddiag probes share one signer. ---- */
/* Lowercase sha256-hex of a buffer into out[65]. */
void brix_s3_sha256_hex(const void *data, size_t len, char *out);
/* Build the SigV4 header block (x-amz-date + x-amz-content-sha256 + Authorization)
 * for `method` on path-style `uri`, with body hash `payload_hex` (lowercase sha256
 * hex; use brix_s3_sha256_hex("",0,..) for an empty body, or the literal
 * "UNSIGNED-PAYLOAD" for a streamed PUT). Region+service "s3". Output is a
 * "K: V\r\n…" block ready as extra_headers. 0 / -1. */
int  brix_s3_sign_v4(const char *method, const char *host, const char *uri,
                     const char *ak, const char *sk, const char *region,
                     const char *payload_hex, char *hdrs, size_t hdrsz);
/* As above, but with a canonical query string (already sorted + RFC-3986 encoded)
 * folded into the canonical request — needed to sign ListObjectsV2 (?list-type=2…). */
int  brix_s3_sign_v4_q(const char *method, const char *host, const char *uri,
                       const char *canon_qs, const char *ak, const char *sk,
                       const char *region, const char *payload_hex,
                       char *hdrs, size_t hdrsz);

/* ---- url.c ---- */
int brix_url_parse(const char *s, brix_url *out, brix_status *st);
/* Expand a root:// URL whose LAST path component globs into matching full URLs.
 * On success returns the match count (>=0) and sets *out (malloc'd array of malloc'd
 * URLs) + *n_out; free with brix_glob_free. Returns -1 if `url` isn't a root:// glob
 * or on error (st set). Declared here, after brix_opts, since it takes a *co. */
int  brix_glob(const char *url, const brix_opts *co, char ***out, size_t *n_out,
               brix_status *st);
void brix_glob_free(char **arr, size_t n);

/* ---- weblist.c — recursive WebDAV listing (for xrdcp -r over davs/http) ---- */
/* PROPFIND Depth:infinity on a WebDAV collection; returns absolute server paths of
 * every FILE beneath it (subdirs excluded). bearer NULL ⇒ anonymous. 0 / -1 (st set).
 * Free *paths with brix_strv_free. */
int  brix_webdav_list(const brix_weburl *u, const char *bearer, int verify,
                      const char *ca_dir, char ***paths, size_t *n_out, brix_status *st);
/* MKCOL a WebDAV collection at `path` on the endpoint `u` (for recursive upload).
 * bearer NULL ⇒ anonymous. Idempotent: an already-existing collection (405/301)
 * is treated as success. 0 / -1 (st set). */
int  brix_webdav_mkcol(const brix_weburl *u, const char *path, const char *bearer,
                       int verify, const char *ca_dir, brix_status *st);
/* List object keys under an s3:// URL's prefix via paginated, SigV4-signed
 * ListObjectsV2. The bucket is the first path component; the prefix is the rest.
 * ak/sk NULL ⇒ anonymous. Returns full object keys. 0 / -1. Free with brix_strv_free. */
int  brix_s3_list(const brix_weburl *u, const char *ak, const char *sk,
                  const char *region, int verify, const char *ca_dir,
                  char ***keys, size_t *n_out, brix_status *st);
void brix_strv_free(char **arr, size_t n);

/* ---- webfile.c — HTTP(S)/WebDAV transport for the FUSE driver (read path) ---- */
/* Single-resource stat via PROPFIND Depth:0 → size/mtime/is-dir (FUSE getattr).
 * bearer NULL ⇒ anonymous; verify+ca_dir apply to TLS (https/davs). 0 / -1. */
int  brix_web_stat(const brix_weburl *u, const char *path, const char *bearer,
                   int verify, const char *ca_dir, brix_statinfo *si, brix_status *st);
/* Directory listing via PROPFIND Depth:1 → child entries with stat (FUSE readdir).
 * Allocates *ents (free with free()); each entry has name + have_stat + st. 0 / -1. */
int  brix_web_readdir(const brix_weburl *u, const char *path, const char *bearer,
                      int verify, const char *ca_dir, brix_dirent **ents,
                      size_t *n, brix_status *st);
/* An open-for-read web file whose pread issues a Range GET over a PERSISTENT
 * keep-alive connection (resilient: reconnect + re-issue on a dropped link). */
typedef struct brix_webfile brix_webfile;
/* Open (stats first; fails if a directory). *si_out (optional) gets the stat. */
brix_webfile *brix_webfile_open(const brix_weburl *u, const char *path,
                                const char *bearer, int verify, const char *ca_dir,
                                int timeout_ms, brix_statinfo *si_out,
                                brix_status *st);
int64_t  brix_webfile_size(const brix_webfile *wf);
/* Read up to len bytes at off; returns bytes (0 at EOF), or -1 (st set). */
ssize_t  brix_webfile_pread(brix_webfile *wf, int64_t off, void *buf, size_t len,
                            brix_status *st);
void     brix_webfile_close(brix_webfile *wf, brix_status *st);

/* ---- xrdrc.c — ~/.xrdrc endpoint aliases ---- */
/* Resolve "name:suffix" via $XRDRC (else ~/.xrdrc) into out[outsz]. Always writes
 * the effective string (the input verbatim when it is not a known alias). Returns
 * 1 if an alias was expanded, 0 if not. */
int brix_alias_resolve(const char *arg, char *out, size_t outsz);
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
} brix_alias_info;
/* Look up an alias by NAME (the part before ':' in "name:suffix") and fill its auth
 * hints. *info is zeroed first. Returns 1 if the alias exists, 0 otherwise. Additive
 * companion to brix_alias_resolve (which handles the URL). */
int brix_alias_lookup(const char *name, brix_alias_info *info);
/* Turn a CLI endpoint — "host[:port]" or a root[s]:// URL — into a connectable
 * brix_url (default port 1094, scheme XRDC_SCHEME_ROOT/ROOTS). Shared by xrdfs and
 * every tool so the endpoint grammar lives in one place. 0 / -1 (st set). */
int brix_endpoint_parse(const char *ep, brix_url *out, brix_status *st);

/* ---- status.c ---- */
void        brix_status_clear(brix_status *st);
void        brix_status_set(brix_status *st, int kxr, int sys_errno, const char *fmt, ...);
const char *brix_kxr_name(int kxr);
int         brix_shellcode(const brix_status *st);
/* 1 if a failed status is transient (reconnect/re-issue may succeed), 0 if fatal.
 * Drives the async resilience layer's transparent retry/reconnect decisions. */
int         brix_status_retryable(const brix_status *st);
/* Map a failed status to a negative errno (for the FUSE/preload POSIX layers):
 * kXR_NotFound→-ENOENT, NotAuthorized→-EACCES, isDirectory/NotFile→-EISDIR, … */
int         brix_kxr_to_errno(const brix_status *st);

/* Narrate an established session (endpoint/roles/caps/signing/auth/TLS/sessid) to
 * `out`. Shared by `xrdfs explain` and `xrddiag check`. opts may be NULL (uses
 * c->opts). Read-only over fields conn.c/auth.c populated. */
void brix_explain_conn(brix_conn *c, const brix_opts *opts, FILE *out);

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
} brix_netfacts;
/* Fill *f from the live conn (getpeername/getsockopt(TCP_INFO)/getsockname on
 * c->io.fd + diag.phase_ns). Zeroes *f first; safe on a closed conn (all 0). */
void brix_netdiag_facts(const brix_conn *c, brix_netfacts *f);
/* Print the human-readable netdiag block (built on brix_netdiag_facts). */
void brix_netdiag_report(const brix_conn *c, FILE *out);

/* ---- capture.c (§15.1 session capture / offline replay) ---- */
/* Open a .xrdcap bundle for writing (magic + records). NULL on error. */
struct brix_capture *brix_capture_open(const char *path);
/* Append a metadata key=value record (endpoint, caps, sessid, auth, tls). */
void brix_capture_meta(struct brix_capture *cap, const char *key, const char *val);
/* Append a frame record (the exact wire bytes = header then body): dir
 * '>'=request '<'=response. hdr is the 24B request / 8B response header. */
void brix_capture_frame(struct brix_capture *cap, int dir, uint16_t sid, int code,
                        int is_request, const void *hdr, uint32_t hdrlen,
                        const void *body, uint32_t blen);
void brix_capture_close(struct brix_capture *cap);
/* Offline: decode a .xrdcap to `out` (no server). verbose≥1 adds a body hexdump. */
int brix_capture_replay(const char *path, int verbose, FILE *out, brix_status *st);
/* Live: re-issue every captured REQUEST frame against `url`, reporting each
 * response status to `out`. 0 / -1 (st set). */
int brix_capture_playback(const char *path, const char *url, const brix_opts *co,
                          FILE *out, brix_status *st);

/* ---- http.c (xrddiag observability pulls) ---- */
/* Minimal cleartext HTTP/1.0 GET: connect host:port, GET path, copy the response
 * body binary-safe into out[outsz] (NUL-terminated for text callers), set
 * *http_status and (if outlen != NULL) the copied body length. 0 / -1 (st set). */
int brix_http_get(const char *host, int port, const char *path, int timeout_ms,
                  int *http_status, char *out, size_t outsz, size_t *outlen,
                  brix_status *st);

/* ---- trace.c (§15 diagnostics) ---- */
const char *brix_reqid_name(int reqid);     /* requestid → "kXR_stat" etc. */
const char *brix_status_name(int status);   /* response status → "ok"/"redirect"/… */
uint64_t    brix_mono_ns(void);             /* CLOCK_MONOTONIC nanoseconds */
/* Phase 40 (a): pseudo-random value in [0, span_ms) for backoff jitter on the
 * synchronous retry/kXR_wait paths (thundering-herd defense). Lazily seeded from
 * brix_mono_ns; a leaf helper with no aio/thread dependency. */
unsigned    brix_jitter_ms(unsigned span_ms);
/* Emit one decoded frame line to stderr (dir '>'=request '<'=response). At
 * c->diag.wire_trace>=2 a bounded hexdump of body[0..blen) follows. */
void        brix_trace_frame(brix_conn *c, int dir, uint16_t sid, int code,
                             int is_request, uint32_t dlen,
                             const void *body, uint32_t blen);
/* Print the accumulated per-opcode RTT summary (if any) to stderr. */
void        brix_timing_report(const brix_conn *c);

/* ---- frame.c ---- */
/* Assign a fresh streamid into hdr[0..1] and write dlen into hdr[20..23] (the
 * caller has already filled requestid + the 16-byte body). Sends header+payload. */
int brix_send(brix_conn *c, void *hdr24, const void *payload, uint32_t plen,
              uint16_t *out_sid, brix_status *st);
/* As brix_send, but the wire dlen (hdr[20..23], also the sigver-signed span)
 * may be smaller than send_len, the payload bytes actually written.  Needed by
 * kXR_writev, whose dlen frames only the 16-byte descriptor block while the
 * segment data streams after the frame (stock XrdXrootdProtocol::do_WriteV).
 * brix_send == brix_send_ext with dlen == send_len. */
int brix_send_ext(brix_conn *c, void *hdr24, const void *payload,
                  uint32_t send_len, uint32_t dlen, uint16_t *out_sid,
                  brix_status *st);
/* Read one response frame for streamid want_sid. Returns 0 with *status set and a
 * malloc'd body/blen (caller frees) for kXR_ok/oksofar/authmore AND kXR_redirect/
 * kXR_wait (so the roundtrip wrapper can act on them). Returns -1 on kXR_error
 * (st filled from errnum+errmsg) or any other status / transport fault. */
int brix_recv(brix_conn *c, uint16_t want_sid, uint16_t *status,
              uint8_t **body, uint32_t *blen, brix_status *st);

/* Send a request and read its reply, transparently following kXR_redirect
 * (reconnect+replay, bounded by XRDC_REDIR_MAX + a visited-set loop guard) and
 * honoring kXR_wait (sleep+resend). Use this for path-based ops so cluster
 * redirectors work. hdr24 is re-stamped (streamid/dlen) on each attempt. Returns 0
 * with *status = kXR_ok/oksofar + body/blen; -1 (st set) on error. */
int brix_roundtrip(brix_conn *c, void *hdr24, const void *payload, uint32_t plen,
                   uint16_t *status, uint8_t **body, uint32_t *blen,
                   brix_status *st);

/* ---- conn.c ---- */
/* connect → handshake → [TLS upgrade] → kXR_protocol → kXR_login → [auth].
 * opts may be NULL (anonymous, no TLS). */
int  brix_connect(brix_conn *c, const brix_url *u, const brix_opts *o,
                  brix_status *st);
/* Tear down the current transport and re-establish the full session (handshake →
 * [TLS] → login → auth) against host:port, preserving the stored opts/creds. Used
 * by the redirect follower. 0 / -1. */
int  brix_reconnect(brix_conn *c, const char *host, int port, brix_status *st);
void brix_close(brix_conn *c);

/* ---- pool.c — thread-safe pool of connections for concurrent callers ---- */
/* An brix_conn is one-request-in-flight and NOT thread-safe; a multi-threaded
 * consumer (e.g. the FUSE driver) checks out an independent connected conn per
 * operation. The struct is opaque; callers hold only the handle. */
typedef struct brix_pool brix_pool;
/* Create a pool of `n` connections to `u` (opts `o`, may be NULL). Connects one
 * eagerly so a bad endpoint/auth fails up front; the rest connect on demand.
 * Returns NULL + sets st on failure. */
brix_pool *brix_pool_create(const brix_url *u, const brix_opts *o, int n,
                            brix_status *st);
/* Borrow a connected conn, blocking until one is free; reconnects a dropped slot
 * transparently. Returns NULL + sets st only if (re)connect fails. */
brix_conn *brix_pool_checkout(brix_pool *p, brix_status *st);
/* Return a checked-out conn. healthy==0 (the op hit a connection-level error,
 * i.e. st->kxr == XRDC_ESOCK/XRDC_EPROTO) drops the conn so the next checkout
 * reconnects on a clean session. */
void       brix_pool_checkin(brix_pool *p, brix_conn *c, int healthy);
void       brix_pool_destroy(brix_pool *p);
/* Establish a secondary data stream bound to `primary`'s session: handshake +
 * kXR_protocol [+ TLS] then kXR_bind{primary->sessid}, skipping kXR_login (the
 * server inherits identity from the primary). `sec` is fully initialised here.
 * Tear it down with brix_streams_close (no endsess). 0 / -1. */
int  brix_bind(brix_conn *sec, const brix_conn *primary, brix_status *st);

/* ---- streams.c (M8 parallel streams) ---- */
#define XRDC_MAX_STREAMS 16
typedef struct {
    int       n;                              /* secondaries actually bound */
    brix_conn sec[XRDC_MAX_STREAMS - 1];
} brix_streamset;
/* Best-effort: bind up to (streams-1) secondaries to `primary` (capped at
 * XRDC_MAX_STREAMS-1). Never fails the caller — returns the number bound; a
 * secondary that won't bind is simply skipped. */
int  brix_streams_open(brix_streamset *ss, brix_conn *primary, int streams,
                       brix_status *st);
void brix_streams_close(brix_streamset *ss);

#endif /* XRDC_NET_H */
