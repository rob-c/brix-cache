/* _brix_net_ext.h — split part 2 of brix_net.h */
#ifndef _BRIX_NET_EXT_H
#define _BRIX_NET_EXT_H
#ifndef XRDC_NET_H
#  include "brix_net.h"
#endif
/* ---- weblist.c — recursive WebDAV listing (for xrdcp -r over davs/http) ---- */
/* PROPFIND Depth:infinity on a WebDAV collection; returns absolute server paths of
 * every FILE beneath it (subdirs excluded). bearer NULL ⇒ anonymous. 0 / -1 (st set).
 * Free *paths with brix_strv_free. */
int  brix_webdav_list(const brix_weburl *u, const char *bearer, int verify,
                      const char *ca_dir, const char *client_cert,
                      char ***paths, size_t *n_out, brix_status *st);
/* MKCOL a WebDAV collection at `path` on the endpoint `u` (for recursive upload).
 * bearer NULL ⇒ anonymous. Idempotent: an already-existing collection (405/301)
 * is treated as success. 0 / -1 (st set). */
int  brix_webdav_mkcol(const brix_weburl *u, const char *path, const char *bearer,
                       int verify, const char *ca_dir, const char *client_cert,
                       brix_status *st);
/* DELETE a WebDAV resource (file or empty collection) at `path`. bearer NULL ⇒
 * anonymous; client_cert = X.509 proxy PEM for mutual TLS (or NULL). NOT
 * idempotent on 404 (a missing target is a reported error). 0 / -1 (st set:
 * 404→ENOENT, 401/403→EAUTH, else EPROTO). */
int  brix_webdav_delete(const brix_weburl *u, const char *path, const char *bearer,
                        int verify, const char *ca_dir, const char *client_cert,
                        brix_status *st);
/* MOVE (rename) the WebDAV resource at `path` to `dest_abs` — an ABSOLUTE URL
 * ("<scheme>://host:port/newpath") per RFC 4918 — with Overwrite: T. bearer/
 * client_cert as for delete. 0 / -1 (st set, mapped like delete). */
int  brix_webdav_move(const brix_weburl *u, const char *path, const char *dest_abs,
                      const char *bearer, int verify, const char *ca_dir,
                      const char *client_cert, brix_status *st);
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
                   int verify, const char *ca_dir, const char *client_cert,
                   brix_statinfo *si, brix_status *st);
/* Directory listing via PROPFIND Depth:1 → child entries with stat (FUSE readdir).
 * Allocates *ents (free with free()); each entry has name + have_stat + st. 0 / -1. */
int  brix_web_readdir(const brix_weburl *u, const char *path, const char *bearer,
                      int verify, const char *ca_dir, const char *client_cert,
                      brix_dirent **ents,
                      size_t *n, brix_status *st);
/* Pooled keep-alive variants (Phase-86): the FUSE driver's getattr/readdir path.
 * `pool` is a brix_cpool of brix_webmeta (one origin+identity per pool); each
 * call reuses a persistent connection instead of connect/close per op. 0 / -1. */
struct brix_cpool;   /* fwd: full type in net/cpool.h */
int  brix_web_stat_pooled(struct brix_cpool *pool, const char *path,
                          brix_statinfo *si, brix_status *st);
int  brix_web_readdir_pooled(struct brix_cpool *pool, const char *path,
                             brix_dirent **ents, size_t *n, brix_status *st);
/* An open-for-read web file whose pread issues a Range GET over a PERSISTENT
 * keep-alive connection (resilient: reconnect + re-issue on a dropped link). */
typedef struct brix_webfile brix_webfile;
/* Open (stats first; fails if a directory). *si_out (optional) gets the stat. */
brix_webfile *brix_webfile_open(const brix_weburl *u, const char *path,
                                const char *bearer, int verify, const char *ca_dir,
                                const char *client_cert,
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
/*
 * brix_xrdrc_default_ms — read a timeout key from the [defaults] section of ~/.xrdrc.
 *
 * WHAT: Returns 1 and sets *out_ms to the parsed value when the [defaults] section
 *       of the user's .xrdrc file carries `key` with a valid positive integer.
 *       Returns 0 when the key is absent, the value is non-numeric, or the value
 *       is <= 0. Supported keys: "connect_timeout_ms", "io_timeout_ms",
 *       "max_stall_ms", "backoff_base_ms".
 * WHY:  Sits in the resolution order below env vars and CLI setters, above the
 *       compiled default: CLI setter > env var > this > compiled default.
 * HOW:  Loads ~/.xrdrc lazily via the same gate as brix_alias_resolve, then looks
 *       up the matching static slot. Invalid / negative values are never stored.
 */
int brix_xrdrc_default_ms(const char *key, int *out_ms);
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
/* Wire framing, connection lifecycle, connection pool and parallel
 * streams — Phase-38 split into brix_net_frame.h to hold this header
 * within the size budget. Included here so every brix_net.h consumer
 * still sees these declarations transparently. */
#include "brix_net_frame.h"
#endif /* _BRIX_NET_EXT_H */
