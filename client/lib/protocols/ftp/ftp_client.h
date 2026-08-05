/*
 * ftp_client.h — private split contract for the client-role GridFTP engine.
 * Not a public API: include only from client/lib/protocols/ftp/ and the xfer
 * sibling that routes gsiftp:// copies (client/lib/xfer/copy_gsiftp.c).
 *
 * WHAT: one blocking gsiftp://(ftp://) control session — dial, RFC 2228 GSI
 *       login, RFC 959/3659 command exchange, and a stream-mode data channel —
 *       expressed over the pure parser kernels in src/fs/backend/gsiftp/.
 * WHY:  phase-82 gave the tree a GridFTP *gateway* (it only ever emits replies);
 *       xrdcp needs the initiator half to move data to and from the grid's
 *       gsiftp endpoints without libglobus. Keeping the session state in one
 *       small struct lets the control, security, and data concerns live in
 *       separate translation units that share no globals.
 * HOW:  brix_ftp_connect() dials and captures the greeting; brix_ftp_login()
 *       negotiates AUTH GSSAPI (or anonymous); brix_ftp_cmd() sends one command
 *       and parses exactly one reply (transparently GSS-wrapping the command and
 *       unwrapping the 63x reply once the security layer is up); the data-channel
 *       helpers open a passive connection and pump one transfer.
 */
#ifndef BRIX_FTP_CLIENT_H
#define BRIX_FTP_CLIENT_H

#include "brix.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Both buffers must hold one whole reply line, and the largest of those is an
 * `ADAT=<base64>` token carrying a TLS flight (server certificate chain) — kilo-
 * bytes, not the hundreds of bytes a plain FTP reply needs. The session is
 * therefore heap-allocated by its owner, never a stack local. */
#define BRIX_FTP_CTL_BUF  32768   /* control receive buffer                    */
#define BRIX_FTP_TEXT_MAX 32768   /* final-line reply text kept per command    */
#define BRIX_FTP_CMD_MAX   4096   /* longest command line we will emit         */
#define BRIX_FTP_DATA_CHUNK (1024u * 1024u)  /* data-channel transfer buffer   */

struct brix_ftp_gss;   /* opaque GSI initiator engine (ftp_gsi.c) */

typedef struct {
    int                  fd;        /* control socket, -1 when closed          */
    int                  timeout_ms;/* per-poll idle budget for control + data */
    size_t               rlen;      /* bytes pending in rbuf                   */
    char                 rbuf[BRIX_FTP_CTL_BUF];
    struct brix_ftp_gss *gss;       /* GSI engine, NULL until AUTH GSSAPI runs */
    int                  secure;    /* 1 ⇒ commands/replies are GSS-wrapped    */
    int                  code;      /* last reply's 3-digit code               */
    char                 text[BRIX_FTP_TEXT_MAX];  /* last final-line text     */
    char                 peer_ip[64];              /* control peer, numeric    */
} brix_ftp_sess;

/* One transfer direction's byte adapter. The sink returns 0/-1 (st set); the
 * source returns bytes produced (0 = end of data) or -1 (st set). */
typedef int (*brix_ftp_sink_fn)(void *ctx, const uint8_t *buf, size_t n,
                                brix_status *st);
typedef ssize_t (*brix_ftp_src_fn)(void *ctx, uint8_t *buf, size_t cap,
                                   brix_status *st);

/* ---- ftp_ctl.c — socket I/O, command send, reply parse ---- */

/* Read once into buf (up to cap). >0 bytes, 0 = peer closed, -1 = error/timeout. */
ssize_t brix_ftp_io_read(int fd, void *buf, size_t cap, int timeout_ms,
                         brix_status *st);
/* Write every byte or fail. 0 / -1. */
int brix_ftp_io_write_all(int fd, const void *buf, size_t n, int timeout_ms,
                          brix_status *st);

/* Dial host:port, record the numeric peer address, and consume the greeting.
 * 0 on a 2xx greeting; -1 otherwise (st set, socket closed). */
int brix_ftp_connect(brix_ftp_sess *s, const char *host, int port,
                     int timeout_ms, brix_status *st);
/* Consume exactly one reply into s->code/s->text, unwrapping the RFC
 * 2228 63x frame when the security layer is active. 0 / -1 (st set). */
int brix_ftp_read_reply(brix_ftp_sess *s, brix_status *st);
/* Send one command line (CRLF appended, wrapped when secure) and read its reply.
 * 0 means "a reply arrived" — the CALLER inspects s->code; -1 is a transport or
 * framing failure (st set). */
int brix_ftp_cmd(brix_ftp_sess *s, brix_status *st, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
/* brix_ftp_cmd + require the reply code to fall in [lo,hi]; -1 (st set) if not. */
int brix_ftp_cmd_expect(brix_ftp_sess *s, int lo, int hi, brix_status *st,
                        const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));
/* Best-effort QUIT + close; always leaves the session closed. */
void brix_ftp_close(brix_ftp_sess *s);

/* ---- ftp_gsi.c — RFC 2228 GSI (GSSAPI) initiator over a mem-BIO TLS 1.2 ---- */

struct brix_ftp_gss *brix_ftp_gss_create(const char *proxy, const char *ca_dir,
                                         int insecure, brix_status *st);
/* Feed one decoded ADAT token; on return *out (malloc'd, caller frees) holds the
 * next token to send. 1 = continue (send *out), 0 = complete, -1 = failed. */
int brix_ftp_gss_step(struct brix_ftp_gss *g, const uint8_t *in, size_t in_len,
                      uint8_t **out, size_t *out_len, brix_status *st);
int brix_ftp_gss_wrap(struct brix_ftp_gss *g, const void *in, size_t in_len,
                      uint8_t **out, size_t *out_len, brix_status *st);
int brix_ftp_gss_unwrap(struct brix_ftp_gss *g, const void *in, size_t in_len,
                        uint8_t **out, size_t *out_len, brix_status *st);
void brix_ftp_gss_free(struct brix_ftp_gss *g);

/* base64 codecs for the ADAT/ENC arguments (malloc'd result, caller frees). */
char    *brix_ftp_b64_encode(const uint8_t *data, size_t len);
uint8_t *brix_ftp_b64_decode(const char *b64, size_t *out_len);

/* ---- ftp_login.c ---- */

/* Negotiate the session credential: AUTH GSSAPI + ADAT (gsiftp://) or anonymous
 * USER/PASS (ftp://). A gsiftp:// endpoint NEVER silently downgrades to
 * anonymous — a missing proxy or a failed handshake is an error. 0 / -1. */
int brix_ftp_login(brix_ftp_sess *s, const brix_ftpurl *u, const brix_opts *co,
                   brix_status *st);

/* ---- ftp_screen.c — pure data-channel address policy (SSRF seam) ---- */

/* 1 when the address a passive reply nominated may be dialled: it must match the
 * control-channel peer (an off-peer address is an FTP-bounce primitive) and name
 * an unprivileged port. allow_offpeer relaxes only the address rule. */
int brix_ftp_data_addr_ok(const char *ctl_ip, const char *data_ip,
                          unsigned port, int allow_offpeer);

/* ---- ftp_data.c ---- */

/* EPSV (RFC 2428), falling back to PASV, then dial the screened address. */
int brix_ftp_data_open(brix_ftp_sess *s, int *dfd, brix_status *st);
/* RETR path → sink. `total` (or -1) drives the progress callback in `o`. */
int brix_ftp_retr(brix_ftp_sess *s, const char *path, brix_ftp_sink_fn sink,
                  void *ctx, const brix_copy_opts *o, int64_t total,
                  brix_status *st);
/* source → STOR path. */
int brix_ftp_stor(brix_ftp_sess *s, const char *path, brix_ftp_src_fn src,
                  void *ctx, const brix_copy_opts *o, int64_t total,
                  brix_status *st);
/* Run one data-channel command whose payload is a text listing, appending every
 * received byte to a malloc'd NUL-terminated buffer (caller frees). 0 / -1. */
int brix_ftp_data_slurp(brix_ftp_sess *s, const char *cmd, char **out,
                        size_t *out_len, brix_status *st);

/* ---- ftp_ops.c ---- */

/* Dial + login + TYPE I. On success the caller owns the session (brix_ftp_close). */
int brix_ftp_session_open(brix_ftp_sess *s, const brix_ftpurl *u,
                          const brix_opts *co, brix_status *st);
/* SIZE + MDTM for one path. Either output is set to -1 when the server does not
 * report it; a missing file is XRDC_ENOENT. 0 / -1 (st set). */
int brix_ftp_stat(brix_ftp_sess *s, const char *path, int64_t *size,
                  int64_t *mtime, brix_status *st);
/* One-shot stat for a gsiftp://ftp:// URL (opens and closes its own session). */
int brix_ftp_url_stat(const char *url, const brix_opts *co, int64_t *size,
                      int64_t *mtime, brix_status *st);

#endif /* BRIX_FTP_CLIENT_H */
