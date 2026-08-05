/*
 * ftp_data.c — GridFTP client data channel: passive open, RETR, STOR, listings.
 *
 * WHAT: negotiate a passive data connection (EPSV, falling back to PASV), then
 *       run exactly one transfer over it in stream mode with the control channel
 *       supplying the preliminary (1xx) and completion (2xx) replies.
 * WHY:  stream mode over a passive connection is the one shape every GridFTP
 *       server supports, including the phase-82 gateway; extended block mode buys
 *       parallelism this client does not yet need and costs a second framing
 *       layer. Keeping open/pump/finish here means the transfer contract (never
 *       report success before the server's 226) lives in one place.
 * HOW:  the passive replies are decoded by the pure kernels gftp_reply_parse_epsv
 *       / gftp_reply_parse_pasv and screened by ftp_screen.c before any socket is
 *       dialled. Payload bytes move through caller-supplied sink/source adapters
 *       so the same pump serves a file, a listing buffer, or a progress-reporting
 *       copy. No goto: each step returns early and closes what it opened.
 */
#include "ftp_client.h"

#include "fs/backend/gsiftp/gftp_reply.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Decode the passive reply currently in `s` into an address + port candidate. */
static int
ftp_passive_target(brix_ftp_sess *s, char *ip, size_t ipsz, unsigned *port,
                   brix_status *st)
{
    size_t tlen = strlen(s->text);

    if (s->code == 229) {
        if (gftp_reply_parse_epsv(s->text, tlen, port) != 0) {
            brix_status_set(st, XRDC_EPROTO, 0, "gsiftp: malformed EPSV reply");
            return -1;
        }
        snprintf(ip, ipsz, "%s", s->peer_ip);   /* EPSV inherits the peer */
        return 0;
    }
    {
        unsigned char a[4];

        if (gftp_reply_parse_pasv(s->text, tlen, a, port) != 0) {
            brix_status_set(st, XRDC_EPROTO, 0, "gsiftp: malformed PASV reply");
            return -1;
        }
        snprintf(ip, ipsz, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
    }
    return 0;
}


int
brix_ftp_data_open(brix_ftp_sess *s, int *dfd, brix_status *st)
{
    char        ip[64];
    unsigned    port = 0;
    const char *env = getenv("BRIX_GSIFTP_ALLOW_OFFPEER");
    int         allow_offpeer = (env != NULL && env[0] == '1');

    *dfd = -1;
    if (brix_ftp_cmd(s, st, "EPSV") != 0) {
        return -1;
    }
    if (s->code != 229) {
        if (brix_ftp_cmd(s, st, "PASV") != 0) {
            return -1;
        }
        if (s->code != 227) {
            brix_status_set(st, XRDC_EPROTO, 0,
                            "gsiftp: passive mode refused: %d %s", s->code,
                            s->text);
            return -1;
        }
    }
    if (ftp_passive_target(s, ip, sizeof(ip), &port, st) != 0) {
        return -1;
    }
    if (!brix_ftp_data_addr_ok(s->peer_ip, ip, port, allow_offpeer)) {
        /* The port is the hard gate — a passive data port below 1024 is a bounce
         * attempt, never a real transfer. An off-peer *address* is merely
         * ignored: we dial the control peer instead (curl's
         * --ftp-skip-pasv-ip behaviour), which also keeps NAT'd servers working. */
        if (!brix_ftp_data_addr_ok(s->peer_ip, s->peer_ip, port, 0)) {
            brix_status_set(st, XRDC_EPROTO, 0,
                            "gsiftp: refusing data channel to port %u", port);
            return -1;
        }
        snprintf(ip, sizeof(ip), "%s", s->peer_ip);
    }

    *dfd = brix_tcp_connect(ip, (int) port, s->timeout_ms, st);
    if (*dfd < 0) {
        return -1;
    }
    return 0;
}


/* Await the preliminary reply that opens a transfer (150/125). */
static int
ftp_await_preliminary(brix_ftp_sess *s, brix_status *st)
{
    if (s->code >= 100 && s->code < 200) {
        return 0;
    }
    brix_status_set(st, (s->code == 550) ? XRDC_ENOENT : XRDC_EPROTO, 0,
                    "gsiftp: %d %s", s->code, s->text);
    return -1;
}


/* Await the completion reply that ends a transfer (226/250). */
static int
ftp_await_completion(brix_ftp_sess *s, brix_status *st)
{
    if (brix_ftp_read_reply(s, st) != 0) {
        return -1;
    }
    if (s->code >= 200 && s->code < 300) {
        return 0;
    }
    brix_status_set(st, XRDC_EIO, 0, "gsiftp: transfer failed: %d %s", s->code,
                    s->text);
    return -1;
}


static void
ftp_report(const brix_copy_opts *o, int64_t done, int64_t total)
{
    if (o != NULL && o->progress != NULL) {
        o->progress(o->progress_arg, (long long) done, (long long) total);
    }
}


/*
 * Open the data channel, issue one transfer verb, take the preliminary reply and
 * hand back the connected socket plus a transfer buffer. On failure everything it
 * opened is released and the caller returns straight away. 0 / -1 (st set).
 */
static int
ftp_xfer_begin(brix_ftp_sess *s, const char *verb, const char *path, int *dfd,
               uint8_t **buf, brix_status *st)
{
    *dfd = -1;
    *buf = NULL;
    if (brix_ftp_data_open(s, dfd, st) != 0) {
        return -1;
    }
    if (brix_ftp_cmd(s, st, "%s %s", verb, path) != 0
        || ftp_await_preliminary(s, st) != 0) {
        close(*dfd);
        return -1;
    }
    *buf = malloc(BRIX_FTP_DATA_CHUNK);
    if (*buf == NULL) {
        close(*dfd);
        brix_status_set(st, XRDC_EIO, 0, "gsiftp: out of memory");
        return -1;
    }
    return 0;
}


/* 1 when the user asked to stop (^C) — checked once per chunk in both pumps. */
static int
ftp_cancelled(brix_status *st)
{
    if (!brix_copy_quit_requested()) {
        return 0;
    }
    brix_status_set(st, XRDC_EIO, EINTR, "gsiftp: transfer cancelled");
    return 1;
}


/* One chunk of work in whichever direction the transfer runs: bytes moved, 0 at
 * end of transfer, -1 on failure (st set). */
typedef struct {
    brix_ftp_sink_fn sink;   /* RETR: socket → caller                          */
    brix_ftp_src_fn  src;    /* STOR: caller → socket                          */
    void            *ctx;
} ftp_pump;

typedef ssize_t (*ftp_chunk_fn)(brix_ftp_sess *s, int dfd, uint8_t *buf,
                                const ftp_pump *p, brix_status *st);

static ssize_t
ftp_chunk_in(brix_ftp_sess *s, int dfd, uint8_t *buf, const ftp_pump *p,
             brix_status *st)
{
    ssize_t n = brix_ftp_io_read(dfd, buf, BRIX_FTP_DATA_CHUNK, s->timeout_ms,
                                 st);

    if (n <= 0) {
        return n;
    }
    if (p->sink(p->ctx, buf, (size_t) n, st) != 0) {
        return -1;
    }
    return n;
}


static ssize_t
ftp_chunk_out(brix_ftp_sess *s, int dfd, uint8_t *buf, const ftp_pump *p,
              brix_status *st)
{
    ssize_t n = p->src(p->ctx, buf, BRIX_FTP_DATA_CHUNK, st);

    if (n <= 0) {
        return n;
    }
    if (brix_ftp_io_write_all(dfd, buf, (size_t) n, s->timeout_ms, st) != 0) {
        return -1;
    }
    return n;
}


/*
 * Run one whole transfer: open the channel, issue `verb`, pump chunks until the
 * stream ends, then take the server's completion reply. `half_close` marks the
 * outbound direction, where the FIN is the end-of-file marker and must reach the
 * server before we wait for its 226.
 */
static int
ftp_xfer(brix_ftp_sess *s, const char *verb, const char *path,
         ftp_chunk_fn chunk, const ftp_pump *pump, const brix_copy_opts *o,
         int64_t total, int half_close, brix_status *st)
{
    uint8_t *buf;
    int64_t  done = 0;
    int      dfd;
    int      rc = 0;

    if (ftp_xfer_begin(s, verb, path, &dfd, &buf, st) != 0) {
        return -1;
    }
    for (;;) {
        ssize_t n;

        if (ftp_cancelled(st)) {
            rc = -1;
            break;
        }
        n = chunk(s, dfd, buf, pump, st);
        if (n < 0) {
            rc = -1;
            break;
        }
        if (n == 0) {
            break;
        }
        done += n;
        ftp_report(o, done, total);
    }
    free(buf);
    if (half_close) {
        (void) shutdown(dfd, SHUT_WR);
    }
    close(dfd);
    if (rc != 0) {
        return -1;
    }
    return ftp_await_completion(s, st);
}


int
brix_ftp_retr(brix_ftp_sess *s, const char *path, brix_ftp_sink_fn sink,
              void *ctx, const brix_copy_opts *o, int64_t total,
              brix_status *st)
{
    ftp_pump pump = { sink, NULL, ctx };

    return ftp_xfer(s, "RETR", path, ftp_chunk_in, &pump, o, total, 0, st);
}


int
brix_ftp_stor(brix_ftp_sess *s, const char *path, brix_ftp_src_fn src,
              void *ctx, const brix_copy_opts *o, int64_t total,
              brix_status *st)
{
    ftp_pump pump = { NULL, src, ctx };

    return ftp_xfer(s, "STOR", path, ftp_chunk_out, &pump, o, total, 1, st);
}


int
brix_ftp_data_slurp(brix_ftp_sess *s, const char *cmd, char **out,
                    size_t *out_len, brix_status *st)
{
    char   *acc = NULL;
    size_t  len = 0;
    uint8_t buf[8192];
    int     dfd = -1;
    int     rc = 0;

    *out = NULL;
    *out_len = 0;
    if (brix_ftp_data_open(s, &dfd, st) != 0) {
        return -1;
    }
    if (brix_ftp_cmd(s, st, "%s", cmd) != 0
        || ftp_await_preliminary(s, st) != 0) {
        close(dfd);
        return -1;
    }
    for (;;) {
        ssize_t n = brix_ftp_io_read(dfd, buf, sizeof(buf), s->timeout_ms, st);
        char   *bigger;

        if (n < 0) {
            rc = -1;
            break;
        }
        if (n == 0) {
            break;
        }
        bigger = realloc(acc, len + (size_t) n + 1);
        if (bigger == NULL) {
            brix_status_set(st, XRDC_EIO, 0, "gsiftp: out of memory");
            rc = -1;
            break;
        }
        acc = bigger;
        memcpy(acc + len, buf, (size_t) n);
        len += (size_t) n;
        acc[len] = '\0';
    }
    close(dfd);
    if (rc != 0) {
        free(acc);
        return -1;
    }
    if (ftp_await_completion(s, st) != 0) {
        free(acc);
        return -1;
    }
    if (acc == NULL) {
        acc = calloc(1, 1);
        if (acc == NULL) {
            brix_status_set(st, XRDC_EIO, 0, "gsiftp: out of memory");
            return -1;
        }
    }
    *out = acc;
    *out_len = len;
    return 0;
}
