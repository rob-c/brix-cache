/*
 * gftp_data.c — GridFTP data transfers for the blocking storage driver.
 *
 * WHAT: RETR / STOR / listing over a data connection, in either transfer mode.
 *
 * WHY:  MODE S (RFC 959) is the interoperable floor and stays the default; MODE
 * E (GFD.020 §3.4) is what production GridFTP endpoints negotiate, and the store
 * line selects it per origin.  Mode selection lives here, at the one place that
 * knows what a given command needs: a data transfer honours the store line, a
 * LISTING is always a plain stream (MLSD carries no block structure, and asking
 * for MODE E around it only creates a way for the two ends to disagree).
 *
 * HOW:  gftp_dc.h owns the connection (including PROT P); gftp_mode_e.h owns
 * extended-block framing.  This file negotiates MODE once per change, opens the
 * connection, issues the command, and dispatches to the stream or block path.
 */

#include "gftp_client.h"
#include "gftp_dc.h"
#include "gftp_mode_e.h"
#include "gftp_feat.h"
#include "gftp_spas.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GFTP_DATA_CHUNK 65536
#define GFTP_SLURP_MAX  (16u * 1024u * 1024u)

/* One retrieve request, bundled so the two mode paths share a signature. */
typedef struct {
    off_t        offset;
    size_t       limit;
    gftp_sink_fn sink;
    void        *ctx;
    size_t       received;
} gftp_get_t;


/* Put the wire in `want`, if it is not already there.  MODE is sticky for the
 * session, so a listing between two MODE E reads costs two commands, not one
 * per transfer. */
static int
gftp_set_mode(gftp_session_t *session, gftp_dmode_t want)
{
    char letter = (want == GFTP_DMODE_E) ? 'E' : 'S';

    if (session->mode == want) {
        return 0;
    }
    if (gftp_expect(session, 200, 299, "MODE %c", letter) != 0) {
        gftp_set_error(session, EPROTO,
            "GridFTP origin refused MODE %c", letter);
        return -1;
    }
    session->mode = want;
    return 0;
}


/* Issue a transfer command on an ALREADY-OPEN data channel and check that the
 * origin accepted it (a 1xx preliminary reply).  Split from the open so the
 * retrieve path can put a whole striped GROUP behind one command. */
static int
gftp_transfer_command(gftp_session_t *session, const char *command)
{
    if (gftp_command(session, "%s", command) != 0
        || session->code < 100 || session->code >= 200) {
        gftp_set_error(session, session->code == 550 ? ENOENT : EIO,
            "GridFTP transfer was refused: %d", session->code);
        return -1;
    }
    return 0;
}


/* Dial, command, THEN handshake — the order is load-bearing, see
 * gftp_dc_secure(). */
static int
gftp_transfer_begin(gftp_session_t *session, const char *command,
    gftp_dc_t *dc)
{
    if (gftp_dc_open(session, dc) != 0) {
        return -1;
    }
    if (gftp_transfer_command(session, command) != 0) {
        gftp_dc_close(dc);
        return -1;
    }
    return gftp_dc_secure(session, dc);
}


static int
gftp_transfer_finish(gftp_session_t *session)
{
    if (gftp_read_reply(session) != 0) {
        return -1;
    }
    if (session->code >= 200 && session->code < 300) {
        return 0;
    }
    gftp_set_error(session, EIO, "GridFTP transfer failed: %d %s",
        session->code, session->text);
    return -1;
}


/* MODE S: one ordered byte stream; the sink's offset is our own running count.
 * Always one connection — striping needs the per-block offsets only MODE E
 * carries, so gftp_dc_group_open() never opens a second one in stream mode. */
static int
gftp_retrieve_stream(gftp_session_t *session, gftp_dc_t *dc, gftp_get_t *g)
{
    uint8_t buffer[GFTP_DATA_CHUNK];
    size_t  total = 0;

    while (total < g->limit) {
        size_t  want = g->limit - total;
        ssize_t n;

        if (want > sizeof(buffer)) {
            want = sizeof(buffer);
        }
        n = gftp_dc_read(session, dc, buffer, want);
        if (n < 0
            || (n > 0 && g->sink(g->ctx, (off_t) total, buffer,
                                 (size_t) n) != 0))
        {
            return -1;
        }
        if (n == 0) {
            g->received = total;
            return 1;                    /* peer closed: read the final reply */
        }
        total += (size_t) n;
    }
    g->received = total;
    return 0;
}


/* MODE E: offset-addressed blocks, terminated by EOD/EOF rather than by close. */
static int
gftp_retrieve_eblock(gftp_session_t *session, gftp_dc_group_t *group,
    gftp_get_t *g, int bounded)
{
    gftp_mode_e_req_t req;

    memset(&req, 0, sizeof(req));
    req.conns   = group->conns;
    req.nconns  = group->n;
    req.start   = g->offset;
    req.limit   = (uint64_t) g->limit;
    req.sink    = g->sink;
    req.ctx     = g->ctx;
    req.bounded = bounded;
    if (gftp_mode_e_receive(session, &req) != 0) {
        return -1;
    }
    g->received = (size_t) req.received;
    /* 1 = the block stream ended on its own EOF, so the origin has finished and
     * its completion reply is already on the control channel.  0 = the window
     * edge was reached first and the origin is still sending: the caller closes
     * the data connection and asks for no reply, exactly as MODE S does. */
    return req.stopped_early ? 0 : 1;
}


/* Whether this retrieve should be expressed as ERET P rather than REST+RETR.
 *
 * ERET P (GFD.020 §5.3) is the one retrieve command that carries the WINDOW —
 * offset AND length — so the origin stops at its end instead of streaming the
 * whole tail this driver would otherwise abandon mid-push.  On a 256-byte range
 * of a 10 GB file that is the difference between the origin reading 256 bytes
 * and reading 10 GB into a socket nobody is draining.
 *
 * MODE E only, and that is a SAFETY rule rather than a taste one.  A door that
 * answers ERET with a plain whole-file push hands back bytes from offset 0; in
 * MODE S those bytes are indistinguishable from the ones that were asked for,
 * so the sink would take the HEAD of the file as its MIDDLE and the corruption
 * would be silent.  MODE E blocks carry their absolute offset, and the receiver
 * already refuses any block outside the requested window (gftp_mode_e.c) — so
 * MODE E is the only place a lie of this shape is caught rather than believed.
 */
static int
gftp_eret_wanted(gftp_session_t *session, const gftp_get_t *g)
{
    if (session->mode != GFTP_DMODE_E || g->limit == 0) {
        return 0;
    }
    return (gftp_feat(session) & GFTP_FEAT_ERET) != 0;
}


/* Start an ERET P transfer.  0 = open, 1 = origin refused the command and the
 * RFC 959 path should be tried, -1 = fatal. */
static int
gftp_retrieve_eret(gftp_session_t *session, const char *path,
    const gftp_get_t *g, gftp_dc_group_t *group)
{
    char command[GFTP_COMMAND_CAP];

    if (snprintf(command, sizeof(command), "ERET P %lld %llu %s",
                 (long long) g->offset, (unsigned long long) g->limit, path)
        >= (int) sizeof(command))
    {
        gftp_set_error(session, EOVERFLOW, "GridFTP path exceeds limit");
        return -1;
    }
    if (gftp_dc_group_open(session, group) != 0) {
        return -1;
    }
    if (gftp_command(session, "%s", command) != 0) {
        gftp_dc_group_close(group);
        return -1;
    }
    if (session->code >= 100 && session->code < 200) {
        return gftp_dc_group_secure(session, group) == 0 ? 0 : -1;
    }
    gftp_dc_group_close(group);
    if (session->code == 550) {
        gftp_set_error(session, ENOENT,
            "GridFTP transfer was refused: %d", session->code);
        return -1;                      /* the FILE is the problem, not ERET */
    }
    /* Advertised, then refused.  Doors exist that list ERET in FEAT and
     * implement only retrieve-modes this driver never sends; the refusal
     * arrives with the control channel clean and not one byte transferred, so
     * the RFC 959 path is still open — and it is POSITIONED (REST first), never
     * a bare RETR that would start at zero.  Do not ask this session again. */
    session->feat &= ~GFTP_FEAT_ERET;
    return 1;
}


/* Start an RFC 959 transfer, positioned with REST when the window does not
 * start at zero. */
static int
gftp_retrieve_positioned(gftp_session_t *session, const char *path,
    const gftp_get_t *g, gftp_dc_group_t *group)
{
    char command[GFTP_COMMAND_CAP];

    if (g->offset > 0
        && gftp_expect(session, 300, 399, "REST %lld",
                       (long long) g->offset) != 0)
    {
        return -1;
    }
    if (snprintf(command, sizeof(command), "RETR %s", path)
        >= (int) sizeof(command))
    {
        gftp_set_error(session, EOVERFLOW, "GridFTP path exceeds limit");
        return -1;
    }
    if (gftp_dc_group_open(session, group) != 0) {
        return -1;
    }
    if (gftp_transfer_command(session, command) != 0) {
        gftp_dc_group_close(group);
        return -1;
    }
    return gftp_dc_group_secure(session, group);
}


int
gftp_retrieve(gftp_session_t *session, const char *path, off_t offset,
    size_t limit, gftp_sink_fn sink, void *ctx, size_t *received)
{
    gftp_get_t      g;
    gftp_dc_group_t group;
    int             bounded;
    int             rc;

    *received = 0;
    memset(&g, 0, sizeof(g));
    g.offset = offset;
    g.limit  = limit;
    g.sink   = sink;
    g.ctx    = ctx;

    if (gftp_set_mode(session, session->want_mode) != 0) {
        return -1;
    }
    rc = gftp_eret_wanted(session, &g)
        ? gftp_retrieve_eret(session, path, &g, &group)
        : 1;
    /* ERET P is the ONLY retrieve command that names the length, so it is the
     * only one after which a block past the window end is the origin's fault. */
    bounded = (rc == 0);
    if (rc > 0) {
        rc = gftp_retrieve_positioned(session, path, &g, &group);
    }
    if (rc != 0) {
        return -1;
    }
    rc = (session->mode == GFTP_DMODE_E)
        ? gftp_retrieve_eblock(session, &group, &g, bounded)
        : gftp_retrieve_stream(session, &group.conns[0], &g);
    gftp_dc_group_close(&group);
    if (rc < 0) {
        return -1;
    }
    *received = g.received;
    return (rc == 1) ? gftp_transfer_finish(session) : 0;
}


int
gftp_store(gftp_session_t *session, const char *path, gftp_source_fn source,
    void *ctx)
{
    uint8_t   buffer[GFTP_DATA_CHUNK];
    gftp_dc_t dc;
    char      command[GFTP_COMMAND_CAP];
    int       rc = 0;

    if (gftp_set_mode(session, session->want_mode) != 0) {
        return -1;
    }
    if (snprintf(command, sizeof(command), "STOR %s", path)
        >= (int) sizeof(command)) {
        gftp_set_error(session, EOVERFLOW, "GridFTP path exceeds limit");
        return -1;
    }
    if (gftp_transfer_begin(session, command, &dc) != 0) {
        return -1;
    }
    if (session->mode == GFTP_DMODE_E) {
        rc = gftp_mode_e_send(session, &dc, source, ctx);
    } else {
        for (;;) {
            ssize_t n = source(ctx, buffer, sizeof(buffer));

            if (n < 0 || (n > 0 && gftp_dc_write_all(session, &dc, buffer,
                                                     (size_t) n) != 0)) {
                rc = -1;
                break;
            }
            if (n == 0) {
                break;
            }
        }
    }
    if (rc == 0) {
        gftp_dc_finish_write(&dc);
    }
    gftp_dc_close(&dc);
    return (rc == 0) ? gftp_transfer_finish(session) : -1;
}


static int
gftp_slurp_append(gftp_session_t *session, char **data, size_t *used,
    const uint8_t *part, size_t len)
{
    char *larger;

    if (len > GFTP_SLURP_MAX - *used) {
        gftp_set_error(session, EOVERFLOW, "GridFTP listing exceeds limit");
        return -1;
    }
    larger = realloc(*data, *used + len + 1);
    if (larger == NULL) {
        gftp_set_error(session, ENOMEM, "cannot allocate GridFTP listing");
        return -1;
    }
    memcpy(larger + *used, part, len);
    *used += len;
    larger[*used] = '\0';
    *data = larger;
    return 0;
}


int
gftp_slurp(gftp_session_t *session, const char *command, char **out,
    size_t *out_len)
{
    uint8_t   buffer[8192];
    gftp_dc_t dc;
    char     *data = NULL;
    size_t    used = 0;

    *out = NULL;
    *out_len = 0;
    /* A listing is always a plain stream: MLSD/NLST carry no block structure. */
    if (gftp_set_mode(session, GFTP_DMODE_S) != 0
        || gftp_transfer_begin(session, command, &dc) != 0) {
        return -1;
    }
    for (;;) {
        ssize_t n = gftp_dc_read(session, &dc, buffer, sizeof(buffer));

        if (n < 0 || (n > 0 && gftp_slurp_append(session, &data, &used,
                                                  buffer, (size_t) n) != 0)) {
            free(data);
            gftp_dc_close(&dc);
            return -1;
        }
        if (n == 0) {
            break;
        }
    }
    gftp_dc_close(&dc);
    if (gftp_transfer_finish(session) != 0) {
        free(data);
        return -1;
    }
    if (data == NULL) {
        data = calloc(1, 1);
        if (data == NULL) {
            gftp_set_error(session, ENOMEM, "cannot allocate GridFTP listing");
            return -1;
        }
    }
    *out = data;
    *out_len = used;
    return 0;
}
