/*
 * ftp_ops.c — GridFTP client session setup and metadata queries.
 *
 * WHAT: bring a control session from "connected" to "ready to transfer", and
 *       answer the one metadata question a copy needs — size and modification
 *       time of a remote path.
 * WHY:  the negotiation preamble (protection buffer size, data-channel
 *       protection, authentication of the data channel, binary type) is fixed
 *       boilerplate every transfer needs and no caller should repeat; and --sync
 *       needs remote metadata through the same session machinery the copy uses.
 * HOW:  PBSZ/PROT/DCAU are advisory — a server that rejects them still transfers,
 *       so their replies are tolerated, while TYPE I is mandatory (a text-mode
 *       transfer would corrupt data). Metadata comes from SIZE and MDTM (RFC 3659
 *       §4/§3), and the MDTM timestamp is converted by the MLSx kernel, which
 *       already implements the timezone-free `modify=` conversion — MLST itself is
 *       unusable here because its payload is a multiline block the reply contract
 *       does not expose.
 */
#include "ftp_client.h"

#include "fs/backend/gsiftp/gftp_mlsx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
brix_ftp_session_open(brix_ftp_sess *s, const brix_ftpurl *u,
                      const brix_opts *co, brix_status *st)
{
    int timeout_ms = (co != NULL && co->max_stall_ms > 0) ? co->max_stall_ms
                                                          : 60000;

    if (brix_ftp_connect(s, u->host, u->port, timeout_ms, st) != 0) {
        return -1;
    }
    if (brix_ftp_login(s, u, co, st) != 0) {
        brix_ftp_close(s);
        return -1;
    }
    if (s->secure) {
        /* Clear-text data channel with an authenticated control channel: the
         * gateway's default, and what globus-url-copy negotiates without -dcpriv.
         * Advisory — a refusal does not stop the transfer. */
        (void) brix_ftp_cmd(s, st, "PBSZ 0");
        (void) brix_ftp_cmd(s, st, "PROT C");
        (void) brix_ftp_cmd(s, st, "DCAU N");
    }
    if (brix_ftp_cmd_expect(s, 200, 299, st, "TYPE I") != 0) {
        brix_ftp_close(s);
        return -1;
    }
    return 0;
}


/* Parse a "213 <digits>" SIZE reply. */
static int
parse_size(const char *text, int64_t *size)
{
    char       *end = NULL;
    long long   v;
    const char *p = text;

    while (*p == ' ') {
        p++;
    }
    v = strtoll(p, &end, 10);
    if (end == p || v < 0) {
        return -1;
    }
    *size = (int64_t) v;
    return 0;
}


/*
 * Convert a "213 YYYYMMDDHHMMSS[.frac]" MDTM reply to an epoch time by handing it
 * to the MLSx fact parser: MDTM's value and MLSx's `modify=` fact are the same
 * production (RFC 3659 §2.3), so the conversion exists once, in one kernel.
 */
static int
parse_mdtm(const char *text, int64_t *mtime)
{
    char          line[96];
    gftp_mlsx_ent_t ent;
    const char   *p = text;
    size_t        n = 0;

    while (*p == ' ') {
        p++;
    }
    while (p[n] != '\0' && p[n] != ' ' && p[n] != '\r' && n < 32) {
        n++;
    }
    if (n < 14) {
        return -1;
    }
    if (snprintf(line, sizeof(line), "modify=%.*s; x", (int) n, p)
        >= (int) sizeof(line)) {
        return -1;
    }
    if (gftp_mlsx_parse(line, strlen(line), &ent) != 0 || !ent.has_mtime) {
        return -1;
    }
    *mtime = (int64_t) ent.mtime;
    return 0;
}


int
brix_ftp_stat(brix_ftp_sess *s, const char *path, int64_t *size,
              int64_t *mtime, brix_status *st)
{
    if (size != NULL) {
        *size = -1;
    }
    if (mtime != NULL) {
        *mtime = -1;
    }
    if (brix_ftp_cmd(s, st, "SIZE %s", path) != 0) {
        return -1;
    }
    if (s->code == 550) {
        brix_status_set(st, XRDC_ENOENT, 0, "gsiftp: %s: no such file", path);
        return -1;
    }
    if (s->code == 213 && size != NULL && parse_size(s->text, size) != 0) {
        *size = -1;
    }
    if (brix_ftp_cmd(s, st, "MDTM %s", path) != 0) {
        return -1;
    }
    if (s->code == 213 && mtime != NULL && parse_mdtm(s->text, mtime) != 0) {
        *mtime = -1;
    }
    return 0;
}


int
brix_ftp_url_stat(const char *url, const brix_opts *co, int64_t *size,
                  int64_t *mtime, brix_status *st)
{
    brix_ftpurl    u;
    brix_ftp_sess *s;
    int            rc;

    if (brix_ftpurl_parse(url, &u) != 0) {
        brix_status_set(st, XRDC_EUSAGE, 0, "gsiftp: bad URL: %s", url);
        return -1;
    }
    s = calloc(1, sizeof(*s));      /* the session carries 64 KiB of buffers */
    if (s == NULL) {
        brix_status_set(st, XRDC_EIO, 0, "gsiftp: out of memory");
        return -1;
    }
    if (brix_ftp_session_open(s, &u, co, st) != 0) {
        free(s);
        return -1;
    }
    rc = brix_ftp_stat(s, u.path, size, mtime, st);
    brix_ftp_close(s);
    free(s);
    return rc;
}
