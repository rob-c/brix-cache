/*
 * ops_meta.c — metadata operations: kXR_stat and kXR_dirlist.
 *
 * WHAT: stat() returns id/size/flags/mtime; dirlist() returns entries, optionally
 *       with per-entry stat (kXR_dstat).
 * WHY:  These back `xrdfs stat` and `xrdfs ls`, and stat also serves xrdcp size
 *       checks later.
 * HOW:  The path is sent as the request payload with dlen=strlen (no trailing NUL
 *       — the server reads exactly dlen bytes). dirlist accumulates kXR_oksofar
 *       chunks until the final kXR_ok; with dstat the body begins with the
 *       ".\n0 0 0 0\n" lead-in followed by name/stat line pairs.
 *
 * wire: XProtocol.hh kXR_stat response — ASCII "<id> <size> <flags> <mtime>".
 * wire: XProtocol.hh kXR_dirlist dstat — ".\n0 0 0 0" prefix, then name\nstat\n pairs.
 */
#include "brix.h"
#include "protocols/root/protocol/stat_line.h"    /* shared stat-line grammar (decode side) */
#include "protocols/root/protocol/dirlist_fmt.h"  /* shared dstat lead-in sentinel */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
parse_statinfo(const char *s, brix_statinfo *out)
{
    brix_statline_ext ext;

    /* The stat-line grammar (mandatory "<id> <size> <flags> <mtime>" + optional
     * EOS "<ctime> <atime> <mode> <owner> <group>" tail) is owned by the shared
     * protocol/stat_line.h so this decoder stays in lockstep with the server's
     * encoder. */
    if (brix_statline_parse(s, &out->id, &out->size, &out->flags, &out->mtime,
                              &ext) != 0) {
        return -1;
    }

    out->have_ext = ext.have_ext;
    out->ctime    = ext.ctime;
    out->atime    = ext.atime;
    out->mode     = ext.mode;
    snprintf(out->owner, sizeof(out->owner), "%s", ext.owner);
    snprintf(out->group, sizeof(out->group), "%s", ext.group);
    return 0;
}

/* Shared core: stat a path with the given kXR_stat options byte (0 = follow
 * symlinks, kXR_statNoFollow = lstat). */
static int
stat_opt(brix_conn *c, const char *path, uint8_t options, brix_statinfo *out,
         brix_status *st)
{
    ClientStatRequest req;
    uint16_t          status;
    uint8_t          *body = NULL;
    uint32_t          blen = 0;
    char              tmp[256];
    uint32_t          n;

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_stat);
    {
        xrdw_stat_req_t b = { .options = options, .wants = 0 };
        xrdw_stat_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }

    if (brix_roundtrip_resilient(c, &req, path, (uint32_t) strlen(path),
                                 XRDC_OP_READONLY, 0,
                                 &status, &body, &blen, st) != 0) {
        return -1;
    }

    n = (blen < sizeof(tmp) - 1) ? blen : (uint32_t) (sizeof(tmp) - 1);
    memcpy(tmp, body, n);
    tmp[n] = '\0';
    free(body);

    if (parse_statinfo(tmp, out) != 0) {
        brix_status_set(st, XRDC_EPROTO, 0, "unparseable stat body: \"%s\"", tmp);
        return -1;
    }
    return 0;
}

int
brix_stat(brix_conn *c, const char *path, brix_statinfo *out, brix_status *st)
{
    return stat_opt(c, path, 0, out, st);
}

int
brix_lstat(brix_conn *c, const char *path, brix_statinfo *out, brix_status *st)
{
    /* kXR_statNoFollow: report a final symlink as itself (kXR_other + target-len
     * size). A server without the vendor extension ignores the bit and follows. */
    return stat_opt(c, path, (uint8_t) kXR_statNoFollow, out, st);
}

/* dirlist */
/* Append n bytes to a growing heap buffer; returns 0 / -1. */
static int
buf_append(uint8_t **buf, size_t *len, size_t *cap, const uint8_t *src, size_t n)
{
    if (*len + n > *cap) {
        size_t   newcap = (*cap == 0) ? 65536 : *cap;
        uint8_t *nb;
        while (*len + n > newcap) {
            newcap *= 2;
        }
        nb = (uint8_t *) realloc(*buf, newcap);
        if (nb == NULL) {
            return -1;
        }
        *buf = nb;
        *cap = newcap;
    }
    memcpy(*buf + *len, src, n);
    *len += n;
    return 0;
}

/* Find the next line within [i, len): a run ending at '\n' or '\0'. Sets *start
 * and *linelen, returns the index just past the terminator, or len if none. The
 * caller stops when it encounters a '\0' terminator (returned via *was_nul). */
static size_t
next_line(const uint8_t *b, size_t len, size_t i, size_t *start, size_t *linelen,
          int *was_nul)
{
    size_t j = i;
    *was_nul = 0;
    while (j < len && b[j] != '\n' && b[j] != '\0') {
        j++;
    }
    *start = i;
    *linelen = j - i;
    if (j < len && b[j] == '\0') {
        *was_nul = 1;
    }
    return (j < len) ? j + 1 : len;
}

static int
dirent_push(brix_dirent **ents, size_t *count, size_t *cap, const brix_dirent *e)
{
    if (*count == *cap) {
        size_t       newcap = (*cap == 0) ? 64 : *cap * 2;
        brix_dirent *na = (brix_dirent *) realloc(*ents, newcap * sizeof(**ents));
        if (na == NULL) {
            return -1;
        }
        *ents = na;
        *cap = newcap;
    }
    (*ents)[*count] = *e;
    (*count)++;
    return 0;
}

/* One full listing pass (a kXR_dirlist roundtrip plus the kXR_oksofar chunk
 * accumulation) on the current connection. On any failure it leaves *ents_out
 * NULL and frees its working buffers, so a resilient retry starts clean. */
static int
dirlist_once(brix_conn *c, const char *path, int want_stat,
             brix_dirent **ents_out, size_t *count_out, brix_status *st)
{
    ClientDirlistRequest req;
    uint16_t             status;
    uint8_t             *acc = NULL;
    size_t               acclen = 0, acccap = 0;
    brix_dirent         *ents = NULL;
    size_t               count = 0, entcap = 0;
    size_t               i;

    *ents_out = NULL;
    *count_out = 0;

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_dirlist);
    {
        xrdw_dirlist_req_t b = { .options = (uint8_t) (want_stat ? kXR_dstat : 0) };
        xrdw_dirlist_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }

    /* First frame via roundtrip (follows a cluster redirect to the data server);
     * subsequent kXR_oksofar chunks come from that same post-redirect connection. */
    {
        uint8_t *body = NULL;
        uint32_t blen = 0;
        int      first = 1;

        for (;;) {
            if (first) {
                if (brix_roundtrip(c, &req, path, (uint32_t) strlen(path),
                                   &status, &body, &blen, st) != 0) {
                    free(acc);
                    return -1;
                }
                first = 0;
            } else if (brix_recv(c, 0xffff, &status, &body, &blen, st) != 0) {
                free(acc);
                return -1;
            }
            if (blen > 0
                && buf_append(&acc, &acclen, &acccap, body, blen) != 0) {
                free(body);
                free(acc);
                brix_status_set(st, XRDC_EPROTO, 0, "out of memory in dirlist");
                return -1;
            }
            free(body);
            body = NULL;
            blen = 0;
            if (status != kXR_oksofar) {
                break;
            }
        }
    }

    /* Skip the dstat lead-in prefix ".\n0 0 0 0" up to and including its '\n'.
     * The sentinel + match length are shared with the server (dirlist_fmt.h). */
    i = 0;
    if (want_stat && acclen >= BRIX_DSTAT_PREFIX_LEN
        && memcmp(acc, BRIX_DSTAT_LEADIN, BRIX_DSTAT_PREFIX_LEN) == 0) {
        while (i < acclen && acc[i] != '\n') { i++; }   /* ".\n..." first \n */
        if (i < acclen) { i++; }                        /* now at "0 0 0 0\n" */
        while (i < acclen && acc[i] != '\n') { i++; }   /* end of "0 0 0 0" */
        if (i < acclen) { i++; }
    }

    while (i < acclen) {
        size_t      ns, nl, ss, sl;
        int         term = 0;
        brix_dirent e;

        i = next_line(acc, acclen, i, &ns, &nl, &term);
        if (nl == 0) {
            break;   /* empty trailing line */
        }

        memset(&e, 0, sizeof(e));
        {
            size_t cp = (nl < sizeof(e.name) - 1) ? nl : sizeof(e.name) - 1;
            memcpy(e.name, acc + ns, cp);
            e.name[cp] = '\0';
        }

        if (want_stat && !term) {
            char statbuf[256];
            size_t cp;
            i = next_line(acc, acclen, i, &ss, &sl, &term);
            cp = (sl < sizeof(statbuf) - 1) ? sl : sizeof(statbuf) - 1;
            memcpy(statbuf, acc + ss, cp);
            statbuf[cp] = '\0';
            if (parse_statinfo(statbuf, &e.st) == 0) {
                e.have_stat = 1;
            }
        }

        if (dirent_push(&ents, &count, &entcap, &e) != 0) {
            brix_status_set(st, XRDC_EPROTO, 0, "out of memory in dirlist");
            /* Error exit: both buffers still owned here; free both, return -1. */
            free(acc);
            free(ents);
            return -1;
        }
        if (term) {
            break;
        }
    }

    /* Success: transfer entry ownership to the caller, then free only the
     * accumulation buffer we still own (ents has been handed off). */
    *ents_out = ents;
    *count_out = count;
    free(acc);
    return 0;
}

/* Args for the resilient wrapper below. */
struct dirlist_args {
    const char   *path;
    int           want_stat;
    brix_dirent **ents_out;
    size_t       *count_out;
};

static int
dirlist_op(brix_conn *c, void *arg, brix_status *st)
{
    struct dirlist_args *a = (struct dirlist_args *) arg;
    return dirlist_once(c, a->path, a->want_stat, a->ents_out, a->count_out, st);
}

/* A directory listing is read-only and idempotent: re-running it on a fresh
 * connection after a sever yields the same entries, so the whole pass is wrapped
 * in brix_with_resilience — every tool that lists directories inherits this. */
int
brix_dirlist(brix_conn *c, const char *path, int want_stat,
             brix_dirent **ents_out, size_t *count_out, brix_status *st)
{
    struct dirlist_args a = { path, want_stat, ents_out, count_out };
    return brix_with_resilience(c, brix_resilient_window_ms(c), XRDC_OP_READONLY,
                                0, dirlist_op, &a, st);
}
