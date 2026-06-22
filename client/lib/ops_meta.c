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
#include "xrdc.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
parse_statinfo(const char *s, xrdc_statinfo *out)
{
    unsigned long long id = 0;
    long long          size = 0;
    int                flags = 0;
    long               mtime = 0;
    long               ctime = 0, atime = 0;
    char               modebuf[32] = {0}, owner[64] = {0}, group[64] = {0};
    int                nf;

    /* Mandatory wire form: "<id> <size> <flags> <mtime>".  Some servers (EOS)
     * append an extended tail "<ctime> <atime> <mode> <owner> <group>"; parse
     * it opportunistically and record have_ext so callers can print it. */
    nf = sscanf(s, "%llu %lld %d %ld %ld %ld %31s %63s %63s",
                &id, &size, &flags, &mtime,
                &ctime, &atime, modebuf, owner, group);
    if (nf < 4) {
        return -1;
    }
    out->id       = (uint64_t) id;
    out->size     = (int64_t) size;
    out->flags    = flags;
    out->mtime    = mtime;
    out->have_ext = 0;
    out->ctime    = 0;
    out->atime    = 0;
    out->mode     = 0;
    out->owner[0] = '\0';
    out->group[0] = '\0';

    if (nf >= 9) {
        out->have_ext = 1;
        out->ctime    = ctime;
        out->atime    = atime;
        out->mode     = (unsigned) strtoul(modebuf, NULL, 8);   /* octal on wire */
        snprintf(out->owner, sizeof(out->owner), "%s", owner);
        snprintf(out->group, sizeof(out->group), "%s", group);
    }
    return 0;
}

/* Shared core: stat a path with the given kXR_stat options byte (0 = follow
 * symlinks, kXR_statNoFollow = lstat). */
static int
stat_opt(xrdc_conn *c, const char *path, uint8_t options, xrdc_statinfo *out,
         xrdc_status *st)
{
    ClientStatRequest req;
    uint16_t          status;
    uint8_t          *body = NULL;
    uint32_t          blen = 0;
    char              tmp[256];
    uint32_t          n;

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_stat);
    req.options   = options;
    req.wants     = 0;

    if (xrdc_roundtrip_resilient(c, &req, path, (uint32_t) strlen(path),
                                 XRDC_OP_READONLY, 0,
                                 &status, &body, &blen, st) != 0) {
        return -1;
    }

    n = (blen < sizeof(tmp) - 1) ? blen : (uint32_t) (sizeof(tmp) - 1);
    memcpy(tmp, body, n);
    tmp[n] = '\0';
    free(body);

    if (parse_statinfo(tmp, out) != 0) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "unparseable stat body: \"%s\"", tmp);
        return -1;
    }
    return 0;
}

int
xrdc_stat(xrdc_conn *c, const char *path, xrdc_statinfo *out, xrdc_status *st)
{
    return stat_opt(c, path, 0, out, st);
}

int
xrdc_lstat(xrdc_conn *c, const char *path, xrdc_statinfo *out, xrdc_status *st)
{
    /* kXR_statNoFollow: report a final symlink as itself (kXR_other + target-len
     * size). A server without the vendor extension ignores the bit and follows. */
    return stat_opt(c, path, (uint8_t) kXR_statNoFollow, out, st);
}

/* ---- dirlist ---- */

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
dirent_push(xrdc_dirent **ents, size_t *count, size_t *cap, const xrdc_dirent *e)
{
    if (*count == *cap) {
        size_t       newcap = (*cap == 0) ? 64 : *cap * 2;
        xrdc_dirent *na = (xrdc_dirent *) realloc(*ents, newcap * sizeof(**ents));
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
dirlist_once(xrdc_conn *c, const char *path, int want_stat,
             xrdc_dirent **ents_out, size_t *count_out, xrdc_status *st)
{
    ClientDirlistRequest req;
    uint16_t             status;
    uint8_t             *acc = NULL;
    size_t               acclen = 0, acccap = 0;
    xrdc_dirent         *ents = NULL;
    size_t               count = 0, entcap = 0;
    size_t               i;

    *ents_out = NULL;
    *count_out = 0;

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_dirlist);
    req.options   = (kXR_char) (want_stat ? kXR_dstat : 0);

    /* First frame via roundtrip (follows a cluster redirect to the data server);
     * subsequent kXR_oksofar chunks come from that same post-redirect connection. */
    {
        uint8_t *body = NULL;
        uint32_t blen = 0;
        int      first = 1;

        for (;;) {
            if (first) {
                if (xrdc_roundtrip(c, &req, path, (uint32_t) strlen(path),
                                   &status, &body, &blen, st) != 0) {
                    free(acc);
                    return -1;
                }
                first = 0;
            } else if (xrdc_recv(c, 0xffff, &status, &body, &blen, st) != 0) {
                free(acc);
                return -1;
            }
            if (blen > 0
                && buf_append(&acc, &acclen, &acccap, body, blen) != 0) {
                free(body);
                free(acc);
                xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory in dirlist");
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

    /* Skip the dstat lead-in prefix ".\n0 0 0 0" up to and including its '\n'. */
    i = 0;
    if (want_stat && acclen >= 9 && memcmp(acc, ".\n0 0 0 0", 9) == 0) {
        while (i < acclen && acc[i] != '\n') { i++; }   /* ".\n..." first \n */
        if (i < acclen) { i++; }                        /* now at "0 0 0 0\n" */
        while (i < acclen && acc[i] != '\n') { i++; }   /* end of "0 0 0 0" */
        if (i < acclen) { i++; }
    }

    while (i < acclen) {
        size_t      ns, nl, ss, sl;
        int         term = 0;
        xrdc_dirent e;

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
            xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory in dirlist");
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
    xrdc_dirent **ents_out;
    size_t       *count_out;
};

static int
dirlist_op(xrdc_conn *c, void *arg, xrdc_status *st)
{
    struct dirlist_args *a = (struct dirlist_args *) arg;
    return dirlist_once(c, a->path, a->want_stat, a->ents_out, a->count_out, st);
}

/* A directory listing is read-only and idempotent: re-running it on a fresh
 * connection after a sever yields the same entries, so the whole pass is wrapped
 * in xrdc_with_resilience — every tool that lists directories inherits this. */
int
xrdc_dirlist(xrdc_conn *c, const char *path, int want_stat,
             xrdc_dirent **ents_out, size_t *count_out, xrdc_status *st)
{
    struct dirlist_args a = { path, want_stat, ents_out, count_out };
    return xrdc_with_resilience(c, xrdc_resilient_window_ms(c), XRDC_OP_READONLY,
                                0, dirlist_op, &a, st);
}
