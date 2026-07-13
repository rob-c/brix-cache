/*
 * meta_advisory.c — the shared advisory unix-metadata codec. See the header.
 * Pure libc: no nginx, no sd.h, no allocation. strtok_r/strtoll need POSIX.2008.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "meta_advisory.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Append a printf-formatted chunk to out[cap] at *n; -1 on truncation. */
static int
adv_append(char *out, size_t cap, int *n, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static int
adv_append(char *out, size_t cap, int *n, const char *fmt, ...)
{
    va_list ap;
    int     r;

    va_start(ap, fmt);
    r = vsnprintf(out + *n, cap - (size_t) *n, fmt, ap);
    va_end(ap);
    if (r < 0 || (size_t) *n + (size_t) r >= cap) {
        return -1;
    }
    *n += r;
    return 0;
}

int
brix_meta_advisory_encode(const brix_meta_advisory_t *m, char *out, size_t cap)
{
    int n = 0;

    if (m == NULL || out == NULL || cap == 0) {
        return -1;
    }
    if (adv_append(out, cap, &n, "v1") != 0) {
        return -1;
    }
    if (m->have_mode
        && adv_append(out, cap, &n, " mode=%04o",
                      (unsigned) (m->mode & 07777)) != 0) {
        return -1;
    }
    if (m->have_owner
        && adv_append(out, cap, &n, " uid=%u gid=%u",
                      (unsigned) m->uid, (unsigned) m->gid) != 0) {
        return -1;
    }
    if (m->have_mtime
        && adv_append(out, cap, &n, " mtime=%lld mtime_ns=%ld",
                      (long long) m->mtime, m->mtime_ns) != 0) {
        return -1;
    }
    return n;
}

int
brix_meta_advisory_decode(const char *blob, size_t len, brix_meta_advisory_t *m)
{
    char    tmp[512];
    size_t  n;
    char   *tok, *save = NULL;
    int     uid_seen = 0, gid_seen = 0;

    if (m == NULL) {
        return -1;
    }
    memset(m, 0, sizeof(*m));
    if (blob == NULL || len == 0) {
        return 0;
    }

    n = (len < sizeof(tmp) - 1) ? len : sizeof(tmp) - 1;
    memcpy(tmp, blob, n);
    tmp[n] = '\0';

    for (tok = strtok_r(tmp, " ", &save); tok != NULL;
         tok = strtok_r(NULL, " ", &save))
    {
        char       *eq = strchr(tok, '=');
        const char *key, *val;

        if (eq == NULL) {
            continue;                      /* version token ("v1"/"v9") — skip */
        }
        *eq = '\0';
        key = tok;
        val = eq + 1;

        if (strcmp(key, "mode") == 0) {
            m->mode = (mode_t) strtol(val, NULL, 8);
            m->have_mode = 1;
        } else if (strcmp(key, "uid") == 0) {
            m->uid = (uid_t) strtoul(val, NULL, 10);
            uid_seen = 1;
        } else if (strcmp(key, "gid") == 0) {
            m->gid = (gid_t) strtoul(val, NULL, 10);
            gid_seen = 1;
        } else if (strcmp(key, "mtime") == 0) {
            m->mtime = (time_t) strtoll(val, NULL, 10);
            m->have_mtime = 1;
        } else if (strcmp(key, "mtime_ns") == 0) {
            m->mtime_ns = strtol(val, NULL, 10);
        }
        /* unknown key → ignored (forward-compatible) */
    }

    m->have_owner = (uid_seen && gid_seen) ? 1 : 0;
    return 0;
}

int
brix_meta_advisory_patch(char *blob, size_t cap, const brix_meta_advisory_t *delta)
{
    brix_meta_advisory_t cur;

    if (blob == NULL || delta == NULL) {
        return -1;
    }
    if (brix_meta_advisory_decode(blob, strlen(blob), &cur) != 0) {
        return -1;
    }
    if (delta->have_mode) {
        cur.mode = delta->mode;
        cur.have_mode = 1;
    }
    if (delta->have_owner) {
        cur.uid = delta->uid;
        cur.gid = delta->gid;
        cur.have_owner = 1;
    }
    if (delta->have_mtime) {
        cur.mtime = delta->mtime;
        cur.mtime_ns = delta->mtime_ns;
        cur.have_mtime = 1;
    }
    return brix_meta_advisory_encode(&cur, blob, cap);
}
