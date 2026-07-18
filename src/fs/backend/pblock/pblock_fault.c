/*
 * pblock_fault.c — Phase-83 fault injection (F1) + I/O shaping (F8).
 * See pblock_fault.h. ngx-free (libc + sqlite3 via pblock_ctl); pure-function
 * hot-path evaluator. Gated by BRIX_HAVE_SQLITE.
 */
#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "pblock_fault.h"
#include "pblock_ctl.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Instance-level rule cache. Refreshed only when the ctl epoch advances; the
 * mutex guards a refresh (rare — a metadata boundary) against concurrent worker
 * threads sharing the instance. */
struct pblock_lab_state {
    pblock_catalog *cat;
    pthread_mutex_t mtx;
    int64_t         epoch;      /* ctl epoch the cached rules were read at    */
    int             loaded;     /* 0 until the first refresh                  */
    pblock_rule_t   r;
    pblock_rule_t   w;
    int             open_ms;
    char            crash_at[48];   /* F7: armed crash point, "" if none  */
};

/* ---- small parsers ------------------------------------------------------ */

static int
errno_by_name(const char *s, size_t len)
{
    static const struct { const char *n; int e; } tab[] = {
        { "EIO", EIO }, { "ENOSPC", ENOSPC }, { "EACCES", EACCES },
        { "EROFS", EROFS }, { "EAGAIN", EAGAIN }, { "EPERM", EPERM },
        { "EDQUOT", EDQUOT }, { "EBUSY", EBUSY },
    };
    size_t i;

    for (i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
        if (strlen(tab[i].n) == len && memcmp(tab[i].n, s, len) == 0) {
            return tab[i].e;
        }
    }
    return 0;
}

/* Parse a "fault.<op>" value: space-separated key=val tokens
 * (errno=NAME, after_bytes=N, short=N) into *out (zeroed first). */
static void
parse_fault(const char *v, pblock_rule_t *out)
{
    const char *p = v;

    memset(out, 0, sizeof(*out));
    out->after_bytes = -1;
    out->short_to    = -1;
    if (v == NULL) {
        return;
    }
    while (*p != '\0') {
        while (*p == ' ') {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        {
            const char *tok_end = p;
            const char *eq;

            while (*tok_end != '\0' && *tok_end != ' ') {
                tok_end++;
            }
            eq = memchr(p, '=', (size_t) (tok_end - p));
            if (eq != NULL) {
                size_t      klen = (size_t) (eq - p);
                const char *val  = eq + 1;
                size_t      vlen = (size_t) (tok_end - val);

                if (klen == 5 && memcmp(p, "errno", 5) == 0) {
                    out->inj_errno = errno_by_name(val, vlen);
                } else if (klen == 11 && memcmp(p, "after_bytes", 11) == 0) {
                    out->after_bytes = strtoll(val, NULL, 10);
                } else if (klen == 5 && memcmp(p, "short", 5) == 0) {
                    out->short_to = (int) strtol(val, NULL, 10);
                }
            }
            p = tok_end;
        }
    }
}

static int64_t
ctl_int(pblock_catalog *cat, const char *key)
{
    char buf[64];

    if (pblock_ctl_get(cat, key, buf, sizeof(buf)) == 1 && buf[0] != '\0') {
        return strtoll(buf, NULL, 10);
    }
    return 0;
}

/* ---- instance cache ----------------------------------------------------- */

pblock_lab_state_t *
pblock_lab_state_create(pblock_catalog *cat)
{
    pblock_lab_state_t *ls = calloc(1, sizeof(*ls));

    if (ls == NULL) {
        return NULL;
    }
    ls->cat = cat;
    if (pthread_mutex_init(&ls->mtx, NULL) != 0) {
        free(ls);
        return NULL;
    }
    ls->epoch = -1;                 /* force a load on first snapshot */
    (void) pblock_ctl_init(cat);    /* ensure the table exists (idempotent) */
    return ls;
}

void
pblock_lab_state_destroy(pblock_lab_state_t *ls)
{
    if (ls != NULL) {
        pthread_mutex_destroy(&ls->mtx);
        free(ls);
    }
}

/* Reload the cached rules from ctl (caller holds the mutex). */
static void
lab_refresh_locked(pblock_lab_state_t *ls)
{
    char buf[256];

    memset(&ls->r, 0, sizeof(ls->r));
    memset(&ls->w, 0, sizeof(ls->w));
    ls->r.after_bytes = ls->w.after_bytes = -1;
    ls->r.short_to    = ls->w.short_to    = -1;

    if (pblock_ctl_get(ls->cat, "fault.pread", buf, sizeof(buf)) == 1) {
        parse_fault(buf, &ls->r);
    }
    if (pblock_ctl_get(ls->cat, "fault.pwrite", buf, sizeof(buf)) == 1) {
        parse_fault(buf, &ls->w);
    }
    ls->r.rate_bps = ctl_int(ls->cat, "shape.read_bps");
    ls->w.rate_bps = ctl_int(ls->cat, "shape.write_bps");
    ls->open_ms    = (int) ctl_int(ls->cat, "shape.open_ms");
    ls->crash_at[0] = '\0';
    (void) pblock_ctl_get(ls->cat, "crash.at", ls->crash_at,
                          sizeof(ls->crash_at));
    ls->loaded     = 1;
}

static int
rule_inert(const pblock_rule_t *r)
{
    return r->inj_errno == 0 && r->short_to < 0 && r->rate_bps == 0;
}

static void
sleep_ms(int ms)
{
    struct timespec ts;

    if (ms <= 0) {
        return;
    }
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (long) (ms % 1000) * 1000000L;
    (void) nanosleep(&ts, NULL);
}

pblock_lab_obj_t *
pblock_lab_snapshot(pblock_lab_state_t *ls, const char *path)
{
    pblock_lab_obj_t *lo;
    int64_t           epoch;
    int               open_ms;

    (void) path;   /* Wave A: rules are export-global, not per-path */
    if (ls == NULL) {
        return NULL;
    }

    pthread_mutex_lock(&ls->mtx);
    epoch = pblock_ctl_epoch(ls->cat);
    if (!ls->loaded || (epoch >= 0 && epoch != ls->epoch)) {
        lab_refresh_locked(ls);
        ls->epoch = epoch;
    }
    if (rule_inert(&ls->r) && rule_inert(&ls->w) && ls->open_ms == 0) {
        pthread_mutex_unlock(&ls->mtx);
        return NULL;
    }
    lo = calloc(1, sizeof(*lo));
    if (lo == NULL) {
        pthread_mutex_unlock(&ls->mtx);
        return NULL;
    }
    lo->r = ls->r;
    lo->w = ls->w;
    open_ms = ls->open_ms;
    pthread_mutex_unlock(&ls->mtx);

    sleep_ms(open_ms);    /* F8 open delay (outside the lock) */
    return lo;
}

void
pblock_lab_obj_free(pblock_lab_obj_t *lo)
{
    free(lo);
}

/* ---- hot-path gate ------------------------------------------------------ */

int
pblock_lab_io_gate(pblock_lab_obj_t *lo, int is_write, size_t *len, off_t off)
{
    const pblock_rule_t *r = is_write ? &lo->w : &lo->r;
    int64_t             *cum = is_write ? &lo->wbytes : &lo->rbytes;

    (void) off;

    /* F8 pacing: sleep proportional to the requested transfer. Capped at 5s so a
     * pathological rate can never wedge an AIO-pool thread indefinitely. */
    if (r->rate_bps > 0 && *len > 0) {
        uint64_t ns = (uint64_t) *len * 1000000000ULL / (uint64_t) r->rate_bps;
        struct timespec ts;

        if (ns > 5000000000ULL) {
            ns = 5000000000ULL;
        }
        ts.tv_sec  = (time_t) (ns / 1000000000ULL);
        ts.tv_nsec = (long) (ns % 1000000000ULL);
        (void) nanosleep(&ts, NULL);
    }

    /* F1 short op: clamp the transfer length. */
    if (r->short_to >= 0 && (size_t) r->short_to < *len) {
        *len = (size_t) r->short_to;
    }

    /* F1 error injection: fire once the cumulative threshold is reached (or
     * immediately when after_bytes < 0). */
    if (r->inj_errno != 0) {
        if (r->after_bytes < 0 || *cum >= r->after_bytes) {
            return r->inj_errno;
        }
    }

    *cum += (int64_t) *len;
    return 0;
}

/* ---- F7 crash points ---------------------------------------------------- */

void
pblock_lab_crash(pblock_lab_state_t *ls, const char *point)
{
    int64_t epoch;
    int     hit;

    if (ls == NULL || point == NULL) {
        return;
    }

    pthread_mutex_lock(&ls->mtx);
    epoch = pblock_ctl_epoch(ls->cat);
    if (!ls->loaded || (epoch >= 0 && epoch != ls->epoch)) {
        lab_refresh_locked(ls);
        ls->epoch = epoch;
    }
    hit = (ls->crash_at[0] != '\0' && strcmp(ls->crash_at, point) == 0);
    pthread_mutex_unlock(&ls->mtx);

    if (hit) {
        /* Simulate a power loss at this durability boundary: the worker dies
         * without flushing anything further; nginx's master respawns it. The
         * post-restart catalog↔blocks residue is what pblock-fsck classifies. */
        _exit(PBLOCK_CRASH_EXIT);
    }
}

#endif /* BRIX_HAVE_SQLITE */
