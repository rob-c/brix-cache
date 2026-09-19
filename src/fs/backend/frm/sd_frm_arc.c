/*
 * sd_frm_arc.c — dataset archiver adapter: key grammar + vtable (phase-115 W3.1)
 *
 * WHAT: the decorator's brix_mss_adapter_t slots. Anything at or above the
 *       dataset depth passes straight to the wrapped adapter; members and the
 *       completion marker get the archive semantics described in sd_frm_arc.h.
 *
 * WHY:  the frm driver (sd_frm.c) speaks only the adapter vtable, so wrapping
 *       the adapter gives every tape dialect the archiver without touching the
 *       driver's open/recall/staged-write paths.
 *
 * HOW:  arc_classify() splits a key into (kind, dataset, member). Residency of a
 *       member answers from the index sidecar (OFFLINE, size known) so stat and
 *       dirlist never recall; recall_begin/recall_poll recall the ARCHIVE via
 *       the inner adapter and extract one member (sd_frm_arc_store.c);
 *       migrate(marker) defers the seal to the driver's backup queue and
 *       create_online refuses mutations of a sealed, sealing or reserved
 *       name -- the write side lives in sd_frm_arc_seal.c (2.0 F3).
 */

#include "sd_frm_arc_internal.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ARC_SUFFIX_LEN  (sizeof(BRIX_ARC_SUFFIX) - 1)

/* ---- key grammar --------------------------------------------------------- */

static int
arc_has_reserved_suffix(const char *key)
{
    size_t n = strlen(key);

    return n >= ARC_SUFFIX_LEN && strcmp(key + n - ARC_SUFFIX_LEN, BRIX_ARC_SUFFIX) == 0;
}

/* Walk `key`'s components: returns the count, and *cut = first byte after the
 * `depth`-th component (NULL when the key is shorter than that). */
static unsigned
arc_components(const char *key, unsigned depth, const char **cut)
{
    const char *p = key;
    unsigned    n = 0;

    *cut = NULL;
    while (*p == '/') {
        p++;
    }
    while (*p != '\0') {
        const char *e = strchr(p, '/');

        n++;
        if (n == depth) {
            *cut = (e != NULL) ? e : p + strlen(p);
        }
        if (e == NULL) {
            break;
        }
        for (p = e; *p == '/'; p++) { /* collapse "//" */ }
    }
    return n;
}

arc_kind_t
arc_classify(const arc_ctx_t *c, const char *key, arc_key_t *out)
{
    const char *cut, *member;
    unsigned    n;

    memset(out, 0, sizeof(*out));
    out->key = key;
    if (key == NULL) {
        return ARC_KEY_PLAIN;
    }
    if (arc_has_reserved_suffix(key)) {
        out->kind = ARC_KEY_RESERVED;
        return out->kind;
    }
    n = arc_components(key, c->depth, &cut);
    if (n <= c->depth || cut == NULL) {
        return ARC_KEY_PLAIN;
    }
    if (snprintf(out->ds, sizeof(out->ds), "%s%.*s", (key[0] == '/') ? "" : "/",
                 (int) (cut - key), key) >= (int) sizeof(out->ds))
    {
        return ARC_KEY_PLAIN;               /* absurdly long dataset name: per-file */
    }
    for (member = cut; *member == '/'; member++) { /* skip the separator */ }
    out->member = member;
    out->kind = (strcmp(member, BRIX_ARC_MARKER) == 0) ? ARC_KEY_MARKER : ARC_KEY_MEMBER;
    return out->kind;
}

int
arc_is_dataset_dir(const arc_ctx_t *c, const char *key)
{
    const char *cut;

    return key != NULL && !arc_has_reserved_suffix(key)
           && arc_components(key, c->depth, &cut) == c->depth;
}

int
arc_archive_key(const arc_key_t *k, char *out, size_t cap)
{
    return (snprintf(out, cap, "%s%s", k->ds, BRIX_ARC_SUFFIX) < (int) cap) ? 0 : -1;
}

int
arc_sidecar_path(const arc_ctx_t *c, const char *ds, char *out, size_t cap)
{
    return (snprintf(out, cap, "%s/%s%s.idx", c->base, BRIX_ARC_IDX_DIR, ds) < (int) cap) ? 0 : -1;
}

int
arc_sealed(const arc_ctx_t *c, const char *ds)
{
    char path[PATH_MAX];

    return arc_sidecar_path(c, ds, path, sizeof(path)) == 0 && access(path, F_OK) == 0;
}

/* ---- residency / recall -------------------------------------------------- */

static int
arc_archive_exists(const arc_ctx_t *c, const arc_key_t *k)
{
    char akey[PATH_MAX];

    return arc_archive_key(k, akey, sizeof(akey)) == 0
           && c->inner->residency(c->ictx, akey, NULL, NULL) != BRIX_RESIDENCY_ABSENT;
}

static int
arc_residency(void *mss, const char *key, off_t *size_out, time_t *mtime_out)
{
    arc_ctx_t        *c = mss;
    arc_key_t         k;
    brix_zip_entry_t  e;
    time_t            sealed = 0;
    int               r = c->inner->residency(c->ictx, key, size_out, mtime_out);

    if (r != BRIX_RESIDENCY_ABSENT || arc_classify(c, key, &k) != ARC_KEY_MEMBER) {
        return r;
    }
    r = arc_sidecar_lookup(c, k.ds, k.member, &e, &sealed);
    if (r == 0) {
        return BRIX_RESIDENCY_ABSENT;       /* sealed dataset, no such member */
    }
    if (r < 0) {
        if (errno != ENOENT || !arc_archive_exists(c, &k)) {
            return BRIX_RESIDENCY_ABSENT;
        }
        e.size = 0;                         /* index lost: rebuilt on recall */
        sealed = time(NULL);
    }
    if (size_out != NULL) {
        *size_out = (off_t) e.size;
    }
    if (mtime_out != NULL) {
        *mtime_out = sealed;
    }
    return BRIX_RESIDENCY_OFFLINE;
}

/* Is `member` worth a recall attempt: indexed, or the index is missing while
 * the archive exists (arc_extract rebuilds it)? */
static int
arc_member_recallable(const arc_ctx_t *c, const arc_key_t *k)
{
    brix_zip_entry_t e;
    int              r = arc_sidecar_lookup(c, k->ds, k->member, &e, NULL);

    if (r == 1) {
        return 1;
    }
    return r < 0 && errno == ENOENT && arc_archive_exists(c, k);
}

/* Make the dataset's archive online: 1 online (extract now), 0 recall in
 * flight, -1 error (errno; ENOENT when the archive does not exist at all). */
static int
arc_archive_online(const arc_ctx_t *c, const arc_key_t *k, int begin)
{
    char akey[PATH_MAX];
    int  r;

    if (arc_archive_key(k, akey, sizeof(akey)) != 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    r = c->inner->residency(c->ictx, akey, NULL, NULL);
    if (r == BRIX_RESIDENCY_ONLINE) {
        return 1;
    }
    if (r == BRIX_RESIDENCY_ABSENT) {
        errno = ENOENT;
        return -1;
    }
    if (begin && c->inner->recall_begin(c->ictx, akey) != 0) {
        return -1;
    }
    return c->inner->recall_poll(c->ictx, akey);
}

static int
arc_recall_begin(void *mss, const char *key)
{
    arc_ctx_t *c = mss;
    arc_key_t  k;
    int        r;

    if (arc_classify(c, key, &k) != ARC_KEY_MEMBER
        || c->inner->residency(c->ictx, key, NULL, NULL) != BRIX_RESIDENCY_ABSENT)
    {
        return c->inner->recall_begin(c->ictx, key);   /* plain key or a per-file copy */
    }
    if (!arc_member_recallable(c, &k)) {
        errno = ENOENT;
        return -1;
    }
    r = arc_archive_online(c, &k, 1);
    if (r <= 0) {
        return r;                                      /* 0: archive still staging */
    }
    return arc_extract(c, &k);
}

static int
arc_recall_poll(void *mss, const char *key)
{
    arc_ctx_t *c = mss;
    arc_key_t  k;
    int        r;

    if (arc_classify(c, key, &k) != ARC_KEY_MEMBER) {
        return c->inner->recall_poll(c->ictx, key);
    }
    r = c->inner->residency(c->ictx, key, NULL, NULL);
    if (r == BRIX_RESIDENCY_ONLINE) {
        return 1;
    }
    if (r != BRIX_RESIDENCY_ABSENT) {
        return c->inner->recall_poll(c->ictx, key);    /* a legacy per-file copy */
    }
    r = arc_archive_online(c, &k, 0);
    if (r != 1) {
        return r;
    }
    return (arc_extract(c, &k) == 0) ? 1 : -1;
}

/* ---- write side: arc_migrate / arc_create_online / arc_seal live in
 * sd_frm_arc_seal.c (2.0 F3 backup queue) ------------------------------- */

static int
arc_purge(void *mss, const char *key)
{
    arc_ctx_t *c = mss;

    return c->inner->purge(c->ictx, key);
}

/* Durable-copy probe for the purge engine: a member is releasable only once
 * its dataset is sealed AND the archive itself is on tape. */
static int
arc_on_tape(void *mss, const char *key)
{
    arc_ctx_t        *c = mss;
    arc_key_t         k;
    brix_zip_entry_t  e;
    char              akey[PATH_MAX];
    int               inner_can = (c->inner->on_tape != NULL);

    if (arc_classify(c, key, &k) != ARC_KEY_MEMBER) {
        return inner_can ? c->inner->on_tape(c->ictx, key) : 1;
    }
    if (inner_can && c->inner->on_tape(c->ictx, key) == 1) {
        return 1;                                       /* legacy per-file copy */
    }
    if (arc_sidecar_lookup(c, k.ds, k.member, &e, NULL) != 1
        || arc_archive_key(&k, akey, sizeof(akey)) != 0)
    {
        return 0;                                       /* unsealed: the only copy */
    }
    return inner_can ? c->inner->on_tape(c->ictx, akey) : 1;
}

static int
arc_exchange(void *mss, const char *a, const char *b)
{
    arc_ctx_t *c = mss;
    arc_key_t  ka, kb;

    if (arc_classify(c, a, &ka) != ARC_KEY_PLAIN || arc_classify(c, b, &kb) != ARC_KEY_PLAIN
        || c->inner->exchange == NULL)
    {
        errno = ENOTSUP;
        return -1;
    }
    return c->inner->exchange(c->ictx, a, b);
}

/* ---- namespace ----------------------------------------------------------- */

typedef struct {
    int  (*cb)(void *ud, const char *name, int is_dir);
    void  *ud;
    char **seen;                /* names the inner listing already produced */
    unsigned n, cap;
    char   last_dir[BRIX_ZIP_NAME_MAX];
    int    stopped;
} arc_list_t;

static int
arc_list_seen(const arc_list_t *l, const char *name)
{
    unsigned i;

    for (i = 0; i < l->n; i++) {
        if (strcmp(l->seen[i], name) == 0) {
            return 1;
        }
    }
    return 0;
}

static int
arc_list_inner_cb(void *ud, const char *name, int is_dir)
{
    arc_list_t *l = ud;
    char       *copy;

    if (l->n == l->cap) {
        unsigned  ncap = l->cap ? l->cap * 2 : 32;
        char    **grown = realloc(l->seen, ncap * sizeof(*grown));

        if (grown == NULL) {
            return 1;
        }
        l->seen = grown;
        l->cap = ncap;
    }
    /* Ownership transfers INTO the seen list; arc_list_free releases every
     * entry. A failed strdup only costs this name its dedup slot, so the
     * callback still runs — the walk is not the allocation's hostage.
     *
     * gcc 11's -fanalyzer cannot see a symbolic-index store through a
     * parameter as an escape, so it reports the copy leaking at the return
     * below. Suppress exactly that diagnostic, at exactly its emission point. */
#pragma GCC diagnostic push
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"
#endif
    copy = strdup(name);
    if (copy != NULL) {
        l->seen[l->n] = copy;
        l->n++;
    }
    l->stopped = l->cb(l->ud, name, is_dir);
    return l->stopped;
#pragma GCC diagnostic pop
}

/* One sidecar member name → its first component, emitted once (the sidecar is
 * sorted, so a directory's members are contiguous and `last_dir` dedupes). */
static int
arc_list_member_cb(void *ud, const char *name)
{
    arc_list_t *l = ud;
    const char *slash = strchr(name, '/');
    char        first[BRIX_ZIP_NAME_MAX];
    size_t      n = (slash != NULL) ? (size_t) (slash - name) : strlen(name);

    if (n == 0 || n >= sizeof(first)) {
        return 0;
    }
    memcpy(first, name, n);
    first[n] = '\0';
    if ((slash != NULL && strcmp(first, l->last_dir) == 0) || arc_list_seen(l, first)) {
        return 0;
    }
    if (slash != NULL) {
        memcpy(l->last_dir, first, n + 1);
    }
    l->stopped = l->cb(l->ud, first, slash != NULL);
    return l->stopped;
}

static void
arc_list_free(arc_list_t *l)
{
    unsigned i;

    for (i = 0; i < l->n; i++) {
        free(l->seen[i]);
    }
    free(l->seen);
}

static int
arc_list(void *mss, const char *key, int (*cb)(void *ud, const char *name, int is_dir), void *ud)
{
    arc_ctx_t  *c = mss;
    arc_list_t  l;
    int         rc = 0;

    if (!arc_is_dataset_dir(c, key)) {
        if (c->inner->list == NULL) {
            errno = ENOTSUP;
            return -1;
        }
        return c->inner->list(c->ictx, key, cb, ud);
    }
    memset(&l, 0, sizeof(l));
    l.cb = cb;
    l.ud = ud;
    if (c->inner->list != NULL) {
        rc = c->inner->list(c->ictx, key, arc_list_inner_cb, &l);
    }
    if (rc != 0 && (errno != ENOENT || !arc_sealed(c, key))) {
        arc_list_free(&l);                  /* neither a tape directory nor sealed */
        return -1;
    }
    if (!l.stopped) {
        rc = arc_sidecar_names(c, key, arc_list_member_cb, &l);
        rc = (rc != 0 && errno == ENOENT) ? 0 : rc;     /* unsealed: inner only */
    }
    arc_list_free(&l);
    return rc;
}

static int
arc_mkpath(void *mss, const char *key, mode_t mode)
{
    arc_ctx_t *c = mss;

    if (c->inner->mkpath == NULL) {
        errno = ENOTSUP;
        return -1;
    }
    return c->inner->mkpath(c->ictx, key, mode);
}

static int
arc_open_online(void *mss, const char *key)
{
    arc_ctx_t *c = mss;

    return c->inner->open_online(c->ictx, key);
}

static void
arc_destroy(void *mss)
{
    arc_ctx_t *c = mss;

    if (c == NULL) {
        return;
    }
    if (c->inner->destroy != NULL) {
        c->inner->destroy(c->ictx);
    }
    free(c);
}

const brix_mss_adapter_t brix_mss_arc_adapter = {
    .name          = "arc",
    .residency     = arc_residency,
    .recall_begin  = arc_recall_begin,
    .recall_poll   = arc_recall_poll,
    .migrate       = arc_migrate,
    .seal          = arc_seal,          /* 2.0 F3: the deferred publish */
    .purge         = arc_purge,
    .on_tape       = arc_on_tape,
    .exchange      = arc_exchange,
    .list          = arc_list,
    .mkpath        = arc_mkpath,
    .open_online   = arc_open_online,
    .create_online = arc_create_online,
    .sync_publish  = arc_sync_publish,
    .destroy       = arc_destroy,
};

void *
brix_mss_arc_create(const brix_mss_adapter_t *inner, void *ictx, const char *base,
    unsigned depth, ngx_log_t *log)
{
    arc_ctx_t *c;

    if (inner == NULL || base == NULL || base[0] == '\0' || depth == 0
        || depth > BRIX_ARC_MAX_DEPTH || strlen(base) >= sizeof(c->base))
    {
        errno = EINVAL;
        return NULL;
    }
    c = calloc(1, sizeof(*c));
    if (c == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    c->inner = inner;
    c->ictx = ictx;
    c->log = log;
    c->depth = depth;
    memcpy(c->base, base, strlen(base) + 1);
    return c;
}

/* ---- store-URL query grammar ---------------------------------------------- */

/* One "key=value" of the query: only `arc=<1..8>` exists today. */
static int
arc_query_pair(const char *kv, size_t n, brix_sd_frm_opts_t *opts)
{
    char          *end;
    unsigned long  v;

    if (n <= 4 || strncmp(kv, "arc=", 4) != 0 || !isdigit((unsigned char) kv[4])) {
        return -1;
    }
    v = strtoul(kv + 4, &end, 10);
    if (end != kv + n || v < 1 || v > BRIX_ARC_MAX_DEPTH) {
        return -1;
    }
    opts->arc_depth = (unsigned) v;
    return 0;
}

int
brix_sd_frm_parse_query(const char *q, brix_sd_frm_opts_t *opts)
{
    memset(opts, 0, sizeof(*opts));
    while (q != NULL && *q != '\0') {
        const char *amp = strchr(q, '&');
        size_t      n = (amp != NULL) ? (size_t) (amp - q) : strlen(q);

        if (arc_query_pair(q, n, opts) != 0) {
            errno = EINVAL;
            return -1;
        }
        q = (amp != NULL) ? amp + 1 : q + n;
    }
    return 0;
}
