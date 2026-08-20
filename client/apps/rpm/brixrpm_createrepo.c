/* brixrpm_createrepo.c — the `brixrpm createrepo` verb (phase-104 D12.1).
 *
 * WHAT: scan a repo directory for *.rpm, parse each through shared/rpm and
 *       emit repodata/ via the repomd writer; keep a per-package fragment
 *       memo (`repodata/.brixrpm-cache`) so `--update` re-parses only
 *       packages whose (size, mtime) changed.
 * WHY:  parsing + sha256-ing every package is the whole cost of a rebuild —
 *       the memo turns the steady-state republish into a stat sweep.
 * HOW:  the memo is length-framed: one `pkg <size> <mtime> <prilen> <fillen>
 *       <othlen> <pkgid> <href>` line per package followed by exactly that
 *       many fragment bytes, staged + renamed like every other artifact.
 *       The memo is always rewritten (a non---update run still primes it).
 */
#include "brixrpm_internal.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CR_PATH_MAX   4096
#define CR_CACHE_NAME ".brixrpm-cache"
#define CR_CACHE_MAGIC "brixrpm-cache 1\n"

typedef struct {
    char **v;
    size_t n, cap;
} strv_t;

/* One memo entry: identity + the three rendered fragments. */
typedef struct {
    char      *href;
    long long  size, mtime;
    char       pkgid[65];
    char      *pri, *fil, *oth;
} cr_ent_t;

typedef struct {
    cr_ent_t *v;
    size_t    n, cap;
} entv_t;

typedef struct {
    uint32_t parsed, cached, skipped, sanitized, drifted;
} cr_stats_t;

static int
strv_push(strv_t *s, const char *str)
{
    if (s->n == s->cap) {
        size_t cap = s->cap > 0 ? s->cap * 2 : 64;
        char **nv  = realloc(s->v, cap * sizeof(*nv));

        if (nv == NULL) {
            return -1;
        }
        s->v   = nv;
        s->cap = cap;
    }
    s->v[s->n] = strdup(str);
    if (s->v[s->n] == NULL) {
        return -1;
    }
    s->n++;
    return 0;
}

static void
strv_free(strv_t *s)
{
    size_t i;

    for (i = 0; i < s->n; i++) {
        free(s->v[i]);
    }
    free(s->v);
}

static int
strp_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *) a, *(char *const *) b);
}

static void
ent_free_payload(cr_ent_t *e)
{
    free(e->href);
    free(e->pri);
    free(e->fil);
    free(e->oth);
}

static void
entv_free(entv_t *ev)
{
    size_t i;

    for (i = 0; i < ev->n; i++) {
        ent_free_payload(&ev->v[i]);
    }
    free(ev->v);
}

/* Append a zeroed slot; NULL on OOM. */
static cr_ent_t *
entv_push(entv_t *ev)
{
    if (ev->n == ev->cap) {
        size_t    cap = ev->cap > 0 ? ev->cap * 2 : 64;
        cr_ent_t *nv  = realloc(ev->v, cap * sizeof(*nv));

        if (nv == NULL) {
            return NULL;
        }
        ev->v   = nv;
        ev->cap = cap;
    }
    memset(&ev->v[ev->n], 0, sizeof(ev->v[ev->n]));
    return &ev->v[ev->n++];
}

static int
ent_cmp(const void *a, const void *b)
{
    return strcmp(((const cr_ent_t *) a)->href,
                  ((const cr_ent_t *) b)->href);
}

static const cr_ent_t *
ent_find(const entv_t *ev, const char *href)
{
    cr_ent_t key;

    key.href = (char *) href;
    return bsearch(&key, ev->v, ev->n, sizeof(*ev->v), ent_cmp);
}

static int cr_scan(const char *root, const char *rel, strv_t *out);

/* One directory entry: skip the noise, recurse into subdirectories, collect
 * the `.rpm`s. An entry that cannot be reached is a warning and a skip — a
 * repository built from what IS readable beats no repository at all — so the
 * only failure this returns is an allocation or a failed recursion. */
static int
cr_scan_child(const char *root, const char *rel, const char *dirpath,
              const char *name, strv_t *out)
{
    char        sub[CR_PATH_MAX], full[CR_PATH_MAX];
    struct stat st;
    size_t      nlen = strlen(name);

    if (name[0] == '.' || strcmp(name, "repodata") == 0) {
        return 0;
    }
    if (snprintf(sub, sizeof(sub), "%s%s%s", rel,
                 rel[0] != '\0' ? "/" : "", name) >= (int) sizeof(sub) ||
        snprintf(full, sizeof(full), "%s/%s", root, sub) >=
            (int) sizeof(full)) {
        fprintf(stderr, "brixrpm: warning: path too long under %s "
                "(skipped)\n", dirpath);
        return 0;
    }
    if (lstat(full, &st) != 0) {
        fprintf(stderr, "brixrpm: warning: %s: %s (skipped)\n", full,
                strerror(errno));
        return 0;
    }
    if (S_ISDIR(st.st_mode)) {
        return cr_scan(root, sub, out);
    }
    if (S_ISREG(st.st_mode) && nlen > 4 &&
        strcmp(name + nlen - 4, ".rpm") == 0) {
        return strv_push(out, sub);
    }
    return 0;
}


/* Recursive *.rpm scan. Dot entries, repodata/ and symlinked dirs are
 * skipped; unreadable subtrees warn and continue (only the root is fatal,
 * checked by the caller). rel is "" at the root. */
static int
cr_scan(const char *root, const char *rel, strv_t *out)
{
    char           dirpath[CR_PATH_MAX];
    DIR           *d;
    struct dirent *de;
    int            rc = 0;

    if (snprintf(dirpath, sizeof(dirpath), "%s%s%s", root,
                 rel[0] != '\0' ? "/" : "", rel) >= (int) sizeof(dirpath)) {
        return 0;
    }
    d = opendir(dirpath);
    if (d == NULL) {
        if (rel[0] != '\0') {
            fprintf(stderr, "brixrpm: warning: %s: %s (skipped)\n", dirpath,
                    strerror(errno));
            return 0;
        }
        fprintf(stderr, "brixrpm: %s: %s\n", dirpath, strerror(errno));
        return -1;
    }
    while (rc == 0 && (de = readdir(d)) != NULL) {
        rc = cr_scan_child(root, rel, dirpath, de->d_name, out);
    }
    closedir(d);
    return rc;
}

/* malloc + fread exactly len bytes, NUL-terminated. NULL on short read. */
static char *
cr_read_block(FILE *f, size_t len)
{
    char *b = malloc(len + 1);

    if (b == NULL || fread(b, 1, len, f) != len) {
        free(b);
        return NULL;
    }
    b[len] = '\0';
    return b;
}

/* One memo record: the "pkg" header line already in `line`, then the three
 * length-counted XML fragments that follow it. 0 = `out` grew by one usable
 * entry; -1 = the memo is malformed from here on and the caller must discard
 * the whole thing (a partially-trusted memo would republish stale metadata
 * for packages that have since changed). */
static int
cr_cache_read_ent(FILE *f, char *line, entv_t *out)
{
    cr_ent_t  *e = entv_push(out);
    size_t     pl, fl, ol;
    int        off = 0;
    char      *nl;

    if (e == NULL ||
        sscanf(line, "pkg %lld %lld %zu %zu %zu %64s %n", &e->size,
               &e->mtime, &pl, &fl, &ol, e->pkgid, &off) != 6 ||
        off == 0 || line[off] == '\0') {
        if (e != NULL) {
            out->n--;
        }
        return -1;
    }
    nl = strchr(line + off, '\n');
    if (nl != NULL) {
        *nl = '\0';
    }
    e->href = strdup(line + off);
    e->pri  = e->href != NULL ? cr_read_block(f, pl) : NULL;
    e->fil  = e->pri != NULL ? cr_read_block(f, fl) : NULL;
    e->oth  = e->fil != NULL ? cr_read_block(f, ol) : NULL;

    return e->oth != NULL ? 0 : -1;
}


/* Load the memo. Absent file = empty memo; a malformed memo is discarded
 * whole (it is only a cache) with a warning. */
static void
cr_cache_load(const char *dir, entv_t *out)
{
    char  path[CR_PATH_MAX], line[CR_PATH_MAX + 256];
    FILE *f;
    int   bad = 0;

    if (snprintf(path, sizeof(path), "%s/repodata/" CR_CACHE_NAME, dir) >=
        (int) sizeof(path)) {
        return;
    }
    f = fopen(path, "r");
    if (f == NULL) {
        return;
    }
    if (fgets(line, sizeof(line), f) == NULL ||
        strcmp(line, CR_CACHE_MAGIC) != 0) {
        bad = 1;
    }
    while (!bad && fgets(line, sizeof(line), f) != NULL) {
        bad = (cr_cache_read_ent(f, line, out) != 0);
    }
    fclose(f);
    if (bad) {
        fprintf(stderr, "brixrpm: warning: %s malformed — ignoring memo\n",
                path);
        entv_free(out);
        memset(out, 0, sizeof(*out));
    }
    qsort(out->v, out->n, sizeof(*out->v), ent_cmp);
}

/* Rewrite the memo (staged + rename; a torn memo must never be loadable). */
static int
cr_cache_save(const char *dir, const entv_t *ev)
{
    char   fin[CR_PATH_MAX], tmp[CR_PATH_MAX], rd[CR_PATH_MAX];
    FILE  *f;
    size_t i;
    int    ok = 1;

    if (snprintf(rd, sizeof(rd), "%s/repodata", dir) >= (int) sizeof(rd) ||
        snprintf(fin, sizeof(fin), "%s/" CR_CACHE_NAME, rd) >=
            (int) sizeof(fin) ||
        snprintf(tmp, sizeof(tmp), "%s/" CR_CACHE_NAME ".tmp", rd) >=
            (int) sizeof(tmp)) {
        return -1;
    }
    if (mkdir(rd, 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    f = fopen(tmp, "w");
    if (f == NULL) {
        return -1;
    }
    ok = fputs(CR_CACHE_MAGIC, f) >= 0;
    for (i = 0; ok && i < ev->n; i++) {
        const cr_ent_t *e = &ev->v[i];

        ok = fprintf(f, "pkg %lld %lld %zu %zu %zu %s %s\n", e->size,
                     e->mtime, strlen(e->pri), strlen(e->fil),
                     strlen(e->oth), e->pkgid, e->href) > 0 &&
             fputs(e->pri, f) >= 0 && fputs(e->fil, f) >= 0 &&
             fputs(e->oth, f) >= 0;
    }
    if (fclose(f) != 0) {
        ok = 0;
    }
    if (!ok || rename(tmp, fin) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

/* Parse + render one package into a fresh memo entry. 0 ok / 1 skip (bad
 * package, non-strict) / -1 fatal. */
static int
cr_parse_one(const brixrpm_cr_opts_t *o, const char *href, cr_ent_t *e,
             long long mtime, cr_stats_t *st, char *err, size_t errlen)
{
    char            full[CR_PATH_MAX];
    brix_rpm_pkg_t *p;
    int             rc;

    if (snprintf(full, sizeof(full), "%s/%s", o->dir, href) >=
        (int) sizeof(full)) {
        snprintf(err, errlen, "%s: path too long", href);
        return o->strict ? -1 : 1;
    }
    p = brix_rpm_open(full, err, errlen);
    if (p == NULL) {
        return o->strict ? -1 : 1;
    }
    rc = brix_repomd_render(p, href, mtime, &e->pri, &e->fil, &e->oth,
                            &st->sanitized, err, errlen);
    if (rc == 0) {
        snprintf(e->pkgid, sizeof(e->pkgid), "%s", brix_rpm_pkgid(p));
    }
    brix_rpm_close(p);
    /* A render failure is OOM *or* a malformed file list, and the file list is
     * attacker-controlled: a DIRINDEXES entry pointing past DIRNAMES arrives
     * here, not at brix_rpm_open(). That is the same answer as an unparsable
     * header — warn and skip, and let --strict decide whether one bad package
     * is allowed to fail the whole repo. */
    return rc == 0 ? 0 : (o->strict ? -1 : 1);
}

/* Republish a package straight from the memo: emit its three stored fragments
 * and carry the record into this run's memo. The strings are copied rather
 * than aliased — the old memo is freed as a unit at the end of the run, and a
 * fresh entry pointing into it would dangle at the next republish. */
static int
cr_reuse_cached(brix_repomd_t *w, const cr_ent_t *hit, entv_t *fresh,
                char *err, size_t errlen)
{
    cr_ent_t  *ke = entv_push(fresh);

    if (ke == NULL ||
        brix_repomd_add_fragments(w, hit->pri, hit->fil, hit->oth, err,
                                  errlen) != 0) {
        return -1;
    }
    *ke      = *hit;
    ke->href = strdup(hit->href);
    ke->pri  = strdup(hit->pri);
    ke->fil  = strdup(hit->fil);
    ke->oth  = strdup(hit->oth);

    return (ke->href == NULL || ke->pri == NULL || ke->fil == NULL ||
            ke->oth == NULL) ? -1 : 0;
}


/* Is the memo entry still the truth about this file? Size must match either
 * way — it is the free discriminator. Then --paranoid re-reads the package
 * and compares its sha256 against the pkgid the memo recorded, where the
 * default trusts the mtime instead.
 *
 * The gap that buys: a package REWRITTEN IN PLACE at the same length with the
 * timestamp preserved (a rebuild copied with `cp -p`, an rsync without
 * --checksum, a tampered mirror leg) is invisible to (size, mtime) and would
 * be republished under its old checksum — metadata that names bytes the file
 * no longer holds. Under --paranoid that is caught, counted and re-parsed;
 * an unchanged package still skips the header walk and the render, so the
 * flag costs one read pass, not a rebuild. */
static int
cr_memo_trusts(const brixrpm_cr_opts_t *o, const cr_ent_t *hit,
               const struct stat *fs, const char *full, cr_stats_t *st)
{
    char hex[65];
    char err[512];

    if (hit->size != (long long) fs->st_size) {
        return 0;
    }
    if (!o->paranoid) {
        return hit->mtime == (long long) fs->st_mtime;
    }
    if (brix_rpm_file_sha256(full, hex, sizeof(hex), err, sizeof(err)) != 0) {
        fprintf(stderr, "brixrpm: warning: %s (re-parsing)\n", err);
        return 0;
    }
    if (strcmp(hex, hit->pkgid) == 0) {
        return 1;
    }
    fprintf(stderr, "brixrpm: warning: %s changed in place under an "
            "unchanged (size, mtime) — re-parsing\n", hit->href);
    st->drifted++;
    return 0;
}


/* One href through the memo-or-parse decision into the writer + new memo. */
static int
cr_add_one(const brixrpm_cr_opts_t *o, brix_repomd_t *w, const char *href,
           const entv_t *old, entv_t *fresh, cr_stats_t *st, char *err,
           size_t errlen)
{
    char            full[CR_PATH_MAX];
    struct stat     fs;
    const cr_ent_t *hit;
    cr_ent_t        ne;
    int             rc;

    if (snprintf(full, sizeof(full), "%s/%s", o->dir, href) >=
            (int) sizeof(full) || stat(full, &fs) != 0) {
        snprintf(err, errlen, "%s: %s", href, strerror(errno));
        return o->strict ? -1 : 1;
    }

    hit = o->update ? ent_find(old, href) : NULL;
    if (hit != NULL && cr_memo_trusts(o, hit, &fs, full, st)) {
        if (cr_reuse_cached(w, hit, fresh, err, errlen) != 0) {
            return -1;
        }
        st->cached++;
        return 0;
    }

    memset(&ne, 0, sizeof(ne));
    ne.size  = (long long) fs.st_size;
    ne.mtime = (long long) fs.st_mtime;
    rc = cr_parse_one(o, href, &ne, (long long) fs.st_mtime, st, err,
                      errlen);
    if (rc != 0) {
        return rc;
    }
    ne.href = strdup(href);
    if (ne.href == NULL ||
        brix_repomd_add_fragments(w, ne.pri, ne.fil, ne.oth, err,
                                  errlen) != 0) {
        ent_free_payload(&ne);
        return -1;
    }
    {
        cr_ent_t *ke = entv_push(fresh);

        if (ke == NULL) {
            ent_free_payload(&ne);
            return -1;
        }
        *ke = ne;
    }
    st->parsed++;
    return 0;
}

/* The pump: every scanned href into the writer, memoizing as we go. */
static int
cr_pump(const brixrpm_cr_opts_t *o, brix_repomd_t *w, const strv_t *hrefs,
        const entv_t *old, entv_t *fresh, cr_stats_t *st, char *err,
        size_t errlen)
{
    size_t i;

    for (i = 0; i < hrefs->n; i++) {
        int rc = cr_add_one(o, w, hrefs->v[i], old, fresh, st, err, errlen);

        if (rc < 0) {
            return -1;
        }
        if (rc > 0) {
            fprintf(stderr, "brixrpm: warning: %s (skipped)\n", err);
            st->skipped++;
        }
    }
    return 0;
}

/* The tail of the summary line. --paranoid's whole product is the count of
 * packages whose bytes moved under a still-plausible (size, mtime); it is
 * silence-by-default because a zero there is the normal case and a run that
 * never re-hashed has nothing to say at all. */
static const char *
cr_drift_note(const cr_stats_t *st, char *buf, size_t buflen)
{
    if (st->drifted == 0) {
        return "";
    }
    snprintf(buf, buflen, ", %u changed-in-place", st->drifted);
    return buf;
}


int
brixrpm_createrepo(const brixrpm_cr_opts_t *o)
{
    char           err[512] = "";
    char           note[64];
    strv_t         hrefs = {0};
    entv_t         old = {0}, fresh = {0};
    cr_stats_t     st = {0, 0, 0, 0, 0};
    brix_repomd_t *w = NULL;
    int            rc = -1;

    if (cr_scan(o->dir, "", &hrefs) == 0) {
        qsort(hrefs.v, hrefs.n, sizeof(*hrefs.v), strp_cmp);
        if (o->update) {
            cr_cache_load(o->dir, &old);
        }
        w = brix_repomd_begin(o->dir, err, sizeof(err));
        if (w != NULL) {
            rc = cr_pump(o, w, &hrefs, &old, &fresh, &st, err, sizeof(err));
        }
    }

    if (rc == 0) {
        if (cr_cache_save(o->dir, &fresh) != 0) {
            fprintf(stderr, "brixrpm: warning: could not write %s memo\n",
                    CR_CACHE_NAME);
        }
        rc = brix_repomd_finish(w, err, sizeof(err));
        if (rc == 0) {
            w = NULL;    /* finish consumed it */
            printf("brixrpm: createrepo %s: %u packages (%u parsed, "
                   "%u cached, %u skipped, %u paths-sanitized%s)\n", o->dir,
                   st.parsed + st.cached, st.parsed, st.cached, st.skipped,
                   st.sanitized, cr_drift_note(&st, note, sizeof(note)));
        }
    }
    if (rc != 0 && err[0] != '\0') {
        fprintf(stderr, "brixrpm: %s\n", err);
    }
    brix_repomd_abort(w);    /* NULL-safe; live only on failure */
    strv_free(&hrefs);
    entv_free(&old);
    entv_free(&fresh);
    return rc == 0 ? 0 : 1;
}
