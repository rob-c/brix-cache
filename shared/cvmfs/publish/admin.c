/* admin.c — Stratum-0 GC + tags over the publish engine's trust chain.
 * See admin.h; shares pub_* plumbing via publish_internal.h.
 *
 * GC is reflog-anchored mark & sweep: the keep set is decided ONLY from a
 * checksum-verified reflog, the mark set is built by walking every kept root
 * catalog through CAS-identity-verified fetches, and references are dropped
 * (reflog prune + manifest re-sign) BEFORE any file is unlinked, so a crash
 * mid-sweep leaves garbage, never dangling references. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L         /* mkdir/unlink & friends under -std=c11 */
#endif
#include "cvmfs/publish/publish_internal.h"
#include "cvmfs/publish/admin.h"
#include "cvmfs/reflog/reflog.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ---- shared context setup ------------------------------------------------ */

static void adm_init(pub_ctx_t *px, cvmfs_publish_opts_t *o,
                     const char *repo_dir, const char *keys_dir,
                     char *err, size_t errlen) {
    memset(o, 0, sizeof(*o));
    memset(px, 0, sizeof(*px));
    o->repo_dir = repo_dir;
    o->keys_dir = keys_dir;
    px->o = o;
    px->err = err;
    px->errlen = errlen;
}

static int adm_workdir(pub_ctx_t *px, const char *name) {
    snprintf(px->workdir, sizeof(px->workdir), "%s/%s", px->o->repo_dir, name);
    if (mkdir(px->workdir, 0755) != 0 && errno != EEXIST)
        return pub_fail(px, "cannot create %s", px->workdir);
    return 0;
}

static void adm_close(pub_ctx_t *px) {
    if (px->workdir[0]) rmdir(px->workdir);
    free(px->manbuf);
    px->manbuf = NULL;
}

/* ---- GC: lock + reflog guards -------------------------------------------- */

/* The .brixtxn dir doubles as the mutual-exclusion point with transactions:
 * an active transaction owns it, so mkdir(EEXIST) refuses; taking it (dir +
 * O_EXCL lock file, the transaction protocol) keeps `transaction` out while
 * gc runs. An existing lock is NEVER broken automatically. */
static int gc_lock_take(pub_ctx_t *px, char *lockdir, size_t cap) {
    snprintf(lockdir, cap, "%s/.brixtxn", px->o->repo_dir);
    if (mkdir(lockdir, 0755) != 0) {
        if (errno == EEXIST)
            return pub_fail(px, "transaction in progress (%s exists) — gc refused",
                            lockdir);
        return pub_fail(px, "cannot create %s", lockdir);
    }
    char lock[PUB_PATH_MAX + 16];
    snprintf(lock, sizeof(lock), "%s/lock", lockdir);
    int fd = open(lock, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
        rmdir(lockdir);
        return pub_fail(px, "cannot take %s", lock);
    }
    dprintf(fd, "pid:%d\ngc\n", (int) getpid());
    close(fd);
    return 0;
}

static void gc_lock_drop(const char *lockdir) {
    char lock[PUB_PATH_MAX + 16];
    snprintf(lock, sizeof(lock), "%s/lock", lockdir);
    unlink(lock);
    rmdir(lockdir);
}

static int gc_check_reflog(pub_ctx_t *px, const char *reflog) {
    if (px->man.reflog_checksum.len == 0)
        return pub_fail(px, "manifest carries no reflog checksum — gc refused%s", "");
    cvmfs_hash_t got;
    if (cvmfs_reflog_checksum(reflog, &got) != 0)
        return pub_fail(px, "reflog required for gc: cannot read %s", reflog);
    if (!cvmfs_hash_eq(&got, &px->man.reflog_checksum))
        return pub_fail(px, "reflog checksum mismatch — refusing to sweep%s", "");
    return 0;
}

/* ---- GC: mark set + reflog collection ------------------------------------ */

typedef struct { unsigned char k[21]; } gc_key_t;    /* 20 hash bytes + suffix */
typedef struct { gc_key_t *v; size_t n, cap; } gc_set_t;
typedef struct { cvmfs_hash_t h; int64_t ts; } gc_ref_t;
typedef struct { gc_ref_t *v; size_t n, cap; } gc_refs_t;

static int gc_set_add(gc_set_t *s, const unsigned char *bytes, char suffix) {
    if (s->n == s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : 256;
        gc_key_t *nv = realloc(s->v, ncap * sizeof(*nv));
        if (nv == NULL) return -1;
        s->v = nv;
        s->cap = ncap;
    }
    memcpy(s->v[s->n].k, bytes, 20);
    s->v[s->n].k[20] = (unsigned char) suffix;
    s->n++;
    return 0;
}

static int gc_key_cmp(const void *a, const void *b) {
    return memcmp(a, b, sizeof(gc_key_t));
}

typedef struct {
    gc_refs_t cats;                      /* CATALOG refs, newest first */
    gc_set_t *mark;                      /* non-catalog refs marked directly */
    int       oom;
} gc_collect_t;

static void gc_collect_cb(const cvmfs_hash_t *h, cvmfs_reflog_type_e t,
                          int64_t ts, void *ud) {
    static const char suffix[4] = { 'C', 'X', 'H', 'M' };
    gc_collect_t *c = ud;
    if (c->oom) return;
    if (t != CVMFS_REFLOG_CATALOG) {
        c->oom = gc_set_add(c->mark, h->bytes, suffix[t & 3]) != 0;
        return;
    }
    if (c->cats.n == c->cats.cap) {
        size_t ncap = c->cats.cap ? c->cats.cap * 2 : 16;
        gc_ref_t *nv = realloc(c->cats.v, ncap * sizeof(*nv));
        if (nv == NULL) {
            c->oom = 1;
            return;
        }
        c->cats.v = nv;
        c->cats.cap = ncap;
    }
    c->cats.v[c->cats.n].h = *h;
    c->cats.v[c->cats.n].ts = ts;
    c->cats.n++;
}

static int gc_collect(pub_ctx_t *px, const char *reflog, gc_collect_t *c) {
    cvmfs_reflog_t *rl = cvmfs_reflog_open(reflog);
    int n = rl != NULL ? cvmfs_reflog_list(rl, -1, gc_collect_cb, c) : -1;
    if (rl != NULL) cvmfs_reflog_close(rl);
    if (n < 0 || c->oom)
        return pub_fail(px, "cannot enumerate %s", reflog);
    return 0;
}

/* ---- GC: recursive catalog mark ------------------------------------------ */

static int gc_mark_blob_col(pub_ctx_t *px, sqlite3 *db, const char *sql,
                            char suffix, gc_set_t *mark) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return pub_fail(px, "catalog mark query failed%s", "");
    int rc = 0;
    for (;;) {
        int s = sqlite3_step(st);
        if (s == SQLITE_DONE) break;
        const void *b = s == SQLITE_ROW ? sqlite3_column_blob(st, 0) : NULL;
        if (b == NULL || sqlite3_column_bytes(st, 0) != 20
            || gc_set_add(mark, b, suffix) != 0) {
            rc = pub_fail(px, "catalog mark scan failed%s", "");
            break;
        }
    }
    sqlite3_finalize(st);
    return rc;
}

static int gc_mark_catalog(pub_ctx_t *px, const cvmfs_hash_t *h,
                           gc_set_t *mark, int depth);

static int gc_mark_nested(pub_ctx_t *px, sqlite3 *db, gc_set_t *mark, int depth) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT sha1 FROM nested_catalogs", -1,
                           &st, NULL) != SQLITE_OK)
        return pub_fail(px, "catalog mark query failed%s", "");
    int rc = 0;
    while (rc == 0) {
        int s = sqlite3_step(st);
        if (s == SQLITE_DONE) break;
        const unsigned char *hex = s == SQLITE_ROW ? sqlite3_column_text(st, 0)
                                                   : NULL;
        cvmfs_hash_t ch;
        if (hex == NULL || cvmfs_hash_parse((const char *) hex,
                                            strlen((const char *) hex), &ch) != 0)
            rc = pub_fail(px, "malformed nested_catalogs row%s", "");
        else
            rc = gc_mark_catalog(px, &ch, mark, depth + 1);
    }
    sqlite3_finalize(st);
    return rc;
}

static int gc_mark_catalog(pub_ctx_t *px, const cvmfs_hash_t *h,
                           gc_set_t *mark, int depth) {
    if (depth > 64)
        return pub_fail(px, "catalog nesting too deep%s", "");
    if (gc_set_add(mark, h->bytes, 'C') != 0)
        return pub_fail(px, "out of memory building mark set%s", "");
    size_t plen = 0;
    unsigned char *plain = pub_fetch_catalog(px, h, &plen);
    if (plain == NULL) return -1;
    char tmp[PUB_PATH_MAX + 32];
    snprintf(tmp, sizeof(tmp), "%s/gc.%d.db", px->workdir, px->seq++);
    int rc = pub_spit(tmp, plain, plen, 0);
    free(plain);
    sqlite3 *db = NULL;
    if (rc != 0 || sqlite3_open_v2(tmp, &db, SQLITE_OPEN_READONLY, NULL)
                   != SQLITE_OK) {
        if (db != NULL) sqlite3_close(db);
        unlink(tmp);
        return pub_fail(px, "cannot open catalog for marking%s", "");
    }
    rc = gc_mark_blob_col(px, db,
             "SELECT hash FROM catalog WHERE hash IS NOT NULL", 0, mark);
    /* BRIX_CVMFS_GC_MUTATION=skip-chunk-mark: TEST-ONLY fault injection — the
     * gc security-negative lane flips it to prove chunk marking has teeth. */
    const char *mut = getenv("BRIX_CVMFS_GC_MUTATION");
    if (rc == 0 && (mut == NULL || strcmp(mut, "skip-chunk-mark") != 0))
        rc = gc_mark_blob_col(px, db, "SELECT hash FROM chunks", 'P', mark);
    if (rc == 0) rc = gc_mark_nested(px, db, mark, depth);
    sqlite3_close(db);
    unlink(tmp);
    return rc;
}

/* ---- GC: tag pins -------------------------------------------------------- */

static int tag_fetch_history(pub_ctx_t *px, char *hist, size_t cap);

typedef struct { cvmfs_hash_t *v; size_t n, cap; int oom; } gc_pins_t;

static void gc_pins_cb(const cvmfs_history_tag_t *t, void *ud) {
    gc_pins_t *p = ud;
    if (p->oom) return;
    if (p->n == p->cap) {
        size_t ncap = p->cap ? p->cap * 2 : 8;
        cvmfs_hash_t *nv = realloc(p->v, ncap * sizeof(*nv));
        if (nv == NULL) {
            p->oom = 1;
            return;
        }
        p->v = nv;
        p->cap = ncap;
    }
    p->v[p->n++] = t->root_hash;
}

/* Root catalogs named by a tag are pinned: gc never drops them (upstream
 * semantics — rollback must stay possible after gc). Pins only protect refs
 * still in the reflog, so a tag already dangling can never wedge gc. */
static int gc_load_pins(pub_ctx_t *px, gc_pins_t *pins) {
    if (px->man.history.len == 0) return 0;
    char hist[PUB_PATH_MAX + 16];
    if (tag_fetch_history(px, hist, sizeof(hist)) != 0) return -1;
    cvmfs_history_t *h = cvmfs_history_open(hist, NULL);
    int n = h != NULL ? cvmfs_history_list(h, gc_pins_cb, pins) : -1;
    if (h != NULL) cvmfs_history_close(h);
    unlink(hist);
    if (n < 0 || pins->oom)
        return pub_fail(px, "cannot read tag database for gc pinning%s", "");
    return 0;
}

/* Which catalog refs survive: the newest keep_n, anything at/after keep_since,
 * tag-pinned roots, and unconditionally the current manifest root. */
static int gc_keep(const cvmfs_gc_opts_t *o, const pub_ctx_t *px,
                   const gc_pins_t *pins, const gc_ref_t *r, size_t idx) {
    if (cvmfs_hash_eq(&r->h, &px->man.root_catalog)) return 1;
    if (o->keep_n > 0 && idx < (size_t) o->keep_n) return 1;
    if (o->keep_since > 0 && r->ts >= o->keep_since) return 1;
    for (size_t i = 0; i < pins->n; i++)
        if (cvmfs_hash_eq(&r->h, &pins->v[i])) return 1;
    return 0;
}

static int gc_mark_kept(pub_ctx_t *px, const cvmfs_gc_opts_t *o,
                        const gc_refs_t *cats, gc_set_t *mark,
                        gc_refs_t *drop, cvmfs_gc_stats_t *st) {
    gc_pins_t pins;
    memset(&pins, 0, sizeof(pins));
    if (gc_load_pins(px, &pins) != 0) {
        free(pins.v);
        return -1;
    }
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < cats->n; i++) {
        if (gc_keep(o, px, &pins, &cats->v[i], i)) {
            rc = gc_mark_catalog(px, &cats->v[i].h, mark, 0);
            st->kept_revisions++;
        } else {
            drop->v[drop->n++] = cats->v[i];     /* cap == cats->n, never grows */
            st->dropped_revisions++;
        }
    }
    free(pins.v);
    if (rc != 0) return -1;
    rc = gc_set_add(mark, px->man.certificate.bytes, 'X');
    if (rc == 0 && px->man.history.len > 0)
        rc = gc_set_add(mark, px->man.history.bytes, 'H');
    return rc == 0 ? 0 : pub_fail(px, "out of memory building mark set%s", "");
}

/* ---- GC: reference drop + sweep ------------------------------------------ */

/* Prune dropped refs and re-sign the manifest (same root, same revision,
 * fresh 'Y') BEFORE the sweep unlinks anything. */
static int gc_drop_refs(pub_ctx_t *px, const char *reflog, const gc_refs_t *drop) {
    cvmfs_reflog_t *rl = cvmfs_reflog_open(reflog);
    if (rl == NULL) return pub_fail(px, "cannot open %s", reflog);
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < drop->n; i++)
        rc = cvmfs_reflog_del(rl, &drop->v[i].h, CVMFS_REFLOG_CATALOG);
    if (cvmfs_reflog_close(rl) != 0) rc = -1;
    if (rc != 0) return pub_fail(px, "cannot prune %s", reflog);
    cvmfs_hash_t root = px->man.root_catalog;
    return pub_swap_manifest(px, &root, (size_t) px->man.catalog_size,
                             px->man.revision);
}

/* One 40-hex CAS name (+ optional suffix) → 21-byte lookup key; -1 = not CAS. */
static int gc_parse_name(const char *dir2, const char *name, gc_key_t *out) {
    size_t n = strlen(name);
    if (n != 38 && n != 39) return -1;
    char hex[41];
    memcpy(hex, dir2, 2);
    memcpy(hex + 2, name, 38);
    hex[40] = '\0';
    cvmfs_hash_t h;
    if (cvmfs_hash_parse(hex, 40, &h) != 0) return -1;
    memcpy(out->k, h.bytes, 20);
    out->k[20] = n == 39 ? (unsigned char) name[38] : 0;
    return 0;
}

static void gc_sweep_dir(pub_ctx_t *px, const gc_set_t *mark, const char *dir2,
                         time_t cutoff, long *swept) {
    char path[PUB_PATH_MAX];
    snprintf(path, sizeof(path), "%s/data/%s", px->o->repo_dir, dir2);
    DIR *d = opendir(path);
    if (d == NULL) return;               /* fan-out dir absent: nothing there */
    const struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        gc_key_t key;
        if (gc_parse_name(dir2, e->d_name, &key) != 0) continue;
        if (bsearch(&key, mark->v, mark->n, sizeof(key), gc_key_cmp) != NULL)
            continue;
        char obj[PUB_PATH_MAX + 300];    /* path + '/' + d_name (≤255) */
        snprintf(obj, sizeof(obj), "%s/%s", path, e->d_name);
        struct stat sb;
        if (stat(obj, &sb) != 0 || sb.st_mtime > cutoff)
            continue;                    /* grace: too young to sweep safely */
        if (unlink(obj) == 0) (*swept)++;
    }
    closedir(d);
}

static int gc_execute(pub_ctx_t *px, const cvmfs_gc_opts_t *o, const char *reflog,
                      gc_collect_t *c, cvmfs_gc_stats_t *st) {
    gc_refs_t drop;
    memset(&drop, 0, sizeof(drop));
    drop.v = calloc(c->cats.n ? c->cats.n : 1, sizeof(*drop.v));
    if (drop.v == NULL)
        return pub_fail(px, "out of memory building drop set%s", "");
    int rc = gc_mark_kept(px, o, &c->cats, c->mark, &drop, st);
    if (rc == 0) {
        qsort(c->mark->v, c->mark->n, sizeof(gc_key_t), gc_key_cmp);
        rc = gc_drop_refs(px, reflog, &drop);
    }
    if (rc == 0) {
        time_t cutoff = time(NULL)
                      - (o->grace_seconds > 0 ? o->grace_seconds : 0);
        for (int i = 0; i < 256; i++) {
            char d2[3];
            snprintf(d2, sizeof(d2), "%02x", i);
            gc_sweep_dir(px, c->mark, d2, cutoff, &st->swept_objects);
        }
    }
    free(drop.v);
    return rc;
}

int cvmfs_gc_run(const cvmfs_gc_opts_t *o, cvmfs_gc_stats_t *st,
                 char *err, size_t errlen) {
    cvmfs_publish_opts_t po;
    pub_ctx_t px;
    adm_init(&px, &po, o->repo_dir, o->keys_dir, err, errlen);
    memset(st, 0, sizeof(*st));
    if (o->keep_n <= 0 && o->keep_since <= 0)
        return pub_fail(&px, "gc needs --keep N or --keep-since T%s", "");
    char lockdir[PUB_PATH_MAX];
    if (gc_lock_take(&px, lockdir, sizeof(lockdir)) != 0) return -1;
    char reflog[PUB_PATH_MAX];
    snprintf(reflog, sizeof(reflog), "%s/.cvmfsreflog", o->repo_dir);
    gc_set_t mark;
    gc_collect_t c;
    memset(&mark, 0, sizeof(mark));
    memset(&c, 0, sizeof(c));
    c.mark = &mark;
    int rc = adm_workdir(&px, ".brixtxn/gc.tmp");
    if (rc == 0) rc = pub_load_and_verify(&px);
    if (rc == 0) rc = gc_check_reflog(&px, reflog);
    if (rc == 0) rc = gc_collect(&px, reflog, &c);
    if (rc == 0) rc = gc_execute(&px, o, reflog, &c, st);
    free(c.cats.v);
    free(mark.v);
    adm_close(&px);
    gc_lock_drop(lockdir);
    return rc;
}

/* ---- tags ---------------------------------------------------------------- */

/* Materialize the manifest's history DB into the workdir.
 * 0 = written, 1 = repo has no history object yet, -1 = error. */
static int tag_fetch_history(pub_ctx_t *px, char *hist, size_t cap) {
    snprintf(hist, cap, "%s/hist.db", px->workdir);
    if (px->man.history.len == 0) return 1;
    size_t plen = 0;
    unsigned char *plain = pub_fetch_object(px, &px->man.history, 'H', &plen);
    if (plain == NULL) return -1;
    int rc = pub_spit(hist, plain, plen, 0);
    free(plain);
    return rc == 0 ? 0 : pub_fail(px, "cannot materialize history DB%s", "");
}

static int tag_row_insert(pub_ctx_t *px, const char *hist, int fresh,
                          const char *name, const char *desc) {
    cvmfs_history_t *h = cvmfs_history_open(hist, fresh ? px->man.repo_name : NULL);
    if (h == NULL) return pub_fail(px, "cannot open history DB%s", "");
    cvmfs_history_tag_t t;
    memset(&t, 0, sizeof(t));
    snprintf(t.name, sizeof(t.name), "%s", name);
    t.root_hash = px->man.root_catalog;
    t.revision = px->man.revision;
    t.timestamp = (int64_t) time(NULL);
    if (desc != NULL) snprintf(t.description, sizeof(t.description), "%s", desc);
    int rc = cvmfs_history_tag_add(h, &t);
    if (cvmfs_history_close(h) != 0) rc = -1;
    return rc == 0 ? 0 : pub_fail(px, "cannot record tag %s", name);
}

/* CAS-store the updated history DB, log it in the reflog, and re-sign the
 * manifest with the new 'H' (same root, same revision, fresh 'Y'). */
static int tag_store_history(pub_ctx_t *px, const char *hist) {
    size_t len = 0;
    unsigned char *buf = pub_slurp(hist, &len);
    if (buf == NULL) return pub_fail(px, "cannot read back history DB%s", "");
    cvmfs_objstore_t store;
    cvmfs_hash_t hh;
    int rc = -1;
    if (cvmfs_objstore_open(&store, px->o->repo_dir) == 0) {
        rc = cvmfs_object_store(&store, buf, len, 'H', 1, &hh, NULL);
        cvmfs_objstore_close(&store);
    }
    free(buf);
    if (rc != 0) return pub_fail(px, "cannot store history object%s", "");
    char reflog[PUB_PATH_MAX];
    snprintf(reflog, sizeof(reflog), "%s/.cvmfsreflog", px->o->repo_dir);
    cvmfs_reflog_t *rl = cvmfs_reflog_open(reflog);
    if (rl == NULL
        || cvmfs_reflog_add(rl, &hh, CVMFS_REFLOG_HISTORY,
                            (int64_t) time(NULL)) != 0
        || cvmfs_reflog_close(rl) != 0)
        return pub_fail(px, "cannot log history object in reflog%s", "");
    px->man.history = hh;
    cvmfs_hash_t root = px->man.root_catalog;
    return pub_swap_manifest(px, &root, (size_t) px->man.catalog_size,
                             px->man.revision);
}

int cvmfs_tag_add(const char *repo_dir, const char *keys_dir, const char *name,
                  const char *description, char *err, size_t errlen) {
    cvmfs_publish_opts_t po;
    pub_ctx_t px;
    adm_init(&px, &po, repo_dir, keys_dir, err, errlen);
    if (name == NULL || name[0] == '\0' || strlen(name) >= 128)
        return pub_fail(&px, "invalid tag name%s", "");
    int rc = adm_workdir(&px, ".brix.tag.tmp");
    if (rc == 0) rc = pub_load_and_verify(&px);
    char hist[PUB_PATH_MAX + 16] = "";
    int have = rc == 0 ? tag_fetch_history(&px, hist, sizeof(hist)) : -1;
    if (rc == 0 && have < 0) rc = -1;
    if (rc == 0) rc = tag_row_insert(&px, hist, have == 1, name, description);
    if (rc == 0) rc = tag_store_history(&px, hist);
    if (hist[0]) unlink(hist);
    adm_close(&px);
    return rc;
}

int cvmfs_tag_list(const char *repo_dir, cvmfs_history_cb cb, void *ud,
                   char *err, size_t errlen) {
    cvmfs_publish_opts_t po;
    pub_ctx_t px;
    adm_init(&px, &po, repo_dir, NULL, err, errlen);
    int rc = adm_workdir(&px, ".brix.tag.tmp");
    if (rc == 0) rc = pub_load_and_verify(&px);
    char hist[PUB_PATH_MAX + 16] = "";
    int n = -1;
    int have = rc == 0 ? tag_fetch_history(&px, hist, sizeof(hist)) : -1;
    if (have == 1) {
        n = 0;                           /* no history object yet: zero tags */
    } else if (have == 0) {
        cvmfs_history_t *h = cvmfs_history_open(hist, NULL);
        n = h != NULL ? cvmfs_history_list(h, cb, ud) : -1;
        if (h != NULL) cvmfs_history_close(h);
        if (n < 0) pub_fail(&px, "cannot enumerate history DB%s", "");
        unlink(hist);
    }
    adm_close(&px);
    return n;
}

static int tag_lookup(pub_ctx_t *px, const char *name, cvmfs_history_tag_t *out) {
    char hist[PUB_PATH_MAX + 16];
    int have = tag_fetch_history(px, hist, sizeof(hist));
    if (have < 0) return -1;
    if (have == 1) return pub_fail(px, "repository has no tags%s", "");
    cvmfs_history_t *h = cvmfs_history_open(hist, NULL);
    int got = h != NULL ? cvmfs_history_tag_get(h, name, out) : -1;
    if (h != NULL) cvmfs_history_close(h);
    unlink(hist);
    if (got == 1) return 0;
    if (got == 0) return pub_fail(px, "unknown tag %s", name);
    return pub_fail(px, "cannot read history DB%s", "");
}

/* The tagged tree comes back as a NEW catalog object: same rows, but with
 * revision/previous_revision/last_modified rewritten so the republished root
 * is self-consistent with the manifest that will carry it. */
static int tag_republish_catalog(pub_ctx_t *px, const cvmfs_hash_t *tagged,
                                 long newrev, cvmfs_hash_t *out, size_t *out_size) {
    size_t plen = 0;
    unsigned char *plain = pub_fetch_catalog(px, tagged, &plen);
    if (plain == NULL) return -1;
    char db[PUB_PATH_MAX + 32];
    snprintf(db, sizeof(db), "%s/roll.%d.db", px->workdir, px->seq++);
    int rc = pub_spit(db, plain, plen, 0);
    free(plain);
    cvmfs_catwriter_t *w = rc == 0 ? cvmfs_catwriter_open(db) : NULL;
    if (w == NULL) {
        unlink(db);
        return pub_fail(px, "cannot open tagged catalog%s", "");
    }
    char rev[32], oldhex[64];
    snprintf(rev, sizeof(rev), "%ld", newrev);
    cvmfs_hash_to_hex(&px->man.root_catalog, 0, oldhex, sizeof(oldhex));
    char now[32];
    snprintf(now, sizeof(now), "%lld", (long long) time(NULL));
    int ok = cvmfs_catwriter_set_property(w, "revision", rev) == 0
          && cvmfs_catwriter_set_property(w, "previous_revision", oldhex) == 0
          && cvmfs_catwriter_set_property(w, "last_modified", now) == 0
          && cvmfs_catwriter_commit(w) == 0;
    if (!ok) {
        unlink(db);
        return pub_fail(px, "cannot rewrite tagged catalog%s", "");
    }
    size_t len = 0;
    unsigned char *buf = pub_slurp(db, &len);
    unlink(db);
    if (buf == NULL) return pub_fail(px, "cannot read rewritten catalog%s", "");
    cvmfs_objstore_t store;
    rc = -1;
    if (cvmfs_objstore_open(&store, px->o->repo_dir) == 0) {
        rc = cvmfs_object_store(&store, buf, len, 'C', 1, out, out_size);
        cvmfs_objstore_close(&store);
    }
    free(buf);
    return rc == 0 ? 0 : pub_fail(px, "cannot store rewritten catalog%s", "");
}

int cvmfs_tag_rollback(const char *repo_dir, const char *keys_dir,
                       const char *name, long *new_revision,
                       char *err, size_t errlen) {
    cvmfs_publish_opts_t po;
    pub_ctx_t px;
    adm_init(&px, &po, repo_dir, keys_dir, err, errlen);
    int rc = adm_workdir(&px, ".brix.tag.tmp");
    if (rc == 0) rc = pub_load_and_verify(&px);
    cvmfs_history_tag_t t;
    if (rc == 0) rc = tag_lookup(&px, name, &t);
    long newrev = rc == 0 ? px.man.revision + 1 : 0;   /* NEVER rewinds */
    cvmfs_hash_t newroot;
    size_t newsize = 0;
    if (rc == 0)
        rc = tag_republish_catalog(&px, &t.root_hash, newrev, &newroot, &newsize);
    if (rc == 0) rc = pub_swap_manifest(&px, &newroot, newsize, newrev);
    if (rc == 0 && new_revision != NULL) *new_revision = newrev;
    adm_close(&px);
    return rc;
}
