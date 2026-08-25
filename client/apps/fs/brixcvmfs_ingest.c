/* brixcvmfs_ingest.c — `brixcvmfs ingest` front-end + the `dir` verb
 * (phase-104 D9). Unprivileged, tool-surface only (G14): no FUSE, no root.
 *
 *   brixcvmfs ingest dir <src_dir> --repo <repo_dir> --prefix /sw/foo/1.2
 *       [--delete] [--follow-symlinks=no] [--dry-run] [--keys-dir D]
 *       [--chunk-size N] [--no-wait]
 *
 * The folder → Tier-0 path: <src_dir> is scanned exactly as a transaction
 * upper tree (cvmfs_changeset_scan — containment, hardlink groups, xattrs),
 * the changeset is re-rooted under --prefix (cvmfs_changeset_reprefix), and
 * the phase-96 publish engine applies it. Without --delete the ingest is
 * add/overwrite-only (the safe default); --delete marks the prefix root
 * opaque so published content absent from src is removed (mirror-exact).
 *
 * A src tree is NOT an overlay upper, so names spelling the reserved
 * ".brix.wh./.brix.opq" grammar are refused rather than interpreted, and
 * symlinks are stored verbatim — never followed (the scan's O_NOFOLLOW
 * discipline; --follow-symlinks=no is the only accepted spelling).
 *
 * Serialization: the phase-96 transaction lock (.brixtxn/lock) is taken for
 * the publish leg — `repo transaction` and `ingest` can never interleave.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L         /* nanosleep/mkdir & co under -std=c11 */
#endif
#include "brixcvmfs_ingest_internal.h"
#include "cvmfs/publish/publish.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ---- shared helpers (also used by the image/prune TU) --------------------- */

int bci_fail(int code, const char *what, const char *detail) {
    return brixcvmfs_emit_err("ingest", what, detail, code);
}

int bci_mkdir_p(const char *path, unsigned mode) {
    char buf[ING_PATH_MAX];
    if (snprintf(buf, sizeof(buf), "%s", path) >= (int) sizeof(buf))
        return -1;
    for (char *p = buf + 1; *p != '\0'; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(buf, mode) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    return mkdir(buf, mode) == 0 || errno == EEXIST ? 0 : -1;
}

int bci_read_line(const char *path, char *buf, size_t buflen) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return -1;
    int ok = fgets(buf, (int) buflen, f) != NULL;
    fclose(f);
    if (!ok) return -1;
    buf[strcspn(buf, "\n")] = '\0';
    return 0;
}

int bci_write_atomic(const char *path, const char *data) {
    char dir[ING_PATH_MAX], tmp[ING_PATH_MAX + 8];
    if (snprintf(dir, sizeof(dir), "%s", path) >= (int) sizeof(dir))
        return -1;
    char *slash = strrchr(dir, '/');
    if (slash != NULL) {
        *slash = '\0';
        if (bci_mkdir_p(dir, 0755) != 0) return -1;
    }
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (f == NULL) return -1;
    int ok = fputs(data, f) >= 0;
    ok = fclose(f) == 0 && ok;
    if (!ok || rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

void bci_utc_now(char *out, size_t outlen) {
    time_t t = time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, outlen, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

int bci_lock_acquire(const char *repo_dir, int no_wait) {
    char txn[ING_PATH_MAX], lock[ING_PATH_MAX + 8];
    snprintf(txn, sizeof(txn), "%s/.brixtxn", repo_dir);
    snprintf(lock, sizeof(lock), "%s/lock", txn);
    int waited = 0;
    for (;;) {
        if (mkdir(txn, 0755) != 0 && errno != EEXIST)
            return bci_fail(ING_FAIL, "cannot create transaction dir", txn);
        if (brixcvmfs_tx_lock_take(lock) == 0)
            return ING_OK;
        /* ENOENT: the holder retired .brixtxn between mkdir and open — retry */
        if (errno != EEXIST && errno != ENOENT)
            return bci_fail(ING_FAIL, "cannot take transaction lock", lock);
        if (errno == EEXIST) {
            char upper[ING_PATH_MAX + 16];
            struct stat st;
            snprintf(upper, sizeof(upper), "%s/upper", txn);
            /* A crashed ingest leaves a lock with nothing behind it; a repo
             * transaction always has its durable upper — never broken. */
            if (lstat(upper, &st) != 0 && brixcvmfs_tx_lock_stale(lock)) {
                fprintf(stderr,
                        "brixcvmfs ingest: breaking stale lock (holder gone)\n");
                unlink(lock);
                continue;
            }
            char who[32];
            snprintf(who, sizeof(who), "pid %d", brixcvmfs_tx_lock_pid(lock));
            if (no_wait)
                return bci_fail(ING_BUSY, "transaction lock is held", who);
            if (!waited) {
                fprintf(stderr,
                        "brixcvmfs ingest: waiting for transaction lock (%s)\n",
                        who);
                waited = 1;
            }
            struct timespec ts = { 0, 200 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
    }
}

void bci_lock_release(const char *repo_dir) {
    char txn[ING_PATH_MAX], lock[ING_PATH_MAX + 8];
    snprintf(txn, sizeof(txn), "%s/.brixtxn", repo_dir);
    snprintf(lock, sizeof(lock), "%s/lock", txn);
    unlink(lock);
    rmdir(txn);                          /* leaves a foreign upper alone */
}

char *bci_memo_digest(char *line) {
    char *sp = strchr(line, ' ');
    if (sp == NULL) return NULL;
    char *dig = sp + 1;
    char *sp2 = strchr(dig, ' ');
    if (sp2 != NULL) *sp2 = '\0';
    return *dig != '\0' ? dig : NULL;
}

int bci_memo_refs(const char *memo_dir, const char *digest, const char *skip) {
    DIR *d = opendir(memo_dir);
    if (d == NULL) return 0;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char sub[ING_PATH_MAX];
        struct stat st;
        if (snprintf(sub, sizeof(sub), "%s/%s", memo_dir, e->d_name)
                >= (int) sizeof(sub)
            || lstat(sub, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode)) {
            n += bci_memo_refs(sub, digest, skip);
            continue;
        }
        if (strcmp(sub, skip) == 0) continue;
        char line[ING_PATH_MAX + 128];
        if (bci_read_line(sub, line, sizeof(line)) != 0) continue;
        const char *dig = bci_memo_digest(line);
        if (dig != NULL && strcmp(dig, digest) == 0) n++;
    }
    closedir(d);
    return n;
}

const char *bci_pfx(const char *prefix) {
    return strcmp(prefix, "/") == 0 ? "" : prefix;
}

cvmfs_change_t *bci_cs_append(cvmfs_changeset_t *cs) {
    if (cs->n == cs->cap) {
        size_t ncap = cs->cap != 0 ? cs->cap * 2 : 8;
        cvmfs_change_t *nv = realloc(cs->v, ncap * sizeof(*nv));
        if (nv == NULL) return NULL;
        cs->v = nv;
        cs->cap = ncap;
    }
    cvmfs_change_t *ch = &cs->v[cs->n++];
    memset(ch, 0, sizeof(*ch));
    return ch;
}

/* --prefix is validated before any scanning by running the remap over an
 * empty set (component grammar + length; "/" identity allowed). */
int bci_prefix_check(const char *prefix) {
    cvmfs_changeset_t probe;
    char err[512];
    memset(&probe, 0, sizeof(probe));
    int rc = cvmfs_changeset_reprefix(&probe, prefix, err, sizeof(err));
    cvmfs_changeset_free(&probe);
    return rc == 0 ? ING_OK : bci_fail(ING_USAGE, "bad --prefix", err);
}

/* ---- ingest dir ----------------------------------------------------------- */

typedef struct {
    const char *src, *repo, *keys_dir;
    char        prefix[ING_PATH_MAX];   /* normalized: no trailing '/' */
    long        chunk_size;
    int         del, dry_run, no_wait;
} ing_dir_opts_t;

static int ing_dir_usage(void) {
    fprintf(stderr,
        "usage: brixcvmfs ingest dir <src_dir> --repo <repo_dir>"
        " --prefix /path\n"
        "       [--delete] [--follow-symlinks=no] [--dry-run] [--keys-dir D]\n"
        "       [--chunk-size N] [--no-wait]\n");
    return ING_USAGE;
}

/* Parse one dir-ingest option while the caller owns argv iteration. */
static int ing_dir_option(int argc, char **argv, int *i, ing_dir_opts_t *o,
                          const char **prefix) {
    const char *arg = argv[*i];

    if (strcmp(arg, "--repo") == 0 && *i + 1 < argc)
        o->repo = argv[++*i];
    else if (strcmp(arg, "--prefix") == 0 && *i + 1 < argc)
        *prefix = argv[++*i];
    else if (strcmp(arg, "--keys-dir") == 0 && *i + 1 < argc)
        o->keys_dir = argv[++*i];
    else if (strcmp(arg, "--chunk-size") == 0 && *i + 1 < argc)
        o->chunk_size = atol(argv[++*i]);
    else if (strcmp(arg, "--delete") == 0)
        o->del = 1;
    else if (strcmp(arg, "--dry-run") == 0)
        o->dry_run = 1;
    else if (strcmp(arg, "--no-wait") == 0)
        o->no_wait = 1;
    else if (strcmp(arg, "--follow-symlinks=no") == 0)
        return ING_OK;
    else if (strncmp(arg, "--follow-symlinks=", 18) == 0)
        return bci_fail(ING_USAGE, "symlinks are never followed", arg);
    else
        return ing_dir_usage();
    return ING_OK;
}

static int ing_dir_parse(int argc, char **argv, ing_dir_opts_t *o) {
    const char *prefix = NULL;
    memset(o, 0, sizeof(*o));
    if (argc < 2 || argv[1][0] == '-') return ing_dir_usage();
    o->src = argv[1];
    for (int i = 2; i < argc; i++) {
        int rc = ing_dir_option(argc, argv, &i, o, &prefix);
        if (rc != ING_OK) return rc;
    }
    if (o->repo == NULL || prefix == NULL) return ing_dir_usage();
    size_t n = snprintf(o->prefix, sizeof(o->prefix), "%s", prefix);
    if (n >= sizeof(o->prefix))
        return bci_fail(ING_USAGE, "bad --prefix", "too long");
    while (n > 1 && o->prefix[n - 1] == '/') o->prefix[--n] = '\0';
    return ING_OK;
}

/* A src tree is not an overlay upper: reserved grammar is refused, never
 * interpreted (a whiteout scans as DELETE, a .brix.opq as the opaque flag).
 * The upper ROOT has no ADD_DIR op to carry the opaque flag, so a top-level
 * .brix.opq must be probed directly — the scan drops it silently. */
static int ing_dir_grammar_check(const char *src, const cvmfs_changeset_t *cs) {
    char opq[ING_PATH_MAX + 16];
    struct stat st;
    snprintf(opq, sizeof(opq), "%s/.brix.opq", src);
    if (lstat(opq, &st) == 0)
        return bci_fail(ING_FAIL,
            "src tree carries reserved overlay grammar (.brix.opq)", src);
    for (size_t i = 0; i < cs->n; i++) {
        if (cs->v[i].op == CVMFS_CH_DELETE)
            return bci_fail(ING_FAIL,
                "src tree carries reserved overlay grammar (.brix.wh.*)",
                cs->v[i].path);
        if (cs->v[i].op == CVMFS_CH_ADD_DIR && cs->v[i].opaque)
            return bci_fail(ING_FAIL,
                "src tree carries reserved overlay grammar (.brix.opq)",
                cs->v[i].path);
    }
    return ING_OK;
}

/* --delete: the reprefix-synthesized prefix root goes opaque, so the engine
 * clears the published subtree before applying the adds (mirror-exact). */
static void ing_dir_mark_mirror(cvmfs_changeset_t *cs, const char *prefix) {
    for (size_t i = 0; i < cs->n; i++)
        if (cs->v[i].op == CVMFS_CH_ADD_DIR
            && strcmp(cs->v[i].path, prefix) == 0)
            cs->v[i].opaque = 1;
}

static int ing_dir_dry_run(const cvmfs_changeset_t *cs, const ing_dir_opts_t *o) {
    size_t n[4] = { 0, 0, 0, 0 };
    for (size_t i = 0; i < cs->n; i++)
        n[cs->v[i].op & 3]++;
    printf("dry-run: %zu changes under %s (dirs %zu, files %zu, links %zu,"
           " deletes %zu)%s\n",
           cs->n, o->prefix, n[CVMFS_CH_ADD_DIR], n[CVMFS_CH_ADD_FILE],
           n[CVMFS_CH_ADD_LINK], n[CVMFS_CH_DELETE],
           o->del ? " [mirror --delete]" : "");
    return ING_OK;
}

static int ing_dir_publish(const ing_dir_opts_t *o, const cvmfs_changeset_t *cs) {
    cvmfs_publish_opts_t po;
    char err[1024];
    long rev = 0;
    memset(&po, 0, sizeof(po));
    po.repo_dir = o->repo;
    po.keys_dir = o->keys_dir;
    po.chunk_size = o->chunk_size;
    int rc = bci_lock_acquire(o->repo, o->no_wait);
    if (rc != ING_OK) return rc;
    rc = cvmfs_publish_run(&po, cs, &rev, err, sizeof(err)) == 0
         ? ING_OK : bci_fail(ING_FAIL, "publish failed", err);
    bci_lock_release(o->repo);
    if (rc == ING_OK)
        printf("published revision %ld (%zu changes under %s)\n",
               rev, cs->n, o->prefix);
    return rc;
}

static int ing_dir_main(int argc, char **argv) {
    ing_dir_opts_t o;
    cvmfs_changeset_t cs;
    char err[1024];
    int rc = ing_dir_parse(argc, argv, &o);
    if (rc != ING_OK) return rc;
    rc = bci_prefix_check(o.prefix);
    if (rc != ING_OK) return rc;
    if (cvmfs_changeset_scan(o.src, &cs, err, sizeof(err)) != 0)
        return bci_fail(ING_FAIL, "src scan failed", err);
    rc = ing_dir_grammar_check(o.src, &cs);
    if (rc == ING_OK
        && cvmfs_changeset_reprefix(&cs, o.prefix, err, sizeof(err)) != 0)
        rc = bci_fail(ING_FAIL, "prefix remap failed", err);
    if (rc == ING_OK) {
        if (o.del) ing_dir_mark_mirror(&cs, o.prefix);
        rc = o.dry_run ? ing_dir_dry_run(&cs, &o) : ing_dir_publish(&o, &cs);
    }
    cvmfs_changeset_free(&cs);
    return rc;
}

/* ---- dispatch ------------------------------------------------------------- */

int brixcvmfs_ingest_main(int argc, char **argv) {
    /* argv[0] = "ingest" after the front-end shift. */
    const char *cmd = argc >= 2 ? argv[1] : "";
    if (strcmp(cmd, "dir") == 0)
        return ing_dir_main(argc - 1, argv + 1);
    if (strcmp(cmd, "image") == 0) {
        if (bci_image_main == NULL) {
            fprintf(stderr, "brixcvmfs ingest: image verb not linked in this build\n");
            return ING_USAGE;
        }
        return bci_image_main(argc - 1, argv + 1);
    }
    if (strcmp(cmd, "prune") == 0) {
        if (bci_prune_main == NULL) {
            fprintf(stderr, "brixcvmfs ingest: prune verb not linked in this build\n");
            return ING_USAGE;
        }
        return bci_prune_main(argc - 1, argv + 1);
    }
    fprintf(stderr,
        "usage: brixcvmfs ingest image <ref> --repo <repo_dir> [options]\n"
        "       brixcvmfs ingest dir <src_dir> --repo <repo_dir>"
        " --prefix /path [options]\n"
        "       brixcvmfs ingest prune --repo <repo_dir> [options]\n");
    return ING_USAGE;
}

#ifdef BRIXCVMFS_INGEST_STANDALONE
/* Test-build entry (tests/cmdscripts/cvmfs_ingest_dir.py): argv[0] plays the
 * "ingest" slot, so `ingesttool dir <src> --repo <dir> …` maps through. */
int main(int argc, char **argv) {
    return brixcvmfs_ingest_main(argc, argv);
}
#endif
