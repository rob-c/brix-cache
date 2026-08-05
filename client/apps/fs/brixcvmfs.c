/*
 * brixcvmfs.c — CVMFS-brix: a hardened, read-only CVMFS FUSE driver (front-end).
 *
 * WHAT: the driver's front-end — CLI entry + brixMount seam, `-o` option
 *       parsing, the clever-overlay/rw-overlay/fuse-launch orchestration, the
 *       opt-in phase-87 sidecar accelerators (G1 negfilter, G6 pathidx, F4
 *       prefetch, G3 dict), and the mount_run lifecycle. Owns the process-global
 *       mounted client (g_cl) and the cat_path/mono_now seam helpers.
 * WHY:  a single small binary "battle-tested against bad/evil networks": every
 *       object is content-hash verified, so any mirror/proxy failure or tampered
 *       reply is retried elsewhere and never trusted unverified.
 * HOW:  the heavy lifting lives in the Phase-38 siblings — brixcvmfs_transport.c
 *       (libcurl fetch seam), brixcvmfs_prefetch.c (F4 worker),
 *       brixcvmfs_ops.c (read-only FUSE ops), brixcvmfs_mount.c (trust-chain
 *       open/check/prewarm) — bound together through brixcvmfs_split.h. This
 *       file wires them into a mount and refuses every mutating op with -EROFS.
 */
#define FUSE_USE_VERSION 31

#include "brixcvmfs_internal.h"
#include "brixcvmfs_split.h"

#include <curl/curl.h>

#include "cvmfs/filter/xorf.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ---- process-global mount state (one repo per process) ------------------ */
cvmfs_client_t *g_cl;

/* ---- path mapping: FUSE "/" is the catalog root "" ---------------------- */
const char *cat_path(const char *p) { return strcmp(p, "/") == 0 ? "" : p; }

long mono_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long) ts.tv_sec;
}

/* ---- seam to the cvmfs-rw union driver (brixcvmfs_internal.h) ------------ */

int brixcvmfs_rw = 0;      /* 1 = mount with the rw ops table (set pre-dispatch) */

cvmfs_client_t *brixcvmfs_client(void)             { return g_cl; }
const char     *brixcvmfs_cat_path(const char *p)  { return cat_path(p); }
long            brixcvmfs_mono_now(void)           { return mono_now(); }

/* Parsed brix-specific mount options (the rest of `-o` is forwarded to libfuse). */
typedef struct {
    int   clever;              /* overlay cache in <mnt>/.brixcache (default ON) */
    int   quota_mb;            /* -o quota=<MB> (0 = from config/unlimited) */
    int   fresh;               /* -o fresh: fresh connection per request */
    int   tls;                 /* -o tls: prefer https:// */
    int   retries;            /* -o retries=<N> (-1 = from config/default) */
    int   prefetch;            /* -o prefetch=<DEPTH>: subtree readahead (-1 = off) */
    long  prefetch_budget;     /* -o prefetch_budget=<BYTES> (0 = unbounded) */
    int   negfilter;           /* -o negfilter: in-process negative lookups (G1) */
    int   bundle;              /* -o bundle: prefetch batches via .cvmfs-bundle (G2) */
    int   dict;                /* -o dict: shared-dictionary transfer coding (G3) */
    int   cache_packed;        /* -o cache_format=packed: log-structured cache (G4) */
    int   cache_tiering;       /* -o cache_tiering: zstd cold packing + promotion (G5) */
    int   index_mmap;          /* -o index=mmap: mmap'd namespace index (G6) */
    char  pin[128];            /* -o pin=<HASH>: pin the root catalog (reproducible mount) */
    char  cache_dir[512];      /* -o cache=<DIR> (implies non-clever) */
    char  writes_dir[512];     /* -o writes=<DIR> (cvmfs-rw overlay location) */
    char  fuse_extra[512];     /* passthrough -o tokens, comma-joined */
    char *flags[16]; int nflags;  /* passthrough flags (-f/-d/-h/...) */
} brix_opts_t;

/* Bare boolean -o tokens. 1 = consumed. */
static int opts_o_flag(const char *t, brix_opts_t *o) {
    if      (strcmp(t, "clever") == 0)   o->clever = 1;
    else if (strcmp(t, "noclever") == 0) o->clever = 0;
    else if (strcmp(t, "fresh") == 0)    o->fresh = 1;
    else if (strcmp(t, "tls") == 0)      o->tls = 1;
    else if (strcmp(t, "negfilter") == 0) o->negfilter = 1;
    else if (strcmp(t, "bundle") == 0)   o->bundle = 1;
    else if (strcmp(t, "dict") == 0)     o->dict = 1;
    else if (strcmp(t, "cache_tiering") == 0) o->cache_tiering = 1;
    else return 0;
    return 1;
}

/* key=value -o tokens. 1 = consumed. */
static int opts_o_kv(const char *t, brix_opts_t *o) {
    if (strncmp(t, "cache_format=", 13) == 0) {
        o->cache_packed = strcmp(t + 13, "packed") == 0;
        if (!o->cache_packed && strcmp(t + 13, "flat") != 0)
            fprintf(stderr, "brixcvmfs: unknown cache_format '%s' "
                    "(flat|packed) — using flat\n", t + 13);
    }
    else if (strncmp(t, "index=", 6) == 0) {
        o->index_mmap = strcmp(t + 6, "mmap") == 0;
        if (!o->index_mmap && strcmp(t + 6, "none") != 0)
            fprintf(stderr, "brixcvmfs: unknown index '%s' "
                    "(mmap|none) — using none\n", t + 6);
    }
    else if (strncmp(t, "quota=", 6) == 0)   o->quota_mb = atoi(t + 6);
    else if (strncmp(t, "retries=", 8) == 0) o->retries = atoi(t + 8);
    else if (strncmp(t, "prefetch=", 9) == 0)        o->prefetch = atoi(t + 9);
    else if (strncmp(t, "prefetch_budget=", 16) == 0) o->prefetch_budget = atol(t + 16);
    else if (strncmp(t, "pin=", 4) == 0)
        snprintf(o->pin, sizeof(o->pin), "%s", t + 4);
    else if (strncmp(t, "cache=", 6) == 0)
        snprintf(o->cache_dir, sizeof(o->cache_dir), "%s", t + 6);
    else if (strncmp(t, "writes=", 7) == 0)
        snprintf(o->writes_dir, sizeof(o->writes_dir), "%s", t + 7);
    else return 0;
    return 1;
}

static void opts_o_list(char *list, brix_opts_t *o) {
    char *save = NULL;
    for (char *t = strtok_r(list, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        if (opts_o_flag(t, o) || opts_o_kv(t, o))
            continue;
        /* forward to libfuse */
        size_t cur = strlen(o->fuse_extra);
        snprintf(o->fuse_extra + cur, sizeof(o->fuse_extra) - cur,
                 "%s%s", cur ? "," : "", t);
    }
}

static void parse_opts(int argc, char **argv, int start, brix_opts_t *o) {
    memset(o, 0, sizeof(*o));
    o->clever = 1; o->retries = -1; o->prefetch = -1;
    char obuf[512];
    for (int i = start; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            snprintf(obuf, sizeof(obuf), "%s", argv[++i]);
            opts_o_list(obuf, o);
        } else if (strncmp(argv[i], "-o", 2) == 0 && argv[i][2] != '\0') {
            snprintf(obuf, sizeof(obuf), "%s", argv[i] + 2);
            opts_o_list(obuf, o);
        } else if (o->nflags < 16) {
            o->flags[o->nflags++] = argv[i];   /* -f / -d / -h / ... */
        }
    }
}

/* Resolve the clever-overlay cache: unless an explicit cache (-o cache= or
 * $BRIXCVMFS_CACHE) opts out, create <mnt>/.brixcache and open a dirfd on it
 * BEFORE the FUSE mount hides it. Sets `*cache_override` (the explicit-cache
 * path, else NULL) and returns the overlay dirfd, or -1 (explicit/fallback). */
static int brixcvmfs_open_clever_cache(const char *mnt, const brix_opts_t *o,
                                       const char **cache_override) {
    *cache_override = NULL;
    int clever = o->clever;
    if (o->cache_dir[0]) { *cache_override = o->cache_dir; clever = 0; }
    else if (getenv("BRIXCVMFS_CACHE")) { clever = 0; }
    if (!clever) return -1;

    mkdir(mnt, 0755);                       /* ensure the mountpoint exists */
    char sub[600];
    snprintf(sub, sizeof(sub), "%s/.brixcache", mnt);
    if (mkdir(sub, 0755) != 0 && errno != EEXIST)
        fprintf(stderr, "brixcvmfs: warning: cannot create overlay cache %s\n", sub);
    int fd = open(sub, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        fprintf(stderr, "brixcvmfs: overlay cache unavailable, falling back\n");
    return fd;
}

/* Bind the cvmfs-rw writable overlay (<mnt>/.brixwrites or -o writes=) BEFORE
 * fuse_main hides the mountpoint — same trick as .brixcache. The rw hooks are
 * weak so a ro-only link (test builds) still works. No-op unless brixcvmfs_rw.
 * Returns 0 on success (or when not requested), else a process exit code. */
static int brixcvmfs_setup_rw_overlay(const char *mnt, const brix_opts_t *o) {
    if (!brixcvmfs_rw) return 0;
    if (brixcvmfs_setup_rw == NULL || &brixcvmfs_rw_ops == NULL) {
        fprintf(stderr, "brixcvmfs: rw overlay driver not linked in this build\n");
        return 2;
    }
    if (brixcvmfs_setup_rw(mnt, o->writes_dir) != 0) return 1;
    return 0;
}

/* Hand the mountpoint (+ passthrough flags/opts) to libfuse. Force
 * single-threaded (-s): the client shares one SQLite catalog handle + lock-free
 * failover state, so serialised FUSE dispatch is the correct, race-free choice
 * (reads are cache-served, so throughput is unaffected). Returns fuse_main's rc. */
static int brixcvmfs_run_fuse(char *arg0, const char *mnt, const brix_opts_t *o) {
    char *fargv[24]; int fargc = 0;
    fargv[fargc++] = arg0;
    fargv[fargc++] = (char *) mnt;
    fargv[fargc++] = (char *) "-s";
    /* Flag the kernel mount read-only (matches official cvmfs2) — the pure-ro
     * build only. The --rw overlay build is genuinely writable, so must not. */
    if (!brixcvmfs_rw) { fargv[fargc++] = (char *) "-o"; fargv[fargc++] = (char *) "ro"; }
    for (int i = 0; i < o->nflags && fargc < 20; i++) fargv[fargc++] = o->flags[i];
    if (o->fuse_extra[0]) { fargv[fargc++] = (char *) "-o"; fargv[fargc++] = (char *) o->fuse_extra; }

    return fuse_main(fargc, fargv,
                     brixcvmfs_rw ? &brixcvmfs_rw_ops : &brixcvmfs_ops, NULL);
}

/* ---- G1 negative-lookup filter (phase-87, -o negfilter / $BRIXCVMFS_NEGFILTER)
 *
 * Built from the client's OWN verified paths walk (client_negfilter.c) and
 * persisted as a cache sidecar so later mounts of the same revision skip the
 * walk. The sidecar is UNTRUSTED input: checksum-verified and root-bound on
 * load; any defect (tamper, truncation, other revision) falls back to a fresh
 * verified build. Every failure here is non-fatal — lookups just stay live. */

#define NEGF_SIDECAR      "negfilter.bxf"
#define NEGF_SIDECAR_TMP  "negfilter.bxf.tmp"
#define NEGF_SIDECAR_MAX  (256u * 1024u * 1024u)   /* load sanity cap */

/* Activate the filter from the sidecar in `dfd`. 0 = active. */
static int negf_load_sidecar(cvmfs_client_t *cl, int dfd) {
    int fd = openat(dfd, NEGF_SIDECAR, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0
        || (unsigned long long) st.st_size > NEGF_SIDECAR_MAX) {
        close(fd);
        return -1;
    }
    size_t len = (size_t) st.st_size;
    unsigned char *img = malloc(len);
    if (img == NULL) { close(fd); return -1; }
    for (size_t off = 0; off < len; ) {
        ssize_t got = read(fd, img + off, len - off);
        if (got <= 0) { free(img); close(fd); return -1; }
        off += (size_t) got;
    }
    close(fd);

    cvmfs_xorf_t f;
    cvmfs_hash_t root;
    int rc = cvmfs_xorf_deserialize(&f, &root, img, len);   /* fail-closed */
    free(img);
    if (rc != 0) return -1;
    if (cvmfs_client_negfilter_adopt(cl, &f, &root) != 0) { /* other revision */
        cvmfs_xorf_reset(&f);
        return -1;
    }
    return 0;
}

/* Persist the active filter atomically (tmp + rename) into `dfd`. */
static void negf_store_sidecar(cvmfs_client_t *cl, int dfd) {
    cvmfs_hash_t root;
    const cvmfs_xorf_t *f = cvmfs_client_negfilter(cl, &root);
    if (f == NULL) return;
    size_t need = cvmfs_xorf_size(f), n = 0;
    unsigned char *img = malloc(need);
    if (img == NULL || cvmfs_xorf_serialize(f, &root, img, need, &n) != 0) {
        free(img);
        return;
    }
    int fd = openat(dfd, NEGF_SIDECAR_TMP, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    int ok = fd >= 0;
    for (size_t off = 0; ok && off < n; ) {
        ssize_t w = write(fd, img + off, n - off);
        if (w <= 0) ok = 0;
        else        off += (size_t) w;
    }
    if (fd >= 0) close(fd);
    free(img);
    if (ok && renameat(dfd, NEGF_SIDECAR_TMP, dfd, NEGF_SIDECAR) == 0) return;
    (void) unlinkat(dfd, NEGF_SIDECAR_TMP, 0);
}

/* Sidecar-or-build bring-up. Runs synchronously before fuse_main (the mount
 * serves FUSE single-threaded, so no locking), once per served revision. */
static void brixcvmfs_negfilter_setup(cvmfs_client_t *cl, const char *repo,
                                      const char *cache_override, int cache_dirfd) {
    int dfd = cache_dirfd, owned = 0;
    if (dfd < 0) {
        char cdir[512] = "";
        brixcvmfs_prepare_cache_dir(repo, cache_override, -1, cdir, sizeof(cdir));
        dfd = open(cdir, O_RDONLY | O_DIRECTORY);
        owned = 1;
    }
    if (dfd >= 0 && negf_load_sidecar(cl, dfd) == 0) {
        fprintf(stderr, "brixcvmfs: negfilter loaded from sidecar\n");
    } else if (cvmfs_client_negfilter_build(cl, mono_now()) == 0) {
        if (dfd >= 0) negf_store_sidecar(cl, dfd);
        fprintf(stderr, "brixcvmfs: negfilter built from verified walk\n");
    } else {
        fprintf(stderr, "brixcvmfs: negfilter unavailable — lookups stay live\n");
    }
    if (owned && dfd >= 0) close(dfd);
}

/* ---- G6 mmap path index (phase-87, -o index=mmap / $BRIXCVMFS_INDEX=mmap)
 *
 * Built from the client's OWN verified paths walk (client_pathidx.c) and
 * persisted as a cache sidecar the client mmaps back — later mounts of the
 * same revision skip both the walk and every catalog open. The sidecar is
 * UNTRUSTED input: geometry-validated + root-bound on load (any other
 * revision, ABI or truncation defect falls back to a fresh verified build),
 * and a tampered ENTRY is caught at first read by the CAS verify-fetch, which
 * drops the index. Every failure here is non-fatal — the catalogs stay live. */

#define PIDX_SIDECAR "pathidx.bxi"

static void brixcvmfs_pathidx_setup(cvmfs_client_t *cl, const char *repo,
                                    const char *cache_override, int cache_dirfd) {
    int dfd = cache_dirfd, owned = 0;
    if (dfd < 0) {
        char cdir[512] = "";
        brixcvmfs_prepare_cache_dir(repo, cache_override, -1, cdir, sizeof(cdir));
        dfd = open(cdir, O_RDONLY | O_DIRECTORY);
        owned = 1;
    }
    if (dfd >= 0 && cvmfs_client_pathidx_load(cl, dfd, PIDX_SIDECAR) == 0)
        fprintf(stderr, "brixcvmfs: pathidx loaded from sidecar\n");
    else if (dfd >= 0
             && cvmfs_client_pathidx_build(cl, dfd, PIDX_SIDECAR, mono_now()) == 0)
        fprintf(stderr, "brixcvmfs: pathidx built from verified walk\n");
    else
        fprintf(stderr, "brixcvmfs: pathidx unavailable — catalog lookups stay live\n");
    if (owned && dfd >= 0) close(dfd);
}

/* F4 predictive prefetch: -o prefetch=<depth> or $BRIXCVMFS_PREFETCH. */
static void brixcvmfs_arm_prefetch(cvmfs_client_t *cl, const char *repo,
                                   const brix_opts_t *o, const char *cache_override,
                                   int cache_dirfd, long quota) {
    const char *env_pf = getenv("BRIXCVMFS_PREFETCH");
    int pf_depth = o->prefetch >= 0 ? o->prefetch : (env_pf ? atoi(env_pf) : -1);
    if (pf_depth < 0) return;

    const char *env_pb = getenv("BRIXCVMFS_PREFETCH_BUDGET");
    long pf_budget = o->prefetch_budget > 0 ? o->prefetch_budget
                   : (env_pb ? atol(env_pb) : 0);
    char pf_cache[512] = "";
    brixcvmfs_prepare_cache_dir(repo, cache_override, cache_dirfd,
                                pf_cache, sizeof(pf_cache));
    /* G2 batch mode: -o bundle or $BRIXCVMFS_BUNDLE=1 (needs prefetch on;
     * set before pf_start so the worker thread never sees it change). */
    const char *env_bd = getenv("BRIXCVMFS_BUNDLE");
    int pf_bundle = (o->bundle || (env_bd != NULL && atoi(env_bd) != 0)) ? 1 : 0;
    pf_start(pf_depth, pf_budget, cl->catalog_tmp, pf_cache, cache_dirfd, quota,
             pf_bundle);
}

/* Arm the opt-in phase-87 lookup accelerators + dict coding. */
static void brixcvmfs_arm_sidecars(cvmfs_client_t *cl, const char *repo,
                                   const brix_opts_t *o, const char *cache_override,
                                   int cache_dirfd) {
    /* G1 negative-lookup filter: -o negfilter or $BRIXCVMFS_NEGFILTER=1. */
    const char *env_nf = getenv("BRIXCVMFS_NEGFILTER");
    if (o->negfilter || (env_nf != NULL && atoi(env_nf) != 0))
        brixcvmfs_negfilter_setup(cl, repo, cache_override, cache_dirfd);

    /* G6 mmap path index: -o index=mmap or $BRIXCVMFS_INDEX=mmap. */
    const char *env_ix = getenv("BRIXCVMFS_INDEX");
    if (o->index_mmap || (env_ix != NULL && strcmp(env_ix, "mmap") == 0))
        brixcvmfs_pathidx_setup(cl, repo, cache_override, cache_dirfd);

    /* G3 shared-dictionary coding: -o dict or $BRIXCVMFS_DICT=1 (armed here;
     * the dict itself is pulled on the first CAS data GET). */
    const char *env_dc = getenv("BRIXCVMFS_DICT");
    if (o->dict || (env_dc != NULL && atoi(env_dc) != 0))
        brixcvmfs_dict_arm();
}

/* Full mount bring-up: clever-cache dirfd, rw overlay, verify-mount the repo,
 * run FUSE, then tear everything down. `cache_dirfd` ownership is local to this
 * function. Returns the process exit code. */
static int brixcvmfs_mount_run(char *arg0, const char *repo, const char *mnt,
                               const brix_opts_t *o) {
    g_tcfg.fresh_connect = o->fresh;
    g_tcfg.prefer_tls    = o->tls;
    long quota = o->quota_mb > 0 ? (long) o->quota_mb * 1024L * 1024L : 0;

    const char *cache_override = NULL;
    int cache_dirfd = brixcvmfs_open_clever_cache(mnt, o, &cache_override);

    int rw_rc = brixcvmfs_setup_rw_overlay(mnt, o);
    if (rw_rc != 0) { if (cache_dirfd >= 0) close(cache_dirfd); return rw_rc; }

    cvmfs_client_t *cl = brixcvmfs_open(repo, cache_override, cache_dirfd, quota, o->retries,
                                        o->pin, o->cache_packed, o->cache_tiering);
    if (cl == NULL) { if (cache_dirfd >= 0) close(cache_dirfd); return 1; }
    g_cl = cl;

    brixcvmfs_arm_prefetch(cl, repo, o, cache_override, cache_dirfd, quota);
    brixcvmfs_arm_sidecars(cl, repo, o, cache_override, cache_dirfd);

    int rc = brixcvmfs_run_fuse(arg0, mnt, o);

    if (brixcvmfs_rw && brixcvmfs_teardown_rw != NULL) brixcvmfs_teardown_rw();
    cvmfs_client_umount(cl);
    transport_cleanup();
    brixcvmfs_dict_free();
    curl_global_cleanup();
    if (cache_dirfd >= 0) close(cache_dirfd);
    free(cl);
    return rc;
}

/* brixcvmfs entry — reused by the brixMount umbrella (SP-G).
 *   brixcvmfs <repo> <mountpoint> [fuse-opts]   — mount
 *   brixcvmfs --check <repo>                     — verify + summarise, no mount */
int brixcvmfs_main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "--check") == 0)
        return brixcvmfs_check(argv[2]);
    if (argc >= 3 && strcmp(argv[1], "--prewarm") == 0)
        return brixcvmfs_prewarm(argv[2]);
    if (argc >= 2 && strcmp(argv[1], "repo") == 0) {
        if (brixcvmfs_repo_main == NULL) {
            fprintf(stderr, "brixcvmfs: repo driver not linked in this build\n");
            return 2;
        }
        return brixcvmfs_repo_main(argc - 1, argv + 1);
    }

    if (argc < 3) {
        fprintf(stderr,
            "usage: brixcvmfs <repo.fqrn> <mountpoint> [fuse-opts]\n"
            "       brixcvmfs --check <repo.fqrn>\n"
            "       brixcvmfs --prewarm <repo.fqrn>\n"
            "       brixcvmfs repo mkfs|info|resign ...\n");
        return 2;
    }

    brix_opts_t o;
    parse_opts(argc, argv, 3, &o);
    return brixcvmfs_mount_run(argv[0], argv[1], argv[2], &o);
}

#ifndef BRIXCVMFS_NO_MAIN
int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--rw") == 0) {   /* brixcvmfs --rw <repo> <mnt> */
        if (brixcvmfs_rw_main == NULL) {
            fprintf(stderr, "brixcvmfs: rw overlay driver not linked in this build\n");
            return 2;
        }
        argv[1] = argv[0];
        return brixcvmfs_rw_main(argc - 1, argv + 1);
    }
    return brixcvmfs_main(argc, argv);
}
#endif
