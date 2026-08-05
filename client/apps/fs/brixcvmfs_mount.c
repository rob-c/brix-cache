/*
 * brixcvmfs_mount.c — CVMFS-brix trust-chain mount pipeline (Phase-38 split).
 *
 * WHAT: bring-up of one mounted repo — master-key loading (single file or a
 *       rotated *.pub directory), the failover/transport/quota config cascade,
 *       root-catalog pin + G4/G5 cache format, and the verify-mount itself —
 *       plus the two no-mount commands `--check` and `--prewarm`.
 * WHY:  split from brixcvmfs.c to keep each TU within the file-size budget;
 *       this is the "prove the repo is trustworthy and open it" concern,
 *       separate from FUSE dispatch, the transport, and option parsing.
 * HOW:  brixcvmfs_open assembles the client, seeds the process-global transport
 *       config, brings the libcurl pool up, and hands the injected transport to
 *       the shared cvmfs core, which owns the whitelist/manifest/catalog trust
 *       chain. check/prewarm reuse open, then summarise without a FUSE mount.
 */
#include <curl/curl.h>

#include "cvmfs/config/cvmfs_conf.h"
#include "cvmfs/walk/walk.h"
#include "brixcvmfs_split.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static unsigned char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc(n > 0 ? (size_t) n : 1);
    if (b && fread(b, 1, (size_t) n, f) != (size_t) n) { free(b); b = NULL; }
    fclose(f);
    if (b) *len = (size_t) n;
    return b;
}

/* Load the repo master key(s). If `path` is a directory (the stock
 * /etc/cvmfs/keys/<domain>/ layout), concatenate every *.pub in it — CVMFS
 * rotates master keys and the whitelist is signed by one of them. */
static unsigned char *load_master_key(const char *path, size_t *len) {
    struct stat st;
    if (stat(path, &st) != 0) return NULL;
    if (!S_ISDIR(st.st_mode)) return read_file(path, len);

    DIR *d = opendir(path);
    if (d == NULL) return NULL;
    unsigned char *buf = NULL; size_t cap = 0, used = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        const char *dot = strrchr(e->d_name, '.');
        if (dot == NULL || strcmp(dot, ".pub") != 0) continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", path, e->d_name);
        size_t kl = 0;
        unsigned char *k = read_file(full, &kl);
        if (k == NULL) continue;
        if (used + kl + 1 > cap) { cap = (used + kl + 1) * 2;
            unsigned char *nb = realloc(buf, cap); if (nb == NULL) { free(k); continue; } buf = nb; }
        memcpy(buf + used, k, kl); used += kl;
        buf[used++] = '\n';
        free(k);
    }
    closedir(d);
    if (buf) *len = used;
    return buf;
}

/* Populate the client failover set for `repo`. $BRIXCVMFS_SERVER pins a single
 * DIRECT stratum-1; otherwise apply the loaded config cascade, and if that yields
 * no hosts, synthesise the conventional cvmfs-stratum-one.<domain> fallback. */
static void brixcvmfs_build_failover(cvmfs_client_t *cl, const cvmfs_conf_t *cf,
                                     const char *repo) {
    cvmfs_failover_init(&cl->fo, 60);
    const char *env_server = getenv("BRIXCVMFS_SERVER");
    if (env_server != NULL) {
        cvmfs_failover_add_proxy(&cl->fo, "DIRECT", 0);
        cvmfs_failover_add_host(&cl->fo, env_server);
        return;
    }
    int hosts = cvmfs_conf_apply(cf, repo, &cl->config, &cl->fo);
    if (hosts == 0) {
        char s1[400];
        snprintf(s1, sizeof(s1), "http://cvmfs-stratum-one.%s/cvmfs/%s",
                 strchr(repo, '.') + 1, repo);
        cvmfs_failover_add_host(&cl->fo, s1);
    }
}

/* Seed the process-global libcurl transport config from the client config +
 * conf cascade for `repo`. `retries_override >= 0` wins over CVMFS_MAX_RETRIES. */
static void brixcvmfs_build_transport_cfg(const cvmfs_client_t *cl, const cvmfs_conf_t *cf,
                                          const char *repo, int retries_override) {
    snprintf(g_tcfg.repo, sizeof(g_tcfg.repo), "%s", repo);
    g_tcfg.connect_timeout_s = cl->config.timeout_s > 0 ? cl->config.timeout_s : 5;
    g_tcfg.low_speed_time_s  = g_tcfg.connect_timeout_s;
    g_tcfg.low_speed_bytes   = 100;
    const char *cfg_retries = cvmfs_conf_get(cf, "CVMFS_MAX_RETRIES");
    g_tcfg.max_retries = retries_override >= 0 ? retries_override
                       : (cfg_retries ? atoi(cfg_retries) : 2);
}

/* Resolve the effective cache quota in bytes: a positive `quota_override` wins;
 * otherwise fall back to CVMFS_QUOTA_LIMIT (MB) from the conf cascade; else 0. */
static long brixcvmfs_resolve_quota(const cvmfs_conf_t *cf, long quota_override) {
    if (quota_override > 0) return quota_override;
    const char *q = cvmfs_conf_get(cf, "CVMFS_QUOTA_LIMIT");   /* MB */
    if (q && atol(q) > 0) return atol(q) * 1024L * 1024L;
    return 0;
}

/* Load the repo master key: $BRIXCVMFS_PUBKEY overrides the config default path.
 * A config-derived CVMFS_KEYS_DIR/<domain>.pub that does not exist falls back to
 * the key-chain DIRECTORY itself (stock layouts rotate keys as e.g.
 * keys/cern.ch/cern-it4.cern.ch.pub with no cern.ch.pub; load_master_key
 * concatenates every *.pub and the verifier tries each). Returns the allocated
 * key blob (caller frees) + `*klen`, or NULL on read failure (message printed). */
static unsigned char *brixcvmfs_load_repo_key(const cvmfs_client_t *cl, size_t *klen) {
    const char *env_key = getenv("BRIXCVMFS_PUBKEY");
    const char *keypath = env_key ? env_key : cl->config.master_pub_path;
    unsigned char *master = load_master_key(keypath, klen);
    if (master == NULL && env_key == NULL) {
        char chain[512];
        snprintf(chain, sizeof(chain), "%s", keypath);
        char *slash = strrchr(chain, '/');
        if (slash != NULL && slash != chain) {
            *slash = '\0';
            master = load_master_key(chain, klen);
        }
    }
    if (master == NULL)
        fprintf(stderr, "brixcvmfs: cannot read master key %s\n", keypath);
    return master;
}

/* Resolve + create the scratch tmp dir for `repo` into `tmp_dir` (cap `cap`):
 * $BRIXCVMFS_TMP overrides the /tmp/brixcvmfs-<repo> default. Best-effort mkdir
 * (a truly unusable dir surfaces as a later mount failure). */
static void brixcvmfs_prepare_tmp_dir(const char *repo, char *tmp_dir, size_t cap) {
    const char *env_tmp = getenv("BRIXCVMFS_TMP");
    if (env_tmp) snprintf(tmp_dir, cap, "%s", env_tmp);
    else         snprintf(tmp_dir, cap, "/tmp/brixcvmfs-%s", repo);
    char mk[600];
    snprintf(mk, sizeof(mk), "mkdir -p '%s'", tmp_dir);
    if (system(mk) != 0) { /* mount will fail later if truly unusable */ }
}

/* Resolve + create the persistent cache dir for `repo` into `cache_dir` when NOT
 * in overlay-dirfd mode (`cache_dirfd < 0`). Precedence: explicit override →
 * $BRIXCVMFS_CACHE → /var/lib/brixcvmfs/<repo>. No-op in dirfd mode. */
void brixcvmfs_prepare_cache_dir(const char *repo, const char *cache_dir_override,
                                        int cache_dirfd, char *cache_dir, size_t cap) {
    if (cache_dirfd >= 0) return;
    const char *env_cache = getenv("BRIXCVMFS_CACHE");
    if (cache_dir_override) snprintf(cache_dir, cap, "%s", cache_dir_override);
    else if (env_cache)     snprintf(cache_dir, cap, "%s", env_cache);
    else                    snprintf(cache_dir, cap, "/var/lib/brixcvmfs/%s", repo);
    char mk[600];
    snprintf(mk, sizeof(mk), "mkdir -p '%s'", cache_dir);
    if (system(mk) != 0) { /* mount will fail later if unusable */ }
}

/* Root-catalog pin + G4/G5 cache format (phase-87): -o pin= / cache_format=
 * packed / cache_tiering, env fallbacks for each. $BRIXCVMFS_CACHE_SEG_BYTES
 * is a test hook to shrink segments so rollover/eviction is exercisable with
 * tiny corpora. -1 = bad pin (message printed). */
static int brixcvmfs_open_pin_cache(cvmfs_client_t *cl, const char *pin_opt,
                                    int packed_opt, int tiering_opt) {
    const char *pin = (pin_opt != NULL && pin_opt[0]) ? pin_opt : getenv("BRIXCVMFS_PIN");
    if (pin != NULL && pin[0] && cvmfs_client_pin_root(cl, pin) != 0) {
        fprintf(stderr, "brixcvmfs: bad pin '%s' (want a root-catalog hash)\n", pin);
        return -1;
    }

    const char *env_cf = getenv("BRIXCVMFS_CACHE_FORMAT");
    const char *env_ct = getenv("BRIXCVMFS_CACHE_TIERING");
    const char *env_sb = getenv("BRIXCVMFS_CACHE_SEG_BYTES");
    int packed  = packed_opt  || (env_cf != NULL && strcmp(env_cf, "packed") == 0);
    int tiering = tiering_opt || (env_ct != NULL && atoi(env_ct) != 0);
    if (packed)
        cvmfs_client_cache_config(cl, 1, tiering, env_sb ? atol(env_sb) : 0);

    return 0;
}

/* Build failover + config and verify-mount the repo trust chain. Cache backing:
 * `cache_dirfd >= 0` = overlay dirfd mode; else `cache_dir_override` (or the
 * default/env path). quota/retries fall back to the config cascade when the
 * override is unset (<=0 quota, <0 retries). Returns a mounted client or NULL. */
cvmfs_client_t *brixcvmfs_open(const char *repo, const char *cache_dir_override,
                                      int cache_dirfd, long quota_override, int retries_override,
                                      const char *pin_opt, int packed_opt, int tiering_opt) {
    cvmfs_client_t *cl = calloc(1, sizeof(*cl));
    if (cl == NULL) { fprintf(stderr, "brixcvmfs: out of memory\n"); return NULL; }

    if (cvmfs_repo_config_defaults(repo, &cl->config) != 0) {
        fprintf(stderr, "brixcvmfs: '%s' is not a fully-qualified repo name\n", repo);
        free(cl); return NULL;
    }

    if (brixcvmfs_open_pin_cache(cl, pin_opt, packed_opt, tiering_opt) != 0) {
        free(cl); return NULL;
    }

    cvmfs_conf_t cf;
    cvmfs_conf_init(&cf);
    cvmfs_conf_load_cascade(&cf, getenv("BRIXCVMFS_ETC"), repo);   /* for quota/retries */

    brixcvmfs_build_failover(cl, &cf, repo);
    brixcvmfs_build_transport_cfg(cl, &cf, repo, retries_override);
    long quota = brixcvmfs_resolve_quota(&cf, quota_override);

    size_t klen = 0;
    unsigned char *master = brixcvmfs_load_repo_key(cl, &klen);
    if (master == NULL) { free(cl); return NULL; }

    char tmp_dir[512];
    brixcvmfs_prepare_tmp_dir(repo, tmp_dir, sizeof(tmp_dir));

    char cache_dir[512] = "";
    brixcvmfs_prepare_cache_dir(repo, cache_dir_override, cache_dirfd,
                                cache_dir, sizeof(cache_dir));

    curl_global_init(CURL_GLOBAL_DEFAULT);
    /* Bring the shared curl-handle pool up before the mount fetches the root
     * catalog (eager slot-0 connect surfaces a curl_easy_init failure here). */
    brix_status pst; brix_status_clear(&pst);
    if (brixcvmfs_transport_pool_init(&pst) != 0) {
        fprintf(stderr, "brixcvmfs: curl handle pool init failed: %s\n", pst.msg);
        curl_global_cleanup();
        free(cl); return NULL;
    }
    int mrc = cvmfs_client_mount(cl, repo, master, klen,
                                 cache_dirfd < 0 ? cache_dir : NULL, tmp_dir,
                                 quota, cache_dirfd, brixcvmfs_transport, NULL, mono_now());
    free(master);
    if (mrc != 0) {
        fprintf(stderr, "brixcvmfs: mount of %s failed (trust/catalog error %d)\n", repo, mrc);
        transport_cleanup();
    curl_global_cleanup();
        free(cl); return NULL;
    }
    return cl;
}

/* --check: verify the trust chain + root catalog and print a summary WITHOUT
 * mounting (the stock `cvmfs_config chksetup` analog). Exit 0 = healthy. */
int brixcvmfs_check(const char *repo) {
    cvmfs_client_t *cl = brixcvmfs_open(repo, NULL, -1, 0, -1, NULL, 0, 0);
    if (cl == NULL) return 1;

    long now = mono_now();
    char rev[64] = "?", root[128] = "?", host[256] = "?", proxy[64] = "?";
    int n;
    n = cvmfs_client_getxattr(cl, "/", "user.revision", rev, sizeof(rev) - 1, now);
    if (n > 0) rev[n] = 0;
    n = cvmfs_client_getxattr(cl, "/", "user.root_hash", root, sizeof(root) - 1, now);
    if (n > 0) root[n] = 0;
    n = cvmfs_client_getxattr(cl, "/", "user.host", host, sizeof(host) - 1, now);
    if (n > 0) host[n] = 0;
    n = cvmfs_client_getxattr(cl, "/", "user.proxy", proxy, sizeof(proxy) - 1, now);
    if (n > 0) proxy[n] = 0;

    cvmfs_dirent_t root_e;
    /* the catalog root entry is the empty path "" (FUSE maps "/" → "" via cat_path). */
    int root_ok = cvmfs_client_resolve(cl, "", &root_e, now) == 1
               && (root_e.flags & CVMFS_FLAG_DIR);
    int entries = cvmfs_catalog_readdir(cl->root_catalog, "", NULL, NULL);

    printf("CVMFS-brix repository check: %s\n", repo);
    printf("  trust chain .... OK (whitelist + manifest signature verified)\n");
    printf("  revision ....... %s\n", rev);
    printf("  root catalog ... %s\n", root);
    printf("  root dir ....... %s (%d entries)\n", root_ok ? "OK" : "MISSING", entries);
    printf("  active server .. %s\n", host);
    printf("  active proxy ... %s\n", proxy);
    printf("  ttl ............ %lds\n", cl->ttl);
    printf("HEALTHY\n");

    cvmfs_client_umount(cl);
    transport_cleanup();
    curl_global_cleanup();
    free(cl);
    return root_ok ? 0 : 1;
}

/* --prewarm (phase-85 F5): walk the WHOLE snapshot (the pin when
 * $BRIXCVMFS_PIN is set, else the current root) and pull every referenced CAS
 * object into the local cache, so a shared cache dir is fully warm before a
 * job wave. No mount, single-threaded: reuses the client's own fetch ctx.
 * Exit 0 = every object landed; a fetch error or a tampered catalog ⇒ 1. */
typedef struct {
    cvmfs_client_t    *cl;
    cvmfs_fetch_ctx_t *fx;
    unsigned char     *out;
    cvmfs_failover_t   fo0;   /* pristine snapshot (blacklist reset, cf. F4) */
    long               objs, bytes, errs;
} prewarm_ud_t;

static int prewarm_visit(const cvmfs_walk_item_t *it, void *ud) {
    prewarm_ud_t *p = ud;
    if (it->kind == CVMFS_WALK_CATALOG) return 0;   /* the walk itself caches it */
    size_t n = 0;
    /* This walk drives cvmfs_fetch_object directly, so it owns the landing-buffer
     * sizing the read path does for itself. `it->size` is the catalog's plaintext
     * size (0 when unrecorded — fall back to the whole object cap). */
    if (cvmfs_client_scratch_reserve(p->cl, it->size ? (size_t) it->size
                                                     : (size_t) BRIX_PF_OBJCAP) != 0) {
        p->errs++;
        return 0;
    }
    if (cvmfs_fetch_object(p->fx, &it->hash, it->suffix,
                           p->out, BRIX_PF_OBJCAP, &n, mono_now()) == 0) {
        p->objs++;
        p->bytes += (long) n;
    } else {
        p->errs++;
        *p->fx->fo = p->fo0;  /* one bad object blacklists its route — restore
                               * so it can't shadow the rest of the sweep */
    }
    return 0;
}

int brixcvmfs_prewarm(const char *repo) {
    cvmfs_client_t *cl = brixcvmfs_open(repo, NULL, -1, 0, -1, NULL, 0, 0);
    if (cl == NULL) return 1;

    prewarm_ud_t ud = { cl, &cl->fetch, malloc(BRIX_PF_OBJCAP), cl->fo, 0, 0, 0 };
    int rc = -1;
    if (ud.out != NULL) {
        const cvmfs_hash_t *root = cl->pin_set ? &cl->pin_root
                                               : &cl->manifest.root_catalog;
        rc = cvmfs_walk_catalog(&cl->fetch, root, cl->catalog_tmp,
                                INT_MAX, prewarm_visit, &ud, mono_now());
        char hex[48];
        cvmfs_hash_to_hex(root, 0, hex, sizeof(hex));
        printf("CVMFS-brix prewarm: %s\n", repo);
        printf("  root catalog ... %s%s\n", hex, cl->pin_set ? " (pinned)" : "");
        printf("  objects ........ %ld fetched (%ld bytes)\n", ud.objs, ud.bytes);
        printf("  errors ......... %ld%s\n", ud.errs,
               rc != 0 ? " (walk aborted: catalog fetch/verify failure)" : "");
        printf("%s\n", rc == 0 && ud.errs == 0 ? "WARM" : "INCOMPLETE");
    } else {
        fprintf(stderr, "brixcvmfs: out of memory\n");
    }
    free(ud.out);

    cvmfs_client_umount(cl);
    transport_cleanup();
    curl_global_cleanup();
    free(cl);
    return rc == 0 && ud.errs == 0 ? 0 : 1;
}
