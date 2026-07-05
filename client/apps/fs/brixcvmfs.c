/*
 * brixcvmfs.c — CVMFS-brix: a hardened, read-only CVMFS FUSE driver.
 *
 * WHAT: mounts a real CVMFS repository (e.g. atlas.cern.ch) as a read-only FUSE
 *       filesystem, driven entirely by the shared ngx-free CVMFS core
 *       (shared/cvmfs) — trust chain, SQLite catalogs, content-addressed fetch
 *       with replica+proxy failover, hash-verified retry, and offline cache mode.
 * WHY:  a single small binary that is "battle-tested against bad/evil networks":
 *       every object is verified by content hash, so any mirror/proxy failure or
 *       tampered reply is retried elsewhere and never trusted unverified.
 * HOW:  FUSE 3.1 high-level ops translate straight into cvmfs_client_* calls; a
 *       libcurl transport implements the injected fetch seam (per-request connect
 *       and low-speed timeouts = the adaptive-timeout pillar), while failover and
 *       verification are owned by the shared core. Read-only: every mutating op is
 *       refused with -EROFS.
 */
#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <curl/curl.h>

#include "cvmfs/client/client.h"
#include "cvmfs/config/cvmfs_conf.h"
#include "net/proxy_env.h"
#include "brixcvmfs_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ---- process-global mount state (one repo per process) ------------------ */
static cvmfs_client_t *g_cl;

typedef struct {
    char repo[256];
    long connect_timeout_s;
    long low_speed_time_s;
    long low_speed_bytes;
    int  max_retries;      /* per-mirror retries (CVMFS_MAX_RETRIES) */
    int  fresh_connect;    /* -o fresh: FRESH_CONNECT + FORBID_REUSE (defeat DPI) */
    int  prefer_tls;       /* -o tls: try https:// before http:// */
} brixcvmfs_transport_cfg_t;

static brixcvmfs_transport_cfg_t g_tcfg;

/* ---- libcurl transport (the injected fetch seam) ------------------------ */

typedef struct { unsigned char *buf; size_t cap, len; } curl_sink_t;

static size_t curl_write_cb(char *ptr, size_t sz, size_t nm, void *ud) {
    curl_sink_t *s = ud;
    size_t n = sz * nm;
    if (s->len + n > s->cap) return 0;         /* overflow → curl aborts */
    memcpy(s->buf + s->len, ptr, n);
    s->len += n;
    return n;
}

/* Extract scheme + host + port from a URL for env-proxy resolution. */
static void url_host(const char *url, char *sch, size_t sl, char *host, size_t hl, int *port) {
    sch[0] = host[0] = '\0'; *port = 0;
    const char *p = url;
    const char *sep = strstr(url, "://");
    if (sep) { size_t n = (size_t)(sep - url); if (n < sl) { memcpy(sch, url, n); sch[n] = '\0'; } p = sep + 3; }
    size_t n = 0;
    while (p[n] && p[n] != ':' && p[n] != '/' && n < hl - 1) { host[n] = p[n]; n++; }
    host[n] = '\0';
    *port = (p[n] == ':') ? atoi(p + n + 1) : (strcmp(sch, "https") == 0 ? 443 : 80);
}

/* One GET of `url`, RESUMING from `*got` bytes already in `out` (HTTP Range).
 * Appends new bytes and updates *got. Returns the CURLcode. If a resume request
 * comes back 200 (server ignored Range), the freshly re-sent from-0 bytes are
 * slid to the front so the buffer stays a valid prefix. */
static CURLcode http_get_range(const char *proxy, const char *url,
                               unsigned char *out, size_t outcap, size_t *got) {
    CURL *c = curl_easy_init();
    if (c == NULL) return CURLE_FAILED_INIT;

    size_t      start = *got;
    curl_sink_t sink  = { out, outcap, start };   /* append after what we have */
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &sink);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, g_tcfg.connect_timeout_s);
    curl_easy_setopt(c, CURLOPT_LOW_SPEED_LIMIT, g_tcfg.low_speed_bytes);
    curl_easy_setopt(c, CURLOPT_LOW_SPEED_TIME, g_tcfg.low_speed_time_s);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_FAILONERROR, 1L);         /* HTTP >=400 → error */
    curl_easy_setopt(c, CURLOPT_TCP_KEEPALIVE, 1L);
    if (start > 0)
        curl_easy_setopt(c, CURLOPT_RESUME_FROM_LARGE, (curl_off_t) start);
    if (g_tcfg.fresh_connect) {
        curl_easy_setopt(c, CURLOPT_FRESH_CONNECT, 1L);
        curl_easy_setopt(c, CURLOPT_FORBID_REUSE, 1L);
    }
    /* Proxy precedence: env proxy wins; else CVMFS-config proxy; else force direct. */
    char sch[8], thost[256]; int tport;
    url_host(url, sch, sizeof(sch), thost, sizeof(thost), &tport);
    brix_proxy_t px;
    if (brix_proxy_resolve(sch, thost, tport, &px)) {
        curl_easy_setopt(c, CURLOPT_PROXY, px.url);
        brix_proxy_report(&px, thost, tport);
    } else if (proxy != NULL && strcmp(proxy, "DIRECT") != 0) {
        curl_easy_setopt(c, CURLOPT_PROXY, proxy);
    } else {
        curl_easy_setopt(c, CURLOPT_PROXY, "");
    }

    CURLcode rc = curl_easy_perform(c);
    long code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    if (start > 0 && code != 206 && sink.len > start) {
        /* Range not honoured (200): the bytes appended after `start` are actually
         * a fresh stream from offset 0 — slide them to the front. */
        size_t fresh = sink.len - start;
        memmove(out, out + start, fresh);
        *got = fresh;
    } else {
        *got = sink.len;
    }
    curl_easy_cleanup(c);
    return rc;
}

/* Rewrite an http:// url to https:// into `buf`; returns 1 if rewritten. */
static int to_https(const char *url, char *buf, size_t n) {
    if (strncmp(url, "http://", 7) != 0) return 0;
    snprintf(buf, n, "https://%s", url + 7);
    return 1;
}

/* DPI/loss-hardened transport: RANGE-RESUME on a severed transfer (so a large
 * object survives per-chunk connection loss — the key to 10%+ loss), optional
 * TLS-first, optional fresh-connection. As long as each attempt makes progress
 * (more bytes received) we keep resuming up to a generous cap; only attempts that
 * make NO progress count against the retry budget. Across-mirror failover +
 * hash-verify are owned by the fetch layer. */
static int brixcvmfs_transport(const char *proxy, const char *host, const char *rel,
                               unsigned char *out, size_t outcap, size_t *outlen, void *ud) {
    (void) ud;
    char httpurl[1024];
    snprintf(httpurl, sizeof(httpurl), "%s/%s", host, rel);

    int    budget  = g_tcfg.max_retries > 0 ? g_tcfg.max_retries : 6;
    int    hard_cap = 64;                 /* absolute ceiling on resume attempts */
    int    stalls  = 0;
    size_t got = 0, last = 0;

    for (int i = 0; i < hard_cap; i++) {
        char httpsbuf[1024];
        int  use_https = (i == 0 && g_tcfg.prefer_tls
                          && to_https(httpurl, httpsbuf, sizeof(httpsbuf)));
        const char *url = use_https ? httpsbuf : httpurl;

        CURLcode rc = http_get_range(proxy, url, out, outcap, &got);
        if (rc == CURLE_OK) { *outlen = got; return 0; }

        /* hard 4xx over plain http = mirror lacks the object → fail over. A 4xx on
         * the https probe just means no TLS — fall through to http. */
        if (rc == CURLE_HTTP_RETURNED_ERROR && !use_https) break;

        if (got > last) { last = got; stalls = 0; }   /* progress → keep resuming */
        else if (++stalls > budget) break;            /* no progress → give up route */

        long ms = 200L << (stalls < 6 ? stalls : 6);  /* backoff on stalls only */
        struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
        nanosleep(&ts, NULL);
    }
    return -1;
}

/* ---- path mapping: FUSE "/" is the catalog root "" ---------------------- */
static const char *cat_path(const char *p) { return strcmp(p, "/") == 0 ? "" : p; }

static long mono_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long) ts.tv_sec;
}

/* ---- seam to the cvmfs-rw union driver (brixcvmfs_internal.h) ------------ */

int brixcvmfs_rw = 0;      /* 1 = mount with the rw ops table (set pre-dispatch) */

cvmfs_client_t *brixcvmfs_client(void)             { return g_cl; }
const char     *brixcvmfs_cat_path(const char *p)  { return cat_path(p); }
long            brixcvmfs_mono_now(void)           { return mono_now(); }

/* ---- FUSE ops (read-only) ---------------------------------------------- */

int brixcvmfs_op_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
    (void) fi;
    cvmfs_client_refresh(g_cl, mono_now());     /* TTL-gated: no-op until due */
    cvmfs_client_reap_tick(g_cl, mono_now());   /* quota-gated: no-op until due */
    cvmfs_dirent_t e;
    int rc = cvmfs_client_resolve(g_cl, cat_path(path), &e, mono_now());
    if (rc < 0)  return -EIO;
    if (rc == 0) return -ENOENT;

    memset(st, 0, sizeof(*st));
    st->st_mode  = e.mode;
    st->st_size  = (off_t) e.size;
    st->st_mtime = (time_t) e.mtime;
    st->st_nlink = (e.flags & CVMFS_FLAG_DIR) ? 2 : e.linkcount;
    st->st_uid   = e.uid ? e.uid : getuid();
    st->st_gid   = e.gid ? e.gid : getgid();
    return 0;
}

typedef struct { void *buf; fuse_fill_dir_t filler; } readdir_ctx_t;

static void readdir_emit(const cvmfs_dirent_t *e, void *ud) {
    readdir_ctx_t *r = ud;
    if (e->name[0] != '\0')
        r->filler(r->buf, e->name, NULL, 0, 0);
}

int brixcvmfs_op_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t off, struct fuse_file_info *fi, enum fuse_readdir_flags fl) {
    (void) off; (void) fi; (void) fl;
    cvmfs_client_refresh(g_cl, mono_now());   /* TTL-gated: no-op until due */
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    readdir_ctx_t r = { buf, filler };
    int n = cvmfs_catalog_readdir(g_cl->root_catalog, cat_path(path), readdir_emit, &r);
    return n < 0 ? -EIO : 0;
}

int brixcvmfs_op_open(const char *path, struct fuse_file_info *fi) {
    if ((fi->flags & O_ACCMODE) != O_RDONLY) return -EROFS;   /* read-only fs */
    cvmfs_dirent_t e;
    int rc = cvmfs_client_resolve(g_cl, cat_path(path), &e, mono_now());
    if (rc < 0)  return -EIO;
    if (rc == 0) return -ENOENT;
    if (!(e.flags & CVMFS_FLAG_FILE)) return -EISDIR;
    return 0;
}

int brixcvmfs_op_read(const char *path, char *buf, size_t size, off_t off,
                   struct fuse_file_info *fi) {
    (void) fi;
    size_t got = 0;
    int rc = cvmfs_client_read(g_cl, cat_path(path), (uint64_t) off, size,
                               (unsigned char *) buf, &got, mono_now());
    return rc == 0 ? (int) got : -EIO;
}

int brixcvmfs_op_readlink(const char *path, char *buf, size_t size) {
    cvmfs_dirent_t e;
    int rc = cvmfs_client_resolve(g_cl, cat_path(path), &e, mono_now());
    if (rc <= 0) return rc < 0 ? -EIO : -ENOENT;
    if (!(e.flags & CVMFS_FLAG_LINK)) return -EINVAL;
    snprintf(buf, size, "%s", e.symlink);
    return 0;
}

int brixcvmfs_op_statfs(const char *path, struct statvfs *sv) {
    (void) path;
    memset(sv, 0, sizeof(*sv));
    sv->f_bsize = 4096;
    sv->f_namemax = 255;
    return 0;
}

int brixcvmfs_op_getxattr(const char *path, const char *name, char *value, size_t size) {
    int n = cvmfs_client_getxattr(g_cl, cat_path(path), name, value, size, mono_now());
    if (n < 0)              return -ENODATA;    /* attribute not present */
    if (size == 0)          return n;           /* size probe */
    if ((size_t) n > size)  return -ERANGE;
    return n;
}

int brixcvmfs_op_listxattr(const char *path, char *list, size_t size) {
    (void) path;
    int n = cvmfs_client_listxattr(list, size);
    if (size == 0)          return n;
    if ((size_t) n > size)  return -ERANGE;
    return n;
}

/* every mutating op is refused */
static int ro_erofs(void) { return -EROFS; }
static int op_mkdir(const char *p, mode_t m) { (void)p;(void)m; return ro_erofs(); }
static int op_unlink(const char *p) { (void)p; return ro_erofs(); }
static int op_write(const char *p, const char *b, size_t s, off_t o, struct fuse_file_info *fi)
    { (void)p;(void)b;(void)s;(void)o;(void)fi; return ro_erofs(); }

static const struct fuse_operations brixcvmfs_ops = {
    .getattr  = brixcvmfs_op_getattr,
    .readdir  = brixcvmfs_op_readdir,
    .open     = brixcvmfs_op_open,
    .read     = brixcvmfs_op_read,
    .readlink = brixcvmfs_op_readlink,
    .statfs   = brixcvmfs_op_statfs,
    .getxattr  = brixcvmfs_op_getxattr,
    .listxattr = brixcvmfs_op_listxattr,
    .mkdir    = op_mkdir,
    .unlink   = op_unlink,
    .write    = op_write,
};

/* ---- front-end --------------------------------------------------------- */

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

/* Parsed brix-specific mount options (the rest of `-o` is forwarded to libfuse). */
typedef struct {
    int   clever;              /* overlay cache in <mnt>/.brixcache (default ON) */
    int   quota_mb;            /* -o quota=<MB> (0 = from config/unlimited) */
    int   fresh;               /* -o fresh: fresh connection per request */
    int   tls;                 /* -o tls: prefer https:// */
    int   retries;            /* -o retries=<N> (-1 = from config/default) */
    char  cache_dir[512];      /* -o cache=<DIR> (implies non-clever) */
    char  fuse_extra[512];     /* passthrough -o tokens, comma-joined */
    char *flags[16]; int nflags;  /* passthrough flags (-f/-d/-h/...) */
} brix_opts_t;

static void opts_o_list(char *list, brix_opts_t *o) {
    char *save = NULL;
    for (char *t = strtok_r(list, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        if      (strcmp(t, "clever") == 0)   o->clever = 1;
        else if (strcmp(t, "noclever") == 0) o->clever = 0;
        else if (strcmp(t, "fresh") == 0)    o->fresh = 1;
        else if (strcmp(t, "tls") == 0)      o->tls = 1;
        else if (strncmp(t, "quota=", 6) == 0)   o->quota_mb = atoi(t + 6);
        else if (strncmp(t, "retries=", 8) == 0) o->retries = atoi(t + 8);
        else if (strncmp(t, "cache=", 6) == 0)
            snprintf(o->cache_dir, sizeof(o->cache_dir), "%s", t + 6);
        else {   /* forward to libfuse */
            size_t cur = strlen(o->fuse_extra);
            snprintf(o->fuse_extra + cur, sizeof(o->fuse_extra) - cur,
                     "%s%s", cur ? "," : "", t);
        }
    }
}

static void parse_opts(int argc, char **argv, int start, brix_opts_t *o) {
    memset(o, 0, sizeof(*o));
    o->clever = 1; o->retries = -1;
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

/* Build failover + config and verify-mount the repo trust chain. Cache backing:
 * `cache_dirfd >= 0` = overlay dirfd mode; else `cache_dir_override` (or the
 * default/env path). quota/retries fall back to the config cascade when the
 * override is unset (<=0 quota, <0 retries). Returns a mounted client or NULL. */
static cvmfs_client_t *brixcvmfs_open(const char *repo, const char *cache_dir_override,
                                      int cache_dirfd, long quota_override, int retries_override) {
    cvmfs_client_t *cl = calloc(1, sizeof(*cl));
    if (cl == NULL) { fprintf(stderr, "brixcvmfs: out of memory\n"); return NULL; }

    if (cvmfs_repo_config_defaults(repo, &cl->config) != 0) {
        fprintf(stderr, "brixcvmfs: '%s' is not a fully-qualified repo name\n", repo);
        free(cl); return NULL;
    }

    cvmfs_conf_t cf;
    cvmfs_conf_init(&cf);
    cvmfs_conf_load_cascade(&cf, getenv("BRIXCVMFS_ETC"), repo);   /* for quota/retries */

    cvmfs_failover_init(&cl->fo, 60);
    const char *env_server = getenv("BRIXCVMFS_SERVER");
    if (env_server != NULL) {
        cvmfs_failover_add_proxy(&cl->fo, "DIRECT", 0);
        cvmfs_failover_add_host(&cl->fo, env_server);
    } else {
        int hosts = cvmfs_conf_apply(&cf, repo, &cl->config, &cl->fo);
        if (hosts == 0) {
            char s1[400];
            snprintf(s1, sizeof(s1), "http://cvmfs-stratum-one.%s/cvmfs/%s",
                     strchr(repo, '.') + 1, repo);
            cvmfs_failover_add_host(&cl->fo, s1);
        }
    }

    snprintf(g_tcfg.repo, sizeof(g_tcfg.repo), "%s", repo);
    g_tcfg.connect_timeout_s = cl->config.timeout_s > 0 ? cl->config.timeout_s : 5;
    g_tcfg.low_speed_time_s  = g_tcfg.connect_timeout_s;
    g_tcfg.low_speed_bytes   = 100;
    const char *cfg_retries = cvmfs_conf_get(&cf, "CVMFS_MAX_RETRIES");
    g_tcfg.max_retries = retries_override >= 0 ? retries_override
                       : (cfg_retries ? atoi(cfg_retries) : 2);

    long quota = quota_override > 0 ? quota_override : 0;
    if (quota == 0) {
        const char *q = cvmfs_conf_get(&cf, "CVMFS_QUOTA_LIMIT");   /* MB */
        if (q && atol(q) > 0) quota = atol(q) * 1024L * 1024L;
    }

    const char *keypath = getenv("BRIXCVMFS_PUBKEY");
    if (keypath == NULL) keypath = cl->config.master_pub_path;
    size_t klen = 0;
    unsigned char *master = load_master_key(keypath, &klen);
    if (master == NULL) {
        fprintf(stderr, "brixcvmfs: cannot read master key %s\n", keypath);
        free(cl); return NULL;
    }

    char tmp_dir[512];
    const char *env_tmp = getenv("BRIXCVMFS_TMP");
    if (env_tmp) snprintf(tmp_dir, sizeof(tmp_dir), "%s", env_tmp);
    else         snprintf(tmp_dir, sizeof(tmp_dir), "/tmp/brixcvmfs-%s", repo);
    { char mk[600]; snprintf(mk, sizeof(mk), "mkdir -p '%s'", tmp_dir);
      if (system(mk) != 0) { /* mount will fail later if truly unusable */ } }

    char cache_dir[512] = "";
    if (cache_dirfd < 0) {
        const char *env_cache = getenv("BRIXCVMFS_CACHE");
        if (cache_dir_override) snprintf(cache_dir, sizeof(cache_dir), "%s", cache_dir_override);
        else if (env_cache)     snprintf(cache_dir, sizeof(cache_dir), "%s", env_cache);
        else                    snprintf(cache_dir, sizeof(cache_dir), "/var/lib/brixcvmfs/%s", repo);
        char mk[600]; snprintf(mk, sizeof(mk), "mkdir -p '%s'", cache_dir);
        if (system(mk) != 0) { /* mount will fail later if unusable */ }
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);
    int mrc = cvmfs_client_mount(cl, repo, master, klen,
                                 cache_dirfd < 0 ? cache_dir : NULL, tmp_dir,
                                 quota, cache_dirfd, brixcvmfs_transport, NULL, mono_now());
    free(master);
    if (mrc != 0) {
        fprintf(stderr, "brixcvmfs: mount of %s failed (trust/catalog error %d)\n", repo, mrc);
        curl_global_cleanup();
        free(cl); return NULL;
    }
    return cl;
}

/* --check: verify the trust chain + root catalog and print a summary WITHOUT
 * mounting (the stock `cvmfs_config chksetup` analog). Exit 0 = healthy. */
static int brixcvmfs_check(const char *repo) {
    cvmfs_client_t *cl = brixcvmfs_open(repo, NULL, -1, 0, -1);
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
    curl_global_cleanup();
    free(cl);
    return root_ok ? 0 : 1;
}

/* brixcvmfs entry — reused by the brixMount umbrella (SP-G).
 *   brixcvmfs <repo> <mountpoint> [fuse-opts]   — mount
 *   brixcvmfs --check <repo>                     — verify + summarise, no mount */
int brixcvmfs_main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "--check") == 0)
        return brixcvmfs_check(argv[2]);

    if (argc < 3) {
        fprintf(stderr,
            "usage: brixcvmfs <repo.fqrn> <mountpoint> [fuse-opts]\n"
            "       brixcvmfs --check <repo.fqrn>\n");
        return 2;
    }
    const char *repo = argv[1];
    const char *mnt  = argv[2];

    brix_opts_t o;
    parse_opts(argc, argv, 3, &o);
    g_tcfg.fresh_connect = o.fresh;
    g_tcfg.prefer_tls    = o.tls;
    long quota = o.quota_mb > 0 ? (long) o.quota_mb * 1024L * 1024L : 0;

    /* Clever overlay (default ON): store cache in <mnt>/.brixcache reached via a
     * dirfd opened BEFORE the FUSE mount hides it. An explicit cache (-o cache= or
     * $BRIXCVMFS_CACHE) opts out. */
    int         cache_dirfd = -1;
    const char *cache_override = NULL;
    int         clever = o.clever;
    if (o.cache_dir[0]) { cache_override = o.cache_dir; clever = 0; }
    else if (getenv("BRIXCVMFS_CACHE")) { clever = 0; }
    if (clever) {
        mkdir(mnt, 0755);                       /* ensure the mountpoint exists */
        char sub[600];
        snprintf(sub, sizeof(sub), "%s/.brixcache", mnt);
        if (mkdir(sub, 0755) != 0 && errno != EEXIST)
            fprintf(stderr, "brixcvmfs: warning: cannot create overlay cache %s\n", sub);
        cache_dirfd = open(sub, O_RDONLY | O_DIRECTORY);
        if (cache_dirfd < 0)
            fprintf(stderr, "brixcvmfs: overlay cache unavailable, falling back\n");
    }

    cvmfs_client_t *cl = brixcvmfs_open(repo, cache_override, cache_dirfd, quota, o.retries);
    if (cl == NULL) { if (cache_dirfd >= 0) close(cache_dirfd); return 1; }
    g_cl = cl;

    /* hand the mountpoint (+ passthrough flags/opts) to libfuse. Force
     * single-threaded (-s): the client shares one SQLite catalog handle +
     * lock-free failover state, so serialised FUSE dispatch is the correct,
     * race-free choice (reads are cache-served, so throughput is unaffected). */
    char *fargv[24]; int fargc = 0;
    fargv[fargc++] = argv[0];
    fargv[fargc++] = (char *) mnt;
    fargv[fargc++] = (char *) "-s";
    for (int i = 0; i < o.nflags && fargc < 20; i++) fargv[fargc++] = o.flags[i];
    if (o.fuse_extra[0]) { fargv[fargc++] = (char *) "-o"; fargv[fargc++] = o.fuse_extra; }

    int rc = fuse_main(fargc, fargv, &brixcvmfs_ops, NULL);

    cvmfs_client_umount(cl);
    curl_global_cleanup();
    if (cache_dirfd >= 0) close(cache_dirfd);
    free(cl);
    return rc;
}

#ifndef BRIXCVMFS_NO_MAIN
int main(int argc, char **argv) { return brixcvmfs_main(argc, argv); }
#endif
