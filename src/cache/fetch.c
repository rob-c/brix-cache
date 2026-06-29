#include "cache_internal.h"
#include "cache_admit.h"
#include "cache_storage.h"
#include "meta.h"
#include "verify.h"
#include "../compat/checksum.h"   /* xrootd_checksum_hex_obj / _parse (verify) */
#include "origin/http_transport.h"
#include "origin/pelican.h"
#include "origin/s3_transport.h"               /* server libcurl S3 transport */
#include "../fs/backend/remote/sd_remote.h"    /* read-only S3 remote-origin driver */
#include "../fs/backend/xroot/sd_xroot.h"      /* read-only root:// remote-origin driver */


#include <fcntl.h>
#include <regex.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

/* xrootd_cache_commit_part — publish the downloaded part file: atomically rename
 * part_path → cache_path, write the .meta sidecar, and record the cached size on
 * the task. Shared by the anonymous-protocol and exec-GSI fills. Returns 0 / -1
 * (t error set). */
static int
xrootd_cache_commit_part(xrootd_cache_fill_t *t)
{
    struct stat                   st;
    xrootd_cache_meta_t           meta;
    ngx_log_t                    *log;
    xrootd_cache_digest_t         origin;
    xrootd_cache_verify_result_e  vr;
    char                          vy_alg[16];
    char                          vy_hex[129];

    log = (t->c != NULL) ? t->c->log : NULL;

    /*
     * Checksum-on-fill: verify the staged part against the origin's advertised
     * digest BEFORE the atomic rename, so a corrupted/truncated transfer never
     * becomes a served cache entry. Fail-closed best-effort by default
     * (xrootd_cache_verify). t->origin_cks_* is empty when the origin offered no
     * checksum (e.g. the GSI-exec fetch path) — the verify policy then governs.
     */
    ngx_memzero(&origin, sizeof(origin));
    if (t->origin_cks_alg[0] != '\0') {
        size_t an = ngx_min(ngx_strlen(t->origin_cks_alg), sizeof(origin.alg) - 1);
        size_t hn = ngx_min(ngx_strlen(t->origin_cks_hex), sizeof(origin.hex) - 1);
        ngx_memcpy(origin.alg, t->origin_cks_alg, an);
        ngx_memcpy(origin.hex, t->origin_cks_hex, hn);
    }

    vy_alg[0] = '\0';
    vy_hex[0] = '\0';
    vr = xrootd_cache_verify_part(t, t->part_path, &origin,
            (xrootd_cache_verify_mode_e) t->conf->cache_verify, vy_alg, vy_hex);
    if (vr == XROOTD_CACHE_VERIFY_MISMATCH || vr == XROOTD_CACHE_VERIFY_ERROR) {
        unlink(t->part_path);          /* t error already set by verify */
        return -1;
    }

    if (rename(t->part_path, t->cache_path) != 0) {
        unlink(t->part_path);
        xrootd_cache_set_syserror(t, kXR_IOError, "cache part file rename failed");
        return -1;
    }

    if (stat(t->cache_path, &st) == 0
        && xrootd_cache_meta_from_stat(&st, NULL, &meta) == NGX_OK)
    {
        t->file_size = (uint64_t) st.st_size;

        /* Record a verified digest into the sidecar for durable provenance. */
        if (vr == XROOTD_CACHE_VERIFY_VERIFIED && vy_alg[0] != '\0') {
            size_t an = ngx_min(ngx_strlen(vy_alg), sizeof(meta.cks_alg) - 1);
            size_t hn = ngx_min(ngx_strlen(vy_hex), sizeof(meta.cks_hex) - 1);
            meta.version     = XROOTD_CACHE_META_VERSION;
            meta.cks_alg_len = (uint8_t) an;
            ngx_memcpy(meta.cks_alg, vy_alg, an);
            meta.cks_alg[an] = '\0';
            meta.cks_len     = (uint8_t) hn;
            ngx_memcpy(meta.cks_hex, vy_hex, hn);
            meta.cks_hex[hn] = '\0';
        }

        if (xrootd_cache_meta_write(log, t->cache_path, &meta) != NGX_OK
            && log != NULL)
        {
            ngx_log_error(NGX_LOG_WARN, log, errno,
                          "xrootd: cache metadata write failed \"%s\"",
                          t->cache_path);
        }
    }
    return 0;
}

/* The cache key (suffix under cache_root) for this fill's cache_path — what the
 * cache STORAGE driver keys its namespace on. NULL if cache_path is not under
 * cache_root (should never happen). */
static const char *
xrootd_cache_fill_key(const xrootd_cache_fill_t *t)
{
    size_t crlen = t->conf->cache_root.len;

    if (crlen == 0
        || ngx_strncmp(t->cache_path, t->conf->cache_root.data, crlen) != 0)
    {
        return NULL;
    }
    return t->cache_path + crlen;          /* "/suffix" (leading slash) */
}

/* Commit-then-verify for the staged (driver-backed) built-in fill: the bytes are
 * already published by staged_commit. Stat for the size, verify the committed
 * entry THROUGH the driver against the origin's advertised digest (evict on a
 * mismatch — never serve proven-bad data), then write the .meta sidecar. */
static int
xrootd_cache_commit_staged(xrootd_cache_fill_t *t, xrootd_sd_instance_t *inst,
    const char *key)
{
    ngx_log_t        *log = (t->c != NULL) ? t->c->log : NULL;
    xrootd_sd_stat_t  sst;

    if (inst->driver->stat(inst, key, &sst) != NGX_OK) {
        xrootd_cache_set_syserror(t, kXR_IOError, "cache commit stat failed");
        return -1;
    }
    t->file_size = (uint64_t) sst.size;

    if (t->conf->cache_verify != XROOTD_CACHE_VERIFY_OFF
        && t->origin_cks_alg[0] != '\0')
    {
        xrootd_checksum_alg_t alg;
        char                  alg_name[16];

        if (xrootd_checksum_parse(t->origin_cks_alg,
                                  ngx_strlen(t->origin_cks_alg),
                                  &alg, alg_name, sizeof(alg_name)) == NGX_OK)
        {
            int              e = 0;
            xrootd_sd_obj_t *o = inst->driver->open(inst, key, XROOTD_SD_O_READ,
                                                    0, &e);
            if (o != NULL) {
                char hex[EVP_MAX_MD_SIZE * 2 + 1];
                int  ok = (xrootd_checksum_hex_obj(alg, o, key, log, hex,
                                                   sizeof(hex)) == NGX_OK)
                          && ngx_strcmp(hex, t->origin_cks_hex) == 0;
                (void) inst->driver->close(o);
                if (o->heap_shell) {
                    free(o);
                }
                if (!ok) {
                    (void) inst->driver->unlink(inst, key, 0);
                    xrootd_cache_set_error(t, kXR_ServerError, 0,
                        "cache fill checksum mismatch (entry evicted)");
                    return -1;
                }
            }
        }
    }

    /* .meta sidecar (origin validity), written at the POSIX state path (== the
     * cache path for a co-located cache). Built from the driver's stat, since a
     * driver-backed entry has no POSIX cache_path to stat. Best-effort. */
    {
        struct stat         pst;
        xrootd_cache_meta_t meta;
        char                sidecar[PATH_MAX];
        const char         *state_root =
            t->conf->cache_state_root.len
                ? (const char *) t->conf->cache_state_root.data
                : (const char *) t->conf->cache_root.data;

        ngx_memzero(&pst, sizeof(pst));
        pst.st_size = (off_t) sst.size;
        pst.st_mtime = sst.mtime;
        if (xrootd_cache_meta_from_stat(&pst, NULL, &meta) == NGX_OK
            && xrootd_cache_sidecar_path((const char *) t->conf->cache_root.data,
                   state_root, t->cache_path, sidecar, sizeof(sidecar)) == 0)
        {
            (void) xrootd_cache_meta_write(log, sidecar, &meta);
        }
    }
    return 0;
}

/* xrootd_cache_fetch_origin_exec — GSI/X.509-proxy origin fetch: fork/exec the
 * native client (cache_origin_client, default "xrdcp") to download into part_path
 * with X509_USER_PROXY + X509_CERT_DIR overridden, then xrootd_cache_commit_part().
 * The built-in client only does an anonymous kXR_login, which a GSI origin (e.g.
 * EOS) rejects; the native client speaks full GSI + open-redirect, so we reuse it
 * as the PSS. Runs in the fill worker (blocking), so posix_spawn + waitpid is fine. */
static int
xrootd_cache_fetch_origin_exec(xrootd_cache_fill_t *t)
{
    ngx_stream_xrootd_srv_conf_t *conf = t->conf;
    char        url[XROOTD_MAX_PATH + 320];
    char        proxy_env[XROOTD_MAX_PATH + 32];
    char        cadir_env[XROOTD_MAX_PATH + 32];
    char        bearer_env[XROOTD_MAX_PATH + 32];
    const char *client;
    char      **envp;
    char       *argv[6];
    int         n, rc, wstatus, ai;
    size_t      envn, ei;
    pid_t       pid;

    if (conf->cache_origin_host.len == 0) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
            "authenticated cache origin (proxy/token) set but no xrootd_cache_origin");
        return -1;
    }

    /* root[s]://host:port//<clean_path>  (clean_path carries its leading '/') */
    n = snprintf(url, sizeof(url), "%s://%s:%u/%s",
                 conf->cache_origin_tls ? "roots" : "root",
                 (char *) conf->cache_origin_host.data,
                 (unsigned) conf->cache_origin_port, t->clean_path);
    if (n < 0 || (size_t) n >= sizeof(url)) {
        xrootd_cache_set_error(t, kXR_ServerError, 0, "cache origin URL too long");
        return -1;
    }

    /* The native client (libxrdc) authenticates the origin from the environment:
     * X509_USER_PROXY/X509_CERT_DIR drive GSI, BEARER_TOKEN_FILE drives token auth
     * (xrdc_token_discover). The cache supplies whichever the operator configured,
     * so a root:// origin gets GSI and/or token parity with the http(s):// path —
     * each is added only when set. */
    int have_proxy = (conf->cache_origin_proxy.len > 0);
    int have_token = (conf->cache_origin_token_file.len > 0);

    if (have_proxy) {
        n = snprintf(proxy_env, sizeof(proxy_env), "X509_USER_PROXY=%s",
                     (char *) conf->cache_origin_proxy.data);
        if (n < 0 || (size_t) n >= sizeof(proxy_env)) {
            xrootd_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin proxy path too long");
            return -1;
        }
        n = snprintf(cadir_env, sizeof(cadir_env), "X509_CERT_DIR=%s",
                     (char *) conf->cache_origin_cadir.data);
        if (n < 0 || (size_t) n >= sizeof(cadir_env)) {
            xrootd_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin CA dir too long");
            return -1;
        }
    }
    if (have_token) {
        n = snprintf(bearer_env, sizeof(bearer_env), "BEARER_TOKEN_FILE=%s",
                     (char *) conf->cache_origin_token_file.data);
        if (n < 0 || (size_t) n >= sizeof(bearer_env)) {
            xrootd_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin token path too long");
            return -1;
        }
    }

    client = conf->cache_origin_client.len
             ? (char *) conf->cache_origin_client.data : "xrdcp";

    /* envp = environ minus any inherited X509 / BEARER credential vars, plus the
     * configured ones (so the cache's own credentials win, never the worker's). */
    for (envn = 0; environ[envn] != NULL; envn++) { /* count */ }
    envp = malloc((envn + 4) * sizeof(char *));
    if (envp == NULL) {
        xrootd_cache_set_error(t, kXR_NoMemory, 0, "cache origin envp alloc failed");
        return -1;
    }
    ei = 0;
    for (n = 0; (size_t) n < envn; n++) {
        if (strncmp(environ[n], "X509_USER_PROXY=", 16) == 0
            || strncmp(environ[n], "X509_CERT_DIR=", 14) == 0
            || strncmp(environ[n], "BEARER_TOKEN=", 13) == 0
            || strncmp(environ[n], "BEARER_TOKEN_FILE=", 18) == 0) {
            continue;
        }
        envp[ei++] = environ[n];
    }
    if (have_proxy) {
        envp[ei++] = proxy_env;
        envp[ei++] = cadir_env;
    }
    if (have_token) {
        envp[ei++] = bearer_env;
    }
    envp[ei]   = NULL;

    ai = 0;
    argv[ai++] = (char *) client;
    argv[ai++] = (char *) "-f";       /* overwrite the part file */
    argv[ai++] = url;
    argv[ai++] = t->part_path;
    argv[ai]   = NULL;

    rc = posix_spawnp(&pid, client, NULL, NULL, argv, envp);
    free(envp);
    if (rc != 0) {
        char emsg[256];
        snprintf(emsg, sizeof(emsg),
                 "cache origin client '%s' spawn failed", client);
        xrootd_cache_set_error(t, kXR_ServerError, rc, emsg);
        return -1;
    }

    while (waitpid(pid, &wstatus, 0) < 0 && errno == EINTR) { /* retry */ }

    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
        char emsg[XROOTD_MAX_PATH + 384];
        unlink(t->part_path);
        snprintf(emsg, sizeof(emsg),
                 "origin GSI fetch via %s failed (exit %d) for %s",
                 client, WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1, url);
        xrootd_cache_set_error(t, kXR_AuthFailed, 0, emsg);
        return -1;
    }

    return xrootd_cache_commit_part(t);
}

/* xrootd_cache_fetch_origin_s3 — fill from an S3 origin (scheme s3://) THROUGH the
 * read-only remote-origin SD driver (sd_remote → shared sd_s3 → server libcurl
 * transport). The whole-object copy is driver→driver: open the origin object,
 * pread sequential ranges into the cache's staged-write sink, then commit + verify.
 * Returns 0 (success), 1 (admission decline), -1 (error; t error fields set). */
static int
xrootd_cache_fetch_origin_s3(xrootd_cache_fill_t *t)
{
    ngx_stream_xrootd_srv_conf_t *conf = t->conf;
    xrootd_sd_remote_cfg_t        cfg;
    xrootd_sd_instance_t         *origin;
    xrootd_sd_instance_t         *cache_inst = xrootd_cache_storage(conf);
    const char                   *key = xrootd_cache_fill_key(t);
    xrootd_sd_obj_t              *src;
    xrootd_sd_staged_t           *staged;
    xrootd_cache_sink_t           sink;
    ngx_log_t                    *log = (t->c != NULL) ? t->c->log : NULL;
    u_char                       *buf;
    off_t                         off = 0;
    int                           e = 0;

    if (cache_inst == NULL || key == NULL) {
        xrootd_cache_set_error(t, kXR_ServerError, 0, "cache storage unavailable");
        return -1;
    }
    if (conf->cache_origin_s3_bucket.len == 0) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
            "s3 origin: no bucket (use s3://endpoint/bucket)");
        return -1;
    }

    ngx_memzero(&cfg, sizeof(cfg));
    cfg.scheme = XROOTD_SD_REMOTE_S3;
    cfg.port   = (int) conf->cache_origin_port;
    cfg.tls    = (conf->cache_origin_tls == 1) ? 1 : 0;
    cfg.timeout_ms = 60000;
    cfg.transport  = &xrootd_s3_origin_curl_transport;
    ngx_snprintf((u_char *) cfg.host, sizeof(cfg.host) - 1, "%V%Z",
                 &conf->cache_origin_host);
    ngx_snprintf((u_char *) cfg.bucket, sizeof(cfg.bucket) - 1, "%V%Z",
                 &conf->cache_origin_s3_bucket);
    ngx_snprintf((u_char *) cfg.access_key, sizeof(cfg.access_key) - 1, "%V%Z",
                 &conf->cache_origin_s3_access_key);
    ngx_snprintf((u_char *) cfg.secret_key, sizeof(cfg.secret_key) - 1, "%V%Z",
                 &conf->cache_origin_s3_secret_key);
    ngx_snprintf((u_char *) cfg.region, sizeof(cfg.region) - 1, "%V%Z",
                 &conf->cache_origin_s3_region);

    origin = xrootd_sd_remote_create(&cfg, log);
    if (origin == NULL) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "s3 origin instance create failed");
        return -1;
    }

    /* The origin object key is the requested logical path; sd_remote prepends the
     * bucket. */
    src = origin->driver->open(origin, t->clean_path, XROOTD_SD_O_READ, 0, &e);
    if (src == NULL) {
        xrootd_sd_remote_destroy(origin);
        xrootd_cache_set_error(t, (e == ENOENT) ? kXR_NotFound : kXR_IOError, e,
                               "s3 origin object open failed");
        return -1;
    }
    t->file_size = (uint64_t) src->snap.size;

    /* Admission filter (size/prefix/regex), shared with write-through + root://. */
    {
        xrootd_cache_admit_cfg_t admit = {
            .deny_prefixes  = conf->cache_deny_prefixes,
            .allow_prefixes = conf->cache_allow_prefixes,
            .size_limit     = conf->cache_max_file_size,
            .include_regex  = conf->cache_include_regex_set
                              ? &conf->cache_include_regex : NULL,
        };
        if (xrootd_cache_admit(&admit, t->clean_path, (off_t) t->file_size, 0)
            == XROOTD_CACHE_DECLINE)
        {
            origin->driver->close(src);
            if (src->heap_shell) { free(src); }
            xrootd_sd_remote_destroy(origin);
            t->result = NGX_DECLINED;
            return 1;
        }
    }

    staged = cache_inst->driver->staged_open(cache_inst, key, 0644, &e);
    if (staged == NULL) {
        origin->driver->close(src);
        if (src->heap_shell) { free(src); }
        xrootd_sd_remote_destroy(origin);
        xrootd_cache_set_error(t, kXR_IOError, e, "cache staged open failed");
        return -1;
    }
    sink.fd = -1;
    sink.staged = staged;

    buf = malloc(XROOTD_CACHE_FETCH_CHUNK);
    if (buf == NULL) {
        cache_inst->driver->staged_abort(staged);
        origin->driver->close(src);
        if (src->heap_shell) { free(src); }
        xrootd_sd_remote_destroy(origin);
        xrootd_cache_set_error(t, kXR_NoMemory, 0, "cache fill buffer alloc failed");
        return -1;
    }

    for (;;) {
        ssize_t n = src->driver->pread(src, buf, XROOTD_CACHE_FETCH_CHUNK, off);

        /* sink_pwrite returns 0 on success, -1 on failure (NOT a byte count). */
        if (n < 0
            || (n > 0
                && xrootd_cache_sink_pwrite(&sink, buf, (size_t) n, off) != 0))
        {
            free(buf);
            cache_inst->driver->staged_abort(staged);
            origin->driver->close(src);
            if (src->heap_shell) { free(src); }
            xrootd_sd_remote_destroy(origin);
            xrootd_cache_set_error(t, kXR_IOError, errno,
                                   "s3 origin read / cache write failed");
            return -1;
        }
        off += n;
        if ((size_t) n < XROOTD_CACHE_FETCH_CHUNK) {
            break;                           /* short read = EOF */
        }
    }

    free(buf);
    origin->driver->close(src);
    if (src->heap_shell) { free(src); }
    xrootd_sd_remote_destroy(origin);

    if (cache_inst->driver->staged_commit(staged, 0) != NGX_OK) {
        xrootd_cache_set_error(t, kXR_IOError, 0, "cache staged commit failed");
        return -1;
    }
    return xrootd_cache_commit_staged(t, cache_inst, key);
}

/* xrootd_cache_fetch_origin_xroot — fill from an anonymous root:// origin THROUGH
 * the read-only root:// remote-origin SD driver (sd_xroot wraps the in-process
 * XRootD wire client). Driver→driver copy: open the origin file, pread sequential
 * ranges into the staged-write sink, query the origin checksum (kXR_Qcksum) for
 * commit-then-verify, then commit. Returns 0 / 1 (admission decline) / -1.
 * Authenticated root:// origins (token/GSI) use the native-client delegation
 * (xrootd_cache_fetch_origin_exec), not this in-process anonymous driver. */
static int
xrootd_cache_fetch_origin_xroot(xrootd_cache_fill_t *t)
{
    ngx_stream_xrootd_srv_conf_t *conf = t->conf;
    xrootd_sd_instance_t         *origin;
    xrootd_sd_instance_t         *cache_inst = xrootd_cache_storage(conf);
    const char                   *key = xrootd_cache_fill_key(t);
    xrootd_sd_obj_t              *src;
    xrootd_sd_staged_t           *staged;
    xrootd_cache_sink_t           sink;
    ngx_log_t                    *log = (t->c != NULL) ? t->c->log : NULL;
    u_char                       *buf;
    off_t                         off = 0;
    int                           e = 0;

    if (cache_inst == NULL || key == NULL) {
        xrootd_cache_set_error(t, kXR_ServerError, 0, "cache storage unavailable");
        return -1;
    }

    origin = xrootd_sd_xroot_create(conf, log);
    if (origin == NULL) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "root:// origin instance create failed");
        return -1;
    }

    src = origin->driver->open(origin, t->clean_path, XROOTD_SD_O_READ, 0, &e);
    if (src == NULL) {
        xrootd_sd_xroot_destroy(origin);
        xrootd_cache_set_error(t, (e == ENOENT) ? kXR_NotFound : kXR_IOError, e,
                               "root:// origin open failed");
        return -1;
    }
    t->file_size = (uint64_t) src->snap.size;

    {
        xrootd_cache_admit_cfg_t admit = {
            .deny_prefixes  = conf->cache_deny_prefixes,
            .allow_prefixes = conf->cache_allow_prefixes,
            .size_limit     = conf->cache_max_file_size,
            .include_regex  = conf->cache_include_regex_set
                              ? &conf->cache_include_regex : NULL,
        };
        if (xrootd_cache_admit(&admit, t->clean_path, (off_t) t->file_size, 0)
            == XROOTD_CACHE_DECLINE)
        {
            origin->driver->close(src);
            if (src->heap_shell) { free(src); }
            xrootd_sd_xroot_destroy(origin);
            t->result = NGX_DECLINED;
            return 1;
        }
    }

    staged = cache_inst->driver->staged_open(cache_inst, key, 0644, &e);
    if (staged == NULL) {
        origin->driver->close(src);
        if (src->heap_shell) { free(src); }
        xrootd_sd_xroot_destroy(origin);
        xrootd_cache_set_error(t, kXR_IOError, e, "cache staged open failed");
        return -1;
    }
    sink.fd = -1;
    sink.staged = staged;
    sink.mem = NULL;
    sink.mem_cap = 0;

    buf = malloc(XROOTD_CACHE_FETCH_CHUNK);
    if (buf == NULL) {
        cache_inst->driver->staged_abort(staged);
        origin->driver->close(src);
        if (src->heap_shell) { free(src); }
        xrootd_sd_xroot_destroy(origin);
        xrootd_cache_set_error(t, kXR_NoMemory, 0, "cache fill buffer alloc failed");
        return -1;
    }

    for (;;) {
        ssize_t n = src->driver->pread(src, buf, XROOTD_CACHE_FETCH_CHUNK, off);

        if (n < 0
            || (n > 0
                && xrootd_cache_sink_pwrite(&sink, buf, (size_t) n, off) != 0))
        {
            free(buf);
            cache_inst->driver->staged_abort(staged);
            origin->driver->close(src);
            if (src->heap_shell) { free(src); }
            xrootd_sd_xroot_destroy(origin);
            xrootd_cache_set_error(t, kXR_IOError, errno,
                                   "root:// origin read / cache write failed");
            return -1;
        }
        off += n;
        if ((size_t) n < XROOTD_CACHE_FETCH_CHUNK) {
            break;                           /* short read = EOF */
        }
    }
    free(buf);

    /* Origin content checksum (kXR_Qcksum) for commit-then-verify, before close. */
    if (conf->cache_verify != XROOTD_CACHE_VERIFY_OFF) {
        xrootd_sd_xroot_query_checksum(src, t->origin_cks_alg,
            sizeof(t->origin_cks_alg), t->origin_cks_hex,
            sizeof(t->origin_cks_hex));
    }

    origin->driver->close(src);
    if (src->heap_shell) { free(src); }
    xrootd_sd_xroot_destroy(origin);

    if (cache_inst->driver->staged_commit(staged, 0) != NGX_OK) {
        xrootd_cache_set_error(t, kXR_IOError, 0, "cache staged commit failed");
        return -1;
    }
    return xrootd_cache_commit_staged(t, cache_inst, key);
}

/* xrootd_cache_fetch_origin — the fill worker's anonymous-protocol fetch: connect →
 * bootstrap (handshake+login) → open source → read loop → fsync the .part → atomic
 * rename, each phase isolated with origin-close cleanup. Admission filtering runs
 * first: a file over cache_max_file_size that doesn't match the include regex is
 * rejected with NGX_DECLINED (1) — not an error — so the done callback redirects the
 * client to origin. Returns 1 (policy reject), -1 (error), 0 (success). */
int
xrootd_cache_fetch_origin(xrootd_cache_fill_t *t)
{
    /* HTTP(S)/WebDAV origin: fetch over libcurl (http_transport.c) instead of the
     * XRootD wire client, then run the shared commit+verify path. */
    if (t->conf->cache_origin_scheme == XROOTD_CACHE_SCHEME_HTTP
        || t->conf->cache_origin_scheme == XROOTD_CACHE_SCHEME_HTTPS)
    {
        if (xrootd_cache_http_download(t) != 0) {
            return -1;
        }
        return xrootd_cache_commit_part(t);
    }

    /* S3 origin: fill through the read-only remote-origin SD driver (sd_remote →
     * sd_s3 → server libcurl). Driver→driver copy into the staged-write sink. */
    if (t->conf->cache_origin_scheme == XROOTD_CACHE_SCHEME_S3) {
        return xrootd_cache_fetch_origin_s3(t);
    }

    /* Pelican federation: discover the Director, then fetch through it (libcurl
     * follows the 307 to the chosen cache/origin). Same commit+verify path. */
    if (t->conf->cache_origin_scheme == XROOTD_CACHE_SCHEME_PELICAN) {
        if (xrootd_cache_pelican_download(t) != 0) {
            return -1;
        }
        return xrootd_cache_commit_part(t);
    }

    /* Authenticated root:// origin (GSI X.509 proxy and/or bearer token): the
     * in-process driver does anonymous login only, which such an origin rejects.
     * Delegate to the native client, which authenticates from the environment
     * (X509_USER_PROXY for GSI, BEARER_TOKEN_FILE for token). */
    if (t->conf->cache_origin_proxy.len > 0
        || t->conf->cache_origin_token_file.len > 0)
    {
        return xrootd_cache_fetch_origin_exec(t);
    }

    /* Anonymous root:// origin: fill in-process through the sd_xroot driver. */
    return xrootd_cache_fetch_origin_xroot(t);
}
