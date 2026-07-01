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
#include "../fs/backend/http/sd_http.h"        /* read-only HTTP(S) remote-origin driver */


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

/* Read the first whitespace-delimited token (a bearer JWT) from `path` into out
 * (NUL-terminated, truncated to cap). O_NOFOLLOW — a config-domain token file, not
 * export storage. Best-effort: on any error out stays "". */
static void
xrootd_cache_read_token_file(const char *path, char *out, size_t cap)
{
    int     fd;
    ssize_t n;
    size_t  i;

    if (cap == 0) {
        return;
    }
    out[0] = '\0';
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);  /* vfs-seam-allow: config-domain bearer token file (not export storage) */
    if (fd < 0) {
        return;
    }
    n = read(fd, out, cap - 1);
    close(fd);
    if (n < 0) {
        out[0] = '\0';
        return;
    }
    out[n] = '\0';
    for (i = 0; i < (size_t) n; i++) {
        if (out[i] == '\r' || out[i] == '\n' || out[i] == ' ' || out[i] == '\t') {
            out[i] = '\0';
            break;
        }
    }
}

/* Forward decl of the shared fill spine (defined below): open the SD source object,
 * pread sequential ranges into the cache's staged-write sink, then commit + verify.
 * Returns 0 (success), 1 (admission decline), -1 (error; t error fields set). */
static int xrootd_cache_fill_from_source(xrootd_cache_fill_t *t,
    xrootd_sd_instance_t *source);

/* xrootd_cache_build_s3_origin — THE single mapping from the legacy cache_origin S3
 * config (s3://endpoint/bucket + access/secret/region) to a bare read-only sd_remote
 * (SigV4) origin instance. Both the whole-file fetch (below) and the config-time
 * source builder (cache_storage.c) build through here so their S3 origin config
 * cannot drift. Caller owns the instance (xrootd_sd_remote_destroy). NULL on failure
 * (errno set) or when no bucket is configured. */
xrootd_sd_instance_t *
xrootd_cache_build_s3_origin(const ngx_stream_xrootd_srv_conf_t *conf, ngx_log_t *log)
{
    xrootd_sd_remote_cfg_t cfg;

    if (conf->cache_origin_s3_bucket.len == 0) {
        return NULL;
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
    return xrootd_sd_remote_create(&cfg, log);
}

/* xrootd_cache_build_http_origin — map the legacy cache_origin HTTP(S) config to a
 * bare read-only sd_http instance (HEAD for size, Range-GET for pread, via the shared
 * libcurl transport). scheme https ⇒ TLS. The path prefix is empty — the fill key IS
 * the object path. Bearer comes from cache_origin_token_file (anonymous otherwise).
 * Caller owns the instance (xrootd_sd_http_destroy). NULL on failure (errno set). */
xrootd_sd_instance_t *
xrootd_cache_build_http_origin(const ngx_stream_xrootd_srv_conf_t *conf,
                               ngx_log_t *log)
{
    xrootd_sd_http_cfg_t cfg;
    char                 host_z[256];
    char                 bearer[4096];

    ngx_snprintf((u_char *) host_z, sizeof(host_z) - 1, "%V%Z",
                 &conf->cache_origin_host);
    bearer[0] = '\0';
    if (conf->cache_origin_token_file.len > 0) {
        (void) xrootd_cache_read_token_file(
            (const char *) conf->cache_origin_token_file.data,
            bearer, sizeof(bearer));
    }
    ngx_memzero(&cfg, sizeof(cfg));
    cfg.host         = host_z;                    /* copied by sd_http_create */
    cfg.port         = (int) conf->cache_origin_port;
    cfg.tls          = (conf->cache_origin_scheme == XROOTD_CACHE_SCHEME_HTTPS
                        || conf->cache_origin_tls == 1) ? 1 : 0;
    cfg.base_path    = "";
    cfg.transport    = &xrootd_s3_origin_curl_transport;
    cfg.timeout_ms   = 60000;
    cfg.bearer_token = (bearer[0] != '\0') ? bearer : NULL;
    return xrootd_sd_http_create(&cfg, log);
}

/* xrootd_cache_build_wt_origin — the WRITE-BACK origin (flush target): host from
 * wt_origin (else cache_origin), with the WRITE-BACK credential precedence — the C-3
 * in-process fields (cache_origin_bearer/x509_proxy/ca_dir) FIRST, falling back to the
 * legacy cache_origin_proxy/cadir. This is the write-side counterpart of
 * xrootd_cache_build_origin (which uses the READ credential); keep them distinct.
 * Caller owns the instance (xrootd_sd_xroot_destroy). NULL if no origin configured. */
xrootd_sd_instance_t *
xrootd_cache_build_wt_origin(const ngx_stream_xrootd_srv_conf_t *conf, ngx_log_t *log)
{
    const ngx_str_t *host = conf->wt_origin_host.len > 0 ? &conf->wt_origin_host
                                                         : &conf->cache_origin_host;
    uint16_t         port = conf->wt_origin_host.len > 0 ? conf->wt_origin_port
                                                         : conf->cache_origin_port;
    char             host_z[256];

    if (host->len == 0 || port == 0) {
        errno = EINVAL;
        return NULL;
    }
    ngx_cpystrn((u_char *) host_z, host->data,
                ngx_min(host->len + 1, sizeof(host_z)));
    return xrootd_sd_xroot_create_origin(host_z, (int) port,
        (conf->cache_origin_tls == 1) ? 1 : 0, (int) conf->cache_origin_family,
        (conf->cache_origin_bearer.len > 0)
            ? (const char *) conf->cache_origin_bearer.data : NULL,
        (conf->cache_origin_x509_proxy.len > 0)
            ? (const char *) conf->cache_origin_x509_proxy.data
        : (conf->cache_origin_proxy.len > 0)
            ? (const char *) conf->cache_origin_proxy.data : NULL,
        (conf->cache_origin_ca_dir.len > 0)
            ? (const char *) conf->cache_origin_ca_dir.data
        : (conf->cache_origin_cadir.len > 0)
            ? (const char *) conf->cache_origin_cadir.data : NULL,
        log);
}

/* xrootd_cache_build_origin — THE single mapping from the legacy cache_origin READ
 * credentials to a bare sd_xroot origin instance: cache_origin_proxy → GSI X.509,
 * cache_origin_cadir → origin-cert verify CA, cache_origin_token_file → ztn bearer,
 * cache_origin_family → connect address family. Both the whole-file fetch (below)
 * and the slice decorator (cache_storage.c) build through here so their read-origin
 * auth cannot drift (the C-3 cache_origin_bearer/x509_proxy/ca_dir fields are the
 * WRITE-BACK credential — wrong for a read fill). Caller owns the instance
 * (xrootd_sd_xroot_destroy). Returns NULL on failure (errno set by the driver). */
xrootd_sd_instance_t *
xrootd_cache_build_origin(const ngx_stream_xrootd_srv_conf_t *conf, ngx_log_t *log)
{
    char        host_z[256];
    char        bearer[4096];
    const char *proxy;
    const char *ca_dir;

    ngx_snprintf((u_char *) host_z, sizeof(host_z) - 1, "%V%Z",
                 &conf->cache_origin_host);
    proxy  = (conf->cache_origin_proxy.len > 0)
             ? (const char *) conf->cache_origin_proxy.data : NULL;
    ca_dir = (conf->cache_origin_cadir.len > 0)
             ? (const char *) conf->cache_origin_cadir.data : NULL;
    bearer[0] = '\0';
    if (conf->cache_origin_token_file.len > 0) {
        (void) xrootd_cache_read_token_file(
            (const char *) conf->cache_origin_token_file.data,
            bearer, sizeof(bearer));
    }
    return xrootd_sd_xroot_create_origin(host_z, (int) conf->cache_origin_port,
        (conf->cache_origin_tls == 1) ? 1 : 0, (int) conf->cache_origin_family,
        (bearer[0] != '\0') ? bearer : NULL, proxy, ca_dir, log);
}

/* xrootd_cache_fill_from_source — THE single cache-fill spine (phase-63): fill from
 * any SD source instance generically — `source->driver->open` → `pread` loop →
 * staged sink → commit-then-verify. The caller owns `source`'s lifecycle (a
 * registry-owned backend, or a per-fill sd_xroot/sd_http/sd_remote built from the
 * cache_origin config). Checksum-on-fill reuses the xroot source's kXR_Qcksum.
 * Returns 1 (admission decline) / -1 (error) / 0 (success). */
static int
xrootd_cache_fill_from_source(xrootd_cache_fill_t *t,
    xrootd_sd_instance_t *source)
{
    ngx_stream_xrootd_srv_conf_t *conf = t->conf;
    xrootd_sd_instance_t         *cache_inst = xrootd_cache_storage(conf);
    const char                   *key = xrootd_cache_fill_key(t);
    xrootd_sd_obj_t              *src;
    xrootd_sd_staged_t           *staged;
    xrootd_cache_sink_t           sink;
    u_char                       *buf;
    off_t                         off = 0;
    int                           e = 0;

    if (source == NULL || cache_inst == NULL || key == NULL) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "cache source/storage unavailable");
        return -1;
    }

    src = source->driver->open(source, t->clean_path, XROOTD_SD_O_READ, 0, &e);
    if (src == NULL) {
        xrootd_cache_set_error(t, (e == ENOENT) ? kXR_NotFound : kXR_IOError, e,
                               "cache source open failed");
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
            source->driver->close(src);
            if (src->heap_shell) { free(src); }
            t->result = NGX_DECLINED;
            return 1;
        }
    }

    staged = cache_inst->driver->staged_open(cache_inst, key, 0644, &e);
    if (staged == NULL) {
        source->driver->close(src);
        if (src->heap_shell) { free(src); }
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
        source->driver->close(src);
        if (src->heap_shell) { free(src); }
        xrootd_cache_set_error(t, kXR_NoMemory, 0,
                               "cache fill buffer alloc failed");
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
            source->driver->close(src);
            if (src->heap_shell) { free(src); }
            xrootd_cache_set_error(t, kXR_IOError, errno,
                                   "cache source read / cache write failed");
            return -1;
        }
        off += n;
        if ((size_t) n < XROOTD_CACHE_FETCH_CHUNK) {
            break;                               /* short read = EOF */
        }
    }
    free(buf);

    /* Checksum-on-fill is the xroot source's kXR_Qcksum; other sources (http) offer
     * no in-band digest here, so the verify policy decides on the local bytes. */
    if (conf->cache_verify != XROOTD_CACHE_VERIFY_OFF
        && ngx_strcmp(xrootd_sd_backend_name(source), "xroot") == 0)
    {
        xrootd_sd_xroot_query_checksum(src, t->origin_cks_alg,
            sizeof(t->origin_cks_alg), t->origin_cks_hex,
            sizeof(t->origin_cks_hex));
    }

    source->driver->close(src);
    if (src->heap_shell) { free(src); }

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
    /* Legacy cache_origin fold (phase-64 §6.5): translate the xroot/s3 origin config
     * to the config-time source instance so a legacy cache_origin fills through the
     * SAME spine as a registry PRIMARY backend (C-1) — not the per-scheme functions
     * below. http/https/pelican have no SD instance (they fill via libcurl), so their
     * source stays NULL and the branches below still handle them. */
    if (t->source_inst == NULL) {
        t->source_inst = xrootd_cache_source_inst(t->conf);
    }

    /* C-1 (phase-63): the export's registered PRIMARY storage backend, or (fold
     * above) the legacy cache_origin xroot/s3 source — fill through the one spine. */
    if (t->source_inst != NULL) {
        return xrootd_cache_fill_from_source(t, t->source_inst);
    }

    /* Pelican federation: discover the Director, then fetch through it (libcurl
     * follows the 307 to the chosen cache/origin). Same commit+verify path. */
    if (t->conf->cache_origin_scheme == XROOTD_CACHE_SCHEME_PELICAN) {
        if (xrootd_cache_pelican_download(t) != 0) {
            return -1;
        }
        return xrootd_cache_commit_part(t);
    }

    /* No usable source: xroot/s3 origins are handled above via source_inst; a
     * missing/unbuildable one (e.g. s3:// without a bucket) lands here. */
    xrootd_cache_set_error(t, kXR_ServerError, 0,
                           "cache: no usable origin source configured");
    return -1;
}
