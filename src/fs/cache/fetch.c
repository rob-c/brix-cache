#include "cache_internal.h"
#include "cache_admit.h"
#include "cache_storage.h"
#include "meta.h"
#include "verify.h"
#include "core/compat/checksum.h"   /* brix_checksum_hex_obj / _parse (verify) */
#include "fs/cache/origin/s3_transport.h"               /* server libcurl S3 transport */
#include "fs/backend/remote/sd_remote.h"    /* read-only S3 remote-origin driver */
#include "fs/backend/xroot/sd_xroot.h"      /* read-only root:// remote-origin driver */
#include "fs/backend/http/sd_http.h"        /* read-only HTTP(S) remote-origin driver */


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


/* The cache key (suffix under cache_root) for this fill's cache_path — what the
 * cache STORAGE driver keys its namespace on. NULL if cache_path is not under
 * cache_root (should never happen). */
static const char *
brix_cache_fill_key(const brix_cache_fill_t *t)
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
brix_cache_commit_staged(brix_cache_fill_t *t, brix_sd_instance_t *inst,
    const char *key)
{
    ngx_log_t        *log = (t->c != NULL) ? t->c->log : NULL;
    brix_sd_stat_t  sst;

    if (inst->driver->stat(inst, key, &sst) != NGX_OK) {
        brix_cache_set_syserror(t, kXR_IOError, "cache commit stat failed");
        return -1;
    }
    t->file_size = (uint64_t) sst.size;

    if (t->conf->cache_verify != BRIX_CACHE_VERIFY_OFF
        && t->origin_cks_alg[0] != '\0')
    {
        brix_checksum_alg_t alg;
        char                  alg_name[16];

        if (brix_checksum_parse(t->origin_cks_alg,
                                  ngx_strlen(t->origin_cks_alg),
                                  &alg, alg_name, sizeof(alg_name)) == NGX_OK)
        {
            int              e = 0;
            brix_sd_obj_t *o = inst->driver->open(inst, key, BRIX_SD_O_READ,
                                                    0, &e);
            if (o != NULL) {
                char hex[EVP_MAX_MD_SIZE * 2 + 1];
                int  ok = (brix_checksum_hex_obj(alg, o, key, log, hex,
                                                   sizeof(hex)) == NGX_OK)
                          && ngx_strcmp(hex, t->origin_cks_hex) == 0;
                (void) inst->driver->close(o);
                if (o->heap_shell) {
                    free(o);
                }
                if (!ok) {
                    (void) inst->driver->unlink(inst, key, 0);
                    brix_cache_set_error(t, kXR_ServerError, 0,
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
        brix_cache_meta_t meta;
        char                sidecar[PATH_MAX];
        const char         *state_root =
            t->conf->cache_state_root.len
                ? (const char *) t->conf->cache_state_root.data
                : (const char *) t->conf->cache_root.data;

        ngx_memzero(&pst, sizeof(pst));
        pst.st_size = (off_t) sst.size;
        pst.st_mtime = sst.mtime;
        if (brix_cache_meta_from_stat(&pst, NULL, &meta) == NGX_OK
            && brix_cache_sidecar_path((const char *) t->conf->cache_root.data,
                   state_root, t->cache_path, sidecar, sizeof(sidecar)) == 0)
        {
            (void) brix_cache_meta_write(log, sidecar, &meta);
        }
    }
    return 0;
}


/* Forward decl of the shared fill spine (defined below): open the SD source object,
 * pread sequential ranges into the cache's staged-write sink, then commit + verify.
 * Returns 0 (success), 1 (admission decline), -1 (error; t error fields set). */
static int brix_cache_fill_from_source(brix_cache_fill_t *t,
    brix_sd_instance_t *source);

/* §14 (phase-64): the legacy cache_origin s3/http/READ-origin builders are
 * DELETED — a cache fills from the export's registered storage backend (the C-1
 * spine), whose credential is the attached brix_credential. */

/* brix_cache_build_wt_origin — the WRITE-BACK origin (flush target): host from
 * brix_wt_origin, credentials from the C-3 in-process fields
 * (cache_origin_bearer/x509_proxy/ca_dir — populated from brix_wt_credential).
 * §14: the legacy cache_origin host/credential fallbacks are deleted with the
 * cache_origin config model. Caller owns the instance (brix_sd_xroot_destroy).
 * NULL if no wt_origin configured. */
brix_sd_instance_t *
brix_cache_build_wt_origin(const ngx_stream_brix_srv_conf_t *conf, ngx_log_t *log)
{
    char host_z[256];

    if (conf->wt.origin_host.len == 0 || conf->wt.origin_port == 0) {
        errno = EINVAL;
        return NULL;
    }
    ngx_cpystrn((u_char *) host_z, conf->wt.origin_host.data,
                ngx_min(conf->wt.origin_host.len + 1, sizeof(host_z)));
    brix_sd_xroot_origin_cfg_t cfg = {
        .host      = host_z,
        .port      = (int) conf->wt.origin_port,
        .tls       = 0, /* tls: legacy cache_origin_tls retired */
        .af_policy = (int) conf->cache_origin_family,
        .bearer    = (conf->cache_origin_bearer.len > 0)
            ? (const char *) conf->cache_origin_bearer.data : NULL,
        .x509_proxy = (conf->cache_origin_x509_proxy.len > 0)
            ? (const char *) conf->cache_origin_x509_proxy.data : NULL,
        .x509_key  = (conf->cache_origin_x509_key.len > 0)
            ? (const char *) conf->cache_origin_x509_key.data : NULL,
        .ca_dir    = (conf->cache_origin_ca_dir.len > 0)
            ? (const char *) conf->cache_origin_ca_dir.data : NULL,
        .sss_keytab = NULL, /* SSS is a tier-grammar credential, not legacy */
    };
    return brix_sd_xroot_create_origin(&cfg, log);
}


/* brix_cache_src_close — WHAT: release a SD source object opened for a fill.
 * WHY: the driver hands back either a pool-owned object or a heap "shell" that
 * the caller must free; every fill-error path must release both identically, so
 * this single-job helper keeps that contract in one place (no per-branch
 * duplication, no leak drift). HOW: driver->close then free() iff heap_shell. */
static void
brix_cache_src_close(brix_sd_instance_t *source, brix_sd_obj_t *src)
{
    source->driver->close(src);
    if (src->heap_shell) {
        free(src);
    }
}

/* brix_cache_fill_admitted — WHAT: apply the cache admission policy to an
 * opened source. WHY: admission (deny/allow prefixes, size cap, include regex)
 * is a decision stage distinct from I/O; isolating it keeps the spine linear.
 * HOW: build the admit cfg from conf and return 1 iff the file is DECLINEd. */
static int
brix_cache_fill_admitted(ngx_stream_brix_srv_conf_t *conf,
    const char *clean_path, off_t file_size)
{
    brix_cache_admit_cfg_t admit = {
        .deny_prefixes  = conf->cache_deny_prefixes,
        .allow_prefixes = conf->cache_allow_prefixes,
        .size_limit     = conf->cache_max_file_size,
        .include_regex  = conf->include_regex.set
                          ? &conf->include_regex.re : NULL,
    };
    return brix_cache_admit(&admit, clean_path, file_size, 0)
           == BRIX_CACHE_DECLINE;
}

/* brix_cache_fill_copy — WHAT: stream the source object into the staged sink.
 * WHY: the sequential pread→pwrite copy loop is the single hot data-moving stage
 * and its exact fill-range math (off advances by n; short read == EOF) must be
 * preserved verbatim; extracting it drops the loop's error branches out of the
 * spine's cyclomatic count. HOW: chunked pread from `src` at `off`, pwrite the
 * same bytes at the same `off` into `sink`; 0 on success, -1 on read/write error
 * (errno set by the failing call, as before). Caller owns buf lifetime. */
static int
brix_cache_fill_copy(brix_sd_obj_t *src, brix_cache_sink_t *sink, u_char *buf)
{
    off_t off = 0;

    for (;;) {
        ssize_t n = src->driver->pread(src, buf, BRIX_CACHE_FETCH_CHUNK, off);

        if (n < 0
            || (n > 0
                && brix_cache_sink_pwrite(sink, buf, (size_t) n, off) != 0))
        {
            return -1;
        }
        off += n;
        if ((size_t) n < BRIX_CACHE_FETCH_CHUNK) {
            break;                               /* short read = EOF */
        }
    }
    return 0;
}

/* brix_cache_fill_body — WHAT: the staged-write body of a fill: open the cache
 * staged sink, allocate the copy buffer, run the copy loop, capture the
 * on-fill checksum, then commit the staged bytes. WHY: pulling the staged
 * lifecycle out of the spine keeps each function under the CCN cap while holding
 * the sink/buf ownership contract (abort on any failure) in one place; the src
 * object is closed by this function on every exit (the caller must not). HOW:
 * staged_open (0600) → malloc → copy → xroot checksum query → src close →
 * staged_commit. Returns 0 (bytes committed) / -1 (error; t error fields set,
 * staged aborted). */
static int
brix_cache_fill_body(brix_cache_fill_t *t, brix_sd_instance_t *source,
    brix_sd_obj_t *src, brix_sd_instance_t *cache_inst, const char *key)
{
    ngx_stream_brix_srv_conf_t *conf = t->conf;
    brix_sd_staged_t           *staged;
    brix_cache_sink_t             sink;
    u_char                       *buf;
    int                           e = 0;

    /* SECURITY: cache-store files hold many users' bytes under one service-owned
     * tree and are created + served AS THE WORKER (open_resolved_file.c from_cache
     * branch, not the impersonation VFS). 0600 (not 0644) so a mapped low-priv uid
     * cannot read another user's cached bytes by direct filesystem access; the
     * per-user protocol gate (open_cache.c) already fronts the served path. */
    staged = cache_inst->driver->staged_open(cache_inst, key, 0600, &e);
    if (staged == NULL) {
        brix_cache_src_close(source, src);
        brix_cache_set_error(t, kXR_IOError, e, "cache staged open failed");
        return -1;
    }
    sink.fd = -1;
    sink.staged = staged;
    sink.mem = NULL;
    sink.mem_cap = 0;

    buf = malloc(BRIX_CACHE_FETCH_CHUNK);
    if (buf == NULL) {
        cache_inst->driver->staged_abort(staged);
        brix_cache_src_close(source, src);
        brix_cache_set_error(t, kXR_NoMemory, 0,
                               "cache fill buffer alloc failed");
        return -1;
    }

    if (brix_cache_fill_copy(src, &sink, buf) != 0) {
        free(buf);
        cache_inst->driver->staged_abort(staged);
        brix_cache_src_close(source, src);
        brix_cache_set_error(t, kXR_IOError, errno,
                               "cache source read / cache write failed");
        return -1;
    }
    free(buf);

    /* Checksum-on-fill is the xroot source's kXR_Qcksum; other sources (http) offer
     * no in-band digest here, so the verify policy decides on the local bytes. */
    if (conf->cache_verify != BRIX_CACHE_VERIFY_OFF
        && ngx_strcmp(brix_sd_backend_name(source), "xroot") == 0)
    {
        brix_sd_xroot_query_checksum(src, t->origin_cks_alg,
            sizeof(t->origin_cks_alg), t->origin_cks_hex,
            sizeof(t->origin_cks_hex));
    }

    brix_cache_src_close(source, src);

    if (cache_inst->driver->staged_commit(staged, 0) != NGX_OK) {
        brix_cache_set_error(t, kXR_IOError, 0, "cache staged commit failed");
        return -1;
    }
    return 0;
}

/* brix_cache_fill_from_source — THE single cache-fill spine (phase-63): fill from
 * any SD source instance generically — `source->driver->open` → `pread` loop →
 * staged sink → commit-then-verify. The caller owns `source`'s lifecycle (a
 * registry-owned backend, or a per-fill sd_xroot/sd_http/sd_remote built from the
 * cache_origin config). Checksum-on-fill reuses the xroot source's kXR_Qcksum.
 * Returns 1 (admission decline) / -1 (error) / 0 (success). */
static int
brix_cache_fill_from_source(brix_cache_fill_t *t,
    brix_sd_instance_t *source)
{
    ngx_stream_brix_srv_conf_t *conf = t->conf;
    brix_sd_instance_t         *cache_inst = brix_cache_storage(conf);
    const char                   *key = brix_cache_fill_key(t);
    brix_sd_obj_t              *src;
    int                           e = 0;

    if (source == NULL || cache_inst == NULL || key == NULL) {
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "cache source/storage unavailable");
        return -1;
    }

    src = source->driver->open(source, t->clean_path, BRIX_SD_O_READ, 0, &e);
    if (src == NULL) {
        brix_cache_set_error(t, (e == ENOENT) ? kXR_NotFound : kXR_IOError, e,
                               "cache source open failed");
        return -1;
    }
    t->file_size = (uint64_t) src->snap.size;

    if (brix_cache_fill_admitted(conf, t->clean_path, (off_t) t->file_size)) {
        brix_cache_src_close(source, src);
        t->result = NGX_DECLINED;
        return 1;
    }

    if (brix_cache_fill_body(t, source, src, cache_inst, key) != 0) {
        return -1;
    }
    return brix_cache_commit_staged(t, cache_inst, key);
}

/* brix_cache_fetch_origin — the fill worker's anonymous-protocol fetch: connect →
 * bootstrap (handshake+login) → open source → read loop → fsync the .part → atomic
 * rename, each phase isolated with origin-close cleanup. Admission filtering runs
 * first: a file over cache_max_file_size that doesn't match the include regex is
 * rejected with NGX_DECLINED (1) — not an error — so the done callback redirects the
 * client to origin. Returns 1 (policy reject), -1 (error), 0 (success). */
int
brix_cache_fetch_origin(brix_cache_fill_t *t)
{
    /* §14 (phase-64): ONE fill path — the export's registered storage backend
     * (resolved on the main thread by open_or_fill, C-1) through the one spine.
     * The legacy cache_origin per-scheme fetches (xroot/s3/http/pelican) are
     * deleted with their config model. */
    if (t->source_inst != NULL) {
        return brix_cache_fill_from_source(t, t->source_inst);
    }

    brix_cache_set_error(t, kXR_ServerError, 0,
                           "cache: no storage backend to fill from "
                           "(brix_cache on requires brix_storage_backend)");
    return -1;
}
