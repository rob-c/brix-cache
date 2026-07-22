/*
 * sd_remote.c — remote-origin (s3://) storage driver. See the header.
 *
 * s3:// delegates entirely to the shared S3 driver (sd_s3): the SD object wraps
 * an sd_s3_file*; pread/preadv are signed Range GETs; stat/fstat report the HEAD
 * size. Writes are staged whole-object uploads (.staged_* → single PUT or MPU)
 * plus .unlink (DELETE) — there is deliberately no .pwrite, so the caps stay
 * CAP_RANGE_READ|CAP_MEMFILE and random in-place writes are rejected at the cap
 * layer. Namespace ops (dirlist/mkdir/rename) remain unimplemented.
 */

#include "sd_remote.h"
#include "sd_remote_internal.h"
#include "fs/backend/s3/sd_s3.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Per-open state: the delegated S3 read handle. */
typedef struct {
    sd_s3_file *s3;
} sd_remote_obj_state;

/* Compose the sd_s3 object path "/bucket/key" from the instance bucket and the
 * export-relative key (which already carries a leading '/'). Shared with the
 * meta/write siblings via sd_remote_internal.h. */
void
sd_remote_s3_key(const brix_sd_remote_cfg_t *cfg, const char *key,
    char *dst, size_t dstcap)
{
    snprintf(dst, dstcap, "/%s%s", cfg->bucket, (key != NULL) ? key : "/");
}

/* Fill sd_s3_open_params from the instance config + a composed object path.
 * Shared with the meta/write siblings via sd_remote_internal.h. */
void
sd_remote_s3_params(const brix_sd_remote_cfg_t *cfg, const char *objpath,
    sd_s3_open_params *p)
{
    memset(p, 0, sizeof(*p));
    p->host       = cfg->host;
    p->port       = cfg->port;
    p->tls        = cfg->tls;
    p->key        = objpath;
    p->ak         = cfg->access_key;
    p->sk         = cfg->secret_key;
    p->region     = cfg->region;
    p->transport  = cfg->transport;
    p->tctx       = cfg->tctx;
    p->timeout_ms = cfg->timeout_ms;
    p->put_checksum = cfg->put_checksum;   /* #12: origin-enforced body integrity */
}

/* ---- sd_remote_cred_gate — classify a per-user credential (P80.3) ---------
 *
 * WHAT: Decides how a cred-scoped slot must treat `cred`: 1 = a usable S3
 *       keypair (sign with the override), 0 = fall back to the instance's
 *       static service credential, -1 = refuse with EACCES.
 *
 * WHY:  Every cred slot on this driver (open/staged_open/stat/unlink) shares
 *       the same three-way decision, including the fallback_deny rule: a cred
 *       of a kind this S3-only backend cannot use (x509/bearer) under deny
 *       mode must be refused rather than silently signed with the export's
 *       shared service credential — exactly the fallback the operator forbade.
 *
 * HOW:  Usable means both s3_ak and s3_sk are present and non-empty; anything
 *       else is refused under fallback_deny and falls back otherwise.
 *
 * Shared with the meta/write siblings via sd_remote_internal.h. */
int
sd_remote_cred_gate(const brix_sd_cred_t *cred)
{
    if (cred != NULL
        && cred->s3_ak != NULL && cred->s3_ak[0] != '\0'
        && cred->s3_sk != NULL && cred->s3_sk[0] != '\0')
    {
        return 1;
    }
    if (cred != NULL && cred->fallback_deny) {
        return -1;
    }
    return 0;
}

/* ---- sd_remote_open_impl (shared by the plain and cred-scoped open slots) --
 *
 * WHAT: Opens `path` for read against the S3 origin, using `ak`/`sk`/`region`
 *       as the SigV4 credential instead of the instance's static
 *       cfg->access_key/secret_key/region when they are non-NULL.
 *
 * WHY:  Phase-3 T3 per-user S3 credentials: a request whose identity resolves
 *       to a `<key>.s3` file must sign against the ORIGIN with that user's
 *       keys, not the export's shared service credential.  Sharing one open
 *       body between sd_remote_open and sd_remote_open_cred keeps the object-
 *       construction logic (size HEAD, obj/state alloc, snap fill) written
 *       exactly once.
 *
 * HOW:  Builds the object path, then an sd_s3_open_params using the override
 *       ak/sk/region when given (falling back to the instance's static
 *       triple field-by-field when a pointer is NULL — region alone can be
 *       overridden without ak/sk, though callers always pass all three or
 *       none), and proceeds identically to the prior sd_remote_open body. */
static brix_sd_obj_t *
sd_remote_open_impl(brix_sd_instance_t *inst, const char *path, int sd_flags,
    const char *ak, const char *sk, const char *region, int *err_out)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_s3_open_params             p;
    char                          objpath[768];
    char                          errbuf[256];
    sd_s3_file                   *s3;
    sd_remote_obj_state          *st;
    brix_sd_obj_t              *obj;
    int64_t                       size = 0;

    /* Read-only origin: refuse any write/create/trunc intent up front. */
    if (sd_flags & (BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC
                    | BRIX_SD_O_APPEND)) {
        if (err_out) { *err_out = EROFS; }
        return NULL;
    }

    sd_remote_s3_key(cfg, path, objpath, sizeof(objpath));
    sd_remote_s3_params(cfg, objpath, &p);
    if (ak != NULL)     { p.ak     = ak; }
    if (sk != NULL)     { p.sk     = sk; }
    if (region != NULL) { p.region = region; }

    s3 = sd_s3_open_read(&p, errbuf, sizeof(errbuf));
    if (s3 == NULL) {
        if (err_out) { *err_out = ENOMEM; }   /* open_read only fails on bad args/OOM */
        return NULL;
    }
    if (sd_s3_size(s3, &size, errbuf, sizeof(errbuf)) != 0) {
        int e = errno;                         /* HEAD set errno (ENOENT on 404) */

        sd_s3_close(s3);
        if (err_out) { *err_out = e ? e : EIO; }
        return NULL;
    }

    st  = calloc(1, sizeof(*st));
    obj = calloc(1, sizeof(*obj));
    if (st == NULL || obj == NULL) {
        free(st);
        free(obj);
        sd_s3_close(s3);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    st->s3 = s3;

    obj->driver        = inst->driver;
    obj->inst          = inst;
    obj->fd            = NGX_INVALID_FILE;     /* no kernel fd — memory-served */
    obj->state         = st;
    obj->heap_shell    = 1;                    /* malloc'd shell; caller may free */
    obj->snap.size     = (off_t) size;
    obj->snap.mode     = S_IFREG | 0444;
    obj->snap.is_reg   = 1;

    return obj;
}

static brix_sd_obj_t *
sd_remote_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    (void) mode;
    return sd_remote_open_impl(inst, path, sd_flags, NULL, NULL, NULL,
                               err_out);
}

/* ---- sd_remote_open_cred — per-user SigV4 credential override (phase-3 T3) -
 *
 * WHAT: Like sd_remote_open, but when cred->s3_ak (and s3_sk) are set, signs
 *       the request with the caller's per-user access key / secret key /
 *       region instead of the instance's static service credential.
 *
 * WHY:  brix_sd_open_maybe_cred (sd.h) routes through this slot whenever the
 *       VFS credential gate (vfs_cred.c) resolved a `<key>.s3` file for the
 *       requesting identity — the origin must see THAT user's SigV4
 *       signature, not the export's shared key.
 *
 * HOW:  Three-way sd_remote_cred_gate: a usable S3 keypair signs with the
 *       override; an unusable kind (x509/bearer) falls back to the static
 *       instance credential, unless the operator set fallback_deny — then it
 *       is refused with EACCES before any origin contact. */
static brix_sd_obj_t *
sd_remote_open_cred(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    int gate = sd_remote_cred_gate(cred);

    (void) mode;

    if (gate > 0) {
        return sd_remote_open_impl(inst, path, sd_flags,
            cred->s3_ak, cred->s3_sk, cred->s3_region, err_out);
    }
    if (gate < 0) {
        if (err_out) { *err_out = EACCES; }
        errno = EACCES;
        return NULL;
    }
    return sd_remote_open_impl(inst, path, sd_flags, NULL, NULL, NULL,
                               err_out);
}

static ngx_int_t
sd_remote_close(brix_sd_obj_t *obj)
{
    sd_remote_obj_state *st;

    if (obj == NULL || obj->state == NULL) {
        return NGX_OK;
    }
    st = obj->state;
    sd_s3_close(st->s3);
    free(st);
    obj->state = NULL;
    return NGX_OK;
}

static ssize_t
sd_remote_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_remote_obj_state *st = obj->state;
    char                 errbuf[256];
    ssize_t              n;

    n = sd_s3_pread(st->s3, buf, len, off, errbuf, sizeof(errbuf));
    if (n < 0) {
        errno = EIO;
        return -1;
    }
    return n;
}

/*
 * sd_remote_preadv — coalesced vectored read over the ranged-GET origin.
 *
 * WHAT: Reads the contiguous file span [off, off + sum(iov_len)) with as few
 *       ranged GETs as the transport allows and scatters the bytes into the
 *       iovecs. Returns total bytes read (short = EOF), or -1 with errno set.
 *
 * WHY: The vectored read paths (pgread batches, kXR_readv runs) describe one
 *      contiguous span split across many small page-sized iovecs. The generic
 *      per-iovec pread fallback would issue one signed HTTP round trip per
 *      4 KiB page — thousands of requests for a large read, which times the
 *      client out. One GET per SD_S3_PREAD_MAX-capped chunk restores sane
 *      request counts.
 *
 * HOW: Single-iovec calls loop sd_remote_pread straight into the caller's
 *      buffer (no copy). Scattered calls fill a malloc'd bounce buffer with
 *      the same loop, then memcpy per iovec — the HTTP body is copied anyway,
 *      so the bounce adds one pass over bytes that already left the socket.
 *      A 0-byte pread means EOF; a short chunk keeps looping (sd_s3_pread
 *      caps each request, a cap hit is not EOF).
 */
static ssize_t
sd_remote_pread_full(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    size_t  done = 0;

    while (done < len) {
        ssize_t n = sd_remote_pread(obj, (char *) buf + done, len - done,
                                    off + (off_t) done);
        if (n < 0) {
            return (done > 0) ? (ssize_t) done : -1;
        }
        if (n == 0) {
            break;              /* EOF */
        }
        done += (size_t) n;
    }
    return (ssize_t) done;
}

static ssize_t
sd_remote_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    size_t   total = 0;
    size_t   scattered;
    ssize_t  n;
    char    *bounce;
    int      i;

    for (i = 0; i < iovcnt; i++) {
        total += iov[i].iov_len;
    }
    if (total == 0) {
        return 0;
    }

    if (iovcnt == 1) {
        return sd_remote_pread_full(obj, iov[0].iov_base, iov[0].iov_len, off);
    }

    bounce = malloc(total);
    if (bounce == NULL) {
        errno = ENOMEM;
        return -1;
    }

    n = sd_remote_pread_full(obj, bounce, total, off);
    if (n < 0) {
        free(bounce);
        return -1;
    }

    scattered = 0;
    for (i = 0; i < iovcnt && scattered < (size_t) n; i++) {
        size_t take = iov[i].iov_len;
        if (take > (size_t) n - scattered) {
            take = (size_t) n - scattered;
        }
        memcpy(iov[i].iov_base, bounce + scattered, take);
        scattered += take;
    }

    free(bounce);
    return n;
}

static ngx_int_t
sd_remote_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    *out = obj->snap;
    return NGX_OK;
}

/* Read + write: the S3 store serves as a read origin (Range GET) and a writable
 * cache_store / stage_store / backend (staged single-PUT / multipart upload, plus
 * DELETE for eviction and post-flush stage cleanup). */
static const brix_sd_driver_t brix_sd_remote_driver = {
    .name  = "remote",
    /* phase-71: no .pwrite slot — writes are staged whole-object uploads via
     * .staged_*, so CAP_RANDOM_WRITE is deliberately NOT advertised. */
    .caps  = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_MEMFILE,
    .cred_accept = BRIX_SD_CRED_BEARER | BRIX_SD_CRED_PROXY_PEM,
    .open  = sd_remote_open,
    .close = sd_remote_close,
    .pread = sd_remote_pread,
    .preadv = sd_remote_preadv,   /* coalesced ranged GETs (P80.1 read path) */
    .fstat = sd_remote_fstat,
    .stat  = sd_remote_stat,
    .unlink        = sd_remote_unlink,
    .getxattr      = sd_remote_getxattr,   /* x-amz-meta-* as user.* xattrs */
    .listxattr     = sd_remote_listxattr,
    .staged_open   = sd_remote_staged_open,
    .staged_write  = sd_remote_staged_write,
    .staged_commit = sd_remote_staged_commit,
    .staged_abort  = sd_remote_staged_abort,
    .open_cred     = sd_remote_open_cred,   /* phase-3 T3: per-user SigV4 */
    /* P80.3: per-user SigV4 for writes + metadata. stat_cred also gates
     * brix_vfs_ns_cred() — registering it turns on per-user namespace
     * credential resolution for this driver. */
    .staged_open_cred = sd_remote_staged_open_cred,
    .stat_cred        = sd_remote_stat_cred,
    .unlink_cred      = sd_remote_unlink_cred,
};

brix_sd_instance_t *
brix_sd_remote_create(const brix_sd_remote_cfg_t *cfg, ngx_log_t *log)
{
    brix_sd_instance_t   *inst;
    brix_sd_remote_cfg_t *copy;

    if (cfg == NULL || cfg->scheme != BRIX_SD_REMOTE_S3
        || cfg->transport == NULL) {
        errno = EINVAL;
        return NULL;
    }

    inst = calloc(1, sizeof(*inst));
    copy = malloc(sizeof(*copy));
    if (inst == NULL || copy == NULL) {
        free(inst);
        free(copy);
        errno = ENOMEM;
        return NULL;
    }
    *copy = *cfg;

    inst->driver = &brix_sd_remote_driver;
    inst->log    = log;
    inst->pool   = NULL;          /* malloc-owned: safe off the event loop */
    inst->state  = copy;
    return inst;
}

void
brix_sd_remote_destroy(brix_sd_instance_t *inst)
{
    if (inst == NULL) {
        return;
    }
    free(inst->state);
    free(inst);
}
