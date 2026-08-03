/*
 * sd_xroot_io.c — object open + data I/O + stat for the root:// origin driver.
 *
 * WHAT: The object-facing vtable slots — open/open_cred (connect the origin,
 *       kXR_open the file, build a memory-served object shell), close, pread
 *       (kXR_read range into a memory sink), preadv (per-segment pread),
 *       pwrite/ftruncate/fsync (the kXR_write/_truncate/_sync write data path),
 *       fstat (handle-snapshot), and stat/stat_cred (open-probe-then-teardown
 *       for the file size).
 *
 * WHY:  Split out of sd_xroot.c (phase-79 file-size split): the per-object I/O
 *       path is one concept, distinct from the shared origin-open machinery +
 *       driver vtable + lifecycle (sd_xroot.c), the staged atomic-publish path
 *       (sd_xroot_staged.c), and the namespace + metadata ops (sd_xroot_ns.c).
 *
 * HOW:  Every open (plain, cred, and the stat probes) funnels through
 *       sd_xroot_origin_open (sd_xroot.c) via sd_xroot_open_common, so the
 *       connect → bootstrap → kXR_open sequence and its error mapping live in
 *       one place; the object holds a live origin connection + fhandle and every
 *       read/write is memory-served (no kernel fd).
 */

#include "sd_xroot_internal.h"    /* obj_state + origin_open_req_t + machinery */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* sd_xroot_open_common — shared body for plain and cred-scoped opens.
 *
 * WHAT: Translate SD flags to want_write, call sd_xroot_origin_open with the
 *       supplied credential (NULL for the plain slot), build the SD object.
 * WHY:  Plain and cred paths differ only in the cred argument; a single body
 *       prevents divergence in error handling and object initialisation.
 *       A cred whose selected kind (bearer/S3) this driver cannot present —
 *       carrying neither an x509 proxy nor a bearer token — must not silently
 *       open on the service credential when the operator asked fallback_deny:
 *       that is exactly the leak the deny flag exists to prevent.
 * HOW:  want_write derived from sd_flags; a fallback_deny cred with no usable
 *       kind is refused (EACCES) before any origin session is opened;
 *       otherwise sd_xroot_origin_open owns the credential copy into the fill
 *       task; obj is heap-allocated (heap_shell=1). */
static brix_sd_obj_t *
sd_xroot_open_common(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    sd_xroot_inst_state *is = inst->state;
    sd_xroot_obj_state  *st;
    brix_sd_obj_t     *obj;
    off_t                size = 0;
    int                  want_write;

    /* fallback_deny: cred kind unusable by this driver — refuse, don't fall
     * back to service cred */
    if (cred != NULL && cred->fallback_deny
        && (cred->x509_proxy == NULL || cred->x509_proxy[0] == '\0')
        && (cred->bearer == NULL || cred->bearer[0] == '\0')
        && (cred->sss_keytab == NULL || cred->sss_keytab[0] == '\0'))
    {
        if (err_out) { *err_out = EACCES; }
        errno = EACCES;
        return NULL;
    }

    want_write = (sd_flags & (BRIX_SD_O_WRITE | BRIX_SD_O_CREATE
                              | BRIX_SD_O_TRUNC | BRIX_SD_O_APPEND)) != 0;

    sd_xroot_origin_open_req_t req = {
        .conf = is->conf, .cred = cred, .path = path,
        .want_write = want_write, .mode = mode,
        .size_out = &size, .err_out = err_out,
    };
    st = sd_xroot_origin_open(&req);
    if (st == NULL) {
        return NULL;
    }

    obj = calloc(1, sizeof(*obj));
    if (obj == NULL) {
        sd_xroot_obj_teardown(st);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    obj->driver      = inst->driver;
    obj->inst        = inst;
    obj->fd          = NGX_INVALID_FILE;     /* no kernel fd — memory-served */
    obj->state       = st;
    obj->heap_shell  = 1;
    obj->snap.size   = size;
    obj->snap.mode   = S_IFREG | (want_write ? 0644 : 0444);
    obj->snap.is_reg = 1;
    return obj;
}

/* sd_xroot_open — vtable open slot: service credential / anonymous.
 *
 * WHAT: Plain open for callers that do not carry a per-user credential.
 * WHY:  Preserves the existing public vtable signature; passes cred=NULL so
 *       the bootstrap uses the static service credential (or anonymous).
 * HOW:  Delegates to sd_xroot_open_common with cred=NULL. */
brix_sd_obj_t *
sd_xroot_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    return sd_xroot_open_common(inst, path, sd_flags, mode, NULL, err_out);
}

/* sd_xroot_open_cred — vtable open_cred slot: per-user x509 proxy credential.
 *
 * WHAT: Credential-scoped open that authenticates to the origin as the
 *       requesting user rather than the static service credential.
 * WHY:  Per-user backend auth requires the user's proxy to be presented at
 *       the origin bootstrap; the fill task copies it before connecting.
 * HOW:  Delegates to sd_xroot_open_common with the supplied cred; the common
 *       path copies x509_proxy + principal into the fill task before bootstrap. */
brix_sd_obj_t *
sd_xroot_open_cred(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    return sd_xroot_open_common(inst, path, sd_flags, mode, cred, err_out);
}

ngx_int_t
sd_xroot_close(brix_sd_obj_t *obj)
{
    if (obj != NULL && obj->state != NULL) {
        sd_xroot_obj_teardown(obj->state);
        obj->state = NULL;
    }
    return NGX_OK;
}

ssize_t
sd_xroot_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_xroot_obj_state       *st = obj->state;
    size_t                    done = 0;

    if (len == 0) {
        return 0;
    }

    /* brix_cache_origin_read_chunk reads each origin reply frame into a buffer
     * bounded by BRIX_CACHE_FETCH_CHUNK (1 MiB): a single kXR_read whose reply
     * frame exceeds that cap is rejected ("response body too large").  A read
     * window can be larger than 1 MiB (BRIX_READ_WINDOW is 2 MiB), so issue the
     * origin read in <=1 MiB sub-requests — mirroring the whole-file fetch, which
     * always loops in FETCH_CHUNK strides — and stop early on a short read (EOF).
     * Each sub-read writes into buf at the running offset (sink base 0 + got). */
    while (done < len) {
        brix_cache_sink_t        sink;
        brix_cache_read_range_t  rng;
        size_t                   want = len - done;

        if (want > BRIX_CACHE_FETCH_CHUNK) {
            want = BRIX_CACHE_FETCH_CHUNK;
        }

        ngx_memzero(&sink, sizeof(sink));
        sink.fd      = -1;
        sink.mem     = (u_char *) buf + done;
        sink.mem_cap = want;

        ngx_memzero(&rng, sizeof(rng));
        rng.read_off = (uint64_t) off + done;
        rng.want     = want;

        if (brix_cache_origin_read_chunk(st->t, &st->oc, st->fhandle, &sink,
                                           &rng) != 0)
        {
            errno = EIO;
            return -1;
        }
        done += rng.got;
        if (rng.got < want) {
            break;                          /* short read: EOF reached */
        }
    }
    return (ssize_t) done;
}

/* Write `len` bytes at `off` to the origin file via kXR_write. The origin file
 * is offset-addressed, so sequential and random writes both map directly. Only
 * valid on a write handle. Returns bytes written, or -1 with errno. */
ssize_t
sd_xroot_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    sd_xroot_obj_state *st = obj->state;

    if (st == NULL || !st->is_write) {
        errno = EBADF;
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    if (brix_cache_origin_write_chunk(st->t, &st->oc, st->fhandle,
            (uint64_t) off, (const u_char *) buf, len) != 0)
    {
        errno = EIO;
        return -1;
    }
    return (ssize_t) len;
}

/* kXR_truncate the origin file. Write handles only. */
ngx_int_t
sd_xroot_ftruncate(brix_sd_obj_t *obj, off_t len)
{
    sd_xroot_obj_state *st = obj->state;

    if (st == NULL || !st->is_write) {
        errno = EBADF;
        return NGX_ERROR;
    }
    if (brix_cache_origin_truncate(st->t, &st->oc, st->fhandle,
                                     (uint64_t) len) != 0)
    {
        errno = EIO;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* kXR_sync the origin file (flush to stable storage). A no-op on a read handle. */
ngx_int_t
sd_xroot_fsync(brix_sd_obj_t *obj)
{
    sd_xroot_obj_state *st = obj->state;

    if (st == NULL || !st->is_write) {
        return NGX_OK;
    }
    if (brix_cache_origin_sync(st->t, &st->oc, st->fhandle) != 0) {
        errno = EIO;
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
sd_xroot_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    *out = obj->snap;
    return NGX_OK;
}

/* Fill *out from a parsed origin kXR_stat reply: a directory becomes
 * S_IFDIR|0755 / is_dir, a file S_IFREG|0444 / is_reg. Shared by the service and
 * credential-scoped stat slots so both describe directories identically. */
static void
sd_xroot_stat_fill(brix_sd_stat_t *out, const brix_cache_stat_out_t *so)
{
    ngx_memzero(out, sizeof(*out));
    out->size  = so->size;
    out->mtime = so->mtime;
    if (so->is_dir) {
        out->mode   = S_IFDIR | 0755;
        out->is_dir = 1;
    } else {
        out->mode   = S_IFREG | 0444;
        out->is_reg = 1;
    }
}

ngx_int_t
sd_xroot_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
{
    sd_xroot_inst_state       *is = inst->state;
    brix_cache_origin_conn_t   oc;
    brix_cache_fill_t         *t;
    brix_cache_stat_out_t      so;
    int                        rc, e = 0;

    /* Real kXR_stat (by name), not stat-by-open: an open of a directory returns
     * kXR_isDirectory→EISDIR, so the old probe could never describe a dir and
     * broke isdir/mv/statx/locate. kXR_stat carries the kXR_isDir flag. */
    if (sd_xroot_session(is->conf, NULL, &oc, &t, &e) != 0) {
        errno = e;
        return NGX_ERROR;
    }
    rc = brix_cache_origin_stat(t, &oc, path, &so);
    e = errno;
    brix_cache_origin_close(&oc);
    free(t);
    if (rc != 0) {
        errno = e;
        return NGX_ERROR;
    }
    sd_xroot_stat_fill(out, &so);
    return NGX_OK;
}

/* sd_xroot_stat_cred — vtable stat_cred slot: probe path metadata under the
 * per-user x509 proxy credential (Phase 2 Task 1).
 *
 * WHAT: Stat the remote path using the requesting user's proxy rather than the
 *       static service credential, so a deny-mode probe authenticates (or fails)
 *       as the user — never opening a session on the service credential.
 * WHY:  brix_vfs_probe dispatches through this slot when the credential gate
 *       fires, closing the gap where a denied stat still reached the origin.
 * HOW:  Opens a per-user session (sd_xroot_session with cred), issues a real
 *       kXR_stat, then tears the session down — describing directories the same
 *       as sd_xroot_stat, but authenticated as the mapped user. */
ngx_int_t
sd_xroot_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred)
{
    sd_xroot_inst_state       *is = inst->state;
    brix_cache_origin_conn_t   oc;
    brix_cache_fill_t         *t;
    brix_cache_stat_out_t      so;
    int                        rc, e = 0;

    if (sd_xroot_session(is->conf, cred, &oc, &t, &e) != 0) {
        errno = e;
        return NGX_ERROR;
    }
    rc = brix_cache_origin_stat(t, &oc, path, &so);
    e = errno;
    brix_cache_origin_close(&oc);
    free(t);
    if (rc != 0) {
        errno = e;
        return NGX_ERROR;
    }
    sd_xroot_stat_fill(out, &so);
    return NGX_OK;
}

/* Vectored read: serve each iov segment from the origin (contiguous from `off`).
 * Reuses sd_xroot_pread per segment — short read on any segment ends the read. */
ssize_t
sd_xroot_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    ssize_t total = 0;
    int     i;

    for (i = 0; i < iovcnt; i++) {
        ssize_t n = sd_xroot_pread(obj, iov[i].iov_base, iov[i].iov_len,
                                   off + total);
        if (n < 0) {
            return (total > 0) ? total : -1;
        }
        total += n;
        if ((size_t) n < iov[i].iov_len) {
            break;                               /* short read = EOF */
        }
    }
    return total;
}
