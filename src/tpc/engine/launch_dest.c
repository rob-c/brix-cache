#include "tpc_internal.h"
#include "fs/vfs/vfs.h"
#include "fs/vfs/vfs_internal.h"

#include <string.h>
#include <errno.h>

/* File: launch_dest.c — opening the destination of a native root:// TPC pull.
 *
 * WHAT: Everything between "the guard ladder said yes" and "the file slot has a
 * write handle": the VFS flag derivation, the identity/credential/delegation-
 * bound VFS context, the two ways a destination can be opened (a random-write
 * handle when the selected storage leaf supports pwrite, a staged whole-object
 * writer otherwise), and the stat each produces.
 *
 * WHY: split out of launch_prepare.c on 2026-08-23, which had reached the
 * 600-line cap. The seam is a real one — launch_prepare.c now holds the guard
 * ladder and the request orchestration, this file holds the storage-facing open
 * — and it keeps both sides reviewable on their own terms.
 *
 * HOW: brix_tpc_open_destination builds the bound context and flags, tries the
 * random-write path, and falls back to the staged writer when the leaf declines.
 * Every refusal is answered through brix_tpc_refuse and reported as
 * TPC_ANSWERED, never as NGX_OK; see the note above that helper.
 */

static ngx_uint_t
tpc_destination_vfs_flags(uint16_t options)
{
    ngx_uint_t flags = BRIX_VFS_O_WRITE | BRIX_VFS_O_CREATE;

    if (options & kXR_new) {
        flags |= BRIX_VFS_O_EXCL;
    }
    if ((options & kXR_delete)
        || !(options & (kXR_new | kXR_delete)))
    {
        flags |= BRIX_VFS_O_TRUNC;
    }
    if (options & kXR_mkpath) {
        flags |= BRIX_VFS_O_MKDIRPATH;
    }
    return flags;
}

/* Build the same identity/credential/delegation-bound VFS context as a normal
 * root:// write open.  TPC used to bypass this context and open a raw fd, which
 * made cache and non-POSIX destinations silently report success without storing
 * the object in their configured namespace. */
static void
tpc_destination_vfs_ctx(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *dst_path,
    brix_vfs_ctx_t *vctx)
{
    const char *logical = brix_vfs_export_relative_root(
        dst_path, conf->common.root_canon);

    brix_vfs_ctx_init(vctx, c->pool, c->log, BRIX_PROTO_ROOT,
        conf->common.root_canon, NULL,
        brix_vfs_policy_from_write_enable(conf->common.allow_write),
        0 /* is_tls */, ctx->identity, logical);
    vctx->rootfd = conf->rootfd;
    brix_vfs_ctx_bind_backend_cred(vctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    brix_vfs_ctx_bind_backend_mint(vctx,
        &conf->common.storage_credential_mint_ca_cert,
        &conf->common.storage_credential_mint_ca_key,
        conf->common.storage_credential_mint_ttl);
    brix_root_vfs_bind_deleg(ctx, conf, vctx);
}

static void
tpc_stat_from_vfs(const brix_vfs_stat_t *vst, struct stat *st)
{
    ngx_memzero(st, sizeof(*st));
    st->st_mode  = (mode_t) vst->mode;
    st->st_size  = vst->size;
    st->st_mtime = vst->mtime;
    st->st_ctime = vst->ctime;
    st->st_ino   = vst->ino;
    st->st_dev   = vst->dev;
}

static ngx_int_t
tpc_try_random_destination(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_vfs_ctx_t *vctx, ngx_uint_t vflags, int idx, brix_file_t *file,
    struct stat *st, const char *dst_path)
{
    brix_sd_instance_t *leaf = brix_vfs_ns_leaf(vctx->sd);
    brix_vfs_file_t *vfh;
    /* Zeroed: a driver may return NGX_OK without setting every field. */
    brix_vfs_stat_t vst = { 0 };
    int fd;

    if (!(vctx->sd == NULL || leaf == NULL
          || (brix_sd_caps(leaf) & BRIX_SD_CAP_RANDOM_WRITE)
          || (leaf->driver != NULL && leaf->driver->pwrite != NULL)))
    {
        return NGX_DECLINED;
    }

    vfh = brix_vfs_open(vctx, vflags, &fd);
    if (vfh == NULL) {
        return NGX_DECLINED;
    }
    if (brix_vfs_file_stat(vfh, &vst) != NGX_OK) {
        int err = errno;

        (void) brix_vfs_close(vfh, c->log);
        brix_free_fhandle(ctx, idx);
        return brix_tpc_refuse(ctx, c, dst_path, kXR_IOError, strerror(err));
    }
    brix_vfs_file_sd_obj(vfh, &file->sd_obj);
    file->fd = brix_vfs_file_fd(vfh);
    tpc_stat_from_vfs(&vst, st);
    return NGX_OK;
}

static ngx_int_t
tpc_open_staged_destination(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, brix_vfs_ctx_t *vctx, ngx_uint_t vflags,
    int idx, brix_file_t *file, struct stat *st, mode_t create_mode,
    const char *dst_path)
{
    brix_sd_instance_t *leaf = brix_vfs_ns_leaf(vctx->sd);
    brix_vfs_writer_t *writer;
    int fd = 0;

    if (leaf == NULL || ((brix_sd_caps(leaf) & BRIX_SD_CAP_RANDOM_WRITE)
                         && leaf->driver != NULL
                         && leaf->driver->pwrite != NULL))
    {
        int err = errno != 0 ? errno : EIO;

        brix_free_fhandle(ctx, idx);
        return brix_tpc_refuse(ctx, c, dst_path, kXR_IOError, strerror(err));
    }

    writer = brix_vfs_writer_open(vctx, vflags & BRIX_VFS_O_TRUNC,
                                  conf->common.verify_write ? 1 : 0, &fd);
    if (writer == NULL) {
        int err = fd != 0 ? fd : (errno != 0 ? errno : EIO);

        brix_free_fhandle(ctx, idx);
        return brix_tpc_refuse(ctx, c, dst_path, kXR_IOError, strerror(err));
    }
    file->writer = writer;
    file->fd = brix_vfs_writer_fd(writer);
    ngx_memzero(st, sizeof(*st));
    st->st_mode = S_IFREG | create_mode;
    return NGX_OK;
}

/* WHAT: Open and classify a TPC destination through the VFS — a random-write
 *       handle when the selected leaf supports pwrite, else a staged whole-object
 *       writer — populating the caller's file slot and stat. NGX_OK on success;
 *       TPC_ANSWERED when the failure was already answered on the wire (the
 *       fhandle is freed by then); NGX_ERROR when it could not be.
 * WHY:  POSIX/cache backends and HTTP/S3-like backends carry different write
 *       handles, but both must pass through the same identity-bound VFS context;
 *       keeping the branch out of the orchestrator makes the security and
 *       resource transitions explicit. */
ngx_int_t
brix_tpc_open_destination(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *dst_path,
    uint16_t options, uint16_t mode_bits, int idx,
    brix_file_t *file, struct stat *st)
{
    brix_vfs_ctx_t     vctx;
    ngx_uint_t          vflags;
    mode_t              create_mode;
    ngx_int_t           rc;

    tpc_destination_vfs_ctx(ctx, c, conf, dst_path, &vctx);
    vflags = tpc_destination_vfs_flags(options);
    create_mode = (mode_bits & 0777) ? (mode_t) (mode_bits & 0777) : 0644;

    /* NGX_DECLINED alone means "this leaf cannot take a random-write handle";
     * every other answer, refusals included, is the final one. */
    rc = tpc_try_random_destination(ctx, c, &vctx, vflags, idx, file, st,
                                    dst_path);
    if (rc != NGX_DECLINED) {
        return rc;
    }
    return tpc_open_staged_destination(ctx, c, conf, &vctx, vflags, idx,
                                       file, st, create_mode, dst_path);
}
