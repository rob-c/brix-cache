/*
 * copy_block.c - extracted concern
 * Phase-38 split of copy.c; behavior-identical.
 */
#include "copy_internal.h"


/* block:// endpoint copy helpers */
/*
 * copy_remote_to_block — root:// → block:// single-file transfer.
 *
 * WHAT: connects to the remote XRootD source, opens the block:// destination
 *       directly through the VFS block backend (in-place write, no temp+rename),
 *       and streams all bytes via the existing download pump machinery.
 * WHY:  copy_download routes its destination through xrdc_url du->path (a stripped
 *       bare POSIX path), which selects the POSIX backend.  A block:// URL must be
 *       passed as-is so vfs_url_to_scheme routes it to the block backend instead.
 * HOW:  parse src → resilient_setup → xrdc_vfs_open(dst_url, WRITE|FORCE) →
 *       download_stream_body → commit (fsync) on success, abort (no-op) on failure.
 *       FORCE is always set: block/device targets pre-exist by design.
 */
int
copy_remote_to_block(const char *src_url, const char *dst_url,
                     const xrdc_copy_opts *o, const xrdc_opts *co,
                     xrdc_status *st)
{
    xrdc_url            su;
    xrdc_conn           c;
    xrdc_statinfo       si;
    xrdc_streamset      ss;
    xrdc_vfs_file      *vf = NULL;
    xrdc_vfs_open_opts  vopts;
    pump_local_t        lc;
    int                 stall;
    int                 rc;

    if (xrdc_url_parse(src_url, &su, st) != 0) {
        return -1;
    }

    stall = copy_stall_ms(o, 60000);
    ss.n = 0;
    if (resilient_setup(&c, &su, co, &si, stall, st) != 0) {
        return -1;
    }
    if (si.flags & kXR_isDir) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "block copy: remote source is a directory (use -r)");
        xrdc_close(&c);
        return -1;
    }

    vopts.io_uring      = (o != NULL) ? o->io_uring : XRDC_IO_URING_AUTO;
    vopts.expected_size = si.size;
    vopts.cred          = NULL;

    if (xrdc_vfs_open(dst_url, XRDC_VFS_WRITE | XRDC_VFS_FORCE,
                      &vopts, &vf, st) != 0) {
        xrdc_close(&c);
        return -1;
    }

    lc.vf = vf;
    rc = download_stream_body(&c, &su, &si, pump_sink_local_vfs, &lc,
                              o, &ss, st);

    if (rc == 0) {
        rc = xrdc_vfs_commit(vf, st);
    } else {
        xrdc_vfs_abort(vf);
    }
    xrdc_vfs_close(vf);
    xrdc_streams_close(&ss);
    xrdc_close(&c);
    return rc;
}


/*
 * copy_block_to_remote — block:// → root:// single-file transfer.
 *
 * WHAT: opens the block:// source through the VFS block backend (READ) and
 *       uploads all bytes into the remote (root://) destination.
 * WHY:  copy_upload reads su->path as a bare path (POSIX backend).  A block://
 *       source URL must be passed to xrdc_vfs_open so vfs_url_to_scheme routes
 *       it to the block backend; the stripped path alone selects the POSIX backend.
 * HOW:  xrdc_vfs_open(src_url, READ) → fstat for size →
 *       parse dst URL → upload_stream_body(pump_src_local_vfs) → close.
 *       Checksum verification on block sources is best-effort: cksum_verify
 *       opens the file by POSIX path; for a pure block:// URL it returns
 *       XRDC_CK_UNVERIFIED (a non-fatal warn), keeping the good upload intact.
 */
int
copy_block_to_remote(const char *src_url, const char *dst_url,
                     const xrdc_copy_opts *o, const xrdc_opts *co,
                     xrdc_status *st)
{
    xrdc_url            du;
    xrdc_url            fake_su;
    xrdc_vfs_file      *vf = NULL;
    xrdc_vfs_open_opts  vopts;
    xrdc_vfs_stat       vst;
    xrdc_status         tmp_st;
    pump_local_t        lc;
    int64_t             total = -1;
    int                 rc;

    if (xrdc_url_parse(dst_url, &du, st) != 0) {
        return -1;
    }

    vopts.io_uring      = (o != NULL) ? o->io_uring : XRDC_IO_URING_AUTO;
    vopts.expected_size = -1;
    vopts.cred          = NULL;

    if (xrdc_vfs_open(src_url, XRDC_VFS_READ, &vopts, &vf, st) != 0) {
        return -1;
    }

    xrdc_status_clear(&tmp_st);
    if (xrdc_vfs_fstat(vf, &vst, &tmp_st) == 0) {
        total = vst.size;
    }

    /* Synthesise a source descriptor for upload_stream_body diagnostics.
     * scheme=LOCAL tells it to use fake_su.path for optional cksum_verify;
     * for a block:// URL that open() cannot resolve, cksum_verify returns
     * XRDC_CK_UNVERIFIED (non-fatal warn) rather than a hard failure. */
    memset(&fake_su, 0, sizeof(fake_su));
    fake_su.scheme = XRDC_SCHEME_LOCAL;
    snprintf(fake_su.path, sizeof(fake_su.path), "%s", src_url);

    lc.vf = vf;
    rc = upload_stream_body(&fake_su, &du, o, co, pump_src_local_vfs, &lc,
                            total, st);
    xrdc_vfs_close(vf);
    return rc;
}


/*
 * copy_vfs_to_vfs — VFS-source → VFS-destination transfer (local↔block).
 *
 * WHAT: opens both src and dst through xrdc_vfs_open (which routes block://
 *       and /dev/ to the block backend; bare paths to the POSIX backend) and
 *       pumps bytes via transfer_pump.  Covers local→block://, block://→local,
 *       and block://→block:// directions.
 * WHY:  when neither side is a root:// remote the generic copy machinery
 *       (copy_download / copy_upload) is unnecessary; two VFS opens + a pump
 *       are enough.
 * HOW:  open src READ → fstat → open dst WRITE|FORCE → pump → commit dst →
 *       close both.  FORCE is always set on the destination: block targets
 *       pre-exist by design; POSIX destinations use atomic temp+rename whose
 *       overwrite semantics are controlled by the FORCE flag.
 */
int
copy_vfs_to_vfs(const char *src_url, const char *dst_url,
                const xrdc_copy_opts *o, xrdc_status *st)
{
    xrdc_vfs_file      *src_vf = NULL;
    xrdc_vfs_file      *dst_vf = NULL;
    xrdc_vfs_open_opts  vopts;
    xrdc_vfs_stat       vst;
    xrdc_status         tmp_st;
    pump_local_t        src_lc, dst_lc;
    int64_t             total = -1;
    int                 rc;

    vopts.io_uring      = (o != NULL) ? o->io_uring : XRDC_IO_URING_AUTO;
    vopts.expected_size = -1;
    vopts.cred          = NULL;

    if (xrdc_vfs_open(src_url, XRDC_VFS_READ, &vopts, &src_vf, st) != 0) {
        return -1;
    }

    xrdc_status_clear(&tmp_st);
    if (xrdc_vfs_fstat(src_vf, &vst, &tmp_st) == 0) {
        total = vst.size;
    }

    vopts.expected_size = total;
    if (xrdc_vfs_open(dst_url, XRDC_VFS_WRITE | XRDC_VFS_FORCE,
                      &vopts, &dst_vf, st) != 0) {
        xrdc_vfs_close(src_vf);
        return -1;
    }

    src_lc.vf = src_vf;
    dst_lc.vf = dst_vf;
    rc = transfer_pump(pump_src_local_vfs, &src_lc,
                       pump_sink_local_vfs, &dst_lc,
                       total, o, total, st);

    if (rc == 0) {
        rc = xrdc_vfs_commit(dst_vf, st);
    } else {
        xrdc_vfs_abort(dst_vf);
    }
    xrdc_vfs_close(dst_vf);
    xrdc_vfs_close(src_vf);
    return rc;
}


/*
 * copy_block — dispatch for copies involving at least one block:// endpoint.
 *
 * WHAT: classifies the (src, dst) pair and routes to the right helper:
 *   root://→block://  → copy_remote_to_block
 *   block://→root://  → copy_block_to_remote
 *   local→block://    → copy_vfs_to_vfs  (POSIX src + block dst)
 *   block://→local    → copy_vfs_to_vfs  (block src + POSIX dst)
 *   block://→block:// → copy_vfs_to_vfs  (block src + block dst)
 * WHY:  xrdc_copy() intercepts block:// before xrdc_url_parse (which does not
 *       know the block:// scheme) and delegates here.
 * HOW:  classify src/dst by xrdc_is_block_url and xrdc_is_web_url; for the
 *       root:// directions use xrdc_url_parse to distinguish remote/local;
 *       recursion and zip are explicitly rejected (not supported for block).
 */
int
copy_block(const char *src, const char *dst, const xrdc_copy_opts *o,
           const xrdc_opts *co, xrdc_status *st)
{
    int src_block  = xrdc_is_block_url(src);
    int dst_block  = xrdc_is_block_url(dst);
    int src_remote = 0;
    int dst_remote = 0;

    if (o != NULL && o->recursive) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "recursive copy not supported for block:// endpoints");
        return -1;
    }

    /* Classify non-block sides: parse with xrdc_url_parse to detect root://. */
    if (!src_block) {
        xrdc_url su;
        xrdc_status tmp;
        xrdc_status_clear(&tmp);
        if (xrdc_url_parse(src, &su, &tmp) == 0) {
            src_remote = (su.scheme == XRDC_SCHEME_ROOT
                          || su.scheme == XRDC_SCHEME_ROOTS);
        }
    }
    if (!dst_block) {
        xrdc_url du;
        xrdc_status tmp;
        xrdc_status_clear(&tmp);
        if (xrdc_url_parse(dst, &du, &tmp) == 0) {
            dst_remote = (du.scheme == XRDC_SCHEME_ROOT
                          || du.scheme == XRDC_SCHEME_ROOTS);
        }
    }

    if (src_remote && dst_block) {
        return copy_remote_to_block(src, dst, o, co, st);
    }
    if (src_block && dst_remote) {
        return copy_block_to_remote(src, dst, o, co, st);
    }
    if (!src_remote && !dst_remote) {
        /* both sides are local/block: pure VFS-to-VFS */
        return copy_vfs_to_vfs(src, dst, o, st);
    }

    xrdc_status_set(st, XRDC_EUSAGE, 0,
                    "unsupported block:// copy direction "
                    "(src=%s dst=%s)", src, dst);
    return -1;
}
