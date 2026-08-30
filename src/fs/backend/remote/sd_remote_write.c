/*
 * sd_remote_write.c — write path (SP3) for the remote-origin (s3://) storage
 * driver: staged whole-object uploads (.staged_* → single PUT or multipart
 * upload) plus .unlink (DELETE). Split out of sd_remote.c verbatim; the driver
 * table lives there and references these via sd_remote_internal.h. Shared
 * path/param/cred helpers stay in sd_remote.c.
 *
 * A staged write delegates to sd_s3's single-PUT/multipart upload; the object
 * only becomes visible at commit, so a staged upload is atomic from the
 * reader's view.
 */

#include "sd_remote_internal.h"
#include "fs/backend/s3/sd_s3.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Per-staged-write state: the delegated S3 write handle, plus the composed
 * object path so a noreplace commit can HEAD the destination (P80.2). When the
 * upload was opened under a per-user credential (P80.3) the triple is copied
 * here — the caller's cred store does not outlive the open call, and the
 * noreplace HEAD must present the same identity as the upload itself. */
typedef struct {
    sd_s3_file *s3;
    char        objpath[768];
    int         has_cred;
    char        ak[128];
    char        sk[256];
    char        region[64];
    char        session[2048];   /* STS X-Amz-Security-Token (phase-70 §5.5); "" static */
} sd_remote_staged_state;

/* Multipart part size for a staged upload of unknown final size (S3's 5 MiB
 * minimum for non-final parts; 16 MiB balances request count vs. buffering). */
#define SD_REMOTE_PART_SIZE  (16 * 1024 * 1024)

/* Shared staged-open body: start the upload, optionally signing with a
 * per-user ak/sk/region override (NULL = the static service credential). The
 * override triple is copied into the staged state so the noreplace commit's
 * HEAD (P80.2) presents the same identity as the upload (P80.3). */
static brix_sd_staged_t *
sd_remote_staged_open_impl(brix_sd_instance_t *inst, const char *final_path,
    const char *ak, const char *sk, const char *region, const char *session,
    int *err_out)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_s3_open_params             p;
    char                          objpath[768];
    char                          errbuf[256];
    sd_s3_file                   *s3;
    sd_remote_staged_state       *ss;
    brix_sd_staged_t           *h;

    sd_remote_s3_key(cfg, final_path, objpath, sizeof(objpath));
    sd_remote_s3_params(cfg, objpath, &p);
    if (ak != NULL)      { p.ak            = ak; }
    if (sk != NULL)      { p.sk            = sk; }
    if (region != NULL)  { p.region        = region; }
    if (session != NULL) { p.session_token = session; }

    /* Unknown final size: sd_s3 buffers a single PUT and lazily upgrades to a
     * multipart upload only past SD_REMOTE_PART_SIZE (P80.2), so small objects
     * cost one request while any size still works. */
    s3 = sd_s3_open_write(&p, -1, SD_REMOTE_PART_SIZE, errbuf, sizeof(errbuf));
    if (s3 == NULL) {
        if (err_out) { *err_out = EIO; }
        return NULL;
    }
    ss = calloc(1, sizeof(*ss));
    h  = calloc(1, sizeof(*h));
    if (ss == NULL || h == NULL) {
        free(ss);
        free(h);
        sd_s3_abort(s3);
        sd_s3_close(s3);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    ss->s3 = s3;
    snprintf(ss->objpath, sizeof(ss->objpath), "%s", objpath);
    if (ak != NULL && sk != NULL) {
        ss->has_cred = 1;
        snprintf(ss->ak, sizeof(ss->ak), "%s", ak);
        snprintf(ss->sk, sizeof(ss->sk), "%s", sk);
        snprintf(ss->region, sizeof(ss->region), "%s",
                 (region != NULL) ? region : "");
        snprintf(ss->session, sizeof(ss->session), "%s",
                 (session != NULL) ? session : "");
    }
    h->inst  = inst;
    h->state = ss;
    return h;
}

brix_sd_staged_t *
sd_remote_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    (void) mode;
    return sd_remote_staged_open_impl(inst, final_path, NULL, NULL, NULL, NULL,
                                      err_out);
}

/* Cred-scoped staged open (P80.3): a write whose identity resolved to a
 * `<key>.s3` credential uploads to the origin as THAT user — every leg of the
 * upload (CreateMPU/UploadPart/PUT/Complete, and the noreplace HEAD via the
 * copied triple) signs with the per-user keys. Gate semantics identical to
 * sd_remote_open_cred. */
brix_sd_staged_t *
sd_remote_staged_open_cred(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    int gate = sd_remote_cred_gate(cred);

    (void) mode;

    if (gate > 0) {
        return sd_remote_staged_open_impl(inst, final_path,
            cred->s3_ak, cred->s3_sk, cred->s3_region, cred->s3_session,
            err_out);
    }
    if (gate < 0) {
        if (err_out) { *err_out = EACCES; }
        errno = EACCES;
        return NULL;
    }
    return sd_remote_staged_open_impl(inst, final_path, NULL, NULL, NULL, NULL,
                                      err_out);
}

ssize_t
sd_remote_staged_write(brix_sd_staged_t *h, const void *buf, size_t len,
    off_t off)
{
    sd_remote_staged_state *ss = h->state;
    char                    errbuf[256];

    if (sd_s3_pwrite(ss->s3, buf, len, off, errbuf, sizeof(errbuf)) != 0) {
        errno = EIO;
        return -1;
    }
    return (ssize_t) len;
}

ngx_int_t
sd_remote_staged_commit(brix_sd_staged_t *h, int noreplace)
{
    sd_remote_staged_state *ss = h->state;
    char                    errbuf[256];
    int                     rc;

    /* Exclusive publish (P80.2): S3 PUT/MPU-complete always replaces, so
     * noreplace is a HEAD-before-publish existence check. This is check-then-
     * act — RACY against a concurrent external writer landing the object
     * between the HEAD and the PUT — but honest O_EXCL/POSC semantics for
     * everything going through this gateway, versus silently overwriting. */
    if (noreplace) {
        const brix_sd_remote_cfg_t *cfg = h->inst->state;
        sd_s3_open_params             p;
        sd_s3_file                   *probe;
        int64_t                       size = 0;

        sd_remote_s3_params(cfg, ss->objpath, &p);
        if (ss->has_cred) {
            /* P80.3: the existence probe must present the same identity as
             * the upload it gates — never the shared service credential. A
             * delegated STS identity (phase-70 §5.5) also carries its session
             * token, or the HEAD signs with an incomplete temporary key. */
            p.ak = ss->ak;
            p.sk = ss->sk;
            if (ss->region[0] != '\0')  { p.region        = ss->region; }
            if (ss->session[0] != '\0') { p.session_token = ss->session; }
        }
        probe = sd_s3_open_read(&p, errbuf, sizeof(errbuf));
        if (probe != NULL) {
            int exists = sd_s3_size(probe, &size, errbuf, sizeof(errbuf)) == 0;

            sd_s3_close(probe);
            if (exists) {
                /* Failure contract: leave the staged handle intact — the
                 * caller's staged_abort discards the upload and frees it. */
                errno = EEXIST;
                return NGX_ERROR;
            }
        }
    }

    rc = sd_s3_commit(ss->s3, errbuf, sizeof(errbuf));
    if (rc != 0) {
        /* Failure contract (as in the noreplace/EEXIST branch above): leave the
         * staged handle intact — the caller's staged_abort discards the upload
         * (sd_s3_abort) and frees ss->s3/ss/h. Freeing here too double-frees /
         * uses-after-free that abort (stage_engine_move always aborts a failed
         * commit): the reused sd_s3_file surfaced as free(put_buf==0x1). */
        errno = EIO;
        return NGX_ERROR;
    }
    sd_s3_close(ss->s3);
    free(ss);
    free(h);
    return NGX_OK;
}

void
sd_remote_staged_abort(brix_sd_staged_t *h)
{
    sd_remote_staged_state *ss = h->state;

    sd_s3_abort(ss->s3);
    sd_s3_close(ss->s3);
    free(ss);
    free(h);
}

/* Shared unlink body: DELETE the object, optionally signing with a per-user
 * ak/sk/region override (NULL = the instance's static service credential). A
 * directory (is_dir, from rmdir) targets the zero-byte "path/" marker object
 * (#4) — the VFS rmtree has already emptied its children — rather than a
 * same-named file key. */
static ngx_int_t
sd_remote_unlink_impl(brix_sd_instance_t *inst, const char *path, int is_dir,
    const char *ak, const char *sk, const char *region, const char *session)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_s3_open_params             p;
    char                          objpath[768];
    char                          errbuf[256];

    if (is_dir) {
        sd_remote_s3_dirkey(cfg, path, objpath, sizeof(objpath));
    } else {
        sd_remote_s3_key(cfg, path, objpath, sizeof(objpath));
    }
    sd_remote_s3_params(cfg, objpath, &p);
    if (ak != NULL)      { p.ak            = ak; }
    if (sk != NULL)      { p.sk            = sk; }
    if (region != NULL)  { p.region        = region; }
    if (session != NULL) { p.session_token = session; }

    if (sd_s3_delete(&p, errbuf, sizeof(errbuf)) != 0) {
        if (errno == 0) { errno = EIO; }
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
sd_remote_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    return sd_remote_unlink_impl(inst, path, is_dir, NULL, NULL, NULL, NULL);
}

/* Cred-scoped unlink (P80.3): the DELETE runs as the requesting user. Gate
 * semantics identical to sd_remote_open_cred. */
ngx_int_t
sd_remote_unlink_cred(brix_sd_instance_t *inst, const char *path, int is_dir,
    const brix_sd_cred_t *cred)
{
    int gate = sd_remote_cred_gate(cred);

    if (gate > 0) {
        return sd_remote_unlink_impl(inst, path, is_dir,
            cred->s3_ak, cred->s3_sk, cred->s3_region, cred->s3_session);
    }
    if (gate < 0) {
        errno = EACCES;
        return NGX_ERROR;
    }
    return sd_remote_unlink_impl(inst, path, is_dir, NULL, NULL, NULL, NULL);
}

/* ---- server-side copy (S3 CopyObject, x-amz-copy-source) ----------------
 *
 * WHAT: Copy the export-relative `src` object to `dst` entirely within the S3
 *       origin — the bytes never traverse this host — signing with a per-user
 *       ak/sk/region/session override when given (NULL = the instance's static
 *       service credential).
 * WHY:  finding #4 — WebDAV COPY / xrdcp server-side copy over an s3:// backend
 *       previously fell through to ENOSYS. S3 exposes CopyObject natively, so
 *       this is a single signed PUT rather than a read-back/re-upload. It lives
 *       here, next to staged_open/unlink, because it is a MUTATION: it is the
 *       one slot on this driver that both reads and writes an object, and the
 *       identity it presents governs both halves at once.
 * HOW:  compose the "/bucket/src" copy-source and the "/bucket/dst" request
 *       target, call the shared sd_s3_copy primitive, then best-effort HEAD the
 *       destination for the copied byte count (mirrors the POSIX server_copy;
 *       0 when the follow-up stat cannot confirm the size). The follow-up HEAD
 *       presents the SAME identity as the copy — the noreplace-commit rule from
 *       the staged path: a probe signed by anyone else answers about visibility
 *       the copying identity may not have.
 */
static ngx_int_t
sd_remote_server_copy_impl(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, const brix_sd_cred_t *cred,
    const char *ak, const char *sk, const char *region, const char *session)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_s3_open_params           p;
    char                        srcpath[768];
    char                        dstpath[768];
    char                        errbuf[256];

    sd_remote_s3_key(cfg, src, srcpath, sizeof(srcpath));   /* /bucket/src   */
    sd_remote_s3_key(cfg, dst, dstpath, sizeof(dstpath));   /* /bucket/dst   */
    sd_remote_s3_params(cfg, dstpath, &p);                  /* target = dst  */
    sd_remote_params_cred(&p, ak, sk, region, session);

    errno = 0;
    if (sd_s3_copy(&p, srcpath, errbuf, sizeof(errbuf)) != 0) {
        if (errno == 0) { errno = EIO; }
        return NGX_ERROR;
    }
    if (bytes_out != NULL) {
        brix_sd_stat_t st;
        ngx_int_t      rc = (cred != NULL)
                            ? sd_remote_stat_cred(inst, dst, &st, cred)
                            : sd_remote_stat(inst, dst, &st);
        *bytes_out = (rc == NGX_OK) ? st.size : 0;
    }
    return NGX_OK;
}

ngx_int_t
sd_remote_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out)
{
    return sd_remote_server_copy_impl(inst, src, dst, bytes_out, NULL,
                                      NULL, NULL, NULL, NULL);
}

/* Cred-scoped server-side copy: the CopyObject runs as the requesting user.
 *
 * WHY: this slot is the widest one on the driver — a single signed request that
 *      READS one key and WRITES another. Without a *_cred sibling the forwarder
 *      fell through to the plain slot, so a per-user WebDAV COPY / third-party
 *      copy was authorised as the export: it could duplicate an object the
 *      caller's own keys could not read, into a prefix they could not write, and
 *      report success. Gate semantics identical to sd_remote_unlink_cred. */
ngx_int_t
sd_remote_server_copy_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, const brix_sd_cred_t *cred)
{
    int gate = sd_remote_cred_gate(cred);

    if (gate > 0) {
        return sd_remote_server_copy_impl(inst, src, dst, bytes_out, cred,
            cred->s3_ak, cred->s3_sk, cred->s3_region, cred->s3_session);
    }
    if (gate < 0) {
        errno = EACCES;
        return NGX_ERROR;
    }
    return sd_remote_server_copy_impl(inst, src, dst, bytes_out, NULL,
                                      NULL, NULL, NULL, NULL);
}
