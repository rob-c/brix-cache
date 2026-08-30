/*
 * sd_remote_meta.c — HEAD-based metadata slots for the remote-origin (s3://)
 * storage driver: stat/stat_cred plus the x-amz-meta-* xattr surface. Split out
 * of sd_remote.c verbatim; the driver table lives there and references these via
 * sd_remote_internal.h. Shared path/param/cred helpers stay in sd_remote.c.
 */

#include "sd_remote_internal.h"
#include "fs/backend/s3/sd_s3.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* Part size for the zero-byte folder-marker PUT (#4). Any value > 0 selects the
 * single-PUT path in sd_s3_open_write since the marker's expected_size is 0. */
#define SD_REMOTE_MARKER_PART  (1 * 1024 * 1024)

/* Apply a per-user ak/sk/region/session override onto a filled sd_s3_open_params
 * (NULL fields keep the instance's static service credential). The same field-
 * by-field override every cred-scoped slot performs inline; shared here across
 * the namespace-mutation slots added for #4 and the xattr/setattr slots in
 * sd_remote_xattr.c (declared in sd_remote_internal.h). */
void
sd_remote_params_cred(sd_s3_open_params *p, const char *ak, const char *sk,
    const char *region, const char *session)
{
    if (ak != NULL)      { p->ak            = ak; }
    if (sk != NULL)      { p->sk            = sk; }
    if (region != NULL)  { p->region        = region; }
    if (session != NULL) { p->session_token = session; }
}

/* HEAD `objpath` under the (already cred-applied) params: 1 = object exists,
 * 0 = absent (or HEAD failed). Best-effort existence probe for the stat/mkdir/
 * rename gates below. */
static int
sd_remote_head_exists(const sd_s3_open_params *p)
{
    char        errbuf[256];
    sd_s3_file *s3;
    int64_t     size = 0;
    int         exists;

    s3 = sd_s3_open_read(p, errbuf, sizeof(errbuf));
    if (s3 == NULL) {
        return 0;
    }
    exists = sd_s3_size(s3, &size, errbuf, sizeof(errbuf)) == 0;
    sd_s3_close(s3);
    return exists;
}

/* ---- xattr surface: x-amz-meta-* as the `user.` namespace --------------
 *
 * getxattr("user.<name>") reads x-amz-meta-<name> via a signed HEAD;
 * listxattr enumerates every x-amz-meta-* header (needs a transport with the
 * optional resp_headers_raw slot — without it sd_s3_list_meta reports
 * ENOTSUP). Both open the object read-only just for the HEAD, mirroring the
 * stat body below.
 *
 * The HEAD signs with the per-user ak/sk/region/session when the caller passes
 * them (NULL = the instance's static service credential), exactly as the stat
 * and mutation bodies do. Reading metadata is a read of the user's data, and
 * while these two slots had no *_cred sibling brix_sd_{get,list}xattr_maybe_cred
 * fell through to the plain slot for every caller it could not refuse: a user
 * presenting perfectly good S3 keys had the read signed as the EXPORT, so it
 * returned attributes that identity's own keys would have been denied. (The
 * forwarder's fallback_deny backstop already refused a credential it could not
 * route — that arm was never the hole; the silent service-key signing was.) */
static sd_s3_file *
sd_remote_meta_open(brix_sd_instance_t *inst, const char *path,
    const char *ak, const char *sk, const char *region, const char *session)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_s3_open_params           p;
    char                        objpath[768];
    char                        errbuf[256];

    sd_remote_s3_key(cfg, path, objpath, sizeof(objpath));
    sd_remote_s3_params(cfg, objpath, &p);
    sd_remote_params_cred(&p, ak, sk, region, session);
    return sd_s3_open_read(&p, errbuf, sizeof(errbuf));
}

static ssize_t
sd_remote_getxattr_impl(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap,
    const char *ak, const char *sk, const char *region, const char *session)
{
    char           val[2048];
    char           errbuf[256];
    sd_s3_meta_buf dst = { val, sizeof(val) };
    sd_s3_file    *s3;
    ssize_t        n;

    if (strncmp(name, "user.", 5) != 0 || name[5] == '\0') {
        errno = ENODATA;      /* only the user. namespace maps to x-amz-meta- */
        return -1;
    }
    s3 = sd_remote_meta_open(inst, path, ak, sk, region, session);
    if (s3 == NULL) {
        errno = ENOMEM;
        return -1;
    }
    errno = 0;
    n = sd_s3_get_meta(s3, name + 5, &dst, errbuf, sizeof(errbuf));
    sd_s3_close(s3);
    if (n < 0) {
        if (errno == 0) { errno = EIO; }
        return -1;
    }
    if (n == 0) {
        errno = ENODATA;      /* HEAD ok, attribute absent */
        return -1;
    }
    if (buf == NULL || cap == 0) {
        return n;             /* getxattr(2) size probe */
    }
    if ((size_t) n > cap) {
        errno = ERANGE;
        return -1;
    }
    memcpy(buf, val, (size_t) n);
    return n;
}

ssize_t
sd_remote_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap)
{
    return sd_remote_getxattr_impl(inst, path, name, buf, cap,
                                   NULL, NULL, NULL, NULL);
}

/* Cred-scoped getxattr: the HEAD runs as the requesting user. Gate semantics
 * identical to sd_remote_stat_cred — a cred this S3-only backend cannot use is
 * refused under fallback_deny rather than signed with the service credential. */
ssize_t
sd_remote_getxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap, const brix_sd_cred_t *cred)
{
    int gate = sd_remote_cred_gate(cred);

    if (gate > 0) {
        return sd_remote_getxattr_impl(inst, path, name, buf, cap,
            cred->s3_ak, cred->s3_sk, cred->s3_region, cred->s3_session);
    }
    if (gate < 0) {
        errno = EACCES;
        return -1;
    }
    return sd_remote_getxattr_impl(inst, path, name, buf, cap,
                                   NULL, NULL, NULL, NULL);
}

static ssize_t
sd_remote_listxattr_impl(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap,
    const char *ak, const char *sk, const char *region, const char *session)
{
    char        errbuf[256];
    sd_s3_file *s3;
    ssize_t     n;

    s3 = sd_remote_meta_open(inst, path, ak, sk, region, session);
    if (s3 == NULL) {
        errno = ENOMEM;
        return -1;
    }
    errno = 0;
    n = sd_s3_list_meta(s3, buf, cap, errbuf, sizeof(errbuf));
    sd_s3_close(s3);
    if (n < 0 && errno == 0) {
        errno = EIO;
    }
    return n;
}

ssize_t
sd_remote_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap)
{
    return sd_remote_listxattr_impl(inst, path, buf, cap,
                                    NULL, NULL, NULL, NULL);
}

/* Cred-scoped listxattr: enumerating an object's metadata keys is as much a
 * read of the user's object as getxattr, so it takes the same gate. */
ssize_t
sd_remote_listxattr_cred(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap, const brix_sd_cred_t *cred)
{
    int gate = sd_remote_cred_gate(cred);

    if (gate > 0) {
        return sd_remote_listxattr_impl(inst, path, buf, cap,
            cred->s3_ak, cred->s3_sk, cred->s3_region, cred->s3_session);
    }
    if (gate < 0) {
        errno = EACCES;
        return -1;
    }
    return sd_remote_listxattr_impl(inst, path, buf, cap,
                                    NULL, NULL, NULL, NULL);
}

/* Shared stat body: HEAD the object, optionally signing with a per-user
 * ak/sk/region override (NULL = the instance's static service credential).
 *
 * S3 has no directories, so classification is by object shape (#4): the export
 * root is always a directory; a "path" object is a regular file; failing that a
 * "path/" marker object is a directory. Directory recognition relies on the
 * marker this driver's mkdir (and put_inner parent-prefix creation) writes — an
 * externally-created prefix with children but no marker stats as ENOENT here,
 * though opendir still lists it. */
static ngx_int_t
sd_remote_stat_impl(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const char *ak, const char *sk, const char *region,
    const char *session)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_s3_open_params             p;
    char                          objpath[768];
    char                          errbuf[256];
    sd_s3_file                   *s3;
    int64_t                       size = 0;

    /* The export root is a directory with no backing marker object. */
    if (path == NULL || path[0] == '\0'
        || (path[0] == '/' && path[1] == '\0'))
    {
        memset(out, 0, sizeof(*out));
        out->mode   = S_IFDIR | 0755;
        out->is_dir = 1;
        return NGX_OK;
    }

    /* (1) regular file: HEAD "path" for the byte count. */
    sd_remote_s3_key(cfg, path, objpath, sizeof(objpath));
    sd_remote_s3_params(cfg, objpath, &p);
    sd_remote_params_cred(&p, ak, sk, region, session);
    s3 = sd_s3_open_read(&p, errbuf, sizeof(errbuf));
    if (s3 != NULL) {
        int ok = sd_s3_size(s3, &size, errbuf, sizeof(errbuf)) == 0;

        sd_s3_close(s3);
        if (ok) {
            memset(out, 0, sizeof(*out));
            out->size   = (off_t) size;
            out->mode   = S_IFREG | 0444;
            out->is_reg = 1;
            return NGX_OK;
        }
    }

    /* (2) directory: HEAD the "path/" folder marker. */
    sd_remote_s3_dirkey(cfg, path, objpath, sizeof(objpath));
    sd_remote_s3_params(cfg, objpath, &p);
    sd_remote_params_cred(&p, ak, sk, region, session);
    if (sd_remote_head_exists(&p)) {
        memset(out, 0, sizeof(*out));
        out->mode   = S_IFDIR | 0755;
        out->is_dir = 1;
        return NGX_OK;
    }

    errno = ENOENT;
    return NGX_ERROR;
}

ngx_int_t
sd_remote_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
{
    return sd_remote_stat_impl(inst, path, out, NULL, NULL, NULL, NULL);
}

/* Cred-scoped stat (P80.3): the probe/HEAD runs as the requesting user, so a
 * deny-mode request never reaches the origin under the service credential.
 * Registering this slot is also the canonical capability gate that turns on
 * per-user namespace credential resolution in brix_vfs_ns_cred(). */
ngx_int_t
sd_remote_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred)
{
    int gate = sd_remote_cred_gate(cred);

    if (gate > 0) {
        return sd_remote_stat_impl(inst, path, out,
            cred->s3_ak, cred->s3_sk, cred->s3_region, cred->s3_session);
    }
    if (gate < 0) {
        errno = EACCES;
        return NGX_ERROR;
    }
    return sd_remote_stat_impl(inst, path, out, NULL, NULL, NULL, NULL);
}

/* ---- mkdir (zero-byte "path/" folder marker) -----------------------------
 *
 * WHAT: Create the directory `path` by PUTting a zero-byte object whose key ends
 *       in '/'. Returns NGX_OK, or NGX_ERROR with errno=EEXIST when the marker
 *       already exists (POSIX mkdir; brix_vfs_backend_mkpath tolerates it per
 *       component) / EIO on a transport failure.
 * WHY:  finding #4 — WebDAV MKCOL / xrdfs mkdir over an s3:// backend hit the NULL
 *       mkdir slot (ENOSYS). Advertising CAP_DIRS_WRITE also turns on put_inner's
 *       S3-PUT parent-prefix creation, which drives this same slot; a working
 *       marker mkdir keeps that cap self-consistent.
 * HOW:  HEAD the marker for idempotency, then a single zero-byte PUT.
 */
static ngx_int_t
sd_remote_mkdir_impl(brix_sd_instance_t *inst, const char *path,
    const char *ak, const char *sk, const char *region, const char *session)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_s3_open_params             p;
    char                          dirkey[768];
    char                          errbuf[256];
    sd_s3_file                   *s3;

    sd_remote_s3_dirkey(cfg, path, dirkey, sizeof(dirkey));
    sd_remote_s3_params(cfg, dirkey, &p);
    sd_remote_params_cred(&p, ak, sk, region, session);

    if (sd_remote_head_exists(&p)) {
        errno = EEXIST;
        return NGX_ERROR;
    }

    s3 = sd_s3_open_write(&p, 0, SD_REMOTE_MARKER_PART, errbuf, sizeof(errbuf));
    if (s3 == NULL) {
        errno = EIO;
        return NGX_ERROR;
    }
    if (sd_s3_commit(s3, errbuf, sizeof(errbuf)) != 0) {
        sd_s3_abort(s3);
        sd_s3_close(s3);
        errno = EIO;
        return NGX_ERROR;
    }
    sd_s3_close(s3);
    return NGX_OK;
}

ngx_int_t
sd_remote_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    (void) mode;   /* object stores carry no per-object mode */
    return sd_remote_mkdir_impl(inst, path, NULL, NULL, NULL, NULL);
}

/* Cred-scoped mkdir (P80.3): the marker PUT runs as the requesting user. Gate
 * semantics identical to sd_remote_open_cred. */
ngx_int_t
sd_remote_mkdir_cred(brix_sd_instance_t *inst, const char *path, mode_t mode,
    const brix_sd_cred_t *cred)
{
    int gate = sd_remote_cred_gate(cred);

    (void) mode;

    if (gate > 0) {
        return sd_remote_mkdir_impl(inst, path,
            cred->s3_ak, cred->s3_sk, cred->s3_region, cred->s3_session);
    }
    if (gate < 0) {
        errno = EACCES;
        return NGX_ERROR;
    }
    return sd_remote_mkdir_impl(inst, path, NULL, NULL, NULL, NULL);
}

/* sd_s3_list_page callback: fire once, flag a child, stop the page. */
static int
sd_remote_rename_child_cb(void *ud, const char *name, int is_dir)
{
    (void) name;
    (void) is_dir;
    *(int *) ud = 1;
    return 1;   /* one child is enough — stop enumerating this page */
}

/* Does the directory prefix for `path` contain at least one child (beyond its
 * own marker, which sd_s3_list_page skips)? 1 = has a child, 0 = empty,
 * -1 = probe error (errno set). */
static int
sd_remote_prefix_has_child(const brix_sd_remote_cfg_t *cfg, const char *path,
    const char *ak, const char *sk, const char *region, const char *session)
{
    sd_s3_open_params  p;
    const char        *rel = (path != NULL) ? path : "/";
    char               root[300];
    char               prefix[768];
    char               cont_out[2048];
    char               errbuf[256];
    size_t             n;
    int                truncated = 0;
    int                found = 0;

    while (*rel == '/') { rel++; }
    n = strlen(rel);
    if (n + 1 >= sizeof(prefix)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(prefix, rel, n);
    if (n > 0 && prefix[n - 1] != '/') { prefix[n++] = '/'; }
    prefix[n] = '\0';

    snprintf(root, sizeof(root), "/%s/", cfg->bucket);   /* bucket-root canon URI */
    sd_remote_s3_params(cfg, root, &p);
    sd_remote_params_cred(&p, ak, sk, region, session);

    errno = 0;
    if (sd_s3_list_page(&p, prefix, "", sd_remote_rename_child_cb, &found,
            &truncated, cont_out, sizeof(cont_out), errbuf, sizeof(errbuf)) != 0)
    {
        if (errno == 0) { errno = EIO; }
        return -1;
    }
    return found;
}

/* Copy `src_objpath` onto the params-addressed destination, then DELETE the
 * source: S3 has no atomic rename, so a move is copy+delete. NGX_OK / NGX_ERROR
 * (errno set). `p` must already address the destination with creds applied;
 * `srckey`/creds re-address the source for the follow-up delete. */
static ngx_int_t
sd_remote_copy_then_delete(const brix_sd_remote_cfg_t *cfg,
    sd_s3_open_params *p, const char *src_objpath,
    const char *ak, const char *sk, const char *region, const char *session)
{
    char errbuf[256];

    errno = 0;
    if (sd_s3_copy(p, src_objpath, errbuf, sizeof(errbuf)) != 0) {
        if (errno == 0) { errno = EIO; }
        return NGX_ERROR;
    }
    sd_remote_s3_params(cfg, src_objpath, p);
    sd_remote_params_cred(p, ak, sk, region, session);
    if (sd_s3_delete(p, errbuf, sizeof(errbuf)) != 0) {
        if (errno == 0) { errno = EIO; }
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* ---- rename (copy + delete; file or empty directory) ---------------------
 *
 * WHAT: Move `src` to `dst`. Returns NGX_OK; NGX_ERROR with errno EEXIST (dst
 *       present under noreplace), ENOENT (src absent), ENOTSUP (src is a
 *       NON-empty directory — no atomic prefix move), EIO otherwise.
 * WHY:  finding #4 — WebDAV MOVE / xrdfs mv over an s3:// backend hit the NULL
 *       rename slot (ENOSYS).
 * HOW:  Classify src (file HEAD, else empty-dir marker after a child probe) and
 *       copy+delete the corresponding object; S3 has no atomic move.
 */
static ngx_int_t
sd_remote_rename_impl(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace,
    const char *ak, const char *sk, const char *region, const char *session)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_s3_open_params             p;
    char                          srckey[768];
    char                          dstkey[768];
    int                           has;

    /* noreplace (POSC/O_EXCL): refuse if the destination file already exists. */
    if (noreplace) {
        sd_remote_s3_key(cfg, dst, dstkey, sizeof(dstkey));
        sd_remote_s3_params(cfg, dstkey, &p);
        sd_remote_params_cred(&p, ak, sk, region, session);
        if (sd_remote_head_exists(&p)) {
            errno = EEXIST;
            return NGX_ERROR;
        }
    }

    /* (1) regular file: HEAD src, then copy "src"->"dst" + delete "src". */
    sd_remote_s3_key(cfg, src, srckey, sizeof(srckey));
    sd_remote_s3_params(cfg, srckey, &p);
    sd_remote_params_cred(&p, ak, sk, region, session);
    if (sd_remote_head_exists(&p)) {
        sd_remote_s3_key(cfg, dst, dstkey, sizeof(dstkey));
        sd_remote_s3_params(cfg, dstkey, &p);
        sd_remote_params_cred(&p, ak, sk, region, session);
        return sd_remote_copy_then_delete(cfg, &p, srckey,
                                          ak, sk, region, session);
    }

    /* (2) directory: a non-empty prefix has no atomic move. */
    has = sd_remote_prefix_has_child(cfg, src, ak, sk, region, session);
    if (has < 0) {
        return NGX_ERROR;
    }
    if (has > 0) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }

    /* Empty directory: move its marker "src/"->"dst/" if it exists. */
    sd_remote_s3_dirkey(cfg, src, srckey, sizeof(srckey));
    sd_remote_s3_params(cfg, srckey, &p);
    sd_remote_params_cred(&p, ak, sk, region, session);
    if (!sd_remote_head_exists(&p)) {
        errno = ENOENT;   /* neither file, nor children, nor a marker */
        return NGX_ERROR;
    }
    sd_remote_s3_dirkey(cfg, dst, dstkey, sizeof(dstkey));
    sd_remote_s3_params(cfg, dstkey, &p);
    sd_remote_params_cred(&p, ak, sk, region, session);
    return sd_remote_copy_then_delete(cfg, &p, srckey, ak, sk, region, session);
}

ngx_int_t
sd_remote_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    return sd_remote_rename_impl(inst, src, dst, noreplace,
                                 NULL, NULL, NULL, NULL);
}

/* Cred-scoped rename (P80.3): every copy/delete/HEAD leg runs as the requesting
 * user. Gate semantics identical to sd_remote_open_cred. */
ngx_int_t
sd_remote_rename_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace, const brix_sd_cred_t *cred)
{
    int gate = sd_remote_cred_gate(cred);

    if (gate > 0) {
        return sd_remote_rename_impl(inst, src, dst, noreplace,
            cred->s3_ak, cred->s3_sk, cred->s3_region, cred->s3_session);
    }
    if (gate < 0) {
        errno = EACCES;
        return NGX_ERROR;
    }
    return sd_remote_rename_impl(inst, src, dst, noreplace,
                                 NULL, NULL, NULL, NULL);
}
