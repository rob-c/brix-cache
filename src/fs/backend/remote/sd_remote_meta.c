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

/* ---- Probe one object while preserving absence versus failure ------------
 *
 * WHAT: Returns 1 when the params-addressed object exists, 0 only for a
 *       genuine ENOENT, or -1 with errno preserved for every other failure.
 *       When size_out is non-NULL, a successful probe stores the object size.
 *
 * WHY: Namespace fallbacks may try a marker or prefix only after a missing
 *      object. Treating AccessDenied or an origin failure as absence both
 *      weakens fail-closed behavior and returns misleading 404 responses.
 *
 * HOW: 1. Bind a read handle without performing I/O.
 *      2. Issue the shared HEAD/size request.
 *      3. Preserve errno across handle cleanup.
 *      4. Collapse only ENOENT to the absent result.
 */
static int
sd_remote_head_probe(const sd_s3_open_params *p, int64_t *size_out)
{
    char        errbuf[256];
    sd_s3_file *s3;
    int64_t     size = 0;
    int         rc;
    int         saved_errno;

    s3 = sd_s3_open_read(p, errbuf, sizeof(errbuf));
    if (s3 == NULL) {
        if (errno == 0) {
            errno = ENOMEM;
        }
        return -1;
    }
    errno = 0;
    rc = sd_s3_size(s3, &size, errbuf, sizeof(errbuf));
    saved_errno = errno;
    sd_s3_close(s3);
    if (rc == 0) {
        if (size_out != NULL) {
            *size_out = size;
        }
        return 1;
    }
    if (saved_errno == ENOENT) {
        errno = ENOENT;
        return 0;
    }
    errno = saved_errno != 0 ? saved_errno : EIO;
    return -1;
}

/* ---- Build the bucket-root params and normalized directory prefix --------
 *
 * WHAT: Returns 0 with params targeting the caller-owned bucket-root buffer
 *       and `prefix` holding the slash-terminated export-relative key, or -1
 *       with errno set.
 *
 * WHY: Prefix probes and child enumeration must sign the same bucket-root URI
 *      and normalize paths identically, including per-user credentials.
 *
 * HOW: 1. Remove leading path separators.
 *      2. Copy the relative key and append one trailing separator.
 *      3. Build the bucket root in caller-owned storage so params->key remains
 *         valid through the subsequent request.
 *      4. Bind S3 params and apply credential overrides.
 */
static int
sd_remote_prefix_params(const brix_sd_remote_cfg_t *cfg, const char *path,
    const char *ak, const char *sk, const char *region, const char *session,
    sd_s3_open_params *params, char *root, size_t root_cap,
    char *prefix, size_t prefix_cap)
{
    const char *relative = path != NULL ? path : "/";
    size_t      path_len;
    int         root_len;

    while (*relative == '/') {
        relative++;
    }
    path_len = strlen(relative);
    if (path_len + 1 >= prefix_cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(prefix, relative, path_len);
    if (path_len > 0 && prefix[path_len - 1] != '/') {
        prefix[path_len++] = '/';
    }
    prefix[path_len] = '\0';

    root_len = snprintf(root, root_cap, "/%s/", cfg->bucket);
    if (root_len < 0 || (size_t) root_len >= root_cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    sd_remote_s3_params(cfg, root, params);
    sd_remote_params_cred(params, ak, sk, region, session);
    return 0;
}

/* ---- Probe an implicit S3 directory prefix ------------------------------
 *
 * WHAT: Returns 1 when at least one key exists under `path/`, 0 when none
 *       exists, or -1 with errno preserved from the bounded list request.
 *
 * WHY: External S3 writers commonly create child keys without zero-byte
 *      directory markers. BriX must give those listable prefixes coherent
 *      filesystem stat semantics without turning list denial into absence.
 *
 * HOW: Build credential-scoped bucket params and issue a max-keys=1 prefix
 *      probe through the shared S3 ListObjectsV2 implementation.
 */
static int
sd_remote_implicit_dir_exists(const brix_sd_remote_cfg_t *cfg,
    const char *path, const char *ak, const char *sk, const char *region,
    const char *session)
{
    sd_s3_open_params params;
    char              root[300];
    char              prefix[768];
    char              errbuf[256];

    if (sd_remote_prefix_params(cfg, path, ak, sk, region, session,
            &params, root, sizeof(root), prefix, sizeof(prefix)) != 0)
    {
        return -1;
    }
    errno = 0;
    return sd_s3_prefix_exists(&params, prefix, errbuf, sizeof(errbuf));
}

/* ---- Classify a remote S3 namespace path --------------------------------
 *
 * WHAT: Fills `out` for a regular object, explicit marker directory, implicit
 *       non-empty prefix, or export root. Returns NGX_ERROR with typed errno
 *       for absence, denial, malformed paths, or origin failures.
 *
 * WHY: XRootD/WebDAV clients require list and stat to describe one coherent
 *      hierarchy. S3 markers preserve empty directories, while implicit
 *      prefixes make externally populated non-empty trees interoperable.
 *
 * HOW: 1. Synthesize the export root.
 *      2. HEAD `path`; an exact object wins and is a regular file.
 *      3. HEAD `path/`; an explicit marker is a directory.
 *      4. Probe one key beneath `path/`; any result is an implicit directory.
 *      5. Return ENOENT only after all authoritative probes report absence.
 */
static ngx_int_t
sd_remote_stat_impl(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const char *ak, const char *sk, const char *region,
    const char *session)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_s3_open_params             p;
    char                          objpath[768];
    int64_t                       size = 0;
    int                           probe;

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
    probe = sd_remote_head_probe(&p, &size);
    if (probe > 0) {
        memset(out, 0, sizeof(*out));
        out->size   = (off_t) size;
        out->mode   = S_IFREG | 0444;
        out->is_reg = 1;
        return NGX_OK;
    }
    if (probe < 0) {
        return NGX_ERROR;
    }

    /* (2) directory: HEAD the "path/" folder marker. */
    sd_remote_s3_dirkey(cfg, path, objpath, sizeof(objpath));
    sd_remote_s3_params(cfg, objpath, &p);
    sd_remote_params_cred(&p, ak, sk, region, session);
    probe = sd_remote_head_probe(&p, NULL);
    if (probe > 0) {
        memset(out, 0, sizeof(*out));
        out->mode   = S_IFDIR | 0755;
        out->is_dir = 1;
        return NGX_OK;
    }
    if (probe < 0) {
        return NGX_ERROR;
    }

    /* (3) directory: any descendant makes path/ an implicit prefix. */
    probe = sd_remote_implicit_dir_exists(cfg, path, ak, sk, region, session);
    if (probe > 0) {
        memset(out, 0, sizeof(*out));
        out->mode   = S_IFDIR | 0755;
        out->is_dir = 1;
        return NGX_OK;
    }
    if (probe < 0) {
        if (errno == 0) {
            errno = EIO;
        }
        return NGX_ERROR;
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
 * HOW:  Classify the complete namespace path, refuse any existing file or
 *       directory, then issue a single zero-byte marker PUT.
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
    brix_sd_stat_t                existing;
    ngx_int_t                     stat_rc;

    stat_rc = sd_remote_stat_impl(inst, path, &existing,
                                  ak, sk, region, session);
    if (stat_rc == NGX_OK) {
        errno = EEXIST;
        return NGX_ERROR;
    }
    if (errno != ENOENT) {
        return NGX_ERROR;
    }

    sd_remote_s3_dirkey(cfg, path, dirkey, sizeof(dirkey));
    sd_remote_s3_params(cfg, dirkey, &p);
    sd_remote_params_cred(&p, ak, sk, region, session);

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
    char               root[300];
    char               prefix[768];
    char               cont_out[2048];
    char               errbuf[256];
    int                truncated = 0;
    int                found = 0;

    if (sd_remote_prefix_params(cfg, path, ak, sk, region, session,
            &p, root, sizeof(root), prefix, sizeof(prefix)) != 0)
    {
        return -1;
    }

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
    int                           probe;
    brix_sd_stat_t                dst_stat;

    /* noreplace (POSC/O_EXCL): refuse every destination namespace shape. */
    if (noreplace) {
        if (sd_remote_stat_impl(inst, dst, &dst_stat,
                ak, sk, region, session) == NGX_OK)
        {
            errno = EEXIST;
            return NGX_ERROR;
        }
        if (errno != ENOENT) {
            return NGX_ERROR;
        }
    }

    /* (1) regular file: HEAD src, then copy "src"->"dst" + delete "src". */
    sd_remote_s3_key(cfg, src, srckey, sizeof(srckey));
    sd_remote_s3_params(cfg, srckey, &p);
    sd_remote_params_cred(&p, ak, sk, region, session);
    probe = sd_remote_head_probe(&p, NULL);
    if (probe > 0) {
        sd_remote_s3_key(cfg, dst, dstkey, sizeof(dstkey));
        sd_remote_s3_params(cfg, dstkey, &p);
        sd_remote_params_cred(&p, ak, sk, region, session);
        return sd_remote_copy_then_delete(cfg, &p, srckey,
                                          ak, sk, region, session);
    }
    if (probe < 0) {
        return NGX_ERROR;
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
    probe = sd_remote_head_probe(&p, NULL);
    if (probe < 0) {
        return NGX_ERROR;
    }
    if (probe == 0) {
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
