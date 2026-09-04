/*
 * oci_store.c — the local registry's on-disk store (Appendix B.3, §D4.1).
 *
 * WHAT: build every path the push surface writes, and perform the five
 *       primitive operations over them — exists, verify, publish-atomically,
 *       put/get a small text record, remove.
 * WHY:  a registry store is a content-addressed tree whose entire safety
 *       argument is "no wire byte ever reaches a path component unvalidated".
 *       Concentrating the path construction in one file is what makes that
 *       argument checkable: every builder below takes an ALREADY-CLASSIFIED
 *       name, digest hex or session id (§0.7.2 — a name that classifies has
 *       no '..' and no leading '/', a digest is 64 lowercase hex characters
 *       by grammar), so the traversal defense is the classifier's, proven
 *       once, rather than a sanitizer repeated per call site and eventually
 *       forgotten in one of them.
 * HOW:  fixed-size buffers and snprintf with an overflow check on every
 *       build; writes go through the phase-108 C10 service-publish verb
 *       (brix_service_publish_*), which stages to a random confined sibling,
 *       fsyncs the data on the durable REGISTRY domain, then renames and flushes
 *       the parent — so a reader never observes a partial object AND an object
 *       the client was told was 201 Created survives a crash.
 *
 * The raw namespace calls below carry per-line vfs-seam-allow markers
 * (invariant #12), for the reason oci_meta.c gives at its own head: this is
 * the module's OWN store, not a VFS export. Routing it through brix_vfs_*
 * would hand a miss to the cache decorator, which would try to FILL it from
 * an upstream registry — and on the registry surface there is none. Object
 * BYTES leaving the store still go out through the VFS + file_serve pipeline
 * (oci_registry.c), which is where invariant #2 and the metering live; what
 * stays here is store bookkeeping and the staging of received uploads.
 */

#include "oci_registry.h"

#include "core/compat/service_publish.h"
#include "core/compat/tmp_path.h"          /* brix_tmp_is_temp_name (C10 lister skip) */

#include <dirent.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define OCI_STORE_DIR_MODE   0700
#define OCI_STORE_IO_CHUNK   (64 * 1024)


ngx_int_t
brix_oci_store_init(brix_oci_store_t *st, ngx_http_brix_oci_loc_conf_t *lcf)
{
    const char *root;
    size_t      n;

    /* The merge has already folded brix_oci_registry_root into common.root
     * and canonicalised it, so the canonical form is the ONLY form worth
     * reading here: taking the raw directive string back would reintroduce
     * the symlinks and "." components brix_prepare_export_root removed. */
    root = lcf->common.root_canon;

    if (root == NULL || root[0] != '/') {
        return NGX_ERROR;
    }
    n = ngx_strlen(root);
    if (n == 0 || n >= sizeof(st->root)) {
        return NGX_ERROR;
    }

    /* A trailing slash would double up in every builder below; normalise it
     * away here so the builders can concatenate unconditionally. */
    while (n > 1 && root[n - 1] == '/') {
        n--;
    }
    ngx_memcpy(st->root, root, n);
    st->root[n] = '\0';
    st->root_len = n;

    return NGX_OK;
}


/* Every builder funnels through this so the overflow check exists once. The
 * printf format attribute earns its keep twice: it type-checks fmt against the
 * arguments at every builder callsite, and it is what tells the compiler the
 * vsnprintf below is forwarding a checked format rather than an arbitrary
 * runtime string (-Wformat-nonliteral). */
static int
oci_store_fmt(char *out, size_t outsz, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static int
oci_store_fmt(char *out, size_t outsz, const char *fmt, ...)
{
    va_list  ap;
    int      n;

    va_start(ap, fmt);
    n = vsnprintf(out, outsz, fmt, ap);
    va_end(ap);

    return (n < 0 || (size_t) n >= outsz) ? -1 : 0;
}


int
brix_oci_store_blob_path(const brix_oci_store_t *st,
    const brix_oci_digest_t *d, char *out, size_t outsz)
{
    const char *alg = brix_oci_alg_name(d->alg);

    if (alg == NULL) {
        return -1;
    }
    /* The two-character fan-out is the CAS convention every registry uses:
     * one directory per repository would put a million entries in one dir on
     * a busy site, and readdir() cost is what a GC eventually pays. */
    return oci_store_fmt(out, outsz, "%s/blobs/%s/%c%c/%s",
                         st->root, alg, d->hex[0], d->hex[1], d->hex);
}


int
brix_oci_store_repo_path(const brix_oci_store_t *st, const char *name,
    size_t name_len, const char *rest, char *out, size_t outsz)
{
    return oci_store_fmt(out, outsz, "%s/repos/%.*s/%s",
                         st->root, (int) name_len, name, rest);
}


int
brix_oci_store_upload_path(const brix_oci_store_t *st, const char *session,
    size_t session_len, const char *rest, char *out, size_t outsz)
{
    if (rest == NULL) {
        return oci_store_fmt(out, outsz, "%s/_uploads/%.*s",
                             st->root, (int) session_len, session);
    }
    return oci_store_fmt(out, outsz, "%s/_uploads/%.*s/%s",
                         st->root, (int) session_len, session, rest);
}


ngx_int_t
brix_oci_store_mkparent(const char *path, ngx_log_t *log)
{
    char    buf[PATH_MAX];
    size_t  n = ngx_strlen(path);
    char   *slash;

    if (n == 0 || n >= sizeof(buf)) {
        return NGX_ERROR;
    }
    ngx_memcpy(buf, path, n + 1);

    slash = strrchr(buf, '/');
    if (slash == NULL || slash == buf) {
        return NGX_OK;                     /* parent is "/" — already there */
    }
    *slash = '\0';

    /* Walk left to right creating each component. EEXIST is the common case
     * (the tree is shallow and shared), so it is not an error — anything
     * else is, and stops the walk rather than pressing on into a store whose
     * shape we no longer know. */
    for (char *p = buf + 1; *p != '\0'; p++) {
        if (*p != '/') {
            continue;
        }
        *p = '\0';
        if (mkdir(buf, OCI_STORE_DIR_MODE) != 0   /* vfs-seam-allow: DOMAIN_REGISTRY — registry store tree, not a VFS export object */
            && ngx_errno != NGX_EEXIST)
        {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "oci: cannot create store directory \"%s\"", buf);
            return NGX_ERROR;
        }
        *p = '/';
    }
    if (mkdir(buf, OCI_STORE_DIR_MODE) != 0       /* vfs-seam-allow: DOMAIN_REGISTRY — registry store tree, not a VFS export object */
        && ngx_errno != NGX_EEXIST)
    {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "oci: cannot create store directory \"%s\"", buf);
        return NGX_ERROR;
    }

    return NGX_OK;
}


int
brix_oci_store_exists(const char *path, off_t *size_out)
{
    struct stat sb;

    if (stat(path, &sb) != 0 || !S_ISREG(sb.st_mode)) {  /* vfs-seam-allow: DOMAIN_REGISTRY — store presence probe (CAS existence, no bytes read) */
        return 0;
    }
    if (size_out != NULL) {
        *size_out = sb.st_size;
    }
    return 1;
}


ngx_int_t
brix_oci_store_verify(const char *path, const brix_oci_digest_t *want,
    ngx_log_t *log)
{
    brix_oci_hash_ctx_t    sha;
    brix_oci_digest_t      got;
    u_char                 buf[OCI_STORE_IO_CHUNK];
    ngx_int_t              rc = NGX_ERROR;
    ssize_t                n;
    int                    fd;

    fd = open(path, O_RDONLY | O_CLOEXEC);   /* vfs-seam-allow: DOMAIN_REGISTRY — seal-time hash of the staged upload, before it becomes an object */
    if (fd < 0) {
        return NGX_ERROR;
    }
    /* Hash under the algorithm the CALLER is verifying against, never a
     * fixed one: verifying a sha512 blob with sha256 would compare two
     * different functions' output and reject every honest upload. */
    if (brix_oci_hash_init(&sha, want->alg) != 0) {
        (void) close(fd);
        return NGX_ERROR;
    }

    /* Sequential whole-file read: the seal is the one moment the registry
     * must know what it just received, and hashing here costs one pass over
     * bytes that are still in page cache from the PATCH that wrote them. */
    for ( ;; ) {
        n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (ngx_errno == NGX_EINTR) {
                continue;
            }
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "oci: unreadable staged upload \"%s\"", path);
            brix_oci_hash_abort(&sha);
            (void) close(fd);
            return NGX_ERROR;
        }
        if (n == 0) {
            break;
        }
        if (brix_oci_hash_update(&sha, buf, (size_t) n) != 0) {
            brix_oci_hash_abort(&sha);
            (void) close(fd);
            return NGX_ERROR;
        }
    }
    (void) close(fd);

    if (brix_oci_hash_final(&sha, &got) != 0) {
        return NGX_ERROR;
    }
    rc = brix_oci_digest_eq(&got, want) ? NGX_OK : NGX_DECLINED;

    return rc;
}


/* Fill the service-publish request the two adapters share: same store root and
 * log, the caller's domain and exclusivity; the mode is left 0 so the published
 * object inherits the staged temp's private 0600 — the mode every store object
 * has always carried, now without a redundant fchmod. */
static void
oci_store_publish_req(brix_service_publish_req_t *req,
    const brix_oci_store_t *st, const char *final_path, brix_vfs_domain_t domain,
    unsigned excl, ngx_log_t *log)
{
    ngx_memzero(req, sizeof(*req));
    req->log        = log;
    req->domain     = domain;
    req->root_canon = st->root;
    req->final_path = final_path;
    req->excl       = excl;
}


ngx_int_t
brix_oci_store_publish_bytes(const brix_oci_store_t *st, const char *path,
    const void *bytes, size_t len, brix_vfs_domain_t domain, ngx_log_t *log)
{
    brix_service_publish_req_t  req;

    if (brix_oci_store_mkparent(path, log) != NGX_OK) {
        return NGX_ERROR;
    }
    oci_store_publish_req(&req, st, path, domain, 0, log);
    return brix_service_publish_bytes(&req, bytes, len);
}


ngx_int_t
brix_oci_store_publish_staged(const brix_oci_store_t *st, const char *stage_path,
    const char *final_path, ngx_log_t *log)
{
    brix_service_publish_req_t  req;

    if (brix_oci_store_mkparent(final_path, log) != NGX_OK) {
        return NGX_ERROR;
    }
    oci_store_publish_req(&req, st, final_path, BRIX_VFS_DOMAIN_REGISTRY, 1, log);
    return brix_service_publish_fd(&req, NGX_INVALID_FILE, stage_path);
}


ssize_t
brix_oci_store_get_text(const char *path, char *out, size_t outsz)
{
    ssize_t  n;
    int      fd;

    fd = open(path, O_RDONLY | O_CLOEXEC);   /* vfs-seam-allow: DOMAIN_REGISTRY — store bookkeeping record (tag pointer / session state) */
    if (fd < 0) {
        return -1;
    }
    n = read(fd, out, outsz - 1);
    (void) close(fd);

    if (n < 0) {
        return -1;
    }
    out[n] = '\0';
    return n;
}


int
brix_oci_store_manifest_path(const brix_oci_store_t *st, const char *name,
    size_t name_len, const brix_oci_digest_t *d, const char *suffix,
    char *out, size_t outsz)
{
    char        rest[BRIX_OCI_HEXLEN_MAX + 32];
    const char *alg = brix_oci_alg_name(d->alg);

    if (alg == NULL) {
        return -1;
    }
    if (oci_store_fmt(rest, sizeof(rest), "manifests/%s/%s%s", alg, d->hex,
                      (suffix != NULL) ? suffix : "") != 0)
    {
        return -1;
    }
    return brix_oci_store_repo_path(st, name, name_len, rest, out, outsz);
}


int
brix_oci_store_tag_path(const brix_oci_store_t *st, const brix_oci_req_t *req,
    char *out, size_t outsz)
{
    char  rest[BRIX_OCI_KEY_MAX];

    /* The tag has already passed the classifier's grammar, so it cannot be
     * "..", cannot contain a separator, and cannot be empty — which is what
     * makes appending it to a directory path safe here without a second
     * sanitizer nobody would keep in step with the first. */
    if (oci_store_fmt(rest, sizeof(rest), "tags/%.*s",
                      (int) req->ref_len, req->ref) != 0)
    {
        return -1;
    }
    return brix_oci_store_repo_path(st, req->name, req->name_len, rest,
                                    out, outsz);
}


int
brix_oci_store_layer_path(const brix_oci_store_t *st, const char *name,
    size_t name_len, const brix_oci_digest_t *d, char *out, size_t outsz)
{
    char  rest[BRIX_OCI_HEXLEN_MAX + 16];

    if (oci_store_fmt(rest, sizeof(rest), "layers/%s", d->hex) != 0) {
        return -1;
    }
    return brix_oci_store_repo_path(st, name, name_len, rest, out, outsz);
}


ngx_int_t
brix_oci_store_tag_set(const brix_oci_store_t *st, const brix_oci_req_t *req,
    const char *digest_str, ngx_log_t *log)
{
    char    path[PATH_MAX];
    char    line[BRIX_OCI_DIGEST_STRLEN + 2];
    size_t  n;

    if (brix_oci_store_tag_path(st, req, path, sizeof(path)) != 0) {
        return NGX_ERROR;
    }
    n = (size_t) snprintf(line, sizeof(line), "%s\n", digest_str);
    if (n >= sizeof(line)) {
        return NGX_ERROR;
    }
    /* A tag swap is deliberately NOT excl: overwriting the pointer is the
     * operation. REGISTRY makes the new pointer durable before we answer. */
    return brix_oci_store_publish_bytes(st, path, line, n,
                                        BRIX_VFS_DOMAIN_REGISTRY, log);
}


int
brix_oci_store_tag_list(const brix_oci_store_t *st, const char *name,
    size_t name_len, char *out, size_t outsz)
{
    char            dir[PATH_MAX];
    struct dirent  *ent;
    size_t          used = 0;
    int             count = 0;
    DIR            *dh;

    out[0] = '\0';

    if (brix_oci_store_repo_path(st, name, name_len, "tags",
                                 dir, sizeof(dir)) != 0)
    {
        return -1;
    }
    dh = opendir(dir);                     /* vfs-seam-allow: DOMAIN_REGISTRY — registry's own store index, not a VFS export listing */
    if (dh == NULL) {
        return 0;                          /* a repo with no tags is not an error */
    }

    while ((ent = readdir(dh)) != NULL) {  /* vfs-seam-allow: DOMAIN_REGISTRY — registry's own store index, not a VFS export listing */
        size_t len = ngx_strlen(ent->d_name);

        /* Skip dotfiles, over-long entries, and a crash-orphaned publish temp
         * (<tag>.xrd-tmp.<pid>.<rand>) that the startup reaper has not yet swept
         * — a stale temp is not a tag. */
        if (ent->d_name[0] == '.' || used + len + 2 > outsz
            || brix_tmp_is_temp_name(ent->d_name)) {
            continue;
        }
        ngx_memcpy(out + used, ent->d_name, len);
        used += len;
        out[used++] = '\n';
        out[used]   = '\0';
        count++;
    }
    (void) closedir(dh);

    return count;
}


ngx_int_t
brix_oci_store_mark_layer(const brix_oci_store_t *st, const char *name,
    size_t name_len, const brix_oci_digest_t *d, ngx_log_t *log)
{
    char  path[PATH_MAX];

    if (brix_oci_store_layer_path(st, name, name_len, d,
                                  path, sizeof(path)) != 0)
    {
        return NGX_ERROR;
    }

    /* An empty file: the MARK is the fact, and its name carries the digest.
     * Rewriting an existing mark is harmless and keeps the caller free of a
     * "does it already reference this?" probe on every push. */
    return brix_oci_store_publish_bytes(st, path, "", 0,
                                        BRIX_VFS_DOMAIN_REGISTRY, log);
}


ngx_int_t
brix_oci_store_remove(const char *path, ngx_log_t *log)
{
    if (unlink(path) != 0 && ngx_errno != NGX_ENOENT) {   /* vfs-seam-allow: DOMAIN_REGISTRY — store object removal (DELETE / session abort) */
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "oci: cannot remove \"%s\"", path);
        return NGX_ERROR;
    }
    return NGX_OK;
}


void
brix_oci_store_drop_dir(const char *dir, ngx_log_t *log)
{
    static const char *const  children[] = { "part", "meta" };
    char                      path[PATH_MAX];
    size_t                    i;

    /* A session directory holds exactly the two children this module puts
     * there, so the teardown enumerates them rather than walking: a recursive
     * remove over an attacker-influenced path is a bigger primitive than this
     * job needs. */
    for (i = 0; i < sizeof(children) / sizeof(children[0]); i++) {
        if (oci_store_fmt(path, sizeof(path), "%s/%s", dir, children[i]) == 0) {
            (void) brix_oci_store_remove(path, log);
        }
    }
    if (rmdir(dir) != 0 && ngx_errno != NGX_ENOENT) {   /* vfs-seam-allow: DOMAIN_REGISTRY — session directory teardown (abort / reap / seal) */
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "oci: cannot remove upload session \"%s\"", dir);
    }
}
