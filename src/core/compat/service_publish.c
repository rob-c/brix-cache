/*
 * service_publish.c — see service_publish.h for WHAT/WHY/HOW.
 *
 * The body is a composition of phase-107 primitives, not new mechanism: the
 * domain claim (vfs_policy_domain), the staged temp (staged_file), and the
 * confined durable commit (staged_file). The only lines that are not a straight
 * reuse are the domain-aware data fsync (§3.3) and the fsync of a caller-staged
 * file that arrives without a held fd.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/compat/service_publish.h"
#include "core/compat/staged_file.h"
#include "fs/path/beneath.h"
#include "fs/vfs/vfs_policy.h"          /* BRIX_VFS_MUTATE_PUBLISH */
#include "fs/vfs/vfs_policy_domain.h"   /* brix_vfs_domain_claim */

/*
 * Durability is a property of the domain (§3.3), not of the medium or a
 * per-operator directive: REGISTRY answers 201 Created, a JOURNAL replay is the
 * recovery mechanism, and CONFIG is operator truth — all three must be on stable
 * storage before the caller proceeds. CACHE and STAGE are reconstructible (a
 * re-fetch, a retried upload), so they rename only. CREDENTIAL never routes here
 * (its arm-explicit verb lives in cred_write.c); EXPORT is refused by the domain
 * claim before this is consulted.
 */
static int
service_domain_durable(brix_vfs_domain_t domain)
{
    return domain == BRIX_VFS_DOMAIN_REGISTRY
        || domain == BRIX_VFS_DOMAIN_JOURNAL
        || domain == BRIX_VFS_DOMAIN_CONFIG;
}

/*
 * Fsync a caller-staged file that arrived without a held fd, so its data is
 * stable before its name is (the durable-domain _fd path). Confined beneath
 * root_canon and O_NOFOLLOW so a symlink swapped in at stage_path can redirect
 * neither the flush nor, by extension, the file the rename will publish.
 * Returns 0, or -1 with errno preserved.
 */
static int
service_fsync_stage(ngx_log_t *log, const char *root_canon,
    const char *stage_path)
{
    const char *rel;
    int         rootfd, fd, e;

    rootfd = brix_beneath_open_root(root_canon);
    if (rootfd < 0) {
        return -1;
    }
    rel = brix_beneath_strip_root(root_canon, stage_path);
    if (rel == NULL) {
        close(rootfd);
        errno = EXDEV;
        return -1;
    }
    fd = brix_open_beneath(rootfd, rel,
                           O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0);
    e = errno;
    close(rootfd);
    if (fd < 0) {
        errno = e;
        return -1;
    }
    if (fsync(fd) != 0) {
        e = errno;
        ngx_log_error(NGX_LOG_ERR, log, e,
                      "brix: service publish fsync of staged \"%s\" failed — "
                      "not publishing", stage_path);
        close(fd);
        errno = e;
        return -1;
    }
    close(fd);
    return 0;
}

/*
 * Seal the write handle before the commit: fsync the data on a durable domain
 * (D1), restore the published mode, then CHECK the close (D3) — a deferred
 * write-back error surfaces here, not silently at a bare close(). Leaves
 * staged->fd = NGX_INVALID_FILE so the commit's own seal is a no-op. Returns 0,
 * or -1 with errno set and the fd already closed.
 */
static int
service_seal_fd(const brix_service_publish_req_t *req,
    brix_staged_file_t *staged)
{
    int  fd = staged->fd;
    int  e;

    if (service_domain_durable(req->domain) && fsync(fd) != 0) {
        e = errno;
        ngx_log_error(NGX_LOG_ERR, req->log, e,
                      "brix: service publish fsync failed — not publishing "
                      "\"%s\"", req->final_path);
        close(fd);
        staged->fd = NGX_INVALID_FILE;
        errno = e;
        return -1;
    }
    /* The temp was created 0600 (private in-flight); publish the intended mode.
     * Service storage is never impersonated, so the fd fchmod reaches it — no
     * broker path is needed. Best-effort, as in staged_seal_temp. */
    if (req->mode != 0) {
        (void) fchmod(fd, req->mode);
    }
    /* close() on a modern Linux frees the fd even on EINTR, so a retry would
     * close a fd we no longer own; treat only a genuine error as a failure. */
    if (close(fd) != 0 && errno != EINTR) {
        e = errno;
        ngx_log_error(NGX_LOG_ERR, req->log, e,
                      "brix: service publish close failed — not publishing "
                      "\"%s\"", req->final_path);
        staged->fd = NGX_INVALID_FILE;
        errno = e;
        return -1;
    }
    staged->fd = NGX_INVALID_FILE;
    return 0;
}

/*
 * The shared tail: seal the staged handle (staged->fd, the write fd for a bytes
 * publish or the caller's held fd adopted onto the struct), then commit through
 * the confined durable publish. When no fd is held, a durable domain fsyncs the
 * staged file by path first. On any failure no file survives — the pre-commit
 * paths abort the staged temp; the commit owns its own cleanup and needs no
 * second abort. errno (EEXIST on the excl arm included) is preserved.
 */
static ngx_int_t
service_publish_finish(const brix_service_publish_req_t *req,
    brix_staged_file_t *staged)
{
    int  e;

    if (staged->fd != NGX_INVALID_FILE) {
        if (service_seal_fd(req, staged) != 0) {
            e = errno;
            brix_staged_abort(req->log, req->root_canon, staged, 1);
            errno = e;
            return NGX_ERROR;
        }
    } else if (service_domain_durable(req->domain)
               && service_fsync_stage(req->log, req->root_canon,
                                      staged->tmp_path) != 0)
    {
        e = errno;
        brix_staged_abort(req->log, req->root_canon, staged, 1);
        errno = e;
        return NGX_ERROR;
    }

    if ((req->excl
            ? brix_staged_commit_excl(req->log, req->root_canon, staged,
                                      req->final_path)
            : brix_staged_commit(req->log, req->root_canon, staged,
                                 req->final_path)) != NGX_OK)
    {
        return NGX_ERROR;               /* commit preserved errno and cleaned up */
    }
    return NGX_OK;
}

ngx_int_t
brix_service_publish_bytes(const brix_service_publish_req_t *req,
    const void *bytes, size_t len)
{
    brix_staged_open_req_t  open_req;
    brix_staged_file_t      staged;
    const u_char           *p = bytes;
    ssize_t                 n;
    int                     e;

    if (req == NULL || req->root_canon == NULL || req->final_path == NULL
        || (len > 0 && bytes == NULL))
    {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (brix_vfs_domain_claim(req->log, req->domain, BRIX_VFS_MUTATE_PUBLISH)
        != NGX_OK)
    {
        return NGX_ERROR;               /* EROFS on EXPORT, EINVAL out of range */
    }

    ngx_memzero(&open_req, sizeof(open_req));
    open_req.root_canon = req->root_canon;
    open_req.final_path = req->final_path;
    open_req.mode       = req->mode;
    open_req.open_flags = O_WRONLY;     /* staged_open adds O_CREAT | O_EXCL */

    if (brix_staged_open(req->log, &open_req, &staged) != NGX_OK) {
        return NGX_ERROR;
    }

    while (len > 0) {
        n = write(staged.fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            e = errno;
            ngx_log_error(NGX_LOG_ERR, req->log, e,
                          "brix: service publish write to \"%s\" failed",
                          req->final_path);
            brix_staged_abort(req->log, req->root_canon, &staged, 1);
            errno = e;
            return NGX_ERROR;
        }
        p   += n;
        len -= (size_t) n;
    }

    return service_publish_finish(req, &staged);
}

ngx_int_t
brix_service_publish_fd(const brix_service_publish_req_t *req,
    ngx_fd_t fd, const char *stage_path)
{
    brix_staged_file_t  staged;

    if (req == NULL || req->root_canon == NULL || req->final_path == NULL
        || stage_path == NULL)
    {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (brix_vfs_domain_claim(req->log, req->domain, BRIX_VFS_MUTATE_PUBLISH)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_strlen(stage_path) >= sizeof(staged.tmp_path)) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    /* Adopt the caller's already-written file as the staged temp: the commit
     * renames it confined beneath root_canon and runs the C3 barrier, exactly
     * as for a temp this unit opened. A held fd (not NGX_INVALID_FILE) is sealed
     * by the shared tail; NGX_INVALID_FILE means the caller kept no fd, and a
     * durable domain reopens and fsyncs stage_path by path. */
    ngx_memzero(&staged, sizeof(staged));
    staged.fd         = fd;
    staged.active     = 1;
    staged.final_mode = req->mode;
    ngx_cpystrn((u_char *) staged.tmp_path, (u_char *) stage_path,
                sizeof(staged.tmp_path));

    return service_publish_finish(req, &staged);
}
