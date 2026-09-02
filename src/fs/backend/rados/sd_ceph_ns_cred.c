/*
 * sd_ceph_ns_cred.c — the credential-scoped NAMESPACE slots of the flat RADOS
 * driver: stat / unlink / getxattr / listxattr / setxattr / removexattr /
 * setattr / truncate_path / opendir, each executed on the requesting user's own
 * CephX connection rather than on the export's service connection.
 *
 * WHY THIS FILE EXISTS
 *   The identity a RADOS operation asserts at the OSDs is the ioctx it runs on
 *   and nothing else. Before this file the driver published open_cred alone, so
 *   a request carrying a per-user keyring got its data plane checked as that user
 *   while every metadata op — the probe stat, the listing, the xattr read, the
 *   delete — still reached st->ioctx and executed as the export service account.
 *   That is the classic confused deputy: the caller supplies the path, the deputy
 *   supplies the authority. It is the same defect closed on sd_remote, and it is
 *   only visible in ALLOW mode: brix_sd_<op>_maybe_cred already refuses with
 *   EACCES when a cred with fallback_deny meets a driver that has the plain slot
 *   and no _cred twin, so deny mode was always safe and the permitted path was
 *   the hole.
 *
 * SHAPE
 *   Every slot is the same three steps — resolve the caller's ioctx with
 *   sd_ceph_cred_ioctx_get(), run the ioctx-explicit core (the *_io functions the
 *   plain slots also call, so there is exactly one implementation of each op),
 *   release with sd_ceph_cred_ioctx_put() on EVERY exit path — so those steps
 *   live once, in sd_ceph_ns_cred_run(), and each slot is only the argument
 *   bundle plus its op tag. The _put releases a TRANSIENT connection only; a
 *   cached one belongs to the LRU. No pin is taken: a namespace op leaves no
 *   handle behind, unlike open_cred, whose object keeps reading from the
 *   connection after the slot returns. opendir_cred is the one slot written out
 *   longhand: it returns a handle rather than a count.
 *
 * NOT HERE, and deliberately so:
 *   - rename_cred: sd_ceph_rename threads sd_ceph_state_t through eight helpers
 *     and copies bytes through st->striper, which is bound to the EXPORT's
 *     connection. A cred-shaped wrapper over that would assert the wrong identity
 *     for the copy while looking correct at the call site.
 *   - staged_open_cred: sd_ceph_staged_t carries only the final oid, so a
 *     cred-scoped stage would have to hold the ioctx and pin the connection
 *     across commit AND abort.
 *   - mkdir_cred: directories are synthetic (ADR-1) and mkdir touches no object,
 *     so there is no cluster-side authority to scope.
 */
#include "sd_ceph_internal.h"

#ifdef BRIX_HAVE_CEPH

#include <errno.h>

/* sd_ceph_ns_op_e / sd_ceph_ns_args_t — which namespace core to run, and the
 * union of everything the cores take. One tagged call site instead of eight
 * copies of "acquire the caller's ioctx, run the op, release": the acquire and
 * the release are the security-relevant half, and they must not exist in eight
 * places where one of them can quietly lose an early return. */
typedef enum {
    SD_CEPH_NS_STAT = 0,
    SD_CEPH_NS_UNLINK,
    SD_CEPH_NS_GETXATTR,
    SD_CEPH_NS_LISTXATTR,
    SD_CEPH_NS_SETXATTR,
    SD_CEPH_NS_UNLINK_MANY,     /* phase-107 C4 batch */
    SD_CEPH_NS_REMOVEXATTR,
    SD_CEPH_NS_TRUNCATE_PATH,
    SD_CEPH_NS_SETATTR
} sd_ceph_ns_op_e;

typedef struct {
    const char      *path;
    const char      *name;      /* xattr name  */
    void            *buf;       /* get/listxattr destination */
    const void      *val;       /* setxattr source */
    size_t           cap;       /* buf capacity, or setxattr value length */
    off_t            len;       /* truncate length */
    int              is_dir;    /* unlink */
    brix_sd_unlink_batch_t *batch;   /* unlink_many (C4) */
    brix_sd_stat_t  *stat_out;
    const brix_sd_setattr_t *attr;   /* setattr request */
} sd_ceph_ns_args_t;

/* sd_ceph_ns_apply — run one ioctx-explicit namespace core.
 * The cores are shared verbatim with the plain (service-credential) slots, so
 * there is exactly one implementation of each op and the credential decides
 * nothing but WHICH ioctx it runs on. Returns the core's own value widened to
 * ssize_t: NGX_OK (0) / NGX_ERROR (-1) for the ngx_int_t cores, a byte count or
 * -1 for the two that return ssize_t — the two encodings agree on both 0 and
 * -1, which is why one return type serves. */
static ssize_t
sd_ceph_ns_apply(sd_ceph_state_t *st, rados_ioctx_t io, sd_ceph_ns_op_e op,
    const sd_ceph_ns_args_t *a)
{
    switch (op) {
    case SD_CEPH_NS_STAT:
        return sd_ceph_stat_io(st, io, a->path, a->stat_out);
    case SD_CEPH_NS_UNLINK:
        return sd_ceph_unlink_io(st, io, a->path, a->is_dir);
    case SD_CEPH_NS_UNLINK_MANY:
        return sd_ceph_unlink_many_io(st, io, a->batch);
    case SD_CEPH_NS_GETXATTR:
        return sd_ceph_getxattr_io(st, io, a->path, a->name, a->buf, a->cap);
    case SD_CEPH_NS_LISTXATTR:
        return sd_ceph_listxattr_io(st, io, a->path, a->buf, a->cap);
    case SD_CEPH_NS_SETXATTR:
        return sd_ceph_setxattr_io(st, io, a->path, a->name, a->val, a->cap);
    case SD_CEPH_NS_REMOVEXATTR:
        return sd_ceph_removexattr_io(st, io, a->path, a->name);
    case SD_CEPH_NS_TRUNCATE_PATH:
        return sd_ceph_truncate_path_io(st, io, a->path, a->len);
    case SD_CEPH_NS_SETATTR:
        return sd_ceph_setattr_io(st, io, a->path, a->attr);
    }
    errno = ENOSYS;                 /* unreachable: the enum is closed */
    return -1;
}

/* sd_ceph_ns_cred_run — the whole shape of a credential-scoped namespace slot:
 * resolve the caller's ioctx, run the core on it, release on EVERY exit path.
 * The release frees a TRANSIENT connection only — a cached one belongs to the
 * LRU — and no pin is needed because a namespace op leaves no handle behind.
 * Returns the core's value, or -1 with errno set if the credential was refused
 * (deny mode) or could not be connected. */
static ssize_t
sd_ceph_ns_cred_run(brix_sd_instance_t *inst, const brix_sd_cred_t *cred,
    sd_ceph_ns_op_e op, const sd_ceph_ns_args_t *a)
{
    sd_ceph_state_t      *st = inst->state;
    sd_ceph_cred_ioctx_t  ci;
    ssize_t               rc;

    if (sd_ceph_cred_ioctx_get(st, inst->pool, cred, &ci) != 0) {
        return -1;
    }
    rc = sd_ceph_ns_apply(st, ci.ioctx, op, a);
    sd_ceph_cred_ioctx_put(&ci);
    return rc;
}

/* sd_ceph_stat_cred — stat as the caller. */
ngx_int_t
sd_ceph_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred)
{
    sd_ceph_ns_args_t a = { .path = path, .stat_out = out };

    return (ngx_int_t) sd_ceph_ns_cred_run(inst, cred, SD_CEPH_NS_STAT, &a);
}

/* sd_ceph_unlink_cred — remove as the caller. A synthetic directory removal
 * enumerates the pool on the same ioctx, so a user who cannot list cannot
 * discover the directory's children through the emptiness probe either. */
ngx_int_t
sd_ceph_unlink_cred(brix_sd_instance_t *inst, const char *path, int is_dir,
    const brix_sd_cred_t *cred)
{
    sd_ceph_ns_args_t a = { .path = path, .is_dir = is_dir };

    return (ngx_int_t) sd_ceph_ns_cred_run(inst, cred, SD_CEPH_NS_UNLINK, &a);
}

/* sd_ceph_unlink_many_cred - the C4 batch as the caller. The batch's entire
 * value on this driver: the caller's ioctx (= identity at the OSDs) is
 * resolved ONCE and every rados_remove in the window runs on it, against N
 * acquire/release cycles for the per-key loop. The acquire/release bracket is
 * safe for the same reason the single unlink's is: a namespace op leaves no
 * handle behind (EAGER - nothing outlives the call, so nothing needs the
 * lazy-slot credential COPY). */
ngx_int_t
sd_ceph_unlink_many_cred(brix_sd_instance_t *inst, brix_sd_unlink_batch_t *b,
    const brix_sd_cred_t *cred)
{
    sd_ceph_ns_args_t a = { .batch = b };

    return (ngx_int_t) sd_ceph_ns_cred_run(inst, cred, SD_CEPH_NS_UNLINK_MANY,
                                           &a);
}

/* sd_ceph_getxattr_cred — read one xattr as the caller. */
ssize_t
sd_ceph_getxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap, const brix_sd_cred_t *cred)
{
    sd_ceph_ns_args_t a = { .path = path, .name = name, .buf = buf, .cap = cap };

    return sd_ceph_ns_cred_run(inst, cred, SD_CEPH_NS_GETXATTR, &a);
}

/* sd_ceph_listxattr_cred — enumerate xattr names as the caller. */
ssize_t
sd_ceph_listxattr_cred(brix_sd_instance_t *inst, const char *path, void *buf,
    size_t cap, const brix_sd_cred_t *cred)
{
    sd_ceph_ns_args_t a = { .path = path, .buf = buf, .cap = cap };

    return sd_ceph_ns_cred_run(inst, cred, SD_CEPH_NS_LISTXATTR, &a);
}

/* sd_ceph_setxattr_cred — write one xattr as the caller. `flags` is ignored for
 * the same reason the plain slot ignores it: RADOS has no CREATE/REPLACE. */
ngx_int_t
sd_ceph_setxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags,
    const brix_sd_cred_t *cred)
{
    sd_ceph_ns_args_t a = { .path = path, .name = name, .val = val, .cap = len };

    (void) flags;

    return (ngx_int_t) sd_ceph_ns_cred_run(inst, cred, SD_CEPH_NS_SETXATTR, &a);
}

/* sd_ceph_removexattr_cred — drop one xattr as the caller. */
ngx_int_t
sd_ceph_removexattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const brix_sd_cred_t *cred)
{
    sd_ceph_ns_args_t a = { .path = path, .name = name };

    return (ngx_int_t) sd_ceph_ns_cred_run(inst, cred, SD_CEPH_NS_REMOVEXATTR,
                                            &a);
}

/* sd_ceph_truncate_path_cred — resize as the caller. Truncation destroys bytes
 * without ever opening the object, which is precisely why it must not run on the
 * export's authority when the request carries one of its own. */
ngx_int_t
sd_ceph_truncate_path_cred(brix_sd_instance_t *inst, const char *path,
    off_t len, const brix_sd_cred_t *cred)
{
    sd_ceph_ns_args_t a = { .path = path, .len = len };

    return (ngx_int_t) sd_ceph_ns_cred_run(inst, cred,
                                            SD_CEPH_NS_TRUNCATE_PATH, &a);
}

/* sd_ceph_setattr_cred — amend the advisory metadata as the caller. The blob is
 * an ordinary RADOS xattr, so writing it must be checked against the caller's
 * own CephX authority for exactly the reason setxattr_cred is: a user who cannot
 * write the object must not be able to rewrite its mode through the metadata
 * plane instead. */
ngx_int_t
sd_ceph_setattr_cred(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr, const brix_sd_cred_t *cred)
{
    sd_ceph_ns_args_t a = { .path = path, .attr = attr };

    return (ngx_int_t) sd_ceph_ns_cred_run(inst, cred, SD_CEPH_NS_SETATTR, &a);
}

/* sd_ceph_opendir_cred — list as the caller. Stands apart from the tagged
 * dispatch above because it alone returns a handle rather than a count, and
 * reports its failure through *err_out. Safe to release the connection at
 * return: sd_ceph_opendir_io is EAGER — it snapshots the whole listing into the
 * handle before it returns, so no later readdir touches the cluster. */
brix_sd_dir_t *
sd_ceph_opendir_cred(brix_sd_instance_t *inst, const char *path, int *err_out,
    const brix_sd_cred_t *cred)
{
    sd_ceph_state_t      *st = inst->state;
    sd_ceph_cred_ioctx_t  ci;
    brix_sd_dir_t        *d;

    if (sd_ceph_cred_ioctx_get(st, inst->pool, cred, &ci) != 0) {
        if (err_out != NULL) {
            *err_out = errno;
        }
        return NULL;
    }
    d = sd_ceph_opendir_io(inst, ci.ioctx, path, err_out);
    sd_ceph_cred_ioctx_put(&ci);
    return d;
}

#endif /* BRIX_HAVE_CEPH */
