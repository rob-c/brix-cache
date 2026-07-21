/*
 * sd_ceph_internal.h — cross-TU internals shared by the Ceph/RADOS driver's
 * implementation files (sd_ceph.c, sd_ceph_io.c, sd_ceph_object.c,
 * sd_ceph_cred.c).
 *
 * WHAT: The driver body was split (file-size guard) across four translation
 *       units. This header carries the pieces they share: the private struct
 *       definitions (the live connection, the per-export state incl. its
 *       cred-conn cache, the per-open object state, and the bundled open
 *       request) plus the declarations of every driver-private function that is
 *       DEFINED in one of those files but REFERENCED from another (the vtable op
 *       functions the descriptor in sd_ceph.c wires up, and the handful of
 *       helpers used across the split).
 *
 * WHY:  These types/functions are implementation-private (they never appear in
 *       the public sd_ceph.h API — that file declares only the pure LFN->oid
 *       helpers, the per-export config struct, the driver symbol, and the
 *       shared oid-level conn/oid API). Keeping them here rather than in
 *       sd_ceph.h keeps the private surface out of the public header while
 *       still letting the four implementation files agree on one definition.
 *
 * HOW:  Include-guarded; pulls in the public sd_ceph.h (which, under
 *       BRIX_HAVE_CEPH, brings librados + fs/backend/sd.h) and the striper
 *       header (rados_striper_t is embedded in sd_ceph_state_t). Everything
 *       below the include block is gated on BRIX_HAVE_CEPH, mirroring the
 *       driver body it serves.
 */
#ifndef BRIX_SD_CEPH_INTERNAL_H
#define BRIX_SD_CEPH_INTERNAL_H

#include "sd_ceph.h"

#if BRIX_HAVE_CEPH

#include <rados/librados.h>
#include "sd_ceph_striper.h"   /* rados_striper_t (embedded in sd_ceph_state_t) */
#include <time.h>

/* sd_ceph_conn_s — a live librados connection (the full definition of the
 * opaque sd_ceph_conn_t declared in sd_ceph.h). Defined here, early in the
 * driver body, rather than down beside sd_ceph_conn_create/_destroy: it must
 * be a COMPLETE type before sd_ceph_state_t's cred-conn cache entries and
 * sd_ceph_cleanup (both further down but still ahead of the "shared oid-
 * level layer" section) can dereference `conn->refs`.
 *
 * `refs` is a PIN count: every open object currently resolved onto this
 * connection (sd_ceph_obj_state_t.conn) holds one ref, taken at open
 * (sd_ceph_conn_pin) and dropped at close (sd_ceph_conn_unpin). `doomed`
 * marks a connection with no future path to reuse — either (a) evicted/
 * removed from the cred-conn cache table while still pinned (a future
 * lookup can never find it again), or (b) a transient connection that was
 * never inserted into the table at all (created when every cache slot was
 * pinned; sd_ceph_cred_conn marks it doomed at birth, before returning it,
 * since nothing else could ever reach it to free it otherwise) — in both
 * cases the connection could not be (or never will be) destroyed at the
 * point it stops being reachable via the table, because refs>0 (or will
 * become >0 the moment the caller pins it). The ref-dropping unpin that
 * brings refs to 0 performs the deferred rados_ioctx_destroy/
 * rados_shutdown. This refcount/pin/deferred-destroy design fixes two
 * historical bugs: (1) UAF — an in-use connection is never torn down out
 * from under a still-open handle's pread/pwrite/fstat, no matter how much
 * LRU eviction pressure other (user,keyring) opens generate; (2) leak — a
 * transient (all-slots-pinned) connection is guaranteed exactly one
 * deferred destroy, at its own last unpin, instead of being abandoned. */
struct sd_ceph_conn_s {
    rados_t        cluster;
    rados_ioctx_t  ioctx;
    ngx_pool_t    *pool;
    unsigned       connected:1;
    unsigned       doomed:1;
    unsigned       refs;
};

/* Sizes for the per-user cred-conn cache key (user id + keyring path). These
 * intentionally MIRROR fs/backend/ucred.h's BRIX_UCRED_CEPH_USER_MAX /
 * BRIX_UCRED_CEPH_KEYRING_MAX (the source of the strings cached here) rather
 * than including ucred.h directly: ucred.h pulls in ngx_config.h/ngx_core.h
 * unconditionally (it has no XRDPROTO_NO_NGX branch, unlike sd.h), which
 * would break the ngx-free standalone build this file supports (the live
 * driver tests under tests/ceph/ compile sd_ceph.c with -DXRDPROTO_NO_NGX
 * and no nginx headers at all). If ucred.h's bounds ever change, update these
 * to match — sd_ceph.c's cred-conn cache entries must stay large enough to
 * hold whatever ucred.c can populate brix_sd_cred_t.ceph_user/ceph_keyring
 * with. */
#define SD_CEPH_CRED_USER_MAX    128
#define SD_CEPH_CRED_KEYRING_MAX 1024

/* Bound on the per-export cache of per-user (ceph_user, ceph_keyring) librados
 * connections (ceph-peruser item). A small bounded LRU: cred-scoped opens are
 * rare relative to plain opens (only credential-gated exports use them), and
 * each entry holds a live rados_t/ioctx pair, so the cap keeps worst-case
 * connection/fd usage predictable under a many-user credential directory. */
#define SD_CEPH_CRED_CONN_CACHE_MAX 8

/* Bound on a single xattr value we buffer for the size-probe path. */
#define SD_CEPH_XATTR_MAX (64u * 1024)

/* One cached per-user connection: the (user, keyring) key it was opened for,
 * the connection itself, and an LRU generation counter (higher = more
 * recently used) so eviction picks the least-recently-used entry. */
typedef struct {
    char            user[SD_CEPH_CRED_USER_MAX];
    char            keyring[SD_CEPH_CRED_KEYRING_MAX];
    sd_ceph_conn_t *conn;
    uint64_t        lru_gen;
} sd_ceph_cred_conn_ent_t;

/* Driver-private per-export state (inst->state): one connected cluster handle +
 * ioctx, plus the resolved configuration, plus the per-user cred-conn cache. */
typedef struct {
    rados_t        cluster;
    rados_ioctx_t  ioctx;
    char          *pool;
    char          *user;
    char          *conf_file;
    char          *keyring;
    char          *key_prefix;
    unsigned       connected:1;
#if defined(BRIX_HAVE_RADOSSTRIPER)
    rados_striper_t striper;        /* lazily created, shared across this export */
    unsigned        striper_ready:1;
#endif
    /* Per-(ceph_user, ceph_keyring) connection cache (ceph-peruser item): a
     * cred-scoped open re-authenticates as the requesting user instead of the
     * export's static service credential. Bounded LRU so a many-user
     * credential directory cannot leak unbounded rados_t handles. */
    sd_ceph_cred_conn_ent_t cred_conns[SD_CEPH_CRED_CONN_CACHE_MAX];
    ngx_uint_t               cred_conn_count;
    uint64_t                 cred_conn_lru_clock;
} sd_ceph_state_t;

/* Driver-private per-open state (obj->state): the object id + a cached size.
 * `striped` is set when the object is stored in the stock-XrdCeph libradosstriper
 * layout and must be read back through the striper to reassemble its bytes.
 * `ioctx` is the connection this OPEN was resolved against — the export's
 * static service ioctx for a plain open, or a per-user cred-conn's ioctx for
 * a cred-scoped open (ceph-peruser item). All raw byte ops (pread/pwrite/
 * ftruncate/fstat) MUST use this field rather than reaching back through
 * obj->inst->state->ioctx, or a per-user open would silently operate under
 * the service account after the initial open — defeating the credential
 * scoping the whole feature exists to provide.
 * `conn` is NON-NULL only for a cred-scoped open: it is the pinned
 * sd_ceph_conn_t this object's `ioctx` was drawn from (sd_ceph_conn_pin at
 * open, sd_ceph_conn_unpin at close). This is the fix for the cred-conn UAF
 * — as long as `conn` is non-NULL and pinned, the LRU cache can never
 * destroy the underlying rados_t/ioctx while this handle is still open,
 * no matter how many other (user,keyring) opens run concurrently. A plain
 * (service-credential) open leaves `conn` NULL: the export's own ioctx is
 * instance-lived (destroyed only at sd_ceph_cleanup, never LRU-evicted) and
 * needs no pin. */
typedef struct {
    char             oid[1024];
    uint64_t         size;
    rados_ioctx_t    ioctx;
    sd_ceph_conn_t  *conn;
    unsigned         for_write:1;
    unsigned         striped:1;
} sd_ceph_obj_state_t;

/* sd_ceph_open_req_t — bundled inputs for one object open (plain or
 * cred-scoped). Collapsing the seven separate open parameters into a single
 * request record keeps sd_ceph_open_on_ioctx and its extracted probe/apply
 * helpers within the parameter budget and lets each helper take the whole
 * request by const pointer instead of re-threading the individual fields.
 *   - st        : export state (key_prefix + shared striper cache)
 *   - ioctx     : the connection (service or per-user) rados_* calls run on
 *   - pin_conn  : non-NULL only for a cred-scoped open (pinned on success)
 *   - path      : the logical path to resolve to an object id
 *   - sd_flags  : BRIX_SD_O_* open intent (create/excl/trunc/write)
 *   - mode      : POSIX mode (unused by RADOS; carried for signature parity) */
typedef struct {
    brix_sd_instance_t *inst;
    sd_ceph_state_t    *st;
    rados_ioctx_t       ioctx;
    sd_ceph_conn_t     *pin_conn;
    const char         *path;
    int                 sd_flags;
    mode_t              mode;
} sd_ceph_open_req_t;

/* ---- cross-TU driver-private helpers ------------------------------------- */

/* sd_ceph_set_errno / sd_ceph_cluster_connect — defined in sd_ceph.c, shared by
 * the byte-I/O, object and cred TUs. */
int sd_ceph_set_errno(int rc);
int sd_ceph_cluster_connect(const char *conf_file, const char *user,
        const char *keyring, const char *pool,
        rados_t *cluster_out, rados_ioctx_t *ioctx_out);

#if defined(BRIX_HAVE_RADOSSTRIPER)
/* sd_ceph_striper — defined in sd_ceph_io.c, used by the object open probe. */
rados_striper_t sd_ceph_striper(sd_ceph_state_t *st);
#endif

/* sd_ceph_fill_stat — defined in sd_ceph_io.c, used by fstat and by the
 * path-level stat in sd_ceph_object.c. */
void sd_ceph_fill_stat(const char *oid, uint64_t size, time_t mtime,
        brix_sd_stat_t *out);

/* sd_ceph_conn_pin / _unpin — defined in sd_ceph_io.c beside the shared
 * connection layer, used by the object open/close path in sd_ceph_object.c. */
void sd_ceph_conn_pin(sd_ceph_conn_t *c);
void sd_ceph_conn_unpin(sd_ceph_conn_t *c);

/* sd_ceph_open_on_ioctx — defined in sd_ceph_object.c, used by the plain open
 * there and by the cred-scoped open in sd_ceph_cred.c. */
brix_sd_obj_t *sd_ceph_open_on_ioctx(const sd_ceph_open_req_t *req, int *err_out);

/* ---- vtable op functions (defined in the sibling TUs, wired into
 * brix_sd_ceph_driver in sd_ceph.c) -------------------------------------- */

/* byte I/O + staged write (sd_ceph_io.c) */
brix_sd_obj_t *sd_ceph_open(brix_sd_instance_t *inst, const char *path,
        int sd_flags, mode_t mode, int *err_out);
ngx_int_t sd_ceph_close(brix_sd_obj_t *obj);
ssize_t sd_ceph_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off);
ssize_t sd_ceph_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len,
        off_t off);
ssize_t sd_ceph_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
        off_t off);
ssize_t sd_ceph_preadv2(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
        off_t off, int flags);
ngx_fd_t sd_ceph_read_sendfile_fd(brix_sd_obj_t *obj, off_t off, size_t len,
        unsigned want_zerocopy);
ngx_int_t sd_ceph_ftruncate(brix_sd_obj_t *obj, off_t len);
ngx_int_t sd_ceph_fsync(brix_sd_obj_t *obj);
ngx_int_t sd_ceph_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out);
brix_sd_staged_t *sd_ceph_staged_open(brix_sd_instance_t *inst,
        const char *final_path, mode_t mode, int *err_out);
ssize_t sd_ceph_staged_write(brix_sd_staged_t *sh, const void *buf, size_t len,
        off_t off);
ngx_int_t sd_ceph_staged_commit(brix_sd_staged_t *sh, int noreplace);
void sd_ceph_staged_abort(brix_sd_staged_t *sh);

/* directory iteration — stripe-collapse listing (sd_ceph_dir.c, phase-89 §B.1) */
brix_sd_dir_t *sd_ceph_opendir(brix_sd_instance_t *inst, const char *path,
        int *err_out);
ngx_int_t sd_ceph_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out);
ngx_int_t sd_ceph_closedir(brix_sd_dir_t *d);

/* object lifecycle + xattr (sd_ceph_object.c) */
ngx_int_t sd_ceph_stat(brix_sd_instance_t *inst, const char *path,
        brix_sd_stat_t *out);
ngx_int_t sd_ceph_unlink(brix_sd_instance_t *inst, const char *path, int is_dir);
ngx_int_t sd_ceph_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode);
ngx_int_t sd_ceph_rename(brix_sd_instance_t *inst, const char *src,
        const char *dst, int noreplace);
ssize_t sd_ceph_getxattr(brix_sd_instance_t *inst, const char *path,
        const char *name, void *buf, size_t cap);
ssize_t sd_ceph_listxattr(brix_sd_instance_t *inst, const char *path,
        void *buf, size_t cap);
ngx_int_t sd_ceph_setxattr(brix_sd_instance_t *inst, const char *path,
        const char *name, const void *val, size_t len, int flags);
ngx_int_t sd_ceph_removexattr(brix_sd_instance_t *inst, const char *path,
        const char *name);

/* cred-scoped open + catalog enumeration (sd_ceph_cred.c) */
brix_sd_obj_t *sd_ceph_open_cred(brix_sd_instance_t *inst, const char *path,
        int sd_flags, mode_t mode, const brix_sd_cred_t *cred, int *err_out);
ngx_int_t sd_ceph_enumerate(brix_sd_instance_t *inst, int want_stat,
        brix_sd_catalog_cb cb, void *ctx);

#endif /* BRIX_HAVE_CEPH */

#endif /* BRIX_SD_CEPH_INTERNAL_H */
