/*
 * sd_ceph.c — Ceph/RADOS Storage Driver (phase-60, basic librados backend).
 *
 * WHAT: brix_sd_ceph_driver — a backend that maps the VFS's logical paths onto
 *       flat RADOS objects via raw librados (rados_read/write/trunc/stat/remove).
 *       Two layers live here:
 *         1. The pure LFN->object-key map (sd_ceph_normalize/_key/_ino) — libc
 *            only, always compiled, unit-tested standalone (sd_ceph_unittest.c).
 *         2. The driver vtable — only when the build found librados
 *            (BRIX_HAVE_CEPH); otherwise this file is just the pure helpers and
 *            the build is byte-for-byte unchanged (the driver row in
 *            sd_registry.c is #if-guarded too).
 *
 * WHY:  RADOS has no kernel fd, no sendfile, no directory tree and no atomic
 *       rename, so this driver advertises only range-read / random-write /
 *       truncate (see .caps). The VFS already serves a no-CAP_FD backend memory-
 *       backed and degrades the absent namespace/rename/xattr ops — the data
 *       plane (root:// read/write, WebDAV/S3 GET/PUT) rides the same VFS seam as
 *       POSIX once the handle path is de-fd'd (phase-60 W0).
 *
 * HOW:  One rados_t + ioctx per export instance, connected at init() on the event
 *       loop (worker init); the blocking rados_* calls are meant to run on the
 *       nginx thread pool (phase-60 §8 / ADR-4). Object handles carry the object
 *       id + a cached size; the raw byte ops are worker-safe (no pool/log/metrics).
 *       libradosstriper (large-object striping + stock XrdCeph on-disk interop,
 *       ADR-3) is a deliberate follow-on; this basic backend uses raw librados.
 *       Per-user credential scoping (ceph-peruser item): the driver also
 *       implements .open_cred (sd_ceph_open_cred), which authenticates to
 *       RADOS as a specific CephX user (parsed from a <key>.keyring file by
 *       fs/backend/ucred.c) instead of the export's static service
 *       credential. A bounded per-(user,keyring) connection-cache LRU on the
 *       instance state amortizes the rados_connect cost across repeated
 *       opens by the same user; every raw byte op (pread/pwrite/ftruncate/
 *       fstat) is keyed off the OPEN object's own ioctx (sd_ceph_obj_state_t.
 *       ioctx), not the export's, so a cred-scoped open stays scoped to that
 *       user for its whole lifetime.
 *
 *       Cred-conn lifetime (pin/refcount, fixes a UAF): a cred-scoped
 *       sd_ceph_conn_t is reference-counted (sd_ceph_conn_t.refs), pinned by
 *       every open object that resolved onto it (sd_ceph_obj_state_t.conn)
 *       and released in sd_ceph_close. The bounded LRU never destroys a
 *       pinned (refs>0) connection: eviction skips pinned slots, and if a
 *       pinned slot is chosen to make room in the cache table it is marked
 *       `doomed` and removed from the table WITHOUT destroying the
 *       connection — the connection is destroyed by whichever sd_ceph_close
 *       drops its refcount to zero. If every cache slot is pinned, a fresh
 *       *uncached* connection is created for that one open (never inserted
 *       into the table, pinned for the object's lifetime, destroyed on
 *       close) so a legitimate concurrent identity beyond the cache bound
 *       still works instead of failing the open.
 */
#include "sd_ceph.h"
#include "sd_ceph_compat.h"   /* pure striper-layout helpers (catalog enumeration) */

#include <errno.h>
#include <string.h>

/* ===================================================================== *
 * Pure LFN -> object-key mapping (always compiled; no librados, no nginx) *
 * ===================================================================== */

/* sd_ceph_seg_t — one path segment carved out of an LFN during normalization:
 * the pointer into the source string and its length (not NUL-terminated). */
typedef struct {
    const char *start;
    size_t      len;
} sd_ceph_seg_t;

/* sd_ceph_next_seg — advance a cursor to the next non-empty path segment.
 *
 * WHAT: From `*cursor`, skip the run of '/' separators, then capture the next
 *       run of non-'/' bytes into `*seg`. Returns 1 when a segment was found
 *       (and advances `*cursor` past it), or 0 at end of string.
 *
 * WHY:  Isolates the pointer-walking tokenizer from the segment-classification
 *       logic in sd_ceph_normalize, so that function reads as a flat loop over
 *       already-carved segments instead of interleaving scan and decision.
 *
 * HOW:  1. Skip leading '/' separators. 2. If at end, report no segment.
 *       3. Mark the segment start, walk to the next '/' or NUL, record the
 *          length, and leave the cursor at the delimiter. */
static int
sd_ceph_next_seg(const char **cursor, sd_ceph_seg_t *seg)
{
    const char *p = *cursor;

    while (*p == '/') {               /* skip run of slashes */
        p++;
    }
    if (*p == '\0') {
        *cursor = p;
        return 0;
    }

    seg->start = p;
    while (*p != '\0' && *p != '/') {
        p++;
    }
    seg->len = (size_t) (p - seg->start);
    *cursor  = p;
    return 1;
}

/* sd_ceph_norm_pop — remove the last component from the canonical buffer for a
 * ".." segment. Returns the new write cursor, or (size_t)-1 for an escape above
 * the root (nothing to pop) so the caller can fail the normalization. */
static size_t
sd_ceph_norm_pop(char *out, size_t w)
{
    if (w == 0) {
        return (size_t) -1;           /* escape above the root */
    }
    while (w > 0 && out[w - 1] != '/') {
        w--;                          /* back over the last component */
    }
    if (w > 0) {
        w--;                          /* drop its leading '/' */
    }
    out[w] = '\0';
    return w;
}

/* sd_ceph_norm_append — append one ordinary segment (as "/<seg>") to the
 * canonical buffer at write cursor `w`. Returns the new cursor, or (size_t)-1
 * when the segment would not fit within `cap` (caller sets ENAMETOOLONG). */
static size_t
sd_ceph_norm_append(char *out, size_t cap, size_t w, const sd_ceph_seg_t *seg)
{
    if (w + 1 + seg->len + 1 > cap) {
        return (size_t) -1;
    }
    out[w++] = '/';
    memcpy(out + w, seg->start, seg->len);
    w += seg->len;
    out[w] = '\0';
    return w;
}

/* sd_ceph_seg_is_dot / sd_ceph_seg_is_dotdot — classify a carved segment as the
 * "." (self) or ".." (parent) special components. */
static int
sd_ceph_seg_is_dot(const sd_ceph_seg_t *seg)
{
    return seg->len == 1 && seg->start[0] == '.';
}

static int
sd_ceph_seg_is_dotdot(const sd_ceph_seg_t *seg)
{
    return seg->len == 2 && seg->start[0] == '.' && seg->start[1] == '.';
}

/* sd_ceph_normalize — see sd_ceph.h. Builds the canonical path in `out` by
 * walking segments: skip empties and ".", pop on "..", append otherwise. A ".."
 * with nothing to pop is an escape above the root and is rejected. */
int
sd_ceph_normalize(const char *lfn, char *out, size_t cap)
{
    const char   *cursor = lfn;
    sd_ceph_seg_t seg = {0};
    size_t        w = 0;

    if (lfn == NULL || out == NULL || cap < 2) {
        errno = EINVAL;
        return -1;
    }
    out[0] = '\0';

    while (sd_ceph_next_seg(&cursor, &seg)) {
        if (sd_ceph_seg_is_dot(&seg)) {
            continue;                 /* "." — no-op */
        }
        if (sd_ceph_seg_is_dotdot(&seg)) {
            w = sd_ceph_norm_pop(out, w);
            if (w == (size_t) -1) {
                errno = EINVAL;       /* escape above the root */
                return -1;
            }
            continue;
        }
        w = sd_ceph_norm_append(out, cap, w, &seg);
        if (w == (size_t) -1) {
            errno = ENAMETOOLONG;
            return -1;
        }
    }

    if (w == 0) {                     /* everything collapsed -> bare root */
        out[0] = '/';
        out[1] = '\0';
    }
    return 0;
}

/* sd_ceph_key — prefix + sd_ceph_normalize(lfn). See sd_ceph.h. */
int
sd_ceph_key(const char *key_prefix, const char *lfn, char *out, size_t cap)
{
    char   norm[1024];
    size_t plen = (key_prefix != NULL) ? strlen(key_prefix) : 0;
    size_t nlen;

    if (sd_ceph_normalize(lfn, norm, sizeof(norm)) != 0) {
        return -1;
    }
    nlen = strlen(norm);

    if (plen + nlen + 1 > cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (plen > 0) {
        /* phase74-fp: prefix copy is intentionally unterminated — the next
         * memcpy appends norm with its NUL (nlen + 1), and the cap check above
         * guarantees room for plen + nlen + 1. */
        memcpy(out, key_prefix, plen);  /* NOLINT(bugprone-not-null-terminated-result) */
    }
    memcpy(out + plen, norm, nlen + 1);
    return 0;
}

/* sd_ceph_ino — FNV-1a/64 over the object id. See sd_ceph.h. */
uint64_t
sd_ceph_ino(const char *oid)
{
    const unsigned char *p = (const unsigned char *) oid;
    uint64_t             h = 1469598103934665603ULL;   /* FNV offset basis */

    while (*p != '\0') {
        h ^= (uint64_t) *p++;
        h *= 1099511628211ULL;                          /* FNV prime */
    }
    return h;
}

/* ===================================================================== *
 * librados driver (only when the build found librados)                   *
 * ===================================================================== */
#if BRIX_HAVE_CEPH

#include <rados/librados.h>
#include "sd_ceph_striper.h"   /* libradosstriper read path (stock XrdCeph layout) */
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

/* Driver-private staged-write state (staged->state): the final object id. RADOS
 * has no atomic rename, so — like the root:// write path — the staged target IS
 * the final object (trunc-on-open, write in place, commit is a no-op). */
typedef struct {
    char oid[1024];
} sd_ceph_staged_t;

/* sd_ceph_pstrdup — copy a C string onto the instance pool (NULL-safe source
 * yields NULL). Keeps the driver's retained strings on the export-lifetime pool. */
static char *
sd_ceph_pstrdup(ngx_pool_t *pool, const char *s)
{
    size_t  n;
    char   *d;

    if (s == NULL) {
        return NULL;
    }
    n = strlen(s) + 1;
    d = ngx_pnalloc(pool, n);
    if (d != NULL) {
        memcpy(d, s, n);
    }
    return d;
}

/* sd_ceph_set_errno — librados returns 0/negative-errno; translate a negative rc
 * into errno and the driver's failure code, returning 1 iff rc indicated error. */
static int
sd_ceph_set_errno(int rc)
{
    if (rc < 0) {
        errno = -rc;
        return 1;
    }
    return 0;
}

/* worker-safe raw byte I/O (no pool/log/metrics) */

#if defined(BRIX_HAVE_RADOSSTRIPER)
/* Lazily create (once per export) the libradosstriper handle bound to this
 * instance's ioctx, so reads of stock-XrdCeph striped objects reassemble the file
 * byte-for-byte. NULL on failure (the caller falls back to a raw read). */
static rados_striper_t
sd_ceph_striper(sd_ceph_state_t *st)
{
    if (!st->striper_ready) {
        if (sd_ceph_striper_create(st->ioctx, NULL, &st->striper) != 0) {
            return NULL;
        }
        st->striper_ready = 1;
    }
    return st->striper;
}

#endif /* BRIX_HAVE_RADOSSTRIPER */

/* sd_ceph_pread — read at off from the object. A striper-format object (stock
 * XrdCeph) is read through libradosstriper so its bytes reassemble exactly;
 * everything else is a flat rados_read. Returns bytes read (>=0, 0 = at/after
 * EOF) or -1 with errno. The VFS owns the EINTR/short-read loop (vfs_core). */
static ssize_t
sd_ceph_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_ceph_obj_state_t *os = obj->state;
    int                  rc;

#if defined(BRIX_HAVE_RADOSSTRIPER)
    if (os->striped) {
        sd_ceph_state_t *st = obj->inst->state;
        rados_striper_t   s = sd_ceph_striper(st);
        ssize_t         n;

        if (s == NULL) {
            errno = EIO;
            return -1;
        }
        n = sd_ceph_striper_read(s, os->oid, buf, len, (uint64_t) off);
        if (n < 0) {
            errno = (int) -n;
            return -1;
        }
        return n;
    }
#endif

    rc = rados_read(os->ioctx, os->oid, buf, len, (uint64_t) off);
    if (rc < 0) {
        errno = -rc;
        return -1;
    }
    return (ssize_t) rc;
}

/* sd_ceph_pwrite — one rados_write at off; returns len on success or -1. Bumps
 * the cached object size so a subsequent fstat reflects in-flight writes. */
static ssize_t
sd_ceph_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    sd_ceph_obj_state_t *os = obj->state;
    int                  rc;

    rc = rados_write(os->ioctx, os->oid, buf, len, (uint64_t) off);
    if (sd_ceph_set_errno(rc)) {
        return -1;
    }
    if ((uint64_t) off + len > os->size) {
        os->size = (uint64_t) off + len;
    }
    return (ssize_t) len;
}

/* sd_ceph_preadv — vectored read as a loop of sd_ceph_pread (RADOS has no native
 * preadv); stops at the first short/EOF segment. Bytes read or -1. */
static ssize_t
sd_ceph_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    ssize_t total = 0;
    int     i;

    for (i = 0; i < iovcnt; i++) {
        ssize_t n = sd_ceph_pread(obj, iov[i].iov_base, iov[i].iov_len,
                                  off + total);
        if (n < 0) {
            return -1;
        }
        total += n;
        if ((size_t) n < iov[i].iov_len) {
            break;                    /* short read / EOF */
        }
    }
    return total;
}

/* sd_ceph_preadv2 — RADOS has no per-read flags (e.g. RWF_NOWAIT); ignore them
 * and serve via the plain vectored read. */
static ssize_t
sd_ceph_preadv2(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off, int flags)
{
    (void) flags;
    return sd_ceph_preadv(obj, iov, iovcnt, off);
}

/* sd_ceph_read_sendfile_fd — RADOS exposes no kernel fd, so reads are always
 * served memory-backed; signal that to the VFS with NGX_INVALID_FILE. */
static ngx_fd_t
sd_ceph_read_sendfile_fd(brix_sd_obj_t *obj, off_t off, size_t len,
    unsigned want_zerocopy)
{
    (void) obj; (void) off; (void) len; (void) want_zerocopy;
    return NGX_INVALID_FILE;
}

/* sd_ceph_ftruncate — rados_trunc to len; updates the cached size. */
static ngx_int_t
sd_ceph_ftruncate(brix_sd_obj_t *obj, off_t len)
{
    sd_ceph_obj_state_t *os = obj->state;

    if (sd_ceph_set_errno(rados_trunc(os->ioctx, os->oid, (uint64_t) len))) {
        return NGX_ERROR;
    }
    os->size = (uint64_t) len;
    return NGX_OK;
}

/* sd_ceph_fsync — a synchronous rados_write is durably acked on return, so there
 * is nothing to flush; succeed. (aio flush belongs to the async follow-on.) */
static ngx_int_t
sd_ceph_fsync(brix_sd_obj_t *obj)
{
    (void) obj;
    return NGX_OK;
}

/* sd_ceph_fill_stat — shape a RADOS (size, mtime) pair into the neutral stat the
 * VFS consumes: a regular object, mode 0644, a stable synthesized inode. */
static void
sd_ceph_fill_stat(const char *oid, uint64_t size, time_t mtime,
    brix_sd_stat_t *out)
{
    ngx_memzero(out, sizeof(*out));
    out->size   = (off_t) size;
    out->mtime  = mtime;
    out->ctime  = mtime;
    out->mode   = 0100644;            /* S_IFREG | 0644 */
    out->ino    = (ino_t) sd_ceph_ino(oid);
    out->is_reg = 1;
}

/* sd_ceph_fstat — rados_stat on the open object's id. */
static ngx_int_t
sd_ceph_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    sd_ceph_obj_state_t *os = obj->state;
    uint64_t             size = 0;
    time_t               mtime = 0;

    if (sd_ceph_set_errno(rados_stat(os->ioctx, os->oid, &size, &mtime))) {
        return NGX_ERROR;
    }
    sd_ceph_fill_stat(os->oid, size, mtime, out);
    return NGX_OK;
}

/* object lifecycle */

/* Forward declarations: sd_ceph_conn_t's pin/unpin (definitions live with the
 * rest of the shared oid-level connection layer, further down this file,
 * beside sd_ceph_conn_create/_destroy/_ioctx) are needed here by
 * sd_ceph_open_on_ioctx (pins on a successful cred-scoped open) and
 * sd_ceph_close (unpins on close) — both defined before that section. */
static void sd_ceph_conn_pin(sd_ceph_conn_t *c);
static void sd_ceph_conn_unpin(sd_ceph_conn_t *c);

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

/* sd_ceph_probe — result of probing an object's existence at open time:
 * whether it exists (`present`), its size/mtime if so, and whether it is a
 * stock-XrdCeph striper object (so pread reassembles via libradosstriper). */
typedef struct {
    int      present;
    int      striped;
    uint64_t size;
    time_t   mtime;
} sd_ceph_probe_t;

/* sd_ceph_probe_object — establish whether the object already exists.
 *
 * WHAT: Fills `pr` from a stat probe. On a read open it first consults the
 *       stock-XrdCeph striper view (marking `striped` when a striped object of
 *       that name exists); otherwise, or on a miss, it falls back to a flat
 *       rados_stat. Returns 0 on success (object present or cleanly absent) or
 *       a negative errno for a hard stat error the caller must surface.
 *
 * WHY:  The existence probe is the branchiest part of the open path; isolating
 *       it lets the orchestrator apply create/excl/trunc intent as a flat
 *       sequence instead of interleaving I/O with policy.
 *
 * HOW:  1. Zero the result. 2. For a non-write open, try the shared striper
 *          stat; a hit sets present+striped. 3. Otherwise flat rados_stat:
 *          0 → present; -ENOENT → cleanly absent; any other negative → error. */
static int
sd_ceph_probe_object(const sd_ceph_open_req_t *req, const char *oid,
    sd_ceph_probe_t *pr)
{
    int rc = -ENOENT;

    ngx_memzero(pr, sizeof(*pr));

#if defined(BRIX_HAVE_RADOSSTRIPER)
    /* On a read open, prefer the stock-XrdCeph striper view: if a striped object
     * exists for this name, mark it so pread reassembles via libradosstriper.
     * The striper handle is bound to the EXPORT's service ioctx (lazily created
     * on `st`, shared across users) — a per-user cred-scoped open still reads
     * striped objects through it; only the raw rados_read/write/stat/trunc calls
     * use the per-user `ioctx`. */
    if (!(req->sd_flags & BRIX_SD_O_WRITE)) {
        rados_striper_t s = sd_ceph_striper(req->st);
        if (s != NULL
            && sd_ceph_striper_stat(s, oid, &pr->size, &pr->mtime) == 0)
        {
            pr->present = 1;
            pr->striped = 1;
            return 0;
        }
    }
#endif
    rc = rados_stat(req->ioctx, oid, &pr->size, &pr->mtime);
    if (rc == 0) {
        pr->present = 1;
        return 0;
    }
    if (rc == -ENOENT) {
        return 0;                     /* cleanly absent */
    }
    return rc;                        /* hard stat error */
}

/* sd_ceph_apply_intent — enforce create/excl/trunc open flags against the
 * probe result. Returns 0 if the open may proceed, or a positive errno the
 * caller surfaces (ENOENT for absent-without-create, EEXIST for excl-collision,
 * or a truncate failure). On a successful truncate the probe size is reset. */
static int
sd_ceph_apply_intent(const sd_ceph_open_req_t *req, const char *oid,
    sd_ceph_probe_t *pr)
{
    if (!pr->present && !(req->sd_flags & BRIX_SD_O_CREATE)) {
        return ENOENT;
    }
    if (pr->present && (req->sd_flags & BRIX_SD_O_EXCL)) {
        return EEXIST;
    }
    if (req->sd_flags & BRIX_SD_O_TRUNC) {
        if (sd_ceph_set_errno(rados_trunc(req->ioctx, oid, 0))) {
            return errno;
        }
        pr->size = 0;
    }
    return 0;
}

/* sd_ceph_obj_build — allocate and populate the open object + its driver state
 * from a completed probe. Pins a cred-scoped connection (req->pin_conn) so the
 * cred-conn LRU cannot free its ioctx while the handle is open (the UAF fix).
 * Returns the handle, or NULL with *err_out on allocation failure. */
static brix_sd_obj_t *
sd_ceph_obj_build(const sd_ceph_open_req_t *req, const char *oid,
    const sd_ceph_probe_t *pr, int *err_out)
{
    brix_sd_obj_t       *obj;
    sd_ceph_obj_state_t *os;

    obj = ngx_pcalloc(req->inst->pool, sizeof(*obj));
    os  = ngx_pcalloc(req->inst->pool, sizeof(*os));
    if (obj == NULL || os == NULL) {
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    memcpy(os->oid, oid, strlen(oid) + 1);
    os->size      = pr->present ? pr->size : 0;
    os->striped   = pr->striped;
    os->ioctx     = req->ioctx;
    os->conn      = req->pin_conn;
    os->for_write = (req->sd_flags & BRIX_SD_O_WRITE) ? 1 : 0;
    obj->driver   = req->inst->driver;
    obj->inst     = req->inst;
    obj->fd       = NGX_INVALID_FILE;
    obj->state    = os;

    if (req->pin_conn != NULL) {
        sd_ceph_conn_pin(req->pin_conn);   /* UAF fix: keep alive until close() */
    }

    /* Populate the metadata snapshot the caller copies into its handle and uses
     * to build the open reply (open_resolved_file.c). RADOS has no fd/inode, so
     * synthesize a stable inode from the object id and present a regular file. */
    obj->snap.size   = (off_t) os->size;
    obj->snap.mtime  = pr->mtime;
    obj->snap.ctime  = pr->mtime;
    obj->snap.mode   = S_IFREG | 0644;
    obj->snap.ino    = (ino_t) sd_ceph_ino(os->oid);
    obj->snap.is_reg = 1;
    return obj;
}

/* sd_ceph_open_on_ioctx — shared body for plain and cred-scoped opens: resolve
 * the LFN to an object id against the SUPPLIED ioctx, honour create/excl/trunc
 * intent against a stat probe, and return a handle carrying the id + cached
 * size. There is no fd: obj->fd stays NGX_INVALID_FILE (the VFS serves such
 * handles memory-backed).
 *
 * WHAT: Resolves `req->path` to an object id, probes its existence, applies the
 *       open intent, and builds the handle. Returns the object, or NULL with
 *       *err_out set on any failure.
 * WHY:  A cred-scoped open (sd_ceph_open_cred) must issue every rados_* /
 *       striper call against the PER-USER connection's ioctx, not the
 *       export's static service ioctx — otherwise the "per-user" open would
 *       silently authenticate as the service account, defeating the whole
 *       point of the ceph-peruser credential kind. Factoring the object-open
 *       body into one function (fed a bundled request) keeps the plain and
 *       cred-scoped paths from diverging in error handling or metadata.
 * HOW:  1. Map the logical path to an object id (sd_ceph_key). 2. Probe
 *          existence (sd_ceph_probe_object). 3. Enforce create/excl/trunc
 *          (sd_ceph_apply_intent). 4. Allocate + populate the handle, pinning
 *          req->pin_conn for a cred-scoped open (sd_ceph_obj_build). On any
 *          failure path nothing is pinned (the caller still owns releasing
 *          req->pin_conn itself, e.g. sd_ceph_open_cred's pin bookkeeping). */
static brix_sd_obj_t *
sd_ceph_open_on_ioctx(const sd_ceph_open_req_t *req, int *err_out)
{
    char            oid[1024];
    sd_ceph_probe_t pr = {0};
    int             rc;
    int             intent_err;

    (void) req->mode;

    if (sd_ceph_key(req->st->key_prefix, req->path, oid, sizeof(oid)) != 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    rc = sd_ceph_probe_object(req, oid, &pr);
    if (rc < 0) {
        if (err_out != NULL) { *err_out = -rc; }
        return NULL;
    }

    intent_err = sd_ceph_apply_intent(req, oid, &pr);
    if (intent_err != 0) {
        if (err_out != NULL) { *err_out = intent_err; }
        return NULL;
    }

    return sd_ceph_obj_build(req, oid, &pr, err_out);
}

/* sd_ceph_open — vtable open slot: service credential.
 *
 * WHAT: Plain open for callers that do not carry a per-user credential.
 * WHY:  Preserves the existing public vtable signature; uses the export's
 *       static service ioctx (inst->state->ioctx).
 * HOW:  Delegates to sd_ceph_open_on_ioctx with the instance's own ioctx. */
static brix_sd_obj_t *
sd_ceph_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_ceph_state_t   *st = inst->state;
    sd_ceph_open_req_t req = {
        .inst     = inst,
        .st       = st,
        .ioctx    = st->ioctx,
        .pin_conn = NULL,
        .path     = path,
        .sd_flags = sd_flags,
        .mode     = mode,
    };

    return sd_ceph_open_on_ioctx(&req, err_out);
}

/* sd_ceph_close — release this handle's pin (if any) on its cred-scoped
 * connection. A plain (service-credential) open has os->conn == NULL — the
 * export's own ioctx is instance-lived and is torn down only by
 * sd_ceph_cleanup, so there is nothing to release. A cred-scoped open's
 * os->conn is non-NULL: sd_ceph_conn_unpin drops the pin taken at open, and
 * if this was the connection's last pin AND it had already been evicted
 * from the cred-conn cache table (doomed) while still in use, the deferred
 * rados_ioctx_destroy/rados_shutdown happens right here — this is the fix
 * for the historical UAF (the connection used to be destroyed by the LRU
 * evictor regardless of whether a handle was still reading/writing through
 * it). Idempotent-safe: the VFS never calls close twice on the same handle,
 * but sd_ceph_conn_unpin tolerates refs already at 0. */
static ngx_int_t
sd_ceph_close(brix_sd_obj_t *obj)
{
    sd_ceph_obj_state_t *os = obj->state;

    if (os->conn != NULL) {
        sd_ceph_conn_unpin(os->conn);
        os->conn = NULL;
    }
    return NGX_OK;
}

/* namespace (logical paths) */

/* sd_ceph_stat — rados_stat on the object id for a logical path. */
static ngx_int_t
sd_ceph_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
{
    sd_ceph_state_t *st = inst->state;
    char             oid[1024];
    uint64_t         size = 0;
    time_t           mtime = 0;

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return NGX_ERROR;
    }
    if (sd_ceph_set_errno(rados_stat(st->ioctx, oid, &size, &mtime))) {
        return NGX_ERROR;
    }
    sd_ceph_fill_stat(oid, size, mtime, out);
    return NGX_OK;
}

/* sd_ceph_unlink — remove the object for a logical path. There are no real
 * directories in this basic backend, so is_dir is advisory only. */
static ngx_int_t
sd_ceph_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    sd_ceph_state_t *st = inst->state;
    char             oid[1024];

    (void) is_dir;

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return NGX_ERROR;
    }
    if (sd_ceph_set_errno(rados_remove(st->ioctx, oid))) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* xattr / object metadata — RADOS objects carry their own xattrs, so the
 * checksum-at-rest seam (user.XrdCks.*) and protocol GETFATTR/SETFATTR work on a
 * Ceph export exactly as on POSIX. All four key the object id off the logical
 * path; the object must already exist (set/get/list/remove on a missing oid
 * return -ENOENT via librados). */

/* Bound on a single xattr value we buffer for the size-probe path. */
#define SD_CEPH_XATTR_MAX (64u * 1024)

static ssize_t
sd_ceph_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap)
{
    sd_ceph_state_t *st = inst->state;
    char             oid[1024];
    char             tmp[SD_CEPH_XATTR_MAX];
    int              n;

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return -1;
    }
    n = rados_getxattr(st->ioctx, oid, name, tmp, sizeof(tmp));
    if (n < 0) {
        errno = -n;
        return -1;
    }
    if (cap == 0) {
        return n;                  /* size probe (getxattr(2) convention) */
    }
    if ((size_t) n > cap) {
        errno = ERANGE;
        return -1;
    }
    memcpy(buf, tmp, (size_t) n);
    return n;
}

static ssize_t
sd_ceph_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap)
{
    sd_ceph_state_t    *st = inst->state;
    char                oid[1024];
    rados_xattrs_iter_t it;
    char               *out = buf;
    size_t              total = 0;

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return -1;
    }
    if (sd_ceph_set_errno(rados_getxattrs(st->ioctx, oid, &it))) {
        return -1;
    }
    for (;;) {
        const char *nm = NULL;
        const char *val = NULL;
        size_t      vlen = 0;
        size_t      nlen;

        if (sd_ceph_set_errno(rados_getxattrs_next(it, &nm, &val, &vlen))) {
            rados_getxattrs_end(it);
            return -1;
        }
        if (nm == NULL) {
            break;                 /* end of iteration */
        }
        nlen = strlen(nm) + 1;     /* listxattr(2): names are NUL-separated */
        if (cap != 0) {
            if (total + nlen > cap) {
                rados_getxattrs_end(it);
                errno = ERANGE;
                return -1;
            }
            memcpy(out + total, nm, nlen);
        }
        total += nlen;
    }
    rados_getxattrs_end(it);
    return (ssize_t) total;
}

static ngx_int_t
sd_ceph_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags)
{
    sd_ceph_state_t *st = inst->state;
    char             oid[1024];

    (void) flags;   /* RADOS has no XATTR_CREATE/REPLACE; a plain set is applied */

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return NGX_ERROR;
    }
    if (sd_ceph_set_errno(rados_setxattr(st->ioctx, oid, name, val, len))) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
sd_ceph_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    sd_ceph_state_t *st = inst->state;
    char             oid[1024];

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return NGX_ERROR;
    }
    if (sd_ceph_set_errno(rados_rmxattr(st->ioctx, oid, name))) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* staged/atomic write — WebDAV PUT and other staged-upload paths.
 *
 * RADOS has no atomic rename, so (matching the root:// write path, which writes
 * straight to the final object) the staged target IS the final object: trunc it
 * to zero at open, write in place, commit is a no-op, abort removes it. A
 * temp-object + server-side copy-on-commit would add true atomicity at O(size)
 * cost; that is a follow-on, not needed for basic PUT parity with root://. */
static brix_sd_staged_t *
sd_ceph_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    sd_ceph_state_t    *st = inst->state;
    brix_sd_staged_t *handle;
    sd_ceph_staged_t   *ps;

    (void) mode;

    handle = ngx_pcalloc(inst->pool, sizeof(*handle));
    ps     = ngx_pcalloc(inst->pool, sizeof(*ps));
    if (handle == NULL || ps == NULL) {
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }
    if (sd_ceph_key(st->key_prefix, final_path, ps->oid, sizeof(ps->oid)) != 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }
    if (sd_ceph_set_errno(rados_trunc(st->ioctx, ps->oid, 0))) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }
    handle->inst  = inst;
    handle->state = ps;
    return handle;
}

static ssize_t
sd_ceph_staged_write(brix_sd_staged_t *sh, const void *buf, size_t len,
    off_t off)
{
    sd_ceph_state_t  *st = sh->inst->state;
    sd_ceph_staged_t *ps = sh->state;

    if (sd_ceph_set_errno(rados_write(st->ioctx, ps->oid, buf, len,
                                      (uint64_t) off)))
    {
        return -1;
    }
    return (ssize_t) len;
}

static ngx_int_t
sd_ceph_staged_commit(brix_sd_staged_t *sh, int noreplace)
{
    (void) sh;
    (void) noreplace;   /* the object is already written in place */
    return NGX_OK;
}

static void
sd_ceph_staged_abort(brix_sd_staged_t *sh)
{
    sd_ceph_state_t  *st = sh->inst->state;
    sd_ceph_staged_t *ps = sh->state;

    (void) rados_remove(st->ioctx, ps->oid);
}

/* instance lifecycle (event loop / worker init) */

/* sd_ceph_user_id — librados wants the entity id without the "client." prefix
 * (rados_create prepends "client."); a NULL id selects the default client.admin. */
static const char *
sd_ceph_user_id(const char *user)
{
    if (user != NULL && strncmp(user, "client.", 7) == 0) {
        return user + 7;
    }
    return user;
}

/* sd_ceph_cluster_connect — create + configure + connect a rados cluster handle
 * and open the pool ioctx. Shared by the flat driver's init and the oid-level
 * connection (sd_ceph_conn_create). 0 / -1 with errno; on failure nothing leaks. */
static int
sd_ceph_cluster_connect(const char *conf_file, const char *user,
    const char *keyring, const char *pool,
    rados_t *cluster_out, rados_ioctx_t *ioctx_out)
{
    rados_t       cluster;
    rados_ioctx_t ioctx;

    if (sd_ceph_set_errno(rados_create(&cluster, sd_ceph_user_id(user)))) {
        return -1;
    }
    if (sd_ceph_set_errno(rados_conf_read_file(cluster,
            conf_file ? conf_file : "/etc/ceph/ceph.conf")))
    {
        rados_shutdown(cluster);
        return -1;
    }
    if (keyring != NULL) {
        rados_conf_set(cluster, "keyring", keyring);
    }
    if (sd_ceph_set_errno(rados_connect(cluster))) {
        rados_shutdown(cluster);
        return -1;
    }
    if (sd_ceph_set_errno(rados_ioctx_create(cluster, pool, &ioctx))) {
        rados_shutdown(cluster);
        return -1;
    }
    *cluster_out = cluster;
    *ioctx_out   = ioctx;
    return 0;
}

/* sd_ceph_init — resolve config onto the pool, create + configure + connect the
 * cluster handle, and open the pool ioctx. Any failure tears down what was built
 * and returns NGX_ERROR with errno set so the export fails closed at init. */
static ngx_int_t
sd_ceph_init(brix_sd_instance_t *inst, void *driver_conf)
{
    brix_sd_ceph_conf_t *dc = driver_conf;
    sd_ceph_state_t       *st;

    if (dc == NULL || dc->pool == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    st = ngx_pcalloc(inst->pool, sizeof(*st));
    if (st == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    st->pool       = sd_ceph_pstrdup(inst->pool, dc->pool);
    st->user       = sd_ceph_pstrdup(inst->pool, dc->user);
    st->conf_file  = sd_ceph_pstrdup(inst->pool,
                         dc->conf_file ? dc->conf_file : "/etc/ceph/ceph.conf");
    st->keyring    = sd_ceph_pstrdup(inst->pool, dc->keyring);
    st->key_prefix = sd_ceph_pstrdup(inst->pool,
                         dc->key_prefix ? dc->key_prefix : "");
    inst->state = st;

    if (sd_ceph_cluster_connect(st->conf_file, st->user, st->keyring, st->pool,
                                &st->cluster, &st->ioctx) != 0)
    {
        return NGX_ERROR;
    }
    st->connected = 1;
    return NGX_OK;
}

/* sd_ceph_cleanup — destroy the ioctx and shut the cluster handle down (a kernel/
 * network resource that must not leak across reconfig); the pool reclaims state.
 * Also destroys every cached per-user cred connection (ceph-peruser item) — each
 * holds its own rados_t/ioctx that would otherwise leak across a reconfig/reload
 * just like the export's own cluster handle would.
 *
 * A connection in the cache table at cleanup time is expected to have
 * refs==0: instance teardown only runs once every request/handle on this
 * export has drained (the VFS/protocol layers close all handles before an
 * instance is torn down), so nothing should still be pinning a cached
 * connection here. If that invariant were ever violated (an object somehow
 * outliving its instance), destroying it anyway is still the right call —
 * the instance and its pool are going away regardless, so there is no
 * "later close()" left to do the deferred destroy — but it is flagged with
 * a WARN so the anomaly is visible rather than silently masked. */
static void
sd_ceph_cleanup(brix_sd_instance_t *inst)
{
    sd_ceph_state_t *st = inst->state;
    ngx_uint_t        i;

    if (st == NULL) {
        return;
    }

    for (i = 0; i < st->cred_conn_count; i++) {
        if (st->cred_conns[i].conn != NULL) {
#if !defined(XRDPROTO_NO_NGX)
            /* ngx_log_error/NGX_LOG_WARN are unavailable in the ngx-free
             * standalone build (tests/ceph/'s live-test drivers link this
             * file directly with -DXRDPROTO_NO_NGX); the anomaly this warns
             * about is a should-never-happen invariant violation, not
             * something the standalone driver tests need to observe. */
            if (st->cred_conns[i].conn->refs > 0 && inst->log != NULL) {
                ngx_log_error(NGX_LOG_WARN, inst->log, 0,
                    "sd_ceph_cleanup: cred connection for user \"%s\" still "
                    "had %ui open handle(s) pinned at instance teardown "
                    "(destroying anyway)",
                    st->cred_conns[i].user,
                    (ngx_uint_t) st->cred_conns[i].conn->refs);
            }
#endif
            sd_ceph_conn_destroy(st->cred_conns[i].conn);
            st->cred_conns[i].conn = NULL;
        }
    }
    st->cred_conn_count = 0;

    if (st->connected) {
#if defined(BRIX_HAVE_RADOSSTRIPER)
        if (st->striper_ready) {
            sd_ceph_striper_destroy(st->striper);
            st->striper_ready = 0;
        }
#endif
        rados_ioctx_destroy(st->ioctx);
        rados_shutdown(st->cluster);
        st->connected = 0;
    }
}

/* ---- shared oid-level layer (reused by cephfsro + recovery tools) --------- */

sd_ceph_conn_t *
sd_ceph_conn_create(const brix_sd_ceph_conf_t *conf, ngx_pool_t *pool, int *err)
{
    sd_ceph_conn_t *c;

    if (conf == NULL || conf->pool == NULL) {
        if (err != NULL) { *err = EINVAL; }
        return NULL;
    }
    c = ngx_pcalloc(pool, sizeof(*c));
    if (c == NULL) {
        if (err != NULL) { *err = ENOMEM; }
        return NULL;
    }
    c->pool = pool;
    if (sd_ceph_cluster_connect(conf->conf_file, conf->user, conf->keyring,
                                conf->pool, &c->cluster, &c->ioctx) != 0)
    {
        if (err != NULL) { *err = errno; }
        return NULL;
    }
    c->connected = 1;
    return c;
}

void
sd_ceph_conn_destroy(sd_ceph_conn_t *c)
{
    if (c != NULL && c->connected) {
        rados_ioctx_destroy(c->ioctx);
        rados_shutdown(c->cluster);
        c->connected = 0;
    }
}

rados_ioctx_t
sd_ceph_conn_ioctx(sd_ceph_conn_t *c)
{
    return c->ioctx;
}

/* sd_ceph_conn_pin — take one reference on a cred-scoped connection for an
 * open object that resolved onto it. Must be matched by exactly one
 * sd_ceph_conn_unpin (from sd_ceph_close) for the object's lifetime. */
static void
sd_ceph_conn_pin(sd_ceph_conn_t *c)
{
    c->refs++;
}

/* sd_ceph_conn_unpin — drop one reference. If the connection is `doomed`
 * (either evicted from the cred-conn cache table while still pinned, or a
 * transient all-slots-pinned connection that was never inserted into the
 * table at all — see sd_ceph_cred_conn) and this was the last pin (refs
 * reaches 0), complete the deferred destroy now — this is the ONLY place a
 * doomed connection is actually torn down, guaranteeing no pread/pwrite/
 * fstat on a still-open handle can ever run against a freed ioctx, AND
 * guaranteeing a transient connection's mon session/ioctx/fds are freed
 * exactly once instead of leaking. A non-doomed connection simply loses a
 * pin and stays live in the cache for reuse. */
static void
sd_ceph_conn_unpin(sd_ceph_conn_t *c)
{
    if (c == NULL) {
        return;
    }
    if (c->refs > 0) {
        c->refs--;
    }
    if (c->doomed && c->refs == 0) {
        sd_ceph_conn_destroy(c);
    }
}

/* ---- per-user cred-conn cache (ceph-peruser item) -------------------------
 *
 * A cred-scoped open (root://, davs, S3 authenticated as an end user whose
 * identity maps to a <key>.keyring file) must authenticate to RADOS as THAT
 * CephX user rather than the export's static service credential. Opening a
 * fresh rados_t/ioctx per request would be prohibitively expensive (a full
 * mon handshake per open), so the per-export instance keeps a small bounded
 * LRU cache of live per-(user,keyring) connections, keyed on the pair — a
 * keyring path always names exactly one user, but caching on BOTH catches
 * the (pathological, but cheap to guard) case of two different keyring paths
 * asserting the same bare user id.
 */

/* sd_ceph_cred_conn_find — locate a cached connection for (user, keyring)
 * and bump its LRU generation. Returns NULL when absent (cache miss). */
static sd_ceph_cred_conn_ent_t *
sd_ceph_cred_conn_find(sd_ceph_state_t *st, const char *user,
    const char *keyring)
{
    ngx_uint_t i;

    for (i = 0; i < st->cred_conn_count; i++) {
        if (strcmp(st->cred_conns[i].user, user) == 0
            && strcmp(st->cred_conns[i].keyring, keyring) == 0)
        {
            st->cred_conns[i].lru_gen = ++st->cred_conn_lru_clock;
            return &st->cred_conns[i];
        }
    }
    return NULL;
}

/* sd_ceph_cred_conn_evict_lru — free up one cache slot for a new (user,
 * keyring) entry. Called only when the cache is full (cred_conn_count ==
 * SD_CEPH_CRED_CONN_CACHE_MAX).
 *
 * WHAT: Picks the least-recently-used slot AMONG UNPINNED (refs==0) entries
 *       and reclaims it, either destroying the connection outright (no
 *       in-flight opens ever touched it since caching) or, if it happens to
 *       still be pinned at the moment of selection, marking it `doomed` and
 *       clearing the slot so the connection itself survives until its last
 *       open() releases the final pin (sd_ceph_conn_unpin completes the
 *       destroy then). Returns the reclaimed slot index, or
 *       SD_CEPH_CRED_CONN_CACHE_MAX if every slot is currently pinned (no
 *       slot could be freed).
 * WHY:  This is the core UAF fix: a connection with refs>0 — i.e. one or
 *       more sd_ceph_obj_state_t handles are still open against it — must
 *       NEVER have rados_ioctx_destroy/rados_shutdown called on it while
 *       still referenced. Skipping pinned slots when choosing the LRU
 *       victim, and deferring the actual destroy when a pinned slot must
 *       still be evicted from the table, together guarantee that.
 * HOW:  Two passes: first look for the coldest UNPINNED slot (safe to
 *       destroy immediately); if none exists (cache saturated with
 *       in-flight cred-scoped opens — pathological but must not crash),
 *       report "no slot available" so the caller falls back to a transient,
 *       uncached connection for this one open (sd_ceph_cred_conn). */
static ngx_uint_t
sd_ceph_cred_conn_evict_lru(sd_ceph_state_t *st)
{
    ngx_uint_t victim = SD_CEPH_CRED_CONN_CACHE_MAX;   /* "not found" sentinel */
    ngx_uint_t i;

    for (i = 0; i < st->cred_conn_count; i++) {
        if (st->cred_conns[i].conn->refs > 0) {
            continue;                  /* pinned: never pick as LRU victim */
        }
        if (victim == SD_CEPH_CRED_CONN_CACHE_MAX
            || st->cred_conns[i].lru_gen < st->cred_conns[victim].lru_gen)
        {
            victim = i;
        }
    }

    if (victim == SD_CEPH_CRED_CONN_CACHE_MAX) {
        return SD_CEPH_CRED_CONN_CACHE_MAX;   /* every slot pinned */
    }

    sd_ceph_conn_destroy(st->cred_conns[victim].conn);
    st->cred_conns[victim].conn = NULL;
    return victim;
}

/* sd_ceph_cred_conn — resolve (or create+cache) the per-user librados
 * connection for (user, keyring).
 *
 * WHAT: Returns a live sd_ceph_conn_t bound to the given CephX user/keyring,
 *       reusing a cached connection when one already exists for this exact
 *       (user, keyring) pair, or creating one via sd_ceph_conn_create and
 *       inserting it into the bounded LRU (evicting the least-recently-used
 *       entry first if the cache is already full).  Returns NULL with *err
 *       set on a connect failure (bad keyring, mon unreachable, auth
 *       rejected by the cluster, etc.) — the caller must treat this exactly
 *       like a rados_connect failure on the service credential path.
 * WHY:  A fresh mon handshake per request would be far too slow for the hot
 *       open path; a bounded LRU amortizes the connect cost across repeated
 *       opens by the same user while keeping a many-user credential
 *       directory's worst-case connection/fd usage bounded (§ cache-size
 *       constant SD_CEPH_CRED_CONN_CACHE_MAX).
 * HOW:  1. Cache hit (sd_ceph_cred_conn_find) → return immediately (the
 *          caller pins it before use — see sd_ceph_open_cred).
 *       2. Cache miss: synthesize a brix_sd_ceph_conf_t reusing the export's
 *          conf_file/pool/key_prefix but with the CRED's user/keyring, and
 *          connect via sd_ceph_conn_create (a full independent rados_t, so
 *          the user's own CephX identity — not the service account's — is
 *          what asserts capabilities at the OSDs).
 *       3. Insert at cred_conn_count++ (room available), or reclaim the
 *          LRU-evicted UNPINNED slot (cache full). If the cache is full AND
 *          every slot is currently pinned (sd_ceph_cred_conn_evict_lru
 *          returns "not found"), do NOT fail the open: hand back this fresh
 *          connection UNCACHED (`*out_transient = 1`) so a legitimate 9th+
 *          concurrent identity still gets served — it is never inserted
 *          into the table, so it costs a fresh mon handshake on this one
 *          open, but that is strictly better than either freezing out a
 *          valid user or (the original UAF this fix addresses) destroying a
 *          connection that is still in use. Because it is never inserted
 *          into the table, nothing else could ever reach it to free it, so
 *          it is marked `doomed` here at birth before being returned — the
 *          caller still pins it like any other connection, and
 *          sd_ceph_close's unpin-to-zero (sd_ceph_conn_unpin) performs the
 *          deferred destroy at that point, guaranteeing the transient
 *          connection's mon session/ioctx/fds are freed exactly once
 *          instead of leaking. */
static sd_ceph_conn_t *
sd_ceph_cred_conn(sd_ceph_state_t *st, ngx_pool_t *pool, const char *user,
    const char *keyring, int *err, int *out_transient)
{
    brix_sd_ceph_conf_t      conf;
    sd_ceph_cred_conn_ent_t *ent;
    sd_ceph_conn_t           *conn;
    ngx_uint_t                slot;

    *out_transient = 0;

    ent = sd_ceph_cred_conn_find(st, user, keyring);
    if (ent != NULL) {
        return ent->conn;
    }

    ngx_memzero(&conf, sizeof(conf));
    conf.conf_file  = st->conf_file;
    conf.pool       = st->pool;
    conf.user       = user;
    conf.keyring    = keyring;
    conf.key_prefix = st->key_prefix;

    conn = sd_ceph_conn_create(&conf, pool, err);
    if (conn == NULL) {
        return NULL;
    }

    if (st->cred_conn_count < SD_CEPH_CRED_CONN_CACHE_MAX) {
        slot = st->cred_conn_count++;
    } else {
        slot = sd_ceph_cred_conn_evict_lru(st);
        if (slot == SD_CEPH_CRED_CONN_CACHE_MAX) {
            /* Every cached slot is pinned (in-flight opens on all 8). Serve
             * this identity uncached rather than reject it or evict a
             * live handle's connection. This connection is never inserted
             * into cred_conns[], so nothing else can ever find or free it —
             * mark it doomed now, at birth, so its last sd_ceph_conn_unpin
             * (when the caller's open object closes and refs reaches 0)
             * performs the deferred destroy. Without this, a transient
             * connection's mon session/ioctx/fds leak on every close. */
            conn->doomed = 1;
            *out_transient = 1;
            return conn;
        }
    }

    if (strlen(user) >= sizeof(st->cred_conns[slot].user)
        || strlen(keyring) >= sizeof(st->cred_conns[slot].keyring))
    {
        /* Cannot happen in practice (BRIX_UCRED_CEPH_USER_MAX/_KEYRING_MAX
         * bound the source strings identically), but fail closed rather than
         * cache a truncated key that could alias a different user. Plain
         * libc strlen/memcpy (not ngx_cpystrn) — this file is compiled both
         * with and without nginx (see the SD_CEPH_CRED_*_MAX comment above);
         * the length check above already guarantees the copy fits. */
        sd_ceph_conn_destroy(conn);
        st->cred_conns[slot].conn = NULL;
        if (err != NULL) { *err = ENAMETOOLONG; }
        return NULL;
    }
    memcpy(st->cred_conns[slot].user, user, strlen(user) + 1);
    memcpy(st->cred_conns[slot].keyring, keyring, strlen(keyring) + 1);
    st->cred_conns[slot].conn    = conn;
    st->cred_conns[slot].lru_gen = ++st->cred_conn_lru_clock;

    return conn;
}

/* sd_ceph_cred_has_keyring — 1 iff `cred` carries a usable (non-empty) CephX
 * keyring path this driver can present. A NULL cred, or one of a different kind
 * (x509/bearer/S3 that reached a Ceph export), has no keyring. */
static int
sd_ceph_cred_has_keyring(const brix_sd_cred_t *cred)
{
    return cred != NULL && cred->ceph_keyring != NULL
        && cred->ceph_keyring[0] != '\0';
}

/* sd_ceph_open_cred — vtable open_cred slot: per-user CephX keyring credential
 * (ceph-peruser item).
 *
 * WHAT: Credential-scoped open that authenticates to RADOS as the requesting
 *       user's CephX identity rather than the export's static service
 *       credential, when the gate-supplied cred carries a ceph_keyring.
 * WHY:  Per-user backend auth requires the request to actually assert the
 *       user's own CephX capabilities at the OSDs — opening on the service
 *       ioctx would silently authenticate every user as the same admin
 *       identity, exactly the leak per-user credential scoping exists to
 *       close.  A cred whose selected kind this driver cannot present (no
 *       ceph_keyring — e.g. an x509/bearer/S3 cred reached a Ceph export) in
 *       fallback_deny mode must not silently fall back to the service
 *       credential, mirroring sd_xroot_open_common's wrong-kind-deny check.
 * HOW:  1. fallback_deny + no ceph_keyring → EACCES, matching sd_xroot's
 *          "cred kind unusable by this driver" refusal.
 *       2. No ceph_keyring at all (cred present but a different kind, deny
 *          not set) → fall back to the plain service-credential open (no
 *          pin needed — see sd_ceph_obj_state_t.conn / sd_ceph_close).
 *       3. ceph_keyring set → sd_ceph_cred_conn resolves/creates/reuses the
 *          per-user connection (possibly a transient uncached one if the
 *          LRU is saturated with pinned entries — see sd_ceph_cred_conn);
 *          sd_ceph_open_on_ioctx opens the object on THAT connection's
 *          ioctx and PINS it for the handle's lifetime (the UAF fix). On open
 *          failure the connection was never pinned, so a transient one is
 *          destroyed here (nothing else references it) and a cached one is
 *          simply left in the table unpinned.
 *
 * NOTE: 6-parameter signature is the brix_sd_driver_t .open_cred vtable slot
 *       (frozen — cannot be reduced without changing every driver). */
static brix_sd_obj_t *
sd_ceph_open_cred(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    sd_ceph_state_t   *st = inst->state;
    sd_ceph_open_req_t req = {
        .inst     = inst,
        .st       = st,
        .ioctx    = st->ioctx,
        .pin_conn = NULL,
        .path     = path,
        .sd_flags = sd_flags,
        .mode     = mode,
    };
    sd_ceph_conn_t *conn;
    brix_sd_obj_t  *obj;
    int             err = 0;
    int             transient = 0;

    if (!sd_ceph_cred_has_keyring(cred)) {
        if (cred != NULL && cred->fallback_deny) {
            if (err_out != NULL) { *err_out = EACCES; }
            errno = EACCES;
            return NULL;
        }
        return sd_ceph_open_on_ioctx(&req, err_out);   /* service credential */
    }

    conn = sd_ceph_cred_conn(st, inst->pool,
        (cred->ceph_user != NULL) ? cred->ceph_user : "", cred->ceph_keyring,
        &err, &transient);
    if (conn == NULL) {
        if (err_out != NULL) { *err_out = (err != 0) ? err : EACCES; }
        errno = (err != 0) ? err : EACCES;
        return NULL;
    }

    req.ioctx    = sd_ceph_conn_ioctx(conn);
    req.pin_conn = conn;
    obj = sd_ceph_open_on_ioctx(&req, err_out);
    if (obj == NULL && transient) {
        /* Never inserted into the cache table and never pinned (the open
         * failed before sd_ceph_obj_build's pin step) — nothing else
         * can reference it, so destroy it right away instead of leaking a
         * live rados_t/ioctx. */
        sd_ceph_conn_destroy(conn);
    }
    return obj;
}

ssize_t
sd_ceph_oid_read(sd_ceph_conn_t *c, const char *oid, void *buf, size_t len,
    off_t off)
{
    int rc = rados_read(c->ioctx, oid, buf, len, (uint64_t) off);

    if (rc < 0) {
        errno = -rc;
        return -1;
    }
    return (ssize_t) rc;
}

ssize_t
sd_ceph_oid_write(sd_ceph_conn_t *c, const char *oid, const void *buf,
    size_t len, off_t off)
{
    if (sd_ceph_set_errno(rados_write(c->ioctx, oid, buf, len, (uint64_t) off))) {
        return -1;
    }
    return (ssize_t) len;
}

int
sd_ceph_oid_stat(sd_ceph_conn_t *c, const char *oid, uint64_t *size,
    time_t *mtime)
{
    uint64_t sz = 0;
    time_t   mt = 0;

    if (sd_ceph_set_errno(rados_stat(c->ioctx, oid, &sz, &mt))) {
        return -1;
    }
    if (size != NULL)  { *size = sz; }
    if (mtime != NULL) { *mtime = mt; }
    return 0;
}

int
sd_ceph_oid_trunc(sd_ceph_conn_t *c, const char *oid, uint64_t len)
{
    return sd_ceph_set_errno(rados_trunc(c->ioctx, oid, len)) ? -1 : 0;
}

int
sd_ceph_oid_remove(sd_ceph_conn_t *c, const char *oid)
{
    return sd_ceph_set_errno(rados_remove(c->ioctx, oid)) ? -1 : 0;
}

ssize_t
sd_ceph_oid_getxattr(sd_ceph_conn_t *c, const char *oid, const char *name,
    void *buf, size_t cap)
{
    char tmp[SD_CEPH_XATTR_MAX];
    int  n = rados_getxattr(c->ioctx, oid, name, tmp, sizeof(tmp));

    if (n < 0) {
        errno = -n;
        return -1;
    }
    if (cap == 0) {
        return n;
    }
    if ((size_t) n > cap) {
        errno = ERANGE;
        return -1;
    }
    memcpy(buf, tmp, (size_t) n);
    return n;
}

ssize_t
sd_ceph_oid_listxattr(sd_ceph_conn_t *c, const char *oid, void *buf, size_t cap)
{
    rados_xattrs_iter_t it;
    char               *out = buf;
    size_t              total = 0;

    if (sd_ceph_set_errno(rados_getxattrs(c->ioctx, oid, &it))) {
        return -1;
    }
    for (;;) {
        const char *nm = NULL;
        const char *val = NULL;
        size_t      vlen = 0;
        size_t      nlen;

        if (sd_ceph_set_errno(rados_getxattrs_next(it, &nm, &val, &vlen))) {
            rados_getxattrs_end(it);
            return -1;
        }
        if (nm == NULL) {
            break;
        }
        nlen = strlen(nm) + 1;
        if (cap != 0) {
            if (total + nlen > cap) {
                rados_getxattrs_end(it);
                errno = ERANGE;
                return -1;
            }
            memcpy(out + total, nm, nlen);
        }
        total += nlen;
    }
    rados_getxattrs_end(it);
    return (ssize_t) total;
}

int
sd_ceph_oid_setxattr(sd_ceph_conn_t *c, const char *oid, const char *name,
    const void *val, size_t len)
{
    return sd_ceph_set_errno(rados_setxattr(c->ioctx, oid, name, val, len))
               ? -1 : 0;
}

int
sd_ceph_oid_rmxattr(sd_ceph_conn_t *c, const char *oid, const char *name)
{
    return sd_ceph_set_errno(rados_rmxattr(c->ioctx, oid, name)) ? -1 : 0;
}

/* sd_ceph_enumerate — backend-catalog enumeration (inventory/drift, §E1/D2).
 * Lists the pool's RADOS objects and reports ONE catalog entry per logical file,
 * byte-compatibly with stock XrdCeph's libradosstriper layout:
 *   - a striper FIRST stripe ("<name>.0000000000000000") represents one file →
 *     recover its physical name by stripping the suffix and report it once;
 *   - striper DATA stripes ("<name>.%016x", index > 0) are skipped (already
 *     accounted by their first stripe);
 *   - a flat object (this basic driver's own, no 16-hex stripe suffix) is itself.
 * The logical path is recovered by stripping the export key_prefix; a key outside
 * the prefix yields path=NULL (an orphan candidate). want_stat adds a rados_stat
 * per reported object. Worker-safe: synchronous librados, no pool/log/metrics.
 * Returns NGX_OK (enumeration ran; the callback may have aborted early) or
 * NGX_ERROR (errno set) if the pool list could not be opened. */
static ngx_int_t
sd_ceph_enumerate(brix_sd_instance_t *inst, int want_stat,
    brix_sd_catalog_cb cb, void *ctx)
{
    sd_ceph_state_t  *st = inst->state;
    rados_list_ctx_t  lc;
    const char       *oid;
    size_t            plen = (st->key_prefix != NULL) ? strlen(st->key_prefix) : 0;

    if (sd_ceph_set_errno(rados_nobjects_list_open(st->ioctx, &lc))) {
        return NGX_ERROR;
    }

    while (rados_nobjects_list_next(lc, &oid, NULL, NULL) == 0) {
        char                    pfn[1024];
        const char             *key_name;
        brix_sd_catalog_ent_t ent;
        uint64_t                size = 0;
        time_t                  mtime = 0;

        if (sd_ceph_oid_is_stripe_data(oid)) {
            continue;                  /* data stripe → counted by its first stripe */
        }
        if (sd_ceph_oid_is_first_stripe(oid)) {
            if (sd_ceph_oid_to_pfn(oid, pfn, sizeof(pfn)) != 0) {
                continue;              /* unrepresentable physical name → skip */
            }
            key_name = pfn;            /* the striper file's physical name */
        } else {
            key_name = oid;            /* flat object: it IS its own key */
        }

        ngx_memzero(&ent, sizeof(ent));
        ent.key  = key_name;
        ent.path = (plen == 0)
                   ? key_name
                   : (strncmp(key_name, st->key_prefix, plen) == 0
                          ? key_name + plen     /* recovered logical path */
                          : NULL);              /* outside prefix → orphan candidate */
        if (want_stat && rados_stat(st->ioctx, oid, &size, &mtime) == 0) {
            ent.have_stat = 1;
            ent.size  = (off_t) size;
            ent.mtime = mtime;
        }
        if (cb(ctx, &ent) != 0) {
            break;                     /* caller asked to stop — not an error */
        }
    }

    rados_nobjects_list_close(lc);
    return NGX_OK;
}

/* The Ceph driver descriptor. Honest caps: range read, random write, truncate —
 * no CAP_FD/SENDFILE (no fd; VFS serves memory-backed), no CAP_DIRS (flat key
 * namespace), no CAP_HARD_RENAME (no atomic rename). Directory iteration, rename,
 * xattr and staged commit are deliberately absent from this basic backend. */
const brix_sd_driver_t brix_sd_ceph_driver = {
    .name = "ceph",
    /* XATTR: the get/set/removexattr slots store object xattrs via rados_*xattr,
     * so a ceph object can carry the cinfo/meta records (phase-64 SP3 cache-store
     * role, XATTR cinfo mode - the cache state lives on the RADOS object itself). */
    .caps = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_RANDOM_WRITE
          | BRIX_SD_CAP_TRUNCATE | BRIX_SD_CAP_XATTR
          | BRIX_SD_CAP_XATTR_WRITE | BRIX_SD_CAP_MEMFILE
          | BRIX_SD_CAP_CATALOG,

    .init    = sd_ceph_init,
    .cleanup = sd_ceph_cleanup,
    .open    = sd_ceph_open,
    .open_cred = sd_ceph_open_cred,   /* per-user CephX keyring (ceph-peruser) */
    .close   = sd_ceph_close,

    .pread            = sd_ceph_pread,
    .pwrite           = sd_ceph_pwrite,
    .preadv           = sd_ceph_preadv,
    .preadv2          = sd_ceph_preadv2,
    .read_sendfile_fd = sd_ceph_read_sendfile_fd,
    .ftruncate        = sd_ceph_ftruncate,
    .fsync            = sd_ceph_fsync,
    .fstat            = sd_ceph_fstat,

    .stat   = sd_ceph_stat,
    .unlink = sd_ceph_unlink,

    .getxattr    = sd_ceph_getxattr,
    .listxattr   = sd_ceph_listxattr,
    .setxattr    = sd_ceph_setxattr,
    .removexattr = sd_ceph_removexattr,

    .staged_open   = sd_ceph_staged_open,
    .staged_write  = sd_ceph_staged_write,
    .staged_commit = sd_ceph_staged_commit,
    .staged_abort  = sd_ceph_staged_abort,

    .enumerate     = sd_ceph_enumerate,
};

#endif /* BRIX_HAVE_CEPH */
