/*
 * sd_ceph_cred.c — Ceph/RADOS driver: per-user cred-conn cache, cred-scoped
 * open, the oid-keyed shared byte/xattr layer, and catalog enumeration.
 *
 * WHAT: The credential + oid-level half of the driver split out of sd_ceph.c
 *       (file-size guard): the bounded per-(user,keyring) LRU of live librados
 *       connections and the .open_cred vtable slot that authenticates to RADOS
 *       as a specific CephX user (ceph-peruser item); and the shared oid-level
 *       byte/xattr ops (sd_ceph_oid_*) keyed by an explicit RADOS object id and
 *       reused by cephfsro + the recovery tools.
 *
 * WHY:  The credential machinery and the oid-keyed layer are a distinct concern
 *       from the path-keyed object lifecycle (sd_ceph_object.c) and the
 *       open-handle byte ops (sd_ceph_io.c); isolating them keeps every file
 *       under the source-size guard while preserving byte-for-byte behaviour.
 *
 * HOW:  The private struct definitions and the cross-TU helper/op declarations
 *       come from sd_ceph_internal.h; the striper-layout catalog helpers come
 *       from sd_ceph_compat.h. The whole body is gated on BRIX_HAVE_CEPH,
 *       exactly like the driver it was split from.
 */
#include "sd_ceph.h"
#include "sd_ceph_compat.h"   /* pure striper-layout helpers (catalog enumeration) */

#include <errno.h>
#include <string.h>

#include "sd_ceph_internal.h"

#if BRIX_HAVE_CEPH

#include <rados/librados.h>
#include "sd_ceph_striper.h"   /* libradosstriper read path (stock XrdCeph layout) */
#include <time.h>

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
brix_sd_obj_t *
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

/* ---- shared oid-level byte/xattr layer (reused by cephfsro + recovery tools)
 * All keyed by an explicit RADOS object id (rather than a logical path). ------ */

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

#endif /* BRIX_HAVE_CEPH */
