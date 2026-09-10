#ifndef BRIX_VFS_DELEG_H
#define BRIX_VFS_DELEG_H

/*
 * vfs_deleg.h — the phase-70 delegation live-cred binding surface of the VFS.
 *
 * WHAT: Binding a request's captured forwardable credential bytes (bearer /
 *       x509 proxy PEM) onto a brix_vfs_ctx_t, the EXCHANGE/SSS/STS/krb5
 *       arming setters, and the mode/capability probes a protocol front door
 *       asks before it delegates. Bodies: vfs_deleg.c / vfs_deleg_bind.c.
 *
 * WHY:  Split out of vfs.h for the file-size cap (2.0). Included at the END of
 *       vfs.h and DEPENDS on the types it defines (brix_vfs_ctx_t,
 *       brix_deleg_live_t, enum brix_cred_mode via fs/backend/sd.h). Do not
 *       include directly — include "fs/vfs/vfs.h".
 */
#include "fs/vfs/vfs.h"
#include "auth/s3/sts.h"                 /* brix_s3_sts_conf_t (§5.5 set_sts) */

/* Bind a per-request delegation live-cred bag (phase-70 §4) onto an already-
 * initialised VFS ctx. `live` carries the raw forwardable credential BYTES the
 * front door captured (bearer text / full x509 proxy PEM) plus the resolved
 * brix_cred_mode; it is borrowed (owned by the caller's request pool) and must
 * outlive the VFS op. A NULL bag leaves the ctx on the SELECT path (phase-1).
 * Defined in vfs_deleg.c. */
void brix_vfs_ctx_bind_backend_deleg(brix_vfs_ctx_t *vctx,
    brix_deleg_live_t *live);

/* Report the delegation mode resolved for this ctx: the bound live bag's mode,
 * or BRIX_CRED_SELECT when no bag is bound. Defined in vfs_deleg.c. */
enum brix_cred_mode brix_vfs_backend_mode(brix_vfs_ctx_t *vctx);

/* Does the storage backend resolved for this ctx consume a forwarded X.509 proxy
 * PEM (BRIX_SD_CRED_PROXY_PEM in its cred_accept mask)? Lets a protocol gate a
 * default-on proxy delegation to only the backends that can actually use it
 * (xroot, s3), leaving posix/pblock (which accept no forwarded proxy) untouched
 * so binding a proxy bag there never turns into a spurious cred-gate deny.
 * Returns 1 when the backend accepts a proxy PEM, 0 otherwise (incl. NULL ctx or
 * the default-POSIX NULL backend). Defined in vfs_deleg.c. */
int brix_vfs_backend_accepts_proxy(brix_vfs_ctx_t *vctx);

/* Snapshot the ctx's bound delegation bytes so a caller can re-bind the same
 * credential onto a derived/child ctx (phase-70). Writes the resolved mode into
 * *mode and, if `bearer` is non-NULL, the raw JWT (borrowed — same lifetime as
 * the source bag). Sets *mode=BRIX_CRED_SELECT and an empty bearer when no bag is
 * bound. The proxy PEM is not exposed here (it is a 0600-materialised secret that
 * must be re-captured, not copied around). Defined in vfs_deleg.c. */
void brix_vfs_deleg_snapshot(const brix_vfs_ctx_t *vctx,
    enum brix_cred_mode *mode, ngx_str_t *bearer);

/* Allocate a delegation live-cred bag from `pool`, populate it with the captured
 * forwardable credential BYTES, and bind it onto `vctx` (phase-70 §5.1/§5.4).
 *
 * `mode` is the export's resolved brix_cred_mode (conf->common.backend_delegation);
 * when it is BRIX_CRED_SELECT this is a no-op (the ctx stays on the dir-based
 * SELECT path). `bearer` is the raw JWT text (or {0,NULL} when none was captured);
 * `proxy_pem` is a user-supplied full x509 proxy PEM (or {0,NULL}). Both byte
 * ranges must be owned by `pool` and outlive every VFS op on `vctx`; they are
 * borrowed, not copied. Returns NGX_OK on success (or the mode-SELECT no-op),
 * NGX_ERROR on OOM. The bag itself is opaque to protocol handlers — this is the
 * single constructor so the struct layout stays private to the VFS. Defined in
 * vfs_deleg.c. */
ngx_int_t brix_vfs_deleg_bind(ngx_pool_t *pool, brix_vfs_ctx_t *vctx,
    enum brix_cred_mode mode, const ngx_str_t *bearer,
    const ngx_str_t *proxy_pem);

/* Populate the EXCHANGE conf on the ctx's bound live-cred bag (phase-70 §5.4).
 * Call at capture time, AFTER brix_vfs_deleg_bind, when the export's mode is
 * BRIX_CRED_EXCHANGE: `endpoint`/`client_id`/`client_secret` come from
 * conf->common.backend_tx_* and `audience` from the first backend_token_aud
 * entry. All strings are borrowed (conf-owned, NUL-terminated) and must outlive
 * the VFS op. `tx_cache_slot` (optional, may be NULL) is the address of the
 * conf's `backend_tx_cache` pointer — the gate lazily creates the per-worker
 * RFC-8693 minted-token cache there (P90-70.9); NULL disables caching. `dns`,
 * the export's phase-116 resolver policy (NULL: libc), pins the endpoint host.
 * A no-op when no bag is bound or `endpoint` is empty — the cred gate then
 * degrades EXCHANGE to verbatim bearer passthrough. In vfs_deleg_bind.c. */
struct brix_dns_policy_s;
void brix_vfs_deleg_set_exchange(brix_vfs_ctx_t *vctx,
    const ngx_str_t *endpoint, const ngx_str_t *client_id,
    const ngx_str_t *client_secret, const ngx_str_t *audience,
    void **tx_cache_slot, const struct brix_dns_policy_s *dns);

/* Bind the export's trusted CA store onto the ctx's bound live-cred bag so the
 * PASSTHROUGH materialiser re-verifies the proxy chain in-gate (phase-70 §5.1
 * RFC-3820 chain-trust, P90-70.4). Call at capture time, AFTER
 * brix_vfs_deleg_bind: `ca_store` is the protocol conf's X509_STORE* (webdav
 * conf->ca_store / stream conf->gsi_store; typed void* so this header stays
 * OpenSSL-free) and is borrowed — it must outlive the VFS op. `verify_depth` is
 * the max proxy chain depth (0 = OpenSSL default). A no-op when no bag is bound
 * or `ca_store` is NULL — the gate then relies on the capture-side validation
 * alone. Defined in vfs_deleg_bind.c. */
void brix_vfs_deleg_set_ca_store(brix_vfs_ctx_t *vctx, void *ca_store,
    ngx_uint_t verify_depth);

/* Arm SSS identity injection on the ctx (phase-70 §5.6 / P90-70.3): when the
 * request carries NO forwardable credential bytes, the cred gate materialises
 * an SSS credential asserting the caller's authenticated principal, signed
 * with `keytab` (conf->common.backend_sss_keytab; borrowed conf bytes,
 * NUL-terminated). Proven bytes (proxy PEM / bearer) always win over
 * injection. Unlike the other setters this ALLOCATES the bag (from vctx->pool)
 * when none is bound — injection is precisely the no-captured-bytes case where
 * brix_vfs_deleg_bind declined to bind. A no-op when `mode` is
 * BRIX_CRED_SELECT or `keytab` is empty; on bag-allocation OOM it degrades to
 * SELECT exactly like brix_vfs_deleg_bind's no-bytes path. Defined in
 * vfs_deleg_bind.c. */
void brix_vfs_deleg_set_sss(brix_vfs_ctx_t *vctx, enum brix_cred_mode mode,
    const ngx_str_t *keytab);

/* Arm S3 STS credential EXCHANGE on the ctx (phase-70 §5.5): when the request
 * carries NO forwardable credential bytes and the leaf backend accepts an S3
 * credential, the cred gate exchanges the node's S3 SERVICE credential for
 * temporary (ak/sk/session) creds scoped to the caller's identity via STS
 * AssumeRole/GetSessionToken. `cf` is a borrowed brix_s3_sts_conf_t built from
 * conf->common.backend_sts_* (its ngx_str_t fields point at conf-owned bytes;
 * the struct itself must outlive the VFS op — build it on the request pool).
 * Like brix_vfs_deleg_set_sss this ALLOCATES the bag (from vctx->pool) when none
 * is bound — STS, like SSS, is precisely the no-captured-bytes case. A no-op
 * when `mode` is BRIX_CRED_SELECT or `cf` is NULL; on bag-allocation OOM it
 * degrades to SELECT. Defined in vfs_deleg_bind.c. */
void brix_vfs_deleg_set_sts(brix_vfs_ctx_t *vctx, enum brix_cred_mode mode,
    const brix_s3_sts_conf_t *cf);

/* Arm krb5 GSSAPI EXCHANGE on the ctx (phase-70 §5.7): the front door has
 * captured the caller's forwarded TGT and serialised it to a 0600 FILE ccache
 * (brix_krb5_cred_to_ccache); this stamps that async-safe ccache PATH plus the
 * derived origin service principal onto the bag. When the leaf backend accepts
 * BRIX_SD_CRED_GSS_KRB5 the cred gate carries them onto the cred (mode EXCHANGE)
 * and the origin leg re-imports the cred and negotiates AS the caller. `ccache`
 * and `origin_princ` are borrowed NUL-terminated request-pool strings that must
 * outlive the VFS op. Like set_sss/set_sts this ALLOCATES the bag when none is
 * bound; a no-op when `mode` is BRIX_CRED_SELECT or either string is empty; on
 * bag-allocation OOM it degrades to SELECT. Defined in vfs_deleg_bind.c. */
void brix_vfs_deleg_set_krb5(brix_vfs_ctx_t *vctx, enum brix_cred_mode mode,
    const ngx_str_t *ccache, const ngx_str_t *origin_princ);

#endif /* BRIX_VFS_DELEG_H */
