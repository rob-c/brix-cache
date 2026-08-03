/* vfs_cred_internal.h — credential-seam declarations for the VFS.
 *
 * WHAT: The per-user backend/namespace credential gates (vfs_cred.c) and the
 *       delegation live-cred materialiser plus its shared failure terminal and
 *       STS/krb5 hooks (vfs_deleg*.c).
 *
 * WHY:  Split out of vfs_internal.h, which crossed the 600-line cap
 *       (coding-standards §1). Credential policy is one coherent seam; the
 *       parent header keeps the handle types and the inline accessors.
 *
 * HOW:  Included from the bottom of vfs_internal.h, so every existing consumer
 *       keeps seeing these declarations with no include churn. Include
 *       vfs_internal.h, never this header directly. */

#ifndef BRIX_VFS_CRED_INTERNAL_H
#define BRIX_VFS_CRED_INTERNAL_H

/* Per-user backend credential policy gates (vfs_cred.c).
 *
 * WHAT: Examine ctx->storage_cred_dir and the ctx identity, select a per-user
 *       x509 proxy via brix_sd_ucred_select, and report whether the op should
 *       proceed with a user credential (use_cred=1, *cred filled from *store),
 *       the service credential (use_cred=0), or be refused (NGX_ERROR, errno/
 *       *err_out = EACCES).
 *
 * WHY:  brix_vfs_backend_cred gates data-plane opens (open/staged_open), keyed
 *       on driver->open_cred.  brix_vfs_ns_cred gates namespace ops (stat/unlink/
 *       mkdir/rename/copy/setattr/xattr/opendir), keyed on driver->stat_cred.
 *       Both share the same select+deny+fallback decision body in vfs_cred.c.
 *
 * HOW:  The gates are stateless — each probes the credential file at call time.
 *       *store and *cred are stack-allocated by the callers and live for the
 *       duration of the driver call that follows. */
ngx_int_t brix_vfs_backend_cred(brix_vfs_ctx_t *ctx, brix_sd_ucred_t *store,
    brix_sd_cred_t *cred, int *use_cred, int *err_out);

/* Namespace-op credential gate (Phase 2 Task 1).  Same semantics as
 * brix_vfs_backend_cred but capability-checks driver->stat_cred rather than
 * driver->open_cred — the canonical namespace credential-scope indicator.
 * Called from the VFS ns dispatch sites before dispatching through the
 * brix_sd_<op>_maybe_cred forwarders. */
ngx_int_t brix_vfs_ns_cred(brix_vfs_ctx_t *ctx, brix_sd_ucred_t *store,
    brix_sd_cred_t *cred, int *use_cred, int *err_out);

/* Unwrap stage/cache decorator layers from `top` to reach the leaf driver
 * instance — the first non-decorator in the composed chain (e.g. sd_xroot,
 * sd_pblock, sd_posix).  Used by the VFS ns dispatch sites so that
 * brix_sd_<op>_maybe_cred dispatches on the leaf (which HAS *_cred slots)
 * rather than the decorator (which has only plain relays).
 * Returns `top` unchanged if it is already a leaf, or NULL if `top` is NULL. */
brix_sd_instance_t *brix_vfs_ns_leaf(brix_sd_instance_t *top);

/* ---- brix_vfs_cred_gate_active ---------------------------------------------
 *
 * WHAT: True when the per-user backend credential gate (brix_vfs_ns_cred /
 *       brix_vfs_backend_cred) must run for this ctx — i.e. a per-user
 *       credential SOURCE is bound: either the directory-based SELECT policy
 *       (storage_cred_dir) OR a live delegation bag (PASSTHROUGH/EXCHANGE).
 *
 * WHY:  The namespace dispatch sites (vfs_xattr/stat/unlink/mkdir/rename/dir/
 *       copy) originally guarded the gate on `storage_cred_dir != NULL` alone.
 *       That drops the credential in pure PASSTHROUGH mode (a deleg bag bound
 *       with NO storage_credential_dir): the ns op then runs on the static
 *       service credential, which a per-user (e.g. token-only) backend rejects —
 *       asymmetric with the data-plane open, whose gate (vfs_backend_cred_decide)
 *       already consults the deleg bag before the dir. This predicate makes the
 *       ns guard consider BOTH sources so a passthrough bearer/proxy reaches the
 *       backend on namespace ops (e.g. the WebDAV lock-state getxattr) exactly
 *       as it does on data-plane opens.
 *
 * HOW:  storage_cred_dir set, OR brix_vfs_backend_mode(ctx) != BRIX_CRED_SELECT
 *       (a bag is bound). A no-op change for the dir-only and no-cred configs. */
int brix_vfs_cred_gate_active(brix_vfs_ctx_t *ctx);

/* Delegation live-cred materialiser (phase-70 §5.1/§5.4, vfs_deleg.c).
 *
 * WHAT: For a ctx carrying a bound live bag in PASSTHROUGH mode, validate the
 *       captured bytes and materialise them into *cred: a bearer token is copied
 *       straight through (cred->bearer); a full x509 proxy PEM is written to a
 *       0600 temp path (cred->x509_proxy) with a pool cleanup that unlink()s +
 *       zeroes the path. Sets cred->mode. On success *use_cred=1, NGX_OK. On a
 *       missing/invalid live cred: *err_out=EACCES and NGX_ERROR when the ctx is
 *       in fallback-deny, else *use_cred=0 + NGX_OK (fall to service cred).
 *
 * WHY:  The one place the front door's raw forwardable credential becomes the
 *       exact cred form the backend GSI/ZTN presenter already consumes, so no
 *       new origin-leg code is needed.
 *
 * HOW:  Reuses brix_proxy_gsi_write_pem_temp() (net/proxy) for the bytes→path
 *       adaptor and PEM_read_bio_X509 to reject non-PEM. When the capture site
 *       stamped a CA store via brix_vfs_deleg_set_ca_store(), the full RFC-3820
 *       chain-trust verify re-runs here at the gate (P90-70.4); DN-match
 *       happens at capture. Unit: tests/c/deleg_gate_test.c. */
ngx_int_t brix_vfs_deleg_live_cred(brix_vfs_ctx_t *ctx, brix_sd_cred_t *cred,
    int *use_cred, int *err_out);

/* Single failure terminal for the delegation gate (vfs_deleg.c): bumps the
 * P90-70.6 outcome + failure-reason counters, then EACCES/NGX_ERROR under
 * fallback-deny (or a NULL ctx), else *use_cred=0 + NGX_OK (service-cred
 * fallback). Shared across the deleg TUs (vfs_deleg_hooks.c) — every deny in
 * the family MUST route through here so policy + metrics stay in one place. */
ngx_int_t brix_vfs_deleg_deny(brix_vfs_ctx_t *ctx, int *use_cred, int *err_out,
    brix_cred_fail_t reason);

/* Phase-70 §5.5/§5.7 call-ready EXCHANGE hooks — compiled + linkable but not yet
 * driven from the cred gate (the STS service-key conf / delegated GSS cred are
 * not reachable from brix_vfs_ctx_t without a capture-site bind owned by other
 * agents; see the DEFERRED notes in vfs_deleg_hooks.c). Declared here (not
 * static) so they link and are ready for that wiring. brix_s3_sts_conf_t comes
 * from auth/s3/sts.h (included above). */
ngx_int_t brix_vfs_deleg_sts_cred(brix_vfs_ctx_t *ctx,
    const brix_s3_sts_conf_t *cf, brix_sd_cred_t *cred,
    int *use_cred, int *err_out);
ngx_int_t brix_vfs_deleg_krb5_token(brix_vfs_ctx_t *ctx, void *deleg_gss_cred,
    const char *origin_service_princ, ngx_str_t *out_token);

#endif /* BRIX_VFS_CRED_INTERNAL_H */
