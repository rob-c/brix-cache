#ifndef BRIX_TPC_TPC_PUSH_H
#define BRIX_TPC_TPC_PUSH_H

/*
 * tpc_push.h — F16 native root:// TPC PUSH: the declarations of the source-side
 * dialect, split out of tpc_internal.h (which owns the pull) so neither header
 * outgrows the 600-line contract and the push surface is reviewable on its own.
 *
 * Not a standalone header: it names brix_ctx_t, brix_file_t, brix_tpc_params_t
 * and ngx_stream_brix_srv_conf_t, so it is included from tpc_internal.h at the
 * point where all four exist. Include tpc_internal.h, never this file directly.
 */

/*
 * launch_push.c — F16, the SOURCE side of a native push (tpc.stage=push).
 *
 * A push read-open is an ORDINARY read-open that happens to name a remote
 * destination: the client opens the local file for read with tpc.key / tpc.dst /
 * tpc.dlfn, and the two kXR_syncs that follow arm and then fire the transfer.
 * The role is decided in brix_open_handle_tpc(), which runs BEFORE path
 * resolution, authz and open — so nothing here reimplements any of that.
 * Instead brix_tpc_prepare_push runs the security ladder and PARKS the decision
 * (brix_tpc_push_pending_t on ctx->tpc_push_pending, allocated from c->pool),
 * and brix_open_finalize_handle() stamps it onto the handle the normal open
 * produced.  A parked intent that is never stamped is simply dropped with the
 * connection pool.
 */

/*
 * brix_tpc_push_pending_t — the push intent parked between the TPC role
 * decision and the handle it will be stamped onto.  Exactly the fields
 * brix_file_t needs: the remote peer to dial, the path to write there, the
 * rendezvous key to present, and the (already clamped) stream count.
 */
typedef struct {
    char       host[256];       /* remote DESTINATION host (bare, no brackets) */
    uint16_t   port;            /* 0 = default 1094 */
    char       lfn[PATH_MAX];   /* remote path to write */
    char       key[128];        /* rendezvous key, presented as tpc.key */
    char       org[256];        /* tpc.org identity of the CLIENT that asked */
    unsigned   org_unresolved:1;/* org holds the numeric fallback; a PTR fill
                                   was started and the thread finishes it */
    int        streams;         /* clamped tpc.str, >= 1 */
} brix_tpc_push_pending_t;

/*
 * brix_tpc_prepare_push — the kXR_open leg.  Runs the operator opt-in
 * (brix_tpc_push), the destination host/path validation, the source-egress
 * allowlist (with its fail2ban signal and refusal counter) and the cached SSRF
 * verdict on the host this server would DIAL, then parks the intent.  An
 * unknown name is NOT parked on DNS here: nothing has been dialled yet and the
 * pull thread re-checks every address it actually connects to (I-DNS-3), so the
 * open proceeds and an offending address is refused at connect time.
 * Returns NGX_DECLINED when the intent is parked and the ordinary open must
 * proceed, or NGX_OK once a refusal has been answered.
 */
ngx_int_t brix_tpc_prepare_push(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc);

/*
 * brix_tpc_push_apply_pending — stamp a parked push intent onto a freshly
 * opened handle and clear the park.  No-op when nothing is parked.  Called
 * from brix_open_finalize_handle() (open_resolved_file_finalize.c).
 */
void brix_tpc_push_apply_pending(brix_ctx_t *ctx, brix_file_t *file);

/*
 * brix_tpc_start_push — the kXR_sync leg: snapshot the handle into a heap task
 * with the remote DESTINATION in src_host/src_port and post the same
 * thread-pool worker, which branches to tpc_push_to_dest.
 */
ngx_int_t brix_tpc_start_push(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int fhandle_idx);


#endif /* BRIX_TPC_TPC_PUSH_H */
