/*
 * deleg_wire.h — shared conf→VFS delegation wiring for every protocol front
 * door (phase-70 §5.2/§5.4, P90-70.9).
 *
 * WHAT: The two steps every bind-deleg site (WebDAV, S3, root wire) performs
 *       around brix_vfs_deleg_bind(): gate a captured bearer through the
 *       backend audience allow-list, and stamp the EXCHANGE conf + per-conf
 *       minted-token cache slot onto the VFS ctx.
 *
 * WHY:  The logic is conf-driven and byte-identical across protocols; keeping
 *       it here once means the audience gate and the exchange wiring cannot
 *       drift per protocol (the original bug: the directive was parsed but
 *       enforced nowhere). Deliberately http-free — the root:// stream module
 *       uses it too.
 *
 * HOW:  Both helpers read the embedded ngx_http_brix_shared_conf_t (the name
 *       is historical; the stream srv conf embeds the same struct). EXCHANGE
 *       with a configured endpoint exempts the bearer from the audience gate —
 *       the exchange re-audiences it for the backend.
 */
#ifndef BRIX_PROTO_DELEG_WIRE_H
#define BRIX_PROTO_DELEG_WIRE_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "core/config/shared_conf_types.h"
#include "fs/vfs/vfs.h"

/* Gate `bearer` for VERBATIM forwarding to the backend. Returns `bearer`
 * unchanged when it is absent/empty, when the export exchanges it (the minted
 * replacement is audienced by the issuer), or when it passes
 * brix_token_backend_aud_ok(); returns NULL when the configured audience gate
 * refuses it — the caller then simply binds no bearer and service-cred policy
 * applies. */
const ngx_str_t *brix_proto_deleg_gate_bearer(const ngx_str_t *bearer,
    const ngx_http_brix_shared_conf_t *cc, ngx_log_t *log);

/* Stamp the export's delegation conf onto the VFS ctx: (1) SSS identity
 * injection (phase-70 §5.6 / P90-70.3) — arms brix_backend_sss_keytab; runs
 * FIRST because it allocates the live-cred bag when the request captured no
 * forwardable bytes; (2) the RFC-8693 exchange conf (endpoint, client
 * credentials, first configured backend audience) + conf-owned minted-token
 * cache slot — no-op unless the mode is EXCHANGE with a configured endpoint.
 * Call right after brix_vfs_deleg_bind at every front-door bind site. */
void brix_proto_deleg_stamp_conf(brix_vfs_ctx_t *vctx,
    ngx_http_brix_shared_conf_t *cc);

#endif /* BRIX_PROTO_DELEG_WIRE_H */
