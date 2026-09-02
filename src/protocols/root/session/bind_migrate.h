#ifndef BRIX_SESSION_BIND_MIGRATE_H
#define BRIX_SESSION_BIND_MIGRATE_H

/*
 * bind_migrate.h — §1.4 cross-worker kXR_bind secondary migration.
 *
 * WHAT: With `listen ... reuseport`, the kernel hashes each of a client's TCP
 *       connections to a worker independently, so a secondary data channel's
 *       kXR_bind routinely lands on a different worker than the session's
 *       primary connection.  Response offloading (§1.1–§1.3) requires primary
 *       and secondary on the SAME event loop — the primary's worker writes
 *       response frames directly to the secondary's socket — so a scattered
 *       bind used to fall back to inline primary responses, costing the
 *       multi-substream throughput reuseport was meant to enable.  This module
 *       hands the freshly-bound secondary's fd to the session-owning worker
 *       over a pre-fork SOCK_SEQPACKET channel pair (SCM_RIGHTS); the owner
 *       adopts the socket into a fabricated stream session and completes the
 *       bind there, restoring same-worker offloading for every substream.
 *
 * WHY:  reuseport is what spreads simultaneous multi-client accepts across
 *       workers (without it one worker's accept storm serializes everything);
 *       migration is what keeps single-client multi-substream transfers on one
 *       event loop.  Together they win both benchmark axes.
 *
 * SAFETY: migration happens only at the bind frame boundary — the recv loop
 *       reads exact per-frame byte counts, so no userspace bytes are buffered
 *       past the bind request; anything the client pipelines later sits in the
 *       kernel socket buffer and travels with the fd.  TLS secondaries never
 *       migrate (SSL state cannot cross processes) and neither does a
 *       connection with queued responses (replies must not reorder).  Every
 *       refusal degrades to the pre-§1.4 behavior: bind locally, respond
 *       inline on the primary.
 */

#include "core/ngx_brix_module.h"

/* Master, init_module (pre-fork): create one SOCK_SEQPACKET socketpair per
 * worker so any worker can pass an fd to any other.  No-op (migration
 * disabled) for a single-worker deployment or > max supported workers. */
void brix_bind_migrate_create_channels(ngx_cycle_t *cycle);

/* Worker, init_process: register this worker's channel read end with the
 * event loop and drop the other workers' read ends. */
void brix_bind_migrate_init_worker(ngx_cycle_t *cycle);

/* kXR_bind path (bind.c): if `sessid`'s primary lives on another worker and
 * this connection is eligible (cleartext, nothing queued), send its fd there.
 * NGX_OK = migrated (caller must abandon the local connection WITHOUT writing
 * a byte); NGX_DECLINED = not migrated (caller binds locally as before). */
ngx_int_t brix_bind_migrate_try(brix_ctx_t *ctx, ngx_connection_t *c,
    const u_char sessid[BRIX_SESSION_ID_LEN]);

/* bind.c: the attach core shared by the local bind path and the migration
 * target — registry lookup, identity inheritance, pathid assignment, offload
 * registration, kXR_ok reply (streamid from ctx->recv.cur_streamid). */
ngx_int_t brix_bind_attach(brix_ctx_t *ctx, ngx_connection_t *c,
    const u_char sessid[BRIX_SESSION_ID_LEN]);

#endif /* BRIX_SESSION_BIND_MIGRATE_H */
