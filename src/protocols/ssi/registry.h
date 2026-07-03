#ifndef BRIX_SSI_REGISTRY_H
#define BRIX_SSI_REGISTRY_H

/*
 * registry.h — per-worker SSI session registry (async-delivery guard).
 *
 * WHAT: maps a stable connection id → live session, validated by generation.
 * WHY:  an async completion (timer / thread-pool job) holds only {conn_id,
 *       generation, reqId} — never a raw connection pointer — so it can safely
 *       resolve the live session or be dropped if the connection has closed or
 *       the slot was recycled. This is the single use-after-free invariant for
 *       server-pushed SSI responses.
 * HOW:  a fixed per-worker table. add() on open, remove() on teardown (BEFORE the
 *       connection pool is freed); find() rejects a moved generation. Sessions
 *       are connection-bound to one worker, so no shared memory is needed.
 */

#include "session.h"

#define BRIX_SSI_REGISTRY_SLOTS 256

/* Register (or refresh) the session for conn_id; stores its current generation. */
void brix_ssi_registry_add(uintptr_t conn_id, brix_ssi_session_t *s);

/* Remove the entry for conn_id (idempotent). MUST be called on connection
 * teardown before the session's pool memory is reclaimed. */
void brix_ssi_registry_remove(uintptr_t conn_id);

/* Return the session for conn_id only if its stored generation equals
 * `generation`; NULL if absent or the generation has moved. */
brix_ssi_session_t *brix_ssi_registry_find(uintptr_t conn_id,
                                               uint64_t generation);

#endif /* BRIX_SSI_REGISTRY_H */
