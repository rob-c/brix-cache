#ifndef BRIX_ROOT_SESSION_OFFLOAD_REGISTRY_H
#define BRIX_ROOT_SESSION_OFFLOAD_REGISTRY_H

/*
 * offload_registry.h — per-worker (sessid, pathid) -> secondary-connection map
 * for pathid response offloading (audit §1.1/§7.3, do_Offload parity).
 *
 * WHAT: an in-process table the kXR_bind handler fills when a secondary data
 *       channel binds (register), the disconnect path clears when it goes away
 *       (unregister), and — in a later slice — the read/readv handler consults
 *       (lookup) to route a pathid-tagged response out the SECONDARY connection's
 *       socket instead of the control stream.
 *
 * WHY:  the SHM session registry already tracks WHICH pathids a session has bound
 *       (brix_session_pathid_bound, cross-worker), but response offloading needs
 *       the actual per-worker `ngx_connection_t` of the secondary to send data on
 *       it — and a connection object is process-local, so it cannot live in SHM.
 *       This is that process-local half.
 *
 * HOW:  a fixed-capacity array keyed by (sessid[BRIX_SESSION_ID_LEN], pathid).
 *       The connection is stored as an opaque `void *` so the table carries no
 *       nginx dependency and is unit-testable with plain pointers. Single-worker
 *       event loop = no locking. A secondary that binds while the table is full
 *       simply is not registered (offloading silently falls back to the control
 *       stream for it — never an error).
 *
 * SCOPE: this slice only maintains the table (bind fills it, disconnect clears
 *        it); nothing consults it yet, so the data path is unchanged. The routing
 *        that consumes lookup() lands in the next slice.
 */

#include <stddef.h>

#ifndef BRIX_SESSION_ID_LEN
#define BRIX_SESSION_ID_LEN 16
#endif

/* Max secondary data channels tracked per worker. A session binds at most a
 * handful; this covers many concurrent multi-stream sessions with headroom. */
#define BRIX_OFFLOAD_MAX 512

/*
 * Register (or re-point) the secondary `conn` for (sessid, pathid). A second
 * register of the same (sessid, pathid) replaces the stored connection. `conn`
 * must be non-NULL. Returns 1 on success, 0 if the table is full (the caller
 * proceeds without offloading for this channel).
 */
int  brix_offload_register(const unsigned char *sessid, unsigned pathid,
    void *conn);

/*
 * Return the secondary connection bound to (sessid, pathid) on this worker, or
 * NULL when none is registered here (unbound, or bound on another worker).
 */
void *brix_offload_lookup(const unsigned char *sessid, unsigned pathid);

/*
 * Drop every table entry pointing at `conn` (a closing connection removes
 * itself, keyed by the pointer so it works regardless of the ctx's state). A
 * no-op for a `conn` that was never registered.
 */
void brix_offload_unregister(void *conn);

/* Test-only: number of live entries (for unit tests / diagnostics). */
size_t brix_offload_count(void);

/*
 * §1.16 admin: the PRIMARY connection of every session on this worker is
 * registered under this out-of-wire-range pseudo-pathid (wire pathids are
 * 1-253, and the SHM bound-path bitmap refuses anything outside that range, so
 * a hostile read_args naming 255 is rejected as unbound BEFORE any offload
 * lookup — the admin entries are invisible to the data path). The admin socket
 * uses it to resolve `sessid -> conn` for disc/msg and to enumerate this
 * worker's sessions.
 */
#define BRIX_ADMIN_PATHID  255u

/*
 * Enumerate every live entry: cb(ud, sessid, pathid, conn) for each, in table
 * order, until the table ends or cb returns nonzero (early stop). Returns the
 * number of entries visited.
 */
size_t brix_offload_foreach(int (*cb)(void *ud, const unsigned char *sessid,
    unsigned pathid, void *conn), void *ud);

#endif /* BRIX_ROOT_SESSION_OFFLOAD_REGISTRY_H */
