#include "registry.h"

/*
 * progress.c — progress-reporting shim for in-flight TPC transfers.
 *
 * WHAT: Implements brix_tpc_progress_emit(), the single entry point both
 *       transports call to report a transfer's advancing byte count and state.
 *
 * WHY: Transports should not care where progress is recorded — today that is the
 *      shared registry, but isolating the call behind one shim keeps callsites
 *      stable if reporting later fans out to metrics or external hooks. It also
 *      gives the bytes_total parameter a home now even though the registry does
 *      not yet store it.
 *
 * HOW: bytes_total is accepted for forward compatibility but currently unused
 *      (the registry tracks bytes_done and state); the call simply forwards
 *      id/bytes_done/state to brix_tpc_registry_update().
 */

/*
 * Record progress for transfer `id`: forward bytes_done and state to the
 * registry. bytes_total is reserved for future use and ignored. Returns the
 * underlying brix_tpc_registry_update() result.
 */
ngx_int_t
brix_tpc_progress_emit(uint64_t id, off_t bytes_done, off_t bytes_total,
    ngx_uint_t state, ngx_log_t *log)
{
    (void) bytes_total;

    return brix_tpc_registry_update(id, bytes_done, state, log);
}
