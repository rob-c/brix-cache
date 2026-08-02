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
 *      carries bytes_total so a transport that only learns the total size
 *      mid-flight can keep the dashboard's total accurate.
 *
 * HOW: forwards id/bytes_done/bytes_total/state to
 *      brix_tpc_registry_update_progress(); a positive bytes_total refreshes the
 *      registry's stored total, a 0 leaves it unchanged.
 */

/*
 * Record progress for transfer `id`: forward bytes_done, bytes_total and state to
 * the registry. A positive bytes_total updates the stored total; 0 leaves it
 * unchanged. Returns the underlying brix_tpc_registry_update_progress() result.
 */
ngx_int_t
brix_tpc_progress_emit(uint64_t id, off_t bytes_done, off_t bytes_total,
    ngx_uint_t state, ngx_log_t *log)
{
    return brix_tpc_registry_update_progress(id, bytes_done, bytes_total, state,
                                              log);
}
