#include "registry.h"

ngx_int_t
xrootd_tpc_progress_emit(uint64_t id, off_t bytes_done, off_t bytes_total,
    ngx_uint_t state, ngx_log_t *log)
{
    (void) bytes_total;

    return xrootd_tpc_registry_update(id, bytes_done, state, log);
}
