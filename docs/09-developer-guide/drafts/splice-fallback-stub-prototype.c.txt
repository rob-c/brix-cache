/*
 * events_splice_fallback_stub.c — macOS stub for splice fallback
 * 
 * macOS lacks splice(), so the fallback path is always used.
 * This stub satisfies the linker but the function is never called.
 */

#include "proxy_internal.h"

/*
 * WHAT: macOS stub for splice fallback completion handler.
 *       No-op function satisfying linker on platforms without splice().
 * WHY:  macOS lacks splice() syscall; fallback path (sendfile/recv+send) always used.
 *       Stub prevents linker errors while keeping code path explicit for audit.
 * HOW:  Cast proxy to void to suppress unused-param warning; no operations performed.
 * NOTE: This function is NEVER called on macOS - fallback path bypasses it entirely.
 */
void
brix_proxy_splice_fallback_finish(brix_proxy_ctx_t *proxy)
{
    /* Stub - splice not available on macOS, fallback path always used */
    (void)proxy;
}
