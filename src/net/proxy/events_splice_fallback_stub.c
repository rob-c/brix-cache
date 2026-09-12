/*
 * events_splice_fallback_stub.c — macOS stub for splice fallback
 * 
 * macOS lacks splice(), so the fallback path is always used.
 * This stub satisfies the linker but the function is never called.
 */

#include "proxy_internal.h"

void
brix_proxy_splice_fallback_finish(brix_proxy_ctx_t *proxy)
{
    /* Stub - splice not available on macOS, fallback path always used */
    (void)proxy;
}
