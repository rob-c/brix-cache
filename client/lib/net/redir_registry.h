/*
 * redir_registry.h — client-side redirect-collapse / VirtualRedirector registry
 * (§7.11).
 *
 * WHAT: a small per-process table mapping an endpoint URL to the endpoint it was
 *   redirected to, with transitive COLLAPSE — so a chain A→B→C is answered as
 *   A→C and a repeated open of A dials C directly instead of walking the chain
 *   again. Cycle-safe (bounded hop count) and bounded in size (LRU eviction).
 * WHY:  without it the client re-incurs every hop of a multi-level redirect on
 *   each operation, and a redirect loop (A→B→A) could spin. This is the client
 *   half of XrdCl's VirtualRedirector registry (the metalink virtual redirector
 *   feeds the same table via brix_vredir_record).
 * HOW:  a fixed-capacity array of (url, target) pairs; record() resolves the
 *   target through any existing chain before storing, and lookup() follows the
 *   chain with a hop cap. Thread-affinity: single-threaded client process.
 */
#ifndef BRIX_NET_REDIR_REGISTRY_H
#define BRIX_NET_REDIR_REGISTRY_H

/* Record that `url` redirected to `target`. Both are copied. `target` is first
 * collapsed through the existing table, so the stored mapping is url→FINAL. A
 * self- or cycle-mapping is refused (never stored). No-op on NULL/empty args. */
void brix_vredir_record(const char *url, const char *target);

/* Return the collapsed final target `url` resolves to (following the chain, hop-
 * capped), or NULL when `url` has no recorded redirect. The returned pointer is
 * owned by the registry and valid until the next record()/clear(). */
const char *brix_vredir_lookup(const char *url);

/* Drop every mapping (test isolation / reconfiguration). */
void brix_vredir_clear(void);

/* Live mapping count (diagnostics/tests). */
unsigned brix_vredir_count(void);

#endif /* BRIX_NET_REDIR_REGISTRY_H */
