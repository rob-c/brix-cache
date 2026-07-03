#ifndef BRIX_TPC_KEY_REGISTRY_H
#define BRIX_TPC_KEY_REGISTRY_H

#include "core/ngx_brix_module.h"

/*
 * TPC key registry — shared-memory table of in-flight TPC keys.
 *
 * When the destination server accepts a write-open with tpc.src=, it
 * generates (or echoes) the tpc.key and registers it here.  The source
 * server can then validate the key before serving the file.  Keys expire
 * after the configured TTL (default BRIX_TPC_KEY_TTL_MS; override with
 * brix_tpc_key_ttl) to prevent resource leaks if
 * the rendezvous never completes.
 *
 * The registry is per nginx worker group (shared memory).  Rendezvous keys
 * are registered and consumed on the *source* data server when the client
 * opens with tpc.dst + tpc.key and the destination later reconnects with
 * tpc.org + tpc.key; that state is local to the source host.
 */

#define BRIX_TPC_KEY_SLOTS   256
#define BRIX_TPC_KEY_LEN     128
#define BRIX_TPC_KEY_TTL_MS  60000   /* 60 seconds */

typedef struct {
    char        key[BRIX_TPC_KEY_LEN];
    ngx_msec_t  expiry;     /* absolute ms at which this entry expires */
    ngx_uint_t  in_use;
} brix_tpc_key_entry_t;

typedef struct {
    ngx_shmtx_sh_t          lock;
    brix_tpc_key_entry_t  slots[BRIX_TPC_KEY_SLOTS];
} brix_tpc_key_table_t;

/* Called once from postconfiguration to allocate the shared memory zone. */
ngx_int_t  brix_tpc_key_configure_registry(ngx_conf_t *cf);

/*
 * Generate a unique TPC key into buf (caller provides ≥25 bytes).
 * Must be called from the event thread only (uses ngx_current_msec +
 * ngx_pid + a per-process counter).
 */
void  brix_tpc_generate_key(char *buf, size_t buf_sz);

/*
 * Register a TPC key with the given TTL in milliseconds.
 * Safe to call from the event thread.
 */
void  brix_tpc_key_register(const char *key, ngx_msec_t ttl_ms);

/*
 * Return 1 if key is present and has not expired; 0 otherwise.
 * Lazy-expires stale entries during the scan.
 */
int   brix_tpc_key_validate(const char *key);

/*
 * Return 1 and remove key if present and unexpired; 0 otherwise.
 * Used when the destination server connects back to a source with tpc.org.
 */
int   brix_tpc_key_consume(const char *key);

/* Remove a key from the registry (called after successful pull). */
void  brix_tpc_key_remove(const char *key);

#endif /* BRIX_TPC_KEY_REGISTRY_H */
