/* fetch.h — CVMFS content-addressed fetch orchestrator (pure C, no ngx/FUSE).
 *
 * WHAT: get a verified plaintext object by its content hash — cache-first, else
 *       fetch over the failover engine, decompress, verify, store.
 * WHY:  this is where the four resilience pillars converge; in particular the
 *       4th (hash-verified safe retry) lives here: because identity is the
 *       content hash, a transport failure OR a corrupt/poisoned reply is retried
 *       against the NEXT mirror and only accepted once the plaintext hashes to
 *       the name it was requested under.
 * HOW:  transport is a caller-injected seam (client = blocking libc HTTP +
 *       resilient.c; server = nginx sd_http), so the orchestrator is pure and
 *       standalone-testable with a mock transport. Cache is the shared CAS store,
 *       which holds VERIFIED PLAINTEXT (a hit needs no re-decode/verify).
 */
#ifndef BRIX_CVMFS_FETCH_H
#define BRIX_CVMFS_FETCH_H

#include <stddef.h>
#include "cvmfs/grammar/hash.h"
#include "cvmfs/failover/failover.h"
#include "cache/cas_store.h"

/* Transport seam: fetch the object at `rel_path` ("data/<2>/<rest>") via the
 * chosen route into `out`/`outcap`; set *outlen. `proxy_url` may be NULL/"DIRECT".
 * Return 0 on a completed transfer (bytes as stored on the server, i.e. possibly
 * compressed), -1 on transport failure. */
typedef int (*cvmfs_transport_fn)(const char *proxy_url, const char *host_url,
                                  const char *rel_path,
                                  unsigned char *out, size_t outcap, size_t *outlen,
                                  void *ud);

typedef enum {
    CVMFS_STORE_COMPRESSED = 0,   /* server object is zlib-compressed (default) */
    CVMFS_STORE_PLAIN             /* server object is stored uncompressed */
} cvmfs_store_form_e;

typedef struct {
    cvmfs_failover_t   *fo;
    brix_cas_store_t   *cache;
    cvmfs_transport_fn  transport;
    void               *transport_ud;
    unsigned            max_attempts;      /* 0 → default 6 */
    cvmfs_store_form_e  store_form;
    unsigned char      *scratch;           /* transport landing buffer */
    size_t              scratch_cap;
} cvmfs_fetch_ctx_t;

/* Fetch object `hash` (+ optional CAS `suffix`) into `out`/`outcap`, verified.
 * *outlen gets the plaintext length. Returns:
 *   0  = success,
 *  -1  = transport/verify exhausted all mirrors (retryable elsewhere),
 *  -2  = offline: every endpoint blacklisted (caller may serve stale/cache only),
 *  -3  = output buffer too small.
 * `now` is monotonic seconds for the failover engine. */
int cvmfs_fetch_object(cvmfs_fetch_ctx_t *ctx, const cvmfs_hash_t *hash, char suffix,
                       unsigned char *out, size_t outcap, size_t *outlen, long now);

#endif /* BRIX_CVMFS_FETCH_H */
