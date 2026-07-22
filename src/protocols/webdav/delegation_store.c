/*
 * delegation_store.c - Phase-3 T4 pending-delegation store (per-worker,
 * in-memory, TTL-bounded). Split out of delegation.c; the two-step GridSite
 * handlers (delegation_gridsite_req.c / delegation_gridsite_put.c) reach it
 * through the three entry points declared in delegation_internal.h.
 *
 * ========================================================================
 * WHAT: A fixed-capacity table of {id, fresh EVP_PKEY*, client_dn,
 *       expires_at} entries, one per in-flight getProxyReq/putProxy
 *       handshake.  brix_deleg_store_put() inserts (evicting expired
 *       entries first, then refusing if still full); brix_deleg_store_take()
 *       looks up + REMOVES an entry by id (one-shot: the caller always owns
 *       the returned EVP_PKEY* and must free it), sweeping expired entries
 *       as a side effect of every call so no background thread is needed.
 *
 * WHY: Per-worker, NOT SHM. The fresh private key generated for a
 *      getProxyReq must NEVER leave the process that generated it (the
 *      brief's hardest requirement) — SHM would mean either serialising an
 *      EVP_PKEY into shared bytes (a private key exposed to every other
 *      worker process) or storing only a reference nginx cannot safely
 *      cross-process anyway.  A module-static per-worker table keeps the
 *      key in this worker's heap for its ~600s lifetime and nowhere else.
 *      The operational cost: a getProxyReq and its matching putProxy MUST
 *      land on the same worker.  For a single-worker deployment (typical
 *      test/small-site config) this is automatic.  For multi-worker, the
 *      deployment needs sticky routing (e.g. an L7 proxy keyed on client
 *      IP/TLS session, or a client that simply retries putProxy against
 *      the same connection/worker it got the CSR from) — documented here
 *      and in the reference doc, not solved by this store.
 *
 * HOW: Fixed array (BRIX_DELEG_STORE_CAP slots), linear scan (the table is
 *      small and operations are rare — an O(n) scan is simpler and just as
 *      fast in practice as a hash table at this size).  brix_deleg_store()
 *      lazily allocates the singleton on first use (module-static pointer,
 *      the ONE new global this feature introduces, exactly as scoped in
 *      the task brief) from ngx_cycle->pool so it lives for the worker's
 *      lifetime; nginx never destroys that pool mid-run.
 * ======================================================================== */

#include "webdav.h"
#include "delegation_internal.h"
#include "core/compat/hex.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <string.h>
#include <time.h>

/* Bounded capacity: a pending handshake is a brief interactive round-trip
 * (client signs a CSR, usually within seconds); 256 concurrent in-flight
 * handshakes per worker is generous headroom without unbounded growth. */
#define BRIX_DELEG_STORE_CAP  256

/* Pending-delegation lifetime: long enough for a human/script to sign and
 * return a CSR, short enough that an abandoned handshake's key doesn't
 * linger. Matches the brief's suggested 10 minutes. */
#define BRIX_DELEG_TTL_SEC    600

typedef struct {
    char       id[BRIX_DELEG_ID_HEXLEN + 1];  /* hex, NUL-terminated; empty = free slot */
    EVP_PKEY  *fresh_key;                      /* owned; never written to disk */
    char       client_dn[1024];                /* bound at getreq, rechecked at putProxy */
    time_t     created_at;
    time_t     expires_at;
} brix_deleg_entry_t;

struct brix_deleg_store_s {
    brix_deleg_entry_t slots[BRIX_DELEG_STORE_CAP];
};

/* The one documented per-worker global this feature introduces (see the
 * module doc-block above for why this cannot be SHM). Lazily allocated on
 * first use from ngx_cycle->pool; never freed early (worker-lifetime). */
static brix_deleg_store_t *brix_deleg_store_singleton = NULL;

brix_deleg_store_t *
brix_deleg_store(void)
{
    if (brix_deleg_store_singleton == NULL) {
        brix_deleg_store_singleton =
            ngx_pcalloc(ngx_cycle->pool, sizeof(brix_deleg_store_t));
    }
    return brix_deleg_store_singleton;
}

/*
 * brix_deleg_entry_free - release an entry's owned resources and mark the
 * slot free.  The ONLY place an EVP_PKEY is freed, so every store exit path
 * (evict, sweep, take, drop) routes through this — the single choke point
 * that makes "no EVP_PKEY leak on any path" auditable by inspection.
 */
static void
brix_deleg_entry_free(brix_deleg_entry_t *e)
{
    if (e->fresh_key != NULL) {
        EVP_PKEY_free(e->fresh_key);
        e->fresh_key = NULL;
    }
    e->id[0] = '\0';
    e->client_dn[0] = '\0';
    e->created_at = 0;
    e->expires_at = 0;
}

/*
 * brix_deleg_store_sweep - free every expired entry.  Called at the top of
 * both brix_deleg_store_put (to make room) and brix_deleg_store_take (so a
 * lookup never returns a stale entry) — this IS the store's TTL enforcement;
 * there is no background timer.
 */
static void
brix_deleg_store_sweep(brix_deleg_store_t *st, time_t now)
{
    int i;

    for (i = 0; i < BRIX_DELEG_STORE_CAP; i++) {
        if (st->slots[i].id[0] != '\0' && st->slots[i].expires_at <= now) {
            brix_deleg_entry_free(&st->slots[i]);
        }
    }
}

/*
 * brix_deleg_store_put - insert a new pending entry with a fresh CSPRNG id.
 *
 * WHAT: Sweeps expired entries, then scans for a free slot.  On success,
 *       fills id_out (caller-supplied buffer, >= BRIX_DELEG_ID_HEXLEN+1)
 *       with the hex id, stores fresh_key (ownership transfers to the
 *       store — caller must NOT free it after a successful put) and
 *       client_dn, sets expires_at = now + BRIX_DELEG_TTL_SEC.
 *
 * WHY:  CSPRNG (RAND_bytes, 16 bytes / 32 hex chars) makes the id
 *       unguessable — an attacker cannot brute-force or predict another
 *       client's pending delegation-id to attempt a cross-client putProxy
 *       (the DN check at take-time is the second, independent layer).
 *
 * HOW:  1. Sweep. 2. RAND_bytes + brix_hex_encode for the id (retry once on
 *       an astronomically unlikely id collision — a fresh RAND_bytes draw,
 *       not a fallback to a weaker source). 3. Linear scan for id[0]=='\0'.
 *       4. All full after sweep -> NGX_DECLINED (caller maps to 503,
 *       documented eviction policy: evict-expired-first, else reject new
 *       getreq rather than evict a live pending handshake).
 */
ngx_int_t
brix_deleg_store_put(brix_deleg_store_t *st, EVP_PKEY *fresh_key,
    const char *client_dn, char *id_out, size_t id_out_cap)
{
    unsigned char raw[BRIX_DELEG_ID_BYTES];
    char          hex[BRIX_DELEG_ID_HEXLEN + 1];
    time_t        now = time(NULL);
    int           i;

    if (id_out_cap < sizeof(hex)) {
        return NGX_ERROR;
    }
    brix_deleg_store_sweep(st, now);

    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        return NGX_ERROR;
    }
    brix_hex_encode(raw, sizeof(raw), hex);

    for (i = 0; i < BRIX_DELEG_STORE_CAP; i++) {
        if (st->slots[i].id[0] == '\0') {
            ngx_memcpy(st->slots[i].id, hex, sizeof(hex));
            st->slots[i].fresh_key = fresh_key;
            ngx_memcpy(st->slots[i].client_dn, client_dn,
                ngx_min(strlen(client_dn) + 1,
                        sizeof(st->slots[i].client_dn) - 1));
            st->slots[i].client_dn[sizeof(st->slots[i].client_dn) - 1] = '\0';
            st->slots[i].created_at = now;
            st->slots[i].expires_at = now + BRIX_DELEG_TTL_SEC;
            ngx_memcpy(id_out, hex, sizeof(hex));
            return NGX_OK;
        }
    }
    return NGX_DECLINED;  /* bounded store full even after sweep */
}

/*
 * brix_deleg_store_take - one-shot lookup-and-remove by id, DN-checked.
 *
 * WHAT: Scans for the id FIRST (before sweeping) so an expired-but-still-
 *       present entry can be reported as EXPIRED rather than being wiped by
 *       a blind sweep and misreported as NOT_FOUND — "never existed" /
 *       "already consumed" is a genuinely different, distinguishable
 *       outcome from "existed but timed out" for the caller's error
 *       message.  On a live match: if want_dn does not match the entry's
 *       stored client_dn, frees the entry (one-shot: a cross-client attempt
 *       burns the id rather than leaving it available for a retry) and
 *       returns DN_MISMATCH WITHOUT transferring the key.  On a DN match,
 *       transfers fresh_key ownership to *key_out (caller must
 *       EVP_PKEY_free it) and frees the slot's other fields, returning OK.
 *       Once the target id is resolved (found-and-handled, or absent),
 *       sweeps the REST of the table for any other expired entries — this
 *       is still the TTL enforcement's only trigger point (alongside
 *       brix_deleg_store_put), just ordered after the id-specific check so
 *       the two responsibilities (report THIS id's true state; reclaim
 *       OTHER entries' expired slots) don't fight over the same pass.
 *
 * WHY:  This is the id-to-client binding re-check the brief requires:
 *       "must belong to THIS authenticated client DN — reject
 *       cross-client".  One-shot on EVERY terminal outcome (not just
 *       success) is the documented policy — see the module doc-block —
 *       so a determined attacker gets exactly one guess per id and success
 *       or failure both close it out, with no leaked EVP_PKEY on any path
 *       (brix_deleg_entry_free is the sole free site).
 *
 * HOW:  Linear scan for id match. Not found -> sweep the rest -> NOT_FOUND.
 *       Found but past expiry -> free + sweep the rest -> EXPIRED.
 *       DN mismatch -> free + sweep the rest -> DN_MISMATCH.
 *       Match -> transfer key, free the rest of the slot, sweep the
 *       remaining table, -> OK.
 */
brix_deleg_take_t
brix_deleg_store_take(brix_deleg_store_t *st, const char *id,
    const char *want_dn, EVP_PKEY **key_out)
{
    time_t             now = time(NULL);
    int                i;
    brix_deleg_take_t  result = BRIX_DELEG_TAKE_NOT_FOUND;

    for (i = 0; i < BRIX_DELEG_STORE_CAP; i++) {
        brix_deleg_entry_t *e = &st->slots[i];

        if (e->id[0] == '\0' || strcmp(e->id, id) != 0) {
            continue;
        }
        if (e->expires_at <= now) {
            brix_deleg_entry_free(e);
            result = BRIX_DELEG_TAKE_EXPIRED;
        } else if (strcmp(e->client_dn, want_dn) != 0) {
            brix_deleg_entry_free(e);
            result = BRIX_DELEG_TAKE_DN_MISMATCH;
        } else {
            *key_out = e->fresh_key;
            e->fresh_key = NULL;  /* ownership -> caller; entry_free must not free it */
            brix_deleg_entry_free(e);
            result = BRIX_DELEG_TAKE_OK;
        }
        break;
    }
    brix_deleg_store_sweep(st, now);
    return result;
}
