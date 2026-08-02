#ifndef BRIX_CACHE_PELICAN_REGISTER_H
#define BRIX_CACHE_PELICAN_REGISTER_H

/*
 * pelican_register.h — advertise THIS node as a discoverable Pelican cache.
 *
 * WHAT: Periodically POST a signed OriginAdvertiseV2 document to the federation
 *       Director's /api/v1.0/director/registerCache endpoint so the Director
 *       redirects clients to this cache. The POST carries a short-lived ES256
 *       advertise JWT (scope "pelican.advertise") signed with the cache's key.
 * WHY:  Phase 3a let the module *pull* from a Pelican federation; this is the
 *       complement — joining the federation as a published cache. Pelican
 *       caches/origins re-advertise on a ~1-minute cadence; the Director expires
 *       ads that stop arriving.
 * HOW:  A per-worker timer (armed in init_process when brix_cache_advertise is
 *       on) offloads each advertisement to the cache thread pool: discover the
 *       Director (.well-known/pelican-configuration), build the advertise JSON
 *       (jansson) and the ES256 JWT (jwt_sign.c), then libcurl POST it. The
 *       cache's public key must already be registered with the federation
 *       registry (an out-of-band operator step — the registry handshake is not
 *       performed here).
 *
 * Exact wire details (PelicanPlatform/pelican server_structs/director.go,
 * origin/advertise.go) are documented inline in pelican_register.c.
 */

#include "fs/cache/cache_internal.h"
#include <ngx_event.h>
#include <jansson.h>        /* json_t — the builder decls below return it */
#include <time.h>           /* time_t — builder timestamps */

/*
 * Arm the per-worker advertise timer for conf (no-op unless cache_advertise is
 * on and the signing key + data-url are configured). Call from init_process so
 * each worker owns its timer. Loads the EC signing key and seeds the instanceID.
 */
void brix_cache_pelican_schedule_advertise(ngx_cycle_t *cycle,
    ngx_stream_brix_srv_conf_t *conf);

/*
 * Build + sign + POST one advertisement synchronously (blocking; thread-pool
 * worker only). Returns NGX_OK on a 2xx from the Director, NGX_ERROR otherwise
 * (reason logged). Exposed for the timer worker and for tests.
 */
ngx_int_t brix_cache_pelican_advertise_once(
    ngx_stream_brix_srv_conf_t *conf, ngx_log_t *log);

/*
 * Internal payload builders — exposed for unit testing only; production code
 * reaches them through brix_cache_pelican_advertise_once() above. The federation
 * POST needs a live Director and an out-of-band registry key handshake, but the
 * *document construction* is deterministic and must be conformance-checked
 * without one, so these are non-static and covered by tests/c/pelican_ad_test.c.
 *
 *   brix_pelican_rfc3339   — format a time_t as the Pelican-required RFC3339
 *                            UTC "%Y-%m-%dT%H:%M:%SZ" into out[outsz].
 *   brix_pelican_caps_json — the cache capability object (jansson; caller
 *                            json_decref()s): PublicRead/Read/Listing/
 *                            FallBackRead true, Write/Copies false.
 *   brix_pelican_build_ad  — the full OriginAdvertiseV2 document for conf at
 *                            time now, as a compact JSON C-string (caller
 *                            free()s), or NULL on allocation failure.
 */
void brix_pelican_rfc3339(time_t t, char *out, size_t outsz);
json_t *brix_pelican_caps_json(void);
char *brix_pelican_build_ad(ngx_stream_brix_srv_conf_t *conf, time_t now);

#endif /* BRIX_CACHE_PELICAN_REGISTER_H */
