/*
 * oci.h — the OCI Distribution protocol plane: config, request ctx, seams.
 *
 * WHAT: the location config and per-request context for `src/protocols/oci/`,
 *       plus the handler entry point and the cross-file prototypes the module
 *       shares with its gate / serve / upstream-auth siblings.
 * WHY:  a container registry mirror is a *cache* with a URL grammar bolted on.
 *       Everything below the grammar — coalesced fills, ranged serving, digest
 *       verify-at-edge, TTL expiry on tag manifests, bounded stale-serve — is
 *       machinery the tree already runs for CVMFS. This header therefore
 *       declares only what is genuinely OCI: the upstream descriptor, the
 *       classified request, and the disposition the access log and the metric
 *       family both read (Appendix J.6 — one enum, never two stories).
 * HOW:  the shared preamble is the FIRST member of the loc conf (the tree-wide
 *       convention that lets brix_http_common_adopt / ngx_http_brix_shared_merge
 *       work on it), the surface flags default off, and nothing here allocates:
 *       a location without brix_oci_mirror / brix_oci_registry never grows a
 *       handler, so a non-OCI deployment is structurally untouched (J.2).
 */
#ifndef BRIX_PROTOCOLS_OCI_H
#define BRIX_PROTOCOLS_OCI_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "oci_classify.h"
#include "auth/token/issuer_registry.h"
#include "core/config/shared_conf.h"
#include "core/shm/kv.h"
#include "fs/backend/sd.h"
#include "observability/metrics/metrics_oci.h"
#include "oci/url.h"

/* The canonical route is "/v2/" + [namespace "/"] + name + "/" + terminal +
 * "/" + reference. Name caps at 255, a tag at 128, a digest string at 72, and
 * the namespace prefix is operator-supplied — 1 KiB clears every legal spelling
 * with room to spare, and an over-long one is refused rather than truncated. */
#define BRIX_OCI_KEY_MAX      1024

/* An upstream bearer token. DockerHub's JWTs run ~1.5 KiB; 4 KiB is the SHM
 * value cap the default token zone is configured with. */
#define BRIX_OCI_TOKEN_MAX    4096

/* The token-cache key is a raw sha256 of (upstream base ‖ NUL ‖ scope) — a
 * fixed 32 bytes, never the scope text, so a repository name from the wire can
 * neither overflow the key nor collide across upstreams (§D1.3). */
#define BRIX_OCI_TOKEN_KEYLEN 32

/* Zone geometry when brix_oci_token_zone was never written: the documented
 * default is `oci_tokens 1m`, and a mirror must work out of the box. */
#define BRIX_OCI_TOKEN_ZONE_DEFAULT_SIZE  (1024 * 1024)

/* A resolved pull-through upstream, built once at config time from the
 * brix_oci_mirror URL. Owned by the location's config pool; strings are fixed
 * buffers because the fill thread reads them without a lock and an ngx_str_t
 * pointing into cf->pool would be one refactor away from a dangling read. */
typedef struct {
    char        host[256];
    int         port;
    int         tls;                        /* 1 = https                     */
    char        base_path[256];             /* URL path prefix ("" | "/sub") */
    char        base_url[512];              /* scheme://host[:port]<base>    */
    char        basic[512];                 /* "user:pass" for the TOKEN
                                             * endpoint only, or ""          */
    int         insecure;                   /* brix_oci_mirror_insecure      */
    brix_oci_realm_list_t realms;           /* brix_oci_upstream_auth_realm  */
    brix_kv_t  *tokens;                     /* token cache zone, or NULL     */
    ngx_log_t  *log;                        /* cycle log for the fill thread */
} brix_oci_upstream_t;

typedef struct {
    ngx_http_brix_shared_conf_t   common;   /* MUST stay first              */

    /* ---- mirror surface (D0–D3) ---- */
    ngx_flag_t             mirror;          /* brix_oci_mirror present       */
    ngx_str_t              mirror_url;
    ngx_str_t              mirror_user;     /* brix_oci_mirror_auth arg 1    */
    ngx_str_t              mirror_pwfile;   /* brix_oci_mirror_auth arg 2    */
    ngx_str_t              upstream_ns;     /* brix_oci_upstream_namespace   */
    ngx_str_t              token_zone_name; /* brix_oci_token_zone           */
    brix_oci_realm_list_t *auth_realms;     /* _upstream_auth_realm entries,
                                             * NULL until one is written     */
    ngx_flag_t             token_zone_set;  /* the name was written, not
                                             * defaulted (§D1.3)             */
    time_t                 manifest_ttl;    /* brix_oci_manifest_ttl         */
    ngx_flag_t             insecure;        /* brix_oci_mirror_insecure      */

    /* ---- registry surface (D4, wave B) ---- */
    ngx_flag_t             registry;        /* brix_oci_registry             */
    ngx_str_t              registry_root;
    size_t                 max_blob;        /* brix_oci_max_blob_size        */
    time_t                 upload_grace;    /* brix_oci_upload_grace         */
    ngx_str_t              token_issuers;   /* brix_oci_token_issuers        */
    ngx_flag_t             registry_anon;   /* _registry_allow_anonymous     */
    ngx_msec_t             gc_interval;     /* brix_oci_gc_interval; 0 = off */
    time_t                 gc_grace;        /* brix_oci_gc_grace             */
    brix_token_registry_t *issuers;         /* built at merge from the above */

    /* ---- built at merge, mirror branch only ---- */
    brix_oci_upstream_t   *up;

    /* Per-worker one-shot: the bearer supplier is attached to the sd_http
     * instance from the REQUEST path, because brix_vfs_backend_resolve()
     * builds instances lazily per worker — there is nothing to attach to at
     * merge time. This flag lives in the (fork-private) location config, so
     * it costs one predictable branch per request and no global. */
    ngx_uint_t             bearer_bound;
} ngx_http_brix_oci_loc_conf_t;

typedef struct {
    brix_oci_req_t             req;         /* classifier output             */
    char                       key[BRIX_OCI_KEY_MAX];  /* canonical route    */
    size_t                     key_len;
    brix_oci_mclass_metric_e   mclass;      /* metric + $oci_class           */
    brix_oci_outcome_metric_e  disp;        /* metric + $oci_cache (J.6)     */
    unsigned                   classified:1;
    unsigned                   keyed:1;
    unsigned                   counted:1;   /* the finalize observer ran     */
    unsigned                   stale:1;     /* served past TTL (J.4)         */

    /* Registry-surface per-request state (oci_upload.c / oci_manifest_put.c),
     * carried here because a body-reading handler is re-entered by nginx with
     * nothing but the request: what the first pass decided to do has to
     * survive the trip. NULL on the mirror surface, which never reads one. */
    void                      *reg;
} ngx_http_brix_oci_ctx_t;

extern ngx_module_t ngx_http_brix_oci_module;

ngx_int_t ngx_http_brix_oci_handler(ngx_http_request_t *r);

/* The floor on brix_oci_gc_interval, enforced at merge time and applied again
 * to the timer's own tick: a sweep that runs more often than once a second is
 * a busy loop over the store, not maintenance. */
#define BRIX_OCI_GC_MIN_INTERVAL  1000

/* The default brix_oci_gc_grace: the window in which an unreferenced blob is
 * assumed to belong to a push whose manifest has not landed yet. An hour is
 * far past the gap between an upload sealing and its manifest PUT, and far
 * short of "the operator will notice the space is still gone" — the same
 * number `brixoci gc` defaults to, because it is the same question. */
#define BRIX_OCI_GC_GRACE_DEFAULT  3600

/* ---- oci_gc.c — the background registry GC (§D15.5) ---------------------- */

/* Record a registry store root for the maintenance timer to sweep. Called at
 * merge time, once per distinct root; an interval of 0 (the default) or a
 * root that is not absolute registers nothing. */
void brix_oci_gc_register(const char *root, ngx_msec_t interval, time_t grace);

/* How many roots were registered — what tells init_process whether there is
 * anything to arm. */
ngx_uint_t brix_oci_gc_registered(void);

/* The cadence the timer runs at: the shortest registered interval, floored at
 * BRIX_OCI_GC_MIN_INTERVAL. Exposed because the arming side and the re-arming
 * side must not compute it differently. */
ngx_msec_t brix_oci_gc_tick_ms(void);

/* Arm the worker-0 sweep timer. A no-op on any other worker, and on every
 * worker when no root was registered. */
void brix_oci_gc_arm_timer(ngx_cycle_t *cycle);

/* ---- oci_errors.c — the §0.7.6 error envelope ---------------------------- */

/* The wire spelling of a spec error code ("MANIFEST_UNKNOWN", …). */
const char *brix_oci_err_code(brix_oci_err_t err);

/* Emit `{"errors":[{"code":…,"message":…,"detail":…}]}` with `status`, the
 * registry API version header, and no cacheable body. `detail` may be NULL.
 * The response is written here, so the return value is the rc the HANDLER
 * must return (NGX_OK / an nginx error rc) — never `status`, which would make
 * the core emit a second, HTML, body over the top of the envelope. */
ngx_int_t brix_oci_error(ngx_http_request_t *r, ngx_uint_t status,
    brix_oci_err_t err, const char *detail);

/* brix_oci_error() for a refusal that has to be recognised as one further up
 * the call chain: identical response, but NGX_DONE (never NGX_OK) when the
 * envelope was written. Callers translate it into their own answer — see the
 * note in oci_errors.c. */
ngx_int_t brix_oci_refuse(ngx_http_request_t *r, ngx_uint_t status,
    brix_oci_err_t err, const char *detail);

/* J.5 errno → HTTP for the read (mirror) surface. */
ngx_uint_t brix_oci_errno_status(ngx_http_request_t *r, int err);

/* ---- oci_gate.c ---------------------------------------------------------- */

/* Method policing + classification + the two locally-answered routes.
 * NGX_DECLINED = a cacheable object route; anything else is terminal. */
ngx_int_t brix_oci_gate(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx);

/* The registry surface's gate: same grammar, no method refusal (a POST is the
 * point here), `/v2/` still answered locally. NGX_DECLINED = an object or
 * upload route for the registry router to dispatch. `uri` is the caller's
 * buffer and must outlive ctx->req, whose spans point into it. */
ngx_int_t brix_oci_registry_gate(ngx_http_request_t *r,
    ngx_http_brix_oci_ctx_t *ctx, char *uri, size_t uri_size);

/* ---- oci_key.c ----------------------------------------------------------- */

/* Build the canonical cache key (§D2.3) for the classified request into
 * ctx->key. NGX_OK, or NGX_HTTP_REQUEST_URI_TOO_LARGE when it would not fit. */
ngx_int_t brix_oci_build_key(ngx_http_brix_oci_loc_conf_t *lcf,
    ngx_http_brix_oci_ctx_t *ctx);

/* ---- oci_meta.c — the `.ocimeta` sidecar (App. B.1) ---------------------- */

typedef struct {
    char    content_type[128];
    char    digest[BRIX_OCI_DIGEST_STRLEN];
    char    etag[128];
    time_t  fetched_at;
    off_t   size;                  /* bytes this record describes            */
    time_t  mtime;                 /* their mtime; 0 = size alone validates  */
    int     verified;
} brix_oci_meta_t;

/* Read/write the sidecar beside the cached body at `body_path`. `size`/`mtime`
 * are the body's own — a memo that does not describe the bytes it sits beside
 * is not a memo, and a tag refilled with a NEW image would otherwise be served
 * under the previous image's digest and media type, so a load whose record
 * disagrees reports NGX_DECLINED (derive again) rather than NGX_OK. An mtime of
 * 0 means "not available here" and validates on size alone, which is the whole
 * truth for a CAS object whose path already names its hash.
 * Read returns NGX_OK / NGX_DECLINED (absent or superseded) / NGX_ERROR;
 * write is staged+renamed. */
ngx_int_t brix_oci_meta_load(const char *body_path, off_t size, time_t mtime,
    brix_oci_meta_t *out, ngx_log_t *log);
ngx_int_t brix_oci_meta_store(const char *body_path, off_t size, time_t mtime,
    brix_oci_meta_t *meta, ngx_log_t *log);

/* ---- oci_tags.c --------------------------------------------------------- */

/* Uncached passthrough of a listing route — GET /v2/<name>/tags/list or GET
 * /v2/<name>/referrers/<digest> — to the upstream, on the thread pool.
 * NGX_DONE when the request was dispatched. */
ngx_int_t brix_oci_listing_passthrough(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx);

/* ---- oci_upstream_auth.c ------------------------------------------------- */

/* Attach the D1 bearer supplier to the http instance beneath `inst` (walking
 * cache decorators down to the "http" driver). Idempotent per worker. */
void brix_oci_bind_bearer(ngx_http_brix_oci_loc_conf_t *lcf,
    brix_sd_instance_t *inst, ngx_log_t *log);

/* Mint (or reuse) a bearer for `challenge` against `up`. Thread-pool context.
 * 0 = token written to tok[toklen]; -1 = the dance failed (fill → 502). */
int brix_oci_token_get(brix_oci_upstream_t *up, const char *path,
    const char *challenge, char *tok, size_t toklen);

#endif /* BRIX_PROTOCOLS_OCI_H */
