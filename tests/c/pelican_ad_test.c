/*
 * pelican_ad_test.c — unit test for the Pelican OriginAdvertiseV2 payload
 * builders in src/fs/cache/origin/pelican_register.c (brix_pelican_build_ad /
 * _caps_json / _rfc3339).
 *
 * Links the real production object (no reimplementation) and drives the three
 * exposed builders against synthetic advertise config, parsing the emitted
 * document back with jansson to assert wire conformance. This closes the
 * *buildable* half of the Pelican cache-registration path: the federation POST
 * needs a live Director and an out-of-band registry key handshake (operator
 * step — not testable here), but the advertisement JSON and its RFC3339
 * timestamps are constructed deterministically and MUST be conformance-checked
 * without one.
 *
 * pelican_register.o's non-libc/jansson deps are the JWT minters (never called
 * here — the advertise-JWT path is separate) plus the per-worker timer/thread
 * machinery (never entered — we only call the pure builders); all are stubbed
 * below so the object links. ngx_pcalloc is malloc-backed and the process exits
 * right after, so nothing is freed on the nginx pool path.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_thread_pool.h>

#include <jansson.h>
#include <string.h>
#include <stdio.h>

#include "fs/cache/origin/pelican_register.h"
#include "auth/token/jwt_sign.h"

/* --- link stubs: symbols pelican_register.o references but the pure builders
 *     never reach (whole-object linking still needs them resolved). --- */

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return calloc(1, size);
}

volatile ngx_msec_t  ngx_current_msec;
ngx_rbtree_t         ngx_event_timer_rbtree;

void
ngx_rbtree_insert(ngx_rbtree_t *tree, ngx_rbtree_node_t *node)
{
    (void) tree; (void) node;
}

void
ngx_rbtree_delete(ngx_rbtree_t *tree, ngx_rbtree_node_t *node)
{
    (void) tree; (void) node;
}

ngx_thread_task_t *
ngx_thread_task_alloc(ngx_pool_t *pool, size_t size)
{
    (void) pool; (void) size;
    return NULL;
}

ngx_int_t
ngx_thread_task_post(ngx_thread_pool_t *tp, ngx_thread_task_t *task)
{
    (void) tp; (void) task;
    return NGX_ERROR;
}

/* JWT minters — declared in jwt_sign.h; the advertise-token path is not under
 * test here, so they are stubbed to fail closed. */
EVP_PKEY *
brix_jwt_load_ec_key(const char *pem_path)
{
    (void) pem_path;
    return NULL;
}

ngx_int_t
brix_jwt_sign_es256(EVP_PKEY *eckey, const char *header_json,
    const char *payload_json, char *out, size_t outsz)
{
    (void) eckey; (void) header_json; (void) payload_json; (void) out; (void) outsz;
    return NGX_ERROR;
}


/* --- test scaffolding ------------------------------------------------------ */

static int failures;

#define CHECK(cond, msg) do {                                               \
        if (!(cond)) { printf("FAIL: %s\n", (msg)); failures++; }           \
    } while (0)

static ngx_str_t
S(const char *s)
{
    ngx_str_t v;
    v.data = (u_char *) s;
    v.len  = strlen(s);
    return v;
}

/* A cache's public read-only capability contract (origin/advertise.go): a cache
 * MUST advertise read/listing but never write — routing a write to a read-only
 * cache would be a data-integrity hole, so Write/Copies staying false is the
 * security-relevant assertion, not incidental. */
static void
check_cache_caps(json_t *caps, const char *where)
{
    CHECK(json_is_object(caps), where);
    CHECK(json_is_true(json_object_get(caps, "PublicRead")),   "caps.PublicRead true");
    CHECK(json_is_true(json_object_get(caps, "Read")),         "caps.Read true");
    CHECK(json_is_true(json_object_get(caps, "Listing")),      "caps.Listing true");
    CHECK(json_is_true(json_object_get(caps, "FallBackRead")), "caps.FallBackRead true");
    CHECK(json_is_false(json_object_get(caps, "Write")),       "caps.Write MUST be false");
    CHECK(json_is_false(json_object_get(caps, "Copies")),      "caps.Copies false");
}

static const char *
jstr(json_t *obj, const char *key)
{
    return json_string_value(json_object_get(obj, key));
}

/* A fixed epoch keeps the RFC3339 output deterministic (independent of the host
 * clock — which on this dev box steps backwards): 1735689600 = 2025-01-01Z. */
#define NOW      ((time_t) 1735689600)
#define NOW_STR  "2025-01-01T00:00:00Z"


int
main(void)
{
    ngx_stream_brix_srv_conf_t  conf;
    char                        ts[40];
    char                       *doc;
    json_t                     *ad;
    json_error_t                jerr;

    /* --- brix_pelican_rfc3339: deterministic UTC RFC3339 --- */
    brix_pelican_rfc3339(NOW, ts, sizeof(ts));
    CHECK(strcmp(ts, NOW_STR) == 0, "rfc3339(2025-01-01)");
    brix_pelican_rfc3339((time_t) 0, ts, sizeof(ts));
    CHECK(strcmp(ts, "1970-01-01T00:00:00Z") == 0, "rfc3339(epoch)");

    /* --- brix_pelican_caps_json: the cache capability contract (security) --- */
    {
        json_t *caps = brix_pelican_caps_json();
        check_cache_caps(caps, "caps_json is an object");
        json_decref(caps);
    }

    /* --- brix_pelican_build_ad happy path: default namespace ("/" == cache
     *     everything, ns unset). Parse the emitted document back and assert the
     *     full OriginAdvertiseV2 shape the Director consumes. --- */
    memset(&conf, 0, sizeof(conf));
    conf.advertise.sitename = S("MyCache");
    conf.advertise.data_url = S("https://cache.example.org:8443");
    conf.advertise.web_url  = S("https://cache.example.org:8444");
    conf.advertise.interval = 60000;                 /* 60s → expiry now+60+30 */
    conf.advertise.gen      = 7;
    memcpy(conf.advertise.instance, "deadbeefcafef00d", sizeof("deadbeefcafef00d"));
    conf.advertise.ns       = NULL;                  /* → single "/" namespace */

    doc = brix_pelican_build_ad(&conf, NOW);
    CHECK(doc != NULL, "build_ad returns a document");
    ad = doc ? json_loads(doc, 0, &jerr) : NULL;
    CHECK(ad != NULL && json_is_object(ad), "build_ad emits a JSON object");

    if (ad != NULL) {
        json_t *ns, *ns0;

        CHECK(strcmp(jstr(ad, "name"), "MyCache") == 0, "name = sitename");
        CHECK(strcmp(jstr(ad, "serverId"), "MyCache") == 0, "serverId = sitename");
        CHECK(strcmp(jstr(ad, "registry-prefix"), "/caches/MyCache") == 0,
              "registry-prefix = /caches/<site>");
        CHECK(strcmp(jstr(ad, "data-url"),
                     "https://cache.example.org:8443") == 0, "data-url verbatim");
        CHECK(strcmp(jstr(ad, "web-url"),
                     "https://cache.example.org:8444") == 0, "web-url verbatim");
        CHECK(strcmp(jstr(ad, "storageType"), "posix") == 0, "storageType posix");
        CHECK(strcmp(jstr(ad, "status"), "ok") == 0, "status ok");
        CHECK(json_is_true(json_object_get(ad, "directorTest")), "directorTest true");
        CHECK(strcmp(jstr(ad, "instanceID"), "deadbeefcafef00d") == 0,
              "instanceID carried");
        CHECK(json_integer_value(json_object_get(ad, "generationID")) == 7,
              "generationID carried");
        CHECK(json_integer_value(json_object_get(ad, "startTime")) == (json_int_t) NOW,
              "startTime = now");
        CHECK(strncmp(jstr(ad, "version"), "BriX-Cache", 10) == 0,
              "version starts with server name");
        CHECK(strcmp(jstr(ad, "now"), NOW_STR) == 0, "now = rfc3339(now)");
        CHECK(strcmp(jstr(ad, "expiry"), "2025-01-01T00:01:30Z") == 0,
              "expiry = now + interval + 30s");

        check_cache_caps(json_object_get(ad, "capabilities"), "top-level capabilities");

        ns = json_object_get(ad, "namespaces");
        CHECK(json_is_array(ns) && json_array_size(ns) == 1,
              "default → exactly one namespace");
        ns0 = json_array_get(ns, 0);
        CHECK(ns0 && strcmp(jstr(ns0, "path"), "/") == 0, "default namespace path /");
        check_cache_caps(json_object_get(ns0, "Caps"), "default namespace Caps");
        CHECK(json_is_array(json_object_get(ns0, "token-generation")),
              "token-generation is an array");
        CHECK(json_is_array(json_object_get(ns0, "token-issuer")),
              "token-issuer is an array");

        json_decref(ad);
    }
    free(doc);

    /* --- configured-namespace branch: an ngx_array_t of prefixes maps 1:1 to
     *     namespace entries (hand-built array — build_ad only reads it). --- */
    {
        ngx_str_t    prefixes[2];
        ngx_array_t  arr;

        prefixes[0] = S("/foo");
        prefixes[1] = S("/bar/baz");
        memset(&arr, 0, sizeof(arr));
        arr.elts   = prefixes;
        arr.nelts  = 2;
        arr.size   = sizeof(ngx_str_t);
        arr.nalloc = 2;
        conf.advertise.ns = &arr;

        doc = brix_pelican_build_ad(&conf, NOW);
        CHECK(doc != NULL, "build_ad (configured ns) returns a document");
        ad = doc ? json_loads(doc, 0, &jerr) : NULL;
        CHECK(ad != NULL, "build_ad (configured ns) parses");
        if (ad != NULL) {
            json_t *ns = json_object_get(ad, "namespaces");
            CHECK(json_array_size(ns) == 2, "two configured namespaces");
            CHECK(strcmp(jstr(json_array_get(ns, 0), "path"), "/foo") == 0,
                  "namespace[0] = /foo");
            CHECK(strcmp(jstr(json_array_get(ns, 1), "path"), "/bar/baz") == 0,
                  "namespace[1] = /bar/baz");
            json_decref(ad);
        }
        free(doc);
        conf.advertise.ns = NULL;
    }

    /* --- robustness / negative: an unset data-url must emit an empty string,
     *     never a fabricated URL or a crash (the Director rejects it, but the
     *     builder must fail soft, not invent an endpoint). --- */
    {
        ngx_str_t empty = { 0, NULL };
        conf.advertise.data_url = empty;
        doc = brix_pelican_build_ad(&conf, NOW);
        CHECK(doc != NULL, "build_ad (no data-url) still builds");
        ad = doc ? json_loads(doc, 0, &jerr) : NULL;
        CHECK(ad != NULL, "build_ad (no data-url) parses");
        if (ad != NULL) {
            const char *du = jstr(ad, "data-url");
            CHECK(du != NULL && du[0] == '\0', "absent data-url → empty string");
            json_decref(ad);
        }
        free(doc);
    }

    if (failures) {
        printf("pelican_ad_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("pelican_ad_test: all checks passed\n");
    return 0;
}
