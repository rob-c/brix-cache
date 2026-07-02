/*
 * pelican_register.c — advertise this node as a discoverable Pelican cache.
 *
 * Wire details (from PelicanPlatform/pelican):
 *   - POST <director>/api/v1.0/director/registerCache, body = OriginAdvertiseV2
 *     JSON, header "Authorization: Bearer <advertise-JWT>".
 *   - OriginAdvertiseV2 (server_structs/director.go): ServerBaseAd {name,
 *     startTime, instanceID (hex UUID), generationID (monotonic), version,
 *     expiry (RFC3339)} + serverId, registry-prefix "/caches/<sitename>",
 *     data-url (required), web-url, capabilities {PublicRead,Read,Write,Listing,
 *     FallBackRead,Copies}, namespaces[] {Caps,path,token-generation,
 *     token-issuer}, storageType, directorTest, status, now.
 *   - Advertise JWT (origin/advertise.go GetAdTokCfg): iss = server issuer,
 *     sub = this cache's data URL, aud = the Director, scope "pelican.advertise",
 *     lifetime 1 minute, ES256.
 *
 * The per-worker timer offloads each advertisement to the cache thread pool so
 * the blocking discovery+POST never runs on the event loop.
 */

#include "pelican_register.h"
#include "auth/token/jwt_sign.h"
#include "core/ident.h"

#include <ngx_thread_pool.h>
#include <curl/curl.h>
#include <jansson.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <string.h>
#include <time.h>


/* Reusable advertise task (one per worker; reused each tick under in_flight). */
typedef struct {
    ngx_stream_xrootd_srv_conf_t *conf;
    ngx_log_t                    *log;
    ngx_thread_task_t            *task;
    unsigned                      in_flight:1;
    ngx_int_t                     result;
} xrootd_pelican_adv_t;


/* small helpers */
static void
xrootd_pelican_rfc3339(time_t t, char *out, size_t outsz)
{
    struct tm tmv;
    gmtime_r(&t, &tmv);
    (void) strftime(out, outsz, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

static void
xrootd_pelican_hex_random(char *out, size_t nbytes)
{
    unsigned char  raw[20];
    static const char hexd[] = "0123456789abcdef";
    size_t         i;

    if (nbytes > sizeof(raw)) {
        nbytes = sizeof(raw);
    }
    if (RAND_bytes(raw, (int) nbytes) != 1) {
        for (i = 0; i < nbytes; i++) {
            raw[i] = (unsigned char) (ngx_random() & 0xff);
        }
    }
    for (i = 0; i < nbytes; i++) {
        out[i * 2]     = hexd[raw[i] >> 4];
        out[i * 2 + 1] = hexd[raw[i] & 0x0f];
    }
    out[nbytes * 2] = '\0';
}

static const char *
xrootd_pelican_cstr(const ngx_str_t *s, const char *dflt)
{
    return (s != NULL && s->len > 0) ? (const char *) s->data : dflt;
}


/* capabilities object (cache defaults: public read-only serving) */static json_t *
xrootd_pelican_caps_json(void)
{
    json_t *c = json_object();
    if (c == NULL) {
        return NULL;
    }
    json_object_set_new(c, "PublicRead",   json_true());
    json_object_set_new(c, "Read",         json_true());
    json_object_set_new(c, "Write",        json_false());
    json_object_set_new(c, "Listing",      json_true());
    json_object_set_new(c, "FallBackRead", json_true());
    json_object_set_new(c, "Copies",       json_false());
    return c;
}


/* OriginAdvertiseV2 document → compact JSON string (caller free()s) */static char *
xrootd_pelican_build_ad(ngx_stream_xrootd_srv_conf_t *conf, time_t now)
{
    json_t      *ad;
    json_t      *nslist;
    char         expiry[40];
    char         nowstr[40];
    char         regpfx[256];
    const char  *site;
    char        *out;

    ad = json_object();
    if (ad == NULL) {
        return NULL;
    }

    site = xrootd_pelican_cstr(&conf->cache_sitename, "nginx-xrootd-cache");
    xrootd_pelican_rfc3339(now + (time_t) (conf->cache_advertise_interval / 1000)
                           + 30, expiry, sizeof(expiry));
    xrootd_pelican_rfc3339(now, nowstr, sizeof(nowstr));
    (void) snprintf(regpfx, sizeof(regpfx), "/caches/%s", site);

    /* ServerBaseAd (embedded — fields are flattened into the parent object). */
    json_object_set_new(ad, "name", json_string(site));
    json_object_set_new(ad, "startTime", json_integer((json_int_t) now));
    json_object_set_new(ad, "instanceID",
                        json_string(conf->cache_advertise_instance));
    json_object_set_new(ad, "generationID",
                        json_integer((json_int_t) conf->cache_advertise_gen));
    json_object_set_new(ad, "version",
                        json_string(XROOTD_SERVER_NAME " " XROOTD_SERVER_VERSION));
    json_object_set_new(ad, "expiry", json_string(expiry));

    json_object_set_new(ad, "serverId", json_string(site));
    json_object_set_new(ad, "registry-prefix", json_string(regpfx));
    json_object_set_new(ad, "data-url",
        json_string(xrootd_pelican_cstr(&conf->cache_data_url, "")));
    if (conf->cache_web_url.len > 0) {
        json_object_set_new(ad, "web-url",
            json_string((char *) conf->cache_web_url.data));
    }
    json_object_set_new(ad, "capabilities", xrootd_pelican_caps_json());

    /* namespaces[]: the configured prefixes, or "/" (cache everything). */
    nslist = json_array();
    if (nslist != NULL) {
        ngx_uint_t i, n = (conf->cache_advertise_ns != NULL)
                          ? conf->cache_advertise_ns->nelts : 0;
        if (n == 0) {
            json_t *ns = json_object();
            json_object_set_new(ns, "Caps", xrootd_pelican_caps_json());
            json_object_set_new(ns, "path", json_string("/"));
            json_object_set_new(ns, "token-generation", json_array());
            json_object_set_new(ns, "token-issuer", json_array());
            json_array_append_new(nslist, ns);
        } else {
            ngx_str_t *pfx = conf->cache_advertise_ns->elts;
            for (i = 0; i < n; i++) {
                json_t *ns = json_object();
                json_object_set_new(ns, "Caps", xrootd_pelican_caps_json());
                json_object_set_new(ns, "path",
                    json_stringn((char *) pfx[i].data, pfx[i].len));
                json_object_set_new(ns, "token-generation", json_array());
                json_object_set_new(ns, "token-issuer", json_array());
                json_array_append_new(nslist, ns);
            }
        }
    }
    json_object_set_new(ad, "namespaces", nslist);

    json_object_set_new(ad, "storageType", json_string("posix"));
    json_object_set_new(ad, "directorTest", json_true());  /* disable test */
    json_object_set_new(ad, "status", json_string("ok"));
    json_object_set_new(ad, "now", json_string(nowstr));

    out = json_dumps(ad, JSON_COMPACT);
    json_decref(ad);
    return out;                          /* malloc'd; caller free()s */
}


/* advertise JWT (ES256, scope pelican.advertise) */static ngx_int_t
xrootd_pelican_build_jwt(ngx_stream_xrootd_srv_conf_t *conf,
    const char *director, time_t now, char *out, size_t outsz)
{
    json_t   *payload;
    char     *pstr;
    char      jti[48];
    time_t    exp = now + 60;            /* 1-minute lifetime (MinFedTokenTicker) */
    ngx_int_t rc;

    xrootd_pelican_hex_random(jti, 16);

    payload = json_object();
    if (payload == NULL) {
        return NGX_ERROR;
    }
    json_object_set_new(payload, "iss",
        json_string(xrootd_pelican_cstr(&conf->cache_issuer_url,
            xrootd_pelican_cstr(&conf->cache_data_url, ""))));
    json_object_set_new(payload, "sub",
        json_string(xrootd_pelican_cstr(&conf->cache_data_url, "")));
    json_object_set_new(payload, "aud", json_string(director));
    json_object_set_new(payload, "scope", json_string("pelican.advertise"));
    json_object_set_new(payload, "wlcg.ver", json_string("1.0"));
    json_object_set_new(payload, "jti", json_string(jti));
    json_object_set_new(payload, "iat", json_integer((json_int_t) now));
    json_object_set_new(payload, "nbf", json_integer((json_int_t) now));
    json_object_set_new(payload, "exp", json_integer((json_int_t) exp));

    pstr = json_dumps(payload, JSON_COMPACT);
    json_decref(payload);
    if (pstr == NULL) {
        return NGX_ERROR;
    }

    rc = xrootd_jwt_sign_es256((EVP_PKEY *) conf->cache_advertise_key_pkey,
                               "{\"alg\":\"ES256\",\"typ\":\"JWT\"}", pstr,
                               out, outsz);
    free(pstr);
    return rc;
}


/* bounded in-memory GET (discovery) */typedef struct { char *buf; size_t len, cap; } xrootd_pelican_mem2_t;

static size_t
xrootd_pelican_mem2_cb(char *ptr, size_t size, size_t nmemb, void *ud)
{
    xrootd_pelican_mem2_t *m = ud;
    size_t                 n = size * nmemb;
    if (n == 0 || m->len + n > m->cap) {
        return 0;
    }
    ngx_memcpy(m->buf + m->len, ptr, n);
    m->len += n;
    return n;
}

static void
xrootd_pelican_set_ca(ngx_stream_xrootd_srv_conf_t *conf, CURL *curl)
{
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    if (conf->trusted_ca.len > 0) {
        curl_easy_setopt(curl, CURLOPT_CAPATH, (char *) conf->trusted_ca.data);
    }
}

static ngx_int_t
xrootd_pelican_discover_cfg(ngx_stream_xrootd_srv_conf_t *conf, ngx_log_t *log,
    char *out, size_t outsz)
{
    CURL                 *curl;
    CURLcode              res;
    xrootd_pelican_mem2_t mem;
    char                  url[512];
    char                  doc[64 * 1024];
    json_t               *root, *ep;
    json_error_t          jerr;
    const char           *director;
    long                  code = 0;
    int                   n;

    n = snprintf(url, sizeof(url),
                 "https://%s:%u/.well-known/pelican-configuration",
                 (char *) conf->cache_origin_host.data,
                 (unsigned) conf->cache_origin_port);
    if (n < 0 || (size_t) n >= sizeof(url)) {
        return NGX_ERROR;
    }

    curl = curl_easy_init();
    if (curl == NULL) {
        return NGX_ERROR;
    }
    mem.buf = doc; mem.len = 0; mem.cap = sizeof(doc) - 1;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, xrootd_pelican_mem2_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &mem);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long) XROOTD_CACHE_IO_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long) XROOTD_CACHE_IO_TIMEOUT);
    xrootd_pelican_set_ca(conf, curl);

    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    }
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || code < 200 || code >= 300) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "xrootd: pelican advertise: discovery failed (%s, http %ld)",
            curl_easy_strerror(res), code);
        return NGX_ERROR;
    }

    doc[mem.len] = '\0';
    root = json_loads(doc, JSON_REJECT_DUPLICATES, &jerr);
    if (root == NULL) {
        return NGX_ERROR;
    }
    ep = json_object_get(root, "director_endpoint");
    director = json_is_string(ep) ? json_string_value(ep) : NULL;
    if (director == NULL || ngx_strlen(director) >= outsz) {
        json_decref(root);
        return NGX_ERROR;
    }
    ngx_memcpy(out, director, ngx_strlen(director) + 1);
    json_decref(root);
    return NGX_OK;
}


/* POST the advertisement */static ngx_int_t
xrootd_pelican_post(ngx_stream_xrootd_srv_conf_t *conf, ngx_log_t *log,
    const char *director, const char *body, const char *jwt)
{
    CURL              *curl;
    CURLcode           res;
    struct curl_slist *hdrs = NULL;
    char               url[640];
    char               authz[2200];
    long               code = 0;
    int                n;

    n = snprintf(url, sizeof(url),
                 "%s/api/v1.0/director/registerCache", director);
    if (n < 0 || (size_t) n >= sizeof(url)) {
        return NGX_ERROR;
    }

    curl = curl_easy_init();
    if (curl == NULL) {
        return NGX_ERROR;
    }

    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    n = snprintf(authz, sizeof(authz), "Authorization: Bearer %s", jwt);
    if (n > 0 && (size_t) n < sizeof(authz)) {
        hdrs = curl_slist_append(hdrs, authz);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long) XROOTD_CACHE_IO_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long) XROOTD_CACHE_IO_TIMEOUT);
    xrootd_pelican_set_ca(conf, curl);

    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    }
    if (hdrs != NULL) {
        curl_slist_free_all(hdrs);
    }
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || code < 200 || code >= 300) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd: pelican advertise: registerCache POST failed "
            "(%s, http %ld) to %s", curl_easy_strerror(res), code, url);
        return NGX_ERROR;
    }
    ngx_log_error(NGX_LOG_INFO, log, 0,
        "xrootd: pelican advertise: registered cache with director (http %ld)",
        code);
    return NGX_OK;
}


ngx_int_t
xrootd_cache_pelican_advertise_once(ngx_stream_xrootd_srv_conf_t *conf,
    ngx_log_t *log)
{
    char       director[512];
    char       jwt[3072];
    char      *body;
    time_t     now = time(NULL);
    ngx_int_t  rc;

    if (conf->cache_advertise_key_pkey == NULL
        || conf->cache_data_url.len == 0)
    {
        return NGX_ERROR;
    }

    if (xrootd_pelican_discover_cfg(conf, log, director, sizeof(director))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    conf->cache_advertise_gen++;
    body = xrootd_pelican_build_ad(conf, now);
    if (body == NULL) {
        return NGX_ERROR;
    }

    if (xrootd_pelican_build_jwt(conf, director, now, jwt, sizeof(jwt))
        != NGX_OK)
    {
        free(body);
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd: pelican advertise: JWT signing failed");
        return NGX_ERROR;
    }

    rc = xrootd_pelican_post(conf, log, director, body, jwt);
    free(body);
    return rc;
}


/* thread-offloaded periodic timer */
static void
xrootd_pelican_adv_thread(void *data, ngx_log_t *log)
{
    xrootd_pelican_adv_t *a = data;
    a->result = xrootd_cache_pelican_advertise_once(a->conf, log);
}

static void
xrootd_pelican_adv_done(ngx_event_t *ev)
{
    xrootd_pelican_adv_t *a = ev->data;
    a->in_flight = 0;
}

static void
xrootd_pelican_adv_timer(ngx_event_t *ev)
{
    xrootd_pelican_adv_t         *a = ev->data;
    ngx_stream_xrootd_srv_conf_t *conf = a->conf;

    /* Re-arm first so a slow advertisement never stops the cadence. */
    ngx_add_timer(ev, conf->cache_advertise_interval);

    if (a->in_flight || a->task == NULL
        || conf->common.thread_pool == NULL)
    {
        /* No pool or a still-running advertisement: run inline only when there
         * is no thread pool (best-effort; bounded by the curl timeouts). */
        if (conf->common.thread_pool == NULL && !a->in_flight) {
            (void) xrootd_cache_pelican_advertise_once(conf, ev->log);
        }
        return;
    }

    a->in_flight = 1;
    if (ngx_thread_task_post(conf->common.thread_pool, a->task) != NGX_OK) {
        a->in_flight = 0;
    }
}


void
xrootd_cache_pelican_schedule_advertise(ngx_cycle_t *cycle,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_event_t          *ev;
    ngx_thread_task_t    *task;
    xrootd_pelican_adv_t *a;

    if (!conf->cache_advertise || conf->cache_advertise == NGX_CONF_UNSET
        || conf->cache_advertise_key.len == 0
        || conf->cache_data_url.len == 0
        || conf->cache_origin_host.len == 0)
    {
        return;
    }

    /* Load the EC signing key once per worker. */
    conf->cache_advertise_key_pkey =
        xrootd_jwt_load_ec_key((char *) conf->cache_advertise_key.data);
    if (conf->cache_advertise_key_pkey == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
            "xrootd: pelican advertise disabled — cannot load EC key \"%s\"",
            conf->cache_advertise_key.data);
        return;
    }

    if (conf->cache_advertise_instance[0] == '\0') {
        xrootd_pelican_hex_random(conf->cache_advertise_instance, 16);
    }

    task = ngx_thread_task_alloc(cycle->pool, sizeof(xrootd_pelican_adv_t));
    ev = ngx_pcalloc(cycle->pool, sizeof(*ev));
    if (task == NULL || ev == NULL) {
        return;
    }
    a = task->ctx;
    a->conf = conf;
    a->log = cycle->log;
    a->task = task;
    a->in_flight = 0;
    task->handler = xrootd_pelican_adv_thread;
    task->event.handler = xrootd_pelican_adv_done;
    task->event.data = a;

    ev->handler = xrootd_pelican_adv_timer;
    ev->data = a;
    ev->log = cycle->log;
    conf->cache_advertise_timer = ev;

    /* First advertisement shortly after startup, then every interval. */
    ngx_add_timer(ev, 2000);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
        "xrootd: pelican cache advertise started — federation=%s interval=%Mms "
        "data-url=%V", conf->cache_origin_host.data,
        conf->cache_advertise_interval, &conf->cache_data_url);
}
