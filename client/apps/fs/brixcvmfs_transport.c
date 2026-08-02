/*
 * brixcvmfs_transport.c — the CVMFS-brix libcurl fetch seam (Phase-38 split).
 *
 * WHAT: the injected transport the shared cvmfs fetch core calls to pull one
 *       object — DPI/loss-hardened range-resume GETs over a pooled libcurl
 *       handle, the G3 shared-dictionary transfer coding, and the G2
 *       .cvmfs-bundle POST — plus the pool lifecycle helpers.
 * WHY:  split from brixcvmfs.c to keep each TU within the file-size budget;
 *       everything here is "bytes on the wire", owns the transport config and
 *       dict state, and stays entirely separate from catalog/FUSE semantics.
 * HOW:  handles come from the shared brix_cpool (exclusive checkout per
 *       transfer); every per-request option is re-set each call so no state
 *       leaks between borrowers. TRUST stays with the CAS layer — this file
 *       only moves bytes and can at worst fail a fetch, never forge one.
 */
#include <curl/curl.h>

#include "cvmfs/dict/dict.h"
#include "net/proxy_env.h"
#include "brixcvmfs_split.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

/* process-global transport config (type in brixcvmfs_split.h). */
brixcvmfs_transport_cfg_t g_tcfg;

/* ---- libcurl transport (the injected fetch seam) ------------------------ */

typedef struct { unsigned char *buf; size_t cap, len; } curl_sink_t;

static size_t curl_write_cb(char *ptr, size_t sz, size_t nm, void *ud) {
    curl_sink_t *s = ud;
    size_t n = sz * nm;
    if (s->len + n > s->cap) return 0;         /* overflow → curl aborts */
    memcpy(s->buf + s->len, ptr, n);
    s->len += n;
    return n;
}

/* Extract scheme + host + port from a URL for env-proxy resolution. */
static void url_host(const char *url, char *sch, size_t sl, char *host, size_t hl, int *port) {
    sch[0] = host[0] = '\0'; *port = 0;
    const char *p = url;
    const char *sep = strstr(url, "://");
    if (sep) { size_t n = (size_t)(sep - url); if (n < sl) { memcpy(sch, url, n); sch[n] = '\0'; } p = sep + 3; }
    size_t n = 0;
    while (p[n] && p[n] != ':' && p[n] != '/' && n < hl - 1) { host[n] = p[n]; n++; }
    host[n] = '\0';
    *port = (p[n] == ':') ? atoi(p + n + 1) : (strcmp(sch, "https") == 0 ? 443 : 80);
}

/* Persistent easy handles, pooled through the generic brix_cpool (the SAME
 * slot/mutex/condvar engine the xrootdfs root:// and WebDAV-metadata paths use —
 * uniformity across the two FUSE drivers, phase-86). libcurl's connection cache
 * lives on the handle, so keeping handles across fetches is what keeps
 * origin/proxy connections alive (keepalive reuse = fewer handshakes for a DPI
 * middlebox to interfere with). checkout() hands a caller exclusive ownership of
 * one handle for the duration of a transfer (libcurl easy handles are NOT
 * concurrency-safe), so the foreground FUSE loop and the background prefetch
 * worker each borrow their own handle without racing. Every per-request option
 * is re-set on each call below, so no stale request state survives reuse; `-o
 * fresh` still forces a new connection per request. */
#define BRIX_CURL_POOL_SLOTS 4     /* foreground (-s serialized) + prefetch + slack */
static brix_cpool *g_curl_pool;

/* brix_cpool vtable: a slot's opaque conn memory is one CURL* easy handle. */
static int curl_slot_connect(void *conn, void *ctx, brix_status *st) {
    (void) ctx;                                  /* no shared endpoint template */
    CURL *c = curl_easy_init();
    if (c == NULL) { brix_status_set(st, XRDC_EIO, 0, "curl_easy_init failed"); return -1; }
    *(CURL **) conn = c;
    return 0;
}
static void curl_slot_close(void *conn) {
    CURL *c = *(CURL **) conn;
    if (c != NULL) { curl_easy_cleanup(c); *(CURL **) conn = NULL; }
}
static const brix_cpool_vtbl CURL_VT = { sizeof(CURL *), curl_slot_connect, curl_slot_close };

void transport_cleanup(void) {
    if (g_curl_pool != NULL) { brix_cpool_destroy(g_curl_pool); g_curl_pool = NULL; }
}

/* ---- trained shared dictionary, client side (phase-87 G3) --------------- *
 * The proxy may hold a zstd dictionary trained on this repo's small objects
 * (GET <repo>/.cvmfs-dict/current, X-Brix-Dict-Id = sha1 of the bytes). When
 * -o dict / $BRIXCVMFS_DICT=1 is set, the dict is fetched ONCE per mount
 * (memory-pinned; any fetch/verify failure disables the feature for the
 * mount) and every CAS data GET then offers "X-Brix-Dict: <id>"; a response
 * marked "Content-Encoding: zstd-dict" is decoded back to the STORED bytes
 * inside the transport, so the fetch orchestrator's decompress+CAS-verify
 * pipeline sees exactly what an identity response would carry. The id check
 * is transport integrity only — TRUST stays with CAS verify: a hostile dict
 * can only fail decode (zstd dictID mismatch) or produce bytes that fail
 * the content hash; either way the client refetches identity. */

typedef struct {
    int  zstd_dict;                       /* saw Content-Encoding: zstd-dict */
    char id[CVMFS_DICT_ID_HEXLEN + 1];    /* saw X-Brix-Dict-Id (else "")    */
} brix_hdrwatch_t;

/* Case-insensitive "Name: value" header line match; trims OWS + CRLF. */
static int hdr_match(const char *p, size_t n, const char *name,
                     const char **val, size_t *vlen) {
    size_t nl = strlen(name);
    if (n < nl + 1 || strncasecmp(p, name, nl) != 0 || p[nl] != ':') return 0;
    const char *v = p + nl + 1;
    size_t rem = n - nl - 1;
    while (rem && (*v == ' ' || *v == '\t')) { v++; rem--; }
    while (rem && (v[rem-1] == '\r' || v[rem-1] == '\n'
                   || v[rem-1] == ' ' || v[rem-1] == '\t')) rem--;
    *val = v; *vlen = rem;
    return 1;
}

static size_t curl_hdr_cb(char *ptr, size_t sz, size_t nm, void *ud) {
    brix_hdrwatch_t *hw = ud;
    size_t n = sz * nm;
    const char *v; size_t vl;
    if (hdr_match(ptr, n, "content-encoding", &v, &vl)
        && vl == sizeof("zstd-dict") - 1 && strncasecmp(v, "zstd-dict", vl) == 0)
        hw->zstd_dict = 1;
    else if (hdr_match(ptr, n, "x-brix-dict-id", &v, &vl)
             && vl == CVMFS_DICT_ID_HEXLEN) {
        memcpy(hw->id, v, vl);
        hw->id[vl] = '\0';
    }
    return n;
}

/* One GET of `url`, RESUMING from `*got` bytes already in `out` (HTTP Range).
 * Appends new bytes and updates *got. Returns the CURLcode. If a resume request
 * comes back 200 (server ignored Range), the freshly re-sent from-0 bytes are
 * slid to the front so the buffer stays a valid prefix.
 * `dict_id` non-NULL adds "X-Brix-Dict: <id>"; `hw` non-NULL captures the
 * response coding headers. Both are reset on the pooled handle every call so
 * no request state leaks into the next borrower (same lesson as the G2 POST). */
static CURLcode http_get_range(CURL **slot, const char *proxy, const char *url,
                               unsigned char *out, size_t outcap, size_t *got,
                               const char *dict_id, brix_hdrwatch_t *hw) {
    if (*slot == NULL) *slot = curl_easy_init();
    CURL *c = *slot;
    if (c == NULL) return CURLE_FAILED_INIT;

    size_t      start = *got;
    curl_sink_t sink  = { out, outcap, start };   /* append after what we have */
    struct curl_slist *req_hdrs = NULL;
    if (dict_id != NULL) {
        char line[64];
        snprintf(line, sizeof(line), "X-Brix-Dict: %s", dict_id);
        req_hdrs = curl_slist_append(NULL, line);
    }
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &sink);
    /* set-or-clear EVERY call: pooled-handle hygiene */
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_hdrs);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, hw ? curl_hdr_cb : NULL);
    curl_easy_setopt(c, CURLOPT_HEADERDATA, hw);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, g_tcfg.connect_timeout_s);
    curl_easy_setopt(c, CURLOPT_LOW_SPEED_LIMIT, g_tcfg.low_speed_bytes);
    curl_easy_setopt(c, CURLOPT_LOW_SPEED_TIME, g_tcfg.low_speed_time_s);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_FAILONERROR, 1L);         /* HTTP >=400 → error */
    curl_easy_setopt(c, CURLOPT_TCP_KEEPALIVE, 1L);
    /* Confine the transport to HTTP(S) for BOTH the first request and every
     * redirect it follows. A poisoned mirror or a DPI middlebox can answer any
     * request with a 3xx to file:///etc/passwd, an internal metadata IP
     * (169.254.169.254), scp://, gopher://, … — FOLLOWLOCATION would chase it.
     * The CAS layer hash-verifies content so a wrong body is caught, but that is
     * no help if the redirect makes libcurl read a LOCAL file or poke an
     * internal service in the first place: confine the scheme up front and cap
     * the chain so a redirect loop can't wedge the mount either. Bitmask form
     * (not the 7.85+ *_STR opts) for alma8-era libcurl portability. */
    curl_easy_setopt(c, CURLOPT_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
    curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
    curl_easy_setopt(c, CURLOPT_MAXREDIRS, 4L);
    /* TLS is defence-in-depth here (CVMFS content self-authenticates), but when
     * a user asks for -o tls we must fail CLOSED against a MITM / intercepting
     * DPI proxy rather than silently accept a forged cert. This restates
     * libcurl's own default so a future edit can't quietly relax it. */
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
    /* Reused handle: set these unconditionally so a prior request's resume
     * offset / freshness flags can never leak into this one. */
    curl_easy_setopt(c, CURLOPT_RESUME_FROM_LARGE, (curl_off_t) start);
    curl_easy_setopt(c, CURLOPT_FRESH_CONNECT, g_tcfg.fresh_connect ? 1L : 0L);
    curl_easy_setopt(c, CURLOPT_FORBID_REUSE, g_tcfg.fresh_connect ? 1L : 0L);
    /* Proxy precedence: env proxy wins; else CVMFS-config proxy; else force direct. */
    char sch[8], thost[256]; int tport;
    url_host(url, sch, sizeof(sch), thost, sizeof(thost), &tport);
    brix_proxy_t px;
    if (brix_proxy_resolve(sch, thost, tport, &px)) {
        curl_easy_setopt(c, CURLOPT_PROXY, px.url);
        brix_proxy_report(&px, thost, tport);
    } else if (proxy != NULL && strcmp(proxy, "DIRECT") != 0) {
        curl_easy_setopt(c, CURLOPT_PROXY, proxy);
    } else {
        curl_easy_setopt(c, CURLOPT_PROXY, "");
    }

    CURLcode rc = curl_easy_perform(c);
    if (req_hdrs != NULL) {
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, NULL);   /* before the free */
        curl_slist_free_all(req_hdrs);
    }
    long code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    if (start > 0 && code != 206 && sink.len > start) {
        /* Range not honoured (200): the bytes appended after `start` are actually
         * a fresh stream from offset 0 — slide them to the front. */
        size_t fresh = sink.len - start;
        memmove(out, out + start, fresh);
        *got = fresh;
    } else {
        *got = sink.len;
    }
    return rc;
}

/* Rewrite an http:// url to https:// into `buf`; returns 1 if rewritten. */
static int to_https(const char *url, char *buf, size_t n) {
    if (strncmp(url, "http://", 7) != 0) return 0;
    snprintf(buf, n, "https://%s", url + 7);
    return 1;
}

/* Mount-lifetime dict state (see the G3 block comment above curl_hdr_cb). */
typedef struct {
    int             mode;    /* 0=off · 1=armed (fetch on first data GET)
                                · 2=ready · -1=disabled for this mount */
    pthread_mutex_t mu;
    char            id[CVMFS_DICT_ID_HEXLEN + 1];
    unsigned char  *bytes;   /* malloc'd, memory-pinned until unmount */
    size_t          len;
} brix_dict_state_t;

static brix_dict_state_t g_dict = { 0, PTHREAD_MUTEX_INITIALIZER, "", NULL, 0 };

/* One-shot dict pull + self-certification (sha1(body) == X-Brix-Dict-Id).
 * Any failure means "this mount runs identity" — never retried, so a dead
 * or dict-less proxy costs exactly one extra GET per mount. */
static int brix_dict_fetch(CURL **slot, const char *proxy, const char *host) {
    char url[1024];
    snprintf(url, sizeof(url), "%s/.cvmfs-dict/current", host);
    unsigned char *buf = malloc(CVMFS_DICT_MAX_BYTES);
    if (buf == NULL) return -1;
    size_t got = 0;
    brix_hdrwatch_t hw; memset(&hw, 0, sizeof(hw));
    char myid[CVMFS_DICT_ID_HEXLEN + 1];
    if (http_get_range(slot, proxy, url, buf, CVMFS_DICT_MAX_BYTES, &got,
                       NULL, &hw) != CURLE_OK
        || got == 0
        || strlen(hw.id) != CVMFS_DICT_ID_HEXLEN
        || cvmfs_dict_id(buf, got, myid) != 0
        || memcmp(myid, hw.id, CVMFS_DICT_ID_HEXLEN) != 0)
    {
        free(buf);
        return -1;
    }
    g_dict.bytes = buf;
    g_dict.len   = got;
    memcpy(g_dict.id, myid, sizeof(myid));
    return 0;
}

/* Armed → fetch once (serialized; losers of the race reuse the outcome).
 * Returns 1 iff a verified dict is ready for use. */
static int brix_dict_ensure(CURL **slot, const char *proxy, const char *host) {
    int ready;
    pthread_mutex_lock(&g_dict.mu);
    if (g_dict.mode == 1) {
        g_dict.mode = (brix_dict_fetch(slot, proxy, host) == 0) ? 2 : -1;
        fprintf(stderr, "brixcvmfs: dict %s%s\n",
                g_dict.mode == 2 ? "ready id=" : "disabled (no verified "
                ".cvmfs-dict/current — serving identity)",
                g_dict.mode == 2 ? g_dict.id : "");
    }
    ready = (g_dict.mode == 2);
    pthread_mutex_unlock(&g_dict.mu);
    return ready;
}

/* G3: offer the dict on CAS data GETs only (never manifests/catalog
 * fetches — those exceed the size class and the server declines anyway).
 * Lazily pulls .cvmfs-dict/current on the first qualifying fetch. */
static int brix_dict_offer(CURL **slot, const char *proxy, const char *host,
                           const char *rel) {
    return (g_dict.mode != 0 && g_dict.mode != -1
            && strncmp(rel, "data/", 5) == 0)
           ? brix_dict_ensure(slot, proxy, host) : 0;
}

/* dict-coded body → decode back to the STORED bytes in place. Failure
 * (wrong/hostile dict, truncation, overflow) is never fatal: the caller
 * drops the dict for THIS fetch and pulls identity. */
static int brix_dict_decode(unsigned char *out, size_t outcap, size_t got,
                            size_t *outlen) {
    unsigned char *dec = malloc(outcap);
    size_t         dlen = 0;
    if (dec != NULL
        && cvmfs_dict_decompress(g_dict.bytes, g_dict.len,
                                 out, got, dec, outcap, &dlen) == 0)
    {
        memcpy(out, dec, dlen);
        free(dec);
        *outlen = dlen;
        return 0;
    }
    free(dec);
    return -1;
}

/* First attempt may probe https when prefer_tls is set; every later attempt
 * (and non-TLS configs) uses the plain http mirror URL. */
static const char *transport_url(int first, const char *httpurl,
                                 char *httpsbuf, size_t cap, int *use_https) {
    *use_https = (first && g_tcfg.prefer_tls
                  && to_https(httpurl, httpsbuf, cap));
    return *use_https ? httpsbuf : httpurl;
}

/* Classify one attempt's outcome. 1 = done (*outlen set), -1 = hard failure
 * (fail over to the next mirror), 2 = retry immediately (identity refetch
 * after a dict drop, no backoff), 0 = retry via the stall budget. */
static int transport_after(CURLcode rc, int use_https, const brix_hdrwatch_t *hw,
                           int *dict_on, unsigned char *out, size_t outcap,
                           size_t *got, size_t *last, size_t *outlen) {
    if (rc == CURLE_OK && *dict_on && hw->zstd_dict) {
        if (brix_dict_decode(out, outcap, *got, outlen) == 0) return 1;
        *dict_on = 0; *got = 0; *last = 0;
        return 2;                               /* identity refetch, no backoff */
    }
    if (rc == CURLE_OK) { *outlen = *got; return 1; }

    /* A dict-coded response is not resumable (an identity 206 cannot
     * continue a coded prefix): restart the object from 0. */
    if (*dict_on && *got > 0) { *got = 0; *last = 0; }

    /* hard 4xx over plain http = mirror lacks the object → fail over. A 4xx on
     * the https probe just means no TLS — fall through to http. */
    if (rc == CURLE_HTTP_RETURNED_ERROR && !use_https) return -1;

    /* Range-blind server: libcurl aborts a resumed request answered 200 with
     * CURLE_RANGE_ERROR before any body byte reaches the sink, so resume can
     * never progress there — throw away the partial prefix and restart the
     * whole object from 0 (the fetch layer's hash check keeps this safe). */
    if (rc == CURLE_RANGE_ERROR) { *got = 0; *last = 0; }

    return 0;
}

/* Progress bookkeeping between attempts. -1 = stall budget exhausted. */
static int transport_stall(size_t got, size_t *last, int *stalls, int budget) {
    if (got > *last) { *last = got; *stalls = 0; }   /* progress → keep resuming */
    else if (++*stalls > budget) return -1;          /* no progress → give up route */

    long ms = 200L << (*stalls < 6 ? *stalls : 6);   /* backoff on stalls only */
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
    return 0;
}

/* DPI/loss-hardened transport: RANGE-RESUME on a severed transfer (so a large
 * object survives per-chunk connection loss — the key to 10%+ loss), optional
 * TLS-first, optional fresh-connection. As long as each attempt makes progress
 * (more bytes received) we keep resuming up to a generous cap; only attempts that
 * make NO progress count against the retry budget. Across-mirror failover +
 * hash-verify are owned by the fetch layer. */
int brixcvmfs_transport(const char *proxy, const char *host, const char *rel,
                               unsigned char *out, size_t outcap, size_t *outlen, void *ud) {
    (void) ud;                                    /* handles now come from g_curl_pool */
    brix_status st; brix_status_clear(&st);
    CURL **slot = brix_cpool_checkout(g_curl_pool, &st);  /* CURL** == the classic slot */
    if (slot == NULL) return -1;

    char httpurl[1024];
    snprintf(httpurl, sizeof(httpurl), "%s/%s", host, rel);

    int    budget  = g_tcfg.max_retries > 0 ? g_tcfg.max_retries : 6;
    int    hard_cap = 64;                 /* absolute ceiling on resume attempts */
    int    stalls  = 0;
    size_t got = 0, last = 0;
    int    ret = -1;
    int    dict_on = brix_dict_offer(slot, proxy, host, rel);

    for (int i = 0; i < hard_cap; i++) {
        char httpsbuf[1024];
        int  use_https = 0;
        const char *url = transport_url(i == 0, httpurl, httpsbuf,
                                        sizeof(httpsbuf), &use_https);

        brix_hdrwatch_t hw; memset(&hw, 0, sizeof(hw));
        CURLcode rc = http_get_range(slot, proxy, url, out, outcap, &got,
                                     (dict_on && got == 0) ? g_dict.id : NULL,
                                     dict_on ? &hw : NULL);
        int act = transport_after(rc, use_https, &hw, &dict_on, out, outcap,
                                  &got, &last, outlen);
        if (act == 1) { ret = 0; break; }
        if (act == -1) break;
        if (act == 2) continue;
        if (transport_stall(got, &last, &stalls, budget) != 0) break;
    }
    /* A libcurl easy handle stays healthy across transfers (it owns its own
     * connection cache and re-establishes internally), so always check it back
     * in reusable — never health-drop. */
    brix_cpool_checkin(g_curl_pool, slot, 1);
    return ret;
}

/* One bundle POST (phase-87 G2): want-list body up, framed reply down. Single
 * attempt, no retry — the caller treats ANY failure as "no bundle" and the
 * per-item fetch path does the real work. The pooled easy handle is shared
 * with GET users, so POST mode is reverted before check-in. */
int bundle_http_post(const char *proxy, const char *host,
                            const char *body, size_t body_len,
                            unsigned char *out, size_t outcap, size_t *outlen) {
    brix_status st; brix_status_clear(&st);
    CURL **slot = brix_cpool_checkout(g_curl_pool, &st);
    if (slot == NULL) return -1;
    if (*slot == NULL) *slot = curl_easy_init();
    CURL *c = *slot;
    int ret = -1;

    if (c != NULL) {
        char url[1024];
        snprintf(url, sizeof(url), "%s/.cvmfs-bundle", host);
        curl_sink_t sink = { out, outcap, 0 };
        curl_easy_setopt(c, CURLOPT_URL, url);
        curl_easy_setopt(c, CURLOPT_POST, 1L);
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) body_len);
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_write_cb);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &sink);
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, g_tcfg.connect_timeout_s);
        curl_easy_setopt(c, CURLOPT_LOW_SPEED_LIMIT, g_tcfg.low_speed_bytes);
        curl_easy_setopt(c, CURLOPT_LOW_SPEED_TIME, g_tcfg.low_speed_time_s);
        curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);   /* no redirected POSTs */
        curl_easy_setopt(c, CURLOPT_FAILONERROR, 1L);
        curl_easy_setopt(c, CURLOPT_PROTOCOLS,
                         (long) (CURLPROTO_HTTP | CURLPROTO_HTTPS));
        curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS,
                         (long) (CURLPROTO_HTTP | CURLPROTO_HTTPS));
        curl_easy_setopt(c, CURLOPT_RESUME_FROM_LARGE, (curl_off_t) 0);
        char sch[8], thost[256]; int tport;
        url_host(url, sch, sizeof(sch), thost, sizeof(thost), &tport);
        brix_proxy_t px;
        if (brix_proxy_resolve(sch, thost, tport, &px))
            curl_easy_setopt(c, CURLOPT_PROXY, px.url);
        else if (proxy != NULL && strcmp(proxy, "DIRECT") != 0)
            curl_easy_setopt(c, CURLOPT_PROXY, proxy);
        else
            curl_easy_setopt(c, CURLOPT_PROXY, "");

        CURLcode rc = curl_easy_perform(c);
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, NULL);   /* body ptr dies with us */
        curl_easy_setopt(c, CURLOPT_HTTPGET, 1L);        /* back to GET for the pool */
        if (rc == CURLE_OK) { *outlen = sink.len; ret = 0; }
    }
    brix_cpool_checkin(g_curl_pool, slot, 1);
    return ret;
}


/* Bring the shared libcurl-handle pool up (mount-time). Encapsulates the pool
 * vtable + slot count so the mount pipeline never names the transport's
 * internals. 0 = ready, -1 = init failed (*st carries the reason). */
int brixcvmfs_transport_pool_init(brix_status *st) {
    g_curl_pool = brix_cpool_create(&CURL_VT, NULL, BRIX_CURL_POOL_SLOTS, st);
    return g_curl_pool != NULL ? 0 : -1;
}

/* G3 dict lifecycle: the mount arms it here; the dict itself is pulled lazily
 * on the first qualifying CAS data GET (brix_dict_offer). */
void brixcvmfs_dict_arm(void)  { g_dict.mode = 1; }
void brixcvmfs_dict_free(void) { free(g_dict.bytes); g_dict.bytes = NULL; g_dict.len = 0; }
