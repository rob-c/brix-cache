/* fetch.c — CVMFS content-addressed fetch orchestrator. See fetch.h. */
#include "cvmfs/fetch/fetch.h"
#include "cvmfs/object/object.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* The cache holds VERIFIED PLAINTEXT, whose bytes do NOT hash to the object's
 * name for compressed objects (the name covers the stored/compressed form). So
 * each entry gets an integrity SIDECAR ("<key>.chk": plaintext hash + length)
 * written at store time, and every cache hit is re-verified against it — local
 * bit-rot, tampering, or truncation turns the hit into a miss + refetch instead
 * of serving damaged bytes forever. */

static void sidecar_key(const char *key, char *buf, size_t n) {
    snprintf(buf, n, "%s.chk", key);
}

/* "<hex-plaintext-hash> <len>\n" for the sidecar; -1 if it can't be built. */
static int sidecar_body(cvmfs_hash_algo_e algo, const unsigned char *plain, size_t len,
                        char *buf, size_t n) {
    cvmfs_hash_t self;
    char         hex[160];
    if (cvmfs_object_hash(algo, plain, len, &self) != 0) return -1;
    if (cvmfs_hash_to_hex(&self, 0, hex, sizeof(hex)) < 0) return -1;
    int w = snprintf(buf, n, "%s %zu\n", hex, len);
    return (w < 0 || (size_t) w >= n) ? -1 : w;
}

/* Store verified plaintext + its integrity sidecar. Best-effort: a failed
 * sidecar put just means the entry re-verifies as a miss later. */
static void cache_put_verified(brix_cas_store_t *cache, const char *key,
                               cvmfs_hash_algo_e algo,
                               const unsigned char *plain, size_t len) {
    char skey[176], body[192];
    int  blen;
    brix_cas_put(cache, key, plain, len);
    sidecar_key(key, skey, sizeof(skey));
    blen = sidecar_body(algo, plain, len, body, sizeof(body));
    if (blen > 0) brix_cas_put(cache, skey, body, (size_t) blen);
}

/* Serve a cache hit: read the entry, then re-verify it against its sidecar.
 * Returns 0 verified, -3 out too small, -1 damaged/unverifiable (caller purges
 * and refetches — entries from before the sidecar era land here once). */
static int serve_from_cache(brix_cas_store_t *cache, const char *key,
                            cvmfs_hash_algo_e algo,
                            unsigned char *out, size_t outcap, size_t *outlen) {
    int fd = brix_cas_open(cache, key);
    if (fd < 0) return -1;

    size_t off = 0;
    for (;;) {
        if (off == outcap) { close(fd); return -3; }     /* out too small */
        ssize_t r = read(fd, out + off, outcap - off);
        if (r < 0) { if (errno == EINTR) continue; close(fd); return -1; }
        if (r == 0) break;
        off += (size_t) r;
    }
    close(fd);

    char skey[176], want[192], got[192];
    sidecar_key(key, skey, sizeof(skey));
    int sfd = brix_cas_open(cache, skey);
    if (sfd < 0) return -1;                              /* no sidecar → unverifiable */
    ssize_t sn = read(sfd, want, sizeof(want) - 1);
    close(sfd);
    if (sn <= 0) return -1;
    want[sn] = '\0';

    if (sidecar_body(algo, out, off, got, sizeof(got)) < 0) return -1;
    if (strcmp(want, got) != 0) return -1;               /* damaged entry */

    *outlen = off;
    return 0;
}

/* Purge a damaged/unverifiable entry (and its sidecar) so the refetch's put
 * stores fresh bytes instead of hitting the immutable-if-present fast path. */
static void cache_purge(brix_cas_store_t *cache, const char *key) {
    char skey[176];
    sidecar_key(key, skey, sizeof(skey));
    brix_cas_del(cache, key);
    brix_cas_del(cache, skey);
}

/* Turn a fetched object into verified plaintext in `out`.
 *
 * A CVMFS object's content hash (its name) is over the STORED bytes — i.e. the
 * compressed form for a compressed object (verified empirically against real
 * atlas.cern.ch catalogs/certs). So we hash-verify the raw fetched bytes FIRST,
 * then decompress; a mangled/poisoned reply fails the hash and is retried
 * elsewhere. Decompression of the verified bytes is deterministic, so the
 * plaintext is authentic without a second hash. */
static int decode_and_verify(cvmfs_fetch_ctx_t *ctx, const cvmfs_hash_t *hash,
                             const unsigned char *raw, size_t rawlen,
                             unsigned char *out, size_t outcap, size_t *outlen) {
    if (!cvmfs_object_verify(raw, rawlen, hash)) return -1;   /* stored-form hash */

    if (ctx->store_form == CVMFS_STORE_PLAIN) {
        if (rawlen > outcap) return -3;
        memcpy(out, raw, rawlen);
        *outlen = rawlen;
        return 0;
    }
    /* compressed: inflate; if the authentic bytes are not actually zlib (some
     * objects are stored uncompressed even in a zlib repo), serve them raw. */
    if (cvmfs_object_inflate(raw, rawlen, out, outcap, outlen) != 0) {
        if (rawlen > outcap) return -3;
        memcpy(out, raw, rawlen);
        *outlen = rawlen;
    }
    return 0;
}

int cvmfs_fetch_object(cvmfs_fetch_ctx_t *ctx, const cvmfs_hash_t *hash, char suffix,
                       unsigned char *out, size_t outcap, size_t *outlen, long now) {
    char key[160];
    if (cvmfs_hash_to_hex(hash, suffix, key, sizeof(key)) < 0) return -1;

    /* 1. cache-first (plaintext, verified at store time AND re-verified against
     * its integrity sidecar on every hit). A damaged/truncated/unverifiable entry
     * is purged and falls through to a normal network refetch. */
    if (brix_cas_has(ctx->cache, key)) {
        int crc = serve_from_cache(ctx->cache, key, hash->algo, out, outcap, outlen);
        if (crc == 0 || crc == -3) return crc;
        cache_purge(ctx->cache, key);
    }

    /* 2. fetch with mirror-agnostic, hash-verified retry. */
    char rel[200];
    {
        char obj[160];
        if (cvmfs_hash_to_object_path(hash, suffix, obj, sizeof(obj)) < 0) return -1;
        snprintf(rel, sizeof(rel), "data/%s", obj);
    }

    /* Two nested loops: fail OVER across mirrors, and within each mirror retry a
     * few times on a corrupt-but-complete reply BEFORE blacklisting. The inner
     * retry is what survives a byte-mangling DPI on a SINGLE path — blacklisting
     * the only mirror on the first corruption would drop straight to offline. The
     * inner loop is bounded, so a persistently-poisoned mirror still gets
     * blacklisted and failed over (hash-verify means a bad reply is never used). */
    unsigned per_route = ctx->max_attempts ? ctx->max_attempts : 6;
    size_t   mirrors   = ctx->fo->n_hosts + 1;            /* failover breadth */

    for (size_t m = 0; m < mirrors; m++) {
        cvmfs_fo_route_t route;
        if (cvmfs_failover_select(ctx->fo, now, &route) != 0)
            return -2;                                    /* offline */

        const char *proxy = route.proxy >= 0 ? ctx->fo->proxies[route.proxy].url : NULL;
        const char *host  = ctx->fo->hosts[route.host].url;

        for (unsigned k = 0; k < per_route; k++) {
            size_t rawlen = 0;
            int tr = ctx->transport(proxy, host, rel, ctx->scratch, ctx->scratch_cap,
                                    &rawlen, ctx->transport_ud);
            if (tr != 0) break;                           /* transport dead → next mirror */

            if (decode_and_verify(ctx, hash, ctx->scratch, rawlen, out, outcap, outlen) == 0) {
                cvmfs_failover_record(ctx->fo, &route, 1, 1 /*rtt*/, now);
                cache_put_verified(ctx->cache, key, hash->algo, out, *outlen);
                return 0;
            }
            /* corrupt-but-complete: retry the SAME route (transient DPI corruption). */
        }
        /* route dead, or per_route consecutive corruptions ⇒ blacklist + fail over. */
        cvmfs_failover_record(ctx->fo, &route, 0, 0, now);
    }
    return -1;                                            /* mirrors exhausted */
}
