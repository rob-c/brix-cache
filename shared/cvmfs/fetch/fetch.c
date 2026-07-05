/* fetch.c — CVMFS content-addressed fetch orchestrator. See fetch.h. */
#include "cvmfs/fetch/fetch.h"
#include "cvmfs/object/object.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Serve from cache if present: read verified plaintext straight into `out`. */
static int serve_from_cache(brix_cas_store_t *cache, const char *key,
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
    *outlen = off;
    return 0;
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

    /* 1. cache-first (plaintext, already verified at store time). */
    if (brix_cas_has(ctx->cache, key))
        return serve_from_cache(ctx->cache, key, out, outcap, outlen);

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
                brix_cas_put(ctx->cache, key, out, *outlen);   /* store verified plaintext */
                return 0;
            }
            /* corrupt-but-complete: retry the SAME route (transient DPI corruption). */
        }
        /* route dead, or per_route consecutive corruptions ⇒ blacklist + fail over. */
        cvmfs_failover_record(ctx->fo, &route, 0, 0, now);
    }
    return -1;                                            /* mirrors exhausted */
}
