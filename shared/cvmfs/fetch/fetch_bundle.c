/* fetch_bundle.c — client-side ingest of a phase-87 G2 chunk-bundle reply.
 *
 * WHAT: unpack a POST /cvmfs/<repo>/.cvmfs-bundle response stream and store
 *       each member into the local cache exactly as if it had been fetched
 *       singly: stored-form hash verify first, then decode, then the
 *       verified-plaintext + sidecar store.
 * WHY:  the bundle collapses N request RTTs into one, nothing more.  Trust is
 *       untouched — the frame carries no integrity of its own, every member is
 *       CAS-verified against the hash embedded in its OWN path, so a hostile
 *       or corrupted bundle can at worst waste bytes, never poison the cache.
 * HOW:  cvmfs_bundle_iter over the stream; per member parse the CAS path back
 *       to its hash (+suffix), verify/decode through the same fetch.c seam
 *       the single-object path uses (fetch_internal.h), store on success.
 *       A member that fails to parse or verify is COUNTED for single-GET
 *       fallback and skipped — but a malformed FRAME aborts the whole parse
 *       (-1): past a framing error, member boundaries are guesswork.
 */
#include "cvmfs/fetch/fetch.h"
#include "cvmfs/fetch/fetch_internal.h"
#include "cvmfs/bundle/bundle.h"

#include <stdlib.h>
#include <string.h>

/* Plaintext scratch for one decoded member.  Stored members are capped at
 * CVMFS_BUNDLE_MAX_OBJ (8 MiB); 4x covers any plausible zlib expansion — an
 * object bigger than that decodes as "out too small" and falls back to the
 * single-GET path (whose caller sizes the buffer for the object it expects). */
#define BUNDLE_PLAIN_CAP  (4u * CVMFS_BUNDLE_MAX_OBJ)

static int is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

/* Parse a repo-relative CAS path "data/<2hex>/<hex...>[suffix]" back into the
 * content hash it names plus its optional one-letter CAS suffix.  Returns 0,
 * or -1 if the path is not a well-formed CAS member name. */
static int bundle_path_to_hash(const char *path, size_t len,
                               cvmfs_hash_t *out, char *suffix) {
    char   hex[160];
    size_t i, hexlen;

    if (len < 8 || memcmp(path, "data/", 5) != 0) return -1;
    if (!is_hex(path[5]) || !is_hex(path[6]) || path[7] != '/') return -1;

    hex[0] = path[5];
    hex[1] = path[6];
    hexlen = 2;
    for (i = 8; i < len && is_hex(path[i]); i++) {
        if (hexlen + 1 >= sizeof(hex)) return -1;
        hex[hexlen++] = path[i];
    }

    *suffix = 0;
    if (i < len) {                       /* one trailing CAS suffix letter */
        if (i + 1 != len) return -1;
        if (path[i] >= 'A' && path[i] <= 'Z') *suffix = path[i];
        else return -1;
    }

    hex[hexlen] = '\0';
    return cvmfs_hash_parse(hex, hexlen, out);
}

/* Verify + store one data member.  Returns 1 stored (or already cached),
 * 0 rejected (bad path / hash mismatch / oversize — refetch singly). */
static int bundle_ingest_one(cvmfs_fetch_ctx_t *ctx,
                             const cvmfs_bundle_item_t *item,
                             unsigned char *plain) {
    cvmfs_hash_t hash;
    char         suffix, key[160];
    size_t       plainlen = 0;

    if (bundle_path_to_hash(item->path, item->path_len, &hash, &suffix) != 0)
        return 0;
    if (cvmfs_hash_to_hex(&hash, suffix, key, sizeof(key)) < 0)
        return 0;

    if (brix_cas_has(ctx->cache, key))   /* immutable: already verified once */
        return 1;

    if (cvmfs_fetch_decode_verify(ctx, &hash, item->data, (size_t) item->data_len,
                                  plain, BUNDLE_PLAIN_CAP, &plainlen) != 0)
        return 0;

    cvmfs_fetch_cache_put(ctx->cache, key, hash.algo, plain, plainlen);
    return 1;
}

int cvmfs_bundle_ingest(cvmfs_fetch_ctx_t *ctx,
                        const unsigned char *stream, size_t len,
                        unsigned *stored_out, unsigned *fallback_out) {
    cvmfs_bundle_iter_t it;
    cvmfs_bundle_item_t item;
    unsigned char      *plain;
    unsigned            stored = 0, fallback = 0;
    int                 rc;

    *stored_out   = 0;
    *fallback_out = 0;

    if (cvmfs_bundle_iter_init(&it, stream, len) != 0) return -1;

    plain = malloc(BUNDLE_PLAIN_CAP);
    if (plain == NULL) return -1;

    while ((rc = cvmfs_bundle_next(&it, &item)) == 1) {
        if (item.miss) { fallback++; continue; }
        if (bundle_ingest_one(ctx, &item, plain)) stored++;
        else                                      fallback++;
    }
    free(plain);

    if (rc != 0) return -1;              /* malformed frame: nothing trusted */
    *stored_out   = stored;
    *fallback_out = fallback;
    return 0;
}
