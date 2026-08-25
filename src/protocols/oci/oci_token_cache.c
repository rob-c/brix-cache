/*
 * oci_token_cache.c — the D1.3 SHM token cache and its key discipline.
 *
 * WHAT: the (upstream, scope[, credential]) → bearer mapping the token dance
 *       reads and writes, the pull-scope derivation both it and the D16 proof
 *       gate key their records by, and the credential-blind "share" write a
 *       granted proof uses to lend its bearer to the coalesced fill.
 * WHY:  split from oci_upstream_auth.c when D16 pushed that file past the
 *       tree's size ceiling — and the split follows the real seam: this half
 *       owns HOW cache keys are derived (the security property that one
 *       principal's token can never satisfy another's request lives entirely
 *       in the key), while the other half owns the HTTP legs that mint.
 * HOW:  every key is a raw sha256 over NUL-separated components, so no wire
 *       text can overflow a key or collide across component boundaries; the
 *       zone is the shared brix_kv table (invariant #10: spin+yield, no I/O
 *       under the lock).
 */

#include "oci.h"
#include "oci_module_internal.h"

#include "observability/metrics/metrics.h"
#include "observability/metrics/metrics_macros.h"

#include <stdio.h>
#include <string.h>

/* Renew this far before the upstream's own expiry, so a token minted at the
 * edge of its life is never handed to a fill that then out-lives it. */
#define OCI_TOKEN_SKEW_S       30
/* An upstream that reports an implausibly short life still gets a cache entry
 * — otherwise every blob of a large image re-runs the whole dance. */
#define OCI_TOKEN_MIN_TTL_S    5

/* ---- token cache -------------------------------------------------------- */

/* sha256 of [data, data+len) as 32 RAW bytes — the form every SHM key in
 * this plane takes. Exported (internal header) because the D16 proof gate and
 * the credential digest derive their keys with the same primitive; a second
 * hex→raw walk would be a second chance to get the nibble math wrong.
 * 0 = key written / -1 = EVP failure. */
int
brix_oci_sha256_key(const void *data, size_t len, u_char key[32])
{
    brix_oci_digest_t  d;
    int                i;

    if (brix_oci_sha256(data, len, &d) != 0) {
        return -1;
    }
    for (i = 0; i < 32; i++) {
        /* d.hex is plain `char`, which is signed on x86: promote through
         * unsigned char so the arithmetic below cannot see a negative. */
        unsigned hi = (unsigned char) d.hex[i * 2];
        unsigned lo = (unsigned char) d.hex[i * 2 + 1];

        hi = (hi <= '9') ? hi - '0' : hi - 'a' + 10;
        lo = (lo <= '9') ? lo - '0' : lo - 'a' + 10;
        key[i] = (u_char) ((hi << 4) | lo);
    }
    return 0;
}

/* The cache key is sha256(base_url ‖ 0x00 ‖ scope [‖ 0x00 ‖ cred]), 32 raw
 * bytes. The NUL separator is what stops ("https://a.io/x", "y") and
 * ("https://a.io/", "xy") from colliding onto one entry — a collision here
 * would hand one repository's token to another repository's fill. `cred`
 * (32 raw bytes, or NULL for the credential-blind entry) extends the same
 * reasoning to principals: without it, one user's bearer would satisfy every
 * other user's request for the same scope (D16). */
static int
oci_token_cache_key(const brix_oci_upstream_t *up, const char *scope,
    const u_char *cred, u_char key[32])
{
    char    buf[1024 + 33];
    size_t  n, s;

    n = strlen(up->base_url);
    s = strlen(scope);
    if (n + 1 + s + 33 >= sizeof(buf)) {
        return -1;
    }
    memcpy(buf, up->base_url, n);
    buf[n] = '\0';
    memcpy(buf + n + 1, scope, s);
    n += 1 + s;
    if (cred != NULL) {
        buf[n] = '\0';
        memcpy(buf + n + 1, cred, 32);
        n += 33;
    }

    return brix_oci_sha256_key(buf, n, key);
}

int
brix_oci_token_cache_get(brix_oci_upstream_t *up, const char *scope,
    const u_char *cred, char *tok, size_t toklen)
{
    u_char  key[32];
    size_t  out_len = toklen - 1;

    if (up->tokens == NULL
        || oci_token_cache_key(up, scope, cred, key) != 0)
    {
        return -1;
    }
    if (!brix_kv_get(up->tokens, key, sizeof(key), tok, &out_len)) {
        return -1;
    }
    tok[out_len] = '\0';

    BRIX_OCI_METRIC_INC(token_fetch_total[BRIX_OCI_TOKEN_CACHED]);
    return 0;
}

void
brix_oci_token_cache_put(brix_oci_upstream_t *up, const char *scope,
    const u_char *cred, const char *tok, long expires_in)
{
    u_char  key[32];
    long    ttl;

    if (up->tokens == NULL
        || oci_token_cache_key(up, scope, cred, key) != 0)
    {
        return;
    }
    ttl = expires_in - OCI_TOKEN_SKEW_S;
    if (ttl < OCI_TOKEN_MIN_TTL_S) {
        ttl = OCI_TOKEN_MIN_TTL_S;
    }
    (void) brix_kv_set(up->tokens, key, sizeof(key), tok, strlen(tok),
                       (ngx_msec_t) ttl * 1000);
}

/* ---- scope derivation --------------------------------------------------- */

/* When a challenge omits `scope=`, derive the pull scope from the route being
 * fetched: "repository:<name>:pull". `path` is the canonical key, so the name
 * is everything between "/v2/" and the terminal — no parsing risk, but the
 * bound still matters because the result becomes a query parameter. Public
 * because the D16 proof gate keys its SHM records by this same string — two
 * derivations would be two chances to disagree about what one repository is. */
int
brix_oci_pull_scope(const char *path, char *out, size_t outsz)
{
    const char *name, *term;
    size_t      len;

    if (strncmp(path, "/v2/", 4) != 0) {
        return -1;
    }
    name = path + 4;

    term = strstr(name, "/manifests/");
    if (term == NULL) {
        term = strstr(name, "/blobs/");
    }
    /* The D16 gate also proves the listing routes — the tags/referrers
     * surfaces are exactly where a private repository's METADATA would
     * otherwise leak — and they authorize on the same repository:pull. */
    if (term == NULL) {
        term = strstr(name, "/tags/");
    }
    if (term == NULL) {
        term = strstr(name, "/referrers/");
    }
    if (term == NULL || term == name) {
        return -1;
    }
    len = (size_t) (term - name);

    return (snprintf(out, outsz, "repository:%.*s:pull", (int) len, name)
            < (int) outsz) ? 0 : -1;
}


void
brix_oci_token_share(brix_oci_upstream_t *up, const char *path,
    const char *tok, long ttl_s)
{
    char  scope[1024];

    if (up == NULL || tok == NULL || tok[0] == '\0' || ttl_s <= 0
        || brix_oci_pull_scope(path, scope, sizeof(scope)) != 0)
    {
        return;
    }
    /* oci_token_to_cache subtracts the renewal skew; ride through it so the
     * shared copy obeys the same early-renewal discipline as a minted one. */
    brix_oci_token_cache_put(up, scope, NULL, tok, ttl_s + OCI_TOKEN_SKEW_S);
}
