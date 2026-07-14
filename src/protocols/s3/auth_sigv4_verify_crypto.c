/*
 * auth_sigv4_verify_crypto.c — SigV4 canonicalisation, signing-key derivation,
 * signature computation, and the single constant-time signature compare.
 *
 * WHAT: Owns the byte-frozen SigV4 crypto carved out of auth_sigv4_verify.c:
 *       the worker-local one-slot signing-key cache + four-round HMAC derive,
 *       the canonical signed-headers block builder, the canonical-request →
 *       string-to-sign → HMAC-SHA256 → hex signature computation, and the single
 *       constant-time key+signature decision.
 * WHY:  auth_sigv4_verify.c exceeded the ~500-line file-size guard (phase-79).
 *       This is the SigV4 cryptographic core — every intermediate byte layout is
 *       load-bearing for interop and security, so it splits into its own unit
 *       away from the timestamp rules and the orchestrator. INVARIANT §6: this
 *       is SigV4-only crypto — it shares no logic with WLCG bearer-token auth.
 * HOW:  s3_sigv4_derive_signing_key_cached caches the last day/region key and
 *       otherwise calls the shared libxrdproto 4-round HMAC chain (byte-identical
 *       to the client sign path). s3_sigv4_compute_signature runs the standard
 *       SigV4 steps 1-7 over canonical URI/query/headers. s3_sigv4_compare folds
 *       the deferred access-key match and the CRYPTO_memcmp into ONE branch so no
 *       timing or message oracle distinguishes an unknown key from a bad
 *       signature. Byte layout, messages, and result codes preserved 1:1 with the
 *       pre-split single-file implementation.
 */

#include "s3.h"
#include "s3_auth_internal.h"
#include "auth_sigv4_verify_internal.h"
#include "core/compat/hex.h"
#include "core/compat/crypto.h"
#include "core/compat/uri.h"
#include "core/compat/sigv4.h"   /* shared SigV4 signing-key derive (libxrdproto) */

#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <openssl/crypto.h>

/*
 * SigV4 signing key derivation
 *
 * Four-round HMAC chain:
 *   k1 = HMAC("AWS4" + secret, date)   k2 = HMAC(k1, region)
 *   k3 = HMAC(k2, "s3")               k4 = HMAC(k3, "aws4_request")
 * */

/* Worker-local one-slot cache: signing key is stable for one calendar day per
 * region, so cache the last key and avoid four HMAC rounds on every request. */
static struct {
    char   date[9];    /* YYYYMMDD\0, empty string means invalid */
    char   region[65];
    u_char key[32];
} s_signing_key_cache;

/*
 * s3_sigv4_derive_signing_key_cached — derive the SigV4 signing key with a
 * worker-local one-slot cache.
 *
 * WHAT:  Fill out[0..31] with the day/region signing key, returning 1 on success
 *        or 0 when the shared derive fails.
 * WHY:   The signing key is stable for one calendar day per region, so caching
 *        the last result avoids four HMAC rounds on the hot verify path (and on
 *        the post-policy path that also calls this).
 * HOW:   Return the cached key on a date+region hit; otherwise run the shared
 *        libxrdproto 4-round HMAC chain (byte-identical to the client sign path),
 *        then refresh the cache slot.
 */
int
s3_sigv4_derive_signing_key_cached(const ngx_str_t *secret_key,
                                    const char *date, const char *region,
                                    u_char out[32])
{
    if (s_signing_key_cache.date[0] != '\0'
        && strcmp(s_signing_key_cache.date, date) == 0
        && strcmp(s_signing_key_cache.region, region) == 0)
    {
        ngx_memcpy(out, s_signing_key_cache.key, 32);
        return 1;
    }

    /* Shared 4-round HMAC chain (libxrdproto) — byte-identical to the client's
     * sign path so client-signs == server-verifies by construction. */
    if (!brix_sigv4_signing_key((const uint8_t *) secret_key->data,
                                  secret_key->len, date, region, "s3", out)) {
        return 0;
    }

    ngx_cpystrn((u_char *) s_signing_key_cache.date,
                (u_char *) date, sizeof(s_signing_key_cache.date));
    ngx_cpystrn((u_char *) s_signing_key_cache.region,
                (u_char *) region, sizeof(s_signing_key_cache.region));
    ngx_memcpy(s_signing_key_cache.key, out, 32);
    return 1;
}

/*
 * build_canonical_headers — build the SigV4 canonical signed-headers block.
 *
 * WHAT:  Write the "header-name:value\n" block (lowercased names, trimmed values)
 *        for each entry of the semicolon-separated signed_hdrs list into out,
 *        returning the number of bytes written (out is also NUL-terminated).
 * WHY:   The canonical headers block is a byte-frozen SigV4 input; a dedicated
 *        builder keeps its exact lowering/trim/order rules in one auditable place.
 * HOW:   Tokenise signed_hdrs on ';'; resolve each value (host from the request
 *        line, others via get_header); lowercase the name, trim leading/trailing
 *        SP/TAB from the value, and append name:value\n while bounds-checking out.
 */
static size_t
build_canonical_headers(ngx_http_request_t *r,
                        const char *signed_hdrs,
                        u_char *out, size_t outsz)
{
    char   hdrs[256];
    size_t oi = 0;

    ngx_cpystrn((u_char *) hdrs, (u_char *) signed_hdrs, sizeof(hdrs));

    char *save = NULL;
    char *tok  = strtok_r(hdrs, ";", &save);

    while (tok) {
        ngx_str_t val;

        if (strcmp(tok, "host") == 0) {
            val = r->headers_in.host ? r->headers_in.host->value
                                     : (ngx_str_t) ngx_null_string;
        } else {
            val = get_header(r, tok);
        }

        size_t nlen = strlen(tok);
        size_t vlen = val.len;

        if (oi + nlen + 1 + vlen + 2 >= outsz) {
            break;
        }

        for (size_t i = 0; i < nlen; i++) {
            out[oi++] = (u_char) tolower((unsigned char) tok[i]);
        }
        out[oi++] = ':';

        const u_char *vs = val.data;
        const u_char *ve = val.data + vlen;
        while (vs < ve && (*vs == ' ' || *vs == '\t')) { vs++; }
        while (ve > vs && (ve[-1] == ' ' || ve[-1] == '\t')) { ve--; }

        /* A SignedHeaders entry may name a header the client never sent, so
         * val.data can be NULL with vlen 0 (empty canonical value). Guard the
         * copy: memcpy's src is 'nonnull', and passing NULL even with length 0
         * is undefined behaviour. */
        if (ve > vs) {
            ngx_memcpy(out + oi, vs, (size_t)(ve - vs));
            oi += (size_t)(ve - vs);
        }
        out[oi++] = '\n';

        tok = strtok_r(NULL, ";", &save);
    }

    out[oi] = '\0';
    return oi;
}

/*
 * s3_sigv4_compute_signature — build the canonical request and compute the
 * server-side SigV4 signature hex.
 *
 * WHAT:  Produce the 64-char lowercase-hex HMAC-SHA256 signature that the client
 *        signature must equal, following the standard SigV4 steps 1-7.
 * WHY:   Concentrates the byte-frozen canonicalisation + HMAC chain in one pure-
 *        ish computation so the verifier's decision logic reads cleanly.  This is
 *        SigV4-only crypto (INVARIANT §6): it shares no logic with token auth.
 * HOW:   Canonical URI/query/headers → canonical request → string-to-sign →
 *        cached signing-key derive → HMAC-SHA256 → hex.  On the two internal
 *        failure modes (derive/HMAC) it records the result and returns
 *        NGX_ERROR; the caller maps that to HTTP 500.  out->k4 is exported for
 *        chunk-sig retention.  Byte layout of every intermediate is preserved 1:1.
 *
 * Returns: NGX_OK with out->computed_hex[0..63] filled and out->k4 populated;
 *   NGX_ERROR (result already recorded) on an internal crypto failure.
 */
ngx_int_t
s3_sigv4_compute_signature(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const sigv4_components_t *comp, const s3_amz_date_out_t *amz,
    s3_sigv4_sig_out_t *out)
{
    u_char canonical[8192];
    u_char canon_qs[2048];
    u_char canon_uri[S3_MAX_KEY];
    u_char canon_hdrs[2048];
    u_char string_to_sign[4096];
    u_char hash_hex[65];
    u_char cr_hash[32];
    u_char computed[32];
    size_t n;

    /* 1. Canonical URI */
    brix_http_urlencode(r->uri.data, r->uri.len,
                        (char *) canon_uri, sizeof(canon_uri), "/");

    /* 2. Canonical query string */
    build_canonical_qs(r->args.data, r->args.len, comp->presigned,
                       canon_qs, sizeof(canon_qs));

    /* 3. Canonical headers */
    build_canonical_headers(r, comp->signed_hdrs,
                            canon_hdrs, sizeof(canon_hdrs));

    /* 4. Canonical request */
    n = (size_t) snprintf((char *) canonical, sizeof(canonical),
        "%.*s\n"        /* method   */
        "%s\n"          /* uri      */
        "%s\n"          /* qs       */
        "%s\n"          /* headers  */
        "%s\n"          /* signed header names */
        "UNSIGNED-PAYLOAD",
        (int) r->method_name.len, r->method_name.data,
        (char *) canon_uri,
        (char *) canon_qs,
        (char *) canon_hdrs,
        comp->signed_hdrs);

    brix_sha256(canonical, n, cr_hash);
    brix_hex_encode(cr_hash, 32, (char *) hash_hex);

    /* 5. String to sign */
    n = (size_t) snprintf((char *) string_to_sign, sizeof(string_to_sign),
        "AWS4-HMAC-SHA256\n"
        "%.*s\n"
        "%s/%s/s3/aws4_request\n"
        "%s",
        (int) amz->len, amz->date,
        comp->date,
        comp->region,
        (char *) hash_hex);

    /* 6. Derive signing key (cached: stable for one calendar day per region) */
    if (!s3_sigv4_derive_signing_key_cached(&cf->secret_key,
                                            comp->date, comp->region, out->k4)) {
        s3_record_auth_result(BRIX_S3_AUTH_INTERNAL_ERROR);
        return NGX_ERROR;
    }

    /* 7. Compute the signature */
    if (!brix_hmac_sha256(out->k4, 32, string_to_sign, n, computed)) {
        s3_record_auth_result(BRIX_S3_AUTH_INTERNAL_ERROR);
        return NGX_ERROR;
    }

    brix_hex_encode(computed, 32, out->computed_hex);
    return NGX_OK;
}

/*
 * s3_sigv4_compare — the single constant-time signature decision (W5).
 *
 * WHAT:  Decide whether the request's access key AND signature are both valid,
 *        emitting the terminal SignatureDoesNotMatch / Signature-length errors.
 * WHY:   An unknown access key and a bad signature MUST take the identical path,
 *        status, message, and HMAC work so no timing or message oracle can
 *        distinguish them.  Consolidating the length check + constant-time
 *        compare here keeps that guarantee obvious and unbroken.
 * HOW:   Reject non-64-char signatures first (prevents CRYPTO_memcmp over pad
 *        bytes).  Then fold key_ok and CRYPTO_memcmp(computed_hex, signature)
 *        into ONE branch — both use constant-time comparison.  Frozen messages,
 *        result codes, and the WARN log line preserved 1:1.
 *
 * Returns: NGX_OK when the signature is authentic, otherwise the terminal
 *   ngx_int_t result (response already emitted).
 */
ngx_int_t
s3_sigv4_compare(ngx_http_request_t *r, const sigv4_components_t *comp,
    const char computed_hex[65], int key_ok)
{
    /* Reject signatures that are not exactly 64 hex chars — prevents a short
     * client string from causing CRYPTO_memcmp to compare against pad bytes. */
    if (strlen(comp->signature) != 64) {
        s3_record_auth_result(BRIX_S3_AUTH_MALFORMED);
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "InvalidRequest",
                                 "Signature must be 64 hex characters");
    }

    /*
     * Single constant-time decision (W5): an unknown access key (!key_ok) and a
     * bad signature take the identical path, status, and message here, having
     * both run the full HMAC above — no timing or message oracle distinguishes
     * them.  CRYPTO_memcmp prevents a timing oracle on the HMAC value itself.
     */
    if (!key_ok || CRYPTO_memcmp(computed_hex, comp->signature, 64) != 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "brix_s3: SigV4 auth failed for key=%s (key_ok=%d)",
                      comp->akid, key_ok);
        s3_record_auth_result(key_ok ? BRIX_S3_AUTH_SIG_MISMATCH
                                     : BRIX_S3_AUTH_BAD_KEY);
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "SignatureDoesNotMatch",
                                 "The request signature we calculated does "
                                 "not match the signature you provided");
    }

    return NGX_OK;
}
