/* ---- File: gsi_outbound_dh_helpers.c — DH key exchange helpers for GSI TPC pull ----
 *
 * WHAT: Three helper functions supporting GSI Diffie-Hellman outbound authentication on the TPC pull socket. tpc_gsi_select_cipher extracts cipher name from server's kXRS_cipher_alg payload bucket (defaulting to aes-256-cbc if no bucket found); tpc_parse_hex_pub parses BEGIN/END BPUB markers in peer pubkey data via memmem, copies hex string, converts to BIGNUM via BN_hex2bn; tpc_dh_peer_from merges local DH key parameters with peer public key BIGNUM into EVP_PKEY_PUBLIC_KEY via OSSL_PARAM_BLD + OSSL_PARAM_merge + EVP_PKEY_fromdata.
 *
 * WHY: GSI authentication requires Diffie-Hellman key exchange between client and server on the outbound TPC socket. The server sends cipher algorithm bucket in login/authmore response parameters, client parses hex-encoded public key from server's pubkey data, then merges local DH parameters with peer pubkey to construct the shared secret context. These helpers bridge the wire payload → OpenSSL structures pipeline — converting raw protocol bytes into EVP_PKEY/BIGNUM objects usable for DH computation.
 *
 * HOW: tpc_gsi_select_cipher — ngx_cpystrn default "aes-256-cbc" → gsi_find_bucket(payload, kXRS_cipher_alg) to find cipher bucket → if found + non-empty, loop through bytes collecting name up to ':' delimiter or size limit → NUL terminate; tpc_parse_hex_pub — memmem for "---BPUB---" and "---EPUB--" markers in puk_data → extract hex region between markers → malloc(hex_len+1) → ngx_memcpy + NUL terminate → BN_hex2bn(&bn, hex_copy) → free(hex_copy) → return bn (caller owns); tpc_dh_peer_from — EVP_PKEY_todata(local_key, KEY_PARAMETERS) for server_params → OSSL_PARAM_BLD_new() + push_BN(peer_pub_bn as OSSL_PKEY_PARAM_PUB_KEY) → OSSL_PARAM_BLD_to_param(client_params) → OSSL_PARAM_merge(server_params+client_params) → EVP_PKEY_CTX_new_id(EVP_PKEY_DH) + fromdata_init + fromdata(EVP_PKEY_PUBLIC_KEY, merged_params) → wrapper cleanup frees all params/ctx/bld. Returns peer_key (caller owns) or NULL on failure. Caller: gsi_outbound_exchange.c (DH pubkey merge step).
 * ------------------------------------------------------------------ */

#include "tpc_internal.h"

#include <openssl/bn.h>
#include <openssl/evp.h>

#include <stdlib.h>
#include <string.h>

/* WHAT: Extract cipher name from server's kXRS_cipher_alg payload bucket (defaulting to aes-256-cbc via ngx_cpystrn). Loop through bytes up to ':' delimiter or size limit. Returns NUL-terminated cipher_name. Caller: gsi_outbound_exchange.c (cipher selection before EVP_get_cipherbyname). */

void
tpc_gsi_select_cipher(const u_char *payload, size_t payload_len,
    char *cipher_name, size_t cipher_name_size)
{
    const u_char *cipher_bucket;
    size_t        cipher_bucket_len;
    size_t        name_len;

    /*
     * Seed the output with the protocol default first: if the server omits the
     * kXRS_cipher_alg bucket (or sends it empty) we fall through to this value.
     * ngx_cpystrn NUL-terminates within cipher_name_size, so a too-small buffer
     * silently truncates rather than overruns.
     */
    ngx_cpystrn((u_char *) cipher_name, (u_char *) "aes-256-cbc",
                cipher_name_size);

    /*
     * Locate the cipher-algorithm bucket in the server's XrdSutBuffer wire
     * payload. gsi_find_bucket bounds-checks the untrusted frame and returns
     * non-zero when the bucket is absent or truncated; an empty bucket is
     * treated the same as absent so we keep the default above.
     */
    if (gsi_find_bucket(payload, payload_len, (uint32_t) kXRS_cipher_alg,
                        &cipher_bucket, &cipher_bucket_len)
        != 0 || cipher_bucket_len == 0)
    {
        return;
    }

    /*
     * The bucket may carry a ':'-separated cipher list ("aes-256-cbc:bf-cbc:…");
     * take only the first entry. Two independent bounds gate the copy: the
     * bucket's own length (cipher_bucket_len, from the wire) and the caller's
     * buffer (cipher_name_size - 1, reserving one byte for the terminator), so a
     * hostile/oversized bucket can never write past cipher_name.
     */
    for (name_len = 0;
         name_len < cipher_bucket_len && name_len < cipher_name_size - 1;
         name_len++)
    {
        if (cipher_bucket[name_len] == ':') {
            break;
        }
        cipher_name[name_len] = (char) cipher_bucket[name_len];
    }

    /* name_len indexes the byte just past the copied name — safe to terminate. */
    cipher_name[name_len] = '\0';
}
/* WHAT: Parse BEGIN/END BPUB markers in peer pubkey data via memmem, extract hex region between markers → malloc+ngx_memcpy+NUL terminate → BN_hex2bn(&bn, hex_copy) → free(hex_copy). Returns BIGNUM (caller owns) or NULL on parse failure. Caller: gsi_outbound_exchange.c (server DH public key parsing step). */

BIGNUM *
tpc_parse_hex_pub(const u_char *puk_data, size_t puk_len)
{
    /*
     * The XRootD/gsi DH public value rides on the wire as ASCII hex framed by
     * "---BPUB---" ... "---EPUB--". sizeof()-1 drops the literal's trailing NUL
     * so the marker lengths match exactly. Note the begin marker has a trailing
     * '-' that the end marker lacks (BPUB---  vs  EPUB--) — they are not the same
     * length, which is why each gets its own sizeof.
     */
    static const char begin_marker[] = "---BPUB---";
    static const char end_marker[]   = "---EPUB--";
    const u_char     *hex_start;
    const u_char     *hex_end;
    char             *hex_copy;
    size_t            hex_len;
    BIGNUM           *bn;

    /* Scan the untrusted PUK blob for both fences (NULL if either is absent). */
    hex_start = memmem(puk_data, puk_len, begin_marker, sizeof(begin_marker) - 1);
    hex_end = memmem(puk_data, puk_len, end_marker, sizeof(end_marker) - 1);

    /*
     * Reject if either marker is missing, or if the end marker is not strictly
     * after the byte following the begin marker. hex_start + (begin length)
     * points at the first hex digit; requiring hex_end to sit beyond it both
     * guarantees a non-negative span below and rejects degenerate/overlapping
     * frames where the markers appear out of order.
     */
    if (hex_start == NULL || hex_end == NULL
        || hex_end <= hex_start + (int) sizeof(begin_marker) - 1)
    {
        return NULL;
    }

    /* Advance past the begin marker so hex_start now points at the hex span. */
    hex_start += sizeof(begin_marker) - 1;
    /* Pointer difference is non-negative per the guard above; span is in bytes. */
    hex_len = (size_t) (hex_end - hex_start);
    /* Defensive: a wrapped/oversized span would surface as SIZE_MAX. */
    if (hex_len == (size_t)-1) {
        return NULL;
    }
    /* +1 reserves room for the NUL that BN_hex2bn requires (it reads a C string). */
    hex_copy = malloc(hex_len + 1);
    if (hex_copy == NULL) {
        return NULL;
    }

    /*
     * Copy the hex out to a private, NUL-terminated buffer rather than scribbling
     * a terminator into the wire frame: the original payload is binary and must
     * stay immutable while parsing.
     */
    ngx_memcpy(hex_copy, hex_start, hex_len);
    hex_copy[hex_len] = '\0';

    /*
     * BN_hex2bn allocates a fresh BIGNUM into *bn (bn must start NULL) and
     * returns the number of hex digits consumed; 0 means parse failure. On
     * failure normalise to NULL so the caller sees a single error sentinel.
     */
    bn = NULL;
    if (BN_hex2bn(&bn, hex_copy) == 0) {
        bn = NULL;
    }

    /* hex_copy has served its purpose; bn is now the only owner we return. */
    free(hex_copy);
    /* Ownership transfers to the caller — they must BN_free(bn). */
    return bn;
}

/* WHAT: Merge local DH key parameters with peer public key BIGNUM into EVP_PKEY_PUBLIC_KEY via OSSL_PARAM_BLD + merge + fromdata. Returns peer_key (caller owns) or NULL on failure. Caller: gsi_outbound_exchange.c (DH pubkey merge step). */

/*
 * Inner builder for tpc_dh_peer_from: runs the OpenSSL 3.x param pipeline and
 * returns the constructed peer key, or NULL on any step failure. Every scratch
 * object is handed back through the out-pointers so the caller's single cleanup
 * frees exactly what was built — which lets this worker stay a flat, goto-free
 * sequence. On the final fromdata failure a partially-built peer_key is freed
 * here (it would otherwise leak, since the caller's cleanup never frees the
 * return value).
 */
static EVP_PKEY *
tpc_dh_peer_build(EVP_PKEY *local_key, BIGNUM *peer_pub_bn,
    EVP_PKEY_CTX **pkey_ctx, OSSL_PARAM_BLD **param_builder,
    OSSL_PARAM **server_params, OSSL_PARAM **client_params,
    OSSL_PARAM **merged_params)
{
    EVP_PKEY *peer_key = NULL;

    /*
     * Extract the DH domain parameters (prime p, generator g, etc.) from our own
     * locally-generated keypair as an OSSL_PARAM array. The peer must share these
     * exact group parameters for the subsequent shared-secret derivation to agree;
     * we reuse ours rather than trusting any group the peer might assert.
     */
    if (EVP_PKEY_todata(local_key, EVP_PKEY_KEY_PARAMETERS, server_params)
        != 1 || *server_params == NULL)
    {
        return NULL;
    }

    /*
     * Build a second OSSL_PARAM array carrying only the peer's public value.
     * push_BN copies the BIGNUM into the builder, so peer_pub_bn ownership stays
     * with the caller (we never free it here).
     */
    *param_builder = OSSL_PARAM_BLD_new();
    if (*param_builder == NULL
        || OSSL_PARAM_BLD_push_BN(*param_builder, OSSL_PKEY_PARAM_PUB_KEY,
                                  peer_pub_bn)
           != 1)
    {
        return NULL;
    }

    *client_params = OSSL_PARAM_BLD_to_param(*param_builder);
    if (*client_params == NULL) {
        return NULL;
    }

    /*
     * Merge: group parameters (from our key) + the peer public value. The result
     * is a complete description of a DH *public* key living in the peer's domain.
     */
    *merged_params = OSSL_PARAM_merge(*server_params, *client_params);
    if (*merged_params == NULL) {
        return NULL;
    }

    /*
     * Materialise the merged parameters into a real EVP_PKEY via fromdata.
     * EVP_PKEY_PUBLIC_KEY selects the public-key selection (no private component
     * is present). On any failure fromdata may have partially populated peer_key,
     * so free and re-NULL it before returning so we never return a half-built key.
     */
    *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (*pkey_ctx == NULL
        || EVP_PKEY_fromdata_init(*pkey_ctx) != 1
        || EVP_PKEY_fromdata(*pkey_ctx, &peer_key, EVP_PKEY_PUBLIC_KEY,
                             *merged_params)
           != 1)
    {
        if (peer_key) {
            EVP_PKEY_free(peer_key);
            peer_key = NULL;
        }
        return NULL;
    }

    return peer_key;
}

EVP_PKEY *
tpc_dh_peer_from(EVP_PKEY *local_key, BIGNUM *peer_pub_bn)
{
    EVP_PKEY_CTX   *pkey_ctx      = NULL;
    OSSL_PARAM_BLD *param_builder = NULL;
    OSSL_PARAM     *server_params = NULL;
    OSSL_PARAM     *client_params = NULL;
    OSSL_PARAM     *merged_params = NULL;
    EVP_PKEY       *peer_key;

    peer_key = tpc_dh_peer_build(local_key, peer_pub_bn, &pkey_ctx,
                                 &param_builder, &server_params,
                                 &client_params, &merged_params);

    /*
     * Unconditional cleanup of every intermediate. peer_key is deliberately NOT
     * freed here on the success path — it is the return value and ownership
     * transfers to the caller (who must EVP_PKEY_free it). On any error path the
     * builder already freed and NULLed it, so this returns the NULL sentinel.
     */
    EVP_PKEY_CTX_free(pkey_ctx);
    OSSL_PARAM_BLD_free(param_builder);
    OSSL_PARAM_free(server_params);
    OSSL_PARAM_free(client_params);
    OSSL_PARAM_free(merged_params);

    return peer_key;
}

