/* ---- File: gsi_outbound_dh_helpers.c — DH key exchange helpers for GSI TPC pull ----
 *
 * WHAT: Three helper functions supporting GSI Diffie-Hellman outbound authentication on the TPC pull socket. tpc_gsi_select_cipher extracts cipher name from server's kXRS_cipher_alg payload bucket (defaulting to aes-256-cbc if no bucket found); tpc_parse_hex_pub parses BEGIN/END BPUB markers in peer pubkey data via memmem, copies hex string, converts to BIGNUM via BN_hex2bn; tpc_dh_peer_from merges local DH key parameters with peer public key BIGNUM into EVP_PKEY_PUBLIC_KEY via OSSL_PARAM_BLD + OSSL_PARAM_merge + EVP_PKEY_fromdata.
 *
 * WHY: GSI authentication requires Diffie-Hellman key exchange between client and server on the outbound TPC socket. The server sends cipher algorithm bucket in login/authmore response parameters, client parses hex-encoded public key from server's pubkey data, then merges local DH parameters with peer pubkey to construct the shared secret context. These helpers bridge the wire payload → OpenSSL structures pipeline — converting raw protocol bytes into EVP_PKEY/BIGNUM objects usable for DH computation.
 *
 * HOW: tpc_gsi_select_cipher — ngx_cpystrn default "aes-256-cbc" → gsi_find_bucket(payload, kXRS_cipher_alg) to find cipher bucket → if found + non-empty, loop through bytes collecting name up to ':' delimiter or size limit → NUL terminate; tpc_parse_hex_pub — memmem for "---BPUB---" and "---EPUB--" markers in puk_data → extract hex region between markers → malloc(hex_len+1) → ngx_memcpy + NUL terminate → BN_hex2bn(&bn, hex_copy) → free(hex_copy) → return bn (caller owns); tpc_dh_peer_from — EVP_PKEY_todata(local_key, KEY_PARAMETERS) for server_params → OSSL_PARAM_BLD_new() + push_BN(peer_pub_bn as OSSL_PKEY_PARAM_PUB_KEY) → OSSL_PARAM_BLD_to_param(client_params) → OSSL_PARAM_merge(server_params+client_params) → EVP_PKEY_CTX_new_id(EVP_PKEY_DH) + fromdata_init + fromdata(EVP_PKEY_PUBLIC_KEY, merged_params) → goto done cleanup: free all params/ctx/bld. Returns peer_key (caller owns) or NULL on failure. Caller: gsi_outbound_exchange.c (DH pubkey merge step).
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

    ngx_cpystrn((u_char *) cipher_name, (u_char *) "aes-256-cbc",
                cipher_name_size);

    if (gsi_find_bucket(payload, payload_len, (uint32_t) kXRS_cipher_alg,
                        &cipher_bucket, &cipher_bucket_len)
        != 0 || cipher_bucket_len == 0)
    {
        return;
    }

    for (name_len = 0;
         name_len < cipher_bucket_len && name_len < cipher_name_size - 1;
         name_len++)
    {
        if (cipher_bucket[name_len] == ':') {
            break;
        }
        cipher_name[name_len] = (char) cipher_bucket[name_len];
    }

    cipher_name[name_len] = '\0';
}
/* WHAT: Parse BEGIN/END BPUB markers in peer pubkey data via memmem, extract hex region between markers → malloc+ngx_memcpy+NUL terminate → BN_hex2bn(&bn, hex_copy) → free(hex_copy). Returns BIGNUM (caller owns) or NULL on parse failure. Caller: gsi_outbound_exchange.c (server DH public key parsing step). */

BIGNUM *
tpc_parse_hex_pub(const u_char *puk_data, size_t puk_len)
{
    static const char begin_marker[] = "---BPUB---";
    static const char end_marker[]   = "---EPUB--";
    const u_char     *hex_start;
    const u_char     *hex_end;
    char             *hex_copy;
    size_t            hex_len;
    BIGNUM           *bn;

    hex_start = memmem(puk_data, puk_len, begin_marker, sizeof(begin_marker) - 1);
    hex_end = memmem(puk_data, puk_len, end_marker, sizeof(end_marker) - 1);

    if (hex_start == NULL || hex_end == NULL
        || hex_end <= hex_start + (int) sizeof(begin_marker) - 1)
    {
        return NULL;
    }

    hex_start += sizeof(begin_marker) - 1;
    hex_len = (size_t) (hex_end - hex_start);
    if (hex_len == (size_t)-1) {
        return NULL;
    }
    hex_copy = malloc(hex_len + 1);
    if (hex_copy == NULL) {
        return NULL;
    }

    ngx_memcpy(hex_copy, hex_start, hex_len);
    hex_copy[hex_len] = '\0';

    bn = NULL;
    if (BN_hex2bn(&bn, hex_copy) == 0) {
        bn = NULL;
    }

    free(hex_copy);
    return bn;
}

/* WHAT: Merge local DH key parameters with peer public key BIGNUM into EVP_PKEY_PUBLIC_KEY via OSSL_PARAM_BLD + merge + fromdata. Returns peer_key (caller owns) or NULL on failure. Caller: gsi_outbound_exchange.c (DH pubkey merge step). */

EVP_PKEY *
tpc_dh_peer_from(EVP_PKEY *local_key, BIGNUM *peer_pub_bn)
{
    EVP_PKEY_CTX   *pkey_ctx;
    EVP_PKEY       *peer_key;
    OSSL_PARAM_BLD *param_builder;
    OSSL_PARAM     *server_params;
    OSSL_PARAM     *client_params;
    OSSL_PARAM     *merged_params;

    pkey_ctx = NULL;
    peer_key = NULL;
    param_builder = NULL;
    server_params = NULL;
    client_params = NULL;
    merged_params = NULL;

    if (EVP_PKEY_todata(local_key, EVP_PKEY_KEY_PARAMETERS, &server_params)
        != 1 || server_params == NULL)
    {
        goto done;
    }

    param_builder = OSSL_PARAM_BLD_new();
    if (param_builder == NULL
        || OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_PUB_KEY,
                                  peer_pub_bn)
           != 1)
    {
        goto done;
    }

    client_params = OSSL_PARAM_BLD_to_param(param_builder);
    if (client_params == NULL) {
        goto done;
    }

    merged_params = OSSL_PARAM_merge(server_params, client_params);
    if (merged_params == NULL) {
        goto done;
    }

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (pkey_ctx == NULL
        || EVP_PKEY_fromdata_init(pkey_ctx) != 1
        || EVP_PKEY_fromdata(pkey_ctx, &peer_key, EVP_PKEY_PUBLIC_KEY,
                             merged_params)
           != 1)
    {
        if (peer_key) {
            EVP_PKEY_free(peer_key);
            peer_key = NULL;
        }
        goto done;
    }

done:
    EVP_PKEY_CTX_free(pkey_ctx);
    OSSL_PARAM_BLD_free(param_builder);
    OSSL_PARAM_free(server_params);
    OSSL_PARAM_free(client_params);
    OSSL_PARAM_free(merged_params);

    return peer_key;
}

