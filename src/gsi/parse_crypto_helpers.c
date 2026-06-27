#include "gsi_internal.h"
#include "gsi_core.h"     /* shared DH kernels (single source w/ the client) */

#include <string.h>

/*
 * GSI kXGC_cert (round 2) crypto helpers, shared by the gsi_parse_x509 driver in
 * parse_x509.c. The heavy lifting (DH decode/derive, the "---BPUB---" blob format)
 * lives in the shared gsi_core.c; these are the thin server-side wrappers.
 */

/* xrootd_gsi_parse_client_dh_public_key — decode the client's DH public value
 * (the "---BPUB---<hex>---EPUB--" kXRS_puk blob) into a caller-owned BIGNUM (free
 * with BN_free); NULL + WARN on a malformed blob. */
BIGNUM *
xrootd_gsi_parse_client_dh_public_key(ngx_connection_t *c, ngx_log_t *log,
    const u_char *public_key_blob, size_t public_key_blob_len)
{
    /* The "---BPUB---<hex>---EPUB--" parse now lives in the shared gsi_core.c. */
    BIGNUM *bn;

    (void) c;
    bn = xrootd_gsi_dh_pub_decode(public_key_blob, public_key_blob_len);
    if (bn == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: malformed/garbled client DH blob");
    }
    return bn;
}

/* xrootd_gsi_select_cipher_name — pick the session cipher from the kXRS_cipher_alg
 * bucket (first name, up to a ':' next-cipher or '#' IV-length suffix), defaulting
 * to aes-128-cbc — the XrdSecgsi default a peer omitting the bucket keyed with. */
void
xrootd_gsi_select_cipher_name(const u_char *payload, size_t payload_len,
    char *cipher_name, size_t cipher_name_size)
{
    const u_char *cipher_bucket;
    size_t        cipher_bucket_len;
    size_t        name_len;

    /* Phase 52: default to aes-128-cbc (the universal XrdSecgsi default that a
     * conformant peer omitting the bucket would have keyed with) rather than
     * aes-256-cbc, so a no-bucket peer is decrypted with the right key length. */
    ngx_cpystrn((u_char *) cipher_name, (u_char *) "aes-128-cbc",
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
        if (cipher_bucket[name_len] == ':' || cipher_bucket[name_len] == '#') {
            break;     /* ':' = next offered cipher, '#' = IV-length suffix */
        }
        cipher_name[name_len] = cipher_bucket[name_len];
    }

    cipher_name[name_len] = '\0';
}

/* xrootd_gsi_build_peer_dh_key — wrap the client's public BIGNUM as an EVP_PKEY peer
 * (against the server DH params) for EVP_PKEY_derive; NULL + WARN on failure. */
EVP_PKEY *
xrootd_gsi_build_peer_dh_key(ngx_log_t *log, EVP_PKEY *server_dh_key,
    BIGNUM *client_public_bn)
{
    /* The OpenSSL param pipeline now lives in the shared gsi_core.c. */
    EVP_PKEY *peer = xrootd_gsi_dh_build_peer(server_dh_key, client_public_bn);

    if (peer == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: cannot build client DH peer key");
    }
    return peer;
}

