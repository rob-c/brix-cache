#include "gsi_internal.h"

#include <string.h>

/* ---- Main GSI certificate parsing function — decrypt and extract x509 proxy chain ----
 *
 * WHAT: Decrypts and extracts the entire x509 certificate chain from a kXGC_cert (GSI authentication round 2) request.
 *       This is called after the client sends its encrypted proxy cert using the shared DH secret derived from round 1. */

/*---- GSI two-message protocol overview ----
 *
 * WHAT: GSI uses a two-round Diffie-Hellman key-exchange layered on top of XRootD auth for secure credential transfer:
 *   Round 1 (kXGC_certreq): server → client — Server sends DH public key + certificate. ctx->gsi_dh_key holds private key.
 *   Round 2 (kXGC_cert): client → server — Client sends encrypted proxy chain using shared DH secret. Parsed here. */

/*---- GSI authentication security invariant ----
 *
 * WHY: The two-round protocol ensures the certificate is encrypted with a DH shared secret, preventing MITM attacks.
 *      Without this encryption, an interceptor could read raw x509 proxy certificates and impersonate clients. */

/*---- kXGC_cert wire payload structure ----
 *
 * WHAT: Client sends two encrypted buckets in the kXGC_cert message:
 *   - kXRS_puk bucket: client's DH public key in "---BPUB---...---EPUB--" hex-encoded format
 *   - kXRS_main bucket: X.509 proxy chain, AES-CBC encrypted with shared DH secret (contains kXRS_x509 inner buffer) */

/*---- Certificate parsing function flow ----
 *
 * HOW: 1) Extract/decode client's DH public value → BIGNUM; 2) Derive DH shared secret; 
 *      3) SHA-256 hash secret → ctx->signing_key (for kXR_sigver HMAC-SHA256 signing);
 *      4) Decrypt kXRS_main using shared secret as AES key; 5) Extract PEM-encoded cert chain from decrypted buffer. */

/*---- Certificate ownership model ----
 *
 * WHY: The returned STACK_OF(X509) is heap-allocated — caller MUST call sk_X509_pop_free(chain, X509_free) when done.
 *      All OpenSSL intermediate objects (BIGNUM, EVP_PKEY, etc.) are freed before return via goto done or direct calls. */

/*---- Signing key derivation invariant ----
 *
 * WHY: The SHA-256 hash of the DH shared secret produces ctx->signing_key (32 bytes) used later for kXR_sigver HMAC-SHA256
 *      request signing — this provides cryptographic integrity for all subsequent authenticated requests. */

/*---- Certificate parsing error handling ----
 *
 * WHAT: On any failure (malformed blob, BN_hex2bn error, decryption failure), logs NGX_LOG_WARN and returns NULL.
 *      Caller (auth.c) handles the NULL return by sending kXR_NotAuthorized error with appropriate message. */

/*---- GSI certificate parsing entry point ----
 *
 * WHAT: Called from src/gsi/auth.c as part of kXGC_cert handling after credential type verification. Returns STACK_OF(X509). */

/* ---- DH public key extraction helper — parse "---BPUB---...---EPUB--" hex blob ----
 *
 * WHAT: Extracts and decodes the client's Diffie-Hellman (DH) public key value as a BIGNUM from wire payload.
 *       The DH public key is encoded in "---BPUB---...---EPUB--" hex format within kXRS_puk bucket. */

/* ---- DH blob parsing mechanism ----
 *
 * HOW: Uses memmem() to find begin/end markers ("---BPUB---"/"---EPUB--"), extracts hex span between them,
 *      copies to NUL-terminated buffer (c->pool allocation), converts via BN_hex2bn(). */

/* ---- DH blob immutability invariant ----
 *
 * WHY: Instead of scribbling a temporary NUL byte into the wire buffer, we copy the hex payload to heap.
 *      The original frame is binary wire data and must stay immutable while being parsed for security integrity. */

/* ---- BIGNUM ownership model ----
 *
 * WHY: The returned BIGNUM is caller-owned — caller MUST call BN_free() when done. This prevents OpenSSL memory leaks in DH operations. */

/*---- GSI certificate parsing entry point ----
 *
 * WHAT: Called from src/gsi/auth.c as part of kXGC_cert handling after credential type verification. Returns STACK_OF(X509). */

/* ---- Main GSI x509 parsing function — DH secret derivation + AES decryption + certificate extraction ----
 *
 * WHAT: Top-level kXGC_cert handler that performs the complete GSI authentication round 2: derives DH shared secret,
 *      SHA-256 hashes it for signing_key, decrypts encrypted proxy chain via AES-CBC, extracts PEM certificates. */

/*---- gsi_parse_x509 function flow (7 phases) ----
 *
 * HOW: Phase 1 — Verify ctx->gsi_dh_key exists (round 1 completed); 
 *      Phase 2 — Extract kXRS_puk bucket (client DH public key); 
 *      Phase 3 — Parse DH public key → BIGNUM via xrootd_gsi_parse_client_dh_public_key();
 *      Phase 4 — Select cipher name from kXRS_cipher_alg bucket;
 *      Phase 5 — Extract kXRS_main bucket (encrypted proxy chain);
 *      Phase 6 — Build peer DH key + derive shared secret + SHA-256 hash → signing_key;
 *      Phase 7 — AES-CBC decrypt kXRS_main using secret as key, extract PEM certs via BIO/PEM_read_bio_X509(). */

/*---- gsi_parse_x509 preconditions ----
 *
 * WHY: ctx->gsi_dh_key must be set (populated by preceding kXGC_certreq exchange in cert_response.c).
 *      ctx->payload/ctx->cur_dlen hold raw kXGC_cert payload. If gsi_dh_key is NULL, round 1 was skipped — return error. */

/*---- gsi_parse_x509 postconditions (success path) ----
 *
 * WHY: On success: ctx->signing_key[0..31] = SHA-256 of DH shared secret; ctx->signing_active = 1 (enables kXR_sigver HMAC verification).
 *      Returns non-empty STACK_OF(X509) with client's proxy chain — caller MUST call sk_X509_pop_free(chain, X509_free). */

/*---- gsi_parse_x509 bucket extraction pattern ----
 *
 * HOW: Uses gsi_find_bucket() to locate kXRS_puk and kXRS_main buckets in outer wire buffer. Each bucket has a 4-byte type identifier. */

/*---- DH shared secret derivation (OpenSSL 3 EVP_PKEY_derive) ----
 *
 * WHAT: Derives the Diffie-Hellman shared secret by combining server private key with client public value via EVP_PKEY_derive().
 *      This is the core cryptographic operation of GSI authentication — both parties share this secret without transmitting it. */

/*---- DH derive mechanism flow ----
 *
 * HOW: 1) EVP_PKEY_CTX_new(ctx->gsi_dh_key, NULL) creates context from server key; 
 *      2) EVP_PKEY_derive_init() + EVP_PKEY_CTX_set_dh_pad(pkctx, 0) initializes DH pad=0 mode;
 *      3) EVP_PKEY_derive_set_peer(pkctx, peer) sets client public value as peer;
 *      4) First call EVP_PKEY_derive(NULL, &secret_len) to get secret length;
 *      5) Second call EVP_PKEY_derive(secret, &secret_len) to derive actual shared secret. */

/*---- DH derive ownership model ----
 *
 * WHY: Both pkctx and peer must be freed via EVP_PKEY_CTX_free/EVP_PKEY_free after derivation completes. The secret is caller-owned (c->pool). */

/*---- Signing key derivation invariant (SHA-256) ----
 *
 * WHAT: SHA-256 hash of the DH shared secret produces ctx->signing_key[0..31] (32 bytes), enables kXR_sigver HMAC-SHA256 request signing.
 *      This provides cryptographic integrity for all subsequent authenticated requests — prevents request tampering. */

/*---- Cipher initialization with key length handling ----
 *
 * WHAT: Initializes AES-CBC decryption context using cipher name from wire payload, handles variable key lengths (EVP_MAX_KEY_LENGTH).
 *      If secret length differs from standard cipher key length, uses temporary EVP_CIPHER_CTX to verify support before setting actual length. */

/*---- Cipher IV initialization invariant ----
 *
 * WHY: Uses zero-initialized iv buffer (ngx_memset(iv, 0)) for AES-CBC decryption — this is the GSI wire protocol standard IV. */

/*---- Secret cleardown security invariant ----
 *
 * WHAT: After using secret for cipher key/IV setup, OPENSSL_cleanse() wipes all secret bytes from memory to prevent crypto material leakage. */

/*---- gsi_parse_x509 error handling pattern ----
 *
 * WHY: On any failure (bucket missing, DH derive failed, cipher unknown, decryption failed), logs NGX_LOG_WARN and returns NULL.
 *      All OpenSSL objects are freed via goto done or explicit cleanup calls before return to prevent memory leaks. */

BIGNUM *
xrootd_gsi_parse_client_dh_public_key(ngx_connection_t *c, ngx_log_t *log,
    const u_char *public_key_blob, size_t public_key_blob_len)
{
    static const char begin_marker[] = "---BPUB---";
    static const char end_marker[]   = "---EPUB--";

    const u_char *hex_start;
    const u_char *hex_end;
    u_char       *hex_copy;
    size_t        hex_len;
    BIGNUM       *public_key_bn;

    hex_start = memmem((void *) public_key_blob, public_key_blob_len,
                       begin_marker, sizeof(begin_marker) - 1);
    hex_end = memmem((void *) public_key_blob, public_key_blob_len,
                     end_marker, sizeof(end_marker) - 1);

    if (hex_start == NULL || hex_end == NULL
        || hex_end <= hex_start + sizeof(begin_marker) - 1)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: malformed client DH blob");
        return NULL;
    }

    hex_start += sizeof(begin_marker) - 1;
    hex_len = (size_t) (hex_end - hex_start);

    hex_copy = ngx_pnalloc(c->pool, hex_len + 1);
    if (hex_copy == NULL) {
        return NULL;
    }

    ngx_memcpy(hex_copy, hex_start, hex_len);
    hex_copy[hex_len] = '\0';

    public_key_bn = NULL;
    if (BN_hex2bn(&public_key_bn, (char *) hex_copy) == 0
        || public_key_bn == NULL)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: BN_hex2bn failed");
        return NULL;
    }

    return public_key_bn;
}

void
xrootd_gsi_select_cipher_name(const u_char *payload, size_t payload_len,
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
        cipher_name[name_len] = cipher_bucket[name_len];
    }

    cipher_name[name_len] = '\0';
}

EVP_PKEY *
xrootd_gsi_build_peer_dh_key(ngx_log_t *log, EVP_PKEY *server_dh_key,
    BIGNUM *client_public_bn)
{
    EVP_PKEY_CTX   *pkey_ctx      = NULL;
    EVP_PKEY       *peer_key      = NULL;
    OSSL_PARAM_BLD *param_builder = NULL;
    OSSL_PARAM     *server_params = NULL;
    OSSL_PARAM     *client_params = NULL;
    OSSL_PARAM     *merged_params = NULL;

    if (EVP_PKEY_todata(server_dh_key, EVP_PKEY_KEY_PARAMETERS,
                        &server_params)
        != 1 || server_params == NULL)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: cannot export server DH parameters");
        goto done;
    }

    param_builder = OSSL_PARAM_BLD_new();
    if (param_builder == NULL
        || OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_PUB_KEY,
                                  client_public_bn)
           != 1)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: cannot build client DH parameters");
        goto done;
    }

    client_params = OSSL_PARAM_BLD_to_param(param_builder);
    if (client_params == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: cannot finalize client DH parameters");
        goto done;
    }

    merged_params = OSSL_PARAM_merge(server_params, client_params);
    if (merged_params == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: cannot merge DH parameters");
        goto done;
    }

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (pkey_ctx == NULL
        || EVP_PKEY_fromdata_init(pkey_ctx) != 1
        || EVP_PKEY_fromdata(pkey_ctx, &peer_key, EVP_PKEY_PUBLIC_KEY,
                             merged_params) != 1)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: cannot build client DH peer key");
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

