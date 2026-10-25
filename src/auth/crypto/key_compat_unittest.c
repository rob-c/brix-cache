/* Native version-neutral crypto contracts; built with the selected real SDK. */
#include "auth/crypto/jwk_compat.h"
#include "auth/crypto/name_compat.h"
#include "auth/crypto/store_compat.h"
#include "auth/crypto/tls_compat.h"
#include "auth/gsi/gsi_core.h"
#include "core/compat/crypto.h"
#include <openssl/rsa.h>
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

/* ---- Verify fixed digest/MAC vectors and reusable streaming ownership ----
 * WHAT: Assert RFC HMAC and SHA vectors, including a second streaming final.
 * WHY: Backend selection must not change signatures or streaming reset behavior.
 * HOW: 1. Initialize. 2. Hash vectors. 3. Reuse the stream. 4. Free and clean up.
 */
static void
check_vectors(void)
{
    static const unsigned char sha[] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    static const unsigned char mac[] = {
        0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
        0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7};
    unsigned char key[20], output[32];
    void *stream;

    memset(key, 0x0b, sizeof(key));
    assert(brix_crypto_init() == 1);
    assert(brix_crypto_init() == 1);
    assert(brix_hmac_sha256(key, sizeof(key), (const unsigned char *) "Hi There", 8, output));
    assert(memcmp(output, mac, sizeof(mac)) == 0);
    assert(brix_sha256((const unsigned char *) "abc", 3, output));
    assert(memcmp(output, sha, sizeof(sha)) == 0);
    stream = brix_sha256_stream_new();
    assert(stream != NULL);
    for (int iteration = 0; iteration < 2; iteration++) {
        assert(brix_sha256_stream_update(stream, (const unsigned char *) "a", 1));
        assert(brix_sha256_stream_update(stream, (const unsigned char *) "bc", 2));
        assert(brix_sha256_stream_final(stream, output));
        assert(memcmp(output, sha, sizeof(sha)) == 0);
    }
    brix_sha256_stream_free(stream);
    brix_crypto_cleanup();
}

/* ---- Reject unsafe MAC arguments and calls outside the initialized lifetime ----
 * WHAT: Assert invalid pointers/lengths and post-cleanup calls return failure.
 * WHY: The legacy int-length API must not truncate hostile size_t values.
 * HOW: 1. Initialize. 2. Refuse invalid inputs. 3. Verify the cleanup boundary.
 */
static void
check_mac_errors(void)
{
    unsigned char output[32];
    const unsigned char byte = 1;

    assert(brix_crypto_init());
    assert(!brix_hmac_sha256(NULL, 1, &byte, 1, output));
    assert(!brix_hmac_sha256(&byte, 1, NULL, 1, output));
    assert(!brix_hmac_sha256(&byte, (size_t) INT_MAX + 1, &byte, 1, output));
    assert(!brix_hmac_sha256(&byte, 1, &byte, 1, NULL));
    assert(brix_hmac_sha256(NULL, 0, NULL, 0, output));
    brix_crypto_cleanup();
    assert(!brix_hmac_sha256(&byte, 1, &byte, 1, output));
    assert(brix_sha256_stream_new() == NULL);
    brix_crypto_cleanup();
}

/* ---- Preserve negotiated DH groups and borrowed input ownership ----
 * WHAT: Assert public export/import and two-sided key agreement are identical.
 * WHY: A seemingly valid fallback to a different DH group breaks GSI signatures.
 * HOW: 1. Generate peers. 2. Import owned public keys. 3. Compare shared secrets.
 */
static void
check_dh(void)
{
    EVP_PKEY *left = brix_gsi_dh_keygen(), *right = brix_gsi_dh_keygen();
    EVP_PKEY *left_public, *right_public;
    BIGNUM *left_bn = NULL, *right_bn = NULL;
    unsigned char *first, *second;
    size_t first_length = 0, second_length = 0;

    assert(left != NULL && right != NULL);
    assert(brix_crypto_dh_public(left, &left_bn));
    assert(brix_crypto_dh_public(right, &right_bn));
    left_public = brix_gsi_dh_build_peer(left, left_bn);
    right_public = brix_gsi_dh_build_peer(right, right_bn);
    BN_free(left_bn);
    BN_free(right_bn);
    assert(left_public != NULL && right_public != NULL);
    assert(brix_crypto_pkey_equal(left, left_public));
    assert(!brix_crypto_pkey_equal(left, right_public));
    first = brix_gsi_dh_derive(left, right_public, &first_length);
    second = brix_gsi_dh_derive(right, left_public, &second_length);
    assert(first != NULL && second != NULL && first_length == second_length);
    assert(CRYPTO_memcmp(first, second, first_length) == 0);
    OPENSSL_clear_free(first, first_length);
    OPENSSL_clear_free(second, second_length);
    EVP_PKEY_free(left_public);
    EVP_PKEY_free(right_public);
    EVP_PKEY_free(left);
    EVP_PKEY_free(right);
}

/* ---- Refuse missing or wrong-type DH keys and incomparable credentials ----
 * WHAT: Assert hostile key types cannot produce a DH public number or match.
 * WHY: A negative EVP comparison code is not an authentication success.
 * HOW: 1. Create a wrong-type RSA public key. 2. Exercise failure contracts.
 */
static void
check_key_errors(void)
{
    BIGNUM *modulus = BN_new(), *exponent = BN_new(), *public_number = NULL;
    EVP_PKEY *rsa;

    assert(BN_set_word(modulus, 3233) && BN_set_word(exponent, 17));
    rsa = brix_crypto_rsa_public(modulus, exponent);
    assert(rsa != NULL);
    assert(!brix_crypto_dh_public(rsa, &public_number));
    assert(public_number == NULL);
    assert(brix_crypto_dh_peer(rsa, modulus) == NULL);
    assert(!brix_crypto_pkey_equal(rsa, NULL));
    assert(!brix_crypto_pkey_equal(NULL, rsa));
    assert(brix_crypto_rsa_public(NULL, exponent) == NULL);
    BN_free(modulus);
    BN_free(exponent);
    EVP_PKEY_free(rsa);
}

/* ---- Validate P-256 encoding and reject an off-curve public point ----
 * WHAT: Import the standard generator and refuse malformed/hostile encodings.
 * WHY: JWT coordinates must not create a usable key for an invalid curve point.
 * HOW: 1. Encode the standard generator. 2. Import. 3. Test invalid inputs.
 */
static void
check_ec(void)
{
    static const unsigned char generator[] = {
        4,0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
        0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,
        0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
        0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5};
    unsigned char invalid[65] = {4};
    EVP_PKEY *key = brix_crypto_p256_public(generator, sizeof(generator));

    assert(key != NULL);
    assert(brix_crypto_pkey_equal(key, key));
    assert(brix_crypto_p256_public(invalid, sizeof(invalid)) == NULL);
    assert(brix_crypto_p256_public(generator, 64) == NULL);
    assert(brix_crypto_p256_public(NULL, 65) == NULL);
    EVP_PKEY_free(key);
}

/* WHAT: Verify a generated key signs, verifies and rejects changed input.
 * WHY: A non-NULL EVP handle alone does not prove usable private material.
 * HOW: Use independent digest contexts and then change the signed bytes. */
static void
check_signature(EVP_PKEY *key)
{
    EVP_MD_CTX *sign = EVP_MD_CTX_new(), *verify = EVP_MD_CTX_new();
    unsigned char signature[512];
    size_t length = sizeof(signature);

    assert(key != NULL && sign != NULL && verify != NULL);
    assert(EVP_DigestSignInit(sign, NULL, EVP_sha256(), NULL, key) == 1);
    assert(EVP_DigestSign(sign, signature, &length, (const unsigned char *) "good", 4) == 1);
    assert(EVP_DigestVerifyInit(verify, NULL, EVP_sha256(), NULL, key) == 1);
    assert(EVP_DigestVerify(verify, signature, length, (const unsigned char *) "good", 4) == 1);
    assert(EVP_DigestVerifyInit(verify, NULL, EVP_sha256(), NULL, key) == 1);
    assert(EVP_DigestVerify(verify, signature, length, (const unsigned char *) "evil", 4) != 1);
    EVP_MD_CTX_free(sign);
    EVP_MD_CTX_free(verify);
}

/* WHAT: Exercise both common key generators and borrowed exponent ownership.
 * WHY: These replace convenience APIs used by the server and native clients.
 * HOW: Generate/sign with each type; free the exponent before native keygen. */
static void
check_keygen(void)
{
    EVP_PKEY *rsa = brix_crypto_rsa_keygen(2048), *ec = brix_crypto_p256_keygen();
    EVP_PKEY *custom = NULL;
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    BIGNUM *exponent = BN_new();

    check_signature(rsa);
    check_signature(ec);
    assert(context != NULL && exponent != NULL);
    assert(EVP_PKEY_keygen_init(context) == 1);
    assert(EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) == 1);
    assert(BN_set_word(exponent, 65537));
    assert(brix_crypto_rsa_keygen_exponent(context, exponent));
    BN_free(exponent);
    assert(EVP_PKEY_keygen(context, &custom) == 1);
    check_signature(custom);
    assert(!brix_crypto_rsa_keygen_exponent(context, NULL));
    assert(brix_crypto_rsa_keygen(UINT_MAX) == NULL);
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(custom);
    EVP_PKEY_free(ec);
    EVP_PKEY_free(rsa);
}

/* WHAT: Refuse absent explicit trust inputs without selecting system defaults.
 * WHY: A compatibility loader must never turn a bad path into widened trust.
 * HOW: Test null/empty inputs and an absent bundle on a fresh store. */
static void
check_store_errors(void)
{
    X509_STORE *store = X509_STORE_new();

    assert(store != NULL);
    assert(!brix_crypto_store_load_path(store, NULL));
    assert(!brix_crypto_store_load_path(store, ""));
    assert(!brix_crypto_store_load_file(store, NULL));
    assert(!brix_crypto_store_load_file(store, ""));
    assert(!brix_crypto_store_load_file(NULL, "/dev/null"));
    assert(!brix_crypto_store_load_file(store, "/dev/null/brix-nonexistent-ca"));
    X509_STORE_free(store);
}

/* WHAT: Confine the unexpected-EOF relaxation to the supplied data session.
 * WHY: GridFTP data compatibility must not relax control or shared TLS policy.
 * HOW: Compare a sibling control session and the original shared context. */
static void
check_tls_options(void)
{
    SSL_CTX *context = SSL_CTX_new(TLS_method());
    SSL *data, *control;
    uint64_t original;

    assert(context != NULL);
    data = SSL_new(context);
    control = SSL_new(context);
    assert(data != NULL && control != NULL);
    original = SSL_get_options(control);
    brix_crypto_gridftp_data_eof(data);
    assert(SSL_get_options(control) == original);
    assert(SSL_CTX_get_options(context) == original);
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    assert((SSL_get_options(data) & SSL_OP_IGNORE_UNEXPECTED_EOF) != 0);
#else
    assert(SSL_get_options(data) == original);
#endif
    SSL_free(data);
    SSL_free(control);
    SSL_CTX_free(context);
}

/* WHAT: Create a signed leaf with explicitly typed subject alternative names.
 * WHY: IP certificate identities must not be confused with numeric DNS names.
 * HOW: Sign one native P-256 key and attach the supplied SAN extension. */
static X509 *
peer_name_certificate(const char *names)
{
    EVP_PKEY *key = brix_crypto_p256_keygen();
    X509 *certificate = X509_new();
    X509_EXTENSION *extension;
    X509_NAME *subject;

    assert(key != NULL && certificate != NULL);
    assert(X509_set_version(certificate, 2) == 1);
    assert(ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1) == 1);
    assert(X509_gmtime_adj(X509_getm_notBefore(certificate), -60) != NULL);
    assert(X509_gmtime_adj(X509_getm_notAfter(certificate), 3600) != NULL);
    assert(X509_set_pubkey(certificate, key) == 1);
    subject = X509_get_subject_name(certificate);
    assert(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
        (const unsigned char *) "127.0.0.1", -1, -1, 0) == 1);
    assert(X509_set_issuer_name(certificate, subject) == 1);
    extension = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, (char *) names);
    assert(extension != NULL && X509_add_ext(certificate, extension, -1) == 1);
    X509_EXTENSION_free(extension);
    assert(X509_sign(certificate, key, EVP_sha256()) > 0);
    EVP_PKEY_free(key);
    return certificate;
}

/* WHAT: Verify the actual SSL parameter binding against a signed native leaf.
 * WHY: API return codes alone cannot prove that wrong-host peers are rejected.
 * HOW: Replace stale DNS/IP identities, copy SSL parameters, verify the chain. */
static void
check_peer_name(X509 *certificate, const char *host, int expected)
{
    SSL_CTX *context = SSL_CTX_new(TLS_client_method());
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *verify = X509_STORE_CTX_new();
    SSL *ssl;

    assert(context != NULL && store != NULL && verify != NULL);
    ssl = SSL_new(context);
    assert(ssl != NULL);
    assert(!brix_crypto_tls_peer_name(NULL, host));
    assert(!brix_crypto_tls_peer_name(ssl, NULL));
    assert(!brix_crypto_tls_peer_name(ssl, ""));
    assert(brix_crypto_tls_peer_name(ssl, "wrong.example"));
    assert(brix_crypto_tls_peer_name(ssl, "192.0.2.17"));
    assert(brix_crypto_tls_peer_name(ssl, host));
    assert(X509_STORE_add_cert(store, certificate) == 1);
    assert(X509_STORE_CTX_init(verify, store, certificate, NULL) == 1);
    assert(X509_VERIFY_PARAM_set1(X509_STORE_CTX_get0_param(verify),
                                  SSL_get0_param(ssl)) == 1);
    X509_VERIFY_PARAM_set_depth(X509_STORE_CTX_get0_param(verify), 4);
    assert(X509_verify_cert(verify) == expected);
    X509_STORE_CTX_free(verify);
    X509_STORE_free(store);
    SSL_free(ssl);
    SSL_CTX_free(context);
}

/* WHAT: Match DNS, IPv4 and IPv6 SANs while rejecting wrong or mistyped peers.
 * WHY: Legacy-library compatibility must retain hostname authentication.
 * HOW: Verify valid names, mismatches and a numeric-DNS/CommonName impostor. */
static void
check_tls_names(void)
{
    X509 *valid = peer_name_certificate("DNS:good.example,IP:127.0.0.1,IP:::1");
    X509 *impostor = peer_name_certificate("DNS:127.0.0.1");

    check_peer_name(valid, "good.example", 1);
    check_peer_name(valid, "127.0.0.1", 1);
    check_peer_name(valid, "::1", 1);
    check_peer_name(valid, "wrong.example", 0);
    check_peer_name(valid, "127.0.0.2", 0);
    check_peer_name(valid, "::2", 0);
    check_peer_name(impostor, "127.0.0.1", 0);
    X509_free(valid);
    X509_free(impostor);
}

/* ---- Build a real one-component name for identity rendering contracts ----
 * WHAT: Return an owned CN name and assert native allocation/construction.
 * WHY: Every ABI must receive the same ASN.1 input, not a pre-escaped string.
 * HOW: 1. Allocate. 2. Add the literal value. 3. Return caller-owned name.
 */
static X509_NAME *
name_with_cn(const char *value)
{
    X509_NAME *name = X509_NAME_new();
    assert(name != NULL);
    assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char *) value, -1, -1, 0));
    return name;
}

/* ---- Preserve exact values, input ownership and allocated-output lifetime ----
 * WHAT: Assert ordinary/escaped names and the OPENSSL_free ownership contract.
 * WHY: Legacy-library normalization must not rewrite the credential's ASN.1.
 * HOW: 1. Duplicate input. 2. Render both output modes. 3. Compare and free.
 */
static void
check_name_values(void)
{
    X509_NAME *name = name_with_cn("Alice/+ops\\tail");
    X509_NAME *original = X509_NAME_dup(name);
    char output[128];
    char *owned = brix_crypto_name_oneline(name, NULL, 0);

    assert(original != NULL && owned != NULL);
    assert(strcmp(owned, "/CN=Alice\\/\\+ops\\\\tail") == 0);
    assert(brix_crypto_name_oneline(name, output, sizeof(output)) == output);
    assert(strcmp(output, owned) == 0);
    assert(X509_NAME_cmp(name, original) == 0);
    OPENSSL_free(owned);
    X509_NAME_free(original);
    X509_NAME_free(name);
}

/* ---- Refuse stale/truncated identities while honoring zero-capacity bounds ----
 * WHAT: Assert NULL, undersized and zero-capacity output return failure.
 * WHY: Prefix truncation and stale bytes must not identify another principal.
 * HOW: 1. Seed stale buffers. 2. Attempt invalid renders. 3. Verify clearing/bounds.
 */
static void
check_name_errors(void)
{
    X509_NAME *name = name_with_cn("Alice");
    char output[16] = "old identity", small[4] = "old", sentinel = 'x';

    assert(brix_crypto_name_oneline(NULL, output, sizeof(output)) == NULL);
    assert(output[0] == '\0');
    assert(brix_crypto_name_oneline(name, small, sizeof(small)) == NULL);
    assert(small[0] == '\0');
    assert(brix_crypto_name_oneline(name, &sentinel, 0) == NULL && sentinel == 'x');
    assert(brix_crypto_name_oneline(NULL, NULL, 0) == NULL);
    X509_NAME_free(name);
}

/* ---- Distinguish literal component injection from real RDN/AVA structure ----
 * WHAT: Assert a CN containing '/OU=' or '+' cannot alias a structured name.
 * WHY: Exact grid-map/authdb selectors must not grant a different certificate.
 * HOW: 1. Construct both forms. 2. Render them. 3. Compare exact representations.
 */
static void
check_name_backslash_grouping(void)
{
    X509_NAME *grouped = name_with_cn("Alice\\");
    X509_NAME *literal = name_with_cn("Alice\\+OU=admin");
    char first[128], second[128];

    assert(X509_NAME_add_entry_by_txt(grouped, "OU", MBSTRING_ASC,
        (const unsigned char *) "admin", -1, -1, -1));
    assert(brix_crypto_name_oneline(grouped, first, sizeof(first)));
    assert(brix_crypto_name_oneline(literal, second, sizeof(second)));
    assert(strcmp(first, "/CN=Alice\\\\+OU=admin") == 0);
    assert(strcmp(second, "/CN=Alice\\\\\\+OU=admin") == 0);
    assert(strcmp(first, second) != 0);
    X509_NAME_free(grouped);
    X509_NAME_free(literal);
}

/* WHAT: Keep literal escapes distinct even beside multi-valued RDN boundaries.
 * WHY: Exact policy selectors cannot accept another certificate's structure.
 * HOW: Render independently constructed literal and grouped values. */
static void
check_name_aliases(void)
{
    X509_NAME *literal = name_with_cn("Alice/OU=admin");
    X509_NAME *structured = name_with_cn("Alice");
    X509_NAME *plus = name_with_cn("Alice+OU=admin");
    X509_NAME *backslash = name_with_cn("Alice\\");
    char first[128], second[128], third[128], fourth[128];

    assert(X509_NAME_add_entry_by_txt(structured, "OU", MBSTRING_ASC,
        (const unsigned char *) "admin", -1, -1, 0));
    assert(X509_NAME_add_entry_by_txt(backslash, "OU", MBSTRING_ASC,
        (const unsigned char *) "admin", -1, -1, 0));
    assert(brix_crypto_name_oneline(literal, first, sizeof(first)));
    assert(brix_crypto_name_oneline(structured, second, sizeof(second)));
    assert(brix_crypto_name_oneline(plus, third, sizeof(third)));
    assert(brix_crypto_name_oneline(backslash, fourth, sizeof(fourth)));
    assert(strcmp(first, "/CN=Alice\\/OU=admin") == 0);
    assert(strcmp(second, "/CN=Alice/OU=admin") == 0);
    assert(strcmp(third, "/CN=Alice\\+OU=admin") == 0);
    assert(strcmp(fourth, "/CN=Alice\\\\/OU=admin") == 0);
    assert(strcmp(first, second) != 0 && strcmp(second, third) != 0);
    assert(strcmp(first, fourth) != 0);
    X509_NAME_free(literal);
    X509_NAME_free(structured);
    X509_NAME_free(plus);
    X509_NAME_free(backslash);
    check_name_backslash_grouping();
}

/* ---- Select one deterministic contract without changing library configuration ----
 * WHAT: Run one named native contract and return nonzero for invalid selection.
 * WHY: Pytest reports each failure independently on both real OpenSSL ABIs.
 * HOW: 1. Match the requested case. 2. Run assertions. 3. Report success.
 */
int
main(int argc, char **argv)
{
    if (argc != 2) { return 2; }
    if (strcmp(argv[1], "vectors") == 0) { check_vectors(); }
    else if (strcmp(argv[1], "mac-errors") == 0) { check_mac_errors(); }
    else if (strcmp(argv[1], "dh") == 0) { check_dh(); }
    else if (strcmp(argv[1], "key-errors") == 0) { check_key_errors(); }
    else if (strcmp(argv[1], "ec") == 0) { check_ec(); }
    else if (strcmp(argv[1], "keygen") == 0) { check_keygen(); }
    else if (strcmp(argv[1], "store-errors") == 0) { check_store_errors(); }
    else if (strcmp(argv[1], "tls-options") == 0) { check_tls_options(); }
    else if (strcmp(argv[1], "tls-names") == 0) { check_tls_names(); }
    else if (strcmp(argv[1], "dn-values") == 0) { check_name_values(); }
    else if (strcmp(argv[1], "dn-errors") == 0) { check_name_errors(); }
    else if (strcmp(argv[1], "dn-aliases") == 0) { check_name_aliases(); }
    else { return 2; }
    puts("OK");
    return 0;
}
