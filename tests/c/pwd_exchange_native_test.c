/* Native password exchange: real DH agreement and decryption, with explicit
 * crypto/allocation refusals at the public primitive seams. */
#include "auth/sec/sec.h"
#include "auth/gsi/gsi_core.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fault(const char *name)
{
    const char *value = getenv("BRIX_PWD_FAULT");
    return value != NULL && strcmp(value, name) == 0;
}

EVP_PKEY *__real_brix_gsi_cipher_keygen(void);
char *__real_brix_gsi_cipher_public(EVP_PKEY *, size_t *);
int __real_brix_gsi_cipher_session_key(EVP_PKEY *, EVP_PKEY *, int, uint8_t *, int);
int __real_brix_gsi_cipher_lookup(const char *, brix_gsi_cipher_t *);
uint8_t *__real_brix_gsi_cipher_apply(const brix_gsi_cipher_t *, const uint8_t *,
                                    const uint8_t *, size_t, int, int, size_t *);
void *__real_realloc(void *, size_t);

EVP_PKEY *__wrap_brix_gsi_cipher_keygen(void)
{
    return fault("keygen") ? NULL : __real_brix_gsi_cipher_keygen();
}
char *__wrap_brix_gsi_cipher_public(EVP_PKEY *key, size_t *length)
{
    return fault("public") ? NULL : __real_brix_gsi_cipher_public(key, length);
}
int __wrap_brix_gsi_cipher_session_key(EVP_PKEY *mine, EVP_PKEY *peer, int padded,
                                      uint8_t *key, int length)
{
    return fault("agreement") ? 0
        : __real_brix_gsi_cipher_session_key(mine, peer, padded, key, length);
}
int __wrap_brix_gsi_cipher_lookup(const char *name, brix_gsi_cipher_t *cipher)
{
    return fault("cipher") ? 0 : __real_brix_gsi_cipher_lookup(name, cipher);
}
uint8_t *__wrap_brix_gsi_cipher_apply(const brix_gsi_cipher_t *cipher, const uint8_t *key,
    const uint8_t *input, size_t size, int use_iv, int encrypt, size_t *length)
{
    return fault("encrypt") ? NULL
        : __real_brix_gsi_cipher_apply(cipher, key, input, size, use_iv, encrypt, length);
}
void *__wrap_realloc(void *pointer, size_t size)
{
    char *skip = getenv("BRIX_PWD_ALLOC_SKIP");
    if (fault("allocation")) {
        if (skip != NULL && skip[0] == '1') { skip[0] = '0'; }
        else { return NULL; }
    }
    return __real_realloc(pointer, size);
}

/* WHAT: Generate a valid server challenge. WHY: Verify actual agreement.
 * HOW: Reuse the client's advertised group, derive a server-side decrypt key. */
static void server_challenge(const uint8_t *first, size_t length, brix_gbuf *challenge,
                             uint8_t key[16], const char *kind)
{
    const uint8_t *wire;
    size_t wire_len, pub_len;
    EVP_PKEY *peer, *server;
    char *pub;
    assert(brix_gsi_find_bucket(first, length, 3004, &wire, &wire_len) == 0);
    peer = brix_gsi_cipher_parse_peer(wire, wire_len);
    assert(peer != NULL);
    server = brix_gsi_cipher_keygen_from(peer);
    assert(server != NULL);
    assert(brix_gsi_cipher_session_key(server, peer, 0, key, 16) == 1);
    pub = brix_gsi_cipher_public(server, &pub_len);
    assert(pub != NULL);
    brix_gbuf_init(challenge);
    brix_gbuf_raw(challenge, "pwd", 4);
    brix_gbuf_u32(challenge, 1003);
    if (strcmp(kind, "missing") != 0) {
        if (strcmp(kind, "invalid") == 0) { brix_gbuf_bucket(challenge, 3004, "invalid", 7); }
        else { brix_gbuf_bucket(challenge, 3004, pub, pub_len); }
    }
    brix_gbuf_end(challenge);
    assert(!challenge->err);
    free(pub); EVP_PKEY_free(server); EVP_PKEY_free(peer);
}

/* WHAT: Check the peer-visible payload. WHY: Password bytes must be encrypted.
 * HOW: Parse the outer bucket, decrypt using the independently derived key. */
static void verify_reply(const uint8_t *reply, size_t length, const uint8_t key[16],
                          const char *expected)
{
    const uint8_t *encrypted, *password;
    size_t encrypted_len, plain_len, password_len, expected_len = strlen(expected);
    uint8_t *plain;
    brix_gsi_cipher_t cipher;
    if (expected_len > 256) { expected_len = 256; }
    assert(brix_gsi_find_bucket(reply, length, 3001, &encrypted, &encrypted_len) == 0);
    assert(brix_gsi_cipher_lookup("aes-128-cbc", &cipher) == 1);
    plain = brix_gsi_cipher_apply(&cipher, key, encrypted, encrypted_len, 0, 0, &plain_len);
    assert(plain != NULL);
    assert(brix_gsi_find_bucket(plain, plain_len, 3010, &password, &password_len) == 0);
    assert(password_len == expected_len && memcmp(password, expected, expected_len) == 0);
    assert(memmem(reply, length, expected, expected_len) == NULL);
    OPENSSL_cleanse(plain, plain_len); free(plain);
}

static void assert_first(const uint8_t *first, size_t length, const char *user)
{
    const uint8_t *value;
    size_t size;
    assert(memcmp(first, "pwd\0", 4) == 0);
    assert(brix_gsi_find_bucket(first, length, 3008, &value, &size) == 0);
    assert(strlen(user) == size && memcmp(value, user, size) == 0);
    assert(brix_gsi_find_bucket(first, length, 3014, &value, &size) == 0 && size == 4);
    assert(value[0] == 0 && value[1] == 0 && value[2] == 39 && value[3] == 116);
    assert(brix_gsi_find_bucket(first, length, 3010, &value, &size) == -1);
}

static int run_more(const brix_sec_module *module, const uint8_t *first, size_t length,
                     const char *mode, const char *injection, const char *expected)
{
    brix_gbuf challenge;
    uint8_t key[16], *reply = NULL;
    uint32_t reply_len = 0;
    brix_status st = {0};
    int rc;
    server_challenge(first, length, &challenge, key, mode);
    assert(setenv("BRIX_PWD_FAULT", injection, 1) == 0);
    rc = module->more(NULL, challenge.p, (uint32_t) challenge.len, &reply, &reply_len, &st);
    assert(unsetenv("BRIX_PWD_FAULT") == 0);
    brix_gbuf_free(&challenge);
    if (strcmp(mode, "error") == 0 || strcmp(mode, "missing") == 0
        || strcmp(mode, "invalid") == 0) {
        assert(rc == -1 && reply == NULL && reply_len == 0);
        printf("REFUSED %s\n", st.msg);
    } else {
        assert(rc == 0 && reply != NULL);
        verify_reply(reply, reply_len, key, expected);
        free(reply);
        reply = NULL; reply_len = 0;
        assert(module->more(NULL, NULL, 0, &reply, &reply_len, &st) == -1);
        assert(reply == NULL && strstr(st.msg, "server key missing") != NULL);
        printf("VERIFIED encrypted password and consumed session key\n");
    }
    OPENSSL_cleanse(key, sizeof(key));
    return 0;
}

int main(int argc, char **argv)
{
    const brix_sec_module *module = brix_sec_pwd();
    brix_status st = {0};
    uint8_t *first = NULL;
    uint32_t length = 0;
    int rc;
    assert(argc == 7 && strcmp(module->name, "pwd") == 0);
    assert(module->have_creds(NULL) == atoi(argv[5]));
    if (strcmp(argv[1], "no-session") == 0) {
        assert(module->more(NULL, NULL, 0, &first, &length, &st) == -1);
        assert(first == NULL && length == 0); puts(st.msg); return 0;
    }
    if (strcmp(argv[1], "first-error") == 0) {
        assert(setenv("BRIX_PWD_FAULT", argv[2], 1) == 0);
    }
    rc = module->first(NULL, "", &first, &length, &st);
    assert(unsetenv("BRIX_PWD_FAULT") == 0);
    if (strcmp(argv[1], "first-error") == 0) {
        assert(rc == -1 && first == NULL && length == 0);
        printf("REFUSED %s\n", st.msg); return 0;
    }
    assert(rc == 0 && first != NULL);
    if (strcmp(argv[1], "repeat") == 0) {
        free(first); first = NULL; length = 0;
        assert(module->first(NULL, "", &first, &length, &st) == 0);
    }
    assert_first(first, length, argv[4]);
    assert(setenv("BRIX_PWD_ALLOC_SKIP", argv[6], 1) == 0);
    rc = run_more(module, first, length, argv[1], argv[2], argv[3]);
    free(first);
    return rc;
}
