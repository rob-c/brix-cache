/* Real GSI crypto round trips and finite provider/allocation failures. */
#include "core/ngx_brix_module.h"
#include "auth/gsi/gsi_core_internal.h"
#include <assert.h>

typedef struct { ngx_cycle_t cycle; const char *fault; int armed; } fixture;
/* WHAT: Select one finite failure. WHY: Preserve real cryptography otherwise. HOW: Read caller-owned cycle state. */
static int failing(const char *name)
{
    fixture *f = (fixture *) ngx_cycle;
    return f->armed && !strcmp(f->fault, name);
}
#define FAILURE_WRAPPER(type, name, args, call, label, refused) \
    type __real_##name args; \
    type __wrap_##name args { \
        if (failing(label)) { return refused; } \
        return __real_##name call; \
    }
FAILURE_WRAPPER(void *, malloc, (size_t n), (n), "malloc", NULL)
FAILURE_WRAPPER(EVP_PKEY_CTX *, EVP_PKEY_CTX_new, (EVP_PKEY *p, ENGINE *e), (p,e), "ctx", NULL)
FAILURE_WRAPPER(EVP_PKEY_CTX *, EVP_PKEY_CTX_new_from_name,
    (OSSL_LIB_CTX *c, const char *n, const char *p), (c,n,p), "ctx-name", NULL)
FAILURE_WRAPPER(int, EVP_PKEY_keygen_init, (EVP_PKEY_CTX *c), (c), "keygen-init", 0)
FAILURE_WRAPPER(int, EVP_PKEY_keygen, (EVP_PKEY_CTX *c, EVP_PKEY **p), (c,p), "keygen", 0)
FAILURE_WRAPPER(int, EVP_PKEY_CTX_set_params,
    (EVP_PKEY_CTX *c, const OSSL_PARAM p[]), (c,p), "params", 0)
FAILURE_WRAPPER(int, EVP_PKEY_get_bn_param,
    (const EVP_PKEY *p, const char *n, BIGNUM **b), (p,n,b), "public", 0)
FAILURE_WRAPPER(char *, BN_bn2hex, (const BIGNUM *b), (b), "hex-print", NULL)
FAILURE_WRAPPER(int, BN_hex2bn, (BIGNUM **b, const char *h), (b,h), "hex-parse", 0)
FAILURE_WRAPPER(int, EVP_PKEY_derive_init, (EVP_PKEY_CTX *c), (c), "derive-init", 0)
FAILURE_WRAPPER(int, EVP_PKEY_derive_set_peer,
    (EVP_PKEY_CTX *c, EVP_PKEY *p), (c,p), "peer", 0)
FAILURE_WRAPPER(BIO *, BIO_new_mem_buf, (const void *b, int n), (b,n), "bio-memory", NULL)
FAILURE_WRAPPER(BIO *, BIO_new, (const BIO_METHOD *m), (m), "bio", NULL)
FAILURE_WRAPPER(EVP_PKEY *, PEM_read_bio_Parameters,
    (BIO *b, EVP_PKEY **p), (b,p), "read-parameters", NULL)
FAILURE_WRAPPER(int, PEM_write_bio_Parameters,
    (BIO *b, const EVP_PKEY *p), (b,p), "write-parameters", 0)
FAILURE_WRAPPER(EVP_CIPHER_CTX *, EVP_CIPHER_CTX_new, (void), (), "cipher-ctx", NULL)
FAILURE_WRAPPER(int, RAND_bytes, (unsigned char *b, int n), (b,n), "rng", 0)
FAILURE_WRAPPER(int, EVP_CipherInit_ex,
    (EVP_CIPHER_CTX *c, const EVP_CIPHER *t, ENGINE *e,
     const unsigned char *k, const unsigned char *iv, int enc), (c,t,e,k,iv,enc), "cipher-init", 0)
FAILURE_WRAPPER(int, EVP_CipherUpdate,
    (EVP_CIPHER_CTX *c, unsigned char *out, int *n, const unsigned char *in, int count),
    (c,out,n,in,count), "cipher-update", 0)
FAILURE_WRAPPER(int, EVP_CipherFinal_ex,
    (EVP_CIPHER_CTX *c, unsigned char *out, int *n), (c,out,n), "cipher-final", 0)
int __real_EVP_PKEY_derive(EVP_PKEY_CTX *, unsigned char *, size_t *);
/* WHAT: Fail one derivation phase. WHY: Check query/output cleanup separately. HOW: Preserve real peer math on normal paths. */
int __wrap_EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *length)
{
    if ((!out && failing("derive-size")) || (out && failing("derive-output"))) { return 0; }
    if (!out && failing("short-secret")) { *length = 1; return 1; }
    return __real_EVP_PKEY_derive(ctx, out, length);
}

/* WHAT: Compare both sides of DH. WHY: Catch wrong group/padding or truncated keys. HOW: Execute reciprocal real derivations and compare bytes. */
static int derive(EVP_PKEY *mine, EVP_PKEY *peer, int session, int padded)
{
    if (session) {
        unsigned char key[BRIX_GSI_MAX_KEY], reverse[BRIX_GSI_MAX_KEY];
        memset(key, 0xa5, sizeof(key));
        int rc = brix_gsi_cipher_session_key(mine, peer, padded, key, 32);
        if (!rc) {
            for (size_t n = 0; n < sizeof(key); ++n) { assert(key[n] == 0xa5); }
            return 0;
        }
        assert(brix_gsi_cipher_session_key(peer, mine, padded, reverse, 32));
        assert(!memcmp(key, reverse, 32)); return 1;
    }
    size_t n = 0, m = 0;
    unsigned char *a = brix_gsi_dh_derive(mine, peer, &n);
    if (!a) { return 0; }
    unsigned char *b = brix_gsi_dh_derive(peer, mine, &m);
    assert(b && n == m && n >= 32 && !memcmp(a,b,n)); free(a);free(b);return 1;
}
/* WHAT: Exercise public-key encodings. WHY: Pin binary lengths and malformed-input refusal. HOW: Round-trip the real DH public value. */
static int public_key(EVP_PKEY *key, const char *action, const char *blob, size_t length)
{
    if (!strcmp(action,"decode")) {
        BIGNUM *number=brix_gsi_dh_pub_decode((const uint8_t *)blob,length);
        int ok=number!=NULL;BN_free(number);return ok;
    }
    if (!strcmp(action,"parse")) {
        EVP_PKEY *peer=brix_gsi_cipher_parse_peer((const uint8_t *)blob,length);
        int ok=peer!=NULL;EVP_PKEY_free(peer);return ok;
    }
    if (!strcmp(action,"encode")) {
        char *text=brix_gsi_dh_pub_encode(key);int ok=text!=NULL;
        if (text) { assert(strstr(text,"---BPUB---") && strstr(text,"---EPUB--")); }
        free(text);return ok;
    }
    size_t size=0;char *text=brix_gsi_cipher_public(key,&size);int ok=text!=NULL;
    if (text) { assert(size>100 && memmem(text,size,"BEGIN DH PARAMETERS",19)); }
    else { assert(size==0); }
    free(text);return ok;
}
/* WHAT: Round-trip negotiated AES. WHY: Verify IV prefix and refusal before output publication. HOW: Encrypt then decrypt actual bytes. */
static int cipher(int iv, const char *name)
{
    brix_gsi_cipher_t type;assert(brix_gsi_cipher_lookup(name,&type));
    unsigned char key[BRIX_GSI_MAX_KEY]={0},message[]={0,1,2,3,0xff,0,0xaa};
    size_t encrypted_size=0,plain_size=0;
    uint8_t *encrypted=brix_gsi_cipher_apply(&type,key,message,sizeof(message),iv,1,&encrypted_size);
    if (!encrypted) { assert(encrypted_size==0);return 0; }
    uint8_t *plain=brix_gsi_cipher_apply(&type,key,encrypted,encrypted_size,iv,0,&plain_size);
    assert(plain && plain_size==sizeof(message) && !memcmp(message,plain,plain_size));
    free(encrypted);free(plain);return 1;
}
/* WHAT: Run a finite crypto contract. WHY: Isolate provider failures from setup. HOW: Arm faults only after generating real compatible keys. */
int main(int argc,char **argv)
{
    assert(argc==5);fixture f={0};ngx_cycle=&f.cycle;f.fault=argv[2];
    EVP_PKEY *mine=brix_gsi_dh_keygen();assert(mine);
    EVP_PKEY *peer=brix_gsi_cipher_keygen_from(mine);assert(peer);
    size_t length=0;char *blob=brix_gsi_cipher_public(peer,&length);assert(blob);
    const char *input=blob;
    if (strcmp(argv[4],"normal")) { input=argv[4];length=strlen(input); }
    f.armed=1;int ok=0;
    if (!strcmp(argv[1],"keygen") || !strcmp(argv[1],"fixed-keygen")) {
        EVP_PKEY *key=!strcmp(argv[1],"keygen") ? brix_gsi_dh_keygen() : brix_gsi_cipher_keygen();
        ok=key!=NULL;EVP_PKEY_free(key);
    } else if (!strcmp(argv[1],"derive") || !strcmp(argv[1],"session")) {
        ok=derive(mine,peer,!strcmp(argv[1],"session"),atoi(argv[3]));
    } else if (!strcmp(argv[1],"cipher")) { ok=cipher(atoi(argv[3]),input); }
    else { ok=public_key(mine,argv[1],input,length); }
    f.armed=0;free(blob);EVP_PKEY_free(peer);EVP_PKEY_free(mine);
    printf("accepted=%d\n",ok);return 0;
}
