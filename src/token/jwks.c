/* JWKS (JSON Web Key Set) loading from disk — parse RSA and EC P-256 public keys for OIDC token verification.
 *
 * WHAT: Loads a JWKS JSON file from disk, parses the "keys" array to extract RSA (n/e) and EC P-256 (crv/x/y)
 * key parameters, converts them into EVP_PKEY objects via OpenSSL, stores kid + pkey pairs in caller-supplied
 * keys array. Also provides cleanup function to free all loaded EVP_PKEY handles.
 *
 * WHY: OIDC token verification requires the public key matching the token's "kid" header claim. JWKS is the
 * standard format for publishing a provider's rotating set of public keys. Loading from disk at startup lets
 * the server verify bearer tokens without HTTP round-trips to the provider's JWKS endpoint.
 *
 * HOW: xrootd_jwks_load() — fopen(path,"r"), fcntl FD_CLOEXEC, fseek/ftell for size validation (0 < fsize ≤ 65536),
 * malloc(fsize+1), fread full file content, null-terminate buf, call xrootd_jwks_load_jansson(log,path,buf,fsize,keys,max_keys),
 * free(buf), return count. xrootd_jwks_free() — iterate i=0..count, EVP_PKEY_free non-null pkey, nullify keys[i].pkey. */

#include "token_internal.h"
#include "json.h"
#include "../compat/log_diag.h"
#include "../shared/safe_size.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

static int
xrootd_jwks_load_jansson(ngx_log_t *log, const char *path,
    const char *buf, size_t len, xrootd_jwks_key_t *keys, int max_keys)
{
    json_error_t  err;
    json_t       *root, *arr, *item;
    size_t        index;
    int           count;

    root = json_loadb(buf, len, 0, &err);
    if (root == NULL || !json_is_object(root)) {
        if (root != NULL) {
            json_decref(root);
        }
        XROOTD_DIAG_ERR(log, 0,
            "xrootd_token: JWKS \"%s\" is not valid JSON: %s",
            "the JWKS file is truncated, HTML (an error page), or was fetched "
            "to the wrong path",
            "verify the file holds the IdP's real JWKS JSON; until it parses, "
            "ALL bearer-token authentication is rejected",
            path, err.text);
        return -1;
    }

    arr = json_object_get(root, "keys");
    if (!json_is_array(arr)) {
        json_decref(root);
        XROOTD_DIAG_ERR(log, 0,
            "xrootd_token: JWKS has no \"keys\" array",
            "the JSON parsed but is not a JWKS document (no top-level "
            "\"keys\": [...] member)",
            "point the JWKS setting at the IdP's jwks_uri output; a bare "
            "single JWK or an OIDC discovery document will not work");
        return -1;
    }

    count = 0;
    json_array_foreach(arr, index, item) {
        const char *kty, *kid, *n_b64, *e_b64, *crv, *x_b64, *y_b64;
        json_t     *v;

        if (!json_is_object(item) || count >= max_keys) {
            continue;
        }

#define JWKS_STRING_FIELD(obj, field) \
        (v = json_object_get((obj), (field)), json_is_string(v) ? json_string_value(v) : "")

        kty   = JWKS_STRING_FIELD(item, "kty");
        kid   = JWKS_STRING_FIELD(item, "kid");
        n_b64 = JWKS_STRING_FIELD(item, "n");
        e_b64 = JWKS_STRING_FIELD(item, "e");
        crv   = JWKS_STRING_FIELD(item, "crv");
        x_b64 = JWKS_STRING_FIELD(item, "x");
        y_b64 = JWKS_STRING_FIELD(item, "y");

#undef JWKS_STRING_FIELD

        if (strcmp(kty, "RSA") == 0 && n_b64[0] && e_b64[0]) {
            EVP_PKEY *pkey;

            pkey = xrootd_token_rsa_pubkey_from_ne(n_b64, strlen(n_b64),
                                                   e_b64, strlen(e_b64),
                                                   log);
            if (pkey != NULL) {
                ngx_cpystrn((u_char *) keys[count].kid,
                            (u_char *) kid, sizeof(keys[count].kid));
                keys[count].pkey = pkey;
                count++;
                ngx_log_error(NGX_LOG_INFO, log, 0,
                              "xrootd_token: loaded RSA JWKS key kid=\"%s\"",
                              kid);
            }
        } else if (strcmp(kty, "EC") == 0 && strcmp(crv, "P-256") == 0
                   && x_b64[0] && y_b64[0])
        {
            EVP_PKEY *pkey;

            pkey = xrootd_token_ec_pubkey_from_xy(x_b64, strlen(x_b64),
                                                  y_b64, strlen(y_b64),
                                                  log);
            if (pkey != NULL) {
                ngx_cpystrn((u_char *) keys[count].kid,
                            (u_char *) kid, sizeof(keys[count].kid));
                keys[count].pkey = pkey;
                count++;
                ngx_log_error(NGX_LOG_INFO, log, 0,
                              "xrootd_token: loaded EC P-256 JWKS key kid=\"%s\"",
                              kid);
            }
        } else {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_token: skipping JWKS key kty=\"%s\" crv=\"%s\" "
                          "(only RSA and EC P-256 supported)", kty, crv);
        }
    }

    json_decref(root);
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "xrootd_token: loaded %d JWKS key(s) from \"%s\" using jansson",
                  count, path);
    return count;
}

/* WHAT: Static helper — parse JWKS JSON from memory buffer into EVP_PKEY key array.
 * WHY: Separates the Jansson-specific parsing logic from disk I/O so xrootd_jwks_load() can swap backends
 * (e.g., file-based vs HTTP-fetched JWKS) without changing parser internals.
 * HOW: json_loadb() parses buffer into json_t root; validate root is object then extract "keys" array (return -1 if missing);
 * json_array_foreach() iterates each item, extracting kty/kid/n_b64/e_b64/crv/x_b64/y_b64 via JWKS_STRING_FIELD macro;
 * for RSA keys: call xrootd_token_rsa_pubkey_from_ne(n_b64,e_b64) → EVP_PKEY; for EC P-256: call xrootd_token_ec_pubkey_from_xy(x_b64,y_b64);
 * store kid+pkey into keys[count], increment count, skip unsupported kty with WARN log; json_decref(root), return count. */

int
xrootd_jwks_load(ngx_log_t *log, const char *path,
    xrootd_jwks_key_t *keys, int max_keys)
/* WHAT: Load JWKS public keys from disk file into caller-supplied key array for OIDC token verification.
 * WHY: Provides the startup-time key loading entry point — callers open a JWKS JSON file and receive parsed
 * EVP_PKEY handles indexed by kid, ready for xrootd_token_verify_bearer() lookup.
 * HOW: fopen(path,"r"), fcntl(fileno(fp),F_SETFD,FD_CLOEXEC) for safe fork behavior; fseek/ftell validate size (0 < fsize ≤ 65536);
 * malloc(fsize+1), fread full content, null-terminate buf; call xrootd_jwks_load_jansson(log,path,buf,fsize,keys,max_keys); free(buf); return count. */
{
    FILE  *fp;
    char  *buf;
    long   fsize;
    int    count;

    fp = fopen(path, "r");
    if (fp == NULL) {
        XROOTD_DIAG_ERR(log, ngx_errno,
            "xrootd_token: cannot open JWKS file \"%s\"",
            "the path is wrong, or the file is unreadable by the nginx user",
            "check xrootd_token_jwks points at a readable file (the JWKS "
            "refresh job must write it where nginx can read); the OS reason "
            "is appended below",
            path);
        return -1;
    }
    fcntl(fileno(fp), F_SETFD, FD_CLOEXEC);

    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 65536) {
        XROOTD_DIAG_ERR(log, 0,
            "xrootd_token: JWKS file is empty or too large (%ld bytes)",
            "an empty file usually means the refresh job failed mid-write; "
            ">64 KiB means it is not a JWKS document",
            "ensure the JWKS is written atomically and contains just the key "
            "set; until then token authentication is rejected",
            fsize);
        fclose(fp);
        return -1;
    }

    /* Defense-in-depth: reject a negative or wraparound fsize before malloc. */
    size_t buf_sz;
    if (fsize < 0 || xrootd_size_add((size_t) fsize, 1, &buf_sz) != NGX_OK) {
        fclose(fp);
        return -1;
    }
    buf = malloc(buf_sz);
    if (buf == NULL) {
        fclose(fp);
        return -1;
    }

    if (fread(buf, 1, (size_t) fsize, fp) != (size_t) fsize) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "xrootd_token: failed to read JWKS file");
        free(buf);
        fclose(fp);
        return -1;
    }
    buf[fsize] = '\0';
    fclose(fp);

    count = xrootd_jwks_load_jansson(log, path, buf, (size_t) fsize,
                                     keys, max_keys);
    free(buf);
    return count;
}

/* Pool-cleanup shim: holds the array + a pointer to the live count so the
 * handler frees whatever set of keys is current when the pool is destroyed
 * (the refresh path rewrites the array in place and updates the count). */
typedef struct {
    xrootd_jwks_key_t *keys;
    int               *count;
} xrootd_jwks_cleanup_t;

static void
xrootd_jwks_pool_cleanup(void *data)
{
    xrootd_jwks_cleanup_t *c = data;

    xrootd_jwks_free(c->keys, *c->count);
}

ngx_int_t
xrootd_jwks_register_cleanup(ngx_pool_t *pool, xrootd_jwks_key_t *keys,
    int *count)
{
    ngx_pool_cleanup_t    *cln;
    xrootd_jwks_cleanup_t *c;

    cln = ngx_pool_cleanup_add(pool, sizeof(xrootd_jwks_cleanup_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    c = cln->data;
    c->keys = keys;
    c->count = count;
    cln->handler = xrootd_jwks_pool_cleanup;

    return NGX_OK;
}

void
xrootd_jwks_free(xrootd_jwks_key_t *keys, int count)
/* WHAT: Free all EVP_PKEY handles loaded by xrootd_jwks_load() to prevent memory leaks.
 * WHY: JWKS keys are allocated at startup; this cleanup function must be called before shutdown or when reloading
 * a new JWKS file to avoid leaking OpenSSL EVP_PKEY resources.
 * HOW: Iterate i=0..count-1, for each non-null keys[i].pkey call EVP_PKEY_free(), then nullify keys[i].pkey to prevent double-free. */
{
    int i;

    for (i = 0; i < count; i++) {
        if (keys[i].pkey != NULL) {
            EVP_PKEY_free(keys[i].pkey);
            keys[i].pkey = NULL;
        }
    }
}
