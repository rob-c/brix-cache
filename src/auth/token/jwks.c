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
 * HOW: brix_jwks_load() — fopen(path,"r"), fcntl FD_CLOEXEC, fseek/ftell for size validation (0 < fsize ≤ 65536),
 * malloc(fsize+1), fread full file content, null-terminate buf, call brix_jwks_load_jansson(log,path,buf,fsize,keys,max_keys),
 * free(buf), return count. brix_jwks_free() — iterate i=0..count, EVP_PKEY_free non-null pkey, nullify keys[i].pkey. */

#include "token_internal.h"
#include "json.h"
#include "core/compat/log_diag.h"
#include "core/compat/safe_size.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

/* ---- Build an RSA public key from a JWK and store it in a key slot ----
 *
 * WHAT: Converts a JWK RSA "n"/"e" pair into an EVP_PKEY via
 * brix_token_rsa_pubkey_from_ne() and, on success, records kid+pkey into
 * *dest and logs an INFO line. Returns 1 when a key was stored, 0 when the
 * key material could not be turned into an EVP_PKEY (dest is left untouched).
 *
 * WHY: Isolates the RSA leg of the JWKS parser so the per-item dispatcher
 * stays flat and under the complexity budget, without altering the exact
 * store-and-log behaviour that governs which bearer keys become active.
 *
 * HOW:
 *   1. Call brix_token_rsa_pubkey_from_ne(n_b64, e_b64) to build the pkey.
 *   2. If it returns NULL, return 0 without writing dest or logging.
 *   3. Copy kid into dest->kid (bounded), assign dest->pkey, log INFO,
 *      return 1.
 */
static int
brix_jwks_store_rsa(ngx_log_t *log, const char *kid,
    const char *n_b64, const char *e_b64, brix_jwks_key_t *dest)
{
    EVP_PKEY *pkey;

    pkey = brix_token_rsa_pubkey_from_ne(n_b64, strlen(n_b64),
                                         e_b64, strlen(e_b64), log);
    if (pkey == NULL) {
        return 0;
    }

    ngx_cpystrn((u_char *) dest->kid, (u_char *) kid, sizeof(dest->kid));
    dest->pkey = pkey;
    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "brix_token: loaded RSA JWKS key kid=\"%s\"", kid);
    return 1;
}

/* ---- Build an EC P-256 public key from a JWK and store it in a key slot ----
 *
 * WHAT: Converts a JWK EC "x"/"y" pair into an EVP_PKEY via
 * brix_token_ec_pubkey_from_xy() and, on success, records kid+pkey into
 * *dest and logs an INFO line. Returns 1 when a key was stored, 0 when the
 * key material could not be turned into an EVP_PKEY (dest is left untouched).
 *
 * WHY: Isolates the EC leg of the JWKS parser so the per-item dispatcher
 * stays flat and under the complexity budget, without altering the exact
 * store-and-log behaviour that governs which bearer keys become active.
 *
 * HOW:
 *   1. Call brix_token_ec_pubkey_from_xy(x_b64, y_b64) to build the pkey.
 *   2. If it returns NULL, return 0 without writing dest or logging.
 *   3. Copy kid into dest->kid (bounded), assign dest->pkey, log INFO,
 *      return 1.
 */
static int
brix_jwks_store_ec(ngx_log_t *log, const char *kid,
    const char *x_b64, const char *y_b64, brix_jwks_key_t *dest)
{
    EVP_PKEY *pkey;

    pkey = brix_token_ec_pubkey_from_xy(x_b64, strlen(x_b64),
                                        y_b64, strlen(y_b64), log);
    if (pkey == NULL) {
        return 0;
    }

    ngx_cpystrn((u_char *) dest->kid, (u_char *) kid, sizeof(dest->kid));
    dest->pkey = pkey;
    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "brix_token: loaded EC P-256 JWKS key kid=\"%s\"", kid);
    return 1;
}

/* ---- Parse one JWKS "keys" array entry into a key slot ----
 *
 * WHAT: Extracts the JWK string fields (kty/kid/n/e/crv/x/y) from a JSON
 * object and dispatches to the RSA or EC P-256 builder. Returns 1 when a key
 * was stored into *dest, 0 when the entry was skipped (unsupported kty/crv,
 * missing key material, or a key that failed to convert). Unsupported entries
 * are logged at WARN; conversion failures are silent, matching prior behaviour.
 *
 * WHY: Concentrates the security-load-bearing field extraction and key-type
 * selection in one small, reviewable unit so the outer loop is a flat walk and
 * every accept/skip branch is preserved exactly as before.
 *
 * HOW:
 *   1. Read each JWK field with JWKS_STRING_FIELD (absent/non-string -> "").
 *   2. RSA with non-empty n and e -> brix_jwks_store_rsa(); return its result.
 *   3. EC with crv "P-256" and non-empty x and y -> brix_jwks_store_ec();
 *      return its result.
 *   4. Otherwise log a WARN naming kty/crv and return 0.
 */
static int
brix_jwks_process_item(ngx_log_t *log, json_t *item, brix_jwks_key_t *dest)
{
    const char *kty, *kid, *n_b64, *e_b64, *crv, *x_b64, *y_b64;
    json_t     *v;

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
        return brix_jwks_store_rsa(log, kid, n_b64, e_b64, dest);
    }

    if (strcmp(kty, "EC") == 0 && strcmp(crv, "P-256") == 0
        && x_b64[0] && y_b64[0])
    {
        return brix_jwks_store_ec(log, kid, x_b64, y_b64, dest);
    }

    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "brix_token: skipping JWKS key kty=\"%s\" crv=\"%s\" "
                  "(only RSA and EC P-256 supported)", kty, crv);
    return 0;
}

static int
brix_jwks_load_jansson(ngx_log_t *log, const char *path,
    const char *buf, size_t len, brix_jwks_key_t *keys, int max_keys)
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
        BRIX_DIAG_ERR(log, 0,
            "brix_token: JWKS \"%s\" is not valid JSON: %s",
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
        BRIX_DIAG_ERR(log, 0,
            "brix_token: JWKS has no \"keys\" array",
            "the JSON parsed but is not a JWKS document (no top-level "
            "\"keys\": [...] member)",
            "point the JWKS setting at the IdP's jwks_uri output; a bare "
            "single JWK or an OIDC discovery document will not work");
        return -1;
    }

    count = 0;
    json_array_foreach(arr, index, item) {
        if (!json_is_object(item) || count >= max_keys) {
            continue;
        }

        count += brix_jwks_process_item(log, item, &keys[count]);
    }

    json_decref(root);
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "brix_token: loaded %d JWKS key(s) from \"%s\" using jansson",
                  count, path);
    return count;
}

/* WHAT: Static helper — parse JWKS JSON from memory buffer into EVP_PKEY key array.
 * WHY: Separates the Jansson-specific parsing logic from disk I/O so brix_jwks_load() can swap backends
 * (e.g., file-based vs HTTP-fetched JWKS) without changing parser internals.
 * HOW: json_loadb() parses buffer into json_t root; validate root is object then extract "keys" array (return -1 if missing);
 * json_array_foreach() iterates each item, extracting kty/kid/n_b64/e_b64/crv/x_b64/y_b64 via JWKS_STRING_FIELD macro;
 * for RSA keys: call brix_token_rsa_pubkey_from_ne(n_b64,e_b64) → EVP_PKEY; for EC P-256: call brix_token_ec_pubkey_from_xy(x_b64,y_b64);
 * store kid+pkey into keys[count], increment count, skip unsupported kty with WARN log; json_decref(root), return count. */

int
brix_jwks_load(ngx_log_t *log, const char *path,
    brix_jwks_key_t *keys, int max_keys)
/* WHAT: Load JWKS public keys from disk file into caller-supplied key array for OIDC token verification.
 * WHY: Provides the startup-time key loading entry point — callers open a JWKS JSON file and receive parsed
 * EVP_PKEY handles indexed by kid, ready for brix_token_verify_bearer() lookup.
 * HOW: fopen(path,"r"), fcntl(fileno(fp),F_SETFD,FD_CLOEXEC) for safe fork behavior; fseek/ftell validate size (0 < fsize ≤ 65536);
 * malloc(fsize+1), fread full content, null-terminate buf; call brix_jwks_load_jansson(log,path,buf,fsize,keys,max_keys); free(buf); return count. */
{
    FILE  *fp;
    char  *buf;
    long   fsize;
    int    count;

    fp = fopen(path, "r");
    if (fp == NULL) {
        BRIX_DIAG_ERR(log, ngx_errno,
            "brix_token: cannot open JWKS file \"%s\"",
            "the path is wrong, or the file is unreadable by the nginx user",
            "check brix_token_jwks points at a readable file (the JWKS "
            "refresh job must write it where nginx can read); the OS reason "
            "is appended below",
            path);
        return -1;
    }
    fcntl(fileno(fp), F_SETFD, FD_CLOEXEC);

    if (fseek(fp, 0, SEEK_END) != 0
        || (fsize = ftell(fp)) < 0
        || fseek(fp, 0, SEEK_SET) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "brix_token: cannot determine JWKS file size \"%s\"",
                      path);
        (void) fclose(fp); /* phase74-fp: read-only stream on an error path already returning -1 */
        return -1;
    }

    if (fsize <= 0 || fsize > 65536) {
        BRIX_DIAG_ERR(log, 0,
            "brix_token: JWKS file is empty or too large (%ld bytes)",
            "an empty file usually means the refresh job failed mid-write; "
            ">64 KiB means it is not a JWKS document",
            "ensure the JWKS is written atomically and contains just the key "
            "set; until then token authentication is rejected",
            fsize);
        (void) fclose(fp); /* phase74-fp: read-only stream on an error path already returning -1 */
        return -1;
    }

    /* Defense-in-depth: reject a negative or wraparound fsize before malloc. */
    size_t buf_sz;
    if (fsize < 0 || brix_size_add((size_t) fsize, 1, &buf_sz) != NGX_OK) {
        (void) fclose(fp); /* phase74-fp: read-only stream on an error path already returning -1 */
        return -1;
    }
    buf = malloc(buf_sz);
    if (buf == NULL) {
        (void) fclose(fp); /* phase74-fp: read-only stream on an error path already returning -1 */
        return -1;
    }

    if (fread(buf, 1, (size_t) fsize, fp) != (size_t) fsize) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "brix_token: failed to read JWKS file");
        free(buf);
        (void) fclose(fp); /* phase74-fp: read-only stream on an error path already returning -1 */
        return -1;
    }
    buf[fsize] = '\0';
    (void) fclose(fp); /* phase74-fp: read-only stream fully read (fread length verified above) */

    count = brix_jwks_load_jansson(log, path, buf, (size_t) fsize,
                                     keys, max_keys);
    free(buf);
    return count;
}

/* Pool-cleanup shim: holds the array + a pointer to the live count so the
 * handler frees whatever set of keys is current when the pool is destroyed
 * (the refresh path rewrites the array in place and updates the count). */
typedef struct {
    brix_jwks_key_t *keys;
    int               *count;
} brix_jwks_cleanup_t;

static void
brix_jwks_pool_cleanup(void *data)
{
    brix_jwks_cleanup_t *c = data;

    brix_jwks_free(c->keys, *c->count);
}

ngx_int_t
brix_jwks_register_cleanup(ngx_pool_t *pool, brix_jwks_key_t *keys,
    int *count)
{
    ngx_pool_cleanup_t    *cln;
    brix_jwks_cleanup_t *c;

    cln = ngx_pool_cleanup_add(pool, sizeof(brix_jwks_cleanup_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    c = cln->data;
    c->keys = keys;
    c->count = count;
    cln->handler = brix_jwks_pool_cleanup;

    return NGX_OK;
}

void
brix_jwks_free(brix_jwks_key_t *keys, int count)
/* WHAT: Free all EVP_PKEY handles loaded by brix_jwks_load() to prevent memory leaks.
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
