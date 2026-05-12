/*
 * JWKS loading from disk.
 */

#include "token_internal.h"
#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
xrootd_jwks_load(ngx_log_t *log, const char *path,
    xrootd_jwks_key_t *keys, int max_keys)
{
    FILE       *fp;
    char       *buf;
    long        fsize;
    int         count;
    const char *end, *val_end, *keys_arr, *p;

    fp = fopen(path, "r");
    if (fp == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "xrootd_token: cannot open JWKS file \"%s\"", path);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 65536) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_token: JWKS file too large or empty: %ld bytes",
                      fsize);
        fclose(fp);
        return -1;
    }

    buf = malloc((size_t) fsize + 1);
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

    end = buf + fsize;
    keys_arr = json_find_key(buf, end, "keys", &val_end);
    if (keys_arr == NULL || *keys_arr != '[') {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_token: JWKS missing \"keys\" array");
        free(buf);
        return -1;
    }

    count = 0;
    p = keys_arr + 1;
    while (p < val_end && count < max_keys) {
        const char *obj_start, *obj_end;
        size_t      obj_len;
        char        kty[16], kid[128], n_b64[1024], e_b64[32];
        char        crv[16], x_b64[128], y_b64[128];

        p = json_skip_ws(p, val_end);
        if (p >= val_end || *p == ']') {
            break;
        }

        obj_start = p;
        obj_end = json_skip_value(p, val_end);
        if (obj_end == NULL) {
            break;
        }

        if (*obj_start != '{') {
            p = json_skip_ws(obj_end, val_end);
            if (p < val_end && *p == ',') {
                p++;
            }
            continue;
        }

        obj_len = (size_t) (obj_end - obj_start);
        ngx_memzero(kty,   sizeof(kty));
        ngx_memzero(kid,   sizeof(kid));
        ngx_memzero(n_b64, sizeof(n_b64));
        ngx_memzero(e_b64, sizeof(e_b64));
        ngx_memzero(crv,   sizeof(crv));
        ngx_memzero(x_b64, sizeof(x_b64));
        ngx_memzero(y_b64, sizeof(y_b64));

        json_get_string(obj_start, obj_len, "kty", kty, sizeof(kty));
        json_get_string(obj_start, obj_len, "kid", kid, sizeof(kid));
        json_get_string(obj_start, obj_len, "n",   n_b64, sizeof(n_b64));
        json_get_string(obj_start, obj_len, "e",   e_b64, sizeof(e_b64));
        json_get_string(obj_start, obj_len, "crv", crv,   sizeof(crv));
        json_get_string(obj_start, obj_len, "x",   x_b64, sizeof(x_b64));
        json_get_string(obj_start, obj_len, "y",   y_b64, sizeof(y_b64));

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

        p = json_skip_ws(obj_end, val_end);
        if (p < val_end && *p == ',') {
            p++;
        }
    }

    free(buf);

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "xrootd_token: loaded %d JWKS key(s) from \"%s\"",
                  count, path);
    return count;
}

void
xrootd_jwks_free(xrootd_jwks_key_t *keys, int count)
{
    int i;

    for (i = 0; i < count; i++) {
        if (keys[i].pkey != NULL) {
            EVP_PKEY_free(keys[i].pkey);
            keys[i].pkey = NULL;
        }
    }
}
