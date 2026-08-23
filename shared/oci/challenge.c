/* challenge.c — WWW-Authenticate Bearer challenge parse (see challenge.h). */
#define _POSIX_C_SOURCE 200809L
#include "oci/challenge.h"

#include <string.h>
#include <strings.h>

static int ch_ws(const char *s, size_t n, size_t *i) {
    while (*i < n && (s[*i] == ' ' || s[*i] == '\t'))
        (*i)++;
    return *i < n;
}

/*
 * WHAT: Parse a bounded authentication-parameter key token.
 * WHY:  Keys end at separators and must fit the caller's fixed buffer.
 * HOW:  Copy until grammar punctuation, reject empty/overlong tokens, then trim.
 */
static int ch_key(const char *s, size_t n, size_t *i,
                  char *key, size_t keycap) {
    size_t k = 0;

    while (*i < n && s[*i] != '=' && s[*i] != ',' && s[*i] != ' ' &&
           s[*i] != '\t') {
        if (k + 1 >= keycap)
            return -1;
        key[k++] = s[*i];
        (*i)++;
    }
    key[k] = '\0';
    if (k == 0)
        return -1;
    ch_ws(s, n, i);
    return 0;
}

/*
 * WHAT: Parse an RFC quoted authentication value with quoted-pair escapes.
 * WHY:  Realm URLs and scopes commonly arrive quoted and may contain escapes.
 * HOW:  Consume quotes, resolve backslash pairs, and refuse missing closure.
 */
static int ch_quoted_value(const char *s, size_t n, size_t *i,
                           char *val, size_t valcap) {
    size_t v = 0;

    (*i)++;
    while (*i < n && s[*i] != '"') {
        char c = s[*i];

        if (c == '\\' && *i + 1 < n) {
            (*i)++;
            c = s[*i];
        }
        if (v + 1 >= valcap)
            return -1;
        val[v++] = c;
        (*i)++;
    }
    if (*i >= n)
        return -1;
    (*i)++;
    val[v] = '\0';
    return 0;
}

/*
 * WHAT: Parse an unquoted authentication value token.
 * WHY:  The challenge grammar permits both token and quoted-string values.
 * HOW:  Copy through the next comma or whitespace within the fixed buffer.
 */
static int ch_token_value(const char *s, size_t n, size_t *i,
                          char *val, size_t valcap) {
    size_t v = 0;

    while (*i < n && s[*i] != ',' && s[*i] != ' ' && s[*i] != '\t') {
        if (v + 1 >= valcap)
            return -1;
        val[v++] = s[*i];
        (*i)++;
    }
    val[v] = '\0';
    return 0;
}

/* One auth-param: key [ "=" ( token / quoted-string ) ]. The value is copied
 * with quoted-pair escapes resolved; overlong values are a refusal. */
static int ch_param(const char *s, size_t n, size_t *i,
                    char *key, size_t keycap, char *val, size_t valcap) {
    if (ch_key(s, n, i, key, keycap) != 0)
        return -1;
    if (*i >= n || s[*i] != '=') {
        val[0] = '\0';
        return 0;
    }
    (*i)++;
    ch_ws(s, n, i);
    if (*i < n && s[*i] == '"')
        return ch_quoted_value(s, n, i, val, valcap);
    return ch_token_value(s, n, i, val, valcap);
}

/*
 * WHAT: Copy one recognized challenge value into its public output field.
 * WHY:  Every field must enforce its own destination capacity before copying.
 * HOW:  Select by case-insensitive key and use one checked-copy operation.
 */
static int ch_store(brix_oci_challenge_t *out, const char *key,
                    const char *val) {
    char  *dst = NULL;
    size_t cap = 0;
    size_t len = strlen(val);

    if (strcasecmp(key, "realm") == 0) {
        dst = out->realm;
        cap = sizeof(out->realm);
    } else if (strcasecmp(key, "service") == 0) {
        dst = out->service;
        cap = sizeof(out->service);
    } else if (strcasecmp(key, "scope") == 0) {
        dst = out->scope;
        cap = sizeof(out->scope);
    } else if (strcasecmp(key, "error") == 0) {
        dst = out->error;
        cap = sizeof(out->error);
    } else {
        return 0;
    }
    if (len >= cap)
        return -1;
    memcpy(dst, val, len + 1);
    return 0;
}

int brix_oci_challenge_parse(const char *value, size_t len,
                             brix_oci_challenge_t *out) {
    size_t i = 0;

    memset(out, 0, sizeof(*out));
    ch_ws(value, len, &i);
    if (len - i < 6 || strncasecmp(value + i, "Bearer", 6) != 0)
        return -1;
    i += 6;
    if (i < len && value[i] != ' ' && value[i] != '\t')
        return -1;    /* "Bearerx" is not a Bearer challenge */

    while (ch_ws(value, len, &i)) {
        char key[32], val[512];

        if (value[i] == ',') {    /* empty list elements are legal */
            i++;
            continue;
        }
        if (ch_param(value, len, &i, key, sizeof(key), val,
                     sizeof(val)) != 0)
            return -1;
        if (ch_store(out, key, val) != 0)
            return -1;
        ch_ws(value, len, &i);
        if (i < len) {
            if (value[i] != ',')
                return -1;
            i++;
        }
    }
    return out->realm[0] != '\0' ? 0 : -1;
}
