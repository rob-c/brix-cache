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

/* One auth-param: key [ "=" ( token / quoted-string ) ]. The value is copied
 * with quoted-pair escapes resolved; overlong values are a refusal. */
static int ch_param(const char *s, size_t n, size_t *i,
                    char *key, size_t keycap, char *val, size_t valcap) {
    size_t k = 0, v = 0;

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
    if (*i >= n || s[*i] != '=') {
        val[0] = '\0';
        return 0;
    }
    (*i)++;
    ch_ws(s, n, i);
    if (*i < n && s[*i] == '"') {
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
            return -1;    /* unterminated quoted-string */
        (*i)++;
    } else {
        while (*i < n && s[*i] != ',' && s[*i] != ' ' && s[*i] != '\t') {
            if (v + 1 >= valcap)
                return -1;
            val[v++] = s[*i];
            (*i)++;
        }
    }
    val[v] = '\0';
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
        if (strcasecmp(key, "realm") == 0) {
            if (strlen(val) >= sizeof(out->realm))
                return -1;
            memcpy(out->realm, val, strlen(val) + 1);
        } else if (strcasecmp(key, "service") == 0) {
            if (strlen(val) >= sizeof(out->service))
                return -1;
            memcpy(out->service, val, strlen(val) + 1);
        } else if (strcasecmp(key, "scope") == 0) {
            if (strlen(val) >= sizeof(out->scope))
                return -1;
            memcpy(out->scope, val, strlen(val) + 1);
        } else if (strcasecmp(key, "error") == 0) {
            if (strlen(val) >= sizeof(out->error))
                return -1;
            memcpy(out->error, val, strlen(val) + 1);
        }
        ch_ws(value, len, &i);
        if (i < len) {
            if (value[i] != ',')
                return -1;
            i++;
        }
    }
    return out->realm[0] != '\0' ? 0 : -1;
}
