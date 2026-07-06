/* Jansson-backed JSON helpers for JWT/JWKS parsing.
 *
 * WHAT: Four thin wrappers around the jansson API providing safe string extraction (single value and array),
 * int64 extraction, and backend identification — keeping callers isolated from jansson types so the token layer
 * only needs json.h.
 *
 * WHY: The token layer parses JWT claims, JWKS keys, and OIDC metadata in JSON format. These helpers abstract
 * away json_t type checking, reference counting (json_decref), and buffer bounds so callers get plain C strings
 * and int64 values without jansson API knowledge.
 */

#include "json.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <jansson.h>

ssize_t
json_get_string(const char *json, size_t json_len, const char *key,
    char *out, size_t out_max)
/* WHAT: Extract a single string value from JSON by key into caller-supplied output buffer with bounds checking.
 * WHY: Used to extract JWT claims (sub, iss, aud), JWKS fields (kid, kty, n, e), and OIDC metadata strings
 * without exposing callers to json_t type handling or reference counting.
 * HOW: Validate out_max>0 and all pointers non-null; json_loadb() parse buffer into json_t root; check root is object;
 * json_object_get(root,key); verify value is string; extract length via json_string_length(); copy min(length, out_max-1) bytes
 * to out with null terminator; json_decref(root); return copy_len or -1 on any failure. */
{
    json_error_t  err;
    json_t       *root;
    json_t       *value;
    const char   *str;
    size_t        copy_len;

    if (out_max == 0 || json == NULL || key == NULL || out == NULL) {
        return -1;
    }

    root = json_loadb(json, json_len, JSON_DECODE_INT_AS_REAL, &err);
    if (root == NULL || !json_is_object(root)) {
        if (root != NULL) {
            json_decref(root);
        }
        return -1;
    }

    value = json_object_get(root, key);
    if (!json_is_string(value)) {
        json_decref(root);
        return -1;
    }

    str = json_string_value(value);
    copy_len = json_string_length(value);
    if (copy_len >= out_max) {
        copy_len = out_max - 1;
    }

    memcpy(out, str, copy_len);
    out[copy_len] = '\0';
    json_decref(root);

    return (ssize_t) copy_len;
}

int
json_get_string_array(const char *json, size_t json_len, const char *key,
    char out[][256], int max_items)
/* WHAT: Extract an array of string values from JSON by key into caller-supplied fixed-size output array.
 * WHY: Used to extract JWT claim arrays (aud), JWKS fields, and OIDC metadata lists where multiple string
 * values need to be collected safely with per-item 256-byte truncation bounds.
 * HOW: Validate max_items>0 and all pointers non-null; json_loadb() parse buffer into json_t root; check root is object;
 * json_object_get(root,key); verify array type; json_array_foreach() iterate each item, skip non-strings; extract string length;
 * copy min(length,255) bytes to out[count] with null terminator; increment count; break at max_items limit; json_decref(root); return count. */
{
    json_error_t  err;
    json_t       *root;
    json_t       *array;
    json_t       *item;
    size_t        index;
    int           count;

    if (max_items <= 0 || json == NULL || key == NULL || out == NULL) {
        return 0;
    }

    root = json_loadb(json, json_len, JSON_DECODE_INT_AS_REAL, &err);
    if (root == NULL || !json_is_object(root)) {
        if (root != NULL) {
            json_decref(root);
        }
        return 0;
    }

    array = json_object_get(root, key);
    if (!json_is_array(array)) {
        json_decref(root);
        return 0;
    }

    count = 0;
    json_array_foreach(array, index, item) {
        const char *str;
        size_t      copy_len;

        if (!json_is_string(item)) {
            continue;
        }

        str = json_string_value(item);
        copy_len = json_string_length(item);
        if (copy_len > 255) {
            copy_len = 255;
        }

        memcpy(out[count], str, copy_len);
        out[count][copy_len] = '\0';
        count++;
        if (count >= max_items) {
            break;
        }
    }

    json_decref(root);
    return count;
}

int
json_get_int64(const char *json, size_t json_len, const char *key,
    int64_t *out)
/* WHAT: Extract a single numeric value from JSON by key into caller-supplied int64 output pointer.
 * WHY: Used to extract JWT numeric claims (exp, iat, nbf).  RFC 7519 §2 permits
 * NumericDate to be fractional (float); jansson would fail to parse integers that
 * overflow int64 (e.g. far-future exp = 99999999999999999999) unless given the
 * JSON_DECODE_INT_AS_REAL flag, which causes all numbers to be represented as
 * json_real so that over-range integers do not abort the document parse.
 * HOW: Validate all pointers non-null; json_loadb() with JSON_DECODE_INT_AS_REAL
 * so oversized integers are parsed as reals; json_object_get(root,key); accept
 * json_integer (exact) OR json_real (truncate fractional, clamp huge positive
 * doubles that would overflow int64_t on the cast); return 0 on success, -1 on
 * any failure. */
{
    json_error_t  err;
    json_t       *root;
    json_t       *value;
    double        d;

    if (json == NULL || key == NULL || out == NULL) {
        return -1;
    }

    /*
     * JSON_DECODE_INT_AS_REAL: parse all JSON numbers as json_real so that
     * over-range integers (> INT64_MAX) do not cause a document parse error.
     * This allows "exp":99999999999999999999 (far-future timestamp) to be read
     * and accepted rather than failing the whole payload decode.
     */
    root = json_loadb(json, json_len, JSON_DECODE_INT_AS_REAL, &err);
    if (root == NULL || !json_is_object(root)) {
        if (root != NULL) {
            json_decref(root);
        }
        return -1;
    }

    value = json_object_get(root, key);
    if (json_is_integer(value)) {
        /* Exact integer path (kept for completeness; JSON_DECODE_INT_AS_REAL
         * means this branch will not fire in practice, but is safe if the
         * flag behaviour ever changes). */
        *out = (int64_t) json_integer_value(value);
    } else if (json_is_real(value)) {
        d = json_real_value(value);
        /*
         * Truncate fractional seconds as RFC 7519 §2 requires.
         * Guard against the cast UB that occurs when d > INT64_MAX: on x86-64
         * cvttsd2si yields INT64_MIN for out-of-range inputs, which the
         * caller's "exp > 0" check would then incorrectly treat as expired.
         * Clamp to INT64_MAX so far-future tokens are accepted.
         * 9223372036854775808.0 is 2^63, the first double above INT64_MAX.
         */
        if (d >= 9223372036854775808.0) {
            *out = INT64_MAX;
        } else {
            *out = (int64_t) d;
        }
    } else {
        json_decref(root);
        return -1;
    }
    json_decref(root);
    return 0;
}

int
json_string_or_array_contains(const char *json, size_t json_len,
    const char *key, const char *needle)
/* WHAT: Membership test for a JWT claim that may be a string or an array of
 * strings (RFC 7519 §4.1.3 "aud"). Returns 1 if json[key] is a string equal to
 * needle, or an array containing a string equal to needle; 0 otherwise.
 * WHY: json_get_string() rejects arrays, so using it for the audience check
 * silently false-denies tokens whose aud is the (spec-legal, common) array form.
 * HOW: json_loadb() parse; json_object_get(key); if string, strcmp; if array,
 * json_array_foreach + strcmp each string item; json_decref; return match. */
{
    json_error_t  err;
    json_t       *root;
    json_t       *value;
    json_t       *item;
    size_t        index;
    int           found = 0;

    if (json == NULL || key == NULL || needle == NULL) {
        return 0;
    }

    root = json_loadb(json, json_len, JSON_DECODE_INT_AS_REAL, &err);
    if (root == NULL || !json_is_object(root)) {
        if (root != NULL) {
            json_decref(root);
        }
        return 0;
    }

    value = json_object_get(root, key);
    if (json_is_string(value)) {
        found = (strcmp(json_string_value(value), needle) == 0);
    } else if (json_is_array(value)) {
        json_array_foreach(value, index, item) {
            if (json_is_string(item)
                && strcmp(json_string_value(item), needle) == 0)
            {
                found = 1;
                break;
            }
        }
    }

    json_decref(root);
    return found;
}

int
json_has_member(const char *json, size_t json_len, const char *key)
/* WHAT: Returns 1 if the JSON object has a member named `key`, else 0.
 * WHY: Used by the JWS `crit` check (RFC 7515 §4.1.11): any token whose
 * header contains a `crit` member MUST be rejected by a processor that does
 * not understand the listed extension parameters.  This helper avoids exposing
 * callers to jansson reference-counting or type-checking detail.
 * HOW: json_loadb() parse buffer into json_t root; check root is object;
 * json_object_get(root, key) != NULL → member present; json_decref(root);
 * return 1 (found) or 0 (missing/parse failure). */
{
    json_error_t  err;
    json_t       *root;
    int           found;

    if (json == NULL || key == NULL) {
        return 0;
    }

    root = json_loadb(json, json_len, JSON_DECODE_INT_AS_REAL, &err);
    if (root == NULL || !json_is_object(root)) {
        if (root != NULL) {
            json_decref(root);
        }
        return 0;
    }

    found = (json_object_get(root, key) != NULL) ? 1 : 0;
    json_decref(root);
    return found;
}

const char *
json_backend_name(void)
/* WHAT: Return the string name of the active JSON parsing backend.
 * WHY: Used by callers (e.g., token validation handlers) to identify which JSON library is in use for logging,
 * metrics labels, or conditional behavior when switching between backends.
 * HOW: Always returns "jansson" — static string constant matching the build-time dependency. */
{
    return "jansson";
}
