#ifndef TOKEN_JSON_H
#define TOKEN_JSON_H
#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) || defined(_WIN64)
# include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
# include <sys/types.h>
#endif

ssize_t json_get_string(const char *json, size_t json_len, const char *key,
    char *out, size_t out_max);
/* Extract a single string value from JSON by key into caller-supplied output buffer
 * with bounds checking. Returns copy length on success, -1 on failure.
 * json/json_len: raw JSON buffer and its length; key: field name to extract;
 * out/out_max: destination buffer and capacity (copy capped at out_max-1). */
int json_get_string_array(const char *json, size_t json_len, const char *key,
    char out[][256], int max_items);
/* Extract an array of string values from JSON by key into a fixed-size output
 * array with per-item 256-byte truncation. Returns count on success, 0 on failure. */
int json_get_int64(const char *json, size_t json_len, const char *key, int64_t *out);
/* Extract a single integer value from JSON by key into caller-supplied int64 output pointer. Returns 0 on success, -1 on failure (key missing or non-integer). */
int json_string_or_array_contains(const char *json, size_t json_len,
    const char *key, const char *needle);
/* Returns 1 if json[key] is a STRING equal to needle, OR an ARRAY of strings
 * containing needle; 0 otherwise. RFC 7519 §4.1.3 allows the JWT "aud" claim to
 * be either form, so the audience check must accept both. Comparison is exact
 * (no truncation). */
int json_has_member(const char *json, size_t json_len, const char *key);
/* Returns 1 if the JSON object has a member named `key`, else 0.
 * Used by the JWS `crit` header check: RFC 7515 §4.1.11 requires that any
 * token carrying a `crit` header be rejected by a processor that does not
 * implement the listed extension parameters. */
/* Return the string name of the active JSON parsing backend ("jansson"). Used
 * for logging, metrics labels, and conditional behaviour across backends. */
const char *json_backend_name(void);

#endif /* TOKEN_JSON_H */
