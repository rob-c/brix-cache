#ifndef BRIX_JSON_ITER_H
#define BRIX_JSON_ITER_H
#include <stddef.h>

/* WHAT: json_min extensions for walking OCI manifests — a raw-span getter
 *       (any value type, delimiters included) and an array-element iterator.
 * WHY:  brix_json_get_str deliberately refuses object/array values; manifest
 *       walking needs `layers[]` / `manifests[].platform` spans. json_min
 *       itself is frozen, so the additions live beside it (phase-104 D5.2).
 * HOW:  same discipline: libc only, no allocation, byte-bounded, and nesting
 *       deeper than BRIX_JSON_DEPTH_MAX is malformed — a hostile manifest
 *       cannot stack-bomb or spin the scanner. Keys are matched as literal
 *       bytes (manifest keys are plain ASCII; escaped keys do not match). */

#define BRIX_JSON_DEPTH_MAX 32

/* Find top-level object key `key` in [json, json+len) and return its VALUE
 * span — raw bytes including string quotes / braces / brackets. 1 found,
 * 0 not found, -1 malformed (bad structure or depth cap). */
int brix_json_get_raw(const char *json, size_t len, const char *key,
                      const char **out, size_t *outlen);

/* Iterate the elements of the array in [arr, arr+arrlen) (the raw span from
 * brix_json_get_raw, brackets included). *cursor must be 0 on the first
 * call and is opaque afterwards. Returns 1 with the element's raw span in
 * *elem / *elemlen, 0 at end of array, -1 malformed. */
int brix_json_arr_next(const char *arr, size_t arrlen, size_t *cursor,
                       const char **elem, size_t *elemlen);

#endif /* BRIX_JSON_ITER_H */
