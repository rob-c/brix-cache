/*
 * json_min.h — minimal, dependency-free JSON value extractor (libxrdproto).
 *
 * WHAT: Extract one top-level object member's value from a JSON document, with
 *       no external dependency (libc only — NO jansson).  String values are
 *       unescaped; scalar values (number/true/false/null) are returned as their
 *       raw token text.
 * WHY:  The native client (xrddiag/explain) needs to peek at a few JWT claims for
 *       DIAGNOSTIC display only, and must not link jansson.  The previous client
 *       helper was a fragile strstr() hack that mis-parsed escaped quotes and
 *       could match a key inside a value; this is a proper string-aware scanner.
 *       The server keeps its jansson-based src/token/json.c for the security-
 *       critical JWKS/JWT paths — this is strictly the lightweight diagnostic core.
 * HOW:  A small non-recursive scanner walks the top-level object, correctly
 *       skipping over string contents and nested objects/arrays so a key is only
 *       matched in object-key position at depth 1.
 *
 * This is a DIAGNOSTIC helper, not a validating parser: it does not reject every
 * malformed document, only enough to extract a well-formed member safely.
 */
#ifndef BRIX_JSON_MIN_H
#define BRIX_JSON_MIN_H

#include <stddef.h>

/*
 * Extract the value of top-level object key `key` from the JSON document in
 * [json, json+len).  A string value has its JSON escapes decoded (including
 * \uXXXX, with surrogate pairs, to UTF-8); a scalar value (number/true/false/
 * null) is copied as its raw token text.  An object/array value is NOT copied
 * (returns 0) since it has no flat-string form.  The result is written
 * NUL-terminated into out[outsz], truncated to fit.
 *
 * Returns 1 if the key was found and a string/scalar value copied, 0 otherwise
 * (not found, value is object/array, malformed input, or out too small).
 */
int brix_json_get_str(const char *json, size_t len, const char *key,
    char *out, size_t outsz);

#endif /* BRIX_JSON_MIN_H */
