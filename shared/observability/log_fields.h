/*
 * log_fields.h — bounded, single-line diagnostic fields for every native role.
 * WHAT: Quote message bytes and identify a repository-relative source.
 * WHY: Server and standalone diagnostics must agree on log-injection handling.
 * HOW: Header-only pure functions; no allocation, mutable globals, or host API.
 */
#pragma once

#include <stddef.h>
#include <string.h>

/*
 * WHAT: Escape a byte span into a NUL-terminated quoted-field body; return the
 * number of consumed bytes so the caller can report truncation explicitly.
 * WHY: Quotes, backslashes and control bytes must not create extra records or
 * fields. Spaces remain readable inside the caller's surrounding quotes.
 * HOW: 1. Copy printable ASCII. 2. Encode other bytes as complete \xNN escapes.
 * 3. Stop before a partial escape or missing terminator would be emitted.
 */
static inline size_t
brix_log_quote(const char *input, size_t length, char *output, size_t capacity)
{
    const char *hex = "0123456789abcdef";
    size_t consumed = 0;
    size_t written = 0;

    if (capacity == 0) {
        return 0;
    }
    while (consumed < length) {
        unsigned char byte = (unsigned char) input[consumed];
        int escaped = byte < 0x20 || byte > 0x7e || byte == '"' || byte == '\\';
        size_t needed = escaped ? 4 : 1;

        if (needed >= capacity - written) {
            break;
        }
        if (escaped) {
            output[written++] = '\\';
            output[written++] = 'x';
            output[written++] = hex[byte >> 4];
            output[written++] = hex[byte & 15];
        } else {
            output[written++] = (char) byte;
        }
        consumed++;
    }
    output[written] = '\0';
    return consumed;
}

/*
 * WHAT: Return a source path relative to src/, client/, tools/, or utils/.
 * WHY: Installation/build-machine paths are noisy and disclose local details.
 * HOW: 1. Locate a known repository root. 2. Otherwise retain only the basename.
 */
static inline const char *
brix_log_source(const char *source)
{
    const char *roots[] = { "/src/", "/client/", "/tools/", "/utils/" };
    const char *best = NULL;
    size_t index;

    for (index = 0; index < sizeof(roots) / sizeof(roots[0]); index++) {
        const char *start = strstr(source, roots[index]);
        while (start != NULL) {
            if (best == NULL || start > best) {
                best = start;
            }
            start = strstr(start + 1, roots[index]);
        }
    }
    if (best != NULL) {
        return best + 1;
    }
    /* Relative compiler inputs already have the desired shape. */
    if (source[0] != '/') {
        return source;
    }
    source = strrchr(source, '/') + 1;
    return source;
}
