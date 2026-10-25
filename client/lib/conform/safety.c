/*
 * Phase-118 prefix-bound mutation path builder.
 *
 * WHAT: Constructs a normalized child path that cannot escape its scratch root.
 * WHY: Mutating probes must be structurally unable to name operator data.
 * HOW: Require absolute prefix, reject empty/dot/control components, then join.
 */
#include "conform/run.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

/* ---- Validate a scratch-relative leaf ----
 *
 * WHAT: Returns one only for slash-separated ordinary relative components.
 * WHY: Rejecting dot, empty and control-bearing components prevents traversal.
 * HOW: Scan each component, rejecting absolute input and exact dot components.
 */
static int
scratch_leaf_valid(const char *leaf)
{
    const char *component;
    const char *cursor;

    if (leaf == NULL || leaf[0] == '\0' || leaf[0] == '/') return 0;
    component = leaf;
    cursor = leaf;
    for (;;) {
        if (*cursor == '/' || *cursor == '\0') {
            size_t len = (size_t) (cursor - component);

            if (len == 0 || (len == 1 && component[0] == '.')
                || (len == 2 && component[0] == '.' && component[1] == '.')) {
                return 0;
            }
            if (*cursor == '\0') return 1;
            component = cursor + 1;
        } else if (iscntrl((unsigned char) *cursor)) {
            return 0;
        }
        cursor++;
    }
}

static int
scratch_control_args_valid(const char *leaf, unsigned char control)
{
    return leaf != NULL && leaf[0] != '\0' && leaf[0] != '/'
        && (control < 0x20 || control == 0x7f);
}

/* Validate the one deliberately hostile leaf shape used by DIR-004.  This is
 * deliberately separate from scratch_leaf_valid(): ordinary callers remain
 * unable to mint control-bearing mutation authority. */
static int
scratch_control_leaf_valid(const char *leaf, unsigned char control)
{
    const char *component;
    const char *cursor;
    size_t controls = 0;

    if (!scratch_control_args_valid(leaf, control)) return 0;
    component = leaf;
    cursor = leaf;
    for (;;) {
        unsigned char byte = (unsigned char) *cursor;

        if (*cursor == '/' || *cursor == '\0') {
            size_t len = (size_t) (cursor - component);

            if (len == 0 || (len == 1 && component[0] == '.')
                || (len == 2 && component[0] == '.' && component[1] == '.'))
                return 0;
            if (*cursor == '\0') return controls == 1;
            if (controls != 0) return 0;
            component = cursor + 1;
        } else if (iscntrl(byte)) {
            if (byte != control) return 0;
            controls++;
        }
        cursor++;
    }
}

static int
scratch_join(const char *prefix, const char *leaf, char *out, size_t out_size)
{
    size_t prefix_len;
    int written;

    if (prefix == NULL || prefix[0] != '/' || out == NULL || out_size == 0)
        return -1;
    prefix_len = strlen(prefix);
    while (prefix_len > 1 && prefix[prefix_len - 1] == '/') prefix_len--;
    written = snprintf(out, out_size, "%.*s/%s", (int) prefix_len, prefix,
        leaf);
    return written < 0 || (size_t) written >= out_size ? -1 : 0;
}

/* ---- Build one path confined beneath the caller's scratch prefix ----
 *
 * WHAT: Returns zero with joined path, or -1 for unsafe/oversized input.
 * WHY: Mutating probes receive this builder rather than concatenate paths.
 * HOW: Validate absolute prefix and relative leaf, normalize one slash, bound.
 */
int
brix_conform_scratch_path(const char *prefix, const char *leaf,
    char *out, size_t out_size)
{
    if (!scratch_leaf_valid(leaf)) return -1;
    return scratch_join(prefix, leaf, out, out_size);
}

/* Mint one prefix-bound hostile-name capability for a conformance fixture.
 * Exactly one caller-selected C0/DEL byte is required; traversal, empty
 * components and every other control byte remain forbidden. */
int
brix_conform_scratch_control_path(const char *prefix, const char *leaf,
    unsigned char control, char *out, size_t out_size)
{
    if (!scratch_control_leaf_valid(leaf, control)) return -1;
    return scratch_join(prefix, leaf, out, out_size);
}
