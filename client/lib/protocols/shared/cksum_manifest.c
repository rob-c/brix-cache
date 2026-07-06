/* cksum_manifest.c — parse/format the tree-audit manifest line format.
 *
 * WHAT: A single parser for the sha256sum-style manifest line format used by
 *       `xrdcksum tree` (writer) and `xrdcksum check` (reader):
 *         "<hex>  <rel>\n"   (two spaces — sha256sum -c compatible)
 * WHY:  A hostile or corrupt manifest must never direct reads or comparisons
 *       outside the audit root.  Centralising the parse + safety gate keeps the
 *       security invariant in one place rather than duplicated across two
 *       subcommands.
 * HOW:  strstr for the mandatory two-space separator; isxdigit for every digit
 *       character; brix_rel_is_unsafe for the path guard (absolute / "..").
 *       Oversized fields are rejected before writing so callers need no truncation
 *       guard. */
#include "brix.h"
#include "brix_ops.h"
#include <ctype.h>
#include <string.h>

/*
 * brix_ckmf_parse_line — parse one manifest line into hex + rel.
 *
 * WHAT: Splits "<hex>  <rel>\n" at the two-space separator, strips the trailing
 *       newline/CRLF, and validates both halves before writing them.
 * WHY:  All callers must use this gate; the security contract is that no rel path
 *       returned here can ever escape the audit root directory.
 * HOW:  strstr locates the separator; isxdigit validates each hex character;
 *       brix_rel_is_unsafe rejects absolute paths and ".." components.  Every
 *       error path returns -1 without modifying the output buffers.
 *
 * Returns 0 with hex[hexsz] and rel[relsz] filled (NUL-terminated), or -1 when:
 *   - line is NULL or empty
 *   - no "  " (double-space) separator found, or hex part is empty
 *   - hex part contains a non-hex character
 *   - hex or rel part would not fit in the supplied buffer (overflow guard)
 *   - rel part is empty after stripping the newline
 *   - brix_rel_is_unsafe(rel) is true (absolute path or ".." escape)
 */
int
brix_ckmf_parse_line(const char *line, char *hex, size_t hexsz,
                     char *rel, size_t relsz)
{
    const char *sep;
    const char *r;
    size_t      hl, rl;

    if (line == NULL) {
        return -1;
    }
    sep = strstr(line, "  ");
    if (sep == NULL || sep == line) {
        return -1;
    }
    hl = (size_t)(sep - line);
    if (hl >= hexsz) {
        return -1;
    }
    for (r = line; r < sep; r++) {
        if (!isxdigit((unsigned char)*r)) {
            return -1;
        }
    }
    /* rel starts two characters after the separator; strip trailing newline. */
    r  = sep + 2;
    rl = strlen(r);
    while (rl > 0 && (r[rl - 1] == '\n' || r[rl - 1] == '\r')) {
        rl--;
    }
    if (rl == 0 || rl >= relsz) {
        return -1;
    }
    /* Guard: reject any path that escapes the audit root. */
    /* Copy rel to a temporary NUL-terminated string for brix_rel_is_unsafe. */
    memcpy(rel, r, rl);
    rel[rl] = '\0';
    if (brix_rel_is_unsafe(rel)) {
        return -1;
    }
    memcpy(hex, line, hl);
    hex[hl] = '\0';
    return 0;
}
