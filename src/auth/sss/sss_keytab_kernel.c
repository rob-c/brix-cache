/*
 * sss_keytab_kernel.c — shared SSS keytab text grammar. See sss_keytab_kernel.h.
 *
 * Pure C, no nginx / OpenSSL / I/O, so it links into both the module and the
 * native client (libxrdproto) as the single source of truth for how a keytab
 * line is tokenised and how a keytab file's permissions are judged. Hex decoding
 * reuses the shared codec (compat/hex.c); the parser fails closed on any
 * malformed required field.
 */
#include "sss_keytab_kernel.h"
#include "core/compat/hex.h"   /* shared hex nibble decode (libxrdproto) */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Bounded copy of a NUL-terminated field into dst[dst_len]; -1 if it won't fit. */
static int
sss_copy_field(char *dst, size_t dst_len, const char *src)
{
    size_t len = strlen(src);
    if (len >= dst_len) {
        return -1;
    }
    memcpy(dst, src, len + 1);
    return 0;
}

/* Decode a hex key string into out (bounded by SSS_K_KEY_MAX); -1 on bad input. */
static int
sss_decode_hex(const char *hex, uint8_t *out, size_t *out_len)
{
    size_t n = strlen(hex), i;

    if (n == 0 || (n & 1) || n / 2 > SSS_K_KEY_MAX) {
        return -1;
    }
    for (i = 0; i < n; i += 2) {
        int hi = brix_hex_from_char((unsigned char) hex[i]);
        int lo = brix_hex_from_char((unsigned char) hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i / 2] = (uint8_t) ((hi << 4) | lo);
    }
    *out_len = n / 2;
    return 0;
}

/* Strict int64 parse (rejects empty / trailing non-numeric / overflow). */
static int
sss_parse_i64(const char *text, int64_t *out)
{
    char      *end;
    long long  v;

    errno = 0;
    v = strtoll(text, &end, 10);
    if (errno || end == text || *end != '\0') {
        return -1;
    }
    *out = (int64_t) v;
    return 0;
}

/*
 * WHAT: Seed *out with the neutral entry defaults before field parsing.
 * WHY:  Every optional text field has a documented default ("nobody" /
 *       "nogroup" / "nowhere") and the required numeric id starts at -1 so a
 *       missing N: is detectable; a clean zero-init also clears the key buffer.
 * HOW:  memset to zero, then set id and the three default strings verbatim —
 *       byte-for-byte identical to the original inline initialisation.
 */
static void
sss_entry_set_defaults(sss_keytab_entry_t *out)
{
    memset(out, 0, sizeof(*out));
    out->id = -1;
    memcpy(out->user, "nobody", sizeof("nobody"));
    memcpy(out->group, "nogroup", sizeof("nogroup"));
    memcpy(out->name, "nowhere", sizeof("nowhere"));
}

/*
 * WHAT: Validate the leading version tag of a keytab line.
 * WHY:  Only the "0" and "1" grammar versions are supported; a blank line or a
 *       comment must be skipped, and any other tag rejects the whole line.
 * HOW:  Returns 1 for a valid tag, 0 for blank/comment (skip), -1 for an
 *       unsupported tag — mirroring the original leading branches exactly.
 */
static int
sss_check_version_tag(const char *field)
{
    if (field == NULL || field[0] == '#') {
        return 0;                       /* blank / comment */
    }
    if (strcmp(field, "0") != 0 && strcmp(field, "1") != 0) {
        return -1;                      /* unsupported version tag */
    }
    return 1;
}

/*
 * WHAT: Apply one "x:value" field token to the entry being built.
 * WHY:  Keeping the per-key dispatch in one focused helper drops the parse
 *       loop's branching to a single call and preserves the exact field-order
 *       independence and reject-on-malformed semantics of the original switch.
 * HOW:  key is field[0], v is the value after "x:". Copies/decodes into the
 *       matching field; returns 0 on success (including unknown keys, which are
 *       ignored) and -1 on any malformed required value.
 */
static int
sss_apply_field(sss_keytab_entry_t *out, char key, const char *v)
{
    switch (key) {
    case 'u':
        return sss_copy_field(out->user, sizeof(out->user), v);
    case 'g':
        return sss_copy_field(out->group, sizeof(out->group), v);
    case 'n':
        return sss_copy_field(out->name, sizeof(out->name), v);
    case 'N':
        return sss_parse_i64(v, &out->id);
    case 'e':
        return sss_parse_i64(v, &out->exp);
    case 'k':
        return sss_decode_hex(v, out->key, &out->key_len);
    default:
        return 0;                       /* unknown field — ignore */
    }
}

/*
 * WHAT: Tokenise the remaining fields of a keytab line into *out.
 * WHY:  The value-field loop is the bulk of the grammar; isolating it keeps the
 *       top-level parser small while retaining the exact "x:value" shape check,
 *       inline-comment stop, and fail-closed behaviour.
 * HOW:  Continues the strtok_r walk started by the caller (via *save). Stops at
 *       an inline '#', ignores tokens that are not "x:value", and returns -1 on
 *       the first malformed value; 0 when the line is fully consumed.
 */
static int
sss_parse_fields(char **save, sss_keytab_entry_t *out)
{
    char *field;

    while ((field = strtok_r(NULL, " \t\r\n", save)) != NULL) {
        if (field[0] == '#') {
            break;                      /* inline comment */
        }
        if (field[1] != ':') {
            continue;                   /* not a "x:value" field — ignore */
        }
        if (sss_apply_field(out, field[0], field + 2) != 0) {
            return -1;
        }
    }
    return 0;
}

int
sss_keytab_parse_line(char *line, sss_keytab_entry_t *out, int64_t now)
{
    char *field, *save;
    int   tag;

    field = strtok_r(line, " \t\r\n", &save);
    tag = sss_check_version_tag(field);
    if (tag <= 0) {
        return tag;                     /* 0 = blank/comment, -1 = bad tag */
    }

    sss_entry_set_defaults(out);

    if (sss_parse_fields(&save, out) != 0) {
        return -1;                      /* malformed field */
    }

    if (out->id < 0 || out->key_len == 0) {
        return -1;                      /* required field missing */
    }
    if (out->exp != 0 && out->exp <= now) {
        return 0;                       /* expired — skip */
    }
    return 1;
}

int
sss_keytab_mode_ok(const char *path, mode_t mode, int allow_dotgrp)
{
    mode_t allowed = S_IRUSR | S_IWUSR;

    if (allow_dotgrp) {
        size_t len = strlen(path);
        if (len >= 4 && strcmp(path + len - 4, ".grp") == 0) {
            allowed |= S_IRGRP;
        }
    }
    return ((mode & (S_IRWXG | S_IRWXO)) & ~allowed) ? -1 : 0;
}
