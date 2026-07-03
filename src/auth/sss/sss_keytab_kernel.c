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

int
sss_keytab_parse_line(char *line, sss_keytab_entry_t *out, int64_t now)
{
    char *field, *save;

    field = strtok_r(line, " \t\r\n", &save);
    if (field == NULL || field[0] == '#') {
        return 0;                       /* blank / comment */
    }
    if (strcmp(field, "0") != 0 && strcmp(field, "1") != 0) {
        return -1;                      /* unsupported version tag */
    }

    memset(out, 0, sizeof(*out));
    out->id = -1;
    memcpy(out->user, "nobody", sizeof("nobody"));
    memcpy(out->group, "nogroup", sizeof("nogroup"));
    memcpy(out->name, "nowhere", sizeof("nowhere"));

    while ((field = strtok_r(NULL, " \t\r\n", &save)) != NULL) {
        const char *v;
        if (field[0] == '#') {
            break;                      /* inline comment */
        }
        if (field[1] != ':') {
            continue;                   /* not a "x:value" field — ignore */
        }
        v = field + 2;
        switch (field[0]) {
        case 'u':
            if (sss_copy_field(out->user, sizeof(out->user), v) != 0) {
                return -1;
            }
            break;
        case 'g':
            if (sss_copy_field(out->group, sizeof(out->group), v) != 0) {
                return -1;
            }
            break;
        case 'n':
            if (sss_copy_field(out->name, sizeof(out->name), v) != 0) {
                return -1;
            }
            break;
        case 'N':
            if (sss_parse_i64(v, &out->id) != 0) {
                return -1;
            }
            break;
        case 'e':
            if (sss_parse_i64(v, &out->exp) != 0) {
                return -1;
            }
            break;
        case 'k':
            if (sss_decode_hex(v, out->key, &out->key_len) != 0) {
                return -1;
            }
            break;
        default:
            break;                      /* unknown field — ignore */
        }
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
