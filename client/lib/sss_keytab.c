/*
 * sss_keytab.c — SSS keytab text I/O + the credential crypto kernels.
 *
 * See sss_keytab.h for the contract. The CRC32 and Blowfish-CFB64 routines are
 * reimplemented from the wire spec (matching src/sss/auth_crypto_helpers.c), not
 * copied from XrdSecsss — clean-room. The keytab grammar matches the server's
 * parser in src/sss/config.c exactly.
 */
#include "sss_keytab.h"
#include "compat/crc32_ieee.h"   /* shared CRC-32/IEEE (libxrdproto) */
#include "compat/sss_bf.h"       /* shared Blowfish-CFB64 (libxrdproto) */
#include "compat/hex.h"          /* shared hex encode/from_char (libxrdproto) */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

/* ------------------------------------------------------------------ */
/* crypto kernels                                                      */
/* ------------------------------------------------------------------ */

/* Forwards to the shared CRC-32/IEEE kernel (libxrdproto) so client-mint and
 * server-verify of the SSS blob use one source of truth. */
uint32_t
xrdc_sss_crc32(const uint8_t *p, size_t len)
{
    return xrootd_crc32_ieee(p, len);
}

/* Forwards to the shared Blowfish-CFB64 kernel (libxrdproto), which owns the
 * OpenSSL-3 legacy-provider load — one source of truth with the server's SSS path. */
int
xrdc_sss_bf32_encrypt(const uint8_t *key, size_t key_len,
                      const uint8_t *src, size_t src_len,
                      uint8_t *dst, size_t dst_max, size_t *out_len,
                      xrdc_status *st)
{
    if (key_len == 0 || src_len == 0 || dst_max < src_len) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "sss bf32: bad lengths");
        return -1;
    }
    if (xrootd_sss_bf_crypt(1, key, key_len, src, src_len,
                            dst, dst_max, out_len) != 0) {
        xrdc_status_set(st, XRDC_EPROTO, 0,
                        "sss bf32: Blowfish encrypt failed (legacy provider?)");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* hex helpers                                                         */
/* ------------------------------------------------------------------ */

/* Decode a hex key string into out (bounded by XRDC_SSS_KEY_MAX); nibbles via the
 * shared xrootd_hex_from_char (case-insensitive, -1 on a non-hex digit). */
static int
decode_hex(const char *hex, uint8_t *out, size_t *out_len)
{
    size_t n = strlen(hex), i;

    if (n == 0 || (n & 1) || n / 2 > XRDC_SSS_KEY_MAX) {
        return -1;
    }
    for (i = 0; i < n; i += 2) {
        int hi = xrootd_hex_from_char((unsigned char) hex[i]);
        int lo = xrootd_hex_from_char((unsigned char) hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i / 2] = (uint8_t) ((hi << 4) | lo);
    }
    *out_len = n / 2;
    return 0;
}

/* ------------------------------------------------------------------ */
/* keytab I/O                                                          */
/* ------------------------------------------------------------------ */

void
xrdc_sss_keytab_default(char *out, size_t outsz)
{
    const char *env = getenv("XrdSecSSSKT");
    const char *home;

    if (env == NULL || env[0] == '\0') {
        env = getenv("XrdSecsssKT");
    }
    if (env != NULL && env[0] != '\0') {
        snprintf(out, outsz, "%s", env);
        return;
    }
    home = getenv("HOME");
    if (home == NULL || home[0] == '\0') {
        struct passwd *pw = getpwuid(geteuid());
        home = (pw != NULL) ? pw->pw_dir : "/tmp";
    }
    snprintf(out, outsz, "%s/.xrd/sss.keytab", home);
}

/* Parse one keytab line (mutated by strtok_r). Returns 1 if a key was filled,
 * 0 for blank/comment/expired, -1 on a malformed required field. */
static int
parse_line(char *line, xrdc_sss_key *k)
{
    char *field, *save;

    field = strtok_r(line, " \t\r\n", &save);
    if (field == NULL || field[0] == '#') {
        return 0;
    }
    if (strcmp(field, "0") != 0 && strcmp(field, "1") != 0) {
        return -1;
    }

    memset(k, 0, sizeof(*k));
    k->id = -1;
    snprintf(k->user, sizeof(k->user), "%s", "nobody");
    snprintf(k->group, sizeof(k->group), "%s", "nogroup");
    snprintf(k->name, sizeof(k->name), "%s", "nowhere");

    while ((field = strtok_r(NULL, " \t\r\n", &save)) != NULL) {
        const char *v;
        if (field[0] == '#') {
            break;
        }
        if (field[1] != ':') {
            continue;
        }
        v = field + 2;
        switch (field[0]) {
        case 'u': snprintf(k->user, sizeof(k->user), "%s", v); break;
        case 'g': snprintf(k->group, sizeof(k->group), "%s", v); break;
        case 'n': snprintf(k->name, sizeof(k->name), "%s", v); break;
        case 'N': k->id = strtoll(v, NULL, 10); break;
        case 'e': k->exp = (int64_t) strtoll(v, NULL, 10); break;
        case 'k':
            if (decode_hex(v, k->key, &k->key_len) != 0) {
                return -1;
            }
            break;
        default: break;
        }
    }
    if (k->id < 0 || k->key_len == 0) {
        return -1;
    }
    if (k->exp != 0 && k->exp <= (int64_t) time(NULL)) {
        return 0;   /* expired: skip */
    }
    return 1;
}

int
xrdc_sss_keytab_read(const char *path, xrdc_sss_key *keys, int max, int *n,
                     xrdc_status *st)
{
    struct stat sb;
    int         fd;
    FILE       *fp;
    char        line[1024];
    int         count = 0, lineno = 0;

    *n = 0;
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        xrdc_status_set(st, XRDC_EAUTH, errno, "open keytab %s: %s",
                        path, strerror(errno));
        return -1;
    }
    if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode)) {
        close(fd);
        xrdc_status_set(st, XRDC_EAUTH, 0, "keytab %s is not a regular file", path);
        return -1;
    }
    if (sb.st_mode & (S_IRWXG | S_IRWXO)) {
        close(fd);
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        "keytab %s must be mode 0600 (group/other bits set)", path);
        return -1;
    }
    fp = fdopen(fd, "r");
    if (fp == NULL) {
        close(fd);
        xrdc_status_set(st, XRDC_EAUTH, errno, "fdopen keytab: %s", strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL && count < max) {
        int rc;
        lineno++;
        rc = parse_line(line, &keys[count]);
        if (rc < 0) {
            fclose(fp);
            xrdc_status_set(st, XRDC_EAUTH, 0,
                            "keytab %s: malformed key on line %d", path, lineno);
            return -1;
        }
        if (rc == 1) {
            count++;
        }
    }
    fclose(fp);
    *n = count;
    return 0;
}

int
xrdc_sss_keytab_write(const char *path, const xrdc_sss_key *keys, int n,
                      xrdc_status *st)
{
    int  fd, i;
    FILE *fp;
    char hex[XRDC_SSS_KEY_MAX * 2 + 1];

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        xrdc_status_set(st, XRDC_EAUTH, errno, "create keytab %s: %s",
                        path, strerror(errno));
        return -1;
    }
    /* Enforce 0600 even if the file pre-existed with looser bits. */
    if (fchmod(fd, 0600) != 0) {
        close(fd);
        xrdc_status_set(st, XRDC_EAUTH, errno, "chmod keytab: %s", strerror(errno));
        return -1;
    }
    fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        xrdc_status_set(st, XRDC_EAUTH, errno, "fdopen keytab: %s", strerror(errno));
        return -1;
    }
    for (i = 0; i < n; i++) {
        xrootd_hex_encode(keys[i].key, keys[i].key_len, hex);
        fprintf(fp, "0 u:%s g:%s N:%lld k:%s n:%s",
                keys[i].user, keys[i].group, (long long) keys[i].id, hex,
                keys[i].name);
        if (keys[i].exp != 0) {
            fprintf(fp, " e:%lld", (long long) keys[i].exp);
        }
        fputc('\n', fp);
    }
    if (fclose(fp) != 0) {
        xrdc_status_set(st, XRDC_EAUTH, errno, "write keytab: %s", strerror(errno));
        return -1;
    }
    return 0;
}
