/*
 * sss_keytab.c — SSS keytab text I/O + the credential crypto kernels.
 *
 * See sss_keytab.h for the contract. The CRC32 and Blowfish-CFB64 routines route
 * through the shared libxrdproto kernels (crc32_ieee / sss_bf), and the keytab
 * line grammar + permission check come from the shared src/auth/sss/sss_keytab_kernel.c
 * — one source of truth with the server's parser (no clean-room duplicate to drift).
 */
#include "sss_keytab.h"
#include "core/compat/crc32_ieee.h"   /* shared CRC-32/IEEE (libxrdproto) */
#include "core/compat/sss_bf.h"       /* shared Blowfish-CFB64 (libxrdproto) */
#include "core/compat/hex.h"          /* shared hex encode/from_char (libxrdproto) */
#include "auth/sss/sss_keytab_kernel.h" /* shared keytab line grammar + mode check */
#include "core/config/envalias.h"     /* alias resolver (WS-1) */

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

/* crypto kernels                                                      */

/* Forwards to the shared CRC-32/IEEE kernel (libxrdproto) so client-mint and
 * server-verify of the SSS blob use one source of truth. */
uint32_t
brix_sss_crc32(const uint8_t *p, size_t len)
{
    return brix_crc32_ieee(p, len);
}

/* Forwards to the shared Blowfish-CFB64 kernel (libxrdproto), which owns the
 * OpenSSL-3 legacy-provider load — one source of truth with the server's SSS path. */
int
brix_sss_bf32_encrypt(const uint8_t *key, size_t key_len,
                      const uint8_t *src, size_t src_len,
                      uint8_t *dst, size_t dst_max, size_t *out_len,
                      brix_status *st)
{
    if (key_len == 0 || src_len == 0 || dst_max < src_len) {
        brix_status_set(st, XRDC_EUSAGE, 0, "sss bf32: bad lengths");
        return -1;
    }
    if (brix_sss_bf_crypt(1, key, key_len, src, src_len,
                            dst, dst_max, out_len) != 0) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "sss bf32: Blowfish encrypt failed (legacy provider?)");
        return -1;
    }
    return 0;
}

/* keytab I/O                                                          */

void
brix_sss_keytab_default(char *out, size_t outsz)
{
    /*
     * WHAT: resolve the SSS keytab path from the canonical alias chain.
     * WHY:  XrdSecSSSKT vs XrdSecsssKT differ only by case; the resolver
     *       emits a TTY note if both are set with different values (WS-1).
     * HOW:  brix_env_resolve walks the chain in precedence order; legacy
     *       names remain accepted forever (C2 compat).
     */
    static const char *const keytab_chain[] = {
        "XRDC_SSS_KEYTAB", "XrdSecSSSKT", "XrdSecsssKT", NULL
    };
    const char *env  = brix_env_resolve(keytab_chain, NULL);
    const char *home;

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

/* The neutral kernel entry must hold any field this struct can — else the copy
 * below could truncate a valid key/name (a drift in either would be a real bug). */
_Static_assert(sizeof(((brix_sss_key *) 0)->key)   == SSS_K_KEY_MAX,
               "SSS key buffer size drift vs shared kernel");
_Static_assert(sizeof(((brix_sss_key *) 0)->user)  == SSS_K_USER_MAX,
               "SSS user buffer size drift vs shared kernel");
_Static_assert(sizeof(((brix_sss_key *) 0)->group) == SSS_K_GROUP_MAX,
               "SSS group buffer size drift vs shared kernel");
_Static_assert(sizeof(((brix_sss_key *) 0)->name)  == SSS_K_NAME_MAX,
               "SSS name buffer size drift vs shared kernel");

/* Parse one keytab line (mutated by strtok_r) via the shared grammar kernel.
 * Returns 1 if a key was filled, 0 for blank/comment/expired, -1 on a malformed
 * required field. */
static int
parse_line(char *line, brix_sss_key *k)
{
    sss_keytab_entry_t entry;
    int                rc;

    rc = sss_keytab_parse_line(line, &entry, (int64_t) time(NULL));
    if (rc <= 0) {
        return rc;   /* 0 = skip, -1 = malformed */
    }

    memset(k, 0, sizeof(*k));
    k->id      = entry.id;
    k->exp     = entry.exp;
    k->key_len = entry.key_len;
    memcpy(k->key, entry.key, entry.key_len);
    snprintf(k->user,  sizeof(k->user),  "%s", entry.user);
    snprintf(k->group, sizeof(k->group), "%s", entry.group);
    snprintf(k->name,  sizeof(k->name),  "%s", entry.name);
    return 1;
}

int
brix_sss_keytab_read(const char *path, brix_sss_key *keys, int max, int *n,
                     brix_status *st)
{
    struct stat sb;
    int         fd;
    FILE       *fp;
    char        line[1024];
    int         count = 0, lineno = 0;

    *n = 0;
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        brix_status_set(st, XRDC_EAUTH, errno, "open keytab %s: %s",
                        path, strerror(errno));
        return -1;
    }
    if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode)) {
        close(fd);
        brix_status_set(st, XRDC_EAUTH, 0, "keytab %s is not a regular file", path);
        return -1;
    }
    if (sss_keytab_mode_ok(path, sb.st_mode, 0) != 0) {
        close(fd);
        brix_status_set(st, XRDC_EAUTH, 0,
                        "keytab %s must be mode 0600 (group/other bits set)", path);
        return -1;
    }
    fp = fdopen(fd, "r");
    if (fp == NULL) {
        close(fd);
        brix_status_set(st, XRDC_EAUTH, errno, "fdopen keytab: %s", strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL && count < max) {
        int rc;
        lineno++;
        rc = parse_line(line, &keys[count]);
        if (rc < 0) {
            fclose(fp);
            brix_status_set(st, XRDC_EAUTH, 0,
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
brix_sss_keytab_write(const char *path, const brix_sss_key *keys, int n,
                      brix_status *st)
{
    int  fd, i;
    FILE *fp;
    char hex[XRDC_SSS_KEY_MAX * 2 + 1];

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        brix_status_set(st, XRDC_EAUTH, errno, "create keytab %s: %s",
                        path, strerror(errno));
        return -1;
    }
    /* Enforce 0600 even if the file pre-existed with looser bits. */
    if (fchmod(fd, 0600) != 0) {
        close(fd);
        brix_status_set(st, XRDC_EAUTH, errno, "chmod keytab: %s", strerror(errno));
        return -1;
    }
    fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        brix_status_set(st, XRDC_EAUTH, errno, "fdopen keytab: %s", strerror(errno));
        return -1;
    }
    for (i = 0; i < n; i++) {
        brix_hex_encode(keys[i].key, keys[i].key_len, hex);
        fprintf(fp, "0 u:%s g:%s N:%lld k:%s n:%s",
                keys[i].user, keys[i].group, (long long) keys[i].id, hex,
                keys[i].name);
        if (keys[i].exp != 0) {
            fprintf(fp, " e:%lld", (long long) keys[i].exp);
        }
        fputc('\n', fp);
    }
    if (fclose(fp) != 0) {
        brix_status_set(st, XRDC_EAUTH, errno, "write keytab: %s", strerror(errno));
        return -1;
    }
    return 0;
}
