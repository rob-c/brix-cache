/*
 * sec_sss.c — SSS (Simple Shared Secret) auth module.
 *
 * WHAT: Build the kXR_auth payload for the "sss" protocol: a self-contained
 *       credential the server decrypts with the shared key from its keytab.
 * WHY:  SSS lets trusted hosts authenticate with a pre-shared symmetric key (no
 *       PKI, no token issuer) — common for intra-site XRootD/CMS traffic.
 * HOW:  Discover the keytab ($XrdSecSSSKT / $XrdSecsssKT / ~/.xrd/sss.keytab),
 *       pick the first live key, and assemble exactly what the server's encoder
 *       produces (src/sss/auth_proxy_credential.c): a 16-byte outer header
 *       ("sss\0" ver spare kn enc key-id-BE) followed by BF32( 40-byte data
 *       header [32 random + gen_time-BE + USEDATA] + NAME TLV + IEEE-CRC32 ). A
 *       single round (the USEDATA form needs no challenge).
 *
 * wire: XProtocol.hh kXR_auth credtype "sss"; blob per src/sss/sss_internal.h.
 */
#include "sec.h"
#include "../sss_keytab.h"

#include <arpa/inet.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/rand.h>

/* Local login name for the NAME TLV (servers with an anyuser key accept any). */
static const char *
local_user(void)
{
    struct passwd *pw = getpwuid(geteuid());
    if (pw != NULL && pw->pw_name != NULL && pw->pw_name[0] != '\0') {
        return pw->pw_name;
    }
    return "xrd";
}

static int
sss_load_first_key(xrdc_sss_key *out, xrdc_status *st)
{
    char         path[XRDC_PATH_MAX];
    xrdc_sss_key keys[XRDC_SSS_KEYS_MAX];
    int          n = 0;

    xrdc_sss_keytab_default(path, sizeof(path));
    if (xrdc_sss_keytab_read(path, keys, XRDC_SSS_KEYS_MAX, &n, st) != 0) {
        return -1;
    }
    if (n == 0) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "keytab %s has no usable keys", path);
        return -1;
    }
    *out = keys[0];
    return 0;
}

static int
sss_have(void)
{
    xrdc_sss_key key;
    xrdc_status  st;
    xrdc_status_clear(&st);
    return sss_load_first_key(&key, &st) == 0;
}

static int
sss_first(xrdc_conn *c, const char *parms, uint8_t **payload, uint32_t *plen,
          xrdc_status *st)
{
    xrdc_sss_key key;
    uint8_t      clear[XRDC_SSS_DATA_HDR_LEN + 3 + 64 + 1];
    uint8_t      plain[sizeof(clear) + 4];
    uint8_t     *blob, *cursor;
    const char  *user;
    size_t       ulen, clear_len, cipher_len, blob_len, crypt_out;
    uint32_t     gen_time, crc;
    uint64_t     id_be;

    (void) c;
    (void) parms;

    if (sss_load_first_key(&key, st) != 0) {
        return -1;
    }

    /* 40-byte data header: 32 random + gen_time(BE) + USEDATA opt byte. */
    memset(clear, 0, sizeof(clear));
    if (RAND_bytes(clear, 32) != 1) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "sss: RAND_bytes failed");
        return -1;
    }
    gen_time = (uint32_t) (time(NULL) - XRDC_SSS_BASE_TIME);
    clear[32] = (uint8_t) (gen_time >> 24);
    clear[33] = (uint8_t) (gen_time >> 16);
    clear[34] = (uint8_t) (gen_time >> 8);
    clear[35] = (uint8_t) gen_time;
    clear[39] = XRDC_SSS_OPT_USEDATA;

    /* NAME TLV: [type][0][len][username NUL-terminated]; len includes the NUL.
     * The login name identifies us; an anyuser/anybody server key accepts it. */
    user = local_user();
    ulen = strlen(user) + 1;
    if (ulen > 64) {
        ulen = 64;
    }
    cursor = clear + XRDC_SSS_DATA_HDR_LEN;
    *cursor++ = XRDC_SSS_TYPE_NAME;
    *cursor++ = 0;
    *cursor++ = (uint8_t) ulen;
    memcpy(cursor, user, ulen - 1);
    cursor[ulen - 1] = '\0';
    cursor += ulen;
    clear_len = (size_t) (cursor - clear);

    /* plain = cleartext + IEEE-CRC32 (big-endian). */
    memcpy(plain, clear, clear_len);
    crc = htonl(xrdc_sss_crc32(plain, clear_len));
    memcpy(plain + clear_len, &crc, sizeof(crc));

    /* blob = 16-byte header + BF32(plain). */
    blob = (uint8_t *) malloc(XRDC_SSS_HDR_LEN + clear_len + 4);
    if (blob == NULL) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "sss: out of memory");
        return -1;
    }
    if (xrdc_sss_bf32_encrypt(key.key, key.key_len, plain, clear_len + 4,
                              blob + XRDC_SSS_HDR_LEN, clear_len + 4,
                              &crypt_out, st) != 0) {
        free(blob);
        return -1;
    }
    cipher_len = crypt_out;

    blob[0] = 's'; blob[1] = 's'; blob[2] = 's'; blob[3] = '\0';
    blob[4] = 1;                    /* version */
    blob[5] = 0;                    /* spare */
    blob[6] = 0;                    /* kn_size: no named key */
    blob[7] = XRDC_SSS_ENC_BF32;
    id_be = (uint64_t) key.id;
    blob[ 8] = (uint8_t) (id_be >> 56);
    blob[ 9] = (uint8_t) (id_be >> 48);
    blob[10] = (uint8_t) (id_be >> 40);
    blob[11] = (uint8_t) (id_be >> 32);
    blob[12] = (uint8_t) (id_be >> 24);
    blob[13] = (uint8_t) (id_be >> 16);
    blob[14] = (uint8_t) (id_be >>  8);
    blob[15] = (uint8_t)  id_be;

    blob_len = XRDC_SSS_HDR_LEN + cipher_len;
    *payload = blob;
    *plen = (uint32_t) blob_len;
    return 0;
}

const xrdc_sec_module *
xrdc_sec_sss(void)
{
    static const xrdc_sec_module m = {
        "sss",
        { 's', 's', 's', 0 },
        sss_have,
        sss_first,
        NULL,   /* single round (USEDATA self-contained credential) */
        NULL,
    };
    return &m;
}
