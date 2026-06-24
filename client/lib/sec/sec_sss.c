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
#include "compat/sss_bf.h"   /* xrootd_sss_build_credential — shared with the server */

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
    uint8_t      nonce[32];
    uint8_t     *blob;
    const char  *user;
    uint32_t     gen_time;
    size_t       blob_len;

    (void) c;
    (void) parms;

    if (sss_load_first_key(&key, st) != 0) {
        return -1;
    }

    /* RNG + clock at the edge; the credential byte assembly lives in the shared
     * kernel (xrootd_sss_build_credential, libxrdproto) so the client and the
     * server mint the identical SSS wire format from one audited implementation. */
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "sss: RAND_bytes failed");
        return -1;
    }
    gen_time = (uint32_t) (time(NULL) - XRDC_SSS_BASE_TIME);
    user = local_user();

    /* 256 bytes always covers HDR + 40-byte data hdr + TLV(<=67) + CRC. */
    blob = (uint8_t *) malloc(256);
    if (blob == NULL) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "sss: out of memory");
        return -1;
    }
    if (xrootd_sss_build_credential(key.key, key.key_len, (uint64_t) key.id,
                                    user, nonce, gen_time, blob, 256,
                                    &blob_len) != 0) {
        free(blob);
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        "sss: credential build failed (legacy provider?)");
        return -1;
    }

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
