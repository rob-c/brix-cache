/*
 * brix site checksum plugin: FNV-1a 64-bit.
 *
 * Build (no server tree needed beyond the ABI header):
 *     cc -shared -fPIC -O2 -I<dir with checksum_plugin_abi.h> \
 *        -o brix_cks_fnv1a64.so brix_cks_fnv1a64.c
 * Register:
 *     brix_checksum_plugin fnv1a64 /usr/lib64/brix/brix_cks_fnv1a64.so;
 * Optional parms: "basis=<16 hex digits>" replaces the standard offset basis
 * (any other parms string is refused at config time).
 *
 * Reference: Fowler/Noll/Vo, FNV-1a, 64-bit: basis 0xcbf29ce484222325,
 * prime 0x100000001b3. The digest is the 8-byte big-endian hash, so the wire
 * form (host hex-encoded) reads as the usual 16-hex-digit FNV value.
 */

#include <stdint.h>
#include <string.h>

#include "checksum_plugin_abi.h"

#define FNV1A64_BASIS   0xcbf29ce484222325ULL
#define FNV1A64_PRIME   0x100000001b3ULL

typedef struct {
    uint64_t  basis;
    uint64_t  h;
} fnv1a64_state_t;


static int
parse_hex64(const char *s, uint64_t *out)
{
    uint64_t  v = 0;
    int       i;

    for (i = 0; i < 16; i++) {
        char  c = s[i];
        int   d;

        if (c >= '0' && c <= '9') {
            d = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            d = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            d = c - 'A' + 10;
        } else {
            return -1;
        }
        v = (v << 4) | (uint64_t) d;
    }

    if (s[16] != '\0') {
        return -1;
    }

    *out = v;
    return 0;
}


static int
fnv1a64_init(void *state, const char *parms)
{
    fnv1a64_state_t  *st = state;

    st->basis = FNV1A64_BASIS;

    if (parms != NULL && parms[0] != '\0') {
        if (strncmp(parms, "basis=", 6) != 0
            || parse_hex64(parms + 6, &st->basis) != 0)
        {
            return -1;
        }
    }

    st->h = st->basis;
    return 0;
}


static int
fnv1a64_update(void *state, const unsigned char *buf, size_t n)
{
    fnv1a64_state_t  *st = state;
    uint64_t          h = st->h;
    size_t            i;

    for (i = 0; i < n; i++) {
        h ^= (uint64_t) buf[i];
        h *= FNV1A64_PRIME;
    }

    st->h = h;
    return 0;
}


static int
fnv1a64_final(void *state, unsigned char *digest)
{
    fnv1a64_state_t  *st = state;
    int               i;

    for (i = 0; i < 8; i++) {
        digest[i] = (unsigned char) (st->h >> (8 * (7 - i)));
    }

    return 0;
}


const brix_cks_plugin_t  brix_cks_plugin = {
    BRIX_CKS_PLUGIN_ABI,
    "fnv1a64",
    8,
    sizeof(fnv1a64_state_t),
    fnv1a64_init,
    fnv1a64_update,
    fnv1a64_final,
};
