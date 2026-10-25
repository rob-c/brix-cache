/*
 * Pure physical-key selection for portable logical xattrs.
 * Owns bounded name hashing and chunk geometry; VFS operations and mutation
 * policy remain in storage.c and the existing VFS entry points.
 */
#include "storage_keys.h"
#include "core/compat/crypto.h"
#include "core/compat/hex.h"
#include "platform/platform_api.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* ---- Choose a physical fattr key ----
 * WHAT: Return zero with a direct or wrapped key, otherwise -1 with errno.
 * WHY: Long or reserved logical names need collision-checked portable storage.
 * HOW: 1. Validate length. 2. Choose direct or digest form. 3. Bound the output.
 */
int
fattr_storage_key(const char *name, size_t nlen, char *key, size_t keycap,
    int *wrapped)
{
    uint8_t digest[32];
    size_t  direct_len;

    if (name == NULL || nlen == 0 || nlen > kXR_faMaxNlen) {
        errno = EINVAL;
        return -1;
    }
    direct_len = BRIX_FATTR_XKEY_PFX_LEN + nlen;
    *wrapped = direct_len > BRIX_XATTR_NAME_MAX
        || (nlen >= sizeof("$brix$") - 1U
            && memcmp(name, "$brix$", sizeof("$brix$") - 1U) == 0);
    if (!*wrapped) {
        if (direct_len + 1U > keycap) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(key, BRIX_FATTR_XKEY_PFX, BRIX_FATTR_XKEY_PFX_LEN);
        memcpy(key + BRIX_FATTR_XKEY_PFX_LEN, name, nlen);
        key[direct_len] = '\0';
        return 0;
    }
    if (FATTR_STORED_KEY_LEN + 1U > keycap
        || !brix_sha256((const uint8_t *) name, nlen, digest))
    {
        errno = EIO;
        return -1;
    }
    memcpy(key, FATTR_STORED_PREFIX, FATTR_STORED_PREFIX_LEN);
    brix_hex_encode(digest, sizeof(digest), key + FATTR_STORED_PREFIX_LEN);
    return 0;
}


/* ---- Derive a wrapped fattr key ----
 * WHAT: Return zero with the SHA-256-derived key, otherwise -1 with errno.
 * WHY: Fallback reads must use exactly the same reserved key namespace as writes.
 * HOW: 1. Validate input and capacity. 2. Hash. 3. Encode under the reserved prefix.
 */
int
fattr_storage_hashed_key(const char *name, size_t nlen, char *key,
    size_t keycap)
{
    uint8_t digest[32];

    if (name == NULL || nlen == 0 || nlen > kXR_faMaxNlen
        || keycap <= FATTR_STORED_KEY_LEN
        || !brix_sha256((const uint8_t *) name, nlen, digest))
    {
        errno = EINVAL;
        return -1;
    }
    memcpy(key, FATTR_STORED_PREFIX, FATTR_STORED_PREFIX_LEN);
    brix_hex_encode(digest, sizeof(digest), key + FATTR_STORED_PREFIX_LEN);
    return 0;
}


/* ---- Derive a bounded chunk key ----
 * WHAT: Return zero with a chunk key, otherwise -1 with EINVAL.
 * WHY: Chunk values must remain tied to the logical name and value digest.
 * HOW: 1. Encode the value digest. 2. Format the key. 3. Reject overflow or bad index.
 */
int
fattr_storage_chunk_key(char *out, size_t cap, const char *base,
    const uint8_t value_digest[32], size_t index)
{
    char value_hex[33];
    int  n;

    brix_hex_encode(value_digest, 16, value_hex);
    value_hex[32] = '\0';
    n = snprintf(out, cap, "%s%s.%s.%02x", FATTR_CHUNK_PREFIX,
                 base + FATTR_STORED_PREFIX_LEN, value_hex,
                 (unsigned) index);
    if (n < 0 || (size_t) n >= cap || index >= FATTR_CHUNK_MAX) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}


/* ---- Count value chunks ----
 * WHAT: Return the ceiling of the value length divided by the chunk size.
 * WHY: Read, write and cleanup must agree on the physical value geometry.
 * HOW: 1. Round the length up using the fixed chunk size.
 */
size_t
fattr_storage_chunk_count(size_t value_len)
{
    return (value_len + FATTR_CHUNK_VALUE_SIZE - 1U)
           / FATTR_CHUNK_VALUE_SIZE;
}
