/*
 * Portable physical fattr key geometry shared by the storage adapter.
 * Requires no prior includes; VFS and wire types come from ngx_brix_fattr.h.
 */
#pragma once
#include "ngx_brix_fattr.h"

#define FATTR_STORED_PREFIX       "user.U.$brix$"
#define FATTR_STORED_PREFIX_LEN   (sizeof(FATTR_STORED_PREFIX) - 1U)
#define FATTR_STORED_MAGIC        "BXFA\001\000\000\000"
#define FATTR_STORED_MAGIC_LEN    8U
#define FATTR_STORED_HEADER_LEN   (FATTR_STORED_MAGIC_LEN + 2U)
#define FATTR_STORED_KEY_LEN      (FATTR_STORED_PREFIX_LEN + 64U)
#define FATTR_CHUNK_MAGIC         "BXFC\001\000\000\000"
#define FATTR_CHUNK_HEADER_LEN    (8U + 2U + 4U + 32U)
#define FATTR_CHUNK_VALUE_SIZE    2048U
#define FATTR_CHUNK_PREFIX        "user.$brix.fattr."
#define FATTR_CHUNK_MAX           ((kXR_faMaxVlen + FATTR_CHUNK_VALUE_SIZE - 1U) \
                                   / FATTR_CHUNK_VALUE_SIZE)

int fattr_storage_key(const char *name, size_t nlen, char *key, size_t keycap,
    int *wrapped);
int fattr_storage_hashed_key(const char *name, size_t nlen, char *key,
    size_t keycap);
int fattr_storage_chunk_key(char *out, size_t cap, const char *base,
    const uint8_t value_digest[32], size_t index);
size_t fattr_storage_chunk_count(size_t value_len);
