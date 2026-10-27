/*
 * Portable backing representation for kXR_fattr names.
 *
 * Darwin caps native xattr names at 127 bytes, while the wire contract permits
 * a 248-byte client name (255 bytes after the private "user.U." prefix). Names
 * that fit remain ordinary xattrs. A name that does not fit is represented by
 * a short SHA-256 key and a versioned value envelope carrying the exact logical
 * name. Reads validate the embedded name before exposing the value, making a
 * digest collision or a forged reserved xattr fail closed.
 */
#include "storage_keys.h"

#include "core/compat/crypto.h"
#include "platform/platform_api.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>



static ssize_t
fattr_storage_read_raw(brix_vfs_ctx_t *vctx, const char *path, int fd,
    const char *key, void *buf, size_t cap)
{
    return path != NULL ? brix_vfs_getxattr(vctx, key, buf, cap)
                        : brix_vfs_fgetxattr(vctx, fd, key, buf, cap);
}

static ngx_int_t
fattr_storage_write_raw(brix_vfs_ctx_t *vctx, const char *path, int fd,
    const char *key, const void *value, size_t vlen, int flags)
{
    return path != NULL ? brix_vfs_setxattr(vctx, key, value, vlen, flags)
                        : brix_vfs_fsetxattr(vctx, fd, key, value, vlen,
                                              flags);
}

static ngx_int_t
fattr_storage_remove_raw(brix_vfs_ctx_t *vctx, const char *path, int fd,
    const char *key)
{
    return path != NULL ? brix_vfs_removexattr(vctx, key)
                        : brix_vfs_fremovexattr(vctx, fd, key);
}




static uint32_t
fattr_storage_u32(const u_char *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

static void
fattr_storage_put_u32(u_char *p, size_t value)
{
    p[0] = (u_char) (value >> 24);
    p[1] = (u_char) (value >> 16);
    p[2] = (u_char) (value >> 8);
    p[3] = (u_char) value;
}

static int
fattr_storage_unpack(u_char *raw, size_t raw_len, const char *expected,
    size_t expected_len, brix_fattr_stored_t *stored)
{
    size_t name_len;

    if (raw_len < FATTR_STORED_HEADER_LEN
        || memcmp(raw, FATTR_STORED_MAGIC, FATTR_STORED_MAGIC_LEN) != 0)
    {
        errno = EIO;
        return -1;
    }
    name_len = ((size_t) raw[FATTR_STORED_MAGIC_LEN] << 8)
             | raw[FATTR_STORED_MAGIC_LEN + 1U];
    if (name_len == 0 || name_len > kXR_faMaxNlen
        || name_len > raw_len - FATTR_STORED_HEADER_LEN
        || memchr(raw + FATTR_STORED_HEADER_LEN, '\0', name_len) != NULL
        || (expected != NULL
            && (name_len != expected_len
                || memcmp(raw + FATTR_STORED_HEADER_LEN, expected,
                          name_len) != 0)))
    {
        errno = EIO;
        return -1;
    }
    stored->name = (const char *) raw + FATTR_STORED_HEADER_LEN;
    stored->nlen = name_len;
    stored->value = raw + FATTR_STORED_HEADER_LEN + name_len;
    stored->vlen = raw_len - FATTR_STORED_HEADER_LEN - name_len;
    return 0;
}

static int
fattr_storage_chunk_manifest(u_char *raw, size_t raw_len,
    const char *expected, size_t expected_len, size_t *name_len,
    size_t *value_len)
{
    if (raw_len < FATTR_CHUNK_HEADER_LEN
        || memcmp(raw, FATTR_CHUNK_MAGIC, 8) != 0)
    {
        return 0;
    }
    *name_len = ((size_t) raw[8] << 8) | raw[9];
    *value_len = fattr_storage_u32(raw + 10);
    if (*name_len == 0 || *name_len > kXR_faMaxNlen
        || *value_len > kXR_faMaxVlen
        || raw_len != FATTR_CHUNK_HEADER_LEN + *name_len
        || memchr(raw + FATTR_CHUNK_HEADER_LEN, '\0', *name_len) != NULL
        || (expected != NULL
            && (*name_len != expected_len
                || memcmp(raw + FATTR_CHUNK_HEADER_LEN, expected,
                          *name_len) != 0)))
    {
        errno = EIO;
        return -1;
    }
    return 1;
}

static int
fattr_storage_read_chunks(ngx_pool_t *pool, brix_vfs_ctx_t *vctx,
    const char *path, int fd, const char *base, u_char *manifest,
    size_t name_len, size_t value_len, brix_fattr_stored_t *stored)
{
    uint8_t digest[32];
    u_char *value;
    size_t  index, count, offset = 0;

    value = ngx_palloc(pool, value_len ? value_len : 1U);
    if (value == NULL) {
        errno = ENOMEM;
        return -1;
    }
    count = fattr_storage_chunk_count(value_len);
    for (index = 0; index < count; index++) {
        char    chunk_key[192];
        size_t  want = value_len - offset;
        ssize_t actual;

        if (want > FATTR_CHUNK_VALUE_SIZE) want = FATTR_CHUNK_VALUE_SIZE;
        if (fattr_storage_chunk_key(chunk_key, sizeof(chunk_key), base,
                manifest + 14, index) != 0)
            return -1;
        actual = fattr_storage_read_raw(vctx, path, fd, chunk_key,
                                        value + offset, want);
        if (actual < 0 || (size_t) actual != want) {
            errno = EIO;
            return -1;
        }
        offset += want;
    }
    if (!brix_sha256(value, value_len, digest)
        || memcmp(digest, manifest + 14, sizeof(digest)) != 0)
    {
        errno = EIO;
        return -1;
    }
    stored->name = (const char *) manifest + FATTR_CHUNK_HEADER_LEN;
    stored->nlen = name_len;
    stored->value = value;
    stored->vlen = value_len;
    return 0;
}

static int
fattr_storage_read(ngx_pool_t *pool, brix_vfs_ctx_t *vctx, const char *path,
    int fd, const char *key, const char *expected, size_t expected_len,
    int wrapped, brix_fattr_stored_t *stored)
{
    ssize_t size;
    ssize_t actual;
    u_char *raw;

    size = fattr_storage_read_raw(vctx, path, fd, key, NULL, 0);
    if (size < 0) return -1;
    if ((size_t) size > kXR_faMaxVlen + kXR_faMaxNlen
                          + FATTR_STORED_HEADER_LEN)
    {
        errno = E2BIG;
        return -1;
    }
    raw = ngx_palloc(pool, (size_t) size + 1U);
    if (raw == NULL) {
        errno = ENOMEM;
        return -1;
    }
    actual = fattr_storage_read_raw(vctx, path, fd, key, raw, (size_t) size);
    if (actual < 0) return -1;
    if (!wrapped) {
        stored->name = expected;
        stored->nlen = expected_len;
        stored->value = raw;
        stored->vlen = (size_t) actual;
        return 0;
    }
    {
        size_t name_len, value_len;
        int chunked = fattr_storage_chunk_manifest(raw, (size_t) actual,
            expected, expected_len, &name_len, &value_len);

        if (chunked < 0) return -1;
        if (chunked > 0)
            return fattr_storage_read_chunks(pool, vctx, path, fd, key, raw,
                                              name_len, value_len, stored);
    }
    return fattr_storage_unpack(raw, (size_t) actual, expected, expected_len,
                                stored);
}

static void
fattr_storage_remove_chunks(brix_vfs_ctx_t *vctx, const char *path, int fd,
    const char *base, const uint8_t digest[32], size_t value_len)
{
    size_t index, count = fattr_storage_chunk_count(value_len);

    for (index = 0; index < count; index++) {
        char chunk_key[192];

        if (fattr_storage_chunk_key(chunk_key, sizeof(chunk_key), base,
                                    digest, index) == 0)
            (void) fattr_storage_remove_raw(vctx, path, fd, chunk_key);
    }
}

static ngx_int_t
fattr_storage_remove_hashed(brix_vfs_ctx_t *vctx, const char *path, int fd,
    const char *base)
{
    u_char manifest[FATTR_CHUNK_HEADER_LEN + kXR_faMaxNlen];
    ssize_t actual, size;
    size_t  name_len, value_len;
    int     chunked;

    size = fattr_storage_read_raw(vctx, path, fd, base, NULL, 0);
    if (size < 0) return NGX_ERROR;
    if ((size_t) size > sizeof(manifest))
        return fattr_storage_remove_raw(vctx, path, fd, base);
    actual = fattr_storage_read_raw(vctx, path, fd, base, manifest,
                                    (size_t) size);
    if (actual < 0) return NGX_ERROR;
    chunked = fattr_storage_chunk_manifest(manifest, (size_t) actual, NULL, 0,
                                            &name_len, &value_len);
    if (chunked < 0) return NGX_ERROR;
    if (chunked > 0)
        fattr_storage_remove_chunks(vctx, path, fd, base, manifest + 14,
                                    value_len);
    return fattr_storage_remove_raw(vctx, path, fd, base);
}

static ngx_int_t
fattr_storage_write_chunks(ngx_pool_t *pool, brix_vfs_ctx_t *vctx,
    const char *path, int fd, const char *base, const char *name, size_t nlen,
    const void *value, size_t vlen, int flags)
{
    uint8_t digest[32], old_digest[32];
    u_char *manifest;
    u_char  old_manifest[FATTR_CHUNK_HEADER_LEN + kXR_faMaxNlen];
    size_t  index, count, offset = 0, old_name_len = 0, old_value_len = 0;
    ssize_t old_actual;
    int     old_chunked = 0;

    if (!brix_sha256(value, vlen, digest)) {
        errno = EIO;
        return NGX_ERROR;
    }
    old_actual = fattr_storage_read_raw(vctx, path, fd, base, old_manifest,
                                        sizeof(old_manifest));
    if (old_actual >= 0) {
        old_chunked = fattr_storage_chunk_manifest(old_manifest,
            (size_t) old_actual, NULL, 0, &old_name_len, &old_value_len);
        if (old_chunked > 0)
            memcpy(old_digest, old_manifest + 14, sizeof(old_digest));
    }
    count = fattr_storage_chunk_count(vlen);
    for (index = 0; index < count; index++) {
        char   chunk_key[192];
        size_t put = vlen - offset;

        if (put > FATTR_CHUNK_VALUE_SIZE) put = FATTR_CHUNK_VALUE_SIZE;
        if (fattr_storage_chunk_key(chunk_key, sizeof(chunk_key), base,
                                    digest, index) != 0
            || fattr_storage_write_raw(vctx, path, fd, chunk_key,
                 (const u_char *) value + offset, put, 0) != NGX_OK)
        {
            int saved_errno = errno;

            fattr_storage_remove_chunks(vctx, path, fd, base, digest, vlen);
            errno = saved_errno;
            return NGX_ERROR;
        }
        offset += put;
    }
    manifest = ngx_palloc(pool, FATTR_CHUNK_HEADER_LEN + nlen);
    if (manifest == NULL) {
        fattr_storage_remove_chunks(vctx, path, fd, base, digest, vlen);
        errno = ENOMEM;
        return NGX_ERROR;
    }
    memcpy(manifest, FATTR_CHUNK_MAGIC, 8);
    manifest[8] = (u_char) (nlen >> 8);
    manifest[9] = (u_char) nlen;
    fattr_storage_put_u32(manifest + 10, vlen);
    memcpy(manifest + 14, digest, sizeof(digest));
    memcpy(manifest + FATTR_CHUNK_HEADER_LEN, name, nlen);
    if (fattr_storage_write_raw(vctx, path, fd, base, manifest,
            FATTR_CHUNK_HEADER_LEN + nlen, flags) != NGX_OK)
    {
        int saved_errno = errno;

        fattr_storage_remove_chunks(vctx, path, fd, base, digest, vlen);
        errno = saved_errno;
        return NGX_ERROR;
    }
    if (old_chunked > 0
        && memcmp(old_digest, digest, sizeof(old_digest)) != 0)
        fattr_storage_remove_chunks(vctx, path, fd, base, old_digest,
                                    old_value_len);
    return NGX_OK;
}

static ngx_int_t
fattr_storage_set_direct(brix_vfs_ctx_t *vctx, const char *path, int fd,
    const char *key, const char *name, size_t nlen, const void *value,
    size_t vlen, int flags)
{
    char      hashed[BRIX_FATTR_XKEY_PFX_LEN + kXR_faMaxNlen + 1U];
    ngx_int_t rc;

    rc = fattr_storage_write_raw(vctx, path, fd, key, value, vlen, flags);
    if (rc == NGX_OK
        && fattr_storage_hashed_key(name, nlen, hashed, sizeof(hashed)) == 0)
        (void) fattr_storage_remove_hashed(vctx, path, fd, hashed);
    return rc;
}

static ngx_int_t
fattr_storage_prepare_wrapped(ngx_pool_t *pool, brix_vfs_ctx_t *vctx,
    const char *path, int fd, const char *key, const char *name, size_t nlen,
    int flags)
{
    brix_fattr_stored_t existing;

    if ((flags & XATTR_CREATE)
        && fattr_storage_get(pool, vctx, path, fd, name, nlen,
                             &existing.value) >= 0)
    {
        errno = EEXIST;
        return NGX_ERROR;
    }
    if (fattr_storage_read(pool, vctx, path, fd, key, name, nlen, 1,
                           &existing) != 0
        && errno != ENODATA && errno != ENOENT)
        return NGX_ERROR;
    return NGX_OK;
}

static void
fattr_storage_drop_direct(brix_vfs_ctx_t *vctx, const char *path, int fd,
    const char *name, size_t nlen)
{
    char direct[BRIX_FATTR_XKEY_PFX_LEN + kXR_faMaxNlen + 1U];
    int  wrapped;

    if (fattr_storage_key(name, nlen, direct, sizeof(direct), &wrapped) == 0
        && !wrapped)
        (void) fattr_storage_remove_raw(vctx, path, fd, direct);
}

static ngx_int_t
fattr_storage_write_envelope(ngx_pool_t *pool, brix_vfs_ctx_t *vctx,
    const char *path, int fd, const char *key, const char *name, size_t nlen,
    const void *value, size_t vlen, int flags)
{
    size_t  raw_len = FATTR_STORED_HEADER_LEN + nlen + vlen;
    u_char *raw = ngx_palloc(pool, raw_len);
    size_t  i;

    if (raw == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    /* The magic is a binary envelope prefix, not a C string. Copy it bytewise
     * so no caller or analyzer can infer a nonexistent terminator contract. */
    for (i = 0; i < FATTR_STORED_MAGIC_LEN; i++) {
        raw[i] = (u_char) FATTR_STORED_MAGIC[i];
    }
    raw[FATTR_STORED_MAGIC_LEN] = (u_char) (nlen >> 8);
    raw[FATTR_STORED_MAGIC_LEN + 1U] = (u_char) nlen;
    memcpy(raw + FATTR_STORED_HEADER_LEN, name, nlen);
    if (vlen != 0)
        memcpy(raw + FATTR_STORED_HEADER_LEN + nlen, value, vlen);
    return fattr_storage_write_raw(vctx, path, fd, key, raw, raw_len, flags);
}

ngx_int_t
fattr_storage_set(ngx_pool_t *pool, brix_vfs_ctx_t *vctx, const char *path,
    int fd, const char *name, size_t nlen, const void *value, size_t vlen,
    int flags)
{
    char key[BRIX_FATTR_XKEY_PFX_LEN + kXR_faMaxNlen + 1U];
    char direct_key[BRIX_FATTR_XKEY_PFX_LEN + kXR_faMaxNlen + 1U];
    int  wrapped;

    if (fattr_storage_key(name, nlen, key, sizeof(key), &wrapped) != 0)
        return NGX_ERROR;
    if (!wrapped)
        memcpy(direct_key, key, strlen(key) + 1U);
    if (!wrapped && vlen <= FATTR_CHUNK_VALUE_SIZE)
        return fattr_storage_set_direct(vctx, path, fd, key, name, nlen,
                                         value, vlen, flags);
    if (!wrapped
        && fattr_storage_hashed_key(name, nlen, key, sizeof(key)) != 0)
        return NGX_ERROR;
    if (fattr_storage_prepare_wrapped(pool, vctx, path, fd, key, name, nlen,
                                      flags) != NGX_OK)
        return NGX_ERROR;
    if (vlen > FATTR_CHUNK_VALUE_SIZE) {
        ngx_int_t rc = fattr_storage_write_chunks(pool, vctx, path, fd, key,
                                                   name, nlen, value, vlen,
                                                   flags);

        if (rc == NGX_OK) {
            if (!wrapped)
                fattr_storage_drop_direct(vctx, path, fd, name, nlen);
            return NGX_OK;
        }
        /* Some filesystems accept one value of this size but cannot fit the
         * chunk keys plus their manifest in the inode's aggregate xattr
         * budget. A direct logical key is already a supported read format;
         * use it only when the name itself fits, retaining hashed chunks for
         * hosts whose single-value limit required the portable form. */
        if (!wrapped && (errno == E2BIG || errno == ENOSPC))
            return fattr_storage_set_direct(vctx, path, fd, direct_key, name,
                                             nlen, value, vlen, flags);
        return rc;
    }
    return fattr_storage_write_envelope(pool, vctx, path, fd, key, name,
                                         nlen, value, vlen, flags);
}

ssize_t
fattr_storage_get(ngx_pool_t *pool, brix_vfs_ctx_t *vctx, const char *path,
    int fd, const char *name, size_t nlen, u_char **value)
{
    char                  key[BRIX_FATTR_XKEY_PFX_LEN + kXR_faMaxNlen + 1U];
    brix_fattr_stored_t   stored;
    int                   wrapped;

    if (fattr_storage_key(name, nlen, key, sizeof(key), &wrapped) != 0)
        return -1;
    if (fattr_storage_read(pool, vctx, path, fd, key, name, nlen, wrapped,
                           &stored) != 0)
    {
        if (wrapped || (errno != ENODATA && errno != ENOENT)
            || fattr_storage_hashed_key(name, nlen, key, sizeof(key)) != 0
            || fattr_storage_read(pool, vctx, path, fd, key, name, nlen, 1,
                                  &stored) != 0)
            return -1;
    }
    if (stored.vlen > kXR_faMaxVlen) {
        errno = E2BIG;
        return -1;
    }
    *value = stored.value;
    return (ssize_t) stored.vlen;
}

ngx_int_t
fattr_storage_remove(brix_vfs_ctx_t *vctx, const char *path, int fd,
    const char *name, size_t nlen)
{
    char key[BRIX_FATTR_XKEY_PFX_LEN + kXR_faMaxNlen + 1U];
    int  wrapped;

    if (fattr_storage_key(name, nlen, key, sizeof(key), &wrapped) != 0)
        return NGX_ERROR;
    if (wrapped)
        return fattr_storage_remove_hashed(vctx, path, fd, key);
    if (fattr_storage_remove_raw(vctx, path, fd, key) == NGX_OK) {
        char hashed[BRIX_FATTR_XKEY_PFX_LEN + kXR_faMaxNlen + 1U];

        if (fattr_storage_hashed_key(name, nlen, hashed, sizeof(hashed)) == 0)
            (void) fattr_storage_remove_hashed(vctx, path, fd, hashed);
        return NGX_OK;
    }
    if (errno != ENODATA && errno != ENOENT) return NGX_ERROR;
    if (fattr_storage_hashed_key(name, nlen, key, sizeof(key)) != 0)
        return NGX_ERROR;
    return fattr_storage_remove_hashed(vctx, path, fd, key);
}

int
fattr_storage_decode_list(ngx_pool_t *pool, brix_vfs_ctx_t *vctx,
    const char *path, int fd, const char *stored_key,
    brix_fattr_stored_t *stored)
{
    size_t key_len = strlen(stored_key);

    if (strncmp(stored_key, BRIX_FATTR_XKEY_PFX,
                BRIX_FATTR_XKEY_PFX_LEN) != 0
        || key_len <= BRIX_FATTR_XKEY_PFX_LEN)
        return 0;
    if (key_len == FATTR_STORED_KEY_LEN
        && memcmp(stored_key, FATTR_STORED_PREFIX,
                  FATTR_STORED_PREFIX_LEN) == 0)
    {
        char expected_key[BRIX_FATTR_XKEY_PFX_LEN + kXR_faMaxNlen + 1U];
        if (fattr_storage_read(pool, vctx, path, fd, stored_key, NULL, 0, 1,
                               stored) != 0
            /* Short logical names also use hashed keys for chunked values.
             * Recompute that physical key, not the direct-name preference;
             * every envelope must still match its exact logical-name digest. */
            || fattr_storage_hashed_key(stored->name, stored->nlen,
                                        expected_key, sizeof(expected_key)) != 0
            || strcmp(expected_key, stored_key) != 0)
        {
            errno = EIO;
            return -1;
        }
        return 1;
    }
    if (key_len > FATTR_STORED_PREFIX_LEN
        && memcmp(stored_key, FATTR_STORED_PREFIX,
                  FATTR_STORED_PREFIX_LEN) == 0)
        return -1;
    stored->name = stored_key + BRIX_FATTR_XKEY_PFX_LEN;
    stored->nlen = key_len - BRIX_FATTR_XKEY_PFX_LEN;
    stored->value = NULL;
    stored->vlen = 0;
    return 1;
}
