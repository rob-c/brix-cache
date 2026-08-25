/*
 * cvmfs xattr BLOB codec (version-1 key/value packing).
 *
 * Split out of catalog_write.c: these three functions are pure C with no
 * sqlite dependency, and libbrix.so (shared/oci/tar.c) links them without
 * pulling the catalog writer's sqlite3 requirement into the public library.
 */
#include "cvmfs/catalog/catalog_write.h"

#include <string.h>

int cvmfs_xattr_pack(const char *const *keys, const unsigned char *const *vals,
                     const size_t *val_lens, size_t n, unsigned char *out, size_t cap) {
    if (n > 255 || cap < 2) return -1;
    out[0] = 1;                      /* version */
    out[1] = (unsigned char) n;
    size_t off = 2;
    for (size_t i = 0; i < n; i++) {
        size_t kl = strlen(keys[i]), vl = val_lens[i];
        if (kl == 0 || kl > 255 || vl > 65535) return -1;
        if (off + 3 + kl + vl > cap) return -1;
        out[off++] = (unsigned char) kl;
        out[off++] = (unsigned char) (vl & 0xff);
        out[off++] = (unsigned char) (vl >> 8);
        memcpy(out + off, keys[i], kl);
        off += kl;
        memcpy(out + off, vals[i], vl);
        off += vl;
    }
    return (int) off;
}

int cvmfs_xattr_count(const unsigned char *blob, size_t blob_len) {
    if (blob == NULL || blob_len < 2 || blob[0] != 1) return -1;
    return blob[1];
}

int cvmfs_xattr_unpack(const unsigned char *blob, size_t blob_len, size_t i,
                       const char **key, size_t *key_len,
                       const unsigned char **val, size_t *val_len) {
    int count = cvmfs_xattr_count(blob, blob_len);
    if (count < 0 || i >= (size_t) count) return -1;
    size_t off = 2;
    for (size_t e = 0; e <= i; e++) {
        if (off + 3 > blob_len) return -1;
        size_t kl = blob[off];
        size_t vl = (size_t) blob[off + 1] | ((size_t) blob[off + 2] << 8);
        off += 3;
        if (off + kl + vl > blob_len) return -1;
        if (e == i) {
            *key = (const char *) blob + off;
            *key_len = kl;
            *val = blob + off + kl;
            *val_len = vl;
            return 0;
        }
        off += kl + vl;
    }
    return -1;
}
