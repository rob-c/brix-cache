/* object.c — CVMFS stored-object decode + integrity verify. See object.h. */
#include "cvmfs/object/object.h"

#include <openssl/evp.h>
#include <string.h>
#include <zlib.h>

int cvmfs_object_inflate(const unsigned char *src, size_t srclen,
                         unsigned char *dst, size_t dstcap, size_t *dstlen) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (inflateInit(&zs) != Z_OK) return -1;

    zs.next_in   = (Bytef *) src;
    zs.avail_in  = (uInt) srclen;
    zs.next_out  = dst;
    zs.avail_out = (uInt) dstcap;

    int rc = inflate(&zs, Z_FINISH);
    size_t produced = dstcap - zs.avail_out;
    inflateEnd(&zs);

    if (rc != Z_STREAM_END) return -1;      /* truncated, corrupt, or overflow */
    *dstlen = produced;
    return 0;
}

static const EVP_MD *md_for(cvmfs_hash_algo_e algo) {
    switch (algo) {
    case CVMFS_HASH_SHA1:     return EVP_sha1();
    case CVMFS_HASH_RMD160:   return EVP_ripemd160();
    case CVMFS_HASH_SHAKE128: return EVP_shake128();
    default:                  return NULL;
    }
}

int cvmfs_object_hash(cvmfs_hash_algo_e algo, const unsigned char *data, size_t len,
                      cvmfs_hash_t *out) {
    const EVP_MD *md = md_for(algo);
    if (md == NULL) return -1;

    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int  n = 0;
    EVP_MD_CTX   *c = EVP_MD_CTX_new();
    if (c == NULL) return -1;

    /* SHAKE-128 is an XOF: request the 20-byte CVMFS truncation explicitly. */
    int ok;
    if (algo == CVMFS_HASH_SHAKE128) {
        ok = EVP_DigestInit_ex(c, md, NULL) == 1
          && EVP_DigestUpdate(c, data, len) == 1
          && EVP_DigestFinalXOF(c, buf, 20) == 1;
        n = 20;
    } else {
        ok = EVP_DigestInit_ex(c, md, NULL) == 1
          && EVP_DigestUpdate(c, data, len) == 1
          && EVP_DigestFinal_ex(c, buf, &n) == 1;
    }
    EVP_MD_CTX_free(c);
    if (!ok) return -1;

    return cvmfs_hash_from_bytes(algo, buf, n < 20 ? n : 20, out);
}

int cvmfs_object_verify(const unsigned char *data, size_t len, const cvmfs_hash_t *expected) {
    cvmfs_hash_t got;
    if (cvmfs_object_hash(expected->algo, data, len, &got) != 0) return 0;
    return cvmfs_hash_eq(&got, expected);
}
