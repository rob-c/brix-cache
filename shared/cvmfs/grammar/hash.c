/* hash.c — CVMFS content-hash parse/format. See hash.h. */
#include "cvmfs/grammar/hash.h"

#include <string.h>

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int cvmfs_hash_parse(const char *hex, size_t hexlen, cvmfs_hash_t *out) {
    memset(out, 0, sizeof(*out));
    out->algo = CVMFS_HASH_SHA1;

    if (hexlen >= 41 && hex[40] == '-') {
        const char *a = hex + 41;
        size_t      an = hexlen - 41;
        if (an == 6 && memcmp(a, "rmd160", 6) == 0) {
            out->algo = CVMFS_HASH_RMD160;
        } else if (an == 8 && memcmp(a, "shake128", 8) == 0) {
            out->algo = CVMFS_HASH_SHAKE128;
        } else {
            return -1;
        }
        hexlen = 40;
    }
    if (hexlen != 40) return -1;

    for (size_t i = 0; i < 20; i++) {
        int hi = hexval(hex[2 * i]);
        int lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out->bytes[i] = (unsigned char) ((hi << 4) | lo);
    }
    out->len = 20;
    return 0;
}

int cvmfs_hash_to_object_path(const cvmfs_hash_t *h, char suffix, char *buf, size_t buflen) {
    static const char hx[] = "0123456789abcdef";
    size_t need = h->len * 2 + 2 + (suffix ? 1u : 0u);   /* +'/' +NUL (+suffix) */

    if (buflen < need) return -1;

    size_t o = 0;
    for (size_t i = 0; i < h->len; i++) {
        buf[o++] = hx[h->bytes[i] >> 4];
        buf[o++] = hx[h->bytes[i] & 0xf];
        if (i == 0) buf[o++] = '/';
    }
    if (suffix) buf[o++] = suffix;
    buf[o] = '\0';
    return (int) o;
}

int cvmfs_hash_to_hex(const cvmfs_hash_t *h, char suffix, char *buf, size_t buflen) {
    static const char hx[] = "0123456789abcdef";
    size_t need = h->len * 2 + 1 + (suffix ? 1u : 0u);   /* +NUL (+suffix) */

    if (buflen < need) return -1;

    size_t o = 0;
    for (size_t i = 0; i < h->len; i++) {
        buf[o++] = hx[h->bytes[i] >> 4];
        buf[o++] = hx[h->bytes[i] & 0xf];
    }
    if (suffix) buf[o++] = suffix;
    buf[o] = '\0';
    return (int) o;
}

int cvmfs_hash_from_bytes(cvmfs_hash_algo_e a, const unsigned char *b, size_t n, cvmfs_hash_t *out) {
    if (n > sizeof(out->bytes)) return -1;
    out->algo = a;
    out->len = n;
    memcpy(out->bytes, b, n);
    return 0;
}

int cvmfs_hash_eq(const cvmfs_hash_t *a, const cvmfs_hash_t *b) {
    return a->algo == b->algo && a->len == b->len
        && memcmp(a->bytes, b->bytes, a->len) == 0;
}
