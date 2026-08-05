/* sign.c — CVMFS manifest/whitelist signers. See sign.h.
 *
 * The signing convention mirrors verify.c's two schemes over the printed
 * hash-line TEXT: whitelists use scheme A (RAW RSA-PKCS#1-v1.5, no digest —
 * the shape of real .cvmfswhitelist files), manifests use scheme B
 * (RSA-PKCS#1-SHA1 DigestInfo — the ONLY shape the official client's
 * EVP_Verify manifest path accepts; S9 pinned this live). Body binding: the
 * hash line is the lowercase sha1-hex of the body EXCLUDING "--\n".
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L         /* gmtime_r under -std=c11 */
#endif
#include "cvmfs/signature/sign.h"
#include "cvmfs/object/object.h"

#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

EVP_PKEY *cvmfs_sign_load_key(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return NULL;
    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    return k;
}

/* Append "K<hex-hash>\n" for a populated hash; skip len-0 hashes. */
static int put_hash_line(char key, const cvmfs_hash_t *h, char *buf, size_t cap, size_t *off) {
    if (h->len == 0) return 0;
    char hex[64];
    if (cvmfs_hash_to_hex(h, 0, hex, sizeof(hex)) < 0) return -1;
    int w = snprintf(buf + *off, cap - *off, "%c%s\n", key, hex);
    if (w < 0 || (size_t) w >= cap - *off) return -1;
    *off += (size_t) w;
    return 0;
}

static int put_line(char *buf, size_t cap, size_t *off, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(buf + *off, cap - *off, fmt, ap);
    va_end(ap);
    if (w < 0 || (size_t) w >= cap - *off) return -1;
    *off += (size_t) w;
    return 0;
}

int cvmfs_manifest_body(const cvmfs_manifest_wr_t *m, char *buf, size_t cap) {
    if (m->root_catalog.len == 0 || m->certificate.len == 0 || m->fqrn == NULL)
        return -1;
    size_t off = 0;
    if (put_hash_line('C', &m->root_catalog, buf, cap, &off) != 0) return -1;
    if (put_line(buf, cap, &off, "B%ld\n", m->catalog_size) != 0) return -1;
    /* R = md5("") — the root-path hash every stock manifest carries. */
    if (put_line(buf, cap, &off, "Rd41d8cd98f00b204e9800998ecf8427e\n") != 0) return -1;
    if (put_hash_line('X', &m->certificate, buf, cap, &off) != 0) return -1;
    if (put_hash_line('H', &m->history, buf, cap, &off) != 0) return -1;
    if (put_hash_line('Y', &m->reflog_checksum, buf, cap, &off) != 0) return -1;
    if (put_line(buf, cap, &off, "Gyes\nAno\nS%ld\nN%s\nT%ld\nD%ld\n",
                 m->revision, m->fqrn, m->timestamp, m->ttl) != 0) return -1;
    return (int) off;
}

int cvmfs_whitelist_body(const char *created14, const char *expiry14,
                         const char *fqrn,
                         const char (*fps)[60], size_t nfp, char *buf, size_t cap) {
    if (expiry14 == NULL || strlen(expiry14) != 14 || fqrn == NULL || nfp == 0
        || (created14 != NULL && strlen(created14) != 14))
        return -1;
    /* Official shape: line 0 = 14-digit creation stamp, then the
     * authoritative "E<expiry>" line — the official client refuses a
     * whitelist whose expiry is not on an E line. created14 == NULL stamps
     * the current UTC time; tests inject a fixed stamp for byte-determinism. */
    char created[16];
    if (created14 == NULL) {
        time_t now = time(NULL);
        struct tm tm_utc;
        gmtime_r(&now, &tm_utc);
        strftime(created, sizeof(created), "%Y%m%d%H%M%S", &tm_utc);
        created14 = created;
    }
    size_t off = 0;
    if (put_line(buf, cap, &off, "%s\nE%s\nN%s\n", created14, expiry14, fqrn) != 0)
        return -1;
    for (size_t i = 0; i < nfp; i++)
        if (put_line(buf, cap, &off, "%s\n", fps[i]) != 0) return -1;
    return (int) off;
}

/* Raw RSA-PKCS#1 signature over `tbs` (both schemes bottom out here). */
static int sign_raw(EVP_PKEY *key, const unsigned char *tbs, size_t tbslen,
                    unsigned char *sig, size_t *slen) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (ctx == NULL) return -1;
    int ok = EVP_PKEY_sign_init(ctx) == 1
          && EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) == 1
          && EVP_PKEY_sign(ctx, sig, slen, tbs, tbslen) == 1;
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* RSA-PKCS#1-SHA1 over the hash text (manifest scheme; the official client's
 * EVP_Verify path accepts nothing else). The SHA-1 DigestInfo DER is built by
 * hand and signed raw: EVP_DigestSign(EVP_sha1()) is rejected outright by
 * hardened OpenSSL-3 crypto policies, while raw RSA on the same bytes is not
 * — and the wire output is identical. */
static int sign_sha1(EVP_PKEY *key, const char *hex, int hexn,
                     unsigned char *sig, size_t *slen) {
    static const unsigned char di_prefix[15] = {
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
        0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    };
    cvmfs_hash_t th;
    if (cvmfs_object_hash(CVMFS_HASH_SHA1, (const unsigned char *) hex,
                          (size_t) hexn, &th) != 0)
        return -1;
    unsigned char di[sizeof(di_prefix) + 20];
    memcpy(di, di_prefix, sizeof(di_prefix));
    memcpy(di + sizeof(di_prefix), th.bytes, 20);
    return sign_raw(key, di, sizeof(di), sig, slen);
}

int cvmfs_sign_artifact(const unsigned char *body, size_t body_len, EVP_PKEY *key,
                        int sha1_digestinfo,
                        unsigned char *out, size_t outcap, size_t *outlen) {
    cvmfs_hash_t bh;
    if (key == NULL
        || cvmfs_object_hash(CVMFS_HASH_SHA1, body, body_len, &bh) != 0)
        return -1;
    char hex[64];
    int  hexn = cvmfs_hash_to_hex(&bh, 0, hex, sizeof(hex));
    if (hexn < 0) return -1;

    /* body + "--\n" + hash line + signature */
    size_t need = body_len + 3 + (size_t) hexn + 1;
    if (need + 512 > outcap) return -1;
    memcpy(out, body, body_len);
    memcpy(out + body_len, "--\n", 3);
    memcpy(out + body_len + 3, hex, (size_t) hexn);
    out[need - 1] = '\n';

    size_t slen = outcap - need;
    int rc = sha1_digestinfo
           ? sign_sha1(key, hex, hexn, out + need, &slen)
           : sign_raw(key, (const unsigned char *) hex, (size_t) hexn,
                      out + need, &slen);
    if (rc != 0) return -1;
    *outlen = need + slen;
    return 0;
}
