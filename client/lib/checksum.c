/*
 * checksum.c — local streaming checksums + the server-side kXR_Qcksum query.
 *
 * WHAT: Compute adler32 / crc32c / md5 over a local file descriptor, and ask the
 *       server for a file's checksum (kXR_query, infotype kXR_Qcksum). Both yield
 *       a lowercase hex digest so xrdcp --cksum can compare local vs source.
 * WHY:  --cksum[:source] needs (a) a digest of the bytes we transferred and (b)
 *       the server's digest of the same file, then asserts they agree.
 * HOW:  The fd compute is delegated to the SHARED kernel xrootd_cksum_*_fd
 *       (src/compat/checksum_core.c, linked via libxrdproto) — the exact same
 *       adler32/crc32c/md5 code the nginx module runs, so client and server agree
 *       by construction (single source). This file only maps the client's algo
 *       enum, hex-encodes, and drives the Qcksum wire query (payload "<algo>
 *       <path>" → reply "<algo> <hexdigest>").
 *
 * wire: XProtocol.hh kXR_query infotype kXR_Qcksum — body "<algo> <path>" → "<algo> <hex>".
 */
#include "xrdc.h"
#include "compat/checksum_core.h"   /* shared fd→checksum kernels (libxrdproto) */
#include "compat/hex.h"             /* shared lowercase hex encoder (libxrdproto) */

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
xrdc_cksum_algo_parse(const char *name, xrdc_cksum_algo *out)
{
    if (name == NULL) {
        return -1;
    }
    if (strcmp(name, "adler32")   == 0) { *out = XRDC_CK_ADLER32;   return 0; }
    if (strcmp(name, "crc32c")    == 0) { *out = XRDC_CK_CRC32C;    return 0; }
    if (strcmp(name, "md5")       == 0) { *out = XRDC_CK_MD5;       return 0; }
    if (strcmp(name, "crc64")     == 0) { *out = XRDC_CK_CRC64;     return 0; }
    if (strcmp(name, "crc64xz")   == 0) { *out = XRDC_CK_CRC64;     return 0; }
    if (strcmp(name, "crc64nvme") == 0) { *out = XRDC_CK_CRC64NVME; return 0; }
    if (strcmp(name, "zcrc32")    == 0) { *out = XRDC_CK_ZCRC32;    return 0; }
    return -1;
}

int
xrdc_cksum_fd(int fd, xrdc_cksum_algo algo, char *hex, size_t hexsz,
              xrdc_status *st)
{
    /* Delegate the compute to the shared (ngx-free) kernel — the same code the
     * nginx module uses (src/compat/checksum_core.c via libxrdproto). The kernel
     * preads from offset 0; callers pass freshly-opened regular-file fds. */
    if (algo == XRDC_CK_MD5) {
        unsigned char dg[64];   /* EVP_MAX_MD_SIZE */
        unsigned int  dn = 0;
        if (xrootd_cksum_digest_fd(XROOTD_CK_MD5, fd, dg, &dn) != 0) {
            xrdc_status_set(st, XRDC_ESOCK, errno, "md5: %s", strerror(errno));
            return -1;
        }
        if (hexsz < (size_t) dn * 2 + 1) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "hex buffer too small");
            return -1;
        }
        xrootd_hex_encode(dg, dn, hex);
        return 0;
    }

    if (algo == XRDC_CK_CRC64 || algo == XRDC_CK_CRC64NVME) {
        int      kind = (algo == XRDC_CK_CRC64) ? XROOTD_CK_CRC64
                                                : XROOTD_CK_CRC64NVME;
        uint64_t value;
        if (xrootd_cksum_u64_fd(kind, fd, &value) != 0) {
            xrdc_status_set(st, XRDC_ESOCK, errno, "checksum read: %s",
                            strerror(errno));
            return -1;
        }
        if (hexsz < 17) {                          /* 16 hex digits + NUL */
            xrdc_status_set(st, XRDC_EUSAGE, 0, "hex buffer too small");
            return -1;
        }
        snprintf(hex, hexsz, "%016llx", (unsigned long long) value);
        return 0;
    }

    {
        int      kind = (algo == XRDC_CK_ADLER32) ? XROOTD_CK_ADLER32
                      : (algo == XRDC_CK_ZCRC32)  ? XROOTD_CK_ZCRC32
                                                  : XROOTD_CK_CRC32C;
        uint32_t value;
        if (xrootd_cksum_u32_fd(kind, fd, &value) != 0) {
            xrdc_status_set(st, XRDC_ESOCK, errno, "checksum read: %s",
                            strerror(errno));
            return -1;
        }
        if (hexsz < 9) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "hex buffer too small");
            return -1;
        }
        snprintf(hex, hexsz, "%08x", value);   /* 8 zero-padded hex digits */
        return 0;
    }
}

int
xrdc_query_cksum(xrdc_conn *c, const char *path, const char *algo_name,
                 char *hex, size_t hexsz, xrdc_status *st)
{
    ClientQueryRequest req;
    uint16_t           status;
    uint8_t           *body = NULL;
    uint32_t           blen = 0;
    char               payload[XRDC_PATH_MAX + 32];
    int                plen;
    const char        *sp;

    /* kXR_Qcksum wire format is the PATH, with the algorithm requested via the
     * standard "?cks.type=<algo>" CGI — NOT a leading "<algo> <path>" (which a
     * standard server, e.g. EOS, treats as a bogus relative path and rejects:
     * "Check summing relative path 'adler32 /…' is disallowed"). Our own server
     * accepts a bare path too, so this is correct for both. */
    if (algo_name != NULL && algo_name[0] != '\0') {
        plen = snprintf(payload, sizeof(payload), "%s%ccks.type=%s", path,
                        (strchr(path, '?') != NULL) ? '&' : '?', algo_name);
    } else {
        plen = snprintf(payload, sizeof(payload), "%s", path);
    }
    if (plen < 0 || (size_t) plen >= sizeof(payload)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "checksum query path too long");
        return -1;
    }

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_query);
    {
        xrdw_query_req_t b = { .infotype = kXR_Qcksum };
        xrdw_query_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }
    /* fhandle stays zero: this is a path-based (not open-handle) query. */

    /* Read-only/idempotent: a re-query after a sever yields the same digest. */
    if (xrdc_roundtrip_resilient(c, &req, payload, (uint32_t) plen,
                                 XRDC_OP_READONLY, 0,
                                 &status, &body, &blen, st) != 0) {
        return -1;
    }

    /* Reply: "<algo> <hexdigest>" — take the token after the (last) space. */
    {
        char tmp[256];
        uint32_t n = (blen < sizeof(tmp) - 1) ? blen : (uint32_t) (sizeof(tmp) - 1);
        memcpy(tmp, body, n);
        tmp[n] = '\0';
        free(body);

        sp = strrchr(tmp, ' ');
        sp = (sp != NULL) ? sp + 1 : tmp;   /* tolerate a digest-only reply */
        /* trim trailing whitespace/newline */
        {
            size_t L = strlen(sp);
            while (L > 0 && (sp[L - 1] == '\n' || sp[L - 1] == '\r'
                             || sp[L - 1] == ' ')) {
                ((char *) sp)[--L] = '\0';
            }
            if (L == 0 || L + 1 > hexsz) {
                xrdc_status_set(st, XRDC_EPROTO, 0,
                                "unparseable checksum reply: \"%s\"", tmp);
                return -1;
            }
        }
        snprintf(hex, hexsz, "%s", sp);
    }
    return 0;
}
