/*
 * xrdcks_xattr.c — xrdcks: manage a checksum stored in a file's extended
 * attribute (§7.20 client-app parity).
 *
 * WHAT: `xrdcks <path> <cksname> [<cksval>|delete]`. With no value, GET (print
 *       the stored checksum; compute+store it on a miss). With a hex value,
 *       SET it. With `delete`, remove it. The checksum lives in the
 *       `user.XrdCks.<cksname>` xattr as the XrdCks `XrdCksData` binary record.
 * WHY:  Files carrying `user.XrdCks.*` checksum xattrs (written by a stock
 *       XRootD server or the stock tool) are common in mixed deployments;
 *       BriX had no tool to read/write/verify them. The on-disk record layout
 *       is a stable, documented format (XrdCksData.hh) — matched byte-exactly
 *       here. NB: the STOCK `xrdcks` CLI on some builds is buggy (segfaults on
 *       get, drops the leading value byte on set); this is a correct
 *       implementation of the FORMAT, deliberately not bug-compatible.
 * HOW:  XrdCksData is a fixed 96-byte record:
 *         Name[16] fmTime[8 BE] csTime[4 BE] Rsvd[3] Length[1] Value[64]
 *       fmTime is the file mtime; Length is the value byte count; Value holds
 *       the binary digest (first Length bytes). We compute via the shared
 *       brix_cksum engine (hex) and hex-decode into Value.
 */
#include "brix.h"
#include "core/progname.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/xattr.h>

/* Linux reports "no such attribute" as ENODATA; some libcs alias ENOATTR. */
#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

#define XRDCKS_RECSZ    96
#define XRDCKS_NAMESZ   16
#define XRDCKS_VALSZ    64
#define XRDCKS_ATTR_PFX "user.XrdCks."

/* ---- hex <-> binary (even-length hex only) ---- */
static int
xrdcks_hex_to_bin(const char *hex, uint8_t *out, size_t outcap, size_t *outlen)
{
    size_t hlen = strlen(hex), i;

    if (hlen == 0 || (hlen & 1) || hlen / 2 > outcap) {
        return -1;
    }
    for (i = 0; i < hlen; i++) {
        char     ch = hex[i];
        uint8_t  nib;

        if      (ch >= '0' && ch <= '9') { nib = (uint8_t) (ch - '0'); }
        else if (ch >= 'a' && ch <= 'f') { nib = (uint8_t) (ch - 'a' + 10); }
        else if (ch >= 'A' && ch <= 'F') { nib = (uint8_t) (ch - 'A' + 10); }
        else { return -1; }
        if (i & 1) { out[i / 2] |= nib; }
        else       { out[i / 2] = (uint8_t) (nib << 4); }
    }
    *outlen = hlen / 2;
    return 0;
}

static void
xrdcks_bin_to_hex(const uint8_t *bin, size_t n, char *out)
{
    static const char hexd[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        out[i * 2]     = hexd[bin[i] >> 4];
        out[i * 2 + 1] = hexd[bin[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

/* ---- Build the "user.XrdCks.<name>" attribute key ---- */
static int
xrdcks_attr_key(const char *cksname, char *out, size_t outsz)
{
    int n = snprintf(out, outsz, XRDCKS_ATTR_PFX "%s", cksname);

    return (n > 0 && (size_t) n < outsz) ? 0 : -1;
}

/* ---- Encode an XrdCksData record (BIG-ENDIAN time fields, as stock stores) --- */
static void
xrdcks_encode(const char *cksname, int64_t fmtime, const uint8_t *val,
              size_t vlen, uint8_t rec[XRDCKS_RECSZ])
{
    uint64_t fm = (uint64_t) fmtime;
    int      i;

    memset(rec, 0, XRDCKS_RECSZ);
    snprintf((char *) rec, XRDCKS_NAMESZ, "%s", cksname);   /* Name[16] */
    for (i = 0; i < 8; i++) {                                /* fmTime[8] BE */
        rec[16 + i] = (uint8_t) (fm >> (56 - i * 8));
    }
    /* csTime[4]=0, Rsvd[3]=0 already zero. */
    rec[31] = (uint8_t) vlen;                                /* Length[1] */
    if (vlen > XRDCKS_VALSZ) { vlen = XRDCKS_VALSZ; }
    memcpy(rec + 32, val, vlen);                             /* Value[64] */
}

/* ---- Decode a record's value length + bytes; -1 if malformed ---- */
static int
xrdcks_decode(const uint8_t *rec, size_t reclen, const uint8_t **val,
              size_t *vlen)
{
    size_t len;

    if (reclen != XRDCKS_RECSZ) {
        return -1;
    }
    len = rec[31];
    if (len > XRDCKS_VALSZ) {
        return -1;
    }
    *val  = rec + 32;
    *vlen = len;
    return 0;
}

/* ---- Compute the file's checksum into a binary value ---- */
static int
xrdcks_compute(const char *path, const char *cksname, uint8_t *val,
               size_t valcap, size_t *vlen)
{
    brix_cksum_algo algo;
    brix_status     st;
    char            hex[2 * XRDCKS_VALSZ + 1];
    int             fd, rc;

    if (brix_cksum_algo_parse(cksname, &algo) != 0) {
        fprintf(stderr, "xrdcks: unknown checksum '%s'\n", cksname);
        return -1;
    }
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "xrdcks: open %s: %s\n", path, strerror(errno));
        return -1;
    }
    brix_status_clear(&st);
    rc = brix_cksum_fd(fd, algo, hex, sizeof(hex), &st);
    close(fd);
    if (rc != 0) {
        fprintf(stderr, "xrdcks: %s: %s\n", path, st.msg);
        return -1;
    }
    return xrdcks_hex_to_bin(hex, val, valcap, vlen);
}

/* ---- SET: write the given hex value into the xattr record ---- */
static int
xrdcks_set(const char *path, const char *cksname, const char *key,
           const char *hexval)
{
    uint8_t  val[XRDCKS_VALSZ], rec[XRDCKS_RECSZ];
    size_t   vlen;
    struct stat sb;

    if (xrdcks_hex_to_bin(hexval, val, sizeof(val), &vlen) != 0) {
        fprintf(stderr, "xrdcks: bad hex value '%s' (even digits, <= %d bytes)\n",
                hexval, XRDCKS_VALSZ);
        return 4;
    }
    if (stat(path, &sb) != 0) {
        fprintf(stderr, "xrdcks: stat %s: %s\n", path, strerror(errno));
        return 4;
    }
    xrdcks_encode(cksname, (int64_t) sb.st_mtime, val, vlen, rec);
    if (setxattr(path, key, rec, XRDCKS_RECSZ, 0) != 0) {
        fprintf(stderr, "xrdcks: set %s on %s: %s\n", key, path,
                strerror(errno));
        return 4;
    }
    return 0;
}

/* ---- GET: print the stored value, or compute+store on a miss ---- */
static int
xrdcks_get(const char *path, const char *cksname, const char *key)
{
    uint8_t rec[XRDCKS_RECSZ];
    ssize_t got = getxattr(path, key, rec, sizeof(rec));

    if (got == XRDCKS_RECSZ) {
        const uint8_t *val;
        size_t         vlen;
        char           hex[2 * XRDCKS_VALSZ + 1];

        if (xrdcks_decode(rec, (size_t) got, &val, &vlen) != 0) {
            fprintf(stderr, "xrdcks: %s: malformed %s record\n", path, key);
            return 4;
        }
        xrdcks_bin_to_hex(val, vlen, hex);
        printf("%s %s\n", cksname, hex);
        return 0;
    }
    if (got < 0 && errno != ENODATA && errno != ENOATTR) {
        fprintf(stderr, "xrdcks: get %s on %s: %s\n", key, path,
                strerror(errno));
        return 4;
    }
    /* No stored checksum: compute it, store it, and print (compute-on-miss). */
    {
        uint8_t val[XRDCKS_VALSZ], newrec[XRDCKS_RECSZ];
        size_t  vlen;
        char    hex[2 * XRDCKS_VALSZ + 1];
        struct stat sb;

        if (xrdcks_compute(path, cksname, val, sizeof(val), &vlen) != 0
            || stat(path, &sb) != 0) {
            return 4;
        }
        xrdcks_encode(cksname, (int64_t) sb.st_mtime, val, vlen, newrec);
        (void) setxattr(path, key, newrec, XRDCKS_RECSZ, 0);   /* best-effort */
        xrdcks_bin_to_hex(val, vlen, hex);
        printf("%s %s\n", cksname, hex);
        return 0;
    }
}

int
brix_xrdcks_main(int argc, char **argv)
{
    char key[XRDCKS_NAMESZ + sizeof(XRDCKS_ATTR_PFX) + 8];

    if (argc == 2 && (strcmp(argv[1], "-h") == 0
                      || strcmp(argv[1], "--help") == 0)) {
        printf("usage: xrdcks <path> <cksname> [<cksval>|delete]\n"
               "  no value : print the stored checksum (compute+store on miss)\n"
               "  <cksval> : store this ASCII-hex value\n"
               "  delete   : remove the stored checksum\n");
        return 0;
    }
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "usage: xrdcks <path> <cksname> [<cksval>|delete]\n");
        return 4;
    }
    if (xrdcks_attr_key(argv[2], key, sizeof(key)) != 0) {
        fprintf(stderr, "xrdcks: checksum name too long\n");
        return 4;
    }
    if (argc == 3) {
        return xrdcks_get(argv[1], argv[2], key);
    }
    if (strcmp(argv[3], "delete") == 0) {
        if (removexattr(argv[1], key) != 0
            && errno != ENODATA && errno != ENOATTR) {
            fprintf(stderr, "xrdcks: delete %s on %s: %s\n", key, argv[1],
                    strerror(errno));
            return 4;
        }
        return 0;
    }
    return xrdcks_set(argv[1], argv[2], key, argv[3]);
}
