/*
 * cks_verify.c — verify a file ON DISK against its recorded checksum.
 *
 * WHAT: xrdc_cks_verify_file() recomputes a local file's checksum (using the
 *       same shared engine as the server / xrdcrc32c) and compares it to the
 *       checksum already recorded for that file, looking in every place this
 *       project records one:
 *         storage endpoint — the "user.XrdCks.<alg>" extended attribute (both
 *           our text form "<hex> <mtime> <nsec> <size>" and the stock binary
 *           XrdCksData record), with a "<path>.cks" sidecar fallback;
 *         proxy cache      — the "<path>.cinfo" block-bitmap record or the
 *           "<path>.meta" sidecar (their cks_alg/cks_hex fields).
 *
 * WHY:  An operator needs a single command to answer "is this cached/stored file
 *       still bit-for-bit what its checksum says" without going through the
 *       running server. The front-end is apps/xrdckverify.c.
 *
 * HOW:  Collect the recorded (algorithm, hex) records for the selected sources,
 *       then recompute each distinct algorithm once over the file (xrdc_cksum_fd)
 *       and compare. The on-disk binary records (XrdCksData, .cinfo, .meta) are
 *       mirrored here as fixed-layout structs — kept byte-compatible with their
 *       canonical definitions in src/compat/integrity_info.c, src/cache/cinfo.h
 *       and src/cache/meta.h (same x86-64 ABI, read verbatim).
 */

#include "xrdc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#define CKV_XATTR_PREFIX "user.XrdCks."
#define CKV_MAX_RECORDS  16

/* ---- mirrors of the canonical on-disk layouts (must stay byte-compatible) -- */

/* src/compat/integrity_info.c struct xrd_cks_data (stock XrdCks/XrdCksData.hh). */
struct ckv_cksdata {
    char      Name[16];
    long long fmTime;
    int       csTime;
    short     Rsvd1;
    char      Rsvd2;
    char      Length;
    char      Value[64];
};

/* src/cache/meta.h xrootd_cache_meta_t. */
struct ckv_meta {
    uint64_t mtime;
    uint64_t size;
    uint8_t  etag_len;
    char     etag[55];
    uint8_t  version;
    uint64_t access_count;
    uint64_t last_access;
    uint64_t bytes_served;
    uint8_t  cks_alg_len;
    char     cks_alg[16];
    uint8_t  cks_len;
    char     cks_hex[129];
};

/* src/cache/cinfo.h xrootd_cache_cinfo_t (header only; bitmap follows on disk). */
struct ckv_cinfo {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
    uint32_t block_size;
    uint32_t reserved;
    uint64_t size;
    uint64_t mtime;
    uint64_t nblocks;
    uint64_t access_count;
    uint64_t bytes_served;
    uint64_t last_access;
    uint8_t  etag_len;
    char     etag[55];
    uint8_t  cks_alg_len;
    char     cks_alg[16];
    uint8_t  cks_len;
    char     cks_hex[129];
};
#define CKV_CINFO_MAGIC 0x58434931u

typedef struct {
    char src[16];                  /* "xattr" | "cks" | "cinfo" | "meta" */
    char algo[16];
    char hex[XRDC_CKV_HEX_MAX];
} ckv_record;

/* ---- helpers ----------------------------------------------------------- */

static void
ckv_bin_to_hex(const unsigned char *bin, int len, char *out, size_t outsz)
{
    static const char hx[] = "0123456789abcdef";
    int i;

    if ((size_t) (2 * len + 1) > outsz) {
        len = (int) ((outsz - 1) / 2);
    }
    for (i = 0; i < len; i++) {
        out[2 * i]     = hx[(bin[i] >> 4) & 0xf];
        out[2 * i + 1] = hx[bin[i] & 0xf];
    }
    out[2 * len] = '\0';
}

/* Decode one "user.XrdCks.<algo>" xattr value into rec.hex. The xattr is either
 * our text form "<hex> <mtime> <nsec> <size>" or a binary XrdCksData record. */
static int
ckv_decode_xattr_value(const char *algo, const char *val, size_t vlen,
    ckv_record *rec)
{
    snprintf(rec->src, sizeof(rec->src), "xattr");
    snprintf(rec->algo, sizeof(rec->algo), "%.15s", algo);

    if (vlen == sizeof(struct ckv_cksdata)) {
        struct ckv_cksdata d;
        memcpy(&d, val, sizeof(d));
        if (d.Length <= 0 || d.Length > (char) sizeof(d.Value)) {
            return 0;
        }
        ckv_bin_to_hex((const unsigned char *) d.Value, d.Length,
                       rec->hex, sizeof(rec->hex));
        return 1;
    }
    /* text form: the leading token is the lowercase hex digest. */
    {
        char hex[XRDC_CKV_HEX_MAX];
        if (sscanf(val, "%128s", hex) != 1 || hex[0] == '\0') {
            return 0;
        }
        snprintf(rec->hex, sizeof(rec->hex), "%s", hex);
        return 1;
    }
}

/* Collect every "user.XrdCks.*" xattr on `path`. */
static void
ckv_collect_xattr(const char *path, ckv_record *recs, size_t max, size_t *n)
{
    char    names[4096];
    ssize_t ln = listxattr(path, names, sizeof(names));
    ssize_t off;

    if (ln <= 0) {
        return;
    }
    for (off = 0; off < ln && *n < max; off += (ssize_t) strlen(names + off) + 1) {
        const char *key = names + off;
        char        val[1024];
        ssize_t     vl;

        if (strncmp(key, CKV_XATTR_PREFIX, sizeof(CKV_XATTR_PREFIX) - 1) != 0) {
            continue;
        }
        vl = getxattr(path, key, val, sizeof(val));
        if (vl <= 0) {
            continue;
        }
        if (ckv_decode_xattr_value(key + sizeof(CKV_XATTR_PREFIX) - 1, val,
                                   (size_t) vl, &recs[*n])) {
            (*n)++;
        }
    }
}

/* Collect records from the "<path>.cks" sidecar (one line per algorithm). */
static void
ckv_collect_sidecar(const char *path, ckv_record *recs, size_t max, size_t *n)
{
    char  scpath[XRDC_PATH_MAX];
    char  line[1024];
    FILE *fp;

    if ((size_t) snprintf(scpath, sizeof(scpath), "%s.cks", path) >= sizeof(scpath)) {
        return;
    }
    fp = fopen(scpath, "re");
    if (fp == NULL) {
        return;
    }
    while (*n < max && fgets(line, sizeof(line), fp) != NULL) {
        char ralgo[32], rhex[XRDC_CKV_HEX_MAX];
        long ms, mn;
        long long sz;
        if (sscanf(line, "%31s %128s %ld %ld %lld", ralgo, rhex, &ms, &mn, &sz) >= 2
            && ralgo[0] && rhex[0]) {
            snprintf(recs[*n].src, sizeof(recs[*n].src), "cks");
            snprintf(recs[*n].algo, sizeof(recs[*n].algo), "%.15s", ralgo);
            snprintf(recs[*n].hex, sizeof(recs[*n].hex), "%.128s", rhex);
            (*n)++;
        }
    }
    fclose(fp);
}

/* Read a fixed-size record from "<path><suffix>" into buf (zeroed first). */
static int
ckv_read_sidecar_blob(const char *path, const char *suffix, void *buf, size_t sz)
{
    char    p[XRDC_PATH_MAX];
    int     fd;
    ssize_t got;

    if ((size_t) snprintf(p, sizeof(p), "%s%s", path, suffix) >= sizeof(p)) {
        return -1;
    }
    fd = open(p, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
    if (fd < 0) {
        return -1;
    }
    memset(buf, 0, sz);
    got = pread(fd, buf, sz, 0);
    close(fd);
    return (got >= 0) ? (int) got : -1;
}

/* Append a cache record (cks_alg/cks_hex) if it carries a checksum. */
static void
ckv_add_cache_record(const char *src, const char *cks_alg, uint8_t cks_alg_len,
    const char *cks_hex, uint8_t cks_len, ckv_record *recs, size_t max, size_t *n)
{
    if (cks_len == 0 || cks_alg_len == 0 || *n >= max) {
        return;
    }
    snprintf(recs[*n].src, sizeof(recs[*n].src), "%.15s", src);
    snprintf(recs[*n].algo, sizeof(recs[*n].algo), "%.*s",
             cks_alg_len > 15 ? 15 : (int) cks_alg_len, cks_alg);
    snprintf(recs[*n].hex, sizeof(recs[*n].hex), "%.*s",
             cks_len > 128 ? 128 : (int) cks_len, cks_hex);
    (*n)++;
}

static void
ckv_collect_cache(const char *path, ckv_record *recs, size_t max, size_t *n)
{
    struct ckv_cinfo ci;
    struct ckv_meta  mt;

    if (ckv_read_sidecar_blob(path, ".cinfo", &ci, sizeof(ci)) >= (int) sizeof(ci)
        && ci.magic == CKV_CINFO_MAGIC) {
        ckv_add_cache_record("cinfo", ci.cks_alg, ci.cks_alg_len,
                             ci.cks_hex, ci.cks_len, recs, max, n);
    }
    if (ckv_read_sidecar_blob(path, ".meta", &mt, sizeof(mt)) >= (int) sizeof(mt)
        && mt.version >= 1) {
        ckv_add_cache_record("meta", mt.cks_alg, mt.cks_alg_len,
                             mt.cks_hex, mt.cks_len, recs, max, n);
    }
}

/* ---- public entry point ------------------------------------------------ */

xrdc_ckv_result
xrdc_cks_verify_file(const char *path, const char *want_algo,
    xrdc_ckv_mode mode, xrdc_ckv_report *rep, xrdc_status *st)
{
    ckv_record recs[CKV_MAX_RECORDS];
    size_t     nrec = 0, i;
    int        fd;
    int        matched = 0, unsupported = 0;
    char       comp[XRDC_CK_ZCRC32 + 1][XRDC_CKV_HEX_MAX];
    int        comp_done[XRDC_CK_ZCRC32 + 1];

    if (rep != NULL) {
        memset(rep, 0, sizeof(*rep));
    }
    memset(comp_done, 0, sizeof(comp_done));

    if (mode == XRDC_CKV_CACHE || mode == XRDC_CKV_AUTO) {
        ckv_collect_cache(path, recs, CKV_MAX_RECORDS, &nrec);
    }
    if (mode == XRDC_CKV_STORAGE || mode == XRDC_CKV_AUTO) {
        ckv_collect_xattr(path, recs, CKV_MAX_RECORDS, &nrec);
        ckv_collect_sidecar(path, recs, CKV_MAX_RECORDS, &nrec);
    }

    if (nrec == 0) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "no recorded checksum found for %s", path);
        return XRDC_CKV_NO_RECORD;
    }

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        xrdc_status_set(st, XRDC_ESOCK, errno, "open %s: %s",
                        path, strerror(errno));
        return XRDC_CKV_ERROR;
    }

    for (i = 0; i < nrec; i++) {
        xrdc_cksum_algo alg;

        if (want_algo != NULL && strcmp(recs[i].algo, want_algo) != 0) {
            continue;
        }
        if (xrdc_cksum_algo_parse(recs[i].algo, &alg) != 0
            || (int) alg > XRDC_CK_ZCRC32) {
            unsupported = 1;
            continue;                 /* recorded with an engine we cannot compute */
        }
        if (!comp_done[alg]) {
            if (lseek(fd, 0, SEEK_SET) < 0
                || xrdc_cksum_fd(fd, alg, comp[alg], XRDC_CKV_HEX_MAX, st) != 0) {
                close(fd);
                return XRDC_CKV_ERROR;
            }
            comp_done[alg] = 1;
        }

        if (rep != NULL) {
            snprintf(rep->source, sizeof(rep->source), "%.15s", recs[i].src);
            snprintf(rep->algo, sizeof(rep->algo), "%.15s", recs[i].algo);
            snprintf(rep->recorded, sizeof(rep->recorded), "%.128s", recs[i].hex);
            snprintf(rep->computed, sizeof(rep->computed), "%.128s", comp[alg]);
        }
        if (strcasecmp(recs[i].hex, comp[alg]) != 0) {
            close(fd);
            xrdc_status_set(st, XRDC_EINTEGRITY, 0,
                            "%s checksum mismatch on %s: recorded %s != computed %s",
                            recs[i].algo, path, recs[i].hex, comp[alg]);
            return XRDC_CKV_MISMATCH;
        }
        matched = 1;
    }

    close(fd);

    if (matched) {
        return XRDC_CKV_OK;
    }
    if (unsupported) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "recorded checksum uses an algorithm this tool cannot compute");
        return XRDC_CKV_UNSUPPORTED;
    }
    xrdc_status_set(st, XRDC_EUSAGE, 0,
                    "no recorded %s checksum for %s",
                    want_algo ? want_algo : "matching", path);
    return XRDC_CKV_NO_RECORD;
}
