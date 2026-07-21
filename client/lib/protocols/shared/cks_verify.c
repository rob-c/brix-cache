/*
 * cks_verify.c — verify a file ON DISK against its recorded checksum.
 *
 * WHAT: brix_cks_verify_file() recomputes a local file's checksum (using the
 *       same shared engine as the server / xrdcrc32c) and compares it to the
 *       checksum already recorded for that file, looking in every place this
 *       project records one:
 *         storage endpoint — the "user.XrdCks.<alg>" extended attribute (both
 *           our text form "<hex> <mtime> <nsec> <size>" and the stock binary
 *           XrdCksData record), with a "<path>.cks" sidecar fallback;
 *         proxy cache      — the unified xmeta record ("user.xrd.cinfo" xattr,
 *           else the "<path>.cinfo" sidecar) ORIGIN section, with a legacy
 *           "<path>.meta" POD fallback for pre-xmeta caches.
 *
 * WHY:  An operator needs a single command to answer "is this cached/stored file
 *       still bit-for-bit what its checksum says" without going through the
 *       running server. The front-end is apps/xrdckverify.c.
 *
 * HOW:  Collect the recorded (algorithm, hex) records for the selected sources,
 *       then recompute each distinct algorithm once over the file (brix_cksum_fd)
 *       and compare. XrdCksData and the legacy .meta POD are mirrored here as
 *       fixed-layout structs (byte-compatible with src/core/compat/integrity_info.c
 *       and the legacy reader in src/fs/cache/meta.c); the xmeta cache record is
 *       parsed from its little-endian wire bytes (same walk as
 *       apps/cksum/xrdcinfo.c and src/fs/meta/xmeta_decode.c).
 */

#include "brix.h"

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

/* mirrors of the canonical on-disk layouts (must stay byte-compatible) -- */

/* src/core/compat/integrity_info.c struct xrd_cks_data (stock XrdCks/XrdCksData.hh). */
struct ckv_cksdata {
    char      Name[16];
    long long fmTime;
    int       csTime;
    short     Rsvd1;
    char      Rsvd2;
    char      Length;
    char      Value[64];
};

/* Legacy pre-xmeta ".meta" sidecar POD (matches the fallback reader kept in
 * src/fs/cache/meta.c for caches written before the xmeta migration). */
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

/* Current cache record: the unified xmeta carrier (src/fs/meta/) — a stock v4
 * cinfo prefix + "XCX1" TLV extension block whose ORIGIN section (type 0x0004)
 * holds {u8 etag_len, u8 alg_len, u8 cks_len, u8 pad} + etag/alg/hex strings.
 * It rides in the data file's "user.xrd.cinfo" xattr when it fits, else in the
 * "<path>.cinfo" sidecar. Parsed from raw little-endian bytes, not mirrored. */
#define CKV_XMETA_XATTR      "user.xrd.cinfo"
#define CKV_XMETA_VERSION    4
#define CKV_XMETA_EXT_MAGIC  0x31584358u             /* "XCX1" */
#define CKV_XMETA_SEC_ORIGIN 0x0004u
#define CKV_XMETA_MAX        (64 * 1024)

typedef struct {
    char src[16];                  /* "xattr" | "cks" | "cinfo" | "meta" */
    char algo[16];
    char hex[XRDC_CKV_HEX_MAX];
} ckv_record;

/* helpers */
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

/* little-endian scalar reads over the raw xmeta bytes */
static uint16_t
ckv_rd_u16(const uint8_t *b, size_t off)
{
    return (uint16_t) (b[off] | (b[off + 1] << 8));
}

static uint32_t
ckv_rd_u32(const uint8_t *b, size_t off)
{
    return (uint32_t) b[off] | ((uint32_t) b[off + 1] << 8)
         | ((uint32_t) b[off + 2] << 16) | ((uint32_t) b[off + 3] << 24);
}

static uint64_t
ckv_rd_u64(const uint8_t *b, size_t off)
{
    uint64_t v = 0;
    int      i;

    for (i = 0; i < 8; i++) {
        v |= (uint64_t) b[off + i] << (8 * i);
    }
    return v;
}

/* ---- Validate the v4 xmeta prefix and locate the "XCX1" extension block ----
 *
 * WHAT: Checks the stock v4 cinfo prefix of the raw xmeta record `buf`
 *       (`n` bytes) — version + 48-byte Store + crc + present bitmap +
 *       AStat[] + crc — then verifies the "XCX1" extension magic that follows.
 *       Returns 1 with `*sec_off` set to the first extension section and
 *       `*nsec` to the section count; returns 0 on any malformed/truncated
 *       prefix.
 *
 * WHY:  Isolates the fixed-prefix arithmetic from the section scan so the
 *       ORIGIN extraction reads as prefix-check → scan → decode; the inline
 *       walk drove ckv_xmeta_origin over the complexity cap.
 *
 * HOW:  1. Require >= 56 bytes and version CKV_XMETA_VERSION.
 *       2. Read bsize/size/astatn and reject non-positive/negative values.
 *       3. Compute the block-bitmap length from size/bsize and derive the
 *          extension-block offset.
 *       4. Bounds-check the 8-byte extension header and require "XCX1".
 *       5. Publish the section count and the offset just past the header.
 */
static int
ckv_xmeta_ext_locate(const uint8_t *buf, size_t n, size_t *sec_off,
    uint16_t *nsec)
{
    int64_t  bsize, size;
    int32_t  astatn;
    uint64_t nblocks;
    size_t   off;

    if (n < 56 || (int32_t) ckv_rd_u32(buf, 0) != CKV_XMETA_VERSION) {
        return 0;
    }
    bsize  = (int64_t) ckv_rd_u64(buf, 4);
    size   = (int64_t) ckv_rd_u64(buf, 12);
    astatn = (int32_t) ckv_rd_u32(buf, 48);
    if (bsize <= 0 || size < 0 || astatn < 0) {
        return 0;
    }
    nblocks = (size > 0)
        ? ((uint64_t) size + (uint64_t) bsize - 1) / (uint64_t) bsize
        : 0;
    off = 4 + 48 + 4 + (size_t) ((nblocks + 7) / 8)
        + (size_t) astatn * 56 + 4;
    if (off + 8 > n || ckv_rd_u32(buf, off) != CKV_XMETA_EXT_MAGIC) {
        return 0;
    }
    *nsec    = ckv_rd_u16(buf, off + 6);
    *sec_off = off + 8;
    return 1;
}

/* ---- Decode one ORIGIN-section payload into *rec ----
 *
 * WHAT: Parses an ORIGIN (0x0004) section payload `p` of `plen` bytes —
 *       {u8 etag_len, u8 alg_len, u8 cks_len, u8 pad} + etag/alg/hex strings —
 *       into rec->{src,algo,hex}. Returns 1 on success, 0 when the embedded
 *       lengths are inconsistent with the payload (corrupt record).
 *
 * WHY:  Keeps the length-sanity checks and string extraction next to each
 *       other and out of the section-scan loop; a 0 here means the whole
 *       record is untrustworthy, matching the pre-split behaviour.
 *
 * HOW:  1. Read the etag/alg/cks length bytes.
 *       2. Reject zero or oversized alg/cks lengths and payload under-runs.
 *       3. Copy source tag, algorithm, and hex digest into *rec.
 */
static int
ckv_xmeta_origin_decode(const uint8_t *p, uint32_t plen, ckv_record *rec)
{
    uint8_t el = p[0], al = p[1], cl = p[2];

    if (al == 0 || cl == 0 || al > 15 || cl > 128
        || plen < 4u + el + al + cl)
    {
        return 0;
    }
    snprintf(rec->src, sizeof(rec->src), "cinfo");
    snprintf(rec->algo, sizeof(rec->algo), "%.*s",
             (int) al, (const char *) p + 4 + el);
    snprintf(rec->hex, sizeof(rec->hex), "%.*s",
             (int) cl, (const char *) p + 4 + el + al);
    return 1;
}

/* Extract the ORIGIN-section checksum from one raw xmeta record into *rec.
 * Walk: v4 stock prefix (ckv_xmeta_ext_locate) -> "XCX1" extension block ->
 * section type 0x0004 (ckv_xmeta_origin_decode). Returns 1 when an (alg, hex)
 * pair was found; every offset is bounds-checked against n so a truncated or
 * corrupt record yields 0, never an over-read. */
static int
ckv_xmeta_origin(const uint8_t *buf, size_t n, ckv_record *rec)
{
    size_t   off;
    uint16_t nsec, i;

    if (!ckv_xmeta_ext_locate(buf, n, &off, &nsec)) {
        return 0;
    }
    for (i = 0; i < nsec && off + 12 <= n; i++) {
        uint16_t       type = ckv_rd_u16(buf, off);
        uint32_t       plen = ckv_rd_u32(buf, off + 4);
        const uint8_t *p    = buf + off + 8;

        if (off + 8 + (size_t) plen + 4 > n) {
            return 0;
        }
        if (type == CKV_XMETA_SEC_ORIGIN && plen >= 4) {
            return ckv_xmeta_origin_decode(p, plen, rec);
        }
        off += 8 + (size_t) plen + 4;
    }
    return 0;
}

/* Slurp the xmeta record for `path` (xattr first, else "<path>.cinfo" sidecar)
 * into a malloc'd buffer. Returns byte count, or -1 when neither carrier
 * exists. */
static ssize_t
ckv_read_xmeta(const char *path, uint8_t *buf, size_t cap)
{
    char    scpath[XRDC_PATH_MAX];
    int     fd;
    ssize_t got;

    got = getxattr(path, CKV_XMETA_XATTR, buf, cap);
    if (got > 0) {
        return got;
    }
    if ((size_t) snprintf(scpath, sizeof(scpath), "%s%s", path, ".cinfo")
        >= sizeof(scpath))
    {
        return -1;
    }
    fd = open(scpath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
    if (fd < 0) {
        return -1;
    }
    got = pread(fd, buf, cap, 0);
    close(fd);
    return (got > 0) ? got : -1;
}

static void
ckv_collect_cache(const char *path, ckv_record *recs, size_t max, size_t *n)
{
    struct ckv_meta  mt;
    uint8_t         *buf;
    ssize_t          got;

    if (*n < max) {
        buf = malloc(CKV_XMETA_MAX);
        if (buf != NULL) {
            got = ckv_read_xmeta(path, buf, CKV_XMETA_MAX);
            if (got > 0
                && ckv_xmeta_origin(buf, (size_t) got, &recs[*n]))
            {
                (*n)++;
            }
            free(buf);
        }
    }
    /* legacy pre-xmeta ".meta" sidecar (mirrors src/fs/cache/meta.c fallback) */
    if (ckv_read_sidecar_blob(path, ".meta", &mt, sizeof(mt)) >= (int) sizeof(mt)
        && mt.version >= 1) {
        ckv_add_cache_record("meta", mt.cks_alg, mt.cks_alg_len,
                             mt.cks_hex, mt.cks_len, recs, max, n);
    }
}

/* ---- Gather every recorded checksum for `path` selected by `mode` ----
 *
 * WHAT: Appends the recorded (source, algo, hex) records for `path` into `recs`
 *       (up to `max`, advancing `*n`), pulling from the cache sidecars
 *       (.cinfo/.meta) and/or the storage records (XrdCks xattrs + .cks sidecar)
 *       according to `mode`.
 *
 * WHY:  Isolates the mode→source routing so the public entry point stays a flat
 *       linear sequence; the four-way mode branching lived inline and drove the
 *       function over the complexity cap without adding any behaviour of its own.
 *
 * HOW:  1. For CACHE or AUTO, collect the .cinfo/.meta cache records.
 *       2. For STORAGE or AUTO, collect the XrdCks xattrs then the .cks sidecar.
 *       Source order is preserved exactly (cache before storage) so verification
 *       reports the same first-match record as before.
 */
static void
ckv_collect_records(const char *path, brix_ckv_mode mode, ckv_record *recs,
    size_t max, size_t *n)
{
    if (mode == XRDC_CKV_CACHE || mode == XRDC_CKV_AUTO) {
        ckv_collect_cache(path, recs, max, n);
    }
    if (mode == XRDC_CKV_STORAGE || mode == XRDC_CKV_AUTO) {
        ckv_collect_xattr(path, recs, max, n);
        ckv_collect_sidecar(path, recs, max, n);
    }
}

/* ---- Verify one recorded checksum against the open file ----
 *
 * WHAT: Compares record `rec` against the file behind `fd`. Returns 0 to keep
 *       iterating (record skipped, unsupported, or matched) and 1 for a terminal
 *       outcome, writing that outcome into `*out` (XRDC_CKV_ERROR on a read/hash
 *       failure, XRDC_CKV_MISMATCH on a digest mismatch). Sets `*matched` on a
 *       match and `*unsupported` when the algorithm cannot be computed. Computed
 *       digests are memoised in `comp`/`comp_done` keyed by algorithm so each
 *       distinct algorithm is hashed over the file at most once.
 *
 * WHY:  Extracts the per-record body of the verification loop so the orchestrator
 *       reads as a short scan; the compare/hash logic is integrity-critical and
 *       preserved verbatim, just relocated behind a return-value contract that
 *       replaces the loop's early `return`/`continue` control flow.
 *
 * HOW:  1. Skip (return 0) if `want_algo` is set and this record's algo differs.
 *       2. Mark unsupported and skip if the algo does not parse to a computable
 *          engine.
 *       3. Compute the digest once per algorithm (rewind + brix_cksum_fd); on any
 *          read/hash failure set `*out` = ERROR and return 1.
 *       4. Fill the caller's report (when non-NULL).
 *       5. Case-insensitively compare recorded vs computed hex; on a mismatch set
 *          the integrity status, `*out` = MISMATCH, and return 1; otherwise flag
 *          `*matched` and return 0.
 */
static int
ckv_verify_one(int fd, const ckv_record *rec, const char *path,
    const char *want_algo, char comp[][XRDC_CKV_HEX_MAX], int *comp_done,
    brix_ckv_report *rep, brix_status *st, int *matched, int *unsupported,
    brix_ckv_result *out)
{
    brix_cksum_algo alg;

    if (want_algo != NULL && strcmp(rec->algo, want_algo) != 0) {
        return 0;
    }
    if (brix_cksum_algo_parse(rec->algo, &alg) != 0
        || (int) alg > XRDC_CK_ZCRC32) {
        *unsupported = 1;             /* recorded with an engine we cannot compute */
        return 0;
    }
    if (!comp_done[alg]) {
        if (lseek(fd, 0, SEEK_SET) < 0
            || brix_cksum_fd(fd, alg, comp[alg], XRDC_CKV_HEX_MAX, st) != 0) {
            *out = XRDC_CKV_ERROR;
            return 1;
        }
        comp_done[alg] = 1;
    }

    if (rep != NULL) {
        snprintf(rep->source, sizeof(rep->source), "%.15s", rec->src);
        snprintf(rep->algo, sizeof(rep->algo), "%.15s", rec->algo);
        snprintf(rep->recorded, sizeof(rep->recorded), "%.128s", rec->hex);
        snprintf(rep->computed, sizeof(rep->computed), "%.128s", comp[alg]);
    }
    if (strcasecmp(rec->hex, comp[alg]) != 0) {
        brix_status_set(st, XRDC_EINTEGRITY, 0,
                        "%s checksum mismatch on %s: recorded %s != computed %s",
                        rec->algo, path, rec->hex, comp[alg]);
        *out = XRDC_CKV_MISMATCH;
        return 1;
    }
    *matched = 1;
    return 0;
}

/* public entry point */
brix_ckv_result
brix_cks_verify_file(const char *path, const char *want_algo,
    brix_ckv_mode mode, brix_ckv_report *rep, brix_status *st)
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

    ckv_collect_records(path, mode, recs, CKV_MAX_RECORDS, &nrec);

    if (nrec == 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "no recorded checksum found for %s", path);
        return XRDC_CKV_NO_RECORD;
    }

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        brix_status_set(st, XRDC_ESOCK, errno, "open %s: %s",
                        path, strerror(errno));
        return XRDC_CKV_ERROR;
    }

    for (i = 0; i < nrec; i++) {
        brix_ckv_result outcome = XRDC_CKV_ERROR;

        if (ckv_verify_one(fd, &recs[i], path, want_algo, comp, comp_done,
                           rep, st, &matched, &unsupported, &outcome) != 0) {
            close(fd);
            return outcome;
        }
    }

    close(fd);

    if (matched) {
        return XRDC_CKV_OK;
    }
    if (unsupported) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "recorded checksum uses an algorithm this tool cannot compute");
        return XRDC_CKV_UNSUPPORTED;
    }
    brix_status_set(st, XRDC_EUSAGE, 0,
                    "no recorded %s checksum for %s",
                    want_algo ? want_algo : "matching", path);
    return XRDC_CKV_NO_RECORD;
}
