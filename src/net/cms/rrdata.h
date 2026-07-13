#ifndef BRIX_CMS_RRDATA_H
#define BRIX_CMS_RRDATA_H

/*
 * rrdata.h — typed decode of a CMS request/forwarded-op payload (XrdOucPup).
 *
 * WHAT: mirrors the subset of XrdCms's XrdCmsRRData that nginx-xrootd needs to
 *       route and execute forwarded namespace ops and request frames. One
 *       parser, keyed by opcode, fills an brix_cms_rrdata_t whose string spans
 *       borrow the caller's payload buffer.
 * WHY:  byte-exact interop with stock cmsd. The on-wire field order per opcode is
 *       fixed by XrdCmsParser's fwdArgA/B/C, padArgs, pdlArgs and locArgs Pup arg
 *       vectors; this decoder reproduces them exactly.
 * HOW:  pure C (no nginx headers) so it is unit-testable standalone, matching the
 *       ini.c / zip_dir.c pattern. Pup "char" fields are length-prefixed strings
 *       ([2B BE len incl. NUL][bytes][NUL]); "int" fields are tag(0xa0)+4B BE.
 *       The decoded string length EXCLUDES the trailing wire NUL, and because the
 *       NUL is present in the buffer the spans are usable as C strings in place.
 */

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const unsigned char *ident;    size_t ident_len;     /* requestor identity */
    const unsigned char *path;     size_t path_len;      /* primary path */
    const unsigned char *path2;    size_t path2_len;     /* mv destination */
    const unsigned char *opaque;   size_t opaque_len;    /* post-fence cgi */
    const unsigned char *opaque2;  size_t opaque2_len;   /* mv destination cgi */
    const unsigned char *avoid;    size_t avoid_len;     /* locate/select avoid */
    const unsigned char *reqid;    size_t reqid_len;     /* prepadd/prepdel */
    const unsigned char *notify;   size_t notify_len;    /* prepadd */
    const unsigned char *prty;     size_t prty_len;      /* prepadd priority */
    const unsigned char *mode;     size_t mode_len;      /* chmod/mkdir/prepadd */
    uint32_t             opts;     /* locate/select option bits */
    unsigned             has_opts; /* 1 if opts was present on the wire */
} brix_cms_rrdata_t;

/*
 * Decode the Pup payload of request opcode `code` into *out (zeroed first).
 * All string spans borrow `payload`. Returns 0 on success, -1 on a malformed or
 * truncated payload. Unknown opcodes return -1 (nothing to decode).
 */
int brix_cms_rrdata_parse(unsigned char code,
                            const unsigned char *payload, size_t len,
                            brix_cms_rrdata_t *out);

/*
 * String fields of a forwarded namespace op, encoder-side counterpart of the
 * decoded brix_cms_rrdata_t spans. NULL members are emitted as absent; which
 * members are consumed depends on the opcode's arg group (fwdArgA/B/C).
 */
typedef struct {
    const char *ident;     /* requestor identity (all groups) */
    const char *path;      /* primary path (all groups) */
    const char *path2;     /* mv destination (fwdArgB) */
    const char *mode;      /* chmod/mkdir/mkpath/trunc mode (fwdArgA) */
    const char *opaque;    /* optional trailing cgi (all groups) */
} brix_cms_fwd_fields_t;

/*
 * Encode the Pup payload for forwarded op `code` into buf (capacity buflen),
 * reproducing the same field order the decoder expects (fwdArgA/B/C). NULL
 * string fields are emitted as absent. Returns the payload byte length, or -1
 * on an unsupported opcode or buffer overflow. This is the manager fan-out half
 * of the codec; round-tripping through brix_cms_rrdata_parse must be lossless.
 */
int brix_cms_rrdata_encode(unsigned char code,
                             const brix_cms_fwd_fields_t *fields,
                             unsigned char *buf, size_t buflen);

/*
 * Space figures for a kYR_statfs reply: one (num, free, util) triple per tier,
 * writable ("w") first, then staging ("s"), matching cmsd's do_StatFS order.
 */
typedef struct {
    uint32_t w_num;        /* writable-tier server count */
    uint32_t w_free;       /* writable-tier free space (MB) */
    uint32_t w_util;       /* writable-tier utilization (%) */
    uint32_t s_num;        /* staging-tier server count */
    uint32_t s_free;       /* staging-tier free space (MB) */
    uint32_t s_util;       /* staging-tier utilization (%) */
} brix_cms_statfs_fields_t;

/*
 * Encode a kYR_statfs (kYR_data) reply payload, byte-exact with cmsd do_StatFS:
 * a 4-byte zero prefix followed by the ASCII "wNum wFree wUtil sNum sFree sUtil"
 * and a trailing NUL. Returns the payload length (incl. prefix + NUL), or -1 on
 * buffer overflow.
 */
int brix_cms_statfs_encode(const brix_cms_statfs_fields_t *space,
                             unsigned char *buf, size_t buflen);

#endif /* BRIX_CMS_RRDATA_H */
