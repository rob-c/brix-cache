/*
 * rrdata.c — typed decode of a CMS request/forwarded-op payload. See rrdata.h.
 *
 * Pure C, no nginx dependency, so the byte-exact wire decode is unit-testable
 * standalone (rrdata_unittest.c). The per-opcode field order reproduces
 * XrdCmsParser's Pup arg vectors exactly (fwdArgA/B/C, padArgs, pdlArgs,
 * locArgs); the "Fence" in those vectors is a parser marker, not a wire byte, so
 * post-fence fields are simply the optional trailing fields here.
 */

#include "rrdata.h"
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* kYR_* request opcodes (wire constants from XProtocol/YProtocol.hh). */
#define K_CHMOD    1
#define K_LOCATE   2
#define K_MKDIR    3
#define K_MKPATH   4
#define K_MV       5
#define K_PREPADD  6
#define K_PREPDEL  7
#define K_RM       8
#define K_RMDIR    9
#define K_SELECT  10
#define K_STATFS  21
#define K_TRUNC   23

#define CMS_PT_INT 0xa0   /* tagged 32-bit scalar */

/*
 * Read one XrdOucPup string at *p: [2B BE len][bytes][NUL], where len counts the
 * trailing NUL. A zero length is an absent/empty string (out=NULL). The returned
 * span EXCLUDES the NUL, so out[out_len] is the in-place NUL terminator. Advances
 * *p. Returns 0 on success, -1 on a short/overrun buffer.
 */
static int
read_str(const unsigned char **p, const unsigned char *end,
         const unsigned char **out, size_t *out_len)
{
    unsigned len;

    if (end - *p < 2) {
        return -1;
    }
    len = ((unsigned) (*p)[0] << 8) | (unsigned) (*p)[1];
    *p += 2;

    if (len == 0) {
        *out = NULL;
        *out_len = 0;
        return 0;
    }
    if ((size_t) (end - *p) < len) {
        return -1;
    }
    *out = *p;
    *out_len = len - 1;        /* drop the trailing NUL from the content span */
    *p += len;
    return 0;
}

/*
 * Read an optional trailing Pup string: absent (no bytes left) is success with
 * out=NULL; otherwise it must decode cleanly.
 */
static int
read_opt_str(const unsigned char **p, const unsigned char *end,
             const unsigned char **out, size_t *out_len)
{
    if (*p >= end) {
        *out = NULL;
        *out_len = 0;
        return 0;
    }
    return read_str(p, end, out, out_len);
}

/* Read a tagged Pup int (CMS_PT_INT + 4B BE). Advances *p. 0 / -1. */
static int
read_int(const unsigned char **p, const unsigned char *end, uint32_t *v)
{
    if (end - *p < 5 || **p != CMS_PT_INT) {
        return -1;
    }
    *v = ((uint32_t) (*p)[1] << 24) | ((uint32_t) (*p)[2] << 16)
       | ((uint32_t) (*p)[3] << 8)  | (uint32_t) (*p)[4];
    *p += 5;
    return 0;
}

/*
 * Spec-driven group decoding. Each XrdCmsParser Pup arg vector (fwdArgA/B/C,
 * padArgs, pdlArgs, locArgs) is one spec string walked left to right; field
 * order is wire-frozen. Letters name a string slot in brix_cms_rrdata_t (see
 * rr_slots), '#' is the tagged locate/select opts int, and '|' marks the
 * fence: every later field is optional-trailing (absent-at-end is success).
 */

typedef struct {
    char     key;        /* spec letter */
    uint16_t ptr_off;    /* offsetof the span pointer in brix_cms_rrdata_t */
    uint16_t len_off;    /* offsetof the matching length */
} rr_slot_t;

#define RR_SLOT(k, f)  { k, offsetof(brix_cms_rrdata_t, f), \
                            offsetof(brix_cms_rrdata_t, f##_len) }

static const rr_slot_t rr_slots[] = {
    RR_SLOT('i', ident),
    RR_SLOT('p', path),
    RR_SLOT('2', path2),
    RR_SLOT('o', opaque),
    RR_SLOT('t', opaque2),
    RR_SLOT('a', avoid),
    RR_SLOT('r', reqid),
    RR_SLOT('n', notify),
    RR_SLOT('y', prty),
    RR_SLOT('m', mode),
};

static const rr_slot_t *
rr_slot(char key)
{
    size_t i;

    for (i = 0; i < sizeof(rr_slots) / sizeof(rr_slots[0]); i++) {
        if (rr_slots[i].key == key) {
            return &rr_slots[i];
        }
    }
    return NULL;
}

/* Walk one group spec over [*p,end), filling *out. Returns 0 / -1. */
static int
rr_parse_spec(const char *spec, const unsigned char **p,
              const unsigned char *end, brix_cms_rrdata_t *out)
{
    int optional = 0;

    for (; *spec != '\0'; spec++) {
        const rr_slot_t      *slot;
        const unsigned char **span;
        size_t               *span_len;

        if (*spec == '|') {
            optional = 1;
            continue;
        }
        if (*spec == '#') {
            if (read_int(p, end, &out->opts) != 0) {
                return -1;
            }
            out->has_opts = 1;
            continue;
        }

        slot     = rr_slot(*spec);
        span     = (const unsigned char **) ((char *) out + slot->ptr_off);
        span_len = (size_t *) ((char *) out + slot->len_off);

        if (optional) {
            if (read_opt_str(p, end, span, span_len) != 0) {
                return -1;
            }
        } else if (read_str(p, end, span, span_len) != 0) {
            return -1;
        }
    }
    return 0;
}

int
brix_cms_rrdata_parse(unsigned char code,
                        const unsigned char *payload, size_t len,
                        brix_cms_rrdata_t *out)
{
    const unsigned char *p   = payload;
    const unsigned char *end = payload + len;

    memset(out, 0, sizeof(*out));

    switch (code) {

    case K_CHMOD:
    case K_MKDIR:
    case K_MKPATH:
    case K_TRUNC:
        /* fwdArgA: ident, mode, path, [opaque] */
        return rr_parse_spec("imp|o", &p, end, out);

    case K_MV:
        /* fwdArgB: ident, path, path2, [opaque, opaque2] */
        return rr_parse_spec("ip2|ot", &p, end, out);

    case K_RM:
    case K_RMDIR:
    case K_STATFS:
        /* fwdArgC: ident, path, [opaque] */
        return rr_parse_spec("ip|o", &p, end, out);

    case K_PREPADD:
        /* padArgs: ident, reqid, notify, prty, mode, path, [opaque] */
        return rr_parse_spec("irnymp|o", &p, end, out);

    case K_PREPDEL:
        /* pdlArgs: ident, reqid */
        return rr_parse_spec("ir", &p, end, out);

    case K_LOCATE:
    case K_SELECT:
        /* locArgs: ident, opts(int), path, [opaque, avoid] */
        return rr_parse_spec("i#p|oa", &p, end, out);

    default:
        return -1;
    }
}

/* Encode one Pup string into [*p,end): [2B BE len incl NUL][bytes][NUL]; an empty
 * string is a bare 2-byte zero. Advances *p. Returns 0 / -1 on overflow. */
static int
enc_str(unsigned char **p, unsigned char *end, const char *s)
{
    size_t n = (s != NULL) ? strlen(s) : 0;

    if (n == 0) {
        if (end - *p < 2) {
            return -1;
        }
        (*p)[0] = 0;
        (*p)[1] = 0;
        *p += 2;
        return 0;
    }
    if ((size_t) (end - *p) < n + 3) {       /* 2 len + n + NUL */
        return -1;
    }
    (*p)[0] = (unsigned char) (((unsigned) (n + 1)) >> 8);
    (*p)[1] = (unsigned char) (n + 1);
    memcpy(*p + 2, s, n);
    (*p)[2 + n] = '\0';
    *p += n + 3;
    return 0;
}

/*
 * Encode a fixed sequence of mandatory Pup strings followed by an optional
 * trailing opaque (omitted entirely when opaque==NULL — the wire form for an
 * absent optional field). Shared body of every rrdata_encode arg group; the
 * caller supplies the group's field order. Returns 0 / -1 on overflow.
 */
static int
enc_seq(unsigned char **p, unsigned char *end,
        const char *const *fields, size_t nfields, const char *opaque)
{
    size_t i;

    for (i = 0; i < nfields; i++) {
        if (enc_str(p, end, fields[i]) != 0) {
            return -1;
        }
    }
    if (opaque != NULL && enc_str(p, end, opaque) != 0) {
        return -1;
    }
    return 0;
}

int
brix_cms_rrdata_encode(unsigned char code,
                         const brix_cms_fwd_fields_t *fields,
                         unsigned char *buf, size_t buflen)
{
    unsigned char *p   = buf;
    unsigned char *end = buf + buflen;
    const char    *seq[3];
    size_t         nseq;

    switch (code) {

    case K_CHMOD:
    case K_MKDIR:
    case K_MKPATH:
    case K_TRUNC:
        /* fwdArgA: ident, mode, path, [opaque] */
        seq[0] = fields->ident; seq[1] = fields->mode; seq[2] = fields->path;
        nseq = 3;
        break;

    case K_MV:
        /* fwdArgB: ident, path, path2, [opaque] */
        seq[0] = fields->ident; seq[1] = fields->path; seq[2] = fields->path2;
        nseq = 3;
        break;

    case K_RM:
    case K_RMDIR:
    case K_STATFS:
        /* fwdArgC: ident, path, [opaque] */
        seq[0] = fields->ident; seq[1] = fields->path;
        nseq = 2;
        break;

    default:
        return -1;
    }

    if (enc_seq(&p, end, seq, nseq, fields->opaque) != 0) {
        return -1;
    }
    return (int) (p - buf);
}

int
brix_cms_statfs_encode(const brix_cms_statfs_fields_t *space,
                         unsigned char *buf, size_t buflen)
{
    int n;

    if (buflen < 5) {                 /* 4-byte zero prefix + at least a NUL */
        return -1;
    }
    buf[0] = buf[1] = buf[2] = buf[3] = 0;
    n = snprintf((char *) buf + 4, buflen - 4, "%u %u %u %u %u %u",
                 space->w_num, space->w_free, space->w_util,
                 space->s_num, space->s_free, space->s_util);
    if (n < 0 || (size_t) n >= buflen - 4) {
        return -1;
    }
    return 4 + n + 1;                 /* prefix + string + trailing NUL */
}
