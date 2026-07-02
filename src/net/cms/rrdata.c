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

int
xrootd_cms_rrdata_parse(unsigned char code,
                        const unsigned char *payload, size_t len,
                        xrootd_cms_rrdata_t *out)
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
        if (read_str(&p, end, &out->ident, &out->ident_len) != 0) return -1;
        if (read_str(&p, end, &out->mode,  &out->mode_len)  != 0) return -1;
        if (read_str(&p, end, &out->path,  &out->path_len)  != 0) return -1;
        if (read_opt_str(&p, end, &out->opaque, &out->opaque_len) != 0) return -1;
        return 0;

    case K_MV:
        /* fwdArgB: ident, path, path2, [opaque, opaque2] */
        if (read_str(&p, end, &out->ident, &out->ident_len) != 0) return -1;
        if (read_str(&p, end, &out->path,  &out->path_len)  != 0) return -1;
        if (read_str(&p, end, &out->path2, &out->path2_len) != 0) return -1;
        if (read_opt_str(&p, end, &out->opaque,  &out->opaque_len)  != 0) return -1;
        if (read_opt_str(&p, end, &out->opaque2, &out->opaque2_len) != 0) return -1;
        return 0;

    case K_RM:
    case K_RMDIR:
    case K_STATFS:
        /* fwdArgC: ident, path, [opaque] */
        if (read_str(&p, end, &out->ident, &out->ident_len) != 0) return -1;
        if (read_str(&p, end, &out->path,  &out->path_len)  != 0) return -1;
        if (read_opt_str(&p, end, &out->opaque, &out->opaque_len) != 0) return -1;
        return 0;

    case K_PREPADD:
        /* padArgs: ident, reqid, notify, prty, mode, path, [opaque] */
        if (read_str(&p, end, &out->ident,  &out->ident_len)  != 0) return -1;
        if (read_str(&p, end, &out->reqid,  &out->reqid_len)  != 0) return -1;
        if (read_str(&p, end, &out->notify, &out->notify_len) != 0) return -1;
        if (read_str(&p, end, &out->prty,   &out->prty_len)   != 0) return -1;
        if (read_str(&p, end, &out->mode,   &out->mode_len)   != 0) return -1;
        if (read_str(&p, end, &out->path,   &out->path_len)   != 0) return -1;
        if (read_opt_str(&p, end, &out->opaque, &out->opaque_len) != 0) return -1;
        return 0;

    case K_PREPDEL:
        /* pdlArgs: ident, reqid */
        if (read_str(&p, end, &out->ident, &out->ident_len) != 0) return -1;
        if (read_str(&p, end, &out->reqid, &out->reqid_len) != 0) return -1;
        return 0;

    case K_LOCATE:
    case K_SELECT:
        /* locArgs: ident, opts(int), path, [opaque, avoid] */
        if (read_str(&p, end, &out->ident, &out->ident_len) != 0) return -1;
        if (read_int(&p, end, &out->opts) != 0) return -1;
        out->has_opts = 1;
        if (read_str(&p, end, &out->path, &out->path_len) != 0) return -1;
        if (read_opt_str(&p, end, &out->opaque, &out->opaque_len) != 0) return -1;
        if (read_opt_str(&p, end, &out->avoid,  &out->avoid_len)  != 0) return -1;
        return 0;

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

int
xrootd_cms_rrdata_encode(unsigned char code, const char *ident,
                         const char *path, const char *path2,
                         const char *mode, const char *opaque,
                         unsigned char *buf, size_t buflen)
{
    unsigned char *p   = buf;
    unsigned char *end = buf + buflen;

    switch (code) {

    case K_CHMOD:
    case K_MKDIR:
    case K_MKPATH:
    case K_TRUNC:
        /* fwdArgA: ident, mode, path, [opaque] */
        if (enc_str(&p, end, ident) != 0) return -1;
        if (enc_str(&p, end, mode)  != 0) return -1;
        if (enc_str(&p, end, path)  != 0) return -1;
        if (opaque != NULL && enc_str(&p, end, opaque) != 0) return -1;
        return (int) (p - buf);

    case K_MV:
        /* fwdArgB: ident, path, path2, [opaque] */
        if (enc_str(&p, end, ident) != 0) return -1;
        if (enc_str(&p, end, path)  != 0) return -1;
        if (enc_str(&p, end, path2) != 0) return -1;
        if (opaque != NULL && enc_str(&p, end, opaque) != 0) return -1;
        return (int) (p - buf);

    case K_RM:
    case K_RMDIR:
    case K_STATFS:
        /* fwdArgC: ident, path, [opaque] */
        if (enc_str(&p, end, ident) != 0) return -1;
        if (enc_str(&p, end, path)  != 0) return -1;
        if (opaque != NULL && enc_str(&p, end, opaque) != 0) return -1;
        return (int) (p - buf);

    default:
        return -1;
    }
}

int
xrootd_cms_statfs_encode(uint32_t w_num, uint32_t w_free, uint32_t w_util,
                         uint32_t s_num, uint32_t s_free, uint32_t s_util,
                         unsigned char *buf, size_t buflen)
{
    int n;

    if (buflen < 5) {                 /* 4-byte zero prefix + at least a NUL */
        return -1;
    }
    buf[0] = buf[1] = buf[2] = buf[3] = 0;
    n = snprintf((char *) buf + 4, buflen - 4, "%u %u %u %u %u %u",
                 w_num, w_free, w_util, s_num, s_free, s_util);
    if (n < 0 || (size_t) n >= buflen - 4) {
        return -1;
    }
    return 4 + n + 1;                 /* prefix + string + trailing NUL */
}
