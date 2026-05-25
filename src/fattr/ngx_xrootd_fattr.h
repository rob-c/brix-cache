#ifndef NGX_XROOTD_FATTR_H
#define NGX_XROOTD_FATTR_H

#include "../ngx_xrootd_module.h"

/*
 * kXR_fattr — XRootD file-attribute (extended attribute) operations.
 *
 * XRootD file attributes are mapped to POSIX extended attributes under the
 * "user." namespace.  The XRootD wire name (e.g. "mykey") is stored as the
 * xattr key "user.U.mykey" on the filesystem.  On retrieval the prefix is
 * stripped back to "U.mykey" for the wire response (XROOTD_FATTR_RESP_PFX).
 *
 * Key prefixes:
 *   XROOTD_FATTR_XKEY_PFX     "user.U." — filesystem xattr key prefix
 *   XROOTD_FATTR_XKEY_PFX_LEN 7         — byte length of that prefix
 *   XROOTD_FATTR_RESP_PFX     "U."      — client-visible key prefix
 *   XROOTD_FATTR_MAX_VBUF     65536     — maximum xattr value buffer
 */
#define XROOTD_FATTR_XKEY_PFX   "user.U."
#define XROOTD_FATTR_XKEY_PFX_LEN  7
#define XROOTD_FATTR_RESP_PFX   "U."
#define XROOTD_FATTR_MAX_VBUF   65536

/*
 * Parsed view of one fattr name-vector (nvec) entry.
 *
 * XRootD fattr requests carry a name vector: a sequence of
 *   [uint16_t rc = 0][uint16_t nlen][nlen bytes name]
 * entries.  After per-attribute operations complete, rc_ptr is overwritten with
 * the XRootD status code in-place so the same nvec buffer is used for the
 * kXR_fattr status response without rebuilding the wire frame.
 *
 * Lifetime: stack-allocated by the dispatch functions; valid only for the
 *   duration of one kXR_fattr request.
 */
typedef struct {
    u_char  *rc_ptr;    /* pointer into nvec_copy where the 2-byte rc lives */
    char    *name;      /* NUL-terminated attribute name from the nvec */
    size_t   nlen;      /* byte count of name (not including NUL) */
    char     xkey[512]; /* full "user.U.<name>" xattr key, NUL-terminated */
    u_char  *value;     /* value for set ops (NULL for get/del/list) */
    ssize_t  vlen;      /* length of value (-1 = not set) */
    uint16_t errcode;   /* per-attribute XRootD error code (0 = success) */
} xrootd_fattr_entry_t;

/* Map a POSIX errno to the nearest XRootD fattr status code. */
uint16_t fattr_errno_to_xrd(int err);

/* Write the 2-byte XRootD status code into the in-place nvec rc slot. */
void fattr_set_rc(xrootd_fattr_entry_t *attr, uint16_t rc);

/*
 * fattr_parse_nvec — parse the name vector from the request payload into the
 * attrs[] array.  nvec_copy must be a writable copy of the wire name vector
 * (rc bytes will be overwritten in place after operations complete).
 *
 * Returns the number of bytes consumed, or -1 on parse error.
 */
ssize_t fattr_parse_nvec(ngx_log_t *log, u_char *nvec_copy, size_t buflen,
    int numattr, xrootd_fattr_entry_t *attrs);

/*
 * fattr_send_vector_status — build and send the kXR_fattr status response
 * using the in-place nvec_copy (with rc slots already overwritten).
 */
ngx_int_t fattr_send_vector_status(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *nvec_copy, size_t nvec_len, int numattr,
    xrootd_fattr_entry_t *attrs);

/* Retrieve xattr values via getxattr(2); fills attrs[i].value and .vlen. */
ngx_int_t fattr_get(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *path, int fd, u_char *nvec_copy, size_t nvec_len,
    int numattr, xrootd_fattr_entry_t *attrs);

/*
 * fattr_set — write xattr values via setxattr(2).
 * options: kXR_fattrMkPath and kXR_fattrDel flags from the wire header.
 * vvec_buf/vvec_len: the value vector from the request payload.
 */
ngx_int_t fattr_set(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *path, int fd, int options, u_char *nvec_copy,
    size_t nvec_len, u_char *vvec_buf, size_t vvec_len, int numattr,
    xrootd_fattr_entry_t *attrs);

/* Remove xattr entries via removexattr(2). */
ngx_int_t fattr_del(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *path, int fd, u_char *nvec_copy, size_t nvec_len,
    int numattr, xrootd_fattr_entry_t *attrs);

/*
 * fattr_list — enumerate all "user.U.*" xattrs via listxattr(2) and send
 * the names as a kXR_fattr response.
 * options: kXR_fa_aData returns values; kXR_fa_recurse (local extension)
 *   walks subdirectories and emits "<relpath>:<U.name>\0" entries.
 */
ngx_int_t fattr_list(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *path, int fd, int options);

#endif /* NGX_XROOTD_FATTR_H */
