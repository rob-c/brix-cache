#ifndef BRIX_FS_BACKEND_HTTP_SD_HTTP_XATTR_INTERNAL_H
#define BRIX_FS_BACKEND_HTTP_SD_HTTP_XATTR_INTERNAL_H

/*
 * sd_http_xattr_internal.h — the xattr-over-dead-properties mapping, shared by
 * the reader (sd_http_xattr.c) and the writer (sd_http_xattr_write.c).
 *
 * The two halves are separate units only because one file carrying both would
 * pass the 600-line cap; they are ONE mapping, and every constant that defines
 * the wire spelling lives here so the two can never drift into writing one
 * encoding and reading another.
 */

#include "sd_http_internal.h"

/* The XML namespace these properties live in. Deliberately NOT DAV: — an xattr
 * is a BriX-side name/value pair, and squatting the DAV namespace would claim a
 * meaning the RFC gets to define. */
#define SD_HTTP_XATTR_NS         "https://brix.dev/ns/xattr"

/* Linux caps an xattr name at 255 bytes and this driver caps a value at 16 KiB —
 * the same ceiling the webdav dead-prop store uses, so a property written through
 * one door and read through the other cannot straddle two limits. */
#define SD_HTTP_XATTR_NAME_MAX   255u
#define SD_HTTP_XATTR_VALUE_MAX  16384u

/* `bxa` + two hex digits per name byte + NUL. */
#define SD_HTTP_XATTR_ELEM_MAX   (3u + 2u * SD_HTTP_XATTR_NAME_MAX + 1u)

/* A multistatus this driver understands is one resource with a bounded set of
 * bounded properties. Past this it is not our reply, and copying it to
 * NUL-terminate it (the tag scanners walk a C string) would be unbounded work. */
#define SD_HTTP_XATTR_XML_MAX    (256u * 1024u)

/* Encode one xattr name as the element local name `bxa<hex(name)>`; 0, or -1
 * with errno EINVAL (empty) / ERANGE (over-long). */
int sd_http_xattr_elem(const char *name, char *out, size_t cap);

/* Resolve one request's credential into an auth header line and an optional
 * per-user x509 proxy path; 0, or -1 with errno EACCES when the deny-mode gate
 * refuses a proxy the transport cannot present. */
int sd_http_xattr_auth(sd_http_inst_state *is, const brix_sd_cred_t *cred,
    char *open_auth, size_t cap, const char **auth_out, const char **cert_out);

/* 1 iff the first `<...status>` element at or after `p` reads 2xx — the propstat
 * verdict that says whether the property beside it is really there. */
int sd_http_xattr_status_ok(const char *p, const char *end);

/* The one property read, shared with the writer because XATTR_CREATE/REPLACE and
 * the POSIX "removing an absent attribute is ENODATA" rule are both decided by a
 * size enquiry (buf NULL, bufsz 0) before the PROPPATCH goes out. */
ssize_t sd_http_getxattr_common(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t bufsz, const brix_sd_cred_t *cred);

#endif /* BRIX_FS_BACKEND_HTTP_SD_HTTP_XATTR_INTERNAL_H */
