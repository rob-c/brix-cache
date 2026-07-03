/*
 * brix.h — internal API for the native XRootD root:// client library.
 *
 * WHAT: Connection/session + metadata/file ops over the XRootD binary protocol,
 *       built directly on the project's wire vocabulary (the src/protocols/root/protocol headers,
 *       shared via libxrdproto). This is the spine that xrdcp/xrdfs sit on.
 * WHY:  A pure-C, libXrdCl-free client (phase-37). Blocking sockets + poll(2)
 *       timeouts; one in-flight request per connection for now (the streamid
 *       counter is the seed for future parallel streams).
 * HOW:  Each request builds its packed ClientXxxRequest struct from wire.h, sets
 *       big-endian fields, and exchanges frames via frame.c. No ngx, no XrdCl.
 *
 * Clean-room: wire facts come only from the src/protocols/root/protocol headers (cross-checked
 * against XProtocol.hh). See docs/refactor/phase-37-clean-room-log.md.
 */
#ifndef XRDC_H
#define XRDC_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>               /* FILE* for the explain/trace sinks */
#include <time.h>                /* struct timespec for brix_setattr */
#include <sys/types.h>

#include "protocols/root/protocol/protocol.h"   /* wire structs + kXR_* constants (-I src) */
#include "protocols/root/protocol/codec/wire_codec.h" /* shared per-opcode wire-body codec */

/* Public-API fixed sizes. Kept under their stable libbrix-public XRDC_* names, but
 * the VALUE is now single-sourced from the shared wire header (protocol/opcodes.h
 * via protocol/protocol.h above) rather than re-spelled as 4 / 16 here. */
#ifndef XRDC_FHANDLE_LEN
#define XRDC_FHANDLE_LEN XRD_FHANDLE_LEN
#endif
#ifndef XRDC_SESSION_ID_LEN
#define XRDC_SESSION_ID_LEN BRIX_SESSION_ID_LEN
#endif

/* kXR_ExpLogin (ClientProtocolRequest.expect) and kXR_FinalResult/kXR_PartialResult
 * (ServerResponseBody_Status.resptype) are real #defines in the shared
 * protocol/flags.h — reached via protocol/protocol.h above. No local copy. */

#define XRDC_MSG_MAX   512
#define XRDC_PATH_MAX  2048
#define XRDC_DLEN_MAX  (64u * 1024u * 1024u)   /* sanity cap on a response body */
#define XRDC_NAME_MAX  256

/* Last-error carrier (the essentials of XrdCl::XRootDStatus). */
typedef struct {
    int  kxr;        /* kXR_* server error code; 0 = none; <0 = local/socket */
    int  sys_errno;  /* local errno when the failure was a syscall */
    char msg[XRDC_MSG_MAX];
} brix_status;

/* Local error sentinels (negative so they never collide with kXR_* codes). */
#define XRDC_ESOCK   (-1)   /* connect/socket/timeout failure */
#define XRDC_EPROTO  (-2)   /* malformed/unexpected server frame */
#define XRDC_EUSAGE  (-3)   /* CLI / argument error */
#define XRDC_EAUTH   (-4)   /* server demanded auth we don't (yet) speak */
#define XRDC_EINTEGRITY (-5)/* data corruption (CRC/checksum mismatch) — NOT
                             * retryable: a re-read yields the same bad bytes, so
                             * the resilient loop MUST fail fast, not spin. */
#define XRDC_EUNSUPPORTED (-6) /* valid protocol feature this client build lacks;
                                * fatal, because reconnecting cannot add support. */
#define XRDC_ERESOLVE (-7)  /* permanent name-resolution failure (NXDOMAIN / no
                             * address) — NOT retryable: the name will not
                             * resolve on a retry, so the resilient loop must
                             * fail fast instead of burning its stall window.
                             * A *transient* resolver failure (EAI_AGAIN) keeps
                             * XRDC_ESOCK so it is still retried. */
#define XRDC_EREDIRECT (-8) /* redirect loop / budget exhausted (self-redirect,
                             * bounce to an already-tried target, too many hops)
                             * — NOT retryable: re-issuing the op just walks into
                             * the same loop, so the resilient wrapper must fail
                             * fast rather than chase it for the whole window. */
#define XRDC_EIO     (-9)   /* local filesystem I/O error (open/read/write/rename/fstat/truncate/alloc) — permanent, NOT retryable */
#define XRDC_ENOENT  (-10)  /* object/path does not exist (HTTP 404 / ENOENT) — permanent, NOT retryable */

typedef enum {
    XRDC_SCHEME_ROOT = 0,   /* root:// / xroot:// */
    XRDC_SCHEME_ROOTS,      /* roots:// / xroots:// (TLS) — declined this pass */
    XRDC_SCHEME_LOCAL,      /* file:// or a bare local path */
    XRDC_SCHEME_STDIO       /* "-" */
} brix_scheme;

typedef struct {
    brix_scheme scheme;
    char        host[256];
    int         port;
    char        user[64];
    char        path[XRDC_PATH_MAX];   /* absolute for root://, local path otherwise */
} brix_url;

/* Web endpoints carried over HTTP (WebDAV + S3) — the non-root transfer surface.
 * davs/s3 are HTTP under the hood; xrdcp uses these for production GET/PUT. */
typedef enum {
    XRDC_WEB_HTTP = 0,   /* http://  */
    XRDC_WEB_HTTPS,      /* https:// */
    XRDC_WEB_DAV,        /* dav://   (cleartext WebDAV) */
    XRDC_WEB_DAVS,       /* davs://  (TLS WebDAV) */
    XRDC_WEB_S3,         /* s3://    (cleartext S3 REST) */
    XRDC_WEB_S3S         /* s3s://   (TLS S3 REST) */
} brix_web_proto;
typedef struct {
    brix_web_proto proto;
    int            tls;                /* 1 if the scheme implies TLS */
    int            is_s3;             /* 1 for s3/s3s (SigV4); 0 for http/dav family */
    char           host[256];
    int            port;
    char           path[XRDC_PATH_MAX];
} brix_weburl;
/* Return 1 if `s` begins with a web scheme (http/https/dav/davs/s3/s3s). */
int brix_is_web_url(const char *s);
/* Return 1 if `s` names a block-device endpoint (block:// prefix or /dev/). */
int brix_is_block_url(const char *s);
/* Parse a web URL into *out. 0 on success, -1 if not a recognized web URL. */
int brix_weburl_parse(const char *s, brix_weburl *out);


/* Phase-38: decl groups live in concern sub-headers, included here so every
 * `#include "brix.h"` still sees the whole API (umbrella). */
#include "brix_net.h"
#include "brix_auth.h"
#include "brix_ops.h"

#endif /* XRDC_H */
