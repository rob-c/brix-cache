#pragma once

/*
 * Compile-time size limits, auth-mode constants, and per-operation metric macros.
 *
 * Included by ngx_xrootd_module.h after the nginx, OpenSSL, protocol, and
 * metrics headers have been pulled in.  Do not include this file directly
 * unless those headers precede it.
 */

/*
 * Read sizing.
 *
 * XROOTD_READ_MAX is the per-vector element cap used when normalising
 * client readv requests.  Large contiguous reads may still return up to
 * XROOTD_READ_REQUEST_MAX, but the response is split into larger 16 MiB
 * wire chunks so cleartext sendfile responses need fewer header/file
 * boundaries and therefore fewer writev/sendfile calls.
 */
#define XROOTD_READ_MAX          (4 * 1024 * 1024)
#define XROOTD_READ_CHUNK_MAX    (16 * 1024 * 1024)
#define XROOTD_READ_REQUEST_MAX  (64 * 1024 * 1024)

/* Maximum simultaneously open files per connection. */
#define XROOTD_MAX_FILES     16

/* Maximum path length accepted from a client. */
#define XROOTD_MAX_PATH      4096

/*
 * Maximum write payload per request.  xrdcp v5 uses 8 MiB chunks by default;
 * each pgwrite payload adds 4-byte CRC per 4096-byte page (~0.1% overhead).
 * Cap at 16 MiB to handle non-default chunk sizes with headroom.
 */
#define XROOTD_MAX_WRITE_PAYLOAD  (16 * 1024 * 1024)

/*
 * Maximum kXR_prepare payload.  XrdCl sends a newline-separated list of paths;
 * allow a moderately sized batch without growing the payload receive buffer.
 */
#define XROOTD_MAX_PREPARE_PAYLOAD  (64 * 1024)

/*
 * Maximum kXR_auth payload.  GSI certificate chains with VOMS attribute
 * certificates can reach 8–10 KB depending on the CA chain depth.
 */
#define XROOTD_MAX_AUTH_PAYLOAD   (32 * 1024)

/* TCP receive buffer — sized to hold the largest expected request. */
#define XROOTD_RECV_BUF      (XROOTD_MAX_PATH + XRD_REQUEST_HDR_LEN + 64)

/*
 * Maximum immediate send_chain continuations before yielding through nginx's
 * posted-event queue.  Keeps large sendfile responses moving without
 * starving other ready connections.
 */
#define XROOTD_SEND_CHAIN_SPIN_MAX  16

/* ---- Authentication mode constants ---- */
#define XROOTD_AUTH_NONE   0   /* no authentication required (anonymous) */
#define XROOTD_AUTH_GSI    1   /* GSI/x509 authentication required       */
#define XROOTD_AUTH_TOKEN  2   /* Bearer token (JWT/WLCG) authentication */
#define XROOTD_AUTH_BOTH   3   /* Accept either GSI or token auth        */
#define XROOTD_AUTH_SSS    4   /* XRootD Simple Shared Secret auth       */

/* ---- SSS constants ---- */
#define XROOTD_SSS_KEY_MAX   128
#define XROOTD_SSS_NAME_MAX  192
#define XROOTD_SSS_USER_MAX  128
#define XROOTD_SSS_GROUP_MAX 64

#define XROOTD_SSS_OPT_ALLUSR  0x01
#define XROOTD_SSS_OPT_ANYUSR  0x02
#define XROOTD_SSS_OPT_ANYGRP  0x04
#define XROOTD_SSS_OPT_USRGRP  0x08
#define XROOTD_SSS_OPT_NOIPCK  0x10

/* Increment a per-operation metric counter.  No-op when metrics are disabled. */
#define XROOTD_OP_OK(ctx, op)  \
    do { if ((ctx)->metrics) { \
        ngx_atomic_fetch_add(&(ctx)->metrics->op_ok[(op)], 1); \
    } } while (0)

#define XROOTD_OP_ERR(ctx, op) \
    do { if ((ctx)->metrics) { \
        ngx_atomic_fetch_add(&(ctx)->metrics->op_err[(op)], 1); \
    } } while (0)

/*
 * Collapse the common three-line pattern into a single macro call.
 * Use only when xrootd_send_ok sends no body (NULL, 0).
 * Handlers that return a body (read data, pgwrite status, query results)
 * must keep the three lines explicit.
 */
#define XROOTD_RETURN_OK(ctx, c, op, verb, path, detail, bytes)         \
    do {                                                                  \
        xrootd_log_access((ctx), (c), (verb), (path), (detail),         \
                          1, kXR_ok, NULL, (bytes));                     \
        XROOTD_OP_OK((ctx), (op));                                       \
        return xrootd_send_ok((ctx), (c), NULL, 0);                      \
    } while (0)

#define XROOTD_RETURN_ERR(ctx, c, op, verb, path, detail, code, msg)    \
    do {                                                                  \
        xrootd_log_access((ctx), (c), (verb), (path), (detail),         \
                          0, (code), (msg), 0);                          \
        XROOTD_OP_ERR((ctx), (op));                                      \
        return xrootd_send_error((ctx), (c), (code), (msg));             \
    } while (0)
