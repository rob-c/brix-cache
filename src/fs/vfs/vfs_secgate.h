/*
 * vfs_secgate.h — generic per-capability TLS gating (the VFS security gate).
 *
 * WHAT: The capability mask (BRIX_TLSREQ_LOGIN/SESSION/DATA/TPC), the pure
 *       parser for the `brix_tls_require` directive grammar
 *       (`none | [all|login|session|data|tpc]... [-cap]...`), the pure
 *       gate check brix_tls_gate_refused(), the cap-name helper for error
 *       messages, and the shared offset-based conf setter used by both the
 *       stream (root://) and HTTP (WebDAV/S3/cvmfs) directive tables.
 *
 * WHY:  Stock XRootD gates TLS per capability (`xrootd.tls login/session/
 *       data/tpc` with `-cap` exceptions); BriX only had the coarse
 *       brix_min_sec_level floor. Implementing the mask + grammar + check
 *       once at the VFS layer means every plane (stream opcodes, WebDAV
 *       methods, S3 requests, native + WebDAV TPC) enforces identical policy
 *       from one `common.tls_require` field instead of four re-implementations.
 *
 * HOW:  Parser and check are side-effect-free (testable without a server):
 *       tokens are folded left-to-right into a 4-bit mask; `all` sets every
 *       bit, `-cap` clears one, `none` must stand alone. The gate returns the
 *       set of REQUIRED-but-unmet bits (0 = allowed) so callers can name the
 *       refused capability in kXR_TLSRequired / 403 messages. The conf setter
 *       writes the parsed mask through cmd->offset, so one function serves
 *       ngx_http_brix_common_conf_t and ngx_stream_brix_srv_conf_t alike.
 */
#ifndef BRIX_VFS_SECGATE_H
#define BRIX_VFS_SECGATE_H

#include <ngx_config.h>
#include <ngx_core.h>

/* Capability bits of the tls_require mask (subset of stock xrootd.tls caps
 * that map onto BriX surfaces; gpf/gpfa are N/A — no xrdcp --server mode). */
#define BRIX_TLSREQ_LOGIN    0x1u   /* login / auth exchanges                */
#define BRIX_TLSREQ_SESSION  0x2u   /* whole post-login session (all ops)    */
#define BRIX_TLSREQ_DATA     0x4u   /* data-bearing ops (read/write family)  */
#define BRIX_TLSREQ_TPC      0x8u   /* third-party-copy orchestration        */
#define BRIX_TLSREQ_ALL      0xfu

ngx_int_t   brix_tls_require_parse(ngx_str_t *args, ngx_uint_t nargs,
                                   ngx_uint_t *mask_out);
ngx_uint_t  brix_tls_gate_refused(ngx_uint_t mask, ngx_uint_t caps,
                                  ngx_uint_t is_tls);
const char *brix_tls_cap_name(ngx_uint_t bit);
char       *brix_conf_set_tls_require(ngx_conf_t *cf, ngx_command_t *cmd,
                                      void *conf);

#endif /* BRIX_VFS_SECGATE_H */
