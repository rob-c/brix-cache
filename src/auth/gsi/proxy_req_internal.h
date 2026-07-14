#pragma once

/* Internal defines and the one cross-file entry point shared by the
 * proxy_req split (proxy_req.c / proxy_req_sign.c / proxy_req_assemble.c).
 *
 * WHAT: Declares the RFC-3820 GSI OID / RSA-strength constants, the
 *   standalone-build compatibility shim + <core/compat/safe_size.h> include
 *   used by all three translation units, and the single function that crosses a
 *   TU boundary after the phase-79 file-size split: pxr_make_pci_ext(), which is
 *   DEFINED in proxy_req.c (alongside its static DER helpers) and CALLED from
 *   proxy_req_sign.c when it adds the proxy's critical proxyCertInfo extension.
 *
 * WHY: proxy_req.c exceeded the ~500-line file-size guard, so it was carved into
 *   three cohesive units — request build (proxy_req.c), issuance/signing
 *   (proxy_req_sign.c), and delegated-chain assembly (proxy_req_assemble.c).
 *   The OID constants are referenced by both build and sign; the proxyCertInfo
 *   builder is shared by both; and the assemble unit needs the overflow-checked
 *   size arithmetic from safe_size.h. Collecting the shared macros, the
 *   standalone shim, and the one crossing symbol here keeps every definition in
 *   exactly one place while preserving the original single-file crypto byte for
 *   byte (identical OIDs, identical proxyCertInfo encoding, identical guards).
 *
 * HOW: Requires proxy_req.h (the brix_gsi_* blob/buf/err types + public API)
 *   before inclusion. Two builds compile the proxy_req units without nginx
 *   headers — the standalone unit test (defines BRIX_SAFE_SIZE_STANDALONE) and
 *   the libxrdproto client core (built with XRDPROTO_NO_NGX) — so the ngx-free
 *   client build implies the standalone path, and the shim supplies the minimal
 *   ngx typedefs / allocation wrappers that safe_size.h's inline helpers need. */

#include "proxy_req.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>

/* Overflow-checked size arithmetic (wire-length guard in brix_gsi_assemble_proxy).
 * Two builds compile these files without nginx headers: the standalone unit test
 * (proxy_req_unittest.c, which defines BRIX_SAFE_SIZE_STANDALONE) and the
 * libxrdproto client core (built with XRDPROTO_NO_NGX). Both must make
 * safe_size.h skip its <ngx_config.h>/<ngx_core.h> includes AND supply the
 * minimal shims its inline helpers need — so the ngx-free client build implies
 * the standalone path. */
#if defined(XRDPROTO_NO_NGX) && !defined(BRIX_SAFE_SIZE_STANDALONE)
#  define BRIX_SAFE_SIZE_STANDALONE 1
#endif
#ifdef BRIX_SAFE_SIZE_STANDALONE
typedef long              ngx_int_t;
typedef struct ngx_pool_s ngx_pool_t;
typedef struct ngx_log_s  ngx_log_t;
#  define NGX_OK    0
#  define NGX_ERROR (-1)
#  define ngx_inline inline    /* safe_size.h writes "static ngx_inline"; not "static static" */
static inline void *ngx_palloc(ngx_pool_t *p, size_t n)  { (void)p; return malloc(n);    }
static inline void *ngx_pcalloc(ngx_pool_t *p, size_t n) { (void)p; return calloc(1, n); }
static inline void *ngx_alloc(size_t n, ngx_log_t *l)    { (void)l; return malloc(n);    }
#endif
#include "core/compat/safe_size.h"

#define GSI_PROXYCERTINFO_OID          "1.3.6.1.5.5.7.1.14"
#define GSI_PROXYCERTINFO_OLD_OID      "1.3.6.1.4.1.3536.1.222"
#define GSI_PROXYPOLICY_IMPERSONATION  "1.3.6.1.5.5.7.21.1"
#define GSI_KEY_USAGE_OID              "2.5.29.15"
#define GSI_SUBJ_ALT_NAME_OID          "2.5.29.17"
#define GSI_MIN_RSA_BITS               2048

/* Defined in proxy_req.c — build the critical proxyCertInfo X509_EXTENSION
 * (impersonation policy, path length = parent_pathlen decremented once and
 * floored at 0). Returns a fresh X509_EXTENSION (caller X509_EXTENSION_free) or
 * NULL on failure. Called across the split from proxy_req_sign.c. */
X509_EXTENSION *pxr_make_pci_ext(int parent_pathlen);
