#ifndef BRIX_VOMS_IO_H
#define BRIX_VOMS_IO_H

/*
 * voms_io.h — the input and output bundles for VOMS attribute extraction.
 *
 * WHAT: brix_voms_in_t (the verified certificate chain to read) and
 *       brix_voms_out_t (the caller-owned buffers to fill).
 * WHY:  the stream (ngx_brix_module.h) and HTTP (voms_http.h) sides may not
 *       include each other's umbrella headers, yet both need these types; and
 *       bundling keeps brix_extract_voms_fqans() within the five-parameter
 *       limit as the output set grows.
 * HOW:  plain aggregates over <stddef.h> and OpenSSL's X509 types.  Every
 *       output buffer is optional: a NULL pointer or a zero size means "the
 *       caller does not want this view", and the producers skip it.
 *
 * The three output views are NOT interchangeable:
 *   primary_vo  the first VO name        — log/metric safe (brix_vo_token_is_safe)
 *   vo_list     every VO name, CSV       — log/metric safe, the `g` selector's list
 *   fqan_list   every raw FQAN, CSV      — 2.0 F20; the ONLY source from which
 *               brix_identity_derive_attrs can recover a VOMS role, and NEVER a
 *               log field or a metric label (it carries '/' and '='; INVARIANT 8).
 */

#include <stddef.h>
#include <openssl/x509.h>

typedef struct {
    X509            *leaf;    /* end-entity certificate of the proxy chain */
    STACK_OF(X509)  *chain;   /* the verified chain (may include leaf first) */
} brix_voms_in_t;

typedef struct {
    char   *primary_vo;
    size_t  primary_vo_sz;
    char   *vo_list;
    size_t  vo_list_sz;
    char   *fqan_list;
    size_t  fqan_list_sz;
} brix_voms_out_t;

#endif /* BRIX_VOMS_IO_H */
