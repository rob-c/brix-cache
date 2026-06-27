/*
 * gsi_core_internal.h - private split contract for gsi_core.c and its Phase-38 siblings.
 * Not a public API: include only from src/gsi/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef XROOTD_GSI_CORE_INTERNAL_H
#define XROOTD_GSI_CORE_INTERNAL_H

#include "gsi_core.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/dh.h>          
#include <openssl/rand.h>        
#include <openssl/pem.h>         
#include <openssl/x509.h>        
#include <openssl/evp.h>         
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>    
#endif
#include <openssl/rsa.h>         
#include "../protocol/gsi.h"      
#include "../protocol/opcodes.h"  
#include "../compat/crypto.h"     

extern const char xrootd_gsi_dh_params_pem[];
extern const char *const gsi_cipher_allow[];
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#endif
typedef struct {
    EVP_PKEY    *mine;          /* our session DH keypair                   */
    EVP_PKEY    *peer;          /* server session DH public                 */
    EVP_PKEY    *servpub;       /* server cert public key (verify signed DH)*/
    uint8_t     *peerblob;      /* recovered server Public() blob (signed)  */
    uint8_t     *signed_rtag;   /* server rtag signed with the proxy key    */
    size_t       signed_rtag_len;
    char        *cpub;          /* our DH public, Public() wire blob        */
    uint8_t     *signed_cpub;   /* our cpub signed with the proxy key       */
    size_t       signed_cpub_len;
    char        *pubpem;        /* proxy public key PEM (signed path)       */
    uint8_t     *enc;           /* encrypted response main                  */
    xrootd_gbuf  inner;
    xrootd_gbuf  outer;
} gsi_cresp_ctx;


/* gsi_dh.c */
EVP_PKEY * gsi_fixed_dh_params(void);
EVP_PKEY * gsi_dh_keygen_with(EVP_PKEY *dhparams);

/* gsi_cipher.c */
void gsi_load_legacy_once(void);

/* gsi_core.c */
EVP_PKEY * gsi_cresp_cert_pubkey(const uint8_t *pem, size_t len);
char * gsi_cresp_export_pubkey_pem(EVP_PKEY *key, size_t *outlen);
size_t gsi_cresp_pick_md_alg(const uint8_t *sbody, uint32_t slen, char *out, size_t outcap);
int gsi_cresp_fail(gsi_cresp_ctx *x, char *err, size_t errcap, const char *msg);

#endif /* XROOTD_GSI_CORE_INTERNAL_H */
