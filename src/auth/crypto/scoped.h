/*
 * scoped.h — Phase 27 W3: NULL-safe destroyers for external handles.
 *
 * WHAT: A small vocabulary of NULL-safe destroyers for OpenSSL handles (and a
 * jansson refcount helper) so that long, branchy error paths driven by
 * attacker-controlled input free *every* handle on *every* exit path without
 * relying on a reviewer to spot a missed `*_free`.
 *
 * WHY: The TPC/GSI exchange and the EVP-using files build several handles over
 * remote-controlled buckets.  A single malformed bucket that takes an early
 * exit before some `*_free` leaks an OpenSSL handle (and its heap) on every
 * failed handshake — a slow OOM an external origin can drive.  The structural
 * fix (per docs/09-developer-guide/coding-standards.md §4, which forbids goto)
 * is to confine the build to a worker that uses flat early returns and let the
 * wrapper own one cleanup site that frees every handle unconditionally.  NULL-
 * safe destroyers make that one cleanup a flat, reviewable list.
 *
 * THE PATTERN (goto-free; see also CODE STYLE):
 *
 *     static ngx_int_t build_inner(..., EVP_PKEY **pk_out, BIO **bio_out)
 *     {
 *         *pk_out  = ...; if (*pk_out  == NULL) return NGX_ERROR;
 *         *bio_out = ...; if (*bio_out == NULL) return NGX_ERROR;
 *         ... work ...
 *         return NGX_OK;
 *     }
 *
 *     ngx_int_t build(...)
 *     {
 *         EVP_PKEY  *pk  = NULL;
 *         BIO       *bio = NULL;
 *         ngx_int_t  rc  = build_inner(..., &pk, &bio);
 *
 *         xrootd_evp_pkey_free(pk);   // wrapper owns the single cleanup site;
 *         xrootd_bio_free(bio);       // every destroyer tolerates NULL
 *         return rc;
 *     }
 *
 * Every destroyer below tolerates NULL (OpenSSL's own *_free already do, but a
 * uniform set keeps the cleanup list flat and usable as cleanup callbacks).
 *
 * ---------------------------------------------------------------------------
 * JANSSON OWNERSHIP CHEATSHEET (W3) — leaks and double-decrefs come from
 * confusing borrowed vs owned references.
 *
 *   OWNED (you must json_decref, unless you hand it to a stealing setter):
 *     json_object(), json_array(), json_string(), json_integer(), json_true(),
 *     json_loads()/json_loadb(), json_pack(), json_deep_copy(), json_incref().
 *   BORROWED (do NOT decref; valid only while the parent is alive):
 *     json_object_get(), json_array_get(), json_object_iter_value().
 *   STEALING (takes ownership of the value — do NOT decref it afterwards;
 *   still decref the CONTAINER once):
 *     json_object_set_new(), json_array_append_new(), json_array_insert_new().
 *   NON-STEALING (incref the value — you still own your reference):
 *     json_object_set(), json_array_append().
 *
 * Rule of thumb: if the name ends in `_new`, the call consumed your reference.
 * Build with `*_set_new`/`*_append_new` + a single decref of the root.
 * ---------------------------------------------------------------------------
 */
#ifndef XROOTD_CRYPTO_SCOPED_H
#define XROOTD_CRYPTO_SCOPED_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

/* Free an EVP_PKEY (NULL-safe, no-op on NULL). Caller's pointer is not nulled;
 * the slot stays dangling, so use only at a one-shot cleanup label. */
static ngx_inline void xrootd_evp_pkey_free(EVP_PKEY *p)
{ if (p) { EVP_PKEY_free(p); } }

/* Free an EVP_PKEY_CTX (keygen/derive/sign context); NULL-safe. */
static ngx_inline void xrootd_evp_pkey_ctx_free(EVP_PKEY_CTX *p)
{ if (p) { EVP_PKEY_CTX_free(p); } }

/* Free an EVP_MD_CTX (digest/sign-verify context); NULL-safe. */
static ngx_inline void xrootd_evp_md_ctx_free(EVP_MD_CTX *p)
{ if (p) { EVP_MD_CTX_free(p); } }

/* Free an EVP_CIPHER_CTX (symmetric cipher context); NULL-safe. */
static ngx_inline void xrootd_evp_cipher_ctx_free(EVP_CIPHER_CTX *p)
{ if (p) { EVP_CIPHER_CTX_free(p); } }

/* Free a BIO; NULL-safe. Uses BIO_free_all, so it frees the WHOLE BIO chain,
 * not just the head — never call on a BIO still linked to one you reuse. */
static ngx_inline void xrootd_bio_free(BIO *p)
{ if (p) { BIO_free_all(p); } }

/* Free an X509 certificate (decrements its refcount); NULL-safe. */
static ngx_inline void xrootd_x509_free(X509 *p)
{ if (p) { X509_free(p); } }

/* Free an X509_STORE (trust store); NULL-safe. Drops the store's refcount and
 * frees contained certs/CRLs when it reaches zero. */
static ngx_inline void xrootd_x509_store_free(X509_STORE *p)
{ if (p) { X509_STORE_free(p); } }

/* Free an X509_STORE_CTX (single verification operation); NULL-safe. */
static ngx_inline void xrootd_x509_store_ctx_free(X509_STORE_CTX *p)
{ if (p) { X509_STORE_CTX_free(p); } }

/* Free a BIGNUM; NULL-safe. Does NOT scrub memory — use the _clear_ variant
 * below for any value derived from secret/key material. */
static ngx_inline void xrootd_bn_free(BIGNUM *p)
{ if (p) { BN_free(p); } }

/* Free a BIGNUM, zeroing its memory before release (BN_clear_free); NULL-safe.
 * Use this for private keys, shared secrets, and other sensitive scalars. */
static ngx_inline void xrootd_bn_clear_free(BIGNUM *p)
{ if (p) { BN_clear_free(p); } }   /* for secret material */

/* Free a STACK_OF(X509) AND every X509 it holds (sk_X509_pop_free); NULL-safe.
 * Do not use on a borrowed stack whose certs you still reference elsewhere. */
static ngx_inline void xrootd_x509_stack_free(STACK_OF(X509) *p)
{ if (p) { sk_X509_pop_free(p, X509_free); } }

/* Free a buffer obtained from OPENSSL_malloc / an OpenSSL out-param (e.g.
 * i2d_*, PEM read into a malloc'd char*); NULL-safe. Must NOT be used on
 * ngx_palloc'd or libc malloc'd memory. */
static ngx_inline void xrootd_openssl_free(void *p)
{ if (p) { OPENSSL_free(p); } }

#endif /* XROOTD_CRYPTO_SCOPED_H */
