/*
 * sts.h — AWS STS (Security Token Service) client for backend credential
 *         EXCHANGE (phase-70 §5.5).
 *
 * WHAT: issue an AssumeRole call (falling back to GetSessionToken when no role
 *       ARN is configured) against a backend STS endpoint and return the
 *       resulting short-lived (AccessKeyId, SecretAccessKey, SessionToken).
 * WHY:  an S3 SigV4 secret is never transmitted, so the inbound access-key id
 *       alone cannot be forwarded to the origin. Instead the node holds a
 *       long-lived backend S3 *service* credential and exchanges it — scoped to
 *       the inbound principal via RoleSessionName — for temporary credentials
 *       the origin trusts. Pure passthrough is impossible by design.
 * HOW:  build the AssumeRole GET query, SigV4-sign it with the node's service
 *       credentials over the "sts" service, POST/GET via libcurl, and parse the
 *       XML (libxml2) or JSON response into pool-copied out params. The service
 *       secret and the returned secret/session token are never logged.
 */
#ifndef BRIX_AUTH_S3_STS_H
#define BRIX_AUTH_S3_STS_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "core/types/identity.h"

/*
 * Static, load-time-validated configuration for one STS exchange target.
 *   endpoint  — STS base URL, e.g. "https://minio.example:9000"
 *   region    — SigV4 region for the "sts" service, e.g. "us-east-1"
 *   role_arn  — role to AssumeRole into; empty selects GetSessionToken
 *   svc_ak    — backend S3 *service* access-key id (signs the STS request)
 *   svc_sk    — backend S3 service secret access key (never logged)
 *   ttl_secs  — requested credential lifetime in seconds (clamped 900..43200)
 */
typedef struct {
    ngx_str_t endpoint;
    ngx_str_t region;
    ngx_str_t role_arn;
    ngx_str_t svc_ak;
    ngx_str_t svc_sk;
    int       ttl_secs;
} brix_s3_sts_conf_t;

/*
 * brix_s3_sts_out_t — the (ak, sk, session) output triple of an STS exchange,
 * bundled so callers hand one struct pointer instead of three loose out-params.
 *
 * WHAT: three borrowed ngx_str_t slots the exchange fills with the temporary
 *       credentials — AccessKeyId, SecretAccessKey and (optional) SessionToken.
 * WHY:  keeps brix_s3_sts_assume() within the ≤5-argument budget and gives the
 *       three logically-coupled outputs a single named home; the slots are the
 *       caller's own (borrowed, not owned by the STS layer).
 * HOW:  the caller declares three ngx_str_t, points the fields at them, and on
 *       NGX_OK reads back pool-allocated, NUL-terminated copies (session may be
 *       empty when the response omits a SessionToken).
 */
typedef struct {
    ngx_str_t *ak;
    ngx_str_t *sk;
    ngx_str_t *session;
} brix_s3_sts_out_t;

/*
 * Exchange the node's service credential for temporary credentials scoped to
 * the inbound identity. `id->subject`/`id->dn` map to RoleSessionName so the
 * origin audit log attributes actions to the real principal.
 *
 * On NGX_OK, out->ak, out->sk and out->session are set to pool-allocated,
 * NUL-terminated copies of the returned credentials (session may be empty if
 * the response omits it).
 * On NGX_ERROR the out params are untouched and a reason is logged (never the
 * secret or session token).
 */
ngx_int_t brix_s3_sts_assume(ngx_pool_t *pool, const brix_identity_t *id,
    const brix_s3_sts_conf_t *cf, const brix_s3_sts_out_t *out, ngx_log_t *log);

#endif /* BRIX_AUTH_S3_STS_H */
