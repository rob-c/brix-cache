/*
 * Copyright (C) 2025-2026  HEP-x Contributors
 *
 * tpc_cred.h — HTTP-TPC credential delegation declarations
 *
 * Provides OAuth2/OIDC access-token acquisition for third-party copy
 * pull transfers.  Two delegation modes are supported:
 *
 *   1. oidc-agent   — UNIX-socket JSON IPC to a local oidc-agent daemon
 *   2. token-exchange — RFC 8693 token-exchange request to an external
 *                       OAuth2 token endpoint
 *
 * The caller (tpc.c) invokes webdav_tpc_cred_obtain_token() after parsing
 * the Credential: header from the COPY request.  On success the returned
 * ngx_str_t contains a raw Bearer token that the caller injects into the
 * transfer_headers array before launching the curl subprocess.
 */

#ifndef _TPC_CRED_H
#define _TPC_CRED_H 1

#include <ngx_core.h>
#include <ngx_http.h>

/* ------------------------------------------------------------------ */
/*  Credential-delegation mode                                        */
/* ------------------------------------------------------------------ */

typedef enum {
    XROOTD_TPC_CRED_NONE = 0,     /* Credential: none  (default) */
    XROOTD_TPC_CRED_OIDC_AGENT,   /* Credential: oidc-agent */
    XROOTD_TPC_CRED_TOKEN_EXCHANGE, /* Credential: token-exchange */
    XROOTD_TPC_CRED_UNKNOWN       /* Unrecognised value */
} xrootd_tpc_cred_mode_e;

/* ------------------------------------------------------------------ */
/*  Metrics counters (see metrics/webdav.c)                           */
/* ------------------------------------------------------------------ */

typedef enum {
    XROOTD_TPC_CRED_NSTARTED = 0,
    XROOTD_TPC_CRED_NSUCCESS,
    XROOTD_TPC_CRED_NERROR,
    XROOTD_TPC_CRED_NUNKNOWN_MODE,
    XROOTD_TPC_CRED_NPARSE_ERROR,
    XROOTD_TPC_CRED_NMAX
} xrootd_tpc_cred_metrics_e;

/* ------------------------------------------------------------------ */
/*  Public API                                                        */
/* ------------------------------------------------------------------ */

/**
 * Parse a Credential: header value into a mode enum.
 *
 * Returns XROOTD_TPC_CRED_UNKNOWN for unrecognised values.
 */
xrootd_tpc_cred_mode_e
webdav_tpc_cred_parse_mode(const char *value, size_t len);

/**
 * Obtain an access token for a TPC pull transfer.
 *
 * @param r            the current ngx_http_request_t
 * @param mode         parsed credential-delegation mode
 * @param source_url   the Source: URL (used as issuer/audience)
 * @param subject_token  the authenticated session token (JWT), may be NULL
 *                       for oidc-agent mode; required for token-exchange
 * @param scope        scope string to request (e.g. "storage.read")
 * @param token_out   [out] allocated in r->pool; caller must not free
 *
 * @return NGX_OK on success; NGX_ERROR on failure (error already logged)
 */
ngx_int_t
webdav_tpc_cred_obtain_token(ngx_http_request_t *r,
                             xrootd_tpc_cred_mode_e mode,
                             const char *source_url,
                             const char *subject_token,
                             const char *scope,
                             ngx_str_t *token_out);

/**
 * Return the name string for a cred-metrics counter index.
 */
const char *
webdav_tpc_cred_metric_name(xrootd_tpc_cred_metrics_e idx);

/**
 * Increment a TPC credential metrics counter in shared memory.
 */
ngx_int_t
webdav_tpc_cred_metric_increment(ngx_http_request_t *r,
                                 xrootd_tpc_cred_metrics_e idx);

#endif /* _TPC_CRED_H */
