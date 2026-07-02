/*
 * rate_limit.h — cross-worker token-bucket rate limiter over the KV store.
 *
 * State (token count + last-refill timestamp) lives per identity in a KV
 * zone, so the limit is enforced across all worker processes.  The check is
 * best-effort: get and set are two separate lock acquisitions, so a small
 * over-admission is possible under high concurrency — acceptable for request
 * throttling.
 *
 * key=dn   limits per authenticated DN (stream/GSI, post-auth)
 * key=ip   limits per client IP (used before identity is known, e.g. HTTP)
 */
#ifndef XROOTD_SHM_RATE_LIMIT_H
#define XROOTD_SHM_RATE_LIMIT_H

#include "kv.h"

/* Per-conf settings, filled by xrootd_rate_limit_directive(). */
typedef struct {
    xrootd_kv_t *kv;        /* NULL = disabled */
    ngx_uint_t   rate;      /* sustained requests per second */
    ngx_uint_t   burst;     /* bucket capacity */
    ngx_uint_t   key_ip;    /* 0 = key by DN, 1 = key by client IP */
} xrootd_rate_limit_conf_t;

/*
 * xrootd_rate_limit_check() — token-bucket admission test for identity
 * bytes id[0..id_len).  Returns NGX_OK to admit, NGX_DECLINED when the bucket
 * is empty.  A NULL/disabled rl always admits (NGX_OK).
 */
ngx_int_t xrootd_rate_limit_check(const xrootd_rate_limit_conf_t *rl,
    const char *id, size_t id_len);

/*
 * xrootd_rate_limit_directive() — setter for
 *   xrootd_rate_limit zone=<name> rate=<N>r/s burst=<N> [key=dn|ip];
 * Writes the xrootd_rate_limit_conf_t at cmd->offset.
 */
char *xrootd_rate_limit_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

#endif /* XROOTD_SHM_RATE_LIMIT_H */
