#ifndef BRIX_SERVER_CONF_INTERNAL_H
#define BRIX_SERVER_CONF_INTERNAL_H
/*
 * server_conf_internal.h — cross-file entry points for the server-block merge,
 * split (phase-79 file-size cap) out of the former 1249-line server_conf.c.
 *
 * WHAT: Declares the five per-area merge entry points that the top-level
 *       ngx_stream_brix_merge_srv_conf() orchestrator (server_conf.c) invokes,
 *       each now defined in a focused sibling file. Their sub-helpers stay
 *       file-local (static) in the file that owns them; only these five cross
 *       the file boundary and are therefore non-static and declared here.
 * WHY:  server_conf.c owned create + merge + enable for every configuration
 *       area in one file, far over the 500-line cap. Splitting the merge areas
 *       into three files keeps each concern reviewable in isolation while
 *       preserving the exact linear invocation order the orchestrator relies on
 *       (cross-area derivations still observe their already-merged inputs).
 * HOW:  Requires "config.h" (for ngx_conf_t + ngx_stream_brix_srv_conf_t)
 *       before inclusion. The security/storage entries live in
 *       server_conf_merge_security.c, the tpc/cluster entries in
 *       server_conf_merge_cluster.c, and the proxy/network entry in
 *       server_conf_merge_proxy_net.c.
 */

/* Identity & crypto area: auth scheme + GSI/pwd, XrdAcc (+native-authdb
 * validation), SciTags/FRM, X.509 + CRL, access log, tokens + L1/L2 caches,
 * sss/krb5/unix/host, security level, TLS toggles. */
char *brix_merge_srv_security(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *conf, ngx_stream_brix_srv_conf_t *prev);

/* Storage area: read/write compression, ZIP access, the read-through cache
 * (origin, sizing, eviction, slice validation, include-regex inheritance),
 * memory budget, readv segment sizing, io_uring backend. */
char *brix_merge_srv_storage(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *conf, ngx_stream_brix_srv_conf_t *prev);

/* Third-party copy (TPC) area: local/private allowances, key TTL, transfer
 * caps + abandoned-slot reaper age, SSI/CNS, and the outbound credentials. */
void brix_merge_srv_tpc(ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev);

/* Cluster & sessions area: manager/redirector mode, write recovery + staged
 * uploads, pipeline/registry/session sizing, active health checks, the traffic
 * mirror, the CMS client, listen port, checksum-scan limits, and the
 * VO/group/manager-map rule arrays + redirector inheritance. */
char *brix_merge_srv_cluster(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *conf, ngx_stream_brix_srv_conf_t *prev);

/* Upstream/proxy & network area: upstream TLS + token, transparent proxy mode,
 * the write-through origin + prefix rules + decision struct, OCSP, the Phase-39
 * network-fault deadlines, and rate-limit rule inheritance. */
char *brix_merge_srv_proxy_net(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *conf, ngx_stream_brix_srv_conf_t *prev);

#endif /* BRIX_SERVER_CONF_INTERNAL_H */
