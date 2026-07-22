#ifndef BRIX_POSTCONFIGURATION_INTERNAL_H
#define BRIX_POSTCONFIGURATION_INTERNAL_H
/*
 * postconfiguration_internal.h — cross-file entry points for the stream-module
 * postconfiguration hook, split (file-size cap) out of the former
 * postconfiguration.c.
 *
 * WHAT: Declares the one symbol that crosses the postconfiguration.c /
 *       postconfiguration_proxy_acl.c file boundary — the E-2 proxy_protocol +
 *       host-allow ACL guard invoked once, fail-closed, by
 *       ngx_stream_brix_postconfiguration before any runtime object is built.
 *       Every other postconf helper stays file-local (static) in
 *       postconfiguration.c.
 * WHY:  The proxy_protocol host-ACL guard is a large, wholly self-contained
 *       concern with two nginx-version-gated variants (#if nginx_version); it
 *       lives in its own sibling so postconfiguration.c stays under the file
 *       cap while preserving the exact frozen validation order.
 * HOW:  Requires "config.h" (for ngx_conf_t / ngx_int_t /
 *       ngx_stream_core_main_conf_t and the brix module/type definitions)
 *       before inclusion. The guard itself lives in
 *       postconfiguration_proxy_acl.c; the orchestrator
 *       (ngx_stream_brix_postconfiguration) stays in postconfiguration.c.
 */

/*
 * E-2 (CWE-290): reject brix_host_allow layered over a proxy_protocol listener.
 * Defined in postconfiguration_proxy_acl.c, called once by the postconfiguration
 * hook. Returns NGX_OK, or NGX_ERROR to fail nginx -t.
 */
ngx_int_t postconf_proxy_protocol_host_acl(ngx_conf_t *cf,
    ngx_stream_core_main_conf_t *cmcf);

#endif /* BRIX_POSTCONFIGURATION_INTERNAL_H */
