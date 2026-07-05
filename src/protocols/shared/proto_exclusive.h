#ifndef BRIX_PROTO_EXCLUSIVE_H
#define BRIX_PROTO_EXCLUSIVE_H

/*
 * proto_exclusive.h - config-load guard "one brix protocol per location, per port".
 *
 * WHAT: A single config-time check, brix_http_proto_exclusive_check(), that
 *       rejects a configuration enabling more than one brix HTTP protocol
 *       (brix_webdav, brix_s3, brix_cvmfs) in the same location, or mixing two
 *       different brix protocols under one listen port.
 *
 * WHY:  The unified per-location storage directives (brix_export,
 *       brix_cache_store, ...) belong to exactly one owning protocol; allowing
 *       two protocols to claim the same location makes their meaning
 *       ambiguous. One-protocol-per-port is the intended deployment model, so a
 *       mismatch is a configuration error caught at load time, not at runtime.
 *
 * HOW:  Called at the end of the WebDAV postconfiguration (which nginx runs
 *       after ALL module merges, so every enable flag is final). Returns NGX_OK
 *       when the configuration is consistent, or logs an EMERG diagnostic and
 *       returns NGX_ERROR to fail `nginx -t`.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t brix_http_proto_exclusive_check(ngx_conf_t *cf);

#endif /* BRIX_PROTO_EXCLUSIVE_H */
