#ifndef BRIX_MIRROR_COMMON_H
#define BRIX_MIRROR_COMMON_H

/*
 * mirror_common.h — the two things every pull-through mirror plane shares.
 *
 * WHAT: (1) brix_http_mirror_key_path(): compose the on-disk path of a
 *       canonical cache key under an export root. (2)
 *       brix_http_mirror_postconf(): the post-config step an HTTP-ONLY node
 *       needs — ensure the SHM zones and the dashboard a stream{} block would
 *       otherwise have created, then resolve each server's fill thread pool.
 *
 * WHY:  A mirror is a pure cache node: it has no local export tree, so its
 *       root anchors at "/" and the cache key IS the path. That "the root
 *       contributes nothing" case is easy to get subtly wrong (a leading
 *       double slash, or a cap check that forgets the NUL), and it was written
 *       twice already. The post-config half is worse: a mirror deployment
 *       typically has no stream{} block at all, so the metrics zone and the
 *       dashboard are created here or nowhere — a plane that forgets loses its
 *       observability silently, at runtime, on a node nobody is watching.
 *
 * HOW:  The postconf helper walks cf's servers, asks the caller's predicate
 *       whether this location's conf actually enables the plane, and resolves
 *       `thread_pool` (or "default") into common->thread_pool, logging a NOTICE
 *       — not an error — when it is absent: a mirror without a pool still
 *       serves, it just fills on the loop. It reaches the shared conf by
 *       casting the module's loc_conf, which is sound because every brix HTTP
 *       protocol declares ngx_http_brix_shared_conf_t as its FIRST member (the
 *       "MUST stay first" comment in each protocol's header).
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "core/config/shared_conf.h"

/* Compose <root><key> into `path`. A root of "/" is the pure-cache-node anchor
 * and contributes nothing, so the path IS the key. Returns NGX_OK, or
 * NGX_HTTP_REQUEST_URI_TOO_LARGE when the result would not fit `path_size`
 * (including its NUL). */
ngx_int_t brix_http_mirror_key_path(const char *root, const char *key,
    size_t key_len, char *path, size_t path_size);

/* 1 iff this location's conf turns the plane on — the one question that
 * differs between planes (a mirror flag, a mirror-or-registry pair). */
typedef ngx_flag_t (*brix_http_mirror_active_pt)(void *loc_conf);

/* Ensure the HTTP-only node's SHM zones and dashboard, then resolve the fill
 * thread pool of every server whose `ctx_index` location conf is `active`.
 * `directive` names the plane in the NOTICE ("brix_oci"). */
ngx_int_t brix_http_mirror_postconf(ngx_conf_t *cf, ngx_uint_t ctx_index,
    brix_http_mirror_active_pt active, const char *directive);

#endif /* BRIX_MIRROR_COMMON_H */
