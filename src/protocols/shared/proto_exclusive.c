/*
 * proto_exclusive.c - enforce "one brix protocol per location, per port".
 *
 * WHAT: config-load validation that at most one brix protocol (webdav, s3,
 *       cvmfs) is enabled in any one location, and that all brix-enabled
 *       locations under a single listen port speak the same protocol.
 * WHY:  the unified storage directives (brix_cache_store, brix_export, ...)
 *       are per-location; a single owning protocol keeps their meaning
 *       unambiguous, and one-protocol-per-port is the deployment model.
 * HOW:  called from the WebDAV postconfiguration (which runs after ALL module
 *       merges AND after nginx has finalised each server's location structures,
 *       so every enable flag is final).  Walks cmcf->ports -> addrs -> servers;
 *       for each server it reads the server-level conf and then the finalised
 *       location structures (static_locations tree, regex_locations and
 *       named_locations), OR-ing each protocol's enable flag into a per-
 *       location, per-server and per-port mask.  More than one bit set at any
 *       level is a configuration error.  brix_scvmfs is a layer on cvmfs, not a
 *       second protocol; the stream-plane handoff mux is out of scope (stream,
 *       not http).
 *
 *       Note on structures: by postconfiguration time nginx has already run
 *       ngx_http_init_locations / ngx_http_init_static_location_trees, which
 *       split named + regex locations out of clcf->locations into separate
 *       arrays and reorganise the prefix locations into clcf->static_locations.
 *       Walking the raw clcf->locations queue is therefore unreliable; this
 *       walker reads the finalised structures instead.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "protocols/shared/proto_exclusive.h"
#include "protocols/webdav/webdav.h"
#include "protocols/s3/s3.h"
#include "protocols/cvmfs/cvmfs.h"

#define BRIX_PROTO_NONE    0u
#define BRIX_PROTO_WEBDAV  (1u << 0)
#define BRIX_PROTO_S3      (1u << 1)
#define BRIX_PROTO_CVMFS   (1u << 2)


/*
 * WHAT: Human-readable directive name for a single protocol bit.
 * WHY:  Error diagnostics name the offending protocols by their directive.
 * HOW:  Tests the bits in a fixed order; the caller passes a mask that has
 *       the wanted protocol bit set (extra bits are ignored).
 */
static const char *
brix_proto_name(ngx_uint_t bit)
{
    if (bit & BRIX_PROTO_WEBDAV) {
        return "brix_webdav";
    }
    if (bit & BRIX_PROTO_S3) {
        return "brix_s3";
    }
    return "brix_cvmfs";
}


/*
 * WHAT: The set of brix protocols this location's conf array enables.
 * WHY:  Each protocol keeps its enable flag in its own loc-conf; the walker
 *       needs one combined mask per location.
 * HOW:  Reads each module's loc-conf via its ctx_index and OR-s the bit for
 *       every protocol whose enable flag merged to on.
 */
static ngx_uint_t
brix_proto_mask(void **loc_conf)
{
    ngx_uint_t                       mask = BRIX_PROTO_NONE;
    ngx_http_brix_webdav_loc_conf_t *w;
    ngx_http_s3_loc_conf_t          *s;
    ngx_http_brix_cvmfs_loc_conf_t  *c;

    w = loc_conf[ngx_http_brix_webdav_module.ctx_index];
    s = loc_conf[ngx_http_brix_s3_module.ctx_index];
    c = loc_conf[ngx_http_brix_cvmfs_module.ctx_index];

    if (w != NULL && w->common.enable == 1) {
        mask |= BRIX_PROTO_WEBDAV;
    }
    if (s != NULL && s->common.enable == 1) {
        mask |= BRIX_PROTO_S3;
    }
    if (c != NULL && c->cvmfs.enable == 1) {
        mask |= BRIX_PROTO_CVMFS;
    }
    return mask;
}


/*
 * WHAT: Fold one conf level's protocol mask into *server_mask, rejecting a
 *       level that enables more than one protocol itself.
 * WHY:  Every individual location (and the server level) must own at most one
 *       protocol, and its bit must contribute to the per-port aggregate.
 * HOW:  Computes the level's mask; a mask with more than one bit set is a
 *       per-location error naming the level.  Otherwise OR-s it into the total.
 */
static ngx_int_t
brix_proto_add_level(ngx_conf_t *cf, void **loc_conf, ngx_str_t *name,
    ngx_uint_t *server_mask)
{
    ngx_uint_t  mask;

    mask = brix_proto_mask(loc_conf);
    if (mask & (mask - 1)) {                 /* more than one bit set */
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "two brix protocols enabled in location \"%V\" - "
            "one brix protocol per location", name);
        return NGX_ERROR;
    }
    *server_mask |= mask;
    return NGX_OK;
}


/* Forward declaration: location and tree walkers are mutually recursive. */
static ngx_int_t brix_proto_walk_location(ngx_conf_t *cf,
    ngx_http_core_loc_conf_t *clcf, ngx_uint_t *server_mask);


/*
 * WHAT: Fold a NULL-terminated array of location confs into *server_mask.
 * WHY:  Both regex (clcf->regex_locations) and named (cscf->named_locations)
 *       locations are stored this way, apart from the static-location tree.
 * HOW:  Walks each entry as a full location (recursing into its own subtree).
 */
static ngx_int_t
brix_proto_walk_loc_array(ngx_conf_t *cf, ngx_http_core_loc_conf_t **arr,
    ngx_uint_t *server_mask)
{
    ngx_uint_t  i;

    if (arr == NULL) {
        return NGX_OK;
    }
    for (i = 0; arr[i] != NULL; i++) {
        if (brix_proto_walk_location(cf, arr[i], server_mask) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}


/*
 * WHAT: Recurse the finalised static-location tree, folding every node's
 *       location into *server_mask.
 * WHY:  After ngx_http_init_static_location_trees the prefix/exact locations
 *       live only in this tree, not in a flat queue.
 * HOW:  Visits each node's exact and inclusive location, then descends the
 *       binary-search siblings (left/right) and the nested subtree (tree).
 */
static ngx_int_t
brix_proto_walk_tree(ngx_conf_t *cf, ngx_http_location_tree_node_t *node,
    ngx_uint_t *server_mask)
{
    if (node == NULL) {
        return NGX_OK;
    }

    if (node->exact != NULL
        && brix_proto_walk_location(cf, node->exact, server_mask) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (node->inclusive != NULL
        && brix_proto_walk_location(cf, node->inclusive, server_mask) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (brix_proto_walk_tree(cf, node->left, server_mask) != NGX_OK
        || brix_proto_walk_tree(cf, node->tree, server_mask) != NGX_OK
        || brix_proto_walk_tree(cf, node->right, server_mask) != NGX_OK)
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}


/*
 * WHAT: Fold one location and all of its descendants into *server_mask.
 * WHY:  A location owns its own protocol and may contain nested prefix, regex
 *       and physically-nested child locations, all of which count toward the
 *       per-port aggregate.
 * HOW:  Adds this location's own mask, then descends its static-location tree
 *       and its regex-location array (each a full location conf to recurse on).
 */
static ngx_int_t
brix_proto_walk_location(ngx_conf_t *cf, ngx_http_core_loc_conf_t *clcf,
    ngx_uint_t *server_mask)
{
    if (brix_proto_add_level(cf, clcf->loc_conf, &clcf->name, server_mask)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (brix_proto_walk_tree(cf, clcf->static_locations, server_mask)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

#if (NGX_PCRE)
    if (brix_proto_walk_loc_array(cf, clcf->regex_locations, server_mask)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
#endif
    return NGX_OK;
}


/*
 * WHAT: Fold one server's whole location structure into *mask.
 * WHY:  The per-port check aggregates over the servers bound to that port; a
 *       server-level enable (a loc-conf directive outside any location) counts
 *       too.
 * HOW:  Reads the server-level conf array (the server's core loc-conf leaves
 *       loc_conf NULL, so the server ctx array is the source of truth), then
 *       walks the server's static-location tree, regex locations and named
 *       (@name) locations.
 */
static ngx_int_t
brix_proto_server_mask(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_uint_t *mask)
{
    ngx_http_core_loc_conf_t  *clcf;

    if (brix_proto_add_level(cf, cscf->ctx->loc_conf, &cscf->server_name, mask)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    clcf = cscf->ctx->loc_conf[ngx_http_core_module.ctx_index];

    if (brix_proto_walk_tree(cf, clcf->static_locations, mask) != NGX_OK) {
        return NGX_ERROR;
    }

#if (NGX_PCRE)
    if (brix_proto_walk_loc_array(cf, clcf->regex_locations, mask) != NGX_OK) {
        return NGX_ERROR;
    }
#endif

    return brix_proto_walk_loc_array(cf, cscf->named_locations, mask);
}


/*
 * WHAT: Reject a configuration that mixes brix protocols per location or per
 *       listen port.
 * WHY:  See the file header — one owning protocol per location keeps the
 *       unified storage directives unambiguous, and one protocol per port is
 *       the deployment model.
 * HOW:  Walks cmcf->ports; for each port, aggregates the protocol mask of every
 *       server bound to every address on it.  A location owning more than one
 *       protocol fails inside the walk; a port whose aggregate mask has more
 *       than one bit set fails here with the two conflicting protocol names.
 */
ngx_int_t
brix_http_proto_exclusive_check(ngx_conf_t *cf)
{
    ngx_uint_t                  p, a, s;
    ngx_uint_t                  port_mask, srv_mask;
    ngx_http_conf_port_t       *port;
    ngx_http_conf_addr_t       *addr;
    ngx_http_core_srv_conf_t  **cscf;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (cmcf->ports == NULL) {
        return NGX_OK;
    }

    port = cmcf->ports->elts;
    for (p = 0; p < cmcf->ports->nelts; p++) {
        port_mask = BRIX_PROTO_NONE;
        addr = port[p].addrs.elts;

        for (a = 0; a < port[p].addrs.nelts; a++) {
            cscf = addr[a].servers.elts;
            for (s = 0; s < addr[a].servers.nelts; s++) {
                srv_mask = BRIX_PROTO_NONE;
                if (brix_proto_server_mask(cf, cscf[s], &srv_mask) != NGX_OK) {
                    return NGX_ERROR;
                }
                port_mask |= srv_mask;
            }
        }

        if (port_mask & (port_mask - 1)) {   /* more than one bit set */
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "%s and %s both enabled under listen port %ui - "
                "one brix protocol per port",
                brix_proto_name(port_mask & (port_mask - 1)),
                brix_proto_name(port_mask & ~(port_mask - 1)),
                (ngx_uint_t) port[p].port);   /* host order (ngx_inet_get_port) */
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}
