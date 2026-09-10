/*
 * Site checksum plugins — host side of core/compat/checksum_plugin_abi.h.
 *
 * WHAT: a process-wide registry of dlopen()ed checksum algorithms, filled by
 * the `brix_checksum_plugin` directive (stream + http main level) and read by
 * the name parser (core/compat/checksum.c), the Qconfig `chksum` list and the
 * digest walker. Plugin algorithms occupy brix_checksum_alg_t values from
 * BRIX_CHECKSUM_PLUGIN_BASE upward so every existing switch keeps its default.
 *
 * WHY: XRootD sites carry `xrootd.chksum` externals; a 2.0 site must be able
 * to answer a non-built-in algorithm without a fork of the server (2.0
 * readiness F8). INVARIANT 9 stays intact: the host hex-encodes at the edge.
 *
 * The registry is keyed on the cycle like the DNS target registry: the first
 * directive of a new cycle drops (dlclose) whatever the previous configuration
 * loaded, and the worker init hook drops it when the new configuration
 * declares no plugin at all.
 */

#ifndef BRIX_CHECKSUM_PLUGIN_H
#define BRIX_CHECKSUM_PLUGIN_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "core/compat/checksum.h"
#include "core/compat/checksum_plugin_abi.h"
#include "fs/backend/sd_registry.h"

/* Alg values below this are built-ins; alg - BASE indexes the registry. */
#define BRIX_CHECKSUM_PLUGIN_BASE    32

/* Config-time registration (validates, dlopen()s, self-tests; logs and
 * returns NGX_ERROR on refusal). `parms` may be empty. */
ngx_int_t brix_cks_plugin_register(ngx_conf_t *cf, ngx_str_t *name,
    ngx_str_t *path, ngx_str_t *parms);

/* Directive handler shared by the stream and http command tables:
 *     brix_checksum_plugin <name> <path.so> [parms]; */
char *brix_checksum_plugin_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* Worker init: drop a registry that belongs to a previous cycle. */
void brix_cks_plugins_init_worker(ngx_cycle_t *cycle);

/* Name lookup: `lname` is already normalized (lowercase alnum, NUL-terminated).
 * NGX_OK + *alg on a hit, NGX_DECLINED otherwise. */
ngx_int_t brix_cks_plugin_lookup(const char *lname, brix_checksum_alg_t *alg);

/* Registered name for a plugin alg, NULL when alg is not a live plugin. */
const char *brix_cks_plugin_name(brix_checksum_alg_t alg);

/* Enumeration for the Qconfig `chksum` list. */
ngx_uint_t brix_cks_plugin_count(void);
const char *brix_cks_plugin_name_at(ngx_uint_t i);

/* Digest of the whole object through the plugin: raw bytes into `out`
 * (BRIX_CKS_PLUGIN_DIGEST_MAX wide), length into *outlen. */
ngx_int_t brix_cksum_plugin_obj(brix_checksum_alg_t alg, brix_sd_obj_t *obj,
    unsigned char *out, size_t *outlen);

#endif /* BRIX_CHECKSUM_PLUGIN_H */
