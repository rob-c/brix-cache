#ifndef BRIX_IMP_LIFECYCLE_H
#define BRIX_IMP_LIFECYCLE_H

/*
 * lifecycle.h — nginx integration glue for per-request UNIX impersonation
 * (phase 40).
 *
 * WHAT: The configuration directives, config-time validation, master-side broker
 *   spawn, worker-side client connect, and per-request principal set/clear that
 *   bridge the self-contained impersonation engine (idmap/broker/client) into the
 *   nginx module lifecycle.
 *
 * WHY: Concentrating ALL nginx-typed glue here keeps the load-bearing module
 *   files (module.c, process.c, postconfiguration.c) touched by only a single
 *   call each, and keeps the engine itself free of ngx_conf/ngx_cycle types.
 *
 * HOW: One process-global settings block (there is at most one broker per nginx
 *   instance) populated by the `brix_impersonation*` directives; init_module
 *   spawns the broker (FRM double-fork) only in `map` mode on a root master;
 *   init_process connects the worker client; the request hooks set the broker's
 *   target principal from the authenticated identity for the duration of one
 *   synchronous op-dispatch.  Off-by-default: in `off`/`single` mode nothing here
 *   spawns a process, opens a socket, or routes any I/O through the broker.
 */

#include "core/ngx_brix_module.h"
#include "core/types/identity.h"

/* ----- Directive setters (ngx_command_t .set) --------------------- */

/* brix_impersonation off|single|map */
char *brix_imp_conf_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
/* String directives; cmd->offset selects the target field (BRIX_IMP_F_*). */
char *brix_imp_conf_str(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
/* Numeric directives; cmd->offset selects the target field. */
char *brix_imp_conf_num(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* cmd->offset selectors for brix_imp_conf_str / _num. */
#define BRIX_IMP_F_SOCKET           1
#define BRIX_IMP_F_EXPORT_ROOT      2
#define BRIX_IMP_F_GRIDMAP          3
#define BRIX_IMP_F_DEFAULT_USER     4
#define BRIX_IMP_F_SINGLE_USER      5
#define BRIX_IMP_F_MIN_UID          6
#define BRIX_IMP_F_CACHE_TTL        7
#define BRIX_IMP_F_BROKER_USER      8
#define BRIX_IMP_F_FORBIDDEN_USERS  9
#define BRIX_IMP_F_FORBIDDEN_GROUPS 10

/* ----- Lifecycle hooks -------------------------------------------- */

/* Validate the configured mode + its required fields.  Call from
 * postconfiguration (with the resolved export root of the first data server, or
 * NULL).  Returns NGX_OK, or NGX_ERROR (emergency-logged) on an invalid combo. */
ngx_int_t brix_imp_validate(ngx_conf_t *cf, const char *derived_export_root);

/* Master, once per (re)load: in `map` mode, spawn the privileged broker
 * (double-forked, reparented to init).  No-op for off/single, during `nginx -t`,
 * or when already running.  Returns NGX_OK (also when impersonation is off). */
ngx_int_t brix_imp_init_module(ngx_cycle_t *cycle);

/* Worker, at init_process: in `map` mode, connect the broker client.  No-op
 * otherwise.  A not-yet-ready broker is a soft warning (lazy reconnect). */
ngx_int_t brix_imp_init_worker(ngx_cycle_t *cycle);
void brix_imp_worker_harden(ngx_log_t *log);

/* ----- Per-request principal -------------------------------------- */

/* Set the broker's target principal from `id` for the next op(s) on this worker;
 * no-op unless `map` mode is active.  Pair with brix_imp_request_end(). */
void brix_imp_request_begin(const brix_identity_t *id);
void brix_imp_request_end(void);

/* Current mode: BRIX_IMP_OFF / BRIX_IMP_SINGLE / BRIX_IMP_MAP. */
int brix_imp_mode(void);

#endif /* BRIX_IMP_LIFECYCLE_H */
