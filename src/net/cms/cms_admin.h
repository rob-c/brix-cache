#ifndef BRIX_NET_CMS_ADMIN_H
#define BRIX_NET_CMS_ADMIN_H

/*
 * cms_admin.h — §2.x CMS runtime admin unix socket (`brix_cms_admin_socket`).
 *
 * WHAT: the cluster-plane sibling of §1.16's session admin socket. Same
 *       transport (src/net/admin/admin_unix.c), same security model, a
 *       different verb table — one that operates on the SHM node registry
 *       rather than on this worker's live sessions:
 *         nodes                        -> ok <n>\n then one line per node:
 *              "<host>:<port> role=<r> free_mb=<n> util_pct=<n> state=<s>"
 *              (field names match brix_srv_snapshot_entry_t, so the wire and
 *               the struct cannot drift; state is up|drained|space-blocked)
 *         drain <host> <port> [<secs>] -> ok        (default 300s, as the
 *                                         HTTP admin API's drain)
 *         undrain <host> <port>        -> ok | err not-found
 *         forget <host> <port>         -> ok        (unregister)
 *         reset <host> <port>          -> ok | err not-found
 *
 * WHY: stock exposes cluster state and node control through the cmsd admin
 *      interface. Everything needed already exists here — the registry
 *      helpers (`brix_srv_snapshot`, `brix_srv_blacklist`, `brix_srv_undrain`,
 *      `brix_srv_unregister`, `brix_srv_reset`) back the HTTP admin API in
 *      `src/observability/dashboard/api_admin_cluster.c`. What was missing was
 *      a way to reach them WITHOUT the HTTP dashboard: a manager that runs no
 *      dashboard, or an operator on the box during an incident when the HTTP
 *      plane is exactly what is unwell, had no cluster control at all.
 *
 * HOW: the verbs call the same registry helpers the HTTP handlers call, with
 *      the same defaults and the same not-found semantics, so the two surfaces
 *      cannot drift into disagreeing about what "undrain" means. The registry
 *      is in SHM, so unlike the session socket this plane is NODE-wide: any
 *      worker's socket sees and controls every node, and an operator needs
 *      only one of them.
 *
 * SECURITY: chmod 0600, no in-band auth — filesystem permission on the path IS
 *      the privilege boundary (see admin_unix.h). Every mutating verb emits a
 *      structured NGX_LOG_NOTICE audit line naming action, target and result,
 *      matching api_admin_cluster.c's fields.
 *
 *      DIVERGENCE, deliberate: those lines are NOT hash-chained, while the
 *      HTTP admin API's are (api_admin.c admin_audit(), P90-28.2). The chain
 *      makes a NETWORK-REACHABLE API tamper-evident — it defends against
 *      someone who can reach the endpoint but not the log. This socket is
 *      reachable only by a principal who can already open a 0600 path on the
 *      box, and such a principal can rewrite the log itself; a chain would
 *      assert an integrity property the threat model does not support. The
 *      fields are identical so the two streams can be read together.
 */

#include "core/ngx_brix_module.h"

/* `brix_cms_admin_socket <path>` setter. */
char *brix_conf_set_cms_admin_socket(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* Create + listen on the configured socket. Called from init_process. */
void brix_cms_admin_socket_init(ngx_cycle_t *cycle);

#endif /* BRIX_NET_CMS_ADMIN_H */
