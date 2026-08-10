#ifndef BRIX_ROOT_SESSION_ADMIN_SOCKET_H
#define BRIX_ROOT_SESSION_ADMIN_SOCKET_H

/*
 * admin_socket.h — §1.16 runtime admin unix socket (XrdXrootdAdmin analog).
 *
 * WHAT: a worker-0 unix-domain control socket (`brix_admin_socket <path>`)
 *       speaking a line-based command protocol:
 *         list                  -> ok <n>\n then one "<sessid-hex> <dn|->" line each
 *         disc <sessid-hex>     -> ok | err ...   (shutdown()s the session's conn)
 *         msg <sessid-hex> <t>  -> ok | err ...   (kXR_attn/asyncms to the client)
 *         pause <sessid-hex> [<secs>] -> ok | err  (stop reading its requests;
 *                                 in-flight replies drain; optional auto-resume)
 *         cont <sessid-hex>     -> ok | err ...   (resume a paused session)
 *         abort <sessid-hex>    -> ok | err ...   (RST-close: SO_LINGER{1,0})
 *       Replies end with a newline; errors are "err <reason>".
 *
 * WHY: stock's XrdXrootdAdmin socket lets an operator inspect and control live
 *      sessions without restarting the server. The stock admin wire grammar is
 *      not published in installed headers, so this speaks a DOCUMENTED-DIVERGENT
 *      simple text protocol with the same operational verbs.
 *
 * HOW: sessions self-register in the per-worker offload registry under
 *      BRIX_ADMIN_PATHID at connection setup; the admin TU resolves
 *      sessid -> conn there (disc = shutdown(2) so the normal event-loop
 *      teardown runs; msg = brix_send_attn_asyncms on the target's out-ring)
 *      and enriches `list` with the peer address and the SHM registry's dn.
 *      MULTI-WORKER: every worker serves its own socket — worker 0 at <path>,
 *      worker n at "<path>.<n>" — each listing/controlling exactly the sessions
 *      its worker owns (an admin tool sweeps the set). The natural mapping of
 *      stock's single-daemon adminpath onto nginx's process model.
 *
 * SECURITY: the socket is chmod 0600 (owner-only) and carries NO in-band auth —
 *      filesystem permission on the path IS the privilege boundary, exactly like
 *      stock's adminpath.
 */

#include "core/ngx_brix_module.h"

/* Create + listen on the configured admin socket (no-op when the directive is
 * unset or on workers other than 0). Called from init_process. */
void brix_admin_socket_init(ngx_cycle_t *cycle);

#endif /* BRIX_ROOT_SESSION_ADMIN_SOCKET_H */
