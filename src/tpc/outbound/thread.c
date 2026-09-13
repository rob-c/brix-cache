#include "tpc/engine/tpc_internal.h"


#include <stdlib.h>
#include <unistd.h>


/*
 *
 * WHAT: Native thread-pool worker for TPC (third-party copy) data pulls.
 *   - Executes full source-side workflow:
 *     1. Connects to remote XRootD endpoint
 *     2. Bootstraps authentication session
 *     3. Initiates data transfer via tpc_pull_from_source()
 *   - Called from nginx's threaded pool
 *   - Enabled when NGX_THREADS is set
 *
 * WHY: TPC transfers require the source server to actively connect to and pull data from a remote endpoint — this cannot be done synchronously on the main event loop because network I/O would block all other connections. The thread-pool approach allows parallel pulls without starving the nginx worker's connection handling. Thread safety: single-owner per connection on one thread; no shared state between threads during execution.
 *
 * HOW: Initializes result/error fields to failure defaults before attempting transfer. Finishes a client PTR the kXR_open could not wait for (brix_tpc_origin_thread_fill, blocking DNS off the event loop). Connects via tpc_connect() — if connection fails, returns immediately with error status. Bootstraps session via tpc_bootstrap() — if bootstrap fails, closes fd and returns. On success delegates to tpc_pull_from_source() for actual data transfer then closes the file descriptor regardless of outcome. Always sets result=NGX_ERROR initially so callers can check failure even on partial completion. */

/* WHAT: one connect → bootstrap → transfer leg against t->src_host:src_port.
 *       Returns the transfer's verdict: 0 done, -1 failed, TPC_PULL_REDIRECT
 *       when the peer answered the open with kXR_redirect (t->redir_* filled).
 *       The socket and its TLS are always released before returning.
 *
 *       F16: src_host/src_port name the REMOTE PEER in both directions — the
 *       source of a pull, the destination of a push — so the connect, the egress
 *       guard inside it, the bootstrap, the TLS teardown and the redirect
 *       protocol are shared verbatim. t->is_push selects only which way the
 *       bytes then move. */
static int
tpc_pull_leg(brix_tpc_pull_t *t)
{
    int fd = tpc_connect(t);
    int rc = -1;

    if (fd < 0) {
        return -1;
    }
    if (tpc_bootstrap(t, fd) == 0) {
        rc = t->is_push ? tpc_push_to_dest(t, fd)
                        : tpc_pull_from_source(t, fd);
    }
    tpc_tls_teardown(t);              /* SSL_shutdown/free before closing the fd */
    close(fd);
    return rc;
}

void
brix_tpc_pull_thread(void *data, ngx_log_t *log)
{
    brix_tpc_pull_t *t    = data;
    ngx_log_t       *plog = (t->c != NULL) ? t->c->log : log;
    int              rc;

    t->result     = NGX_ERROR;
    t->xrd_error  = kXR_ServerError;
    t->err_msg[0] = '\0';

    (void) brix_tpc_registry_update(t->transfer_id, 0,
                                      BRIX_TPC_STATE_ACTIVE, plog);

    brix_tpc_origin_thread_fill(t);   /* tpc.org: a PTR the open left pending */

    /* F7 multihop: a kXR_redirect from the open re-runs the whole leg against
     * the named data server — once tpc_redirect_follow() has admitted the hop
     * (budget, self-loop, egress guard). A refused hop fails the pull with
     * its reason already in t->err_msg. */
    do {
        rc = tpc_pull_leg(t);
    } while (rc == TPC_PULL_REDIRECT && tpc_redirect_follow(t, plog) == 0);

    (void) brix_tpc_registry_update(
        t->transfer_id, (off_t) t->bytes_written,
        t->result == NGX_OK ? BRIX_TPC_STATE_DONE : BRIX_TPC_STATE_ERROR,
        plog);
    if (t->deleg_cred_pem) { free(t->deleg_cred_pem); t->deleg_cred_pem = NULL; }
}
