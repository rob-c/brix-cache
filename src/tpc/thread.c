#include "tpc_internal.h"


#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Thread-pool worker: orchestrates connect → bootstrap → pull           */
/* ------------------------------------------------------------------ */

/* ---- Function: xrootd_tpc_pull_thread() ----
 *
 * WHAT: Native thread-pool worker for TPC (third-party copy) data pulls. Executes the full source-side workflow: connects to remote XRootD endpoint, bootstraps authentication session, then initiates data transfer via tpc_pull_from_source(). Called from nginx's threaded pool when native TPC is enabled (NGX_THREADS).
 *
 * WHY: TPC transfers require the source server to actively connect to and pull data from a remote endpoint — this cannot be done synchronously on the main event loop because network I/O would block all other connections. The thread-pool approach allows parallel pulls without starving the nginx worker's connection handling. Thread safety: single-owner per connection on one thread; no shared state between threads during execution.
 *
 * HOW: Initializes result/error fields to failure defaults before attempting transfer. Connects via tpc_connect() — if connection fails, returns immediately with error status. Bootstraps session via tpc_bootstrap() — if bootstrap fails, closes fd and returns. On success delegates to tpc_pull_from_source() for actual data transfer then closes the file descriptor regardless of outcome. Always sets result=NGX_ERROR initially so callers can check failure even on partial completion. */

void
xrootd_tpc_pull_thread(void *data, ngx_log_t *log)
{
    xrootd_tpc_pull_t *t = data;
    int                fd;

    (void) log;

    t->result     = NGX_ERROR;
    t->xrd_error  = kXR_ServerError;
    t->err_msg[0] = '\0';

    fd = tpc_connect(t);
    if (fd < 0) { return; }

    if (tpc_bootstrap(t, fd) != 0) {
        close(fd);
        return;
    }

    (void) tpc_pull_from_source(t, fd);
    close(fd);
}

