#include "tpc_internal.h"

#if (NGX_THREADS)

#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Thread-pool worker: orchestrates connect → bootstrap → pull           */
/* ------------------------------------------------------------------ */

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

#endif /* NGX_THREADS */
