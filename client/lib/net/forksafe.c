/*
 * forksafe.c — §7.7 fork safety: neuter inherited connections in the child.
 *
 * WHAT: A process-wide registry of live brix_conns plus pthread_atfork
 *       handlers. After fork(), the CHILD's copies of every registered
 *       connection are neutered: the fd is closed (per-process descriptor
 *       table — the parent's socket is untouched and NO bytes move), the
 *       shared-buffer diagnostics are abandoned unflushed, and the conn is
 *       marked `forked` so every later operation fails with a clean
 *       non-retryable error instead of writing into the parent's stream.
 * WHY:  HEP frameworks fork with sessions open. An inherited fd is shared
 *       with the parent: any child write — including brix_close's
 *       fire-and-forget kXR_endsess, or an atexit teardown — interleaves
 *       frames into the parent's session (stream corruption, sid collisions,
 *       and a child endsess KILLS the parent's session server-side).
 *       Flushing inherited stdio buffers (the --capture file) would
 *       duplicate the parent's buffered bytes; abandoning them leaks a
 *       little memory in a process that is about to exec or exit, which is
 *       the correct trade.
 * HOW:  brix_connect registers on success, brix_close unregisters first
 *       thing. The atfork trio locks the registry across the fork (prepare/
 *       parent) so the child never sees a half-updated table, and the child
 *       handler re-inits the mutex and walks the slots. Fixed table:
 *       overflow conns simply stay unregistered and un-neutered — counted,
 *       and far above any real tool's concurrent connection count.
 */
#include "brix.h"
#include "_brix_net_ext.h"

#include <pthread.h>
#include <unistd.h>

#define BRIX_FORKSAFE_MAX 256

static pthread_mutex_t g_fs_mx = PTHREAD_MUTEX_INITIALIZER;
static brix_conn      *g_fs_reg[BRIX_FORKSAFE_MAX];
static int             g_fs_overflow;

static void
forksafe_prepare(void)
{
    pthread_mutex_lock(&g_fs_mx);
}

static void
forksafe_parent(void)
{
    pthread_mutex_unlock(&g_fs_mx);
}

/* ---- Child-side neuter of every registered connection ----
 *
 * WHAT: Closes each registered conn's fd (no protocol goodbye, no TLS
 *       close_notify), abandons the SSL/capture handles unfreed, and marks
 *       the conn forked.
 *
 * WHY: close() in the child only drops the child's descriptor reference —
 *      the parent's socket lives on and, critically, nothing is transmitted.
 *      SSL_free/fclose would emit bytes or flush shared buffers; leaking
 *      them in the child is deliberate.
 *
 * HOW: The mutex was taken pre-fork, so the table is consistent; re-init it
 *      for the child (the parent's lock state is meaningless here), then
 *      walk and neuter.
 */
static void
forksafe_child(void)
{
    int i;

    pthread_mutex_init(&g_fs_mx, NULL);
    for (i = 0; i < BRIX_FORKSAFE_MAX; i++) {
        brix_conn *c = g_fs_reg[i];

        if (c == NULL) {
            continue;
        }
        if (c->io.fd >= 0) {
            close(c->io.fd);
            c->io.fd = -1;
        }
        c->io.ssl  = NULL;   /* abandoned: SSL_free would send close_notify */
        c->diag.cap = NULL;  /* abandoned: fclose would flush shared buffers */
        c->forked  = 1;
    }
}

/* ---- Registry maintenance (conn.c calls these) ---- */

void
brix_forksafe_register(brix_conn *c)
{
    static int installed = 0;
    int        i;

    pthread_mutex_lock(&g_fs_mx);
    if (!installed) {   /* install the atfork trio exactly once per process */
        (void) pthread_atfork(forksafe_prepare, forksafe_parent,
                              forksafe_child);
        installed = 1;
    }
    for (i = 0; i < BRIX_FORKSAFE_MAX; i++) {
        if (g_fs_reg[i] == NULL) {
            g_fs_reg[i] = c;
            pthread_mutex_unlock(&g_fs_mx);
            return;
        }
    }
    g_fs_overflow++;   /* unregistered ⇒ un-neutered; capacity is generous */
    pthread_mutex_unlock(&g_fs_mx);
}

void
brix_forksafe_unregister(brix_conn *c)
{
    int i;

    pthread_mutex_lock(&g_fs_mx);
    for (i = 0; i < BRIX_FORKSAFE_MAX; i++) {
        if (g_fs_reg[i] == c) {
            g_fs_reg[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&g_fs_mx);
}

/* Public probe: is this connection still usable (not neutered by a fork)?
 * The preload shim keys its transparent child re-connect on this. */
int
brix_conn_usable(const brix_conn *c)
{
    return c != NULL && !c->forked && c->io.fd >= 0;
}
