/*
 * xfer_spawn.h — crash-safe synchronous external-command runner.
 *
 * WHAT: xrootd_xfer_run_reparented() runs an argv (no shell) in a double-forked,
 *       reparented-to-init agent so the calling process manager (nginx) never
 *       reaps it, blocks until it finishes, and returns the command's exit status.
 *
 * WHY:  Some transfers shell out to an external client (write-through's GSI origin
 *       upload, and — later — TPC). Those used posix_spawn + waitpid, which leaves
 *       a direct child of the nginx worker; reaping a worker child can crash the
 *       master via the SHM-zone-as-slab-pool SIGCHLD handler (see the FRM fork
 *       postmortem). This is the synchronous sibling of the long-lived agent
 *       harness (xfer_mover_agent.c): same reparent-so-nginx-never-reaps guarantee,
 *       but call-and-block-for-exit-code, which is what those upload paths need.
 *
 * HOW:  Deliberately ngx-free (POSIX only) so it is unit-testable standalone
 *       (src/fs/xfer/xfer_spawn_unittest.c) and callable from any context — the
 *       event loop or an nginx thread-pool worker. The child only performs
 *       async-signal-safe operations between fork and execve, so it is safe to
 *       call from a multithreaded (thread-pool) context.
 */

#ifndef XROOTD_FS_XFER_SPAWN_H
#define XROOTD_FS_XFER_SPAWN_H

/*
 * Run argv[0] with argv/envp (no shell). Blocks until the command exits.
 *
 * Returns the command's exit status (0..255; 127 means execve failed), or -1 with
 * errno set if the agent could not be spawned or its result could not be read.
 * envp == NULL inherits the current environment.
 */
int xrootd_xfer_run_reparented(const char *const argv[], char *const envp[]);

#endif /* XROOTD_FS_XFER_SPAWN_H */
