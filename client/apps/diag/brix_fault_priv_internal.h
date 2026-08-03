/* brix_fault_priv_internal.h — seam between the privileged-lever TUs.
 *
 * WHAT: The subprocess runners and operator-argument validators defined in
 *       brix_fault_priv_exec.c, the netem plane defined in
 *       brix_fault_priv_netem.c, and the lever state owned by
 *       brix_fault_priv.c — everything the three TUs share.
 *
 * WHY:  The three TUs are one unit split for the 600-line cap
 *       (coding-standards §1). Nothing outside brix-fault-proxy includes this;
 *       the public lever API stays in brix_fault_priv.h.
 *
 * HOW:  Validators return 1 = accept, 0 = reject, and never mutate the input.
 *       Runners return the child's exit status, or -1 if it could not start.
 *       Every netem entry point below expects the caller to hold g_lock, which
 *       brix_fault_priv.c takes at the public API boundary. */

#ifndef BRIX_FAULT_PRIV_INTERNAL_H
#define BRIX_FAULT_PRIV_INTERNAL_H

#include <net/if.h>
#include <stddef.h>

/* fork+execvp argv with stdout silenced (stderr inherited for diagnostics). */
int priv_run(char *const argv[]);

/* As priv_run, but feeds `input` to the child on stdin (nft ruleset load). */
int priv_run_stdin(char *const argv[], const char *input);

/* Conservative charset AND exists under /sys/class/net. */
int valid_iface(const char *s);

/* A percentage "N" or "N.M" (0..100), copied to out on accept. */
int fmt_pct(const char *s, char *out, size_t osz);

/* An unsigned decimal <= max, copied to out on accept. */
int fmt_uint(const char *s, char *out, size_t osz, long max);

/* A tc rate literal (digits + optional unit suffix). */
int valid_rate(const char *s);

/* --------------------------------------------------------- netem plane ------ */

/* netem feature slots, emitted in this order (delay must precede reorder for
 * `tc netem` to honour the hold-back). Each slot holds a validated, ready-to-
 * tokenize fragment such as "delay 100ms 20ms" or "loss gemodel 5% 90%". */
enum { NE_DELAY, NE_LOSS, NE_CORRUPT, NE_DUP, NE_REORDER, NE_RATE, NE_LIMIT, NE_N };

/* Defined in brix_fault_priv.c, which owns the lever lifecycle. */
extern char g_iface[IFNAMSIZ];   /* configured NIC, "" when none */
extern char g_ne[NE_N][96];      /* the fragment table */
extern int  g_netem_on;          /* a netem qdisc is currently installed */

/* Re-emit the qdisc from g_ne (or delete it when every slot is empty).
 * 0 = applied, -1 = tc failed, -2 = no interface configured. */
int netem_apply(void);

/* Drop every clause and reinstall; the teardown / `priv clear` path. */
int netem_clear(void);

/* `priv netem <sub> ...`. Writes the operator reply; 0 = ok, -1 = rejected.
 * Mutates `args` (strtok). */
int netem_command(char *args, char *reply, size_t rsz);

#endif /* BRIX_FAULT_PRIV_INTERNAL_H */
