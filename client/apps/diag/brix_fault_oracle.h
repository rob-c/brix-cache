/*
 * brix_fault_oracle.h — gated external-command oracle for brix-fault-proxy.
 *
 * The auto-bisection and assert-recovery features need to ask a yes/no question
 * about the system under test — "did the client survive this fault?", "has the
 * service recovered?" — by running an operator-supplied probe command and reading
 * its exit code (0 = pass, non-zero = fail/repro).
 *
 * Because that means the (loopback, unauthenticated) control port could spawn
 * processes, it is DOUBLE-GATED like the privileged netem levers: it does nothing
 * unless the operator passed --enable-exec at startup.  Without the flag every
 * oracle call refuses, so the control port cannot execute anything by default.
 */
#ifndef BRIX_FAULT_ORACLE_H
#define BRIX_FAULT_ORACLE_H

/* Arm the oracle (from --enable-exec). */
void fp_oracle_enable(void);

/* True if --enable-exec was given. */
int  fp_oracle_enabled(void);

/* Run `cmd` via /bin/sh -c in its own process group, waiting up to `timeout_ms`
 * (0 = no timeout).  Returns the child's exit status (0..255) on a clean exit,
 * -2 if the oracle is not enabled, or -1 on a spawn error / timeout kill
 * (inconclusive).  The child is SIGKILLed (whole group) on timeout. */
int  fp_oracle_run(const char *cmd, int timeout_ms);

#endif /* BRIX_FAULT_ORACLE_H */
