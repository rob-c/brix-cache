# Worker seccomp-BPF Syscall Filter

Defence-in-depth (hyper-hardening-plan §D-3). The privilege model is already
strong — unprivileged operation, PR_SET_NO_NEW_PRIVS, full capability drop —
but the impersonation broker necessarily retains CAP_SETUID, so a worker-code
exploit is root-equivalent if the broker is reached. This component installs a
libseccomp allowlist on each worker so a hijacked worker cannot spawn a shell,
ptrace another process, or peer into the broker's address space.

Operator-facing model: tri-state opt-in via `brix_seccomp off|audit|enforce`
(default off). AUDIT loads a log-only filter to converge the allowlist without
risk; ENFORCE kills the named-dangerous set and EPERMs any other syscall.
`brix_seccomp_allow_exec` (default ON) keeps execve/execveat allowlisted under
enforce, because brix legitimately fork+execs helpers (FRM "exec" MSS adapter,
OIDC token fetch, native-TPC token exchange, the kXR_prepare hook); `off` opts
into the strict anti-shell posture. The hard kills (ptrace/process_vm_*) apply
regardless of the exec flag.

File split (same ngx-free-core convention as wverify / opaque / negcache):

- `seccomp_core.h` / `seccomp_core.c` — the nginx-free core: the allowlist /
  named-dangerous tables and the libseccomp build+load
  (`brix_seccomp_core_apply`), plus `brix_seccomp_broker_apply`, a
  DEFAULT-ALLOW filter for the impersonation broker that hard-kills a small
  never-legitimate set (exec, ptrace, process_vm_*, mount/ns, modules, kexec,
  bpf, keyctl, mknod, reboot). Exercised directly by `tests/c/test_seccomp.c`
  so the shipped tables are the tables under test.
- `seccomp.h` / `seccomp.c` — the ngx wrapper: the `brix_seccomp` /
  `brix_seccomp_allow_exec` directive setters, the process-global effective
  mode, `brix_seccomp_install_once()` (per-worker idempotent latch), and the
  error sink that routes libseccomp failures to ngx_log_error.

Gotchas: both the mode and the exec flag are fail-secure ratchets — they only
tighten within a master's lifetime (a SIGHUP reload cannot lower the mode or
re-enable exec; restart to reset). The strictest mode requested by ANY brix
server (stream or http) wins, since a filter is per-process and one worker
serves every server. A binary built without libseccomp fails closed for
audit/enforce (the worker refuses to start) rather than silently serving
unfiltered.
