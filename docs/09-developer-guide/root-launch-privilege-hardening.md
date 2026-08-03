# Launched-as-Root Privilege Hardening

**Status:** Design/decision record for the worker and broker privilege model
when brix-cache is started as (or with the caps of) root. Covers the
unconditional worker capability drop, forced de-escalation to a confined
account, the broker `SO_PEERCRED` gate, broker seccomp, and the worker seccomp
filter (including exec compatibility). Cross-references
[pblock-privilege-drop-hardening.md](pblock-privilege-drop-hardening.md) for the
`CAP_SETUID`-keep-vs-pblock conflict.

Originated 2026-07-19/20 from the POSIX-backend hardening review (items 1/2/3/5/6
of that review). Verified throughout via `/proc/<pid>/status`
(`CapEff`/`Seccomp`/`NoNewPrivs`/`Uid`).

---

## Context

Pre-auth credential parsers (JWT / macaroon / X.509 / VOMS / krb5) run **in the
worker**, on attacker-controlled bytes, during `kXR_auth`, **before** any auth
decision is made. If a worker retains root-capable identity or capabilities at
that point, a parser bug is a root compromise. Independently, the impersonate
broker is a long-lived root-capable helper whose only job is `setuid`, so it
should be locked down to a tiny syscall surface.

The previous model only hardened the worker in impersonation `map` mode, and the
cap-drop sat **after** the stream-config early-return, so HTTP-only
(WebDAV/S3/cvmfs) workers were never covered. This record captures the model
that replaced it.

---

## The cap-drop model

### Unconditional worker hardening

`brix_imp_worker_harden(log)`
(`src/auth/impersonate/lifecycle_worker.c`) is the public entry point, delegating
to `imp_worker_drop_caps()` in the same file. It is called from
`ngx_stream_brix_init_process` (`src/core/config/process.c`) **before** the
`cmcf == NULL` early-return, so HTTP-only workers are hardened too. (The old
`brix_imp_init_worker` cap-drop sat after that return and never ran for
http-only, `off`, or `single`.)

For a **root** worker, `imp_worker_drop_caps` reduces permitted+effective caps to
**only** `{CAP_SETUID, CAP_SETGID}` — shedding `DAC_OVERRIDE`, `MKNOD`,
`SYS_ADMIN`, `PTRACE`, `CHOWN`, `FOWNER`, `FSETID`, `DAC_READ_SEARCH`, `SETPCAP`,
`SETFCAP` — and sets `NO_NEW_PRIVS`. Result: root worker `CapEff == 00..c0`.
Retaining `SETUID` adds no escalation (the process is already uid 0) but lets
legitimate identity drops work. The retention is now conditional on the cap being
currently held, via `brix_imp_cap_held(cap)` (a `SYS_capget` probe, also in
`lifecycle_worker.c`), so a non-root worker holding `CAP_SETUID` can also be
dropped; a plain non-root worker keeps nothing.

### Forced de-escalation to a confined account

`brix_imp_worker_deescalate(log)` (`src/auth/impersonate/lifecycle_worker.c`,
declared in `lifecycle.h`) force-drops **any** root-capable worker — euid 0 **or**
a non-root account holding `CAP_SETUID` — down to a confined account at init.
This is because `euid == 0` is the wrong test: a service account with
`CAP_SETUID` or passwordless sudo is root-equivalent.

- Directive: `brix_worker_user <acct>` (default `nobody`, with a WARN),
  fail-closed. Setter `brix_conf_set_worker_user`, registered in **both** the
  stream table (`src/protocols/root/stream/directives_security.inc`) and the http
  table (`src/core/config/http_common.c`); global `char brix_worker_user[64]`.
- Called from `process.c` early — right after `brix_imp_worker_harden`, **before**
  the `cmcf` early-return, backend init, broker connect, and seccomp install — so
  it runs once for stream, mixed, and http-only workers uniformly
  (`src/core/config/process.c` around lines 198–207).
- Branches: already-target → silent no-op (normal `user nobody`); can-drop
  (root/`CAP_SETUID`) → `setgroups`/`setgid`/`setuid` + verify + re-harden, fail
  `NGX_ERROR` closed; can't-drop with a residual dangerous cap → refuse; can't-drop
  with an unreachable configured account → WARN; can't-drop plain non-root (normal
  rootless) → quiet INFO.
- The unconditional `NO_NEW_PRIVS` set by `harden` neutralizes
  passwordless-sudo / setuid-binary escalation on the worker's own exec chain
  (`execve` ignores the setuid bit under NNP), so sudo need not be probed:
  dropping handles root/`CAP_SETUID`, NNP handles sudo.

`/dev/shm` credential staging (`src/core/compat/cred_stage.c` —
`/dev/shm/brix-creds.<euid>`, 0700 dir / 0600 files, fail-closed) is owned by the
worker EUID, so it follows the drop automatically: a `nobody` worker yields
`nobody`-owned creds, no separate change needed.

### Related edge fixes (items 5/6)

- Central setuid/setgid strip in the chmod canon:
  `src/fs/path/resolve_confined_ops.c` now masks `mode & 0777` (was `07777`).
- `O_NOFOLLOW` added to the two service-owned staging opens:
  `src/protocols/root/connection/fd_table.c` (from-cache) and
  `src/protocols/webdav/tpc_curl.c` (assembly temp).

---

## The broker: peercred gate + seccomp

### `SO_PEERCRED` gate no longer no-ops when `user` is unset

`imp_worker_uid` (`src/auth/impersonate/lifecycle_broker.c`) falls back to
`getpwnam("nobody")` so `brix_imp_broker_allow_uid` is a real uid. Previously an
unset `user` left `allow_uid == 0`, and the gate treated 0 as "allow all",
silently disabling the peercred check (`broker_creds.c` consumes
`brix_imp_broker_allow_uid`). Validated indirectly by the gridmap map-mode suite
(worker=nobody still connects).

### The root broker is seccomp-filtered

`brix_seccomp_broker_apply()` (`src/core/seccomp/seccomp_core.c`) installs a
**DEFAULT-ALLOW** filter with `SCMP_ACT_KILL_PROCESS` on a small never-legit set:
`execve`/`execveat`, `ptrace`, `process_vm_readv`/`writev`,
`mount`/`umount2`/`unshare`/`setns`/`pivot_root`/`chroot`, module load/unload,
`kexec`, `bpf`, `keyctl`/`add_key`/`request_key`, `mknod`/`mknodat`, `reboot`.
Default-allow (not an allowlist) so a forgotten broker syscall can't break it. It
is called from `brix_imp_broker_drop_caps` after the cap-drop; best-effort (WARN +
continue on load failure). The broker also WARNs when it runs as root (no
`brix_impersonation_broker_user`). Broker `/proc`: `Seccomp=2`, `NoNewPrivs=1`,
`CapEff=00..c0`.

---

## Worker seccomp filter

`brix_seccomp` is opt-in (compiled default **OFF**). It is registered in **both**
the stream table and the shared http table
(`common.seccomp` in the shared conf); the custom setter `brix_conf_set_seccomp`
(`src/core/seccomp/seccomp.c`) parses the enum into the per-conf field and bumps a
process-global `brix_seccomp_worker_mode` to the strictest across **all** brix
servers. `brix_seccomp_install_once(cycle)` (`seccomp.c`, an idempotent per-worker
latch) installs it and is called from the **end** of both
`ngx_stream_brix_init_process` and `ngx_http_brix_webdav_init_process` (http-only,
after `curl_global_init`), preserving fail-closed. The global ratchets **up** only
within a master lifetime (reload cannot lower it — restart to drop).

Verified via `/proc`: http-only WebDAV + `brix_seccomp enforce` → worker
`Seccomp:2` + PUT/GET 201/200; no directive → `Seccomp:0`; mixed stream+http
enforce → `Seccomp:2`, no `SIGSYS`.

### Worker deny-set: HARD vs EXEC

The worker deny-set (`brix_seccomp_deny` in `seccomp_core.c`) splits into:

- **HARD** — `ptrace`, `process_vm_readv`/`writev`: always killed under ENFORCE.
  These are how one process reads/injects another, so they protect the broker.
- **EXEC** — `execve`/`execveat`: killed under ENFORCE only when
  `allow_exec` is off.

`brix_seccomp_core_apply(mode, allow_exec, ...)` gained the `allow_exec` param;
the log reports `exec=allowed|killed` (e.g. "220 allowed, 3 denied" vs "218
allowed, 5 denied").

### `brix_seccomp_allow_exec` — default ON, ratchet inverted

Directive `brix_seccomp_allow_exec on|off` (setter
`brix_conf_set_seccomp_allow_exec`, both tables). It **defaults to ON** because
the exec paths are E2E-proven and killing exec by default would silently break
features the moment an operator turns on `brix_seccomp enforce`. The ratchet is
**inverted** relative to the mode: `off` is the fail-secure direction — an `off`
on any server sets the global to 0 (kill exec) and **sticks** (a later `on`, or a
reload dropping `off`, cannot re-enable — restart to reset); `on` is a no-op
default that must not override a prior `off`. HARD kills are unaffected.

Fork+exec sites that need `allow_exec`:

- FRM "exec" MSS adapter (`src/fs/backend/frm/sd_frm_exec.c`, `posix_spawn` of
  `$BRIX_FRM_STAGECMD`, a real external HSM — authority `tape://exec` /
  `frm://exec`).
- OIDC token fetch (`src/tpc/outbound/tpc_token.c`).
- Native-TPC token-exchange (`src/tpc/outbound/tpc_token_exchange.c`).
- WebDAV HTTP-TPC oidc-agent (`src/protocols/webdav/tpc_cred_oidc.c`).
- `kXR_prepare` hook (`src/protocols/root/query/prepare_cmd.c`).
- Shared mover-spawn helper (`src/fs/xfer/xfer_spawn.c`).

WebDAV HTTP-TPC **data** transfer uses libcurl in-process (no exec). The
**default** tape/nearline backend is the POSIX "stub" MSS adapter
(`src/fs/backend/frm/sd_frm_stub.c`, authority `frm://stub<dir>`): recall/migrate/
purge are plain file copies (open/read/write/rename/unlink), no exec → works under
STRICT enforce with no `allow_exec`. (An earlier claim that `tape://` requires
`allow_exec` was wrong — only the external-HSM exec adapter does.)

### Allowlist gotchas discovered under enforce

- **xattr family**: `set/get/list/removexattr` (+ `l`/`f` variants) must be in
  `brix_seccomp_allow` (`seccomp_core.c` around line 130). Without them, every
  xattr op (WebDAV LOCK/PROPPATCH, `kXR_fattr`, xmeta, cache xattr-meta) is
  EPERM'd under ENFORCE.
- **process-group/session family**: `getpgrp`/`getpgid`/`setpgid`/`getsid`/
  `setsid` must be allowed (`seccomp_core.c` around line 75). bash calls
  `getpgrp()` during job-control init at startup; without it, an exec'd shell
  exits (EPERM, not SIGSYS — diagnosed via `ausearch -m SECCOMP`, since
  `SCMP_ACT_LOG` goes to auditd, not dmesg) before running a line. Lesson: an
  `allow_exec` that must run arbitrary external programs (shells, coreutils, curl)
  needs the pgrp/session syscalls too. No privilege gain (grouping only).

---

## The pblock conflict

Clearing `CAP_SETUID` from a root worker would break pblock's later
`setuid(nobody)` (fail-closed) and would break `single` mode. This is why the
worker cap-drop **retains `{CAP_SETUID, CAP_SETGID}`** for a root-capable worker
rather than shedding everything. See
[pblock-privilege-drop-hardening.md](pblock-privilege-drop-hardening.md).

`brix_worker_user` **supersedes** pblock's `unpriv_user` for the worker uid:
de-escalation precedes pblock init, which then no-ops via its `geteuid() != 0`
guard — blobs still land `nobody`-owned. The pblock-drop and deescalate paths log
different messages; `test_pblock_privilege_drop.py` accepts either.

**Invariant / gotcha:** the worker cap-drop must **keep** `{SETUID, SETGID}` or
pblock/single uid-drops fail closed.

---

## Why (design rationale)

- **Harden before the early-return** so http-only workers (WebDAV/S3/cvmfs) are
  not silently exempt — the original bug.
- **Default-allow broker filter** trades a smaller guarantee for robustness: the
  broker's job is narrow, but a forgotten legit syscall must not brick it; only
  the never-legit set is killed.
- **Opt-in worker seccomp, ratchet-up-only** avoids breaking sites whose syscalls
  aren't covered, while making the strict posture available and monotonic within a
  master lifetime.
- **`allow_exec` default ON with an inverted ratchet** keeps proven exec features
  working by default while still giving operators a sticky, fail-secure `off`.
- **De-escalate on `CAP_SETUID`, not just euid 0**, because a capability-holding
  service account is root-equivalent; NNP covers the sudo/setuid-binary vector.

---

## Packaging / deployment (item 5 and follow-ups)

- `contrib/brix-cache.conf.example` documents the hardened systemd unit, the
  SELinux subpackage, and `brix_seccomp enforce` as the recommended posture, with
  `#brix_seccomp_allow_exec off;` shown as the opt-in strict setting; example uses
  `user brix` + `brix_worker_user brix`. Compiled seccomp default remains OFF.
- RPM `%pre` creates `brix-broker` (system user, nologin); conf example sets
  `brix_impersonation_broker_user brix-broker`.
- `packaging/brix-cache.service` adds mount-namespace hardening at the correct
  layer (a hardened worker lacks `CAP_SYS_ADMIN` to `unshare(2)`):
  `ProtectProc=invisible`, `ProtectHostname`, `ProtectClock`,
  `ProtectKernelLogs`, `ReadOnlyPaths=/etc/grid-security`.

### Deferred / not shipped active

- **SELinux broker-domain split** — the broker is a double-fork (no execve), so
  SELinux cannot `type_transition` it, and `dyntransition` is blocked by
  `typebounds` (the broker needs `setuid`, a superset of a tightened worker
  domain). A clean split needs re-architecting the broker to `execve` a dedicated
  entrypoint; the full design + ready-to-activate policy lives in
  `packaging/selinux/brix.te`. Meanwhile the worker/broker asymmetry stays at the
  DAC/cap + seccomp layer.
- **Seccomp-exec broker (Option B)** — route the fork+exec sites through an
  unprivileged allowlist broker (TOCTOU-safe, blocks arbitrary exec) with execve
  kept killed; planned in `docs/refactor/seccomp-exec-broker-plan.md`, not
  implemented (~impersonation-broker sized).
- Also deferred: mount namespace beyond the systemd layer, per-user upload
  quota / `RLIMIT_FSIZE`, flipping the compiled seccomp default to enforce.

---

## Tests

- `tests/test_privilege_hardening_root.py` (configs
  `nginx_hardening_root_webdav.conf`, `nginx_hardening_http_seccomp.conf`) —
  cap-drop, http-only worker seccomp-filterable, and
  `test_root_configured_worker_deescalates_to_nobody` (a `user root` worker is no
  longer observable as root: `Uid 65534` + no caps). Verified via
  `/proc/<pid>/status`.
- `tests/test_worker_deescalation_root.py` (config
  `nginx_worker_deescalate_root.conf`, `user root`) — drops to `nobody` by
  default / to a configured distinct account / **refuses** fail-closed on a
  missing account (worker exits fatal code 2, master listen socket stays
  tcp-ready, log has "refusing to serve").
- `tests/test_seccomp_tape_stub.py` (config `nginx_lc_frm_stub_seccomp.conf`) —
  `frm://stub` backend under `brix_seccomp enforce` (no allow_exec) → `Seccomp:2`
  + nearline recall serves bytes.
- `tests/test_seccomp_exec_frm.py` (config `nginx_lc_frm_exec_seccomp.conf`) — a
  mock POSIX-shell stage command fork+exec'd from `$BRIX_FRM_STAGECMD`:
  `test_exec_recall_works_under_enforce_by_default` (default allow_exec on) and
  `test_exec_recall_killed_under_enforce_with_allow_exec_off`.
- `tests/c/test_seccomp.c` — C unit test (needs `-DBRIX_HAVE_SECCOMP=1`):
  enforce+allow_exec permits `execve` and still kills `ptrace` (9/9).

**Known unrelated failure:**
`test_impersonation_gridmap_root.py::test_x509_dn_gridmap_write_owned_by_mapped_account`
fails "No protocols left to try" — a pre-existing GSI/X.509 breakage on the root
box (fails identically with the deescalate call env-gated off; sibling gridmap +
kernel_dac GSI tests pass), not caused by this work.
