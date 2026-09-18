# Phase 119 — macOS feature parity for BriX-Cache v2.1

**Status:** PLAN — no code proposed as landed by this document.
**One-sentence goal:** every feature the macOS port currently stubs, degrades or
silently no-ops, and for which Darwin offers a supported mechanism, works on
macOS in v2.1 with the same tests the Linux path passes; the residue that has
no Darwin mechanism fails closed, is documented, and is caught by CI.
**Scope:** `src/platform/darwin/`, the `#if defined(__APPLE__)` sites across
`src/` `shared/` `client/`, `config`, `client/Makefile`, `tools/ci/`, the test
harness. Linux behaviour does not change; every item is a Darwin branch that
today returns `ENOSYS`/`ENOTSUP`/`NGX_DECLINED`/`501`, or returns success while
doing nothing.
**Depends on:** the 2026-09-14 macOS-branch integration (BUILD.md §8), the
2026-09-15 Homebrew build audit (BUILD.md §12, `macos-quickstart.md`),
phase-116 (DNS seam — the resolver bridge item), phase-114 (credential artifact
lifecycle — the staging item).
**Supersedes:** the open items of `macos-support-v3.0.md` §"Phase 3/4/5" and
`macos-phase2-summary.md` §"Next Steps". Those documents describe the PAL
skeleton; this one closes the feature bodies behind it.
**Ground truth:** a source-level sweep on 2026-09-15 of all 132 platform-macro
sites across ~80 files (`__linux__` / `__APPLE__` / `BRIX_HAVE_*` /
`__has_include`), every `src/platform/darwin/*.c` stub, the build gates in
`config` and `client/Makefile`, and the test-side skips. Every row in §3–§6
was read-verified at the cited line; nothing is taken from the older macOS
docs, several of whose claims (thread-pool AIO fallback, sandbox "Phase 4",
"equivalent sendfile") are corrected here.

**Hard rules for every item below** (CLAUDE.md, coding-standards.md):

- Use existing HELPERS; no reimplemented path/auth/metrics/framing.
- Three tests per change: success + error + security-negative.
- No `goto`; no new globals; early-return style.
- Raw storage syscalls only in `src/fs/backend/` (INVARIANT 12); the Darwin
  PAL files are already inside the seam allow-list, new call sites are not.
- Every name resolution through `brix_dns_*` (INVARIANT 13).
- New `src/` `.c` files go in repo-root `config`; new `client/` `.c` files go
  in `client/Makefile`.
- A Darwin branch that cannot implement the contract **fails closed with the
  same errno the Linux branch would use for "unsupported"**. A success return
  with no effect is a defect (§2.2).

---

## 0. Executive summary

The macOS port builds and serves files. It does so by stubbing, not by porting:
of the 132 platform-gated sites, 41 replace a Linux mechanism with a return
code, 9 replace it with a **success return that has no effect**, and only ~20
replace it with the Darwin equivalent. The result is that a long list of
features that operators would reasonably expect to work on a Mac do not, and
several of the most important failures are invisible — the directive parses,
the log says nothing, and the feature is off.

Almost none of this is a platform limitation. Darwin has a supported API for
every item in §3 and §4. The port simply never got past the "compile it"
milestone. v2.1 gets it to "it works and the suite proves it".

The deliverable is five waves (§7). Wave A is small and must land first: it
turns every silent-success stub into a fail-closed one, and turns the CI
script that reports SUCCESS without compiling a single PAL file into one that
compiles the real module. Everything after that is feature restoration in
order of blast radius: security and auth (B), storage and protocol
correctness (C), telemetry and client tools (D), performance (E).

| Wave | Items | What comes back |
|---|---|---|
| A | §2 | honesty: fail-closed stubs, a CI that compiles Darwin, a status table that is true |
| B | §3.1–§3.6 | impersonation broker, WebDAV X.509/GSI auth, sandbox, no-new-privs, krb5 carry, secure env |
| C | §4.1–§4.9 | digest PUT, FRM `dread`, space reservation, block backend, atomic rename, dashboard files, memfile reopen, credential staging dir, anon-fd seam |
| D | §5.1–§5.7 | CMS load meter, TCP telemetry, resolver eventfd, FSEvents, automounter, `xrd mount`, dashboard passwords |
| E | §6.1–§6.5 | CRC32C on Apple Silicon, thread-pool AIO, kqueue read+write, F_RDAHEAD/F_NOCACHE hints, copyfile |

§8 is the list of things that **stay unsupported** and how each one is
reported. §9 is the test plan. §10 is the exit gate.

---

## 1. How the port fails today — the four shapes

Reading the 132 sites, every Darwin branch takes one of four shapes. Naming
them matters because the fix for each shape is different.

**Shape 1 — honest stub.** Returns `ENOSYS`/`ENOTSUP`/`NGX_DECLINED`. The
caller sees the failure. Examples: `brix_plat_splice`
(`src/platform/darwin/posix_wrapper.c:107`), `brix_aio_submit_read`
(`aio_wrapper.c:43`), `sd_posix_copy_range` (`sd_posix_io.c:101`), the
`RENAME_EXCHANGE` arms (`src/fs/path/beneath.c:522`). Fix: implement, or
leave and document (§8).

**Shape 2 — silent success.** Returns 0/`NGX_OK`/`1` and does nothing.
The caller believes the feature is on. Nine sites, all listed in §2.2. Fix:
implement in the wave it belongs to, **and in wave A change the stub to
fail closed** so nothing ships in the lying state.

**Shape 3 — wrong mechanism.** Calls a Darwin API with Linux semantics so it
fails at runtime, or substitutes an API with materially different semantics.
The broker peer-cred gate (`SO_PEERCRED` at `SOL_SOCKET`, `broker.c:54`),
`setresuid`→`seteuid` (`broker_creds.c:42`), `MNT_DETACH`→`MNT_FORCE`
(`brixautofs.c:144`), `sync_tree`→global `sync()` (`posix_wrapper.c:76`).
Fix: the correct Darwin call.

**Shape 4 — ungated Linuxism.** No platform guard at all; the code reads
`/proc/...` or a Linux-only ioctl and simply fails on Darwin. CMS meter
(`src/net/cms/meter.c:254-319`), digest PUT reopen
(`put_body_digest.c:155`), FRM exec fd hygiene (`sd_frm_exec.c:60`),
automounter `af_is_mounted` (`brixautofs.c:163`). Fix: a platform seam with
both implementations; the guard `check_pal_seam.py` is extended to catch
future `/proc` reads outside the PAL (§2.4).

---

## 2. Wave A — honesty first

### 2.1 Why this wave is separate

Every later wave is feature work that can slip. Wave A cannot, because until
it lands the repository **claims** things about macOS that are false: a CI
job that passes, a quickstart table that says "thread pool fallback" for AIO
when there is none, a `brix_seccomp enforce`-equivalent that returns success.
Wave A is one commit-sized batch and is the precondition for calling anything
after it "v2.1".

### 2.2 The nine silent-success stubs → fail closed

Each becomes the Linux "unsupported" errno until its wave lands. Where the
Linux side has no unsupported path (because Linux always supports it), the
Darwin stub logs at `emerg` and refuses to start when the directive is
present, matching the seccomp stub's "audit/enforce refuse to start; off is
a no-op" precedent (`config:406-411`).

| # | Site | Today | Wave A behaviour | Restored in |
|---|---|---|---|---|
| S1 | `src/platform/darwin/security_wrapper.c:60-91` `brix_security_init()` `enforce`/`default` | `free(ctx); return 0;` | `errno = ENOTSUP; return -1;` — caller refuses to start under `enforce`; `audit` logs a one-line notice that audit is unavailable | §3.3 |
| S2 | `security_wrapper.c:97-101` `brix_security_enable_audit()` | `return 0` | `ENOTSUP` | §3.3 |
| S3 | `security_wrapper.c:105-116` `brix_security_load_profile()` | `(void)path; return 0` | `ENOTSUP` | §3.3 |
| S4 | `src/auth/impersonate/broker_internal.h:73-88`, `lifecycle_worker.c:30-42` `prctl(PR_SET_NO_NEW_PRIVS)` | `return 0` | `PR_SET_NO_NEW_PRIVS` → `ENOTSUP`; `PR_GET_NO_NEW_PRIVS` → `-1` with `ENOTSUP`; the worker's no-new-privs assertion logs `warn` "unsupported on Darwin" rather than `notice` "set" | §3.4 |
| S5 | `src/protocols/webdav/postconfig.c:412+` `brix_webdav_postconfig_init` / `ngx_http_brix_webdav_postconfiguration` | `return NGX_OK` | delete the Darwin branch (§3.2 shows the Linux body compiles unchanged) | §3.2 |
| S6 | `src/protocols/webdav/darwin_config_stub.h` `brix_webdav_darwin_config_stub()` used by `module_directives_cert.c`, `postconfig_proxy_capath.c` | `return NGX_CONF_OK` for any directive | delete (§3.2) | §3.2 |
| S7 | `src/protocols/webdav/auth_cert.c:414-421` `webdav_nginx_verify_compatible()` | `return 1` "always compatible" | delete the Darwin branch; the Linux check compiles unchanged | §3.2 |
| S8 | `src/platform/darwin/posix_wrapper.c:51-57` `brix_plat_fadvise()` | `return 0` | keep returning 0 — `posix_fadvise` is advisory and the Linux contract permits a no-op — but the header comment at `platform_api_file.h` must say so and §6.4 maps the two hints Darwin does have | §6.4 |
| S9 | `src/platform/darwin/clonefile_optimized.c:160-186` `brix_plat_get_clone_stats()` | zero-filled struct, `return 0` | `ENOTSUP` so the metrics layer emits nothing instead of zeros (INVARIANT 8 — no misleading series) | §8 (stays) |

### 2.3 CI actually compiles Darwin

`tools/ci/verify_platform_builds.sh:86-127` compiles a ten-line hello-world
and prints `[SUCCESS]`. Replace `verify_darwin_build()` with:

1. `./configure --add-module=$REPO` against the host nginx tree given by
   `TEST_NGINX_SRC` (the same variable the PAL tests already use).
2. `make -j` and `objs/nginx -t` with `tests/configs/nginx_lc_cred_dir_default.conf`.
3. `make -C client` and `make -C client check` (the C unit binaries).
4. The `report_warnings()` hardcoded three-line list (`:169-182`) is replaced
   by a generated table: every `#if defined(__APPLE__)` site whose Darwin
   branch contains `ENOSYS|ENOTSUP|NGX_DECLINED|NGX_HTTP_NOT_IMPLEMENTED`
   is printed with file:line. This is the §8 residue, machine-derived, and
   the number must go **down** across waves (`check_ratchet_monotonic.py`
   pattern).

Off a Darwin host the function still skips (`:222-227`) — that is correct;
what it may no longer do is print SUCCESS.

### 2.4 Guard: no ungated `/proc` outside the PAL

Extend `tools/ci/check_pal_seam.py` with a rule: a string literal beginning
`/proc/` or `/sys/` in `src/` `shared/` `client/` is allowed only inside
`src/platform/linux/`, `client/lib/platform/linux/` (new, §5.5), or on a line
carrying `/* pal-seam-allow: <reason> */`. Baseline the current offenders
(§1 shape 4 list plus `runtime_server_backend_stage.c:37`,
`prepare_cmd.c:103`, `brix_fault_priv*.c`, `brixcvmfs_publish.c:46`,
`xrd.c:63`) into the ratchet file so the count can only fall.

### 2.5 The status table becomes true

`docs/01-getting-started/macos-quickstart.md` §"Known Limitations" is
rewritten from the §2.3 generated table plus §8. Specifically the rows
"io_uring → thread pool fallback" (there is no fallback until §6.2),
"seccomp → Phase 4 (sandbox_exec)" (sandbox returns success and does
nothing until §3.3), and "sendfile ✅ equivalent" (true) are corrected.
`src/platform/darwin/README.md` already says the honest thing; it gains a
pointer to this phase.

---

## 3. Wave B — security and authentication

### 3.1 Impersonation broker: peer-credential gate

**Today.** `src/auth/impersonate/broker.c:8-34` defines `SO_PEERCRED` as
`LOCAL_PEERCRED` and a fake `struct ucred {pid,uid,gid}`; `:54` calls
`getsockopt(conn_fd, SOL_SOCKET, SO_PEERCRED, ...)`. On Darwin
`LOCAL_PEERCRED` is at level `SOL_LOCAL` and fills `struct xucred`, so the
call fails and `:55` returns 0 — every connection refused. Because
`lifecycle_broker.c:177-188` deliberately resolves the allow-uid so the gate
is never 0, **impersonation is dead on arrival on macOS**, fail-closed but
silent.

**Fix.** A PAL entry `brix_plat_peer_uid(int fd, uid_t *uid, gid_t *gid)`:
Linux `SO_PEERCRED`; Darwin `getpeereid(3)` (which is `LOCAL_PEERCRED` done
right). `broker.c` calls the PAL entry; the fake struct and the `#define`
are deleted. Declared in `platform_api_security.h`.

**Tests.** `tests/test_impersonate_broker_gate.py` (exists for Linux):
success — allowed uid connects; error — gate enabled, peer uid mismatch →
refused with the existing audit line; security-neg — a socket that is not
`AF_UNIX` → refused (Darwin `getpeereid` returns `EINVAL`, must map to
refuse, never to "gate disabled"). C unit `tests/c/peer_uid_unit.c` over a
`socketpair`.

### 3.2 WebDAV X.509 / GSI client-certificate authentication

**Today.** Four files carry `#if !defined(__APPLE__) || !defined(__MACH__)`
around their **entire** implementation with a Darwin `#else` that no-ops:
`src/protocols/webdav/postconfig.c:3/412`, `module_directives_cert.c:3`,
`postconfig_proxy_capath.c:3`, and `auth_cert.c:101-116, 414-451`. The
stated reason ("nginx SSL module internals may differ on macOS") is not
true — the module links the same nginx `ngx_http_ssl_module.h` and the same
OpenSSL on both platforms. Net effect: `brix_webdav_cert_*`,
`brix_client_certificate_folder`, `brix_backend_ca_dir`, `proxy_certs=on`
and `ssl_verify_client` compatibility checking **all parse and none act**.
Worse: `postconfig.c:124` is the **only** place
`ngx_http_brix_webdav_handler` is pushed into `NGX_HTTP_CONTENT_PHASE`
(`rg` finds no other registration), so on a Darwin build the WebDAV
content handler is never installed and HTTP requests fall through to
nginx's static handler. `X509_V_FLAG_ALLOW_PROXY_CERTS` is never set, so
even with a handler **GSI proxy chains would be rejected**.

**Fix.** Delete the four Darwin branches and `darwin_config_stub.h`
(remove from `config:640`). Build. Nothing else is expected to change; if a
Darwin compile error appears it is fixed in place, not re-stubbed.

**Tests.** The existing `tests/test_webdav_x509*.py`, `test_gsi_proxy_*.py`
and `tests/clauses/` WLCG rows must pass on macOS unchanged. Add to
`tests/test_platform_darwin_helpers.py`: success — proxy cert chain accepted
on a Darwin build; error — expired proxy rejected with the same status as
Linux; security-neg — `ssl_verify_client off` plus `brix_webdav_cert_ca`
→ startup refused by `webdav_nginx_verify_compatible()` (the check S7
currently bypasses).

### 3.3 Sandbox: `sandbox_init` profile

**Today.** S1–S3. The Phase-4 note at `security_wrapper.c:118-142` already
names `sandbox_init()` and `.sb` profiles.

**Fix.** Implement `brix_security_init(mode)` on Darwin with
`sandbox_init_with_parameters()` (deprecated in the headers, still
functional and what Apple's own daemons use) and a profile shipped at
`src/platform/darwin/profiles/brix-worker.sb` derived from the seccomp
allow-list in `src/core/seccomp/seccomp_core.c:86-121` (same syscall
families: file I/O under the export roots, `AF_UNIX`+`AF_INET*` sockets,
no `process-exec` except the broker's spawn helper, no `mach-lookup` except
`com.apple.SecurityServer` for `SecRandomCopyBytes`). `audit` mode uses the
profile's `(deny default (with report))` form so violations log via
`sandboxd` without being blocked; `enforce` drops `(with report)`. The
profile path is a directive (`brix_sandbox_profile`) so operators can
override, mirroring `brix_seccomp`.

**Tests.** `tests/test_darwin_sandbox.py` (Darwin-only): success —
`enforce` starts and serves; error — a profile file that fails to parse →
startup refused with the parse message; security-neg — under `enforce`, an
injected `execve` from a worker (via the existing fault-injection hook)
returns `EPERM` and is logged. Plus `tests/c/sandbox_profile_unit.c`
compiling the profile through `sandbox_compile_file` on Darwin.

### 3.4 No-new-privs and the privilege model

**Today.** S4 fakes `prctl`. `broker_internal.h:21-33` maps
`setfsuid`/`setfsgid` to `seteuid`/`setegid` (process-wide, not
per-thread). `broker_creds.c:42-56` maps `setresuid` to `seteuid` **and
discards the saved uid**, so the drop is reversible. `:11-64` fabricates
Linux capability structs; `SYS_capset/capget` are `-1`.

**Fix.**
- `setresuid`/`setresgid`: Darwin has real `setresuid`? No — but it has
  `setuid(2)` which, when the caller is root, sets real, effective **and
  saved** uid (POSIX `_POSIX_SAVED_IDS` semantics, documented in
  `setuid(2)`). The Darwin arm calls `setgid`+`setgroups`+`setuid` in that
  order for a full drop and verifies with `getuid()==geteuid()==target` and
  a probe `seteuid(0)` that **must fail** with `EPERM`. That probe is the
  security-negative test.
- `setfsuid`: no per-thread analogue exists; the broker on Darwin runs the
  file operation in its own process after a full drop (the broker already
  is a separate process — `lifecycle_broker.c`), so `setfsuid` is not
  needed. The mapping macro is deleted and the Darwin branch of
  `imp_do_*` uses the full-drop helper. Document the difference in
  `impersonate.h`.
- Capabilities: the "non-root broker keeping only CAP_SETUID/SETGID"
  posture (`impersonate.h:226-231`) cannot exist. On Darwin the broker
  runs as root and the profile in §3.3 confines it. This is documented,
  not emulated.
- No-new-privs: Darwin's equivalent is the sandbox profile's
  `(deny process-exec*)` plus the fact that the worker never holds a
  saved root uid after §3.4's drop. `PR_GET_NO_NEW_PRIVS` on Darwin
  returns 1 **only** when §3.3 `enforce` is active, otherwise `ENOTSUP`.

**Tests.** `tests/test_release20_posix_cred_plane.py` (already has two
Darwin branches) gains: success — impersonated open as mapped uid works
end-to-end; error — mapping to a uid with no home → same errno as Linux;
security-neg — after the drop, `seteuid(0)` fails inside the broker child
(asserted via the existing `imp_call_status` probe op).

### 3.5 Kerberos credential carry and GSS import

**Today.** `src/auth/krb5/carry.c:1-3, 234-269` is a whole-file Darwin fork
returning `NGX_ERROR` because Heimdal lacks `gss_store_cred_into` and
`gss_krb5_import_cred`. `capture.c:19-25, 107-115` sets
`BRIX_SKIP_GSS_IMPORT`. But the build on this host already **requires**
MIT krb5 from Homebrew (`macos-build-workflow` memory, BUILD.md §12:
`PKG_CONFIG_PATH=$(brew --prefix krb5)/lib/pkgconfig`), and MIT has both
functions.

**Fix.** Gate on the library, not the OS: `config` probes
`gss_store_cred_into` via `pkg-config --exists mit-krb5-gssapi` (or a
compile test) and defines `BRIX_HAVE_GSS_STORE_CRED_INTO`. `carry.c` and
`capture.c` switch from `__APPLE__` to that macro. Heimdal builds keep the
stub (and it becomes fail-closed with a startup `emerg` when
`brix_krb5_delegate` is configured, per §2.2 policy).

**Tests.** `tests/_test_audit16s_krb5_delegate_arms_helpers.py` (already
ported to `CRED_STORE_BASE`) must pass on macOS with MIT krb5. Add:
success — forwarded TGT lands in the ccache and a downstream GSS init
succeeds; error — non-forwardable TGT → same `KRB5_*` error as Linux;
security-neg — ccache written 0600 under the §4.7 staging dir, never
readable by another uid (asserted with the existing `cred_dir_check`
harness in `tests/c/test_cred_stage.c`).

### 3.6 `secure_getenv` for the TPC token

**Today.** `src/tpc/outbound/tpc_token.c:65-70` maps `secure_getenv` to
`getenv`, losing the setuid/`AT_SECURE` guard.

**Fix.** Darwin arm: `issetugid(2)` — if it returns 1, return `NULL`,
else `getenv`. Three-line helper in `src/core/compat/`.

**Tests.** `tests/c/secure_getenv_unit.c`: success — normal process reads
the variable; error — unset variable → `NULL`; security-neg — the test
binary re-executed with a setgid bit (test harness already has
`run_suite_unprivileged.py` for privilege lanes) sees `NULL`.

---

## 4. Wave C — storage and protocol correctness

### 4.1 Digest-asserted WebDAV PUT

**Today.** `src/protocols/webdav/put_body_digest.c:155-171` reopens the
write-only staged fd through `/proc/self/fd/<fd>` to hash what was written;
on Darwin `open` fails and the code fails closed with **400 on every
digest-asserted PUT**. `src/fs/core/vfs_core.c:230-241` uses the same trick
for memfile re-read.

**Fix.** Do not reopen at all. The staged temp is opened by
`staged_open_posix` (`src/core/compat/staged_file.c`); open it
`O_RDWR` instead of `O_WRONLY` — the descriptor is private to the worker,
the file is 0600 and pre-commit, and nothing in the write path depends on
write-only. Then `brix_integrity_get_fd()` hashes over the same fd after
`lseek(0)`. This removes the procfs dependency on **Linux too** and the
`/proc/self/fd` string disappears from the tree (§2.4 ratchet −2).

**Tests.** `tests/test_webdav_put_digest.py` (exists): success — PUT with
`Digest: adler32=` verified on macOS; error — mismatching digest → 400 with
the existing body; security-neg — a digest header naming an algorithm the
server does not support → 400, not silent accept. Add a
`test_stage_cross_device_commit.py`-style case that the reopened fd sees
the bytes when the temp is on a different device than the export.

### 4.2 FRM tape `dread` spawn

**Today.** `src/fs/backend/frm/sd_frm_exec.c:60-87`: `__GLIBC_PREREQ` is 0
on Darwin so the `/proc/self/fd` branch runs, `opendir` fails, and
**`frm_exec_spawn()` always fails**. The same hygiene problem, less
severely, in `src/protocols/root/query/prepare_cmd.c:103-135` (brute-force
close loop) and `src/net/cms/perf_pgm.c:33-56` (closes 3..N where N is a
connection-count tunable reused as an fd ceiling).

**Fix.** Darwin has `posix_spawn_file_actions_addclosefrom_np` since
macOS 10.15. Gate `exec_fa_close_inherited()` on
`__has_include(<spawn.h>) && defined(__APPLE__) || __GLIBC_PREREQ(2,34)`.
Move the helper into `src/core/compat/subprocess.c` (which already owns
the `pipe2`/`SOCK_CLOEXEC` compat, `:19-30`) and make `prepare_cmd.c` and
`perf_pgm.c` call it, deleting their private loops.

**Tests.** `tests/test_frm_dread_stream.py` (exists, Linux): must pass on
macOS. Add `tests/c/spawn_hygiene_unit.c`: success — child sees only
0,1,2 plus the explicit pass-through fd; error — closefrom on an
already-closed fd is ignored; security-neg — a leaked listening socket fd
in the parent is **not** inherited (assert `fstat` fails in the child).

### 4.3 Space reservation before declared-size writes

**Today.** `src/fs/backend/posix/sd_posix_io.c:140-175` compiles out
`sd_posix_reserve()` (`fallocate(FALLOC_FL_KEEP_SIZE)`), so the
ENOSPC-at-open guarantee that pgwrite and PUT rely on is gone.

**Fix.** Darwin arm: `fcntl(fd, F_PREALLOCATE, &fst)` with
`fst_flags = F_ALLOCATECONTIG|F_ALLOCATEALL`, retry with `F_ALLOCATEALL`
only, `fst_posmode = F_PEOFPOSMODE`, `fst_length = size`. This does not
change `st_size`, matching `KEEP_SIZE`. Returns `ENOSPC` on a full volume.

**Tests.** `tests/test_declared_size_enospc.py` (exists): success —
reserve then write within the reservation; error — reserve past free space
→ `ENOSPC` at open, no partial file; security-neg — a reservation on a
path outside the export is refused by `resolve_path()` before `open()`
(INVARIANT 4), i.e. the reserve helper is never reachable with an
unresolved path.

### 4.4 Block-device backend capacity

**Today.** `BLKGETSIZE64` is gated out in `sd_block_ns.c:29-31, 116-123`,
`sd_block.c:36-38` and the client `vfs_block.c:36-38`; `st_size` of a
device node is 0 → `ENODEV` at init.

**Fix.** PAL entry `brix_plat_blockdev_size(int fd, off_t *bytes)`: Linux
`BLKGETSIZE64`; Darwin `DKIOCGETBLOCKCOUNT * DKIOCGETBLOCKSIZE` from
`<sys/disk.h>`. Both backends call it.

**Tests.** `tests/test_block_backend.py` (exists; uses a loop file on
Linux). On Darwin the fixture attaches `hdiutil attach -nomount ram://N`
and detaches in teardown: success — capacity equals the ram disk size;
error — a regular file passed as a "device" → capacity from `st_size`
(unchanged behaviour); security-neg — a device node the worker cannot
open → `EACCES`, never a zero-capacity "success".

### 4.5 Atomic rename: noreplace and exchange

**Today.** `src/fs/path/beneath.c:432-440` (`RENAME_NOREPLACE`) and
`:522-531` (`RENAME_EXCHANGE`), `broker_ops.c:255-300`, and
`sd_frm_exec.c:340-353` all return `ENOTSUP` on Darwin. Fail-closed and
correct, but WebDAV `MOVE` with `Overwrite: F`, the FRM two-name swap,
and the broker's impersonated rename are all unavailable.

**Fix.** Darwin has `renamex_np(2)` (`<sys/stdio.h>`, macOS 10.12+) with
`RENAME_EXCL` (= noreplace) and `RENAME_SWAP` (= exchange), and
`renameatx_np` for the `at` form. Both work on APFS and HFS+; on other
filesystems they return `ENOTSUP`, which is exactly the existing
fail-closed path. The three sites gain a Darwin arm calling
`renameatx_np`. Keep `errno` semantics identical to `renameat2`.

**Tests.** `tests/test_atomic_rename_native.py` and
`tests/test_frm_exchange_native.py` currently fake `__APPLE__` and assert
`ENOTSUP`; they are rewritten to assert the real behaviour on a real
Darwin host and to keep the `ENOTSUP` assertion only for a non-APFS
volume (fixture: `hdiutil` with `-fs MS-DOS`). Three tests each as today,
plus the WebDAV `Overwrite: F` clause rows in `tests/clauses/`.

### 4.6 Dashboard file browser and download

**Today.** `src/observability/dashboard/files.c:501-531` returns 501 on
Darwin. The Linux body needs `statx` for birth time and `brix_open_beneath`.

**Fix.** Birth time: Darwin `struct stat` has `st_birthtimespec`; add
`brix_plat_stat_btime()` to the PAL returning it on Darwin and the `statx`
value on Linux (the helper already exists in spirit in
`integrity_info.c:22-26` for `st_mtim`; consolidate). `brix_open_beneath`
already has a non-openat2 fallback (§4.9). Delete the Darwin branch.

**Tests.** `tests/test_dashboard_files.py` (exists): success — listing
shows birth time on macOS; error — path outside the export → 403; security-
neg — a symlink inside the export pointing outside → 403 via the confined
walk, on both platforms.

### 4.7 Credential staging directory on Darwin

**Today.** `src/core/compat/cred_stage.c:34-41` and
`src/core/config/shared_conf.h:24-28` use `/tmp/brix-creds` because there
is no `/dev/shm`. `/tmp` is world-writable and disk-backed; the per-uid
subdir plus `cred_dir_check` keeps it safe but the design depends on a
shared sticky root.

**Fix.** Use `confstr(_CS_DARWIN_USER_TEMP_DIR)` — the per-user 0700
directory macOS creates under `/var/folders/`. `BRIX_CRED_STAGE_BASE`
becomes a function `brix_cred_stage_base(char *out, size_t)` on Darwin
(compile-time constant on Linux, unchanged). The shared-root squatting
surface disappears; `cred_dir_check` is kept as defence in depth. The
harness constant `CRED_STORE_BASE` in `tests/brix_suite/settings_values.py`
resolves the same way. Operators who want RAM residency mount a ram disk
and set `brix_storage_credential_dir` — documented in the quickstart.

**Tests.** `tests/c/test_cred_stage.c:40, 143, 275, 345, 542` hardcode the
`/dev/shm/brix-creds.` prefix and would fail on macOS today; they are
changed to compare against `brix_cred_stage_base()`. `tests/test_credential_dir_default.py`
success/error/security-neg triple unchanged in meaning: created 0700
under the per-user temp dir; a pre-existing dir owned by another uid →
refused; a symlink at the path → refused.

### 4.8 Anonymous-fd seam and memfile reopen

**Today.** Two implementations of `brix_plat_anon_fd()`:
`shared/cvmfs/platform/platform.c:19-39` (honours `spill_dir`, tries
`O_TMPFILE`) and `src/platform/darwin/posix_wrapper.c:27-48` (ignores
nothing but defaults to `/tmp`, is the one the module links on Darwin per
`config:1020-1022`). `brix_plat_map_ro()`/`brix_plat_unmap()` therefore
have **no Darwin definition**, which blocks `shared/cvmfs/index/pathidx.c`
from ever entering the module source list on macOS.

**Fix.** One implementation in `shared/cvmfs/platform/platform.c`, built
on every platform; `posix_wrapper.c` drops its copy. Darwin default spill
dir is §4.7's per-user temp dir. This item was analysed separately on
2026-09-15: a pure-mmap or `shm_open` substitute is **not** viable because
every caller (`vfs_open_handle.c:172`, `pblock_pack.c:424`,
`http_serve_offload.c:128`, `_cas_pack_part2.c:241`) consumes the result
with `pread`/`pwrite`/`sendfile`, which Darwin POSIX shm descriptors reject
with `ENOTSUP`. mkstemp+unlink stays.

**Tests.** `tests/platform/test_anon_fd.py` (exists): add the Darwin arm —
success: fd is unlinked (no directory entry after return); error:
unwritable spill dir → falls to the default dir, never fails; security-neg:
the template is created 0600 and `FD_CLOEXEC` is set (assert via
`fcntl(F_GETFD)`).

### 4.9 Confined open on Darwin: `O_NOFOLLOW_ANY`

**Today.** Every `openat2(RESOLVE_BENEATH)` site falls back to the
segment-by-segment `O_PATH|O_DIRECTORY|O_NOFOLLOW` walk
(`resolve_confined_helpers.c:183, 218, 401`, `resolve_confined_ops.c:143`,
`beneath.c:169-175`). That walk is the correct pre-openat2 defence and is
kept. But `O_PATH` is mapped to `O_RDONLY` in eight files, which means the
"descriptor-only" opens now require read permission.

**Fix.** Darwin 11+ has `O_NOFOLLOW_ANY`, which rejects a symlink at **any**
component in one call; the Darwin arm of `brix_open_beneath` adds it to
the final `openat`, which closes the TOCTOU window between the walk and the
open. `O_PATH`: Darwin has no equivalent. The sites split two ways:
- **Directory anchors** (`http_rootfd.c:52`, `lifecycle_broker.c:286`,
  `beneath.c:125`, `broker_ops.c:134,138`): `O_RDONLY|O_DIRECTORY` is the
  correct substitute — the worker must be able to read the export root
  anyway. The mapping moves from the private `#define`s in eight files to
  one in `platform_api_file.h`.
- **Stat-only file handles** (`beneath.c:379,446,462`,
  `broker_ops.c:377`): `O_RDONLY` would fail on a file the worker may
  stat but not read. `beneath.c:398-408` already has
  `darwin_stat_resolve()` doing a confined `fstatat` for exactly this
  case; `broker_ops.c:377` (the impersonated `IMP_OP_STAT`/`LSTAT` arm)
  is switched to the same helper instead of an `O_PATH` open.

**Tests.** `tests/test_vfs_seam_platform.py` (exists, one Darwin branch):
success — confined open of a deep path; error — `..` escape → `EXDEV`
(same as Linux `RESOLVE_BENEATH`); security-neg — a symlink swapped in
**after** the walk and before the open (fault-injection hook exists in
`resolve_confined_helpers.c`) → `ELOOP` on Darwin via `O_NOFOLLOW_ANY`.

---

## 5. Wave D — telemetry and client tools

### 5.1 CMS load meter

**Today.** `src/net/cms/meter.c:254, 263, 317, 319` reads `/proc/loadavg`,
`/proc/meminfo`, `/proc/net/dev`, `/proc/vmstat` with no gate and no
fallback. On macOS `brix_cms_meter_sample()` reports **cpu=0 net=0 xeq=0
mem=0 pag=0**, so the node advertises itself as idle to every manager it
joins and receives a disproportionate share of redirects.

**Fix.** A `brix_plat_sysload_t` sample struct and
`brix_plat_sysload_sample()` in the PAL: Linux keeps the procfs parsers
(moved from `meter.c` to `src/platform/linux/sysload.c`); Darwin uses
`getloadavg(3)`, `host_statistics64(HOST_VM_INFO64)` for memory and paging
(`pageins`/`pageouts`), and `sysctl(NET_RT_IFLIST2)` summed over
non-loopback interfaces for bytes in/out. `meter.c` becomes
platform-free.

**Tests.** `tests/test_cms_meter.py` (exists): success — under the
`stress` fixture the reported cpu load rises on macOS; error — an
interface disappearing between samples → delta clamped to 0, not
negative; security-neg — the meter never reads a path from configuration
(no directive can point it at an arbitrary file), asserted by
`check_pal_seam.py` (§2.4). Interop: the CMS mesh tests in
`tests/brix_suite/mesh/` must show a non-zero load line in the stock
manager's `cmsd` log on macOS.

### 5.2 Per-connection TCP telemetry

**Today.** `src/observability/pmark/sockstats.c:34-83` returns
`NGX_DECLINED` on Darwin (no `TCP_INFO`).

**Fix.** Darwin `getsockopt(IPPROTO_TCP, TCP_CONNECTION_INFO, struct
tcp_connection_info)` provides `tcpi_rttcur`, `tcpi_txbytes`,
`tcpi_rxbytes`, `tcpi_txretransmitbytes`. Map into the existing
`brix_sockstats_t` fields; leave fields Darwin lacks as "absent"
(the struct already has an `have_*` mask for Linux kernels that lack
fields).

**Tests.** `tests/test_pmark_sockstats.py` (exists): success — RTT and
byte counters non-zero after a transfer; error — a closed socket →
`NGX_DECLINED`; security-neg — metric labels stay low-cardinality
(INVARIANT 8): `check_metric_cardinality.py` sees no new label.

### 5.3 Resolver-bridge wake descriptor

**Today.** `src/net/dns/resolve_bridge.c:40-70, 223-256` half-emulates
`eventfd` with a pipe and octal magic flags; `posix_wrapper.c:132-157`
`brix_plat_eventfd()` returns only the read end. The client already has
the correct pattern in `client/lib/core/aio/aio_engine.c:235-258`
(non-blocking `FD_CLOEXEC` pipe pair, `evfd`/`evfd_w`).

**Fix.** `brix_plat_wakefd_t {int r; int w;}` with `open`/`signal`/
`drain`/`close` in `shared/compat/wakefd.{h,c}` used by **both** the client
engine and the server bridge; Linux backs it with one `eventfd`
(`r == w`), Darwin with a pipe. `brix_plat_eventfd()` is deleted. INVARIANT
13 unaffected (the bridge still resolves through `brix_dns_*`).

**Tests.** `tests/test_dns_resolve_bridge.py` (phase-116): the three
existing tests pass on macOS. `tests/c/wakefd_unit.c`: success — signal
then drain returns once; error — signal on a full pipe returns `EAGAIN`
and is coalesced; security-neg — both ends are `FD_CLOEXEC`.

### 5.4 Filesystem watching via FSEvents

**Today.** `src/platform/darwin/fs_watcher.c` is per-fd `EVFILT_VNODE`:
one open fd per watched path, no recursion, "doesn't work well for
directories" (its own words, `:15`). The Linux side is inotify with
recursive directory watches used by the config-reload and CVMFS publish
paths.

**Fix.** `FSEventStreamCreate` on a dispatch queue with
`kFSEventStreamCreateFlagFileEvents|NoDefer|WatchRoot`, delivering into
the existing `brix_plat_fs_event_t` ring via the §5.3 wake fd so the nginx
event loop drains it. Keep the kqueue path for single-file watches (it is
lower latency). The `BRIX_EVENT_CREATE → NOTE_EXTEND` mismapping in
`event_wrapper.c` is fixed in passing (`NOTE_WRITE` on the parent
directory is the create signal).

**Tests.** `tests/platform/test_fs_watcher.py` (exists): success —
recursive create/modify/delete under a watched root delivered on macOS;
error — watching a non-existent root → `ENOENT` at register, not at first
event; security-neg — events for paths outside the root are never
delivered (FSEvents can report parent-dir flags; filter by prefix).

### 5.5 Client automounter, mount listing, self-path, boot id

**Today.**
- `client/apps/fs/brixautofs.c:163-176` `af_is_mounted()` parses
  `/proc/self/mountinfo`; on Darwin returns 0 for everything, so
  idempotency and unmount logic are broken.
- `:140-145` maps `MNT_DETACH` to `MNT_FORCE` — a forced unmount kills
  in-flight I/O; lazy detach defers it.
- `client/apps/diag/xrd_mount.c:247-341` prints "mount listing is only
  supported on Linux".
- `brixautofs.c:248`, `xrd.c:63` `readlink("/proc/self/exe")`.
- `brixcvmfs_publish.c:46` reads `/proc/sys/kernel/random/boot_id`.
- `brix_fault_priv*.c:150,131` read `/sys/class/net/<if>/mtu`.

**Fix.** New `client/lib/platform/{linux,darwin}/` (added to
`client/Makefile`, guard `check_client_build_coverage.py`) with:
`brix_cl_mounts_list()` (Linux mountinfo; Darwin `getmntinfo(3)`),
`brix_cl_self_exe()` (Linux `/proc/self/exe`; Darwin
`_NSGetExecutablePath` + `realpath`), `brix_cl_boot_id()` (Linux boot_id;
Darwin `sysctlbyname("kern.bootsessionuuid")`), `brix_cl_if_mtu()` (Linux
sysfs; Darwin `ioctl(SIOCGIFMTU)`). `MNT_DETACH`: Darwin has no lazy
detach; the automounter's EBUSY retry loop on Darwin retries `unmount(0)`
with backoff and only escalates to `MNT_FORCE` after the configured
grace, logging that it did — never as the first attempt.

**Tests.** `tests/test_brixautofs.py` and `tests/test_xrd_mount.py`
(exist): the same triples on macOS with macFUSE; `xrd mount` lists the
mounted xrootdfs on Darwin. `client/tests/c/platform_unit.c`: success —
self-exe resolves to the running binary; error — `mounts_list` with a
too-small buffer → `ERANGE`; security-neg — `boot_id` output is exactly 36
chars and contains no newline (it is used in a path).

### 5.6 `xrd` interface diagnostics

Covered by §5.5's `brix_cl_if_mtu()`; the two `brix_fault_priv*` sites call
it. No separate item.

### 5.7 Dashboard password hashes

**Today.** Darwin `crypt(3)` is DES-only. `dashboard_auth_creds.c` will
never verify `$6$` (SHA-512-crypt) or `$2b$` (bcrypt) entries, and nothing
says so — a `$6$` line simply fails auth.

**Fix.** Ship SHA-crypt (`$5$`/`$6$`, the Ulrich Drepper reference
algorithm, public domain) in `shared/compat/sha_crypt.c` and use it on
every platform for `$5$`/`$6$` so Linux stops depending on libcrypt for
those too. `$2b$` stays unsupported everywhere (it is today) and is
rejected at **config load** with a message naming the line, instead of at
login.

**Tests.** `tests/test_dashboard_auth.py` (exists): success — a `$6$`
entry verifies on macOS; error — a `$2b$` entry → startup refused with the
line number; security-neg — verification is constant-time
(`tests/c/sha_crypt_unit.c` compares timing of a correct vs wrong
password over 10k iterations, asserts ratio < 1.05, matching the existing
`brix_consttime_eq` test pattern).

---

## 6. Wave E — performance

### 6.1 Hardware CRC32C on Apple Silicon

**Today.** `config:1021-1033` compiles `src/platform/linux/crc32c_arm64.c`,
`checksum_neon.c`, `arm64_crypto.c` only on Linux;
`src/core/compat/crc32c_hw.c:26` is `#ifdef __x86_64__` only. On arm64
macOS `brix_crc32c_extend` uses the **software table** — directly on the
pgread/pgwrite per-page CRC path (INVARIANT 1) and every TPC
copy-with-checksum. `checksum_accelerate.c` is a float `vDSP_sve` sum with
a documented 24-bit precision loss (`:79-82`) and is **not** a substitute
for any wire checksum; `apple_silicon.c:158-172` `memcpy/memset_accelerate`
drop tail bytes for lengths not a multiple of 4.

**Fix.**
- Move `crc32c_arm64.c` and `checksum_neon.c` from `src/platform/linux/`
  to `src/platform/arm64/` and build them on any `__aarch64__`. The
  intrinsics (`__crc32cd`, NEON) are identical; only detection differs:
  Linux `getauxval(AT_HWCAP)`, Darwin `sysctlbyname("hw.optional.armv8_crc32")`
  — and every Apple Silicon chip has it, so the Darwin probe may return 1
  unconditionally with a comment.
- Fix the `#include` inside a function body at `crc32c_arm64.c:236-237`
  while moving it.
- Delete `checksum_accelerate.c`'s float checksum and the tail-dropping
  `memcpy/memset_accelerate` (nothing on the wire path calls them;
  verified by `rg`). If Accelerate has no remaining caller, drop
  `-framework Accelerate` from `config:118`.
- `client/Makefile:28-37` gains an `apple_silicon` `BRIX_OPTIMIZE`
  profile matching `config:255-257`.

**Tests.** `tests/c/crc32c_unit.c` (exists): success — hardware and
software paths agree on the 1 MiB corpus on arm64 macOS; error — a
misaligned tail (length ≡ 1..7 mod 8) agrees; security-neg — the pgread
per-page CRC over a page with a flipped bit is detected on the hardware
path (`tests/test_pgread_crc.py` on Darwin arm64). Benchmark line in
BUILD.md: table vs hardware MB/s on M-series.

### 6.2 Async disk I/O: thread pool first, kqueue second

**Today.** `src/platform/darwin/aio_wrapper.c` returns `-1`/`-ENOSYS` for
init/submit/wait. The quickstart claims a "thread pool fallback"; there is
none — the header comment says nginx's thread pool API is not used either.

**Fix, step 1 (v2.1):** wire the Darwin `aio_wrapper.c` to
`ngx_thread_pool_run` exactly as the Linux non-io_uring path does (the
selector in `src/fs/vfs/` already falls back to the pool when io_uring is
absent — Darwin just never implemented the pool arm). nginx's thread pool
works on macOS. This is the "~15–20 % on large reads" configuration the
docs already describe.
**Step 2 (v2.2, out of scope here):** a kqueue + pool engine; noted so
nobody designs step 1 in a way that blocks it.

**Tests.** `tests/c/aio_smoke.c`, `aio_resil.c`, `aio_waitresp.c` (exist,
Linux) run on macOS: success — 64 concurrent reads complete; error — a
read past EOF returns 0 bytes, not error; security-neg — a submit with a
buffer outside the request pool is refused (the existing bounds check).

### 6.3 kqueue: read and write on one descriptor

**Today.** `event_wrapper.c:44-80` registers `EVFILT_READ` **or**
`EVFILT_WRITE` via `if/else if`; a caller asking for both silently gets
read only. The client's `epoll_compat.c` does it right (two `kevent`
entries, coalesced).

**Fix.** Register both filters when both flags are set; coalesce on wait.
Or delete `event_wrapper.c` and use the client shim from `shared/` — the
client's is the more complete of the two and has tests. Preferred: move
`epoll_compat.{h,c}` to `shared/compat/` and have both link it.

**Tests.** `tests/platform/pal_cases_integration_io.py` (exists, skips
today when `brix_plat_epoll` is unavailable): success — read+write
readiness on a socketpair; error — `EBADF` on a closed fd; security-neg —
an fd registered by one worker is not visible in another's set (separate
kqueues per worker).

### 6.4 File access hints

**Today.** `brix_plat_fadvise()` is a no-op (S8).

**Fix.** `POSIX_FADV_SEQUENTIAL`/`WILLNEED` → `fcntl(F_RDAHEAD, 1)`;
`POSIX_FADV_RANDOM` → `F_RDAHEAD, 0`; `POSIX_FADV_DONTNEED`/`NOREUSE` →
`F_NOCACHE, 1` for the remainder of the descriptor's life (Darwin has no
range form; document). `sync_tree` (`posix_wrapper.c:76-83`): Darwin has
no `syncfs`. Its sole caller is the CVMFS publish commit
(`shared/cvmfs/publish/publish.c:313`), which passes the repository root
fd and wants that tree durable, not the whole machine. The Darwin arm
becomes `fcntl(dirfd, F_FULLFSYNC)` after the per-file fsyncs the commit
already issues; the global `sync()` is dropped.

**Tests.** `tests/platform/test_pal_api.py`: success — hint returns 0 on a
regular file; error — hint on a socket → `ENOTTY`, mapped to the Linux
`ESPIPE`; security-neg — none needed (advisory), the third test asserts
the hint never changes `st_size` or content.

### 6.5 Kernel copy for file-to-file paths

**Today.** `sd_posix_copy_range()` → `ENOSYS`; the VFS uses its pread/pwrite
loop. `brix_plat_copy_range` (posix_wrapper.c:116) is an `ENOSYS` stub
while the differently-named `brix_platform_copy_range` (copy_range.c:20) is
the 256 KB loop — two symbols, one stub. `apple_silicon.c:243-267`
clones only whole files and returns `ENOSYS` otherwise.

**Fix.** One Darwin `sd_posix_copy_range()`: if `in_off==0 && len ==
st_size` and same APFS volume → `fclonefileat` (zero-copy, instantaneous);
else `fcopyfile(in, out, NULL, COPYFILE_DATA)` after `lseek` on both
(kernel-side loop, no user copy); else the pread/pwrite loop. Delete
`brix_plat_copy_range` and `brix_platform_copy_range` duplicates; the
`apple_silicon.c` clone helpers with hardcoded syscall numbers
(`syscall(356/357)`, `:194-236`) are deleted in favour of
`<sys/clonefile.h>`, which `clonefile_optimized.c` already includes.
Socket-to-socket proxy relay (`events_splice.c`) stays buffered: Darwin
has no `splice`, and this is listed in §8.

**Tests.** `tests/test_vfs_copy_range.py` (exists): success — whole-file
copy on APFS is a clone (assert `st_blocks` shared via
`fcntl(F_LOG2PHYS)` or the `du` delta); error — cross-volume copy falls to
`fcopyfile` and is byte-exact; security-neg — a destination outside the
export is refused by the VFS policy kernel before any copy primitive runs
(INVARIANT 12: `EROFS` for a read-only export, never `EACCES`).

---

## 7. Sequencing

```
A ─┬─ B.1 broker peer-uid ──┬─ B.4 privilege model ── C.5 rename (broker arm)
   │                        └─ B.3 sandbox ────────── B.4 no-new-privs
   ├─ B.2 webdav x509 (delete stubs) ── B.5 krb5 carry ── B.6 secure env
   ├─ C.7 staging dir ── C.8 anon-fd seam ── C.1 digest PUT
   ├─ C.2 FRM spawn (subprocess.c) ── D.3 wakefd ── D.4 FSEvents
   ├─ C.3 F_PREALLOCATE · C.4 blockdev · C.6 dashboard files · C.9 O_NOFOLLOW_ANY
   ├─ D.1 CMS meter · D.2 TCP_CONNECTION_INFO · D.5 client platform lib · D.7 sha-crypt
   └─ E.1 CRC32C arm64 · E.2 thread-pool AIO · E.3 kqueue rw · E.4 hints · E.5 copy
```

A is one batch. B.1, B.2 and C.1 are each a day and remove the three most
user-visible breakages (impersonation, grid auth, digest PUT); land them
next. Everything else is independent and can proceed in parallel. E.2 is
the largest single item and the only one with an open design question
(step 2), so it goes last.

---

## 8. What stays unsupported in v2.1, and how it is reported

Every row here is emitted by the §2.3 generated table and appears in the
quickstart "Known Limitations" verbatim. None returns success.

| Feature | Linux mechanism | Why not on Darwin | Darwin behaviour |
|---|---|---|---|
| io_uring disk engine | `io_uring` | no kernel equivalent | thread pool (§6.2); `BRIX_ENABLE_IO_URING` ignored with a configure notice |
| seccomp-BPF | `libseccomp` | no kernel equivalent | `brix_seccomp audit\|enforce` refuses to start (already); `brix_sandbox_profile` is the Darwin analogue (§3.3) |
| memfd sealing | `F_ADD_SEALS` | none | pblock read-intent fd unsealed; comment kept at `pblock_pack.c:439` |
| `setfsuid` per-thread identity | `setfsuid` | none | broker does a full drop in its own process (§3.4) |
| non-root broker with retained capabilities | `capset` | none | broker runs as root under the §3.3 profile; `impersonate.h` documents |
| IPv6 flow-label marking (SciTag) | `IPV6_FLOWLABEL_MGR` | none | `flowlabel.c` returns `NGX_DECLINED`; pmark falls back to the firefly UDP path already implemented |
| socket-to-socket zero-copy relay | `splice` | none | buffered relay; `events_splice.c` stays compiled out |
| `copy_file_range` for arbitrary ranges | `copy_file_range` | none | `fcopyfile` / clone / loop (§6.5) |
| `posix_fadvise` range hints | `fadvise` | `F_RDAHEAD`/`F_NOCACHE` are per-fd | §6.4 mapping, per-fd only |
| `syncfs` | `syncfs` | none | `F_FULLFSYNC` on the dir fd (§6.4) |
| clone-space statistics | `FIEMAP` | no public API | `ENOTSUP` (S9) |
| `perf_events` counters | `perf_event_open` | needs entitlement | `brix_apple_perf_*` return `ENOTSUP`; the zero-filling stubs at `apple_silicon.c:312-346` are made honest in wave A |
| CephFS / librados backend | `libcephfs` | no macOS build | configure disables; `brix-tools` Ceph utilities not built |
| VOMS | `libvomsapi` | no macOS build | `host_caps.py` drops `vo-acl`; tests skipped with reason |
| LD_PRELOAD POSIX shim | glibc symbol aliases | needs a `DYLD_INTERPOSE` port | not built on Darwin (`client/Makefile:219`); tracked for v2.2 |
| ELF link hardening (`-z relro/now/noexecstack`), `-fcf-protection`, `-fstack-clash-protection` | GNU ld / ELF | Mach-O has no RELRO; ld64 rejects | dropped by `config:76-83, 131-137`; document that Darwin hardening is ASLR + code signing + the §3.3 profile |

---

## 9. Test plan

**Principle.** No new test file asserts "Darwin returns `ENOTSUP`" for a
feature this phase implements. The three existing "native" tests that fake
`__APPLE__` on Linux (`test_atomic_rename_native.py`,
`test_frm_exchange_native.py`, `test_platform_darwin_helpers.py`) are
rewritten to run on a real Darwin host and to skip elsewhere; their Linux
run keeps only the compile-adapter checks.

**Lanes.**

1. **Unit C** — every new PAL entry gets a `tests/c/*_unit.c` or
   `client/tests/c/*_unit.c` with the success/error/security-neg triple,
   built by `make -C tests/c` on both platforms.
2. **Pytest, Darwin host** — the full `tests/` suite under
   `run_suite_unprivileged.py` on this Mac (Intel) and on an Apple
   Silicon host. The recorded skip list must contain **only** §8 reasons
   plus missing third-party daemons (`host_caps.py`).
3. **PAL suite** — `tests/platform/` on Darwin with `TEST_NGINX_SRC`
   set; the `pal_cases_integration_*` skips for epoll, sendfile, xattr
   must clear (§6.3, existing sendfile wrapper, `xattr_compat.h`).
4. **Interop** — `tests/brix_suite/mesh/` CMS meshes against stock
   `cmsd` on macOS show a real load line (§5.1); the WLCG clause rows in
   `tests/clauses/` pass on a Darwin build (§3.2).
5. **Guards** — `check_pal_seam.py` (§2.4 rule), `check_config_coverage.py`
   and `check_client_build_coverage.py` (new files), `check_vfs_seam.py`
   (new raw syscalls only in `src/fs/backend/` and the PAL allow-list),
   `check_dns_seam.py` (§5.3 touches the resolver bridge),
   `check_metric_cardinality.py` (§5.2), `check_ratchet_monotonic.py` on
   the §2.3 residue count.

**Recorded results.** BUILD.md gains §13 "macOS v2.1 validation" with the
same shape as §8/§12: host, toolchain, configure line, `make` result,
`nginx -t`, suite pass/skip/fail counts, and the §2.3 table as it stood at
the run.

---

## 10. Exit gate for v2.1

All of the following, on an Intel and an Apple Silicon host:

- `tools/ci/verify_platform_builds.sh` compiles the module and the client
  from source and passes `nginx -t` (§2.3).
- The §2.3 generated residue table equals §8 exactly — no other
  `ENOSYS|ENOTSUP|NGX_DECLINED|501` Darwin branch exists.
- Zero silent-success stubs: `rg` for `return 0;` / `return NGX_OK;` /
  `return 1;` inside a `__APPLE__` branch with no side effect finds only
  `brix_plat_fadvise` (documented advisory no-op) — enforced by a
  `check_pal_seam.py` rule.
- The pytest suite skip list on macOS contains only §8 reasons and
  missing daemons.
- `tests/c/test_cred_stage.c` passes on macOS (§4.7).
- The impersonation, WebDAV X.509, digest-PUT, FRM `dread`, CMS mesh,
  block-backend, atomic-rename, dashboard-files, automounter and
  `xrd mount` test files pass on macOS without a Darwin-specific skip.
- pgread/pgwrite CRC32C on Apple Silicon runs the hardware path
  (`tests/test_pgread_crc.py` asserts the `crc32c_impl` metric label is
  `hw`).
- The quickstart "Known Limitations" table is generated, not hand-written,
  and matches §8.
- `docs/09-developer-guide/agent-guide-extended.md` OP→FILE tables gain
  the PAL entries introduced here; `coding-standards.md` gains the
  "Darwin branch fails closed, never succeeds silently" rule from §2.2.
