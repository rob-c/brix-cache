# `tests/userns/` — user-namespace impersonation tests (phase 40)

End-to-end tests for the **per-request UNIX impersonation broker**
(`src/auth/impersonate/`). They live in their **own sub-folder, independent of the
main test suite**, because they need capabilities the rest of the suite does not
— and must **not** trigger the nginx server-fleet bring-up that
`tests/conftest.py` performs.

## Why a separate folder

The security properties of the broker (files owned by the *mapped* user, the
mapped user's kernel **DAC enforced**, no credential leak between requests) can
only be proven by creating files owned by **several distinct uids** and having the
broker switch between them. That is normally root-only. Instead these tests run
the whole stack inside an **unprivileged user namespace** with a **subuid range
map**, so the test process is in-ns root over a private band of uids and the
broker can genuinely `setfsuid()` to mapped users **with zero real privilege**.

A local `pytest.ini` + empty `conftest.py` make `pytest tests/userns/` resolve
its rootdir here, so the parent `tests/conftest.py` (which runs
`manage_test_servers.sh start-all`) is **not** loaded.

## Requirements

| Requirement | Why | If missing |
|---|---|---|
| Unprivileged user namespaces (`CLONE_NEWUSER`) | become in-ns root with no real privilege | test **skips** |
| `newuidmap` / `newgidmap` (the `uidmap` package, setuid-root) | install a subuid **range** map (util-linux < 2.38 has no `unshare --map-users`) | test **skips** |
| `/etc/subuid` + `/etc/subgid` range for the invoking user | the band of uids the broker impersonates | test **skips** |
| C compiler + nginx source tree (`TEST_NGINX_SRC`, default `/tmp/nginx-1.28.3`) | compile the driver against the real broker/client/idmap `.c` | test **skips** |

Everything is a graceful **skip** (never a failure) when unavailable, so the test
is CI-safe on hosts without userns.

No `nss_wrapper` is needed: the driver bind-mounts a fake `/etc/passwd` +
`/etc/group` inside its private mount namespace so `getpwnam` resolves the test
principals to in-ns uids.

## Running

```bash
# via pytest (skips cleanly if prerequisites are missing)
pytest tests/userns/

# or directly, for the full per-assertion PASS/FAIL trace on stderr
tests/userns/run.sh
```

Override the nginx source tree if needed: `TEST_NGINX_SRC=/path/to/nginx pytest tests/userns/`.

## What it asserts

`c/userns_broker_test.c` forks the **real** privileged broker
(`xrootd_imp_broker_run`) on an `AF_UNIX` socket and drives the **real** worker
client (`xrootd_imp_*`) through the wire protocol — including `SCM_RIGHTS` fd
passing — covering:

- **Ownership** — a file created via the broker as `alice` is owned `alice:alice`,
  not the worker; `STAT` reports the mapped owner.
- **DAC enforcement** — `alice` is denied (`EACCES`) writing into `bob`'s `0700`
  directory, while `bob` succeeds. This only holds because the broker dropped
  `CAP_DAC_OVERRIDE` — it is the proof that cap-dropping works.
- **Supplementary groups** — `alice` (member of group `shared`) may write a
  `0070` group-only directory; `bob` (not a member) is denied — proving
  `setgroups` is applied.
- **Confinement** — `../` traversal and a `/esc -> /etc` symlink escape are both
  blocked (`RESOLVE_BENEATH` re-applied broker-side).
- **Deny policy** — an unmapped principal, a uid-0 principal, and a
  below-`min_uid` principal are all denied.
- **Squash** — with `default_user = alice`, an unmapped principal is squashed and
  its file owned by `alice`.
- **No credential leak** — two client processes interleaving `alice`/`bob` opens
  against the single broker: every file ends up owned by the correct uid (the
  serialized broker never bleeds `setfsuid` across requests).
- **Mutating ops** — `rename` / `link` / `truncate` / `chmod` / `unlink` /
  `rmdir` under impersonation.

## Full-stack red-team (`test_e2e_redteam.py`)

The micro test above forks the broker directly. The **red-team** test boots the
**real nginx binary** with `xrootd_impersonation map` inside the namespace — real
master/worker/broker processes, real `init_module` broker spawn, real svc-uid
workers, real **token-authenticated WebDAV** traffic — and tries to break the
permissions model end-to-end. It is the pseudo-production check for *module
interactions* that the micro tests cannot see (lifecycle spawn, the auth →
identity → dispatch → principal-hook → broker chain, concurrency across real
workers). It runs in **< 1 s** so it is cheap to run regularly.

The battery (each a real HTTP request as a distinct ES256-token identity):

- **Baseline** — `alice` PUT → `201`, file owned `alice:alice` (not the svc
  worker, not root): exercises the *entire* real chain in one assertion.
- **Escalation denied** — tokens for `root` (uid 0), a sub-1000 uid, the **worker
  service account**, a member of the forbidden `docker` group, and an **unmapped**
  principal — each fully write-authorized — are all refused and create no file.
- **DAC** — `alice` cannot read `bob`'s `0700`-dir file (`403`).
- **Confinement** — a `/escape -> /etc` symlink GET and `../` PUTs do not escape.
- **No credential leak** — **24 concurrent interleaved** `alice`/`bob` PUTs across
  the real worker: every file ends up owned by the correct uid.
- **Confused deputy** — no worker/broker identity leaks into created-file owner.

> This test found (and the fix is included) a real cross-feature bug: checkpoint
> recovery scanned the whole export *as the worker uid* at startup and fatally
> aborted on a per-user `0700` private dir — impossible to run impersonation with
> private user dirs. The scan now skips inaccessible/transient dirs.

## Files

| File | Purpose |
|---|---|
| `c/userns_broker_test.c` | the namespace launcher + broker fork + client assertions (micro) |
| `c/userns_exec_launcher.c` | generic userns launcher (range-map + bind-mount passwd/group, then exec) |
| `test_userns_impersonate.py` | micro broker test (compile + run + skip logic) |
| `test_creds_guard.py` | reserved-id predicate unit test |
| `test_impersonate_config.py` | `nginx -t` mode-validation |
| `e2e_redteam.py` | the red-team orchestrator (runs as in-ns root: mints tokens, writes config, boots nginx, attacks, asserts) |
| `test_e2e_redteam.py` | pytest wrapper for the full-stack red-team |
| `run.sh` | manual compile-and-run with full stderr trace |
| `pytest.ini`, `conftest.py` | make this directory a standalone pytest root |
