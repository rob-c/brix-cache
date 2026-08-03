# Host-Root Grid-Mapfile Impersonation Ownership Suite

A privileged, real-root test suite that proves `brix_impersonation map` lands backend
files owned by the **real local UNIX account** an authenticated identity maps to through a
real grid-mapfile — with kernel DAC actually enforcing per-identity separation.

## Context

`brix_impersonation map` (`src/auth/impersonate/`) makes the nginx **master run as root**
and spawn a double-forked privileged broker that `setfsuid()`/`setfsgid()`s per request to
the local account an authenticated identity resolves to, so backend files land owned by
that real UNIX user. Kernel DAC is the enforcer: the broker holds only
`CAP_SETUID`/`CAP_SETGID`, never `CAP_DAC_OVERRIDE`.

Before this suite, nothing launched the real nginx binary **as host root** with a
**grid-mapfile** and verified real on-disk uid/gid:

- `tests/userns/` proves ownership WITHOUT real root (unprivileged user namespace; drives
  the broker C directly / launches nginx in-ns; maps token `sub` via `getpwnam` — no gridmap).
- The multi-user conformance fleet (`tests/mu_authz_lib/`, `nginx_mu_*` / `multiuser/*_noimp.conf`)
  runs `brix_impersonation off` and only checks authz verdicts; `test_mu_impersonation_e2e.py`
  targets a `ROOT_CACHE` port the fleet never starts, so it is effectively inert.

This suite fills that gap. Added 2026-07-19.

## What it asserts

Launches the real nginx binary as host root via the registry `LifecycleHarness`, then maps:

- an incoming **WLCG token** (WebDAV PUT), and
- an **X.509 GSI proxy leaf DN** (`root://`)

through a real grid-mapfile to real local accounts (`brixgm_alice` / `brixgm_bob` /
`brixgm_squash`, created with `useradd -o -u` at fixed `uid == gid`), and asserts:

- the written backend file's real `st_uid` / `st_gid`, with no group/other write bit;
- per-identity **kernel DAC deny** (e.g. alice's private `0600` object is unreadable by bob);
- the **reserved-id floor** — a gridmap entry to the reserved `root` account never yields
  uid 0; any resolved uid/gid below `brix_idmap_min_uid` (hard-clamped ≥ 1000) is refused,
  squashing to `brix_idmap_default_user` if set, else hard-DENY (403, no file);
- **squash** to `brixgm_squash` for unmapped principals when a default_user is set;
- **fail-closed deny** for unmapped / reserved principals when no default_user is set.

Backend create mode is `0600` for WebDAV, `0644` for `root://`. The export must be `0777`
with world-traversable ancestors, because both the `nobody` worker and the broker (running
as the mapped user) need to reach it.

## The test suite: files + run command

- `tests/test_impersonation_gridmap_root.py` — the suite (currently 9 test functions).
  Every test is `@pytest.mark.privileged` (conftest auto-marks privileged tests serial) and
  `skipif(os.geteuid() != 0)`.
- `tests/impersonation_gridmap_helpers.py` — account provisioning + broker reaping.
  `ACCT_PREFIX = "brixgm_"`; creates `brixgm_<name>` nologin system users at fixed
  `uid == gid` via `useradd -M -N -o -u …`; crash-safe idempotent reap of all `brixgm_*`
  accounts. Exports `reap_broker(sock_path)` (defined at
  `tests/impersonation_gridmap_helpers.py:215`).
- `tests/configs/nginx_impersonate_gridmap_webdav.conf` — WebDAV PUT server, token `sub`
  principal.
- `tests/configs/nginx_impersonate_gridmap_root.conf` — `root://` GSI server, proxy leaf DN
  principal.

Both configs place the impersonation directives in the `stream {}` block
(`brix_impersonation map`, `brix_impersonation_socket`, `brix_impersonation_export`,
`brix_gridmap`, `brix_idmap_min_uid 1000`, optional `brix_idmap_default_user`).

Run privileged:

```
sudo -E env PYTHONPATH=tests pytest tests/test_impersonation_gridmap_root.py -v
```

Off a root host every test skips cleanly (via the `skipif`), so the suite is inert in the
ordinary non-root CI lane.

Launch/teardown helpers live in `tests/server_launcher.py`: `LifecycleHarness`,
`launch_fleet_nginx()` (`:75`), `render_nginx()` (`:570`), `nginx_test()` (`:634`),
`register()` (`:1093`).

## Gotchas

Two non-obvious integration gotchas that cost real debugging:

1. **Launch — the broker holds the launcher's stderr pipe open.**
   `brix_impersonation map` double-forks the privileged broker during `init_module`
   (before nginx daemonizes), so it inherits and holds the launcher's stderr pipe open
   forever. `harness.start()` (which uses `capture_output=True` and waits for EOF) HANGS.
   Fix: render + validate via `harness.register` / `launcher.render_nginx` /
   `harness.nginx_test`, then launch through the registry's detached seam
   `launch_fleet_nginx()` (`start_new_session`, inherited fds). `nginx -t` itself does NOT
   spawn the broker, so validation is safe.

2. **Teardown — the broker leaks past `nginx -s quit`.**
   The broker runs in its OWN session (init-reparented), so `nginx -s quit` on the master
   (what `harness.close()` does) reaps master + workers but LEAKS the broker. It records its
   pid in `<impersonation_socket>.pid`; reap it directly via `reap_broker`. The broker's pid
   is the original `nginx -p …` argv process (PPID 1); the master is the separate
   `nginx: master process`.
