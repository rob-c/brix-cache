# Default Gateway Write Staging

*Design/decision record — landed 2026-07-20 (two sessions).*

## Context

A brix export can be configured as a **writable gateway** in front of a
whole-object remote `brix_storage_backend` — an `http://`, `https://`, or
`s3://` origin that stores each object as one indivisible blob (no partial /
byte-range write semantics). Such a backend cannot absorb streaming random
writes directly: the object has to be assembled locally and flushed back as a
whole. brix already ships a stage tier (`sd_stage`) that can do exactly this
spooling, but historically the operator had to configure a stage store by hand.
A writable whole-object gateway with **no stage tier configured** had nowhere to
land incoming writes.

This record covers the zero-config auto-provisioning of that stage tier, the
systemd `PrivateTmp` hazard it introduces, the write-back hydration path that
keeps update-opens from truncating existing objects, and the worker-identity
ownership fixes required once workers always de-escalate away from root.

## What changed

### 1. Auto-provisioned `/tmp/staging` stage tier

A writable export whose backend is whole-object and which has **no stage store
configured** now auto-provisions the stock `sd_stage` tier over
`posix:/tmp/staging/<sanitised-backend-url>`. The provisioned spool is created
with the leaf directory `0700` chown'd to the runtime worker identity and the
base `0711`, and a loud `[warn]` banner is emitted so the operator knows staging
was implicitly enabled.

- Decision logic and provisioning:
  `brix_tier_default_stage_store()` and
  `brix_storage_backend_is_whole_object()` in
  `src/core/config/runtime_server_backend_stage.c` /
  `src/core/config/runtime_server_backend.c` (declared in
  `src/core/config/runtime_server_backend_internal.h`). The gateway check in
  `runtime_server_backend.c` gates on
  `common->stage_enable == NGX_CONF_UNSET` **and**
  `brix_storage_backend_is_whole_object(common)` before calling
  `brix_tier_default_stage_store()`, which points `common->stage_store` at
  `posix:<dir>`, sets `common->stage_enable = 1`, and emits the banner.

- The **UNSET vs. off** distinction is load-bearing. `stage_enable` is adopted
  as `NGX_CONF_UNSET` (`BRIX_ADOPT_VAL(stage_enable, NGX_CONF_UNSET)` in
  `src/core/config/http_common.c`; initialised to `NGX_CONF_UNSET` in
  `src/core/config/shared_conf.h`) and deliberately keeps that UNSET value
  through the merge. This lets an explicit `brix_stage off` (which drives the
  flag to `0`) be distinguished from *never configured* (`NGX_CONF_UNSET`), so
  auto-provisioning only fires in the unconfigured case.

- **Opt-outs.** Auto-staging does not fire if the operator sets `brix_stage
  off`, configures an explicit stage store, or has `allow_write` off (a
  read-only export needs no write spool).

### 2. `PrivateTmp` warning

The auto-provisioned spool lives under `/tmp`, which collides with systemd's
`PrivateTmp=true` sandboxing — a per-service private `/tmp` means the spool the
operator inspects on the host is not the one the service actually uses.

- `brix_tmp_is_systemd_private()` (`runtime_server_backend_stage.c`) parses
  `/proc/self/mountinfo`, detecting a mount whose mountpoint is `/tmp` and whose
  root path contains `/systemd-private-`.
- `brix_tier_warn_private_tmp()` (same file; declared in
  `runtime_server_backend_internal.h`, called from `runtime_server_backend.c`)
  emits a warning for each stage/cache store located under `/tmp` when a private
  `/tmp` is detected.
- The hazard is real for the shipped unit: `packaging/brix-cache.service` sets
  `PrivateTmp=true`.

### 3. `sd_stage` write-back hydration

On an **update-open** of an object that already exists on the source (an open
*without* `O_TRUNC` / `O_EXCL`), a whole-object flush would otherwise reassemble
only the bytes touched in this session and truncate everything else. To prevent
that, the spool copy is hydrated from the source first.

- `sd_stage_wb_hydrate()` in `src/fs/backend/stage/sd_stage_write.c` runs the
  staging engine's `BRIX_STAGE_RECALL` operation (the generic
  `pread` → `staged_write` mover) source → store **before** the write-back
  open, so the whole-object flush reassembles the full object instead of
  truncating it. It is invoked from the write-back open path in the same file.
- **Skip conditions:** the store copy is already non-empty (a durable retry copy
  is newer and authoritative); the source returns ENOENT or is unreachable (a
  write-back against a dead origin must still absorb writes); or the object is
  size 0. A copy failure of a *provably existing* object fails the open with
  EIO.
- **Mode gotcha.** The recall mover preserves the source-reported mode, and
  `sd_xroot` synthesizes `r--r--r--` for objects it reports — which would leave
  the spool copy unwritable. Hydration therefore forces `(mode | 0600)` on the
  spool copy via a store `setattr`. This required a **new `.setattr` slot on the
  posix driver**: `sd_posix_setattr()` in `src/fs/backend/posix/sd_posix_ns.c`
  (wired into the driver vtable in `src/fs/backend/posix/sd_posix.c`, declared in
  `src/fs/backend/posix/sd_posix_internal.h`), which composes the existing
  confined helpers `brix_chmod_confined_canon` (set_mode) and
  `brix_setattr_confined_canon` (set_times / set_owner).

### 4. Worker-identity ownership for provisioned dirs

brix workers always de-escalate — they drop to `brix_worker_user` / `nobody`
even under `user root`. That broke root-owned `0700` provisioned directories:
the de-escalated workers hit EACCES on dirs owned by root.

- `brix_imp_worker_runtime_ids()` (`src/auth/impersonate/lifecycle_worker.c`,
  declared in `src/auth/impersonate/lifecycle.h`) resolves the **post-drop**
  worker identity.
- `brix_shared_worker_dir_ids()` (`src/core/config/shared_conf.h`) uses it, and
  is the source of truth for both the credential-store default owner and the
  stage-spool chown (`brix_tier_default_stage_store()` calls it to pick the
  provisioned-dir owner).
- This also fixed `test_credential_dir_default` (a `putProxy` was returning
  507): the credential store must be nobody-owned under a root harness, and the
  test was updated to expect that.

## Why

- **Zero-config correctness over silent data loss.** A writable whole-object
  gateway with no place to spool writes is a foot-gun; auto-provisioning a
  spool (with a loud banner and explicit opt-outs) makes the common case work
  while keeping the operator informed.
- **UNSET vs. off** preserves operator intent: an explicit `brix_stage off` is
  honoured and never silently overridden by auto-provisioning.
- **Hydration before write-back** upholds whole-object flush semantics —
  update-opens must not truncate the untouched remainder of an existing object.
- **Worker-identity ownership** is forced by the always-on worker
  de-escalation: any directory a worker must write has to be owned by the
  post-drop identity, not root.

## Testing / verification

- `tests/test_stage_default_gateway.py` — the auto-provisioning path, including
  a `PrivateTmp` test that uses `unshare -m` plus a bind of
  `/tmp/systemd-private-*/tmp`. **Harness note:** copy the nginx binary out of
  `/tmp` first, because the build tree itself lives under `/tmp`.
- `tests/test_stage_hydration.py` — the `sd_stage_wb_hydrate` path. Topology: 1
  nginx, 2 stream servers (origin + gateway), `worker_processes 2` to avoid a
  self-connect deadlock on the sync flush, and the XRootD Python client to drive
  the update-open.
- `tests/test_credential_dir_default.py` — verifies the credential store is
  nobody-owned under a root harness (the `putProxy` 507 regression).

### Test-harness reachability pattern

De-escalated workers cannot traverse pytest's root-`0700` tmp parents. The
helper `worker_reachable(*dirs)` in `tests/official_interop_lib.py` chowns the
stock leaves (via `chown_stock`, same file) and adds `o+x` / `g+x` up the chain
to `/tmp`. It was applied to `tests/test_xfer_wt_journal.py` and
`tests/test_xfer_wt_replay.py` (the symptom was `xrdcp` error 3010 "permission
denied", with an "origin connect refused" red herring). Use `worker_reachable`
for any new suite whose nginx data / stage / journal directories live under
`tmp_path`.
