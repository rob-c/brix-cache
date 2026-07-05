# bats → pytest parity (complete)

The 20 `tests-bats/*.bats` files are ported to `k8s-tests/pytests/` and the
bats suite has been deleted. `klib.py` is rewritten on the official `kubernetes`
client (kubectl subprocess removed).

Run: `pytest pytests/ -m 'not e2e'` (fast, no cluster) · `pytest pytests/ -m e2e`
(needs Docker + minikube).

| bats file | pytest | status |
|---|---|---|
| `svc_read.bats` | `test_klib.py` (10, FakeServer) | ✅ verified |
| `xrd_lab_unit.bats` | `test_xrd_lab.py` | ✅ verified |
| `xrd_lab_e2e.bats` | `test_xrd_lab.py` (`@e2e`) | ✅ ported |
| `sync_remote_suite.bats` | `test_remote_suite.py` | ✅ verified |
| `remote_suite_e2e.bats` | `test_remote_suite.py` (+`@e2e`) | ✅ verified (dry) |
| `docs.bats` | `test_misc.py` | ✅ verified |
| `require_tools.bats` | `test_misc.py` | ✅ verified |
| `catalog.bats` | `test_config.py` | ✅ verified |
| `import_config.bats` | `test_config.py` | ✅ verified |
| `mega_config.bats` | `test_config.py` (+`@e2e` nginx -t) | ✅ verified |
| `smoke_image.bats` | `test_images.py` (`@e2e`) | ✅ verified |
| `server_image.bats` | `test_images.py` (`@e2e`) | ✅ verified |
| `client_image.bats` | `test_images.py` (`@e2e`) | ✅ verified |
| `authority_image.bats` | `test_images.py` (`@e2e`) | ✅ verified |
| `client_pki_init.bats` | `test_images.py` (`@e2e`) | ✅ verified |
| `fleet_e2e.bats` | `test_fleet_e2e.py` (dry + `@e2e`) | ✅ dry + **live verified** (`fleet OK`) |
| `chaos_e2e.bats` | `test_fleet_e2e.py` | ✅ dry verified |
| `cms_e2e.bats` | `test_fleet_e2e.py` | ✅ dry verified |
| `dedicated_e2e.bats` | `test_fleet_e2e.py` | ✅ dry verified |
| `auth_authority_e2e.bats` | `test_fleet_e2e.py` | ✅ dry verified |

## Verified

- `pytest -m 'not e2e'` → **36 passed** (klib logic via FakeServer, xrd-lab
  dry-runs incl. the 5 fleet profiles, sync/coverage, config/catalog/docs).
- `pytest -m e2e` image tier → **7 passed** (4 images + client-pki-init + smoke
  healthz) and `test_config.py` mega `nginx -t` → passed.
- **klib on the k8s client — verified live** against the mega (binary + 5 MB
  round-trips, mkdir/chmod/mode/xattr/symlink) **and in-pod**: adapted
  `test_fs_ops.py` → 20/20 in the client pod with in-cluster config.

## Fixes the port surfaced

- **client-rbac chart bug:** the RoleBinding subject had no `namespace`, and the
  Role granted only `create` on `pods/exec`. The kubernetes Python client's
  `connect_get_namespaced_pod_exec` uses a **GET** websocket (needs `get`),
  unlike `kubectl exec` (POST/`create`) — so the old klib worked but the new one
  was denied. Fixed both in `charts/client-rbac/templates/rbac.yaml`.
- **svc_write hang:** the exec WS has no clean stdin-close, so `base64 -d`
  blocked forever. Fixed with a bounded `head -c <len>` read.
- **multi-container exec:** the mega pod has sidecars → `container=<svc>` is
  required or the API returns 400.
- Added `kubernetes` to `images/client/Dockerfile` (in-pod klib).

## Bug found + fixed while verifying the live fleet

`xrd-lab deploy fleet` failed at the pre-install `bootstrap` job
(`BackoffLimitExceeded`) → the fleet never came up → the anon probe saw
`[FATAL] Invalid address`. Root cause was the auth-authority bootstrap's CA-hash
step (`charts/auth-authority/templates/bootstrap-job.yaml`): `blitz_test_pki`
already runs `c_rehash`, leaving `<hash>.0` as **symlinks** to `ca.pem`, and the
step did `cp ca.pem <hash>.0` → `cp: ... are the same file` → job exit 1. Worse,
`kubectl create configmap --from-file=<dir>` **skips symlinks**, so the published
ca-bundle omitted `<hash>.0` — the very thing GSI-WebDAV needs. Fixed by
materializing every CA-dir symlink into a real file, which both lets the job
succeed and puts `<hash>.0` in the ConfigMap (so webdav-8444 works without the
earlier manual patch). Verified: `xrd-lab test fleet` → `fleet OK`; pytest
`@e2e` fleet round-trip passes.


## Fully Python (2026-07-05)

All bash logic is now importable Python; `tools/*.sh` (8) and `xrd-lab` are thin wrappers.

- **labtools/** = the lab's logic as pure functions, one source of truth for tests + CLI:
  `catalog` (lint/render), `import_config` (convert/unmapped), `coverage` (classify), `require_tools` (missing), `sync` (is_protected/sync), `mega_config` (build — byte-identical), and `lab`/`lab_suite` (the driver: `plan_up/deploy/down/status/images` command lists + `scenario_*` report lines).
- **Tests import and call these directly** — no subprocess/grep:
  `lab.plan_up()` returns the argv list; `lab.scenario_fleet()` (dry) returns its description; `catalog.lint(path) == []`; `import_config.unmapped(convert('...{UPSTREAM_PORT}')) == ['{UPSTREAM_PORT}']`; `coverage.classify()` sums to the file count; `sync.sync()` into a fake repo preserves an adapted file; `mega_config.build()` matches the committed config.
- **Verified:** fast tier 38 passed in ~0.3s (was 5s via subprocess); `xrd-lab` fleet deploy+probe live e2e passes through the Python driver (149s); dry-run tokens byte-match the old bash; shellcheck clean.
- **LoC:** `xrd-lab` 466→6, `tools/*.sh` → 8 wrappers (~75 lines), logic = 888 LoC testable Python.
