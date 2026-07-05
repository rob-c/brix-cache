# k8s-tests Python Port — Design

**Date:** 2026-07-05
**Goal:** Replace the 20 bats files that test the k8s lab with a pytest suite, and rewrite
`klib.py` on the official `kubernetes` Python client — optimized so **reviewing any one test is
quick and obvious**.

## Why

The lab is verified by 20 bash `bats` files (46 tests) that shell out to `docker`/`kubectl`/
`helm`/`minikube`, plus `remote-suite/tests/klib.py` which reaches server-side files via
`kubectl exec` subprocesses. Bash asserts (`[[ $output == *x* ]]`, fake-`kubectl` PATH shims) are
hard to scan and easy to get subtly wrong. Moving to pytest + a real k8s client makes each test a
few lines of arrange/act/assert a reviewer can read at a glance.

## Decisions (approved)

1. **Scope:** all 20 bats → pytest, **and** `klib.py` → official `kubernetes` client.
2. **Library:** official `kubernetes` client for k8s ops. helm/docker/minikube stay as a one-line
   `run()` subprocess wrapper (no first-class Python equivalents worth the weight — honest about
   what executes).
3. **Transition:** replace — port, verify parity against the bats checks, then delete `tests-bats/`.

## Architecture

```
k8s-tests/
  pytests/
    requirements.txt      # kubernetes (+ pytest)
    conftest.py           # fixtures (below)
    labkit/               # thin readable helpers — the only place tools are invoked
      __init__.py
      shell.py            # run(argv, **) -> CompletedProcess ; lab(*args, dry=False)
      kube.py             # kubernetes client: exec_(svc,argv,stdin), logs, pods, wait_ready, get, list_
      helm.py             # install/upgrade/uninstall/status/lint via run()
      images.py           # docker build/run/inspect via run()
    test_xrd_lab.py       # <- xrd_lab_unit.bats + xrd_lab_e2e.bats
    test_mega_config.py   # <- mega_config.bats + import_config.bats
    test_remote_suite.py  # <- sync_remote_suite.bats + svc_read.bats + remote_suite_e2e.bats
    test_images.py        # <- server/client/authority/smoke_image.bats (parametrized)
    test_fleet_e2e.py     # <- fleet/chaos/cms/dedicated/auth_authority e2e (@e2e)
    test_misc.py          # <- docs.bats + require_tools.bats + client_pki_init.bats + catalog.bats
  remote-suite/tests/klib.py   # REWRITTEN on kubernetes client, SAME public API
```

### `labkit` helpers (the readability layer)

- **`shell.run(argv, check=False, env=None, timeout=None) -> CompletedProcess`** — captures text
  stdout/stderr. Every subprocess goes through here.
- **`shell.lab(*args, dry=False, env=None)`** — runs `../xrd-lab`; `dry=True` sets `XRD_LAB_DRY_RUN=1`.
- **`kube.Kube`** wraps the client:
  - `exec_(service, argv, stdin=None) -> Exec(rc, stdout, stderr)` — resolve pod by
    `app.kubernetes.io/component=<service>`, run via `stream(connect_get_namespaced_pod_exec, …)`,
    parse the exit code from the status channel. Binary-safe stdin via the caller's base64.
  - `logs(service, container=None)`, `pods(selector)`, `wait_ready(selector, timeout)`,
    `get(kind, name)`, `list_(kind, selector)`.
  - Config: `load_incluster_config()` then fall back to `load_kube_config()`.
- **`helm`/`images`** — thin `run()` wrappers returning parsed results (e.g. `helm.status()->dict`).

### Fixtures (`conftest.py`) — all heavy setup lives here

- `kube` (session): a `labkit.kube.Kube` bound to the test namespace.
- `ns` (function/module): create a throwaway namespace, yield, delete. e2e tests use it.
- `lab`: bound `labkit.shell.lab` runner.
- `image(name)`: build (or assume-built) a lab image; used by `test_images.py`.
- `deployed(release, chart, values)`: helm install into `ns`, `wait_ready`, yield handle, uninstall.
- Markers: `e2e` (real minikube deploy; deselected by default), registered in `pytest.ini`.

### `klib.py` rewrite (same API)

Keep all 14 `svc_*` functions with identical signatures
(`svc_read/write/mkdir/rm/rmtree/isdir/isfile/exists/listdir/chmod/mode/symlink/setxattr/getxattr`)
so **no adapted suite test changes**. Internals:

- `_kube()` — memoized `Kube` (in-cluster in the pod, kubeconfig locally).
- `_exec(service, argv, stdin=None)` — delegate to `Kube.exec_`; return `(rc, stdout_bytes, stderr)`.
- Rebuild each `svc_*` on `_exec` exactly as today (base64 stdin for `svc_write`, `cat`/`test`/`ls`/
  `stat`/`chmod`/`setfattr`/`getfattr`/`ln` argv unchanged). Public behaviour identical.
- Pod cache preserved.

## Simplicity rules (the point of the exercise)

- **One assert idea per test**; heavy setup in fixtures; body 3–8 lines.
- **Parametrize** repetition: `test_images.py` = one row per image; `mega_config` port list = one
  row per port; sync-marker cases = one row per marker.
- **No PATH shims / fake binaries.** klib unit tests use a fake `Kube` injected via a fixture (or a
  monkeypatched `_exec`) instead of a fake-`kubectl` script — the assertion reads as Python.
- **`e2e` marker** replaces the `XRD_LAB_E2E=1`/dry-run bifurcation. `pytest` (default) runs
  fast; `pytest -m e2e` runs real deploys.

## Verification & parity

- Every bats `@test` maps to a named pytest; a short `PARITY.md` table records bats→pytest so the
  reviewer can confirm nothing was dropped.
- Fast tier (`pytest -m 'not e2e'`) must be green locally (dry-run + config + klib-fake + image
  metadata) before deleting bats.
- Gated e2e tier (`-m e2e`) runs against the live `brix-remote` namespace / minikube.
- After parity is green, delete `tests-bats/` and update `xrd-lab`/docs references (`bats` →
  `pytest pytests/`).

## Out of scope

- The 267/25/29 adapted+pure suite tests themselves (unchanged; only `klib` internals move).
- helm/docker/minikube Python SDKs (subprocess wrapper is intentional).
- CI wiring changes beyond swapping the test command.
