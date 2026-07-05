# Remote Test Suite — Sub-project B: Per-test Adaptation — Rolling Plan

> **For agentic workers:** executing-plans, inline, **no git**. Checkbox items are per-family batches. Each batch: adapt → run against the mega → green/clean-skip → checkpoint.

**Goal:** Adapt the copied server-file-inspection tests so they run remotely against the mega server, using `klib.svc_read/svc_listdir/svc_exists` (kubectl exec) for genuine server-side file checks, and `pytest.skip` for tests that need an un-deployed topology.

**Foundation:** Sub-project A (done) — `remote-suite/` fork, `brix-client` (pyxrootd), mega server, `klib`, `xrd-lab test remote-suite`, `remote-coverage.sh`.

## Categorization (from a 12-file / 136-test sample)

Running the "server-local" files against the mega showed **58 passed, 40 skipped, 18 failed, 20 errored**. So most tests in these files already work; the adaptation surface is the failing/erroring subset, which splits into:

- **Type A — single-node server-file inspection:** writes a file over the wire, then verifies it landed by reading the *server's* `DATA_DIR` path locally (`os.path.join(DATA_DIR, name)`, `os.listdir(DATA_DIR)`). **Adapt** → `klib.svc_*('mega', '/data/xrootd/<name>')`.
- **Type B — multi-server topology tests:** target servers not in the mega (cache-only/wt-sync/wt-async, cluster, upstream, chaos tiers). **Skip** in remote mode with a reason (`pytest.skip("needs <topology> — not in the mega server")`), or run under the dedicated k8s-lab topology later.

## Adaptation recipe (Type A)

1. First line `# brix-remote-adapted`; `import klib`.
2. Add `SERVER_DATA = "/data/xrootd"` (the mega server's data root) and `SERVER_SVC = "mega"`.
3. Replace local server-file access:
   - `os.listdir(DATA_DIR)` → `klib.svc_listdir(SERVER_SVC, SERVER_DATA)`
   - `os.path.exists(os.path.join(DATA_DIR, n))` → `klib.svc_exists(SERVER_SVC, f"{SERVER_DATA}/{n}")`
   - `open(os.path.join(DATA_DIR, n),'rb').read()` → `klib.svc_read(SERVER_SVC, f"{SERVER_DATA}/{n}")`
   - local unlink cleanup → a best-effort `klib`-driven cleanup or drop (the mega data dir is per-pod scratch).

## Skip recipe (Type B)

Guard the module or the relevant class with:
```python
pytestmark = pytest.mark.skipif(
    os.environ.get("TEST_SERVER_HOST") not in (None, "localhost", "127.0.0.1"),
    reason="multi-server topology not served by the remote mega server")
```
(REMOTE mode sets `TEST_SERVER_HOST`; local runs leave it unset → unaffected.)

## Batches (rolling; run each family against the mega before moving on)

- [x] **Batch 1 — write/upload verify:** `test_write.py` (Type A: `os.listdir` + `DATA_DIR` verify). Proves the pattern.
- [ ] **Batch 2 — file-api / stat / xattr / truncate:** the remaining `DATA_DIR`-verify single-node files.
- [ ] **Batch 3 — checksum / cksum-at-rest:** verify `.cks`/xattr on the server via `svc_read`.
- [ ] **Batch 4 — cache/cinfo (single-node cache_store):** `svc_read` the `.cinfo`/present-bitmap.
- [x] **Batch 5 — Type B skips (23 files marked # brix-remote-skip + conftest hook, verified):** mark cache-tier/cluster/upstream/chaos/ipv6 multi-server files as remote-skip.
- [ ] **Batch N …** iterate by family until `remote-coverage.sh` shows `server-local(unadapted): 0`.

Each batch ends with: run the family via `kubectl exec client -- pytest <files>` against the mega → green or clean-skip; update `remote-coverage.sh` burn-down; checkpoint (no git).

## Done when

BURN-DOWN (2026-07-05): 267 pure-remote + 1 adapted + 37 remote-skip = 305/390 handled; 85 Type-A remain (verification+adapt on a capable box). Method + tooling all in place.
