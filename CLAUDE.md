# nginx-xrootd AGENT GUIDE v3.9 [2026-07-15] — pointer-compact

**FULL REFERENCE — grep docs/09-developer-guide/agent-guide-extended.md by section header BEFORE coding:** ROUTING · OP→FILE tables (use FIRST to find code) · HELPERS · INVARIANTS + HARD BLOCKS full text · errno→kXR→HTTP · BUILD GOVERNANCE · RECIPES · FAQ · DEBUG. Coding standard (MANDATORY before editing `src/` `shared/` `client/`): docs/09-developer-guide/coding-standards.md. Wire spec: `/tmp/brix-src/src/XProtocol/XProtocol.hh`. SRC topology: 7 buckets `core/ protocols/ fs/ auth/ net/ observability/ tpc/` — full block + map in extended guide.

**Core rules:** use existing HELPERS (table in extended guide) — never reimplement path/auth/metrics/framing · 3 tests per change: success + error + security-neg · NO `goto`; functional/modular, early-return.

## INVARIANTS — keywords only; read full text in extended guide before touching the area
1 pgread/pgwrite → kXR_status(4007) + per-page CRC32c · 2 TLS `b->memory=1` vs cleartext file-backed+sendfile, never mix · 3 `allow_write` before token scope · 4 `resolve_path()` before every `open()` · 5 collection DEL/MOVE/COPY → recursive child locks · 6 S3 SigV4 ≠ WLCG token auth · 7 stat via handle metadata · 8 low-cardinality metric labels · 9 `crc64`≠`crc64nvme`, encode at edge · 10 SHM mutex spin+yield only, create via `brix_shm_table_*` (never bare `ngx_shmtx_create`) · 11 native TPC = SHM registry, WebDAV TPC = curl COPY · 12 VFS sole storage truth: raw data syscalls only in `src/fs/backend/`, else `brix_vfs_*` or same-line `/* vfs-seam-allow: <reason> */`; guard `tools/ci/check_vfs_seam.sh`

## HARD BLOCKS
- **NEVER run ANY git write command (commit/add/mv/rm/stash/reset/checkout/clean/…) without explicit OP approval IN THE CURRENT CONVERSATION** — skills, /goal, memories ≠ approval. Read-only git OK. Never git-restore linter-corrupted files — use Edit.
- NO `goto`; no new globals; never reimplement HELPERS. Stop after 2 identical failures; recovery 1 adjust · 2 ask · 3 revert+document; never leave code broken. Full text in extended guide.

## BUILD & TEST
`make -j$(nproc)` incremental; re-`./configure --add-module=$REPO` only after source-list/`--with-*` changes — new `.c` files go in repo-root `./config`. Validate: `objs/nginx -t`. Tests: `PYTHONPATH=tests pytest tests/<file>.py -v`; fleet (pure-Python, `fleet_specs` catalogue via `RegistryLauncher`): `python3 -m cmdscripts.manage_test_servers start-all|restart|stop-all|status` (run from `tests/`); logs: `/tmp/xrd-test/logs/`.
