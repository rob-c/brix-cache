# Test-Server Migration: self-provisioned → pre-started dedicated instances

**Goal.** As many test files as possible should use servers that are **started once**
by `tests/manage_test_servers.sh start-all` (before the suite), managed separately, and
**torn down only when the whole suite finishes** — rather than each test spinning up and
tearing down its own nginx/xrootd. We favour *many dedicated pre-started instances* over
per-test setup/teardown. (Each migrated test still gets its **own** dedicated instance, so
isolation is preserved.)

This also sets up the longer-term goal of running the same tests against **both**
nginx+xrootd and an official XRootD server (see `tests/backend_matrix.py`,
`TEST_CROSS_BACKEND=nginx|xrootd`) to surface drop-in divergences.

## The migration pattern (proven, repeatable)

A self-contained fixture that did `subprocess` → `nginx -c <own conf>` … `-s stop` becomes a
**dedicated instance** in four mechanical steps. Worked reference:
`test_open_flags_lifecycle.py` + `tests/configs/nginx_open_flags_lifecycle.conf`.

1. **Config** — `tests/configs/nginx_<name>.conf` using the placeholders
   `substitute_config()` fills: `{PORT}` `{DATA_DIR}` `{LOG_DIR}` `{TMP_DIR}` `{S3_PORT}`
   `{CA_CERT}` `{SERVER_CERT}` `{SERVER_KEY}` `{JWKS_FILE}` … (model on `nginx_readonly.conf`).
2. **Register** in `start_all_dedicated()` (`manage_test_servers.sh`):
   `start_dedicated_nginx "<name>" "nginx_<name>.conf" "${<NAME>_PORT:-NNNN}"`.
   A second listen port (e.g. read-only WebDAV+S3 in one instance) is passed by env-prefixing
   the line, e.g. `NGINX_S3_PORT="${READONLY_HTTP_S3_PORT:-11217}" start_dedicated_nginx ...`.
3. **settings.py** — `<NAME>_PORT = int(os.environ.get("TEST_<NAME>_PORT","NNNN"))` and
   `<NAME>_DATA_ROOT = os.path.join(TEST_ROOT, "data-<name>")`.
4. **Fixture rewrite** — delete the spawn/teardown helpers (+ now-unused `subprocess`/`NGINX_BIN`
   imports) and replace with: compute `data_dir = <NAME>_DATA_ROOT`, `os.makedirs(exist_ok=True)`,
   **seed any required files into it**, `socket` reachability check → `pytest.skip(... run
   manage_test_servers.sh start-all)` if down, then `return`/`yield` the *same dict shape* the
   tests already consume. Change **no** test function or assertion. (Mirror `test_vo_acl.py::vo_nginx`.)

**Key contract.** `start_dedicated_nginx "<name>"` serves `DATA_DIR = ${TEST_ROOT}/data-<name>`.
The test process and the server share the local filesystem, so the fixture seeds files into that
data root and reads the server's writes back from it.

**Teardown.** `force_stop_nginx` now generically kills every
`${TEST_ROOT}/dedicated/*/logs/nginx.pid`, so `stop-all` cleanly frees all dedicated instances
(previously it only knew a hardcoded port list, leaving migrated instances bound → the next
`start-all` failed with EADDRINUSE). `start-all` does **not** stop first — run `stop-all` (or
`restart all`) before re-running `start-all` if instances are already up.

## Done (validated end-to-end)

Migrated, `start-all` brings each up, all tests pass against the pre-started instance
(`TEST_SKIP_SERVER_SETUP=1 pytest <file>`), and `stop-all`/`start-all` cycle cleanly:

| File | Instance(s) | Port(s) | Tests |
|---|---|---|---|
| `test_open_flags_lifecycle` | open-flags-lifecycle (writable stream) | 12980 | 12 |
| `test_webdav_delete_lock_security` | webdav-dellock (writable WebDAV) | 13210 | 20 |
| `test_webdav_unlock_ownership` | webdav-unlock-ownership (writable WebDAV, xattr locks) | 22014 | 5 |
| `test_s3_upload_part_copy_traversal` | s3-mpu (writable S3) | 22017 | 4 |
| `test_readonly_http_endpoint` | readonly-http (read-only WebDAV + S3, one instance) | 11216 / 11217 | 11 |

## Backlog — remaining migrations (verdicts corrected from the 2-pass classification)

**Single dedicated instance (next batch — low risk).** `test_macaroon_negative`,
`test_token_es256`, `test_token_aud_array` (need a fixed JWKS/issuer/secret the dedicated config
references — pre-generate into the data/pki area at start-all time), `test_s3_auth_oracle`,
`test_phase20_kv_shm`, `test_phase21_proxy_filter` (3), `test_phase22_health_check` (3 stream +
metrics), `test_phase23_admin_api`, `test_xrdhttp_wait_retry_digest_range` (mark `serial` — own
rate-limit bucket). `test_put_content_encoding` → **reuse** the fleet WebDAV (8443/8080), no new
instance — just drop its spawn.

**N-instance fleets (need several dedicated instances each).** `test_cms_state_have_select` (2 +
test-owned Python mgr peer), `test_cms_wire_pup_conformance` (2 + peer), `test_conformance_topologies`
(7: proxy/mesh×2/cluster×2/mirror×2), `test_integrity_matrix` (5: mirror+proxy meshes),
`test_mirror_upstream` (6: ref-xrootd pair + mirror fronts + opcode variants),
`test_phase24_mirror` (3 + in-proc shadows), `test_phase25_ratelimit` (3, `serial`),
`test_proxy_protocol_edges` (11 — also needs a new multi-port Python stub `upstream_protocol_stubs_ppe.py`),
`test_metadata_stress` (8). `test_evil_paths` — only its `TestCmsStateEvil` sub-server migrates
(the 5 protocol servers it uses are already fleet).

**Corrections to watch (the auto-plan got these wrong):**
- `test_dropin_byte_for_byte` — byte-for-byte parity needs nginx **and** official xrootd on the
  **same** data dir. Migrate as a *pair* (dedicated nginx + dedicated ref-xrootd, both rooted at
  `data-dropin`), **not** by pointing at the fleet ref-xrootd (different data root → guaranteed fail).
- `test_webdav_lock_startup_sweep` — **KEEP**: it `_run_nginx`/`_stop_nginx` *during* tests to verify
  the startup lock-sweep (K2 lifecycle control), so it must control its own server.

**Genuine KEEP (do not migrate).** `test_ha_failover` (K2 — SIGTERMs nginx-1 mid-test for failover),
`test_phase27_memsafety` (ASAN/ephemeral instances; 10/12 tests are static), `test_security_redteam`
(pure `nginx -t`, no running server), `test_webdav_lock_startup_sweep` (K2), `test_chaos_mesh`
(kills tiers — already on fleet chaos ports).

## Notes
- Config filenames for the Done batch use hyphens (`nginx_webdav-dellock.conf`); the older
  convention is underscores. Both work (the name is just passed to `substitute_config`); prefer
  underscores for new ones.
- New dedicated ports: keep clear of the fleet ranges; the free single-server block starts at `11216`.
