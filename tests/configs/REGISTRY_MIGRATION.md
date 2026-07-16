# Test Server Registry Migration

Pytest owns test server lifecycle through `tests/server_registry.py` and
`tests/server_launcher.py`.

New tests should register required nginx topology in Python and consume endpoint
metadata from the registry manifest. Tests may still run real clients such as
`xrdcp`, `xrdfs`, `curl`, and local helper binaries, but they should not start or
stop nginx directly unless the test is itself marked `uses_lifecycle_harness` and
uses the registry launcher primitives.

Remote mode (`TEST_SERVER_HOST`), attach mode, and `TEST_SKIP_SERVER_SETUP=1`
skip local startup. xdist workers read `$TEST_ROOT/registry/manifest.json`; only
the controller starts and stops registry-owned servers.

## Adding A Registry Server

Keep nginx config bodies in `tests/configs/` and use placeholders for values the
registry owns, usually `{PORT}`, `{DATA_ROOT}`, `{LOG_DIR}`, `{TMP_DIR}`, and
dependency endpoint values like `{UPSTREAM_PORT}`.

Register the topology at module import time:

```python
from server_registry import NginxInstanceSpec, register_nginx

register_nginx(
    NginxInstanceSpec(
        name="example",
        template="nginx_example.conf",
        protocol="root",
        data_root=None,
        readiness="tcp",
        reason="example registry-backed server",
    )
)
```

Tests should request the server with a marker and consume the endpoint fixture:

```python
import pytest

pytestmark = pytest.mark.registry_server("example")

def test_example(registry_server):
    srv = registry_server("example")
    assert srv.url.startswith("root://")
```

Use `requires=("other-server",)` for dependency ordering. The launcher also
publishes `{OTHER_SERVER_HOST}`, `{OTHER_SERVER_PORT}`, and `{OTHER_SERVER_URL}`
template values for registered dependencies.

## Porting A Shell Script

Shell wrappers are migration backlog, not the target shape. Port each command
flow into importable Python:

- Put reusable command logic in `tests/cmdscripts/<name>.py`.
- Put collected assertions in `tests/test_cmd_<name>.py` or a domain-specific
  test file.
- Use `command_runner` or `cmdscripts.run()` for real clients such as `xrdcp`,
  `xrdfs`, `curl`, helper binaries, and build tools.
- Use registry markers and `registry_server()` for server endpoints.
- Replace `trap cleanup` with pytest fixtures, `tmp_path`, and registry-owned
  teardown.

Naming convention:

- `tests/run_af_family_conf.sh` -> `tests/cmdscripts/af_family_conf.py` and
  `tests/test_cmd_af_family_conf.py` (first completed command-port example).
- `tests/run_cache_pblock_pblock.sh` ->
  `tests/cmdscripts/cache_pblock_pblock.py` and
  `tests/test_cmd_cache_pblock_pblock.py`.
- `tests/run_credential_http_bearer.sh` ->
  `tests/cmdscripts/credential_http_bearer.py` and
  `tests/test_cmd_credential_http_bearer.py` (currently xfailed because the
  legacy shell flow fails the same authenticated-fill checks).
- `tests/run_credential_webdav_xroot.sh` ->
  `tests/cmdscripts/credential_webdav_xroot.py` and
  `tests/test_cmd_credential_webdav_xroot.py`.
- `tests/run_storage_backend_metrics.sh` ->
  `tests/cmdscripts/storage_backend_metrics.py` and
  `tests/test_cmd_storage_backend_metrics.py`.
- `tests/run_dashboard_vfs_browse.sh` ->
  `tests/cmdscripts/dashboard_vfs_browse.py` and
  `tests/test_cmd_dashboard_vfs_browse.py`.
- `tests/run_storage_backend_schemes.sh` ->
  `tests/cmdscripts/storage_backend_schemes.py` and
  `tests/test_cmd_storage_backend_schemes.py` (currently xfailed for the FRM
  recall data-plane check that also fails in the legacy shell flow).
- `tests/run_s3_usermeta.sh` -> `tests/cmdscripts/s3_usermeta.py` and
  `tests/test_cmd_s3_usermeta.py`.
- `tests/run_s3_store_writable.sh` ->
  `tests/cmdscripts/s3_store_writable.py` and
  `tests/test_cmd_s3_store_writable.py`.
- `tests/run_s3_storage_backend.sh` ->
  `tests/cmdscripts/s3_storage_backend.py` and
  `tests/test_cmd_s3_storage_backend.py`.
- `tests/run_cache_http_source.sh` ->
  `tests/cmdscripts/cache_http_source.py` and
  `tests/test_cmd_cache_http_source.py`.
- `tests/run_cache_xroot_origin.sh` ->
  `tests/cmdscripts/cache_xroot_origin.py` and
  `tests/test_cmd_cache_xroot_origin.py`.
- `tests/run_cache_s3_origin.sh` ->
  `tests/cmdscripts/cache_s3_origin.py` and
  `tests/test_cmd_cache_s3_origin.py` (currently xfailed for the SigV4
  cache-fill failure that also fails in the legacy shell flow).
- `tests/run_cache_backend_source.sh` ->
  `tests/cmdscripts/cache_backend_source.py` and
  `tests/test_cmd_cache_backend_source.py`.
- `tests/run_cache_pblock_posix.sh` ->
  `tests/cmdscripts/cache_pblock_posix.py` and
  `tests/test_cmd_cache_pblock_posix.py`.
- `tests/run_cache_wt_driver.sh` ->
  `tests/cmdscripts/cache_wt_driver.py` and
  `tests/test_cmd_cache_wt_driver.py`.
- `tests/run_cache_watermark.sh` ->
  `tests/cmdscripts/cache_watermark.py` and
  `tests/test_cmd_cache_watermark.py`.
- `tests/run_cache_watermark_config.sh` ->
  `tests/cmdscripts/cache_watermark_config.py` and
  `tests/test_cmd_cache_watermark_config.py`.
- `tests/run_cache_reaper.sh` ->
  `tests/cmdscripts/cache_reaper.py` and
  `tests/test_cmd_cache_reaper.py`.
- `tests/run_cache_stage_throttle.sh` ->
  `tests/cmdscripts/cache_stage_throttle.py` and
  `tests/test_cmd_cache_stage_throttle.py`.
- `tests/run_cache_slice_gsi_legacy.sh` ->
  `tests/cmdscripts/cache_slice_gsi_legacy.py` and
  `tests/test_cmd_cache_slice_gsi_legacy.py`.
- `tests/run_cache_unit.sh` ->
  `tests/cmdscripts/cache_unit.py` and `tests/test_cmd_cache_unit.py`.
- `tests/run_credential_xroot_ztn.sh` ->
  `tests/cmdscripts/credential_xroot_ztn.py` and
  `tests/test_cmd_credential_xroot_ztn.py` (currently xfailed for the token
  root credential fill failure that also fails in the legacy shell flow).
- `tests/run_credential_xroot_gsi_writeback.sh` ->
  `tests/cmdscripts/credential_xroot_gsi_writeback.py` and
  `tests/test_cmd_credential_xroot_gsi_writeback.py`.
- `tests/run_credential_wt_ztn.sh` ->
  `tests/cmdscripts/credential_wt_ztn.py` and
  `tests/test_cmd_credential_wt_ztn.py`.
- `tests/run_credential_dup_warn.sh` ->
  `tests/cmdscripts/credential_dup_warn.py` and
  `tests/test_cmd_credential_dup_warn.py`.
- `tests/run_delegation_twostep.sh` ->
  `tests/cmdscripts/delegation_twostep.py` and
  `tests/test_cmd_delegation_twostep.py`.
- `tests/cvmfs/run_matrix.sh` -> `tests/cmdscripts/cvmfs_matrix.py`.
- `tests/c/run_vfs_caps_tests.sh` -> `tests/cmdscripts/c_vfs_caps.py`.
- `tests/ceph/run_sd_ceph_live.sh` -> `tests/cmdscripts/ceph_sd_ceph_live.py`.

After this phase is complete, new `.sh` files under `tests/` are forbidden and
the remaining historical shell wrappers should be deleted as their Python
replacements land.
