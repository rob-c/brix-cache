"""Phase-81 registry lint — enforce the server-lifecycle policy on the test tree.

Policy (docs/refactor/phase-81-test-server-registry.md §"registry lint"):
  * A test must not start/stop/reload nginx directly — it goes through the
    registry (`LifecycleHarness`, marked with ``pytest.mark.uses_lifecycle_harness``)
    or the session fleet.  Direct ``subprocess.run/Popen([NGINX, ...])`` is banned.
  * No ``*.sh`` under ``tests/`` except the compat-fleet backend
    (``manage_test_servers.sh``) and its sourced ``tests/lib/*.sh`` helpers.
  * Test code must not reach around the registry by sourcing those shell helpers.

The direct-launch ban is enforced against a *strictly shrinking* backlog: files
that still launch nginx directly are enumerated in ``LAUNCH_BACKLOG``.  The lint
fails on (a) any NEW direct launch outside the backlog, and (b) any backlog entry
that no longer launches directly — a migrated file must be removed from the list.
So the only legal way to change the backlog is to make it smaller.  A file drops
out of scope the moment it carries the ``uses_lifecycle_harness`` marker.
"""

from pathlib import Path
import re


TESTS = Path(__file__).resolve().parent
PY_FILES = [p for p in TESTS.rglob("*.py") if ".pytest_cache" not in p.parts]
SH_FILES = [p for p in TESTS.rglob("*.sh") if ".pytest_cache" not in p.parts]

# Registry/infra files that own the launch primitive itself, plus this lint.
INFRA_ALLOW = {
    "server_launcher.py",
    "conftest.py",
    "test_server_registry_lint.py",
}

_LAUNCH = re.compile(r"subprocess\.(?:run|Popen)\(\s*\[[^\]]*NGINX", re.S)
_MARKER = "uses_lifecycle_harness"

# Documented, strictly-shrinking backlog of files that still launch nginx
# directly (relative to tests/).  Burn this down phase by phase; never add to it.
# `userns/e2e_redteam.py` is a deliberate long-lived entry: it is a standalone
# in-namespace-root privilege-escalation battery (launched by the C
# userns_exec_launcher, not a shell) whose `user svc;` worker-setuid model and
# per-uid export-tree ownership conflict with the registry's prefix-ownership
# model — see the tracker's "Files requiring lifecycle-harness migration" note.
LAUNCH_BACKLOG = frozenset({
    "_cache_partial_helpers.py",
    "_test_evil_actor_v3_helpers.py",
    "_test_gsi_handshake_helpers.py",
    "cms_mesh_lib.py",
    "mu_authz_lib/fleet.py",
    "official_interop_lib.py",
    "resilience/run_http_reorder.py",
    "resilience/servers.py",
    "test_chaos_mixed_auth.py",
    "test_checksum_on_write.py",
    "test_client_gaps.py",
    "test_cms_fast_settle.py",
    "test_cms_resilience.py",
    "test_cms_state_have_select.py",
    "test_cms_wire_pup_conformance.py",
    "test_cns.py",
    "test_compression_fuse_resilience.py",
    "test_compression_root_adversarial.py",
    "test_conformance_topologies.py",
    "test_crc64.py",
    "test_delegation_t4_credential.py",
    "test_dropin_byte_for_byte.py",
    "test_e2e_proxy_matrix.py",
    "test_evil_actor.py",
    "test_evil_actor_v2.py",
    "test_frm_async.py",
    "test_frm_control_locality.py",
    "test_frm_owner.py",
    "test_frm_phase1_http.py",
    "test_frm_phase4.py",
    "test_frm_phase4_engines.py",
    "test_frm_queue.py",
    "test_frm_scratch.py",
    "test_frm_staging.py",
    "test_gohep_interop.py",
    "test_ha_failover.py",
    "test_integrity_matrix.py",
    "test_libbrix.py",
    "test_metadata_stress.py",
    "test_mirror_upstream.py",
    "test_mu_cache_serve_authz.py",
    "test_mu_sidecar_config_guard.py",
    "test_mu_sidecar_hidden.py",
    "test_mu_stage_modes.py",
    "test_mu_webdav_authz.py",
    "test_native_xrdcp_xrdfs.py",
    "test_native_xrdcp_xrdfs_b.py",
    "test_p805_remote_authz_guard.py",
    "test_pblock_pwd_multiuser.py",
    "test_phase20_kv_shm.py",
    "test_phase51_resilience.py",
    "test_pmark.py",
    "test_put_content_encoding.py",
    "test_pwd_auth_multiproto.py",
    "test_readv_segment_size.py",
    "test_readv_variable_blocks.py",
    "test_root_open_existence_oracle.py",
    "test_s3_xrootd_gateway.py",
    "test_security_redteam.py",
    "test_shutdown_resume.py",
    "test_slice_cache.py",
    "test_ssi.py",
    "test_ssi_config.py",
    "test_ssi_metrics.py",
    "test_ssi_wire.py",
    "test_tape_rest.py",
    "test_tpc_async_open.py",
    "test_tpc_delegation.py",
    "test_tpc_gsi_nginx_source.py",
    "test_tpc_gsi_outbound.py",
    "test_tpc_tls.py",
    "test_upstream_auth_multiround.py",
    "test_wlcg_audit_log.py",
    "test_xfer_ledger.py",
    "test_xfer_wt_journal.py",
    "test_xfer_wt_replay.py",
    "test_xrddiag.py",
    "test_xrddiag_compare_davs.py",
    "test_xrddiag_multiproto.py",
    "test_xrddiag_remote_doctor.py",
    "test_xrootd_conformance.py",
    "test_xrootdfs_resilience.py",
    "userns/e2e_redteam.py",
    "userns/test_impersonate_config.py",
    "wlcg_conformance_fleet.py",
    "wlcg_fleet.py",
})


# Inline-nginx-config ban applies to pytest test modules (``test_*.py``): a test
# must render from a committed template, not embed an nginx config heredoc.  The
# ``cmdscripts/*.py`` generators and ``*_lib`` helpers are the committed config
# *source* for the compat fleet and are intentionally out of scope.  Strictly
# shrinking, like LAUNCH_BACKLOG.
_INLINE_EVENTS = re.compile(r"events\s*\{")
_INLINE_HTTP_STREAM = re.compile(r"(?:^|\W)(?:http|stream)\s*\{")
INLINE_CONFIG_BACKLOG = frozenset({
    # `test_evil_paths.py` embeds a stream{} CMS-node config heredoc and launches
    # a throwaway nginx via a lowercase `nginx_bin` local, so the NGINX-token
    # launch scan misses it — this is the offender only the inline scan catches.
    # The rest also appear in LAUNCH_BACKLOG (they embed *and* launch directly);
    # both allowlists must lose the entry when a file is migrated.
    "test_chaos_mixed_auth.py",
    "test_cms_resilience.py",
    "test_cms_state_have_select.py",
    "test_cms_wire_pup_conformance.py",
    "test_conformance_topologies.py",
    "test_dropin_byte_for_byte.py",
    "test_evil_actor.py",
    "test_evil_paths.py",
    "test_frm_control_locality.py",
    "test_frm_phase4_engines.py",
    "test_frm_queue.py",
    "test_frm_scratch.py",
    "test_integrity_matrix.py",
    "test_metadata_stress.py",
    "test_mu_sidecar_config_guard.py",
    "test_p805_remote_authz_guard.py",
    "test_phase20_kv_shm.py",
    "test_phase51_resilience.py",
    "test_security_redteam.py",
    "userns/test_impersonate_config.py",
})


def _rel(path):
    return path.relative_to(TESTS).as_posix()


def _inline_config_modules():
    """test_*.py modules that embed an nginx config and are not marker-exempt."""
    offenders = set()
    for path in PY_FILES:
        if path.name in INFRA_ALLOW or not path.name.startswith("test_"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if _MARKER in text:
            continue
        if _INLINE_EVENTS.search(text) and _INLINE_HTTP_STREAM.search(text):
            offenders.add(_rel(path))
    return offenders


def _direct_launchers():
    """Files that launch nginx directly and are not exempt via the marker."""
    launchers = set()
    for path in PY_FILES:
        rel = _rel(path)
        if path.name in INFRA_ALLOW:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if _LAUNCH.search(text) and _MARKER not in text:
            launchers.add(rel)
    return launchers


def test_migration_doc_states_the_policy():
    migration_doc = (TESTS / "configs" / "REGISTRY_MIGRATION.md").read_text(
        encoding="utf-8"
    )
    flat_doc = " ".join(migration_doc.split())
    assert _MARKER in migration_doc
    assert "should not start or stop nginx directly" in flat_doc


def test_no_new_direct_nginx_launches():
    """No test may launch nginx directly outside the shrinking backlog."""
    launchers = _direct_launchers()
    new_offenders = sorted(launchers - LAUNCH_BACKLOG)
    assert not new_offenders, (
        "new direct nginx launch(es) — route through the registry "
        f"(LifecycleHarness + @pytest.mark.{_MARKER}): {new_offenders}"
    )


def test_launch_backlog_only_shrinks():
    """Every backlog entry must still be a direct launcher.

    A migrated file (now marked, or no longer launching nginx) must be deleted
    from LAUNCH_BACKLOG so the allowlist can only get smaller."""
    launchers = _direct_launchers()
    stale = sorted(LAUNCH_BACKLOG - launchers)
    assert not stale, (
        "stale LAUNCH_BACKLOG entries — these no longer launch nginx directly, "
        f"remove them from the list: {stale}"
    )


def test_no_test_code_sources_shell_helpers():
    """Test code must not reach around the registry by sourcing the fleet
    shell helpers (manage_test_servers.sh / tests/lib/*.sh)."""
    pattern = re.compile(
        r"""subprocess\.(?:run|Popen|call|check_call|check_output)\([^)]*"""
        r"""(?:manage_test_servers\.sh|lib/[\w./-]+\.sh)""",
        re.S,
    )
    offenders = []
    for path in PY_FILES:
        if path.name in INFRA_ALLOW:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if pattern.search(text):
            offenders.append(_rel(path))
    assert not offenders, (
        "test code invokes the fleet shell helpers directly; drive nginx "
        f"through the registry instead: {sorted(offenders)}"
    )


def test_no_new_inline_nginx_configs():
    """No test module may embed an nginx config (events{} + http/stream{})
    outside the shrinking backlog — render from a committed template instead."""
    new_offenders = sorted(_inline_config_modules() - INLINE_CONFIG_BACKLOG)
    assert not new_offenders, (
        "new inline nginx config(s) in a test module — extract to a "
        "tests/configs/*.conf template and drive it through the registry: "
        f"{new_offenders}"
    )


def test_inline_config_backlog_only_shrinks():
    """Every INLINE_CONFIG_BACKLOG entry must still embed an inline config.
    A migrated file must be removed from the list so it can only shrink."""
    stale = sorted(INLINE_CONFIG_BACKLOG - _inline_config_modules())
    assert not stale, (
        "stale INLINE_CONFIG_BACKLOG entries — these no longer embed an inline "
        f"nginx config, remove them from the list: {stale}"
    )


def test_shell_tests_fully_ported_except_fleet_backend():
    """Phase-81 endgame: every test shell has been ported to Python and deleted.
    Only the compatibility fleet backend (manage_test_servers.sh) and its
    sourced tests/lib/*.sh helpers may remain."""
    present = {path.name for path in SH_FILES}
    assert "manage_test_servers.sh" in present
    allowed_dirs = {TESTS / "lib"}
    strays = [
        _rel(p)
        for p in SH_FILES
        if p.parent not in allowed_dirs and p.name != "manage_test_servers.sh"
    ]
    assert not strays, f"unported/undeleted shell scripts: {strays}"
