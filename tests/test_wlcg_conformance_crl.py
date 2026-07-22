"""CRL-* — revocation and brix_crl_mode on the davs:// wire.

The forge writes CRLs as <hash>.r0 beside the CA, so brix_webdav_crl points at
the CA directory.  brix_crl_mode governs strictness:
  off     -> CRLs ignored even when present
  try     -> revocation enforced where a CRL exists; a CA with none passes;
             an EXPIRED CRL is still fatal
  require -> a missing/expired CRL is fatal
"""
import pytest

import x509forge
from wlcg_fleet import WlcgInstance

# Bucket-2 lifecycle subjects: all four WLCG conformance files share one
# fixed-port WlcgInstance ("lc-wlcg") and serialise onto one worker via a shared
# xdist_group so the fixed exclusive-band port never has two concurrent drivers.
pytestmark = [pytest.mark.x509conf, pytest.mark.slow, pytest.mark.xdist_group("lc-wlcg")]


@pytest.fixture(scope="module")
def crl_fixtures(tmp_path_factory):
    root = tmp_path_factory.mktemp("crl")
    return {
        "revoked": x509forge.forge_scenario(root, "crl_revoked_eec"),
        "expired": x509forge.forge_scenario(root, "crl_expired"),
        "nocrl": x509forge.forge_scenario(root, "sp_no_policy"),
    }


def test_crl_revoked_rejected_good_accepted(tmp_path, crl_fixtures):
    sc = crl_fixtures["revoked"]
    inst = WlcgInstance(tmp_path / "try", ca_dir=sc.ca_dir,
                        crl=sc.ca_dir, crl_mode="try")
    inst.start()
    try:
        assert inst.attempt_davs(sc.credentials["good"])[0] is True, \
            "non-revoked EEC must be accepted"
        assert inst.attempt_davs(sc.credentials["revoked"])[0] is False, \
            "revoked EEC must be rejected"
    finally:
        inst.stop()


def test_crl_off_ignores_revocation(tmp_path, crl_fixtures):
    sc = crl_fixtures["revoked"]
    inst = WlcgInstance(tmp_path / "off", ca_dir=sc.ca_dir,
                        crl=sc.ca_dir, crl_mode="off")
    inst.start()
    try:
        assert inst.attempt_davs(sc.credentials["revoked"])[0] is True, \
            "crl_mode=off must not enforce revocation"
    finally:
        inst.stop()


def test_crl_expired_is_fatal_in_try(tmp_path, crl_fixtures):
    sc = crl_fixtures["expired"]
    inst = WlcgInstance(tmp_path / "exp", ca_dir=sc.ca_dir,
                        crl=sc.ca_dir, crl_mode="try")
    inst.start()
    try:
        # A stale CRL is evidence of neglect, not absence -> reject even in try.
        assert inst.attempt_davs(sc.credentials["eec"])[0] is False
    finally:
        inst.stop()


def test_crl_missing_try_passes_require_rejects(tmp_path, crl_fixtures):
    """A CA with a CRL path configured but no CRL present: try tolerates,
    require rejects."""
    sc = crl_fixtures["nocrl"]
    empty = tmp_path / "emptycrl"
    empty.mkdir()

    tryinst = WlcgInstance(tmp_path / "t", ca_dir=sc.ca_dir,
                           crl=empty, crl_mode="try")
    tryinst.start()
    try:
        assert tryinst.attempt_davs(sc.credentials["eec"])[0] is True
    finally:
        tryinst.stop()

    reqinst = WlcgInstance(tmp_path / "r", ca_dir=sc.ca_dir,
                           crl=empty, crl_mode="require")
    reqinst.start()
    try:
        assert reqinst.attempt_davs(sc.credentials["eec"])[0] is False
    finally:
        reqinst.stop()


def test_crl_unrevocation_via_reload(tmp_path):
    """Replacing the CRL with one that no longer revokes, then reloading,
    restores acceptance."""
    sc = x509forge.forge_scenario(tmp_path / "unrev", "crl_revoked_eec")
    inst = WlcgInstance(tmp_path / "inst", ca_dir=sc.ca_dir,
                        crl=sc.ca_dir, crl_mode="try")
    inst.start()
    try:
        assert inst.attempt_davs(sc.credentials["revoked"])[0] is False
        # Re-sign the CRL revoking nothing (same CA key), then reload.
        x509forge.rewrite_crl(sc, revoked_names=[])
        inst.reload()
        assert inst.attempt_davs(sc.credentials["revoked"])[0] is True
    finally:
        inst.stop()
