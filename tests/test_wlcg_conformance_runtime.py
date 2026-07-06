"""RT-* — runtime trust-store rebuild / reload correctness on davs://.

A SIGHUP rebuilds the CA + CRL + signing_policy store atomically.  These tests
prove the rebuilt store takes effect (revocation, policy tightening,
malformed-file fail-closed) and that an ordinary reload does not disturb an
already-valid credential.
"""
import pytest

import x509forge
from wlcg_fleet import WlcgInstance

pytestmark = [pytest.mark.x509conf, pytest.mark.slow]


def test_reload_preserves_valid_credential(tmp_path):
    sc = x509forge.forge_scenario(tmp_path / "keep", "sp_in_namespace")
    inst = WlcgInstance(tmp_path / "inst", ca_dir=sc.ca_dir, signing_policy="on")
    inst.start()
    try:
        assert inst.attempt_davs(sc.credentials["eec_in_ns"])[0] is True
        inst.reload()   # identical config
        assert inst.attempt_davs(sc.credentials["eec_in_ns"])[0] is True
    finally:
        inst.stop()


def test_reload_applies_revocation(tmp_path):
    sc = x509forge.forge_scenario(tmp_path / "rev", "crl_revoked_eec")
    inst = WlcgInstance(tmp_path / "inst", ca_dir=sc.ca_dir,
                        crl=sc.ca_dir, crl_mode="try")
    inst.start()
    try:
        assert inst.attempt_davs(sc.credentials["good"])[0] is True
        # Revoke the previously-good cert, reload, and confirm it is rejected.
        x509forge.rewrite_crl(sc, revoked_names=["good", "revoked"])
        inst.reload()
        assert inst.attempt_davs(sc.credentials["good"])[0] is False
    finally:
        inst.stop()


def test_reload_malformed_policy_fails_closed(tmp_path):
    sc = x509forge.forge_scenario(tmp_path / "bad", "sp_in_namespace")
    inst = WlcgInstance(tmp_path / "inst", ca_dir=sc.ca_dir, signing_policy="on")
    inst.start()
    try:
        assert inst.attempt_davs(sc.credentials["eec_in_ns"])[0] is True
        # Corrupt the signing_policy file; on reload the CA must fail closed.
        (sc.ca_dir / "signing-policy").write_text(
            "this is not a valid eacl grammar line\n")
        inst.reload()
        assert inst.attempt_davs(sc.credentials["eec_in_ns"])[0] is False
    finally:
        inst.stop()
