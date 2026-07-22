"""CAD-* — CA-directory mechanics on the davs:// wire.

Covers hash-link variants (SHA-1 vs legacy MD5), an expired trust anchor,
hot-reload add/remove of a CA, bundle-file parity, and the
signing_policy=require + bundle-file configuration error.
"""
import json

import pytest

import x509forge
from wlcg_fleet import WlcgInstance

# Bucket-2 lifecycle subjects: all four WLCG conformance files share one
# fixed-port WlcgInstance ("lc-wlcg") and serialise onto one worker via a shared
# xdist_group so the fixed exclusive-band port never has two concurrent drivers.
pytestmark = [pytest.mark.x509conf, pytest.mark.slow, pytest.mark.xdist_group("lc-wlcg")]

CAD_SCENARIOS = ["cad_sha1_only", "cad_md5_only", "cad_expired_ca"]


@pytest.fixture(scope="module")
def cad_fixtures(tmp_path_factory):
    root = tmp_path_factory.mktemp("cad")
    return {name: x509forge.forge_scenario(root, name) for name in CAD_SCENARIOS}


@pytest.mark.parametrize("scenario", CAD_SCENARIOS)
def test_cadir_verdict(tmp_path, cad_fixtures, scenario):
    sc = cad_fixtures[scenario]
    inst = WlcgInstance(tmp_path / scenario, ca_dir=sc.ca_dir,
                        signing_policy="off")   # isolate CA-lookup, not policy
    inst.start()
    try:
        m = json.loads((sc.dir / "manifest.json").read_text())[0]
        accepted, code = inst.attempt_davs(sc.credentials[m["credential"]])
        assert accepted == (m["expected"] == "accept"), (
            f"{scenario}: expected {m['expected']}, HTTP {code}; {m['reason']}")
    finally:
        inst.stop()


def test_cadir_reload_add_ca(tmp_path):
    """A credential is rejected until its CA is added to the dir and reloaded."""
    good = x509forge.forge_scenario(tmp_path / "good", "cad_sha1_only")
    # Start with an EMPTY (but valid) CA dir — no CA the client chains to.
    empty_dir = tmp_path / "emptyca"
    empty_dir.mkdir()
    (empty_dir / "placeholder.pem").write_bytes(
        (good.ca_dir / "ca.pem").read_bytes())   # unrelated: make dir non-empty
    empty_only = tmp_path / "trust"
    empty_only.mkdir()

    inst = WlcgInstance(tmp_path / "inst", ca_dir=empty_only, signing_policy="off")
    inst.start()
    try:
        assert inst.attempt_davs(good.credentials["eec"])[0] is False, \
            "no CA present yet → reject"
        # Copy the CA + its hash link into the trust dir, reload.
        import shutil
        for p in good.ca_dir.iterdir():
            dst = empty_only / p.name
            if p.is_symlink():
                dst.symlink_to(p.readlink())
            else:
                shutil.copy2(p, dst)
        inst.reload()
        assert inst.attempt_davs(good.credentials["eec"])[0] is True, \
            "CA added + reloaded → accept"
    finally:
        inst.stop()


def test_cadir_bundle_file_parity(tmp_path):
    """A single CA bundle file verifies the same EEC a hashed dir would."""
    sc = x509forge.forge_scenario(tmp_path / "bundle", "cad_sha1_only")
    inst = WlcgInstance(tmp_path / "inst", cafile=sc.ca_dir / "ca.pem",
                        signing_policy="off")
    inst.start()
    try:
        assert inst.attempt_davs(sc.credentials["eec"])[0] is True
    finally:
        inst.stop()


def test_require_mode_with_bundle_file_is_config_error(tmp_path):
    """signing_policy=require needs a hashed dir; with a bundle file nginx -t
    must fail (no directory to search for policy files)."""
    sc = x509forge.forge_scenario(tmp_path / "req", "cad_sha1_only")
    inst = WlcgInstance(tmp_path / "inst", cafile=sc.ca_dir / "ca.pem",
                        signing_policy="require")
    result = inst.configtest()
    assert result.returncode != 0, \
        "require + bundle file should fail nginx -t"
    assert "require" in result.stdout or "signing_policy" in result.stdout
