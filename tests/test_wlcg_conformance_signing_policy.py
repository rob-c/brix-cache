"""SP-* — signing_policy enforcement on the davs:// wire.

Each scenario is materialised by x509forge and driven through a real nginx
instance whose brix_webdav_cadir points at the scenario's hashed CA directory.
The verdict is produced by brix's own certificate verifier (auth_cert.c ->
brix_gsi_verify_chain), so a PASS here proves the production code path enforces
the signing_policy namespace rule, not just the standalone parser.
"""
import json

import pytest

import x509forge
from wlcg_fleet import WlcgInstance

# Bucket-2 lifecycle subjects: all four WLCG conformance files share one
# fixed-port WlcgInstance ("lc-wlcg") and serialise onto one worker via a shared
# xdist_group so the fixed exclusive-band port never has two concurrent drivers.
pytestmark = [pytest.mark.x509conf, pytest.mark.slow, pytest.mark.xdist_group("lc-wlcg")]

# Scenarios whose manifest verdict is independent of the CA-not-present-mode
# distinction (each has a policy file that names its own CA).
SP_SCENARIOS = [
    "sp_in_namespace",
    "sp_out_of_namespace",
    "sp_wrong_ca_block",
    "sp_proxy_cn_exempt",
]


@pytest.fixture(scope="module")
def sp_fixtures(tmp_path_factory):
    root = tmp_path_factory.mktemp("sp")
    return {name: x509forge.forge_scenario(root, name) for name in SP_SCENARIOS}


def _manifest(sc):
    return json.loads((sc.dir / "manifest.json").read_text())


@pytest.mark.parametrize("scenario", SP_SCENARIOS)
def test_signing_policy_verdict_davs(tmp_path, sp_fixtures, scenario):
    sc = sp_fixtures[scenario]
    inst = WlcgInstance(tmp_path / scenario, ca_dir=sc.ca_dir,
                        signing_policy="on")
    inst.start()
    try:
        for m in _manifest(sc):
            if m["surface"] not in ("davs", "both"):
                continue
            cred = sc.credentials[m["credential"]]
            accepted, code = inst.attempt_davs(cred)
            want = (m["expected"] == "accept")
            assert accepted == want, (
                f"{scenario}/{m['credential']}: expected {m['expected']} "
                f"but server returned HTTP {code} (accepted={accepted}); "
                f"reason={m['reason']}")
    finally:
        inst.stop()


def test_signing_policy_require_rejects_ca_without_policy(tmp_path):
    """REQUIRE mode: a CA whose dir has no signing_policy file is rejected,
    even for an otherwise valid in-namespace-style EEC."""
    sc = x509forge.forge_scenario(tmp_path / "nopolicy", "sp_no_policy")
    on = WlcgInstance(tmp_path / "on", ca_dir=sc.ca_dir, signing_policy="on")
    on.start()
    try:
        # ON: no policy file present -> pass-through accept.
        assert on.attempt_davs(sc.credentials["eec"])[0] is True
    finally:
        on.stop()

    req = WlcgInstance(tmp_path / "req", ca_dir=sc.ca_dir,
                       signing_policy="require")
    req.start()
    try:
        # REQUIRE: no policy file present -> reject.
        assert req.attempt_davs(sc.credentials["eec"])[0] is False
    finally:
        req.stop()


def test_signing_policy_off_allows_out_of_namespace(tmp_path):
    """The out-of-namespace verdict is genuinely gated by the directive."""
    sc = x509forge.forge_scenario(tmp_path / "off", "sp_out_of_namespace")
    inst = WlcgInstance(tmp_path / "inst", ca_dir=sc.ca_dir,
                        signing_policy="off")
    inst.start()
    try:
        assert inst.attempt_davs(sc.credentials["eec_out_ns"])[0] is True
    finally:
        inst.stop()


def test_signing_policy_hot_reload_tightens(tmp_path):
    """Editing the policy to a disjoint namespace + reload flips accept->reject."""
    sc = x509forge.forge_scenario(tmp_path / "reload", "sp_in_namespace")
    inst = WlcgInstance(tmp_path / "inst", ca_dir=sc.ca_dir, signing_policy="on")
    inst.start()
    try:
        assert inst.attempt_davs(sc.credentials["eec_in_ns"])[0] is True
        x509forge.rewrite_signing_policy(sc, '"/DC=nobody/*"')
        inst.reload()
        assert inst.attempt_davs(sc.credentials["eec_in_ns"])[0] is False
    finally:
        inst.stop()
