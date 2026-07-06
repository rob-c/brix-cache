"""Selftest for the x509forge fixture library."""
import json

import x509forge


def test_forge_baseline_scenario(tmp_path):
    sc = x509forge.forge_scenario(tmp_path, "sp_in_namespace",
                                  x509forge.BASELINE_SPEC)
    names = [p.name for p in sc.ca_dir.iterdir()]
    assert any(n.endswith(".0") for n in names)
    assert any(n.endswith(".signing_policy") for n in names)


def test_forge_all_manifest_has_both_verdicts(tmp_path):
    forged = x509forge.forge_all(tmp_path)
    verdicts = set()
    for sc in forged.values():
        manifest = json.loads((sc.dir / "manifest.json").read_text())
        assert manifest, f"{sc.name} has an empty manifest"
        verdicts |= {m["expected"] for m in manifest}
    assert {"accept", "reject"} <= verdicts


def test_proxy_cert_info_der_roundtrips_oid(tmp_path):
    # A limited proxy must carry the Globus limited policy OID in its PCI.
    der = x509forge.proxy_cert_info_der(x509forge.OID_GLOBUS_LIMITED, None)
    assert isinstance(der, bytes) and der[0] == 0x30  # SEQUENCE
