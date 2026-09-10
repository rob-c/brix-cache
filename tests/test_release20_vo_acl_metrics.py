"""2.0 readiness F15 — VO-ACL and authdb verdicts on ``/metrics``.

GSI sign-in is counted once per session in ``brix_auth_total{method="gsi"}``;
a VO or authdb DENIAL is an authorisation verdict on the operation and shows up
as ``brix_requests_total{op=...,status="error"}`` — never as a second or failed
authentication, and never as a label carrying the VO or the path.  Legs, on a
``brix_require_vo`` export and on a ``brix_authdb`` twin: the right VO reads
and both counters move (success); the wrong VO is denied and only the
operation's error counter moves (error); a proxy with no VO at all is denied
on every VO path while its sign-in still counted ok, and no label anywhere
names a VO or a path (security negative).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from _test_release20_metrics_helpers import samples, scrape, total, wait_for, wait_port
from _test_vo_acl_helpers import (
    _gsi_env, _guard_vo_nginx_1, _guard_vo_nginx_2, _make_voms_proxy,
    _make_voms_signing_cert, _make_vomsdir,
)
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, CA_CERT, CA_DIR, HOST, PROXY_STD, SERVER_CERT, SERVER_KEY, VOMSDIR

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-r20-vo")]

PKI = {"SERVER_CERT": SERVER_CERT, "SERVER_KEY": SERVER_KEY, "CA_CERT": CA_CERT,
       "CA_DIR": CA_DIR, "VOMSDIR": VOMSDIR, "BIND_HOST": BIND_HOST}


class Lab:
    def __init__(self, ep, cms, atlas):
        self.ep, self.cms, self.atlas = ep, cms, atlas

    def scrape(self):
        return scrape(self.ep.extra_ports["METRICS_PORT"])

    def stat(self, path, proxy):
        r = subprocess.run(["xrdfs", f"root://{HOST}:{self.ep.port}", "stat", path],
                           env=_gsi_env(proxy), capture_output=True, text=True, timeout=20)
        return r.returncode


def _proxies(tmp_path):
    _guard_vo_nginx_1()
    _make_voms_signing_cert()
    _make_vomsdir()
    _guard_vo_nginx_2()
    cms, atlas = str(tmp_path / "proxy_cms.pem"), str(tmp_path / "proxy_atlas.pem")
    _make_voms_proxy("cms", "/cms/Role=NULL/Capability=NULL", cms)
    _make_voms_proxy("atlas", "/atlas/Role=NULL/Capability=NULL", atlas)
    return cms, atlas


def _seed(data, dirs):
    for d in dirs:
        (data / d).mkdir(parents=True, exist_ok=True)
        (data / d / "seed.txt").write_text(f"seed in {d}\n")


def _ready(lab):
    """A GSI stat of the open /public file: allowed on both templates (the
    authdb grants only /public, /private and the VO trees, never "/")."""
    return True if lab.stat("/public/seed.txt", lab.cms) == 0 else None


def _start(lifecycle, tmp_path, name, template, dirs):
    cms, atlas = _proxies(tmp_path)
    data = tmp_path / "data"
    _seed(data, dirs)
    ep = lifecycle.start(NginxInstanceSpec(
        name=name, template=template, data_root=str(data), template_values=PKI,
        reason=f"2.0 readiness F15: {name}"))
    if not wait_port(ep.extra_ports["METRICS_PORT"]):
        pytest.skip(f"{name} exposed no /metrics")
    lab = Lab(ep, cms, atlas)
    if wait_for(lambda: _ready(lab), 20) is None:
        pytest.skip(f"{name} never answered a GSI stat")
    return lab


@pytest.fixture
def vo(lifecycle, tmp_path):
    return _start(lifecycle, tmp_path, "lc-r20-vo-metrics",
                  "nginx_lc_r20_vo_metrics.conf", ("cms", "atlas", "public"))


@pytest.fixture
def authdb(lifecycle, tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "authdb").write_text(
        "u * /public rl\ng cms /cms r\ng atlas /atlas r\nu * /private rw\n")
    return _start(lifecycle, tmp_path, "lc-r20-authdb-metrics",
                  "nginx_lc_r20_authdb_metrics.conf", ("cms", "atlas", "public", "private"))


def _counts(body, port):
    return {
        "gsi_ok": total(body, "brix_auth_total", method="gsi", status="ok"),
        "gsi_fail": total(body, "brix_auth_total", method="gsi", status="fail"),
        "stat_ok": total(body, "brix_requests_total", port=str(port), op="stat", status="ok"),
        "stat_err": total(body, "brix_requests_total", port=str(port), op="stat", status="error"),
    }


def _delta(lab, path, proxy):
    before = _counts(lab.scrape(), lab.ep.port)
    rc = lab.stat(path, proxy)
    after = wait_for(
        lambda: (lambda c: c if c["gsi_ok"] + c["gsi_fail"] > before["gsi_ok"] + before["gsi_fail"] else None)(
            _counts(lab.scrape(), lab.ep.port)),
        timeout=10)
    assert after is not None, "no authentication was counted"
    return rc, {k: after[k] - before[k] for k in before}


def test_right_vo_read_counts_one_signin_and_one_ok_stat(vo):
    rc, d = _delta(vo, "/cms/seed.txt", vo.cms)
    assert rc == 0
    assert d["gsi_ok"] == 1 and d["gsi_fail"] == 0
    assert d["stat_ok"] >= 1 and d["stat_err"] == 0
    rc, d = _delta(vo, "/atlas/seed.txt", vo.atlas)
    assert rc == 0 and d["gsi_ok"] == 1 and d["stat_err"] == 0


@pytest.mark.parametrize("path,who", [("/cms/seed.txt", "atlas"), ("/atlas/seed.txt", "cms")])
def test_cross_vo_denial_is_an_operation_error_not_an_auth_failure(vo, path, who):
    _assert_denied_after_a_counted_signin(vo, path, getattr(vo, who))


def _assert_denied_after_a_counted_signin(lab, path, proxy):
    rc, d = _delta(lab, path, proxy)
    assert rc != 0, f"{path} was served"
    assert d["gsi_ok"] == 1 and d["gsi_fail"] == 0, d
    assert d["stat_err"] >= 1 and d["stat_ok"] == 0, d


def _assert_label_is_clean(name, key, val):
    """INVARIANT 8: no path fragment in a label value, and a VO name appears
    ONLY as the ``vo`` label of the bounded ``brix_vo_*`` accounting families
    (`src/observability/metrics/stream_tracking.c`) — never on ``brix_auth_total``,
    ``brix_requests_total`` or anything else, and never a DN or a proxy name."""
    assert "/" not in val and "=" not in val, (name, key, val)
    if key == "vo":
        assert name.startswith("brix_vo_") and val in ("cms", "atlas"), (name, val)
        return
    assert "cms" not in val and "atlas" not in val, (name, key, val)


def _assert_labels_name_nothing(body):
    for name, labels, _ in samples(body):
        for key, val in labels.items():
            if key != "export":  # the configured export root: config-time, bounded
                _assert_label_is_clean(name, key, val)


def test_no_vo_proxy_is_denied_everywhere_and_labels_name_nothing(vo):
    for path in ("/cms/seed.txt", "/atlas/seed.txt"):
        _assert_denied_after_a_counted_signin(vo, path, PROXY_STD)
    rc, d = _delta(vo, "/public/seed.txt", PROXY_STD)
    assert rc == 0 and d["stat_ok"] >= 1
    _assert_labels_name_nothing(vo.scrape())


def test_authdb_verdicts_gate_the_operation_not_the_signin(authdb):
    rc, d = _delta(authdb, "/public/seed.txt", PROXY_STD)
    assert rc == 0 and d["gsi_ok"] == 1 and d["stat_ok"] >= 1 and d["stat_err"] == 0
    rc, d = _delta(authdb, "/cms/seed.txt", authdb.cms)
    assert rc == 0 and d["gsi_ok"] == 1 and d["stat_err"] == 0
    rc, d = _delta(authdb, "/cms/seed.txt", authdb.atlas)
    assert rc != 0 and d["gsi_ok"] == 1 and d["gsi_fail"] == 0 and d["stat_err"] >= 1
    rc, d = _delta(authdb, "/private/seed.txt", PROXY_STD)
    assert rc == 0 and d["stat_ok"] >= 1
