"""The outbound GridFTP lane's wiring — chart, role config and runner (W5.5).

This lane cannot be exercised here: it needs a real Globus or dCache door, and
this repository ships none and cannot.  What CAN be checked here is that the
three places describing the same four fronts still describe the same four
fronts, because they are the parts that rot silently — a renamed port, a
default that quietly reappears, a store line that loses the parameter it exists
to test.  A lane whose wiring has drifted does not fail loudly at the door: it
deploys, skips, and exits 0.

`charts/gridftp-interop/values.yaml`   owns the listeners (helm renders them)
`topology-role/configs/gridftp_outbound.conf`  owns what each listener DOES
`labtools/lab_suite.py`                 owns the env the test runner is given
`remote-suite/tests/test_gridftp_outbound_interop.py`  reads that env
"""
from __future__ import annotations

import re

import pytest
import yaml

from labkit import paths
from labtools import lab_suite

CHART = paths.chart("gridftp-interop")
CONF = paths.config("gridftp_outbound.conf")
REMOTE = paths.SUITE / "tests" / "test_gridftp_outbound_interop.py"

# The fronts in the order values.yaml lists them, which is also the order the
# config indexes them (`index .Values.role.ports N`).  The env-var suffix is
# the front name upper-cased with `-` -> `_`; both spellings appear below.
FRONTS = ("plain", "mode-e", "prot-p", "streams")


@pytest.fixture(scope="module")
def values():
    return yaml.safe_load(CHART.joinpath("values.yaml").read_text())


@pytest.fixture(scope="module")
def outbound(values):
    return values["outbound"]


@pytest.fixture(scope="module")
def conf():
    return CONF.read_text()


def _server_blocks(text):
    """The config's `server { ... }` bodies, in file order."""
    return [m.group(1) for m in
            re.finditer(r"\n    server \{\n(.*?)\n    \}\n", text, re.S)]


def _store_line(block):
    return re.search(r"brix_storage_backend ([^;]+);", block).group(1).strip()


# -- the four fronts agree across the three files --------------------------
def test_the_runner_names_the_ports_helm_actually_listens_on(outbound):
    """`lab_suite._OUTBOUND_PORTS` is a duplicate of the chart's port list.

    It has to be — the runner is a separate release and can only reach the
    fronts by number — so the duplication is pinned here rather than trusted.
    """
    chart_ports = {p["name"].upper().replace("-", "_"): p["port"]
                   for p in outbound["role"]["ports"]}
    assert lab_suite._OUTBOUND_PORTS == chart_ports


def test_the_chart_lists_the_four_documented_fronts_in_order(outbound):
    """Order is load-bearing: the config indexes ports positionally."""
    assert [p["name"] for p in outbound["role"]["ports"]] == list(FRONTS)


def test_every_front_gets_its_own_server_block(conf):
    listens = re.findall(r"listen \{\{ \(index \.Values\.role\.ports (\d)\)", conf)
    assert listens == ["0", "1", "2", "3"]


def _store_suffixes(text):
    """Each front's store-line parameters, with the SPAS count normalised.

    A line that does not start with the shared `{{ $url }}` keeps it here and
    fails the comparison, which is the point: the fronts must differ in the
    parameters and in nothing else, the door included.
    """
    lines = [_store_line(b) for b in _server_blocks(text)]
    bare = [re.sub(r"^\{\{ \$url \}\}", "", line).strip() for line in lines]
    return [re.sub(r"streams=\{\{.*\}\}$", "streams=<n>", line) for line in bare]


def test_the_store_lines_differ_only_in_the_data_channel_parameters(conf):
    """One door, one export, one credential — four store lines.

    Anything else that varied between the fronts would make a difference
    between them attributable to something other than MODE E / PROT P / SPAS,
    which is the whole point of running four.
    """
    assert _store_suffixes(conf) == ["", "mode=e", "mode=e prot=p",
                                     "mode=e streams=<n>"]


def test_the_remote_suite_reads_exactly_the_env_the_runner_exports():
    """A port the runner exports and the suite never reads is a silent skip."""
    exported = {"TEST_OUTBOUND_HOST"} | {
        f"TEST_OUTBOUND_{name}_PORT" for name in lab_suite._OUTBOUND_PORTS}
    read = set(re.findall(r"TEST_OUTBOUND_[A-Z_]+", REMOTE.read_text()))
    assert read == exported


# -- the lane refuses rather than defaults ---------------------------------
def test_the_chart_leaves_the_outbound_role_off(values):
    assert values["outbound"]["enabled"] is False


def test_the_dependency_is_conditional_on_that_switch():
    """Off by default has to mean not rendered, not merely not reached."""
    chart = yaml.safe_load(CHART.joinpath("Chart.yaml").read_text())
    outbound = [d for d in chart["dependencies"] if d.get("alias") == "outbound"]
    assert len(outbound) == 1
    assert outbound[0]["condition"] == "outbound.enabled"
    assert outbound[0]["name"] == "topology-role"


def test_no_door_is_ever_defaulted(outbound):
    """An empty host, and a runner that raises instead of inventing one.

    A placeholder door would deploy, fail to connect, skip every cell and exit
    0 — indistinguishable from a lane that ran and passed.
    """
    assert outbound["role"]["outbound"]["host"] == ""
    with pytest.raises(SystemExit) as exc:
        lab_suite._outbound_door()
    assert "BRIX_OUTBOUND_DOOR" in str(exc.value)


def test_the_protected_front_is_not_rendered_for_a_cleartext_door(conf):
    """`prot=p` on an anonymous ftp:// origin is refused at `nginx -t`.

    Rendering it unconditionally would not fail one cell, it would fail the
    config parse and take all four fronts down with it.
    """
    guarded = re.findall(r'\{\{- if eq \$door\.scheme "gsiftp" \}\}(.*?)'
                         r"\{\{- end \}\}", conf, re.S)
    assert any("prot=p" in g for g in guarded)
    assert any("brix_credential door" in g for g in guarded)
    # ...and the other three fronts are NOT inside such a guard: an ftp:// door
    # must still get a lane, just a three-front one.
    for section in guarded:
        assert "streams=" not in section


# -- security negatives ----------------------------------------------------
def test_the_lane_never_borrows_the_labs_own_pki(conf, outbound):
    """The credential must be the operator's, not the pki-bootstrap Job's.

    Minting one here would authenticate brix to a CA the real door has never
    heard of: the lane would go green against our own trust anchors while
    proving nothing about the door's.
    """
    assert outbound["role"]["auth"] == {"extraSecret": "outbound-proxy",
                                        "caBundle": "outbound-ca"}
    for minted in ("gridftp-pki", "gridftp-ca-bundle", "gridftp-jwks"):
        assert minted not in conf
        assert minted not in yaml.safe_dump(outbound)


def test_the_proxy_is_read_from_the_dereferenced_mount(conf, outbound):
    """`/etc/brix/extra`, the init container's plain emptyDir copy.

    The credential loader opens proxies O_NOFOLLOW and refuses a Secret's
    `..data/` symlink farm, so pointing this at the Secret mount directly would
    fail at load time with a permission-shaped error and no hint why.
    """
    door = outbound["role"]["outbound"]
    assert door["proxyPath"].startswith("/etc/brix/extra/")
    assert door["caDir"] == "/etc/grid-security/certificates"
    assert "x509_proxy {{ $door.proxyPath }};" in conf


def test_no_front_authenticates_without_naming_the_credential(conf):
    """Every gsiftp store line is paired with `brix_storage_credential door`.

    A front that reached a GSI door with no credential named would fall back to
    whatever the worker's environment happened to hold — the confused-deputy
    shape the driver's `_cred` split exists to prevent.
    """
    for block in _server_blocks(conf):
        assert "brix_storage_credential door;" in block
