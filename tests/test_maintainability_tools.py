"""Regression tests for the phase-103 maintainability-conformance tool splits.

phase-103 decomposed 16 over-complex functions across ``tools/`` and ``utils/``
below the CCN-15 cap. Each was a behaviour-preserving refactor, but the tools had
little or no direct coverage, so a bad extraction could pass the complexity gate
while silently changing what the tool DOES. These tests pin the observable
behaviour of the refactored surfaces:

  * pure verdict helpers (coverage / asan / analyzer runners) — exact outputs,
  * the code-generating splitters (split_large_tests / split_large_c) — real
    splits produce valid Python / the documented C fragment structure,
  * the reference XRootD server — a full protocol session round-trips bytes,
  * the token forge — every negative-test kind still yields a 3-part JWT.

Everything here is hermetic (tmp_path + subprocess); nothing needs the fleet or a
configured nginx build, so it runs in the fast lane.
"""

from __future__ import annotations

import ast
import importlib.util
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest
from ephemeral_port import free_port

pytestmark = pytest.mark.xdist_group("maintainability-tools")

ROOT = Path(__file__).resolve().parents[1]


def _load(relpath: str, name: str):
    """Import a tools/utils script by path (those trees have no package init)."""
    if not (ROOT / relpath).exists():
        # The two split_large_* dev tools were only ever untracked
        # working-tree files (no commit in history contains them); a fresh
        # checkout cannot audit a tool it does not have.
        pytest.skip(f"{relpath} is not present in this checkout "
                    f"(untracked dev tool, never committed)")
    spec = importlib.util.spec_from_file_location(name, ROOT / relpath)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# coverage.py — line-rate parsing + floor enforcement                         #
# --------------------------------------------------------------------------- #

def test_coverage_parse_line_rate():
    cov = _load("tools/ci/coverage.py", "cov_lr")
    summary = ("Reading tracefile x\n"
               "  lines......: 87.3% (1234 of 1414 lines)\n"
               "  functions..: 90.0% (9 of 10)\n")
    assert cov._line_rate(summary) == "87.3"
    assert cov._line_rate("no coverage here") == ""
    # a "lines" line with too few fields breaks out to "" (the historical path)
    assert cov._line_rate("  lines\n") == ""


def test_coverage_enforce_floor():
    cov = _load("tools/ci/coverage.py", "cov_ef")
    assert cov._enforce_floor("87.3", None) == 0        # no floor configured
    assert cov._enforce_floor("87.3", "85") == 0        # above floor
    assert cov._enforce_floor("80.0", "85") == 1        # below floor
    assert cov._enforce_floor("", "85") == 1            # floor set, unparsable rate


def test_coverage_verdict_requires_a_green_suite():
    cov = _load("tools/ci/coverage.py", "cov_verdict")
    assert cov._coverage_verdict(0, "68.9", "67") == 0
    assert cov._coverage_verdict(0, "66.9", "67") == 1
    assert cov._coverage_verdict(7, "99.9", "67") == 7


def test_coverage_preflight_skip():
    cov = _load("tools/ci/coverage.py", "cov_pf")
    assert cov._skip_reason("/definitely/not/a/real/nginx")


# --------------------------------------------------------------------------- #
# asan.py — verdict + preflight + provided-binary short-circuit               #
# --------------------------------------------------------------------------- #

def test_asan_scan_verdict(tmp_path):
    asan = _load("tools/ci/asan.py", "asan_sv")
    log_dir = str(tmp_path)
    assert asan._verdict(log_dir, 0) == 0          # clean + ok driver
    assert asan._verdict(log_dir, 5) == 5          # clean but driver failed
    (tmp_path / "asan.1234").write_text(
        "noise\nERROR: AddressSanitizer: heap-use-after-free\n"
        "SUMMARY: AddressSanitizer: heap-use-after-free\n")
    assert asan._verdict(log_dir, 0) == 1          # a real finding fails


def test_asan_preflight_skip_vs_strict(monkeypatch):
    asan = _load("tools/ci/asan.py", "asan_pf")
    reason = asan._missing_prerequisite("/no/such/src")
    assert reason                                       # missing src is named
    monkeypatch.delenv("BRIX_CI_STRICT", raising=False)
    assert asan.skip_or_fail(reason) == 0               # tolerant: skip
    monkeypatch.setenv("BRIX_CI_STRICT", "1")
    assert asan.skip_or_fail(reason) == 1               # required check: fail


def test_asan_uses_provided_binary(monkeypatch):
    asan = _load("tools/ci/asan.py", "asan_bp")
    # a runnable provided binary short-circuits the build and is returned
    monkeypatch.setenv("TEST_ASAN_NGINX_BIN", "/bin/true")
    assert asan._prepare_binary({"tests": "/tmp", "nginx_src": "/tmp"}) \
        == "/bin/true"


# --------------------------------------------------------------------------- #
# analyzer runners — pure gate / normalise / baseline logic                   #
# --------------------------------------------------------------------------- #

def test_fanalyzer_gate_and_parse_args():
    fa = _load("tools/ci/run_fanalyzer.py", "fa_gate")
    # zero-findings gate: any finding fails, an empty set passes
    assert fa._gate_current(["a"]) == 1
    assert fa._gate_current([]) == 0
    assert fa.parse_args([]) == ""
    assert fa.parse_args(["--filter", "src/auth"]) == "src/auth"
    assert fa.parse_args(["src/auth"]) == "src/auth"   # bare back-compat


def test_fanalyzer_normalise_strips_line_col():
    fa = _load("tools/ci/run_fanalyzer.py", "fa_norm")
    raw = [f"{fa.REPO}/src/x.c:42:9: warning: leak of 'p' [-Wanalyzer-malloc-leak]"]
    out = fa.normalise(raw)
    assert len(out) == 1
    # repo prefix dropped, :line:col gone, collapsed to path │ … │ checker
    assert out[0].startswith("src/x.c") and ":42:" not in out[0]
    assert "-Wanalyzer-malloc-leak" in out[0]


def test_codechecker_load_baseline_and_parse_args(tmp_path):
    cc = _load("tools/ci/run_codechecker.py", "cc_bl")
    bl = tmp_path / "baseline.txt"
    bl.write_text("# a comment\n\nsrc/x.c │ core.NullDeref │ abc123\n")
    loaded = cc.load_baseline(str(bl))
    assert loaded == {"src/x.c │ core.NullDeref │ abc123"}
    assert cc.parse_args(["--regen"]) == (1, "")
    assert cc.parse_args(["--filter", "src/auth"]) == (0, "src/auth")


# --------------------------------------------------------------------------- #
# split_large_tests.py — real splits produce valid, capped Python             #
# --------------------------------------------------------------------------- #

def _all_parse_and_fit(paths: list[Path]) -> None:
    for p in paths:
        ast.parse(p.read_text())                        # valid Python
        assert sum(1 for _ in p.open()) <= 500, f"{p.name} over the 500-line cap"


def test_split_extracting_header_branch(tmp_path):
    slt = _load("tools/split_large_tests.py", "slt_hdr")
    lines = ["import pytest\n", "\n", "CONST = 1\n", "\n"]
    for i in range(40):
        lines += [f"def test_case_{i}():\n"] + [f"    assert {i} == {i}  # {j}\n"
                                                for j in range(14)] + ["\n"]
    f = tmp_path / "test_big_nohelpers.py"
    f.write_text("".join(lines))
    slt.split_test_file(str(f))
    outputs = sorted(tmp_path.glob("*.py"))
    assert any(p.name.endswith("_helpers.py") for p in outputs)  # header lifted
    assert any(p.name.endswith("_b.py") for p in outputs)        # split into parts
    _all_parse_and_fit(outputs)


def test_split_reusing_helpers_branch(tmp_path):
    slt = _load("tools/split_large_tests.py", "slt_reuse")
    lines = ["from _shared_helpers import *  # noqa\n", "\n"]
    for i in range(40):
        lines += [f"def test_reuse_{i}():\n"] + [f"    assert True  # {j}\n"
                                                 for j in range(15)] + ["\n"]
    f = tmp_path / "test_big_withhelpers.py"
    f.write_text("".join(lines))
    slt.split_test_file(str(f))
    outputs = sorted(tmp_path.glob("test_*.py"))
    assert any(p.name.endswith("_b.py") for p in outputs)
    # every split keeps the original helpers import (reuse branch)
    for p in outputs:
        assert "from _shared_helpers import *" in p.read_text()
    _all_parse_and_fit(outputs)


def test_split_giant_class_to_mixins(tmp_path):
    slt = _load("tools/split_large_tests.py", "slt_mixin")
    lines = ["import os\n", "\n", "class BigService:\n", "    ATTR = 1\n", "\n"]
    for i in range(40):
        lines += [f"    def method_{i}(self):\n"] + [f"        return {i}  # {j}\n"
                                                     for j in range(14)] + ["\n"]
    f = tmp_path / "giant_class.py"
    f.write_text("".join(lines))
    slt.split_test_file(str(f))
    _all_parse_and_fit(sorted(tmp_path.glob("*.py")))
    # the composed class must still expose every method from both mixins
    sys.path.insert(0, str(tmp_path))
    try:
        mod = _load_from_dir(tmp_path, "giant_class")
        svc = mod.BigService()
        assert svc.method_0() == 0 and svc.method_39() == 39
        assert mod.BigService.ATTR == 1
    finally:
        sys.path.remove(str(tmp_path))


def _load_from_dir(directory: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, directory / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# split_large_c.py — .c split keeps sentinel/include + guarded fragment       #
# --------------------------------------------------------------------------- #

def _big_c_source():
    """A C source with 40 small functions — big enough for split_large_c."""
    lines = ['#include <stdio.h>\n', '\n', 'static int g;\n', '\n']
    for i in range(40):
        body = [f'    x += {j};\n' for j in range(13)]
        lines += [f'static int fn_{i}(int x)\n', '{\n'] + body \
            + ['    return x;\n', '}\n', '\n']
    return "".join(lines)


def test_split_c_file_structure(tmp_path):
    slc = _load("tools/split_large_c.py", "slc")
    f = tmp_path / "big.c"
    f.write_text(_big_c_source())
    slc.split_c_file(str(f))
    frags = sorted(tmp_path.glob("_big_part*.c.inc"))
    assert frags, "expected at least one extracted fragment"
    part1 = f.read_text()
    assert all(('#define __BIG_C_COMPILED__' in part1, '.c.inc"' in part1))
    for frag in frags:
        assert '#ifndef _BIG_PART' in frag.read_text()      # standalone guard
        assert sum(1 for _ in frag.open()) <= 500


# --------------------------------------------------------------------------- #
# xrd_ref_server.py — full protocol session round-trips file bytes            #
# --------------------------------------------------------------------------- #

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", free_port()))  # net-literal-allow: loopback mock shim; leased mock-range port (never kernel-assigned)
        return s.getsockname()[1]


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        assert chunk, "unexpected eof from reference server"
        buf += chunk
    return buf


def test_xrd_ref_server_protocol_roundtrip(tmp_path):
    content = b"reference xrootd payload \x00\x01\x02\n" * 30
    (tmp_path / "test.txt").write_bytes(content)
    port = _free_port()
    srv = subprocess.Popen(
        [sys.executable, str(ROOT / "utils/xrd_ref_server.py"), str(port), str(tmp_path)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        sock = _await_server(port)
        _handshake(sock)
        _request(sock, 1, 3007)                          # login
        _, st, sess = _response(sock)
        assert st == 0 and len(sess) == 16
        _request(sock, 2, 3010, payload=b"/test.txt")    # open
        _, st, ob = _response(sock)
        assert st == 0 and len(ob) == 12
        fh = ob[:4]
        rbody = fh + struct.pack(">q", 0) + struct.pack(">I", len(content))
        _request(sock, 3, 3013, body=rbody)              # read
        _, st, data = _response(sock)
        assert st == 0 and data == content, "file bytes did not round-trip"
        _request(sock, 4, 3013,                           # bad handle -> error
                 body=struct.pack(">I", 999) + struct.pack(">q", 0) + struct.pack(">I", 8))
        _, st, _ = _response(sock)
        assert st != 0
        _request(sock, 5, 3023)                          # endsess
        _, st, _ = _response(sock)
        assert st == 0
        sock.close()
    finally:
        srv.terminate()
        srv.wait(timeout=5)


def _await_server(port: int):
    for _ in range(50):
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=1)  # net-literal-allow: probes the loopback mock shim
        except OSError:
            time.sleep(0.1)
    raise AssertionError("reference server never accepted a connection")


def _handshake(sock) -> None:
    sock.sendall(struct.pack(">iiiii", 0, 0, 0, 4, 2012))
    _recv_exact(sock, 12)


def _request(sock, sid: int, reqid: int, body: bytes = b"", payload: bytes = b"") -> None:
    body = body.ljust(16, b"\0")
    sock.sendall(struct.pack(">HH", sid, reqid) + body
                 + struct.pack(">I", len(payload)) + payload)


def _response(sock):
    sid, status, dlen = struct.unpack(">HHI", _recv_exact(sock, 8))
    return sid, status, (_recv_exact(sock, dlen) if dlen else b"")


# --------------------------------------------------------------------------- #
# make_token.py — every negative-test kind still emits a 3-part JWT           #
# --------------------------------------------------------------------------- #

def test_make_token_every_kind(tmp_path):
    pytest.importorskip("cryptography")
    mk = _load("utils/make_token.py", "mk_tok")
    issuer = mk.TokenIssuer(str(tmp_path))
    issuer.init_keys()

    class _Args:
        sub, scope, groups, audience, issuer, lifetime = "u", "storage.read:/", None, None, None, 3600

    for kind in ("valid", "expired", "bad-signature", "wrong-issuer",
                 "wrong-audience", "no-scope"):
        _Args.kind = kind
        token = mk._issue_variant(issuer, _Args, None)
        assert token.count(".") == 2 and all(token.split(".")), f"{kind} not a JWT"


# --------------------------------------------------------------------------- #
# _xrdcl_worker._encode_response — Pattern-D dispatch registry (§4.3, CCN 39→11)#
# --------------------------------------------------------------------------- #

def test_encode_response_dispatch_and_recursion():
    pytest.importorskip("XRootD")
    import _xrdcl_worker as w
    # container recursion (the prologue that must precede any tname dispatch)
    assert w._encode_response(None) is None
    assert w._encode_response("cms") == "cms" and w._encode_response(42) == 42
    assert "__tuple__" in w._encode_response(("a", 1))
    assert "__list__" in w._encode_response(["a"])
    assert "__dict__" in w._encode_response({"k": 1})

    # tname dispatch: a class named like an XrdCl type routes to its encoder
    class XRootDStatus:
        ok, error, fatal, code, status, errno, message, shellcode = (
            True, False, False, 0, 0, 0, "ok", 0)

    class StatInfoVFS:
        nodes_rw = nodes_staging = free_rw = util_rw = free_staging = util_staging = 3

    assert w._encode_response(XRootDStatus())["__status__"]["ok"] is True
    assert w._encode_response(StatInfoVFS())["__type__"] == "StatInfoVFS"

    # unknown type -> scrape fallback, dropping private + callable attributes
    class Weird:
        pub = 7
        _priv = 9

        def method(self):
            return 1

    scraped = w._encode_response(Weird())
    assert scraped["__type__"] == "Weird" and scraped["pub"] == 7
    assert "_priv" not in scraped and "method" not in scraped


# --------------------------------------------------------------------------- #
# the two NEW phase-103 guards must actually BITE (success + error)            #
# --------------------------------------------------------------------------- #

def test_py_file_size_guard_detects_and_gates(tmp_path, monkeypatch):
    cpfs = _load("tools/ci/check_py_file_size.py", "cpfs")
    # detection: an oversized .py in a scanned tree is listed; a small one is not
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "big.py").write_text("".join(f"x{i} = {i}\n" for i in range(700)))
    (tmp_path / "tests" / "small.py").write_text("y = 1\n")
    listed = {p for p, _ in cpfs.list_oversized(root=tmp_path)}
    assert all(("tests/big.py" in listed, "tests/small.py" not in listed))
    _assert_size_guard_verdict(cpfs, monkeypatch)


def _assert_size_guard_verdict(cpfs, monkeypatch):
    """The guard is a HARD CAP (phase-103 burned the backlog to zero): any file
    over the cap fails; an empty over-cap set passes."""
    monkeypatch.setattr(cpfs, "list_oversized", lambda: [("tests/big.py", 700)])
    assert cpfs.check() == 1                          # an offender over CAP -> FAIL
    monkeypatch.setattr(cpfs, "list_oversized", lambda: [])
    assert cpfs.check() == 0                          # nothing over CAP -> OK


def test_py_complexity_guard_gates(tmp_path, monkeypatch):
    cpc = _load("tools/ci/check_py_complexity.py", "cpc")
    # Hard cap on cyclomatic complexity: any gated function fails, none passes.
    monkeypatch.setattr(cpc, "gate_rows", lambda: [("f.py", "hot", 20)])
    assert cpc.check() == 1                           # an over-complex fn -> FAIL
    monkeypatch.setattr(cpc, "gate_rows", lambda: [])
    assert cpc.check() == 0                           # none over cap -> OK


# --------------------------------------------------------------------------- #
# readability.py — the gate-csv feed check_complexity consumes is well-formed #
# --------------------------------------------------------------------------- #

def test_readability_gate_csv_is_stable(tmp_path):
    if not _have_lizard():
        pytest.skip("lizard not installed")
    over = tmp_path / "hot.py"
    over.write_text(_hot_py_source())
    out = subprocess.run(
        [sys.executable, str(ROOT / "tools/readability.py"), "--gate-csv", str(over)],
        capture_output=True, text=True)
    assert out.returncode == 0
    # one row: file,func,ccn — func "hot" over the CCN cap
    rows = _nonblank_rows(out.stdout)
    assert len(rows) == 1, rows
    path_field, func_field, ccn_field = rows[0].split(",")
    assert all((func_field == "hot", int(ccn_field) > 15))
    assert path_field.endswith("hot.py")


def _nonblank_rows(text):
    """The non-blank lines of `text`."""
    return [r for r in text.splitlines() if r.strip()]


def _hot_py_source():
    """A Python function whose 20 branches push it over the CCN cap."""
    body = ["def hot(x):\n"] \
        + [f"    if x == {i}: x += {i}\n" for i in range(20)] \
        + ["    return x\n"]
    return "".join(body)


def _have_lizard() -> bool:
    import shutil
    return bool(shutil.which("lizard")
                or (Path.home() / ".local/bin/lizard").exists())
