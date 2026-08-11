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

pytestmark = pytest.mark.xdist_group("maintainability-tools")

ROOT = Path(__file__).resolve().parents[1]


def _load(relpath: str, name: str):
    """Import a tools/utils script by path (those trees have no package init)."""
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
    assert cov._parse_line_rate(summary) == "87.3"
    assert cov._parse_line_rate("no coverage line here") == ""
    # a "lines" line with too few fields breaks out to "" (the historical path)
    assert cov._parse_line_rate("  lines\n") == ""


def test_coverage_enforce_floor():
    cov = _load("tools/ci/coverage.py", "cov_ef")
    assert cov._enforce_floor("87.3", None) == 0        # no floor configured
    assert cov._enforce_floor("87.3", "85") == 0        # above floor
    assert cov._enforce_floor("80.0", "85") == 1        # below floor
    assert cov._enforce_floor("", "85") == 1            # floor set, unparsable rate


def test_coverage_preflight_skip():
    cov = _load("tools/ci/coverage.py", "cov_pf")
    assert cov._preflight_skip("/definitely/not/a/real/nginx") is not None


# --------------------------------------------------------------------------- #
# asan.py — verdict + preflight + provided-binary short-circuit               #
# --------------------------------------------------------------------------- #

def test_asan_scan_verdict(tmp_path):
    asan = _load("tools/ci/asan.py", "asan_sv")
    log_dir = str(tmp_path)
    assert asan._scan_verdict(log_dir, 0) == 0          # clean + ok driver
    assert asan._scan_verdict(log_dir, 5) == 5          # clean but driver failed
    (tmp_path / "asan.1234").write_text(
        "noise\nERROR: AddressSanitizer: heap-use-after-free\n"
        "SUMMARY: AddressSanitizer: heap-use-after-free\n")
    assert asan._scan_verdict(log_dir, 0) == 1          # a real finding fails


def test_asan_preflight_skip_vs_strict(monkeypatch):
    asan = _load("tools/ci/asan.py", "asan_pf")
    monkeypatch.delenv("BRIX_CI_STRICT", raising=False)
    assert asan._asan_preflight("/no/such/src") == 0    # tolerant: skip
    monkeypatch.setenv("BRIX_CI_STRICT", "1")
    assert asan._asan_preflight("/no/such/src") == 1    # required check: fail


def test_asan_uses_provided_binary(monkeypatch):
    asan = _load("tools/ci/asan.py", "asan_bp")
    # a runnable provided binary short-circuits the build and is returned
    monkeypatch.setenv("TEST_ASAN_NGINX_BIN", "/bin/true")
    assert asan._build_or_use_provided("/tmp", "/tmp") == "/bin/true"


# --------------------------------------------------------------------------- #
# analyzer runners — pure gate / normalise / baseline logic                   #
# --------------------------------------------------------------------------- #

def test_fanalyzer_gate_and_parse_args():
    fa = _load("tools/ci/run_fanalyzer.py", "fa_gate")
    ok, new = fa.gate(["a", "b"], ["a"])
    assert ok is False and new == ["b"]
    ok, new = fa.gate(["a"], ["a", "b"])
    assert ok is True and new == []
    assert fa.parse_args(["--regen"]) == (True, "")
    assert fa.parse_args(["--filter", "src/auth"]) == (False, "src/auth")
    assert fa.parse_args(["src/auth"]) == (False, "src/auth")   # bare back-compat


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

def test_split_c_file_structure(tmp_path):
    slc = _load("tools/split_large_c.py", "slc")
    lines = ['#include <stdio.h>\n', '\n', 'static int g;\n', '\n']
    for i in range(40):
        lines += [f'static int fn_{i}(int x)\n', '{\n'] + [f'    x += {j};\n'
                  for j in range(13)] + ['    return x;\n', '}\n', '\n']
    f = tmp_path / "big.c"
    f.write_text("".join(lines))
    slc.split_c_file(str(f))
    frags = sorted(tmp_path.glob("_big_part*.c.inc"))
    assert frags, "expected at least one extracted fragment"
    part1 = f.read_text()
    assert '#define __BIG_C_COMPILED__' in part1 and '.c.inc"' in part1
    for frag in frags:
        assert '#ifndef _BIG_PART' in frag.read_text()      # standalone guard
        assert sum(1 for _ in frag.open()) <= 500


# --------------------------------------------------------------------------- #
# xrd_ref_server.py — full protocol session round-trips file bytes            #
# --------------------------------------------------------------------------- #

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
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
            return socket.create_connection(("127.0.0.1", port), timeout=1)
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
        token = mk._generate_token(issuer, _Args, None)
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
    assert "tests/big.py" in listed and "tests/small.py" not in listed
    # verdict: a new oversized file fails; frozen at its size passes; growth fails
    monkeypatch.setattr(cpfs, "list_oversized", lambda: [("tests/big.py", 700)])
    bl = tmp_path / "bl.txt"
    monkeypatch.setattr(cpfs, "BACKLOG", bl)
    bl.write_text("")
    assert cpfs.check() == 1                          # new offender -> FAIL
    bl.write_text("tests/big.py\t700\n")
    assert cpfs.check() == 0                          # frozen at its size -> OK
    bl.write_text("tests/big.py\t650\n")
    assert cpfs.check() == 1                          # grew past ceiling -> FAIL


def test_py_complexity_guard_gates(tmp_path, monkeypatch):
    cpc = _load("tools/ci/check_py_complexity.py", "cpc")
    monkeypatch.setattr(cpc, "gate_rows", lambda: [("f.py", "hot", 20)])
    bl = tmp_path / "bl.txt"
    monkeypatch.setattr(cpc, "BACKLOG", bl)
    bl.write_text("")
    assert cpc.check() == 1                           # new over-complex fn -> FAIL
    bl.write_text("f.py::hot\t20\n")
    assert cpc.check() == 0                           # frozen at its ccn -> OK
    bl.write_text("f.py::hot\t18\n")
    assert cpc.check() == 1                           # grew past ceiling -> FAIL


# --------------------------------------------------------------------------- #
# readability.py — the gate-csv feed check_complexity consumes is well-formed #
# --------------------------------------------------------------------------- #

def test_readability_gate_csv_is_stable(tmp_path):
    if not _have_lizard():
        pytest.skip("lizard not installed")
    over = tmp_path / "hot.py"
    body = ["def hot(x):\n"] + [f"    if x == {i}: x += {i}\n" for i in range(20)] + ["    return x\n"]
    over.write_text("".join(body))
    out = subprocess.run(
        [sys.executable, str(ROOT / "tools/readability.py"), "--gate-csv", str(over)],
        capture_output=True, text=True)
    assert out.returncode == 0
    # one row: file,func,ccn — func "hot" over the CCN cap
    rows = [r for r in out.stdout.splitlines() if r.strip()]
    assert len(rows) == 1, rows
    path_field, func_field, ccn_field = rows[0].split(",")
    assert func_field == "hot" and int(ccn_field) > 15
    assert path_field.endswith("hot.py")


def _have_lizard() -> bool:
    import shutil
    return bool(shutil.which("lizard")
                or (Path.home() / ".local/bin/lizard").exists())
