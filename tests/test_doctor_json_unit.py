"""Compile + run the `xrddiag doctor --json` assembler unit suite
(client/apps/diag/diag_doctor_json_unittest.c), then parse what it emits.

The assembler stitches one JSON document out of six emitters, four of which live
in their own translation units and each write their own leading comma. That
convention makes the document's validity depend entirely on WHERE the assembler
calls them: a sub-object emitted after the `}` that closes the endpoint lands
between two objects of the endpoints array and the whole document stops being
JSON — which is precisely what the `eos` object used to do. So the suite is in
two halves: the C harness asserts byte ordering and escaping deterministically
(no server, no connection, no libbrix — the TU is #included and every extern is
stubbed), and this driver feeds the printed document to a real JSON parser,
including a mutation check that proves the parser assertion has teeth.
"""
import json
import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(REPO, "client")
DIAG = os.path.join(CLIENT, "apps", "diag")
SRC = os.path.join(DIAG, "diag_doctor_json.c")
TEST = os.path.join(DIAG, "diag_doctor_json_unittest.c")

CFLAGS = ["-std=c11", "-Wall", "-Wextra", "-Werror",
          "-Ilib", "-I../src", "-I../shared", "-DXRDPROTO_NO_NGX"]


def _cc():
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    if not (os.path.exists(SRC) and os.path.exists(TEST)):
        pytest.skip("diag_doctor_json sources missing")
    return cc


def _document(stdout):
    """Pull the single `JSON {...}` line the harness prints out of its output."""
    for line in stdout.splitlines():
        if line.startswith("JSON "):
            return line[len("JSON "):]
    pytest.fail(f"harness printed no JSON document:\n{stdout}")


@pytest.fixture(scope="module")
def json_bin(tmp_path_factory):
    out = str(tmp_path_factory.mktemp("jsonut") / "ut")
    r = subprocess.run(
        [_cc(), *CFLAGS,
         os.path.join("apps", "diag", "diag_doctor_json_unittest.c"),
         "-o", out],
        cwd=CLIENT, capture_output=True, text=True)
    if r.returncode != 0:
        pytest.fail("diag_doctor_json suite failed to COMPILE "
                    f"(warnings are errors):\n{r.stderr}")
    return out


@pytest.fixture(scope="module")
def rendered(json_bin):
    r = subprocess.run([json_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, \
        f"doctor_json suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "all doctor-json assembler checks passed" in r.stdout
    return json.loads(_document(r.stdout))


def test_doctor_json_document_parses(rendered):
    """Success case: the emitted document is valid JSON with the expected shape,
    and every per-endpoint sub-object is a MEMBER of its endpoint rather than a
    sibling that got flushed out past the closing brace."""
    eps = rendered["remote_doctor"]["endpoints"]
    assert len(eps) == 2
    assert rendered["remote_doctor"]["cross_endpoint_analysis"]["hops"] == 1

    assert eps[0]["host"] == "mgm.example.org"
    assert eps[0]["cms"]["role"] == "manager"
    assert eps[0]["latency"]["samples"] == 5
    # the regression under test: `eos` inside the endpoint object, not after it
    assert eps[0]["eos"] == {"kind": "mgm", "instance": "eosdev",
                             "fst_count": 3}
    assert eps[1]["eos"]["kind"] == "fst"
    assert eps[1]["eos"]["geotag"] == "uk::ed::r1"
    assert eps[1]["diagnosis"][0]["kxr"] == 3014
    # an unprobed sub-object emits nothing at all — not a null placeholder
    assert "recon" not in eps[0] and "recon" not in eps[1]


def test_doctor_json_escapes_metacharacters(rendered):
    """Security-negative: an issue string carrying JSON metacharacters must be
    escaped by the emitter, not passed through. If it were not, an attacker-
    influenced field (a server-supplied error text lands in `issues`) could
    close the string and inject structure into an operator's machine report."""
    eps = rendered["remote_doctor"]["endpoints"]
    assert eps[0]["issues"] == ['quoted "issue" with a backslash \\']


def test_doctor_json_mutation_is_caught(tmp_path):
    """Error case / meta-check: move the `eos` emitter back to where the defect
    had it — after the endpoint's closing brace — and the document must stop
    parsing. Without this, a green parse above would not prove the placement is
    what makes it green. The mutated copy shadows the real TU because
    `#include "diag_doctor_json.c"` resolves from the includer's directory."""
    good = open(SRC, encoding="utf-8").read()
    bad = good.replace(
        '        doctor_eos_emit_json(e, out);',
        '        MUTATED_MARKER(e, out);', 1)
    assert bad != good, "call site moved — update this mutation"
    bad = bad.replace('        fprintf(out, "}");',
                      '        fprintf(out, "}");\n'
                      '        doctor_eos_emit_json(e, out);', 1)
    bad = bad.replace('        MUTATED_MARKER(e, out);', '', 1)

    shutil.copy(TEST, tmp_path / "diag_doctor_json_unittest.c")
    (tmp_path / "diag_doctor_json.c").write_text(bad, encoding="utf-8")
    out = str(tmp_path / "ut")
    r = subprocess.run(
        [_cc(), *CFLAGS, "-Iapps/diag",
         str(tmp_path / "diag_doctor_json_unittest.c"), "-o", out],
        cwd=CLIENT, capture_output=True, text=True)
    assert r.returncode == 0, f"mutant failed to compile:\n{r.stderr}"

    m = subprocess.run([out], capture_output=True, text=True, timeout=60)
    assert m.returncode != 0, \
        "the C harness accepted a document with `eos` outside the endpoint " \
        f"object:\n{m.stdout}"
    with pytest.raises(json.JSONDecodeError):
        json.loads(_document(m.stdout))
