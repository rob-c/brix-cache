"""TS-5, the differentials cluster: three drivers moved into `brix_suite.security`.

`token_differential.py`, `x509_differential.py` and `x509_matrix_differential.py`
are the Layer-3 tier: they replay minted credentials against our server AND
against stock XRootD, assert *ours == spec* and record every place stock XRootD
diverges.  They moved to :mod:`brix_suite.security.tokens_vectors`,
:mod:`~brix_suite.security.x509_vectors` and
:mod:`~brix_suite.security.x509_matrix_vectors`, each behind a §10.2 shim.

Three properties make this cluster the most dangerous of TS-5 to move, and each
one has tests below:

1. **They are scripts, invoked by absolute path.**  Each `cmdscripts/` runner
   does ``python3 tests/<name>.py <arg>``.  A ``__main__`` guard left behind in
   the package is a guard no caller ever reaches.
2. **Their pytest wrappers SKIP by default** — ``TEST_TOKEN_DIFF=1`` /
   ``TEST_X509_DIFF=1``.  So a driver that ran nothing and exited 0 would not
   turn anything red; it would be reported as a pass, indefinitely.
3. **Their exit code is the assertion.**  `main` returns 1 only when *our*
   verdict disagrees with the spec; stock divergences are recorded, never
   fatal.  Invert or flatten that and a real credential-acceptance bug in our
   own server becomes a green run with a findings table nobody reads.

The verbatim-move check is an AST body hash against
``brix_suite/_legacy/*_flat.py``, so a body that changed cannot be argued to be
the same body.
"""

from __future__ import annotations

import ast
import builtins
import hashlib
import pathlib
import runpy
import sys

import pytest

TESTS = pathlib.Path(__file__).resolve().parent
SECURITY = TESTS / "brix_suite" / "security"
LEGACY = TESTS / "brix_suite" / "_legacy"
REPO = TESTS.parent

#: (flat spelling, canonical module, archive, definition count before the move)
CLUSTER = [
    ("token_differential", "brix_suite.security.tokens_vectors",
     "token_differential_flat.py", 4),
    ("x509_differential", "brix_suite.security.x509_vectors",
     "x509_differential_flat.py", 6),
    ("x509_matrix_differential", "brix_suite.security.x509_matrix_vectors",
     "x509_matrix_differential_flat.py", 4),
]


def _import(dotted):
    __import__(dotted)
    return sys.modules[dotted]


def _bodies(path: pathlib.Path) -> dict:
    """sha256 of each top-level def/class body, position-independent.

    `include_attributes=False` is what makes it position-independent: the
    archives carry a prepended header, so line numbers differ by construction
    and an unchanged body must not read as changed.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            blob = "".join(ast.dump(b, include_attributes=False) for b in node.body)
            out[node.name] = hashlib.sha256(blob.encode()).hexdigest()
    return out


# --------------------------------------------------------------------------
# success — the move landed
# --------------------------------------------------------------------------

@pytest.mark.parametrize("flat,dotted,_a,_n", CLUSTER)
def test_flat_spelling_is_the_package_object(flat, dotted, _a, _n):
    """One module object, not two copies.

    `x509_vectors` memoises its throwaway stock-server certificate in a module
    global (`_SRV`).  Two copies would mint two certificates and quietly undo
    the memoisation the flat module was written to rely on.
    """
    canonical = _import(dotted)
    flat_mod = _import(flat)
    assert flat_mod is canonical, f"{flat} and {dotted} are two objects"


@pytest.mark.parametrize("flat,dotted,archive,count", CLUSTER)
def test_every_definition_moved_verbatim(flat, dotted, archive, count):
    moved = SECURITY / (dotted.rsplit(".", 1)[1] + ".py")
    old, new = _bodies(LEGACY / archive), _bodies(moved)
    assert len(old) == count, f"archive shape changed: {sorted(old)}"
    assert set(old) - set(new) == set(), f"lost: {sorted(set(old) - set(new))}"
    differing = sorted(k for k in old if old[k] != new[k])
    assert differing == [], f"bodies changed during the move: {differing}"
    #: the only thing the move is allowed to add is the named entry point.
    assert sorted(set(new) - set(old)) == ["main"]


@pytest.mark.parametrize("flat,dotted,_a,_n", CLUSTER)
def test_the_vector_tables_did_not_lose_a_case(flat, dotted, _a, _n):
    """These modules *are* their vector tables; a silent trim is the whole risk."""
    mod = _import(dotted)
    if flat == "token_differential":
        ids = [c[0] for c in mod.CASES]
        assert ids == [f"DIFF-0{i}" for i in range(1, 8)], ids
    elif flat == "x509_differential":
        assert len(mod.DAVS_SCENARIOS) == 8, mod.DAVS_SCENARIOS
    else:
        assert len(mod.ALL_CLAUSES) > 0


# --------------------------------------------------------------------------
# error — the failure modes the new location introduces
# --------------------------------------------------------------------------

@pytest.mark.parametrize("flat,dotted,_a,_n", CLUSTER)
def test_findings_are_written_to_the_repo_not_under_tests(flat, dotted, _a, _n):
    """The `parents[1]` hazard, stated as a property of the output path.

    Left alone, each FINDINGS path would have named
    ``tests/brix_suite/docs/10-reference/...`` — a directory the writers create
    for themselves, so nothing raises.  The published table would simply have
    stopped being updated, and the tier would still have exited 0.
    """
    findings = pathlib.Path(str(_import(dotted).FINDINGS))
    assert findings.is_absolute()
    assert findings.parent.is_dir(), f"{findings.parent} does not exist"
    assert REPO / "docs" in findings.parents, f"{findings} escaped the docs tree"
    assert TESTS not in findings.parents, f"{findings} was written under tests/"
    assert findings.is_file(), "the committed findings file is no longer the target"


@pytest.mark.parametrize("flat,dotted,_a,_n", CLUSTER)
def test_the_script_entry_point_survived_the_move(flat, dotted, _a, _n, monkeypatch):
    """Run the flat *path* as `__main__`, with the expensive leg stubbed.

    This is the defect the cluster was most exposed to: the runner invokes the
    file by path and its pytest wrapper SKIPs, so a stranded `__main__` would
    exit 0 having replayed nothing and be reported as a pass.
    """
    canonical = _import(dotted)
    seen = {}

    def _fake_run(*a, **kw):
        seen["args"] = (a, kw)
        return ([], []) if flat == "token_differential" else 0

    monkeypatch.setattr(canonical, "run", _fake_run)
    monkeypatch.setattr(sys, "argv", [f"tests/{flat}.py", "/tmp/unused-diff-root"]
                        if flat != "token_differential" else [f"tests/{flat}.py", "1094"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(TESTS / f"{flat}.py"), run_name="__main__")
    assert exc.value.code == 0
    assert "args" in seen, "the entry point never reached run()"


def test_a_fresh_interpreter_reaches_main_by_path(tmp_path):
    """The runner's own spelling: a new process, the file named by path.

    A bad port makes `main` raise before any server is touched, which is the
    cheap proof that the process really got there — a stranded entry point
    would have exited 0 in silence instead.
    """
    import subprocess
    r = subprocess.run(
        [sys.executable, str(TESTS / "token_differential.py"), "not-a-port"],
        capture_output=True, text=True, cwd=str(REPO),
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": "tests",
             "HOME": str(tmp_path)}, timeout=300)
    assert r.returncode != 0, "the script exited 0 without parsing its argument"
    assert "ValueError" in r.stderr, r.stderr[-2000:]


@pytest.mark.parametrize("flat,dotted,_a,_n", CLUSTER)
def test_no_module_reaches_a_name_it_never_binds(flat, dotted, _a, _n):
    """The `exec`-composition defect class, carried as a standing scan.

    None of these three was ever sharded, so they should be clean; the *move*
    is what introduces the risk, by changing where each name comes from.
    """
    moved = SECURITY / (dotted.rsplit(".", 1)[1] + ".py")
    tree = ast.parse(moved.read_text(encoding="utf-8"))
    bound = set(dir(builtins)) | {"__file__", "__name__", "__doc__",
                                  "__package__", "__spec__", "__loader__"}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            bound.add(node.id)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            bound.update(node.names)
        elif isinstance(node, ast.alias):
            bound.add((node.asname or node.name).split(".")[0])
    dangling = sorted({n.id for n in ast.walk(tree)
                       if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
                       and n.id not in bound})
    assert dangling == [], f"{dotted} reaches names it never binds: {dangling}"


def test_the_settings_values_did_not_fork():
    """`brix_suite.settings` and flat `settings` must be the same object.

    Each module now imports the canonical spelling; if the shim were ever
    replaced by a re-implementation, these drivers would probe a different port
    than the fleet was started on and report every case as a reject.
    """
    import settings as flat
    import brix_suite.settings as canonical
    assert flat is canonical
    tv = _import("brix_suite.security.tokens_vectors")
    assert tv.NGINX_TOKEN_PORT == flat.NGINX_TOKEN_PORT
    assert tv.SERVER_HOST == flat.SERVER_HOST
    assert str(tv.TOKENS_DIR) == str(flat.TOKENS_DIR)
    assert _import("brix_suite.security.x509_vectors").HOST == flat.HOST


# --------------------------------------------------------------------------
# security-negative — the tier must still be able to fail
# --------------------------------------------------------------------------

def test_our_own_mismatch_is_fatal_and_a_stock_divergence_is_not(monkeypatch):
    """The asymmetry that makes this a conformance tier rather than a report.

    A mismatch on OUR verdict means our server accepted a credential the spec
    forbids (or refused one it requires) — that must fail the run.  Stock
    XRootD diverging from spec is evidence about *upstream* and must not.
    Flatten either direction and a real acceptance bug ships green.
    """
    mod = _import("brix_suite.security.tokens_vectors")

    monkeypatch.setattr(mod, "run",
                        lambda **kw: ([("DIFF-02", "accept", "reject")], []))
    assert mod.main([]) == 1, "our verdict disagreed with the spec and the tier passed"

    monkeypatch.setattr(mod, "run",
                        lambda **kw: ([], [("DIFF-02", "accept", "reject")]))
    assert mod.main([]) == 0, "a stock-XRootD divergence was made fatal"


@pytest.mark.parametrize("dotted", ["brix_suite.security.x509_vectors",
                                    "brix_suite.security.x509_matrix_vectors"])
def test_the_x509_drivers_pass_their_verdict_straight_through(dotted, monkeypatch):
    mod = _import(dotted)
    monkeypatch.setattr(mod, "run", lambda root: 1)
    assert mod.main(["/tmp/unused-diff-root"]) == 1
    monkeypatch.setattr(mod, "run", lambda root: 0)
    assert mod.main(["/tmp/unused-diff-root"]) == 0


def test_a_rejected_credential_is_still_a_rejected_credential(tmp_path, monkeypatch):
    """The findings writers must not launder a divergence into a clean row.

    Each row records what stock XRootD did next to what the spec demands; the
    `⚠` marker and the divergence section are how an upstream acceptance of a
    revoked or forged credential becomes visible at all.
    """
    tv = _import("brix_suite.security.tokens_vectors")
    out = tmp_path / "tok.md"
    monkeypatch.setattr(tv, "FINDINGS", str(out))
    tv._write_findings([("DIFF-02", "alg_none", "reject", "accept", "reject")],
                       True, [("DIFF-02", "accept", "reject")])
    text = out.read_text()
    assert "## Divergences (xrootd != spec)" in text
    assert "DIFF-02: xrootd=accept, spec=reject" in text

    xv = _import("brix_suite.security.x509_vectors")
    out2 = tmp_path / "x509.md"
    monkeypatch.setattr(xv, "FINDINGS", out2)
    xv._write_findings([("crl_revoked_eec", "eec", "reject", "reject", "accept",
                         "revoked EEC")])
    assert "accept ⚠" in out2.read_text(), "upstream accepting a revoked EEC was unflagged"

    xm = _import("brix_suite.security.x509_matrix_vectors")
    out3 = tmp_path / "matrix.md"
    monkeypatch.setattr(xm, "FINDINGS", out3)
    xm._write([("C-1", "4.2 revocation", "reject", "reject", "accept", "revoked")])
    assert "accept ⚠" in out3.read_text()


def test_the_drivers_never_write_findings_into_the_source_tree(tmp_path, monkeypatch):
    """A findings path under `tests/` is both wrong and a tracked-file hazard.

    The guard-negative rule for this suite is that a test may damage a copy,
    never the real tree; the same holds for a *driver* whose output path the
    move could have redirected into the package it now lives in.
    """
    for dotted in ("brix_suite.security.tokens_vectors",
                   "brix_suite.security.x509_vectors",
                   "brix_suite.security.x509_matrix_vectors"):
        findings = pathlib.Path(str(_import(dotted).FINDINGS))
        assert SECURITY not in findings.parents
        assert LEGACY not in findings.parents
        assert not str(findings).startswith(str(TESTS) + "/")
