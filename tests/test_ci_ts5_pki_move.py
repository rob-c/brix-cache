"""TS-5 security cluster — the PKI generator move, pinned.

``tests/pki_helpers.py`` became :mod:`brix_suite.security.pki`.  It is the
smallest move of the cluster and the one with the most hostile call graph: of
its ten call sites, six invoke it as a *string* from a subprocess —
``python -c "from pki_helpers import blitz_test_pki; blitz_test_pki()"`` — so
neither an import rewrite nor a linter can see them, and a broken flat spelling
would surface as a live driver failing to find a CA, not as an ImportError.

Two deviations from a verbatim move are deliberate and are the whole risk of
this move:

* ``ROOT_DIR`` had to walk three parents instead of one.  Left at one, both
  ``MAKE_PROXY`` and ``MAKE_CRL`` would point into a ``tests/utils`` that does
  not exist.  ``MAKE_CRL`` is guarded by ``.exists()``, so the CRL step would
  have gone quiet; the proxy step would have raised only *after* the
  certificates were written, leaving a tree that looks provisioned.
* the settings import names the canonical module.  The §10.2 shim makes the two
  spellings one object, so this cannot fork the values — asserted below rather
  than assumed.

The suite's `_missing_sentinels` check watches `pki/ca/ca.pem`, which the CA
step writes first.  It would not have caught either failure.
"""

from __future__ import annotations

import ast
import builtins
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
SRC = ROOT / "brixtest" / "src"
ARCHIVE = TESTS / "brix_suite" / "_legacy" / "pki_helpers_flat.py"
MOVED = TESTS / "brix_suite" / "security" / "pki.py"


def _probe(code: str, env: dict | None = None) -> str:
    """Run a snippet the way the six string call sites do: a bare subprocess."""
    e = dict(os.environ, PYTHONPATH=str(TESTS))
    e.update(env or {})
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, env=e, cwd=str(ROOT))
    assert proc.returncode == 0, f"rc={proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    return proc.stdout.strip()


# ---------------------------------------------------------------------------
# success


@pytest.mark.parametrize("flat", ["pki_helpers"])
def test_flat_spelling_is_the_package_object(flat):
    """Not "the same names" — the same object.

    Anything weaker allows two copies with two `PKI_DIR`s, one of which is
    stale after a lane rebases its port ladder.
    """
    out = _probe(
        f"import {flat}, brix_suite.security.pki as c; "
        f"print({flat} is c)"
    )
    assert out == "True"


def test_every_definition_moved_verbatim():
    """AST body hash per top-level def/class, archive vs package.

    Position-independent, so the archive's prepended header cannot make an
    unchanged body read as changed.
    """
    def bodies(path: Path) -> dict[str, str]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        out = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                dumped = "".join(
                    ast.dump(b, include_attributes=False) for b in node.body)
                out[node.name] = hashlib.sha256(dumped.encode()).hexdigest()
        return out

    old, new = bodies(ARCHIVE), bodies(MOVED)
    assert old, "archive parsed to nothing — wrong path?"
    assert set(old) == set(new), f"missing={set(old)-set(new)} extra={set(new)-set(old)}"
    differing = [n for n in old if old[n] != new[n]]
    assert differing == [], f"bodies changed in the move: {differing}"
    assert len(old) == 4


def test_the_settings_values_did_not_fork():
    """The import spelling changed; the values it binds must not have.

    `brix_suite.settings` and flat `settings` are one object via the TS-3 shim.
    If that ever stopped being true, this module would read a PKI_DIR from a
    second settings instance — one that never saw the lane's TEST_ROOT rebase.
    """
    out = _probe(
        "import brix_suite.security.pki as p, settings; "
        "print(p.PKI_DIR == settings.PKI_DIR, p.CA_CERT == settings.CA_CERT, "
        "p.USER_KEY == settings.USER_KEY)"
    )
    assert out == "True True True"


# ---------------------------------------------------------------------------
# error


def test_the_repo_root_walk_still_lands_on_the_repo():
    """The deviation, asserted at the value rather than at the literal.

    `parents[3]` is not self-evidently right; `MAKE_PROXY` existing is.
    """
    out = _probe(
        "import brix_suite.security.pki as p; import json; "
        "print(json.dumps([str(p.ROOT_DIR), p.MAKE_PROXY.is_file(), "
        "p.MAKE_CRL.is_file()]))"
    )
    root, proxy, crl = json.loads(out)
    assert Path(root) == ROOT
    assert proxy, "MAKE_PROXY does not exist; blitz_test_pki cannot mint proxies"
    assert crl, "MAKE_CRL does not exist; the CRL step would skip in silence"


def test_no_module_reaches_a_name_it_never_binds():
    """The defect class TS-5 exists to close.

    Under `exec`-composition a module could call a helper its own file never
    imported.  This module was never sharded, so it should be clean — the scan
    is carried here anyway because the *move* is what introduces the risk: a
    name that used to come from `settings` and now does not.
    """
    tree = ast.parse(MOVED.read_text(encoding="utf-8"))
    #: builtins plus the module dunders the interpreter injects — this
    #: module computes `ROOT_DIR` from `__file__`, which no statement binds.
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
    assert dangling == [], f"reaches names it never binds: {dangling}"


def test_the_generator_is_stamped_by_its_canonical_path(tmp_path):
    """`prep_steps` must stamp the moved file, not the shim.

    The shim's mtime is frozen for the life of the migration, so stamping it
    would report "unchanged" for every edit to the generator and let the
    fleet-prep cache restore a PKI built by the old code.
    """
    import brix_suite.prep_steps as prep_steps

    stamped = {p for p in prep_steps._GENERATOR_SOURCES}
    assert MOVED in stamped
    assert (TESTS / "pki_helpers.py") not in stamped


# ---------------------------------------------------------------------------
# security-negative


@pytest.mark.timeout(600)
def test_the_forged_ca_actually_signs_the_user_cert(tmp_path):
    """A tree that *looks* provisioned but does not chain is the failure mode.

    Every GSI, VOMS and proxy test in the suite asserts against this CA.  If
    the move had left the user certificate self-signed, or signed by a CA the
    hash links do not point at, `openssl verify` would be the only thing that
    noticed — and nothing runs it.  Certificate presence is not chain validity.
    """
    lane = tmp_path / "lane"
    (lane / "pki").mkdir(parents=True)
    out = _probe(
        "import pki_helpers, settings, json; "
        "pki_helpers.blitz_test_pki(); "
        "print(json.dumps([settings.PKI_DIR, settings.CA_CERT, "
        "settings.USER_CERT, settings.SERVER_CERT]))",
        env={"TEST_ROOT": str(lane)},
    )
    pki_dir, ca, user, server = json.loads(out.splitlines()[-1])
    assert Path(pki_dir) == lane / "pki", "the lane's TEST_ROOT was not honoured"

    for leaf in (user, server):
        proc = subprocess.run(
            ["openssl", "verify", "-CAfile", ca, leaf],
            capture_output=True, text=True)
        assert proc.returncode == 0, f"{leaf} does not chain to the CA:\n{proc.stderr}"

    # ...and it is a CA, not a look-alike leaf that happens to have signed it.
    text = subprocess.run(["openssl", "x509", "-in", ca, "-noout", "-text"],
                          capture_output=True, text=True, check=True).stdout
    assert "CA:TRUE" in text


@pytest.mark.timeout(600)
def test_the_proxy_step_is_not_allowed_to_go_missing(tmp_path):
    """The `parents[3]` failure, stated as a property of the output tree.

    With ROOT_DIR one level too shallow, `MAKE_CRL.exists()` is False and the
    CRL step vanishes without a word — so every "revoked credential is refused"
    test would run against a PKI with no CRL at all and pass by default.
    """
    lane = tmp_path / "lane"
    (lane / "pki").mkdir(parents=True)
    _probe("import pki_helpers; pki_helpers.blitz_test_pki()",
           env={"TEST_ROOT": str(lane)})
    pki = lane / "pki"
    assert (pki / "user" / "proxy_std.pem").is_file(), "proxies were never minted"
    #: `utils/make_crl.py` writes `ca/test-user.crl.pem`; hash-link form is
    #: `<hash>.r0`.  Accept either — the point is that the step ran at all.
    crls = [q for q in (pki / "ca").iterdir()
            if q.name.endswith(".r0") or "crl" in q.name]
    assert crls, "no CRL emitted; revocation tests would assert nothing"
