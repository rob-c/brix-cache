"""TS-5 security cluster — the token forge move, pinned.

``tokenforge.py`` + ``tokenforge_part2.py`` + ``tokenforge_part3.py`` + the four
``_tokenforge_part2_mixin*`` slices became the
:mod:`brix_suite.security.tokens` package.  Four things have to stay true:

* the seven flat names and the package are ONE namespace, so a caller that
  still says ``from tokenforge import TokenForge`` gets the moved class and not
  a second copy that would drift from it;
* the move was verbatim — every one of the 83 forge methods keeps the body it
  had in the flat slice, so a reviewer can trust that no conformance vector
  quietly changed shape while crossing the seam;
* the manifest module imports and runs on its own, which ``tokenforge_part3``
  never could: it was ``exec``-ed into its parent's globals and reached
  ``TokenForge`` through them;
* ``header_jwk_injection`` mints a token instead of raising.  It called
  ``_rsa_jwk``, which the flat slice never defined, so the method raised
  ``NameError`` for every caller and the two security tests that assert an
  embedded ``jwk`` header is untrusted could never have exercised the server.

Guard #3 (``check_shim_completeness.py``) already pins the *names*; this file
pins the *identity*, the *bytes*, and the behaviour under the import spellings
the tree actually uses.
"""

from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys

import pytest

TESTS = pathlib.Path(__file__).resolve().parent
ROOT = TESTS.parent
SRC = ROOT / "brixtest" / "src"
TOKENS = TESTS / "brix_suite" / "security" / "tokens"
LEGACY = TESTS / "brix_suite" / "_legacy"

#: Minting writes key material and JWKS files, and the forge puts the repository
#: root on ``sys.path`` to reach ``utils.make_token``.  Every probe therefore
#: runs in a child process so neither escapes into this session.  The archived
#: flat slices are imported directly here rather than through the shims, and an
#: archive does no path setup of its own, so the repository root goes on the
#: path explicitly.
_PREAMBLE = ("import sys; sys.path[:0] = [%r, %r, %r]\n"
             % (str(TESTS), str(SRC), str(ROOT)))

#: The flat slice each package module was cut from.  The facade keeps the
#: slice-letter classes as aliases, so the pairing is checkable by name.
_MOVES = {
    "mint.py": "_tokenforge_part2_mixina_flat.py",
    "signing.py": "_tokenforge_part2_mixinb_flat.py",
    "claims.py": "_tokenforge_part2_mixinc_flat.py",
}


def _probe(code: str) -> str:
    proc = subprocess.run([sys.executable, "-c", _PREAMBLE + code],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def _probe_json(code: str):
    """Read the probe's last line as JSON.

    ``TokenIssuer.init_keys`` prints where it put the key and the JWKS, so a
    probe that has to mint first cannot own the whole of stdout.
    """
    return json.loads(_probe(code).splitlines()[-1])


def _methods(path: pathlib.Path) -> dict:
    """Map method name -> its exact source text, for every class in a file."""
    source = path.read_text()
    found = {}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ClassDef):
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    found[member.name] = ast.get_source_segment(source, member)
    return found


def _defines(path: pathlib.Path, name: str) -> bool:
    return any(isinstance(node, ast.FunctionDef) and node.name == name
               for node in ast.parse(path.read_text()).body)


# ---------------------------------------------------------------------------
# success


@pytest.mark.parametrize("flat,canonical", [
    ("tokenforge", "brix_suite.security.tokens"),
    ("tokenforge_part2", "brix_suite.security.tokens"),
    ("tokenforge_part3", "brix_suite.security.tokens.manifest"),
    ("_tokenforge_part2_mixina", "brix_suite.security.tokens"),
    ("_tokenforge_part2_mixinb", "brix_suite.security.tokens"),
    ("_tokenforge_part2_mixinc", "brix_suite.security.tokens"),
    ("_tokenforge_part2_mixind", "brix_suite.security.tokens"),
])
def test_flat_spelling_is_the_package_object(flat, canonical):
    """One module object, not two copies that can drift apart."""
    out = _probe(
        "import %s as flat, %s as canon; print(flat is canon)" % (flat, canonical))
    assert out == "True"


@pytest.mark.parametrize("moved,archived", sorted(_MOVES.items()))
def test_every_method_moved_verbatim(moved, archived):
    """Bodies are byte-identical to the pre-move slice."""
    before = _methods(LEGACY / archived)
    after = _methods(TOKENS / moved)
    assert before, "archive %s exposes no methods" % archived
    missing = sorted(set(before) - set(after))
    assert not missing, "%s lost %s" % (moved, missing)
    changed = sorted(n for n in before if before[n] != after[n])
    assert not changed, "%s changed bodies: %s" % (moved, changed)


def test_mixin_d_merged_into_claims():
    """The one-method slice is gone, and its method landed in ``claims``."""
    archived = _methods(LEGACY / "_tokenforge_part2_mixind_flat.py")
    assert sorted(archived) == ["aud_any"]
    claims = _methods(TOKENS / "claims.py")
    assert claims["aud_any"] == archived["aud_any"]


def test_the_forge_still_composes_every_method():
    """83 methods before the move, the same 83 after."""
    out = _probe(
        "import inspect;"
        "from brix_suite.security.tokens import TokenForge as T;"
        "print(len([n for n, f in inspect.getmembers(T, inspect.isfunction)"
        " if f.__module__.startswith('brix_suite.security.tokens')]))")
    assert int(out) == 83


def test_the_duplicated_encoders_became_one():
    """``_b64url``/``_seg`` had five byte-identical definitions; now one."""
    archives = [LEGACY / n for n in (
        "tokenforge_flat.py", "_tokenforge_part2_mixina_flat.py",
        "_tokenforge_part2_mixinb_flat.py", "_tokenforge_part2_mixinc_flat.py",
        "_tokenforge_part2_mixind_flat.py")]
    for helper in ("_b64url", "_seg"):
        assert sum(_defines(p, helper) for p in archives) == 5
        homes = [p.name for p in sorted(TOKENS.glob("*.py")) if _defines(p, helper)]
        assert homes == ["jose.py"], "%s also defined in %s" % (helper, homes)


# ---------------------------------------------------------------------------
# error


def test_manifest_imports_and_runs_on_its_own_now():
    """The archived slice raises ``NameError``; the moved module does not.

    ``tokenforge_part3`` reached ``TokenForge`` through the globals it was
    ``exec``-ed into, so importing it directly gave a module whose functions
    all failed on first call.
    """
    err = _probe(
        "import tempfile;"
        "import brix_suite._legacy.tokenforge_part3_flat as flat;"
        "\ntry:\n"
        "    flat.alg_jwks(tempfile.mkdtemp()); print('no-error')\n"
        "except NameError as exc: print(type(exc).__name__)")
    assert err == "NameError"

    kids = _probe_json(
        "import json, os, tempfile;"
        "import brix_suite.security.tokens.manifest as man;"
        "d = tempfile.mkdtemp();"
        "man.alg_jwks(d);"
        "print(json.dumps([k['kid'] for k in "
        "    json.load(open(os.path.join(d, 'jwks_alg.json')))['keys']]))")
    assert kids == ["test-key-1", "ec-p384", "ec-p521"], kids


def test_importing_the_manifest_module_first_does_not_deadlock_the_cycle():
    """``manifest`` imports ``TokenForge`` from the facade that composes it.

    Importing the submodule first initialises the parent package first, so the
    class is bound before the final import runs.  A regression here shows up as
    ``ImportError: cannot import name 'TokenForge'``, not as a subtle failure.
    """
    out = _probe("import brix_suite.security.tokens.manifest as m;"
                 " print(m.TokenForge.__name__)")
    assert out == "TokenForge"


# ---------------------------------------------------------------------------
# security-negative


def test_header_jwk_injection_mints_a_forged_token_instead_of_raising():
    """The RFC 7515 §4.1.3 vector must exist before a server can be judged on it.

    ``_rsa_jwk`` lived in ``tokenforge.py``'s globals and never in the slice
    whose method called it, so this raised ``NameError`` for every caller —
    including ``test_wlcg_token_conformance_headers.py`` HDR-11 and
    ``test_wlcg_token_conformance_parity.py``, both of which assert the server
    REJECTS a token whose signing key is embedded in the header.  A vector that
    cannot be minted is a security assertion that was never made.
    """
    out = _probe_json(
        "import base64, json, tempfile;"
        "from brix_suite.security.tokens import TokenForge;"
        "f = TokenForge(tempfile.mkdtemp());"
        "tok = f.header_jwk_injection();"
        "hdr = json.loads(base64.urlsafe_b64decode("
        "    tok.split('.')[0] + '=' * (-len(tok.split('.')[0]) % 4)));"
        "print(json.dumps([tok.count('.'), hdr.get('kid'), 'jwk' in hdr,"
        "                  hdr['jwk'].get('kty'), hdr['jwk'].get('kid')]))")
    segments, kid, has_jwk, kty, jwk_kid = out
    assert segments == 2, "not a three-segment JWS"
    assert has_jwk, "the attacker key is not embedded — nothing to reject"
    assert kid == "attacker-1" and jwk_kid == "attacker-1"
    assert kty == "RSA"


def test_the_embedded_key_is_not_the_configured_signing_key():
    """The forgery must be a forgery: the embedded key is a throwaway.

    If the vector were signed by the forge's own configured key the server
    would be right to accept it, and HDR-11 would be asserting the opposite of
    what it means to assert.
    """
    out = _probe_json(
        "import base64, json, tempfile;"
        "from brix_suite.security.tokens import TokenForge;"
        "d = tempfile.mkdtemp();"
        "f = TokenForge(d);"
        "f.init_keys();"
        "tok = f.header_jwk_injection();"
        "hdr = json.loads(base64.urlsafe_b64decode("
        "    tok.split('.')[0] + '=' * (-len(tok.split('.')[0]) % 4)));"
        "own = json.load(open(d + '/jwks.json'))['keys'];"
        "print(json.dumps([hdr['jwk']['n'] in [k.get('n') for k in own],"
        "                  [k.get('kid') for k in own]]))")
    embedded_is_configured, configured_kids = out
    assert not embedded_is_configured, "vector is signed by the trusted key"
    assert "attacker-1" not in configured_kids


# ---------------------------------------------------------------------------
# the CLI — the flat stack's entry point, which `exec` had been carrying


def test_the_forge_cli_still_writes_the_fleet_artifacts_as_a_script():
    """``prep_steps`` runs ``tokenforge.py`` as a script and tolerates failure.

    ``FleetArtifactsStep`` (``brix_suite/prep_steps.py``) invokes this with
    ``tolerate=True, quiet=True``, so the step cannot tell a no-op from a
    success: the move briefly made the CLI exit 0 while writing nothing, and
    every fleet would have come up without ``jwks_multi.json`` or
    ``scitokens.cfg``.  The artefact list, not the exit code, is the assertion.
    """
    out = _probe(
        "import os, subprocess, sys, tempfile;"
        "d = tempfile.mkdtemp();"
        "r = subprocess.run([sys.executable, %r, 'fleet-artifacts', d],"
        "                   capture_output=True, text=True);"
        "print(r.returncode);"
        "print(' '.join(sorted(os.listdir(d))))" % str(TESTS / "tokenforge.py"))
    rc, files = out.splitlines()
    assert rc == "0", out
    assert files.split() == [
        "jwks.json", "jwks_multi.json", "scitokens.cfg",
        "signing_key.pem", "signing_key_2.pem", "signing_key_ec.pem",
    ], files


def test_the_module_spelling_of_the_cli_writes_the_same_artifacts():
    """``python -m brix_suite.security.tokens`` is the spelling TS-5 moves to.

    The flat script name keeps working through the shim; this pins that the two
    entry points share one ``main`` rather than drifting into two CLIs.
    """
    out = _probe(
        "import os, subprocess, sys, tempfile;"
        "d = tempfile.mkdtemp();"
        "env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path[:3]));"
        "r = subprocess.run([sys.executable, '-m', 'brix_suite.security.tokens',"
        "                    'fleet-artifacts', d],"
        "                   capture_output=True, text=True, env=env);"
        "print(r.returncode);"
        "print(' '.join(sorted(os.listdir(d))))")
    rc, files = out.splitlines()
    assert rc == "0", out
    assert "scitokens.cfg" in files.split() and "jwks_multi.json" in files.split()


def test_no_module_reaches_a_name_it_never_binds():
    """The defect class the ``exec`` composition hid, checked statically.

    ``exec``-ing a slice into a parent's globals let it use names its own file
    never imported.  Two survived the flat stack undetected — ``_rsa_jwk`` in
    the mixin that mints the RFC 7515 §4.1.3 vector, and ``write_scitokens_cfg``
    in ``fleet_artifacts`` — because both sat on paths no test reached.  Real
    imports turn every such reference into a ``NameError`` at call time, which
    is only better if something looks for them before a fleet does.
    """
    import builtins

    dangling = {}
    for path in sorted(TOKENS.glob("*.py")):
        tree = ast.parse(path.read_text())
        bound = set(dir(builtins)) | {"__file__", "__name__", "__doc__"}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                bound.add(node.name)
            elif isinstance(node, ast.Import):
                bound.update(a.asname or a.name.split(".")[0]
                             for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                bound.update(a.asname or a.name for a in node.names)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                bound.add(node.id)
            elif isinstance(node, ast.arg):
                bound.add(node.arg)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                bound.add(node.name)
            elif isinstance(node, ast.Global):
                bound.update(node.names)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
                    and node.id not in bound):
                dangling.setdefault(path.name, set()).add(node.id)

    assert not dangling, f"names used but never bound: {dangling}"


def test_an_unknown_subcommand_does_not_report_success():
    """A CLI that prints help and exits 0 is how the no-op stayed invisible."""
    out = _probe(
        "import subprocess, sys;"
        "r = subprocess.run([sys.executable, %r, 'no-such-command'],"
        "                   capture_output=True, text=True);"
        "print(r.returncode)" % str(TESTS / "tokenforge.py"))
    assert out != "0", "an unrecognised subcommand exited 0"
