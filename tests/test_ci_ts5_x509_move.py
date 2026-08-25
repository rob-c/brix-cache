"""TS-5 security cluster — the x509 scenario forge move, pinned.

``x509forge.py`` + ``x509forge_part2.py`` + ``x509forge_part3.py`` became the
:mod:`brix_suite.security.x509` package.  The flat trio was composed by
``split_continuation``: shards 2 and 3 were ``compile``-d and ``exec``-ed into
shard 1's globals, which is why each shard repeated the same 49-line prelude
and why shard 3's ``__main__`` guard fired when someone ran shard 1.

The same composition had already been measured to hide two live defects in the
token forge earlier in TS-5 — a mint method calling a helper its own file never
imported, and a CLI that moved out from under its ``__main__`` guard and left
``prep_steps`` exiting 0 while writing nothing.  This file pins the x509 move
against both, plus the properties that make the move safe to depend on:

* the three flat spellings and the package are ONE module object, so the 38
  consumers that still say ``from x509forge import forge_scenario`` cannot end
  up holding a second, drifting copy;
* every one of the 49 functions and classes kept the body it had in the flat
  shard, checked by AST body hash against the ``_legacy`` archives;
* no module reaches a name it never binds — the defect class itself;
* the hostile scenarios still come out hostile.  A forge that quietly emitted a
  *valid* tree would turn every conformance REJECT case green while asserting
  nothing, which is precisely how ``header_jwk_injection`` failed.
"""

from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys

import pytest
from ts5_ast_checks import (
    missing_names,
    move_problem,
    top_level_body_hashes as _file_body_hashes,
)

TESTS = pathlib.Path(__file__).resolve().parent
ROOT = TESTS.parent
SRC = ROOT / "brixtest" / "src"
PKG = TESTS / "brix_suite" / "security" / "x509"
LEGACY = TESTS / "brix_suite" / "_legacy"

#: Forging a scenario generates RSA keys, so the whole-catalogue run costs
#: minutes.  Everything here works from one tree, forged once.
_ARCHIVES = ("x509forge_flat.py", "x509forge_part2_flat.py",
             "x509forge_part3_flat.py")

_PREAMBLE = ("import sys; sys.path[:0] = [%r, %r, %r]\n"
             % (str(TESTS), str(SRC), str(ROOT)))


def _probe(code: str) -> str:
    proc = subprocess.run([sys.executable, "-c", _PREAMBLE + code],
                          capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def _body_hashes(paths) -> dict:
    """Map every top-level function/class to a hash of its body.

    Positions are excluded, so prepending an archive header or reordering the
    modules cannot make an unchanged body look changed.
    """
    out = {}
    for path in paths:
        out.update(_file_body_hashes(pathlib.Path(path)))
    return out


def _assignment_names(node, names):
    if not isinstance(node, ast.Assign):
        return []
    return [
        target.id for target in node.targets
        if isinstance(target, ast.Name) and target.id in names
    ]


def _path_constants(path, names):
    tree = ast.parse(path.read_text())
    return [
        (path.name, name)
        for node in tree.body
        for name in _assignment_names(node, names)
    ]


def _assigned_constants(paths, names):
    return [row for path in paths for row in _path_constants(path, names)]


def _manifest_verdicts(manifest):
    return {row["credential"]: row["expected"] for row in manifest}


def _hash_links(ca_dir):
    return sorted(
        path.name for path in ca_dir.iterdir()
        if path.suffix == ".0" or path.name.endswith(".0")
    )


def _hash_link_problem(links, new_hash, old_hash):
    if f"{old_hash}.0" not in links:
        return f"the legacy MD5 link {old_hash}.0 is missing: {links}"
    if f"{new_hash}.0" in links:
        return "the SHA-1 link is present, so the scenario is no longer hostile"
    return None


def _prelude_problem():
    names = {"_EPOCH", "_DAY", "OID_PROXY_CERT_INFO", "OID_PPL_INHERIT_ALL",
             "OID_PPL_INDEPENDENT", "OID_GLOBUS_LIMITED"}
    archives = [LEGACY / name for name in _ARCHIVES]
    archived = _assigned_constants(archives, names)
    if len(archived) != 18:
        return f"{len(archived)} archived prelude assignments, expected 18"
    defining = _assigned_constants(sorted(PKG.glob("*.py")), names)
    modules = sorted({module for module, _name in defining})
    if modules != ["constants.py"]:
        return f"prelude constants are defined by {modules}"
    if len(defining) != 6:
        return f"constants.py defines {len(defining)} prelude constants, expected 6"
    return None


@pytest.fixture(scope="module")
def forged(tmp_path_factory):
    """One CRL scenario and one MD5-only CA dir, forged once for this module."""
    out = tmp_path_factory.mktemp("x509gate")
    _probe("from brix_suite.security.x509 import forge_scenario;"
           "forge_scenario(%r, 'crl_revoked_eec');"
           "forge_scenario(%r, 'cad_md5_only');"
           "print('ok')" % (str(out), str(out)))
    return out


# ---------------------------------------------------------------------------
# success


@pytest.mark.parametrize("flat", ["x509forge", "x509forge_part2",
                                  "x509forge_part3"])
def test_flat_spelling_is_the_package_object(flat):
    """Not "exports the same names" — the same object.

    Two modules exporting equal functions look identical until one of them is
    reloaded, patched, or edited.  Identity is the property that makes the 38
    consumers safe to leave alone.
    """
    out = _probe("import %s as flat, brix_suite.security.x509 as pkg;"
                 " print(flat is pkg)" % flat)
    assert out == "True"


def test_every_definition_moved_verbatim():
    """60 bodies, hashed against the archives.

    The move was mechanical by construction (line ranges cut out of the
    shards), and this is what proves it stayed mechanical after the imports
    were pruned to what each module actually uses.
    """
    old = _body_hashes(LEGACY / a for a in _ARCHIVES)
    support_modules = {"__init__.py", "__main__.py", "primitive_operations.py"}
    new = _body_hashes(
        path for path in sorted(PKG.glob("*.py"))
        if path.name not in support_modules
    )
    problem = move_problem(old, new, expected_shape=(60, 60))
    assert problem is None, problem


def test_the_facade_still_exports_the_private_helpers():
    """The shards used each other's underscore helpers freely.

    ``import *`` would have dropped exactly those names, which is why the
    facade enumerates them.  ``_scenario``/``_key``/``_symlink`` are the ones
    the shards crossed most.
    """
    out = _probe("import x509forge as f;"
                 " print(all(hasattr(f, n) for n in"
                 " ['_scenario', '_key', '_symlink', '_openssl_hashes',"
                 "  '_der_seq', '_BUILDERS', '_place_ca_in_dir']))")
    assert out == "True"


def test_the_prelude_constants_have_one_definition_now():
    """All three shards opened with the same six assignments.

    Identical values made the triple definition harmless *and* invisible: an
    edit to one copy would have been overwritten by whichever shard loaded
    next, silently and in load order.
    """
    problem = _prelude_problem()
    assert problem is None, problem


# ---------------------------------------------------------------------------
# error


def test_no_module_reaches_a_name_it_never_binds():
    """The ``exec``-composition defect class, checked statically.

    A shard ``exec``-ed into its parent's globals could use any name the parent
    had bound.  Turned into a real import, that reference raises ``NameError``
    at call time — better only if something looks for it before a conformance
    run does.  Four such references existed in this move (``CA_DN``,
    ``_openssl_hashes``, ``_symlink``, ``_key``); this is the check that found
    them.
    """
    dangling = missing_names(sorted(PKG.glob("*.py")))
    assert not dangling, f"names used but never bound: {dangling}"


def test_the_manual_cli_still_forges(tmp_path):
    """``python3 tests/x509forge.py <dir>`` is a documented manual entry point.

    Its ``__main__`` guard was at the foot of shard 3 and only ever fired
    because the shard ran inside shard 1's globals.  The token forge's
    equivalent guard was lost exactly this way and left a ``tolerate=True``
    prep step reporting success over an empty directory, so this asserts on the
    tree, not on the exit code.
    """
    out = tmp_path / "cli"
    proc = subprocess.run([sys.executable, str(TESTS / "x509forge.py"),
                           str(out)],
                          capture_output=True, text=True, timeout=900,
                          cwd=str(TESTS))
    assert proc.returncode == 0, proc.stderr
    scenarios = sorted(p.name for p in out.iterdir() if p.is_dir())
    assert len(scenarios) >= 10, scenarios
    for name in scenarios:
        assert (out / name / "manifest.json").is_file(), name


def test_the_module_spelling_of_the_cli_agrees(tmp_path):
    """``python -m brix_suite.security.x509`` is the spelling TS-5 moves to.

    Both entry points call one ``main``; this pins that they have not drifted
    into two CLIs that forge different catalogues.
    """
    out = tmp_path / "mod"
    proc = subprocess.run(
        [sys.executable, "-m", "brix_suite.security.x509", str(out)],
        capture_output=True, text=True, timeout=900, cwd=str(TESTS))
    assert proc.returncode == 0, proc.stderr
    assert (out / "cad_md5_only" / "manifest.json").is_file()


# ---------------------------------------------------------------------------
# security-negative


def test_the_revocation_scenario_actually_revokes(forged):
    """The CRL must carry the revoked EEC's serial, and only it.

    ``crl_revoked_eec`` is the tree behind every "revoked credential is
    refused" conformance case.  If the forge emitted a CRL with an empty
    revocation list the tree would still materialise, the manifest would still
    say ``reject``, and the server would be tested against a credential that
    nothing had revoked — a green run asserting the opposite of its intent.
    """
    sc = forged / "crl_revoked_eec"
    manifest = json.loads((sc / "manifest.json").read_text())
    verdicts = _manifest_verdicts(manifest)
    assert verdicts == {"good": "accept", "revoked": "reject"}, verdicts

    crls = sorted((sc / "ca").glob("*.r0"))
    assert crls, "no CRL written into the CA directory"
    out = _probe(
        "import subprocess;"
        "print(subprocess.run(['openssl','crl','-in',%r,'-noout','-text'],"
        "                     capture_output=True, text=True).stdout)"
        % str(crls[0]))
    serials = [ln.split(":", 1)[1].strip()
               for ln in out.splitlines() if "Serial Number:" in ln]
    assert len(serials) == 1, f"expected exactly one revoked serial, got {serials}"


def test_the_md5_only_scenario_withholds_the_sha1_link(forged):
    """The whole point of ``cad_md5_only`` is the link that is *missing*.

    OpenSSL's ``X509_STORE_load_path`` finds CAs by the new SHA-1 subject hash.
    A CA directory that shipped both links would be found, the chain would
    build, and the scenario's ``reject`` manifest row would be asserting
    something the tree no longer expresses.
    """
    ca_dir = forged / "cad_md5_only" / "ca"
    links = _hash_links(ca_dir)
    assert links, f"no hash links at all in {ca_dir}"

    out = _probe(
        "import subprocess;"
        "r = subprocess.run(['openssl','x509','-in',%r,'-noout','-hash','-subject_hash_old'],"
        "                   capture_output=True, text=True);"
        "print(r.stdout.strip())" % str(next(ca_dir.glob("*.pem"))))
    new_hash, old_hash = out.split()
    problem = _hash_link_problem(links, new_hash, old_hash)
    assert problem is None, problem
