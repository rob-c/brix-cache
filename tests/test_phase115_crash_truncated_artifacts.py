"""A crash-truncated artifact must never be mistaken for a generated one.

WHAT   Pins the two halves of a defect that silently disabled token auth for a
       whole suite run: the prep pipeline reused a signing key it only checked
       the EXISTENCE of, and the generator that wrote that key did not make it
       durable.

WHY    Observed 2026-09-07.  The VM took a fatal machine-check panic at 13:10
       while a full-tier fleet was running.  `/tmp` survives a WSL2 reboot, so
       the next session inherited its predecessor's TEST_ROOT, in which
       `tokens/signing_key.pem`, `signing_key_2.pem` and `signing_key_ec.pem`
       were all ZERO bytes at mode 0400 — ext4 had persisted the rename from
       `init_keys`' temp-file dance but not the data behind it.  `SigningKeyStep`
       asks `.exists()`, saw three names, and skipped regeneration; every
       `make_token.py gen` for the rest of the run then died with

           ValueError: Unable to load PEM file ... MalformedFraming

       so the fleet came up with no issuable tokens and the entire WLCG/scitoken
       surface failed for reasons that had nothing to do with the code under
       test.  `_missing_sentinels` — the guard whose whole purpose is to stop a
       bad tree being snapshotted or accepted as a restore — asked `.exists()`
       too, so the poisoned tree was eligible to be cached for FUTURE sessions.

HOW    Two fixes, pinned here.  `_is_usable()` replaces every existence check on
       a generated artifact: non-empty, and for PEM also carrying its END
       armour, since truncation is not always to zero.  `init_keys()` fsyncs the
       key body before the rename and the directory after it, so the file that
       survives a panic is the one that was written.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "utils"))

from brix_suite import prep_steps  # noqa: E402
from brix_suite.prep_steps import (  # noqa: E402
    PrepPaths, SigningKeyStep, _is_loadable_pem, _is_usable,
    _missing_sentinels)

GOOD_PEM = b"-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n"


def _paths(tmp_path: Path) -> PrepPaths:
    paths = PrepPaths.resolve({"TEST_ROOT": str(tmp_path)})
    paths.mkdirs()
    return paths


def _regenerations(monkeypatch) -> list:
    """Record what `SigningKeyStep` asks the generator to do.

    The step reads `_make_token` out of the module globals inside `build()`
    precisely so a test can rebind it (see the `PrepStep` docstring), which is
    what keeps this from shelling out to the real 2048-bit keygen.
    """
    calls = []
    monkeypatch.setattr(prep_steps, "_make_token",
                        lambda *a, **kw: calls.append(a))
    return calls


# --- the reuse gate ----------------------------------------------------------

def test_a_good_signing_key_is_reused_across_sessions(tmp_path, monkeypatch):
    """The success path the fix must not cost us.

    Regenerating an RSA-2048 key is ~11 s of the session's startup budget, and
    the step exists to skip it.  A fix that regenerated unconditionally would
    "pass" every negative below while quietly taxing every run.
    """
    paths = _paths(tmp_path)
    (paths.tokens_dir / "signing_key.pem").write_bytes(GOOD_PEM)
    calls = _regenerations(monkeypatch)

    SigningKeyStep(paths).build()

    assert calls == [], "a usable key was regenerated anyway"


def test_a_zero_length_signing_key_is_regenerated(tmp_path, monkeypatch):
    """The defect itself, in the exact shape the panic left behind."""
    paths = _paths(tmp_path)
    key = paths.tokens_dir / "signing_key.pem"
    key.write_bytes(b"")
    os.chmod(key, 0o400)
    calls = _regenerations(monkeypatch)

    SigningKeyStep(paths).build()

    assert len(calls) == 1, (
        "a zero-length key was reused; every make_token.py gen in the session "
        "will fail with MalformedFraming")


def test_a_truncated_key_is_regenerated(tmp_path, monkeypatch):
    """Truncation is not always to zero.

    A PEM body that lost only its tail is still unloadable, and a size>0 test
    alone would wave it through — so the armour, not the length, is the test.
    """
    paths = _paths(tmp_path)
    (paths.tokens_dir / "signing_key.pem").write_bytes(
        b"-----BEGIN PRIVATE KEY-----\nQUJDREVG\n")
    calls = _regenerations(monkeypatch)

    SigningKeyStep(paths).build()

    assert len(calls) == 1, "a PEM with no END armour was reused"


def test_a_missing_key_is_still_regenerated(tmp_path, monkeypatch):
    """The original behaviour, unchanged: absence has always meant generate."""
    paths = _paths(tmp_path)
    calls = _regenerations(monkeypatch)

    SigningKeyStep(paths).build()

    assert len(calls) == 1, "an absent key was not generated"


# --- the snapshot / restore guard -------------------------------------------

def _sentinels(tmp_path: Path) -> tuple:
    pki, tokens = tmp_path / "pki", tmp_path / "tokens"
    (pki / "ca").mkdir(parents=True)
    (pki / "user").mkdir(parents=True)
    tokens.mkdir(parents=True)
    (pki / "ca" / "ca.pem").write_bytes(GOOD_PEM)
    (pki / "user" / "proxy_std.pem").write_bytes(GOOD_PEM)
    (tokens / "signing_key.pem").write_bytes(GOOD_PEM)
    (tokens / "upstream.jwt").write_bytes(b"a.b.c")
    (tokens / "scitokens.cfg").write_bytes(b"[Global]\n")
    return pki, tokens


def test_a_complete_tree_reports_nothing_missing(tmp_path):
    """Success path: the guard stays quiet on a tree that really is complete."""
    pki, tokens = _sentinels(tmp_path)
    assert _missing_sentinels(pki, tokens) == []


@pytest.mark.parametrize("victim", [
    "pki/ca/ca.pem", "pki/user/proxy_std.pem",
    "tokens/signing_key.pem", "tokens/upstream.jwt", "tokens/scitokens.cfg",
])
def test_a_zero_length_sentinel_counts_as_missing(tmp_path, victim):
    """Every sentinel, not just the key: the panic truncates whatever is open.

    Parametrised because the guard's value is being exhaustive — one artifact
    left on `.exists()` is a hole the next crash finds.
    """
    pki, tokens = _sentinels(tmp_path)
    (tmp_path / victim).write_bytes(b"")

    missing = _missing_sentinels(pki, tokens)

    assert [p.name for p in missing] == [Path(victim).name], (
        f"a zero-length {victim} was accepted as generated")


def test_an_unusable_artifact_can_never_be_snapshotted(tmp_path):
    """SECURITY-NEGATIVE: a poisoned tree must not propagate to later sessions.

    `_missing_sentinels` is what stands between a crash-damaged TEST_ROOT and
    the artifact cache.  If it answers "nothing missing" the damaged tree is
    snapshotted OUTSIDE the test root and restored into every subsequent
    session, turning a one-off panic into a permanent, silent loss of token
    auth that survives deleting TEST_ROOT — the obvious remedy.
    """
    pki, tokens = _sentinels(tmp_path)
    key = tokens / "signing_key.pem"
    key.write_bytes(b"")
    os.chmod(key, 0o400)

    assert _missing_sentinels(pki, tokens), (
        "a crash-damaged tree was eligible for the artifact snapshot")


# --- the predicate itself ----------------------------------------------------

def test_an_absent_path_is_not_usable(tmp_path):
    assert not _is_usable(tmp_path / "nope.pem")


def test_a_directory_is_not_usable(tmp_path):
    """SECURITY-NEGATIVE: a name of the right shape is not an artifact.

    A directory stats non-empty on most filesystems, so a size-only predicate
    would report a directory standing where a key belongs as a usable key and
    skip generation for the whole session.
    """
    victim = tmp_path / "signing_key.pem"
    victim.mkdir()
    assert not _is_usable(victim)


def test_an_unreadable_pem_is_not_usable(tmp_path):
    """SECURITY-NEGATIVE: fail closed, never on an exception.

    A key the session cannot read is a key the session cannot sign with.  The
    predicate must answer False rather than raise, or one EACCES aborts prep
    before the pipeline reaches the step that would have fixed it.
    """
    victim = tmp_path / "signing_key.pem"
    victim.write_bytes(GOOD_PEM)
    os.chmod(victim, 0o000)
    try:
        assert not _is_loadable_pem(victim)
    finally:
        os.chmod(victim, 0o600)


def test_a_non_pem_artifact_is_judged_on_length_alone(tmp_path):
    """JWTs and cfg files have no armour; length is all we can ask of them.

    And the sentinel predicate stays a length test even for PEM, so the fake
    artifacts other suites write ("cert", "proxy") keep meaning what they mean;
    only the signing-key gate parses.
    """
    victim = tmp_path / "upstream.jwt"
    victim.write_bytes(b"a.b.c")
    assert _is_usable(victim)
    assert _is_usable(tmp_path / "stand-in.pem") is False
    (tmp_path / "stand-in.pem").write_text("cert")
    assert _is_usable(tmp_path / "stand-in.pem"), (
        "the sentinel predicate started parsing PEM; every suite that fakes an "
        "artifact with a short string now fails")
    assert not _is_loadable_pem(tmp_path / "stand-in.pem"), (
        "the signing-key gate stopped requiring loadable PEM")


# --- durability of the write ------------------------------------------------

def test_the_key_write_is_durable_against_a_crash(tmp_path, monkeypatch):
    """The other half: what the panic was able to destroy in the first place.

    `init_keys` writes to a temp file, chmods, and `os.replace()`s — atomic,
    but atomicity is not durability.  Without an fsync of the body before the
    rename and of the directory after it, a machine that dies seconds later
    comes back with the final name, the 0400 mode, and no contents.  That is
    not a hypothetical failure mode; it is the one this whole module is about.
    """
    cryptography = pytest.importorskip("cryptography")  # noqa: F841
    from make_token import TokenIssuer  # noqa: PLC0415

    synced = []
    real_fsync = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(fd),
                                                 real_fsync(fd))[1])

    issuer = TokenIssuer(str(tmp_path))
    issuer.init_keys()

    assert len(synced) >= 2, (
        "init_keys() synced neither the key body nor its directory; a panic "
        "after the rename leaves a zero-length key behind")
    assert _is_usable(Path(issuer.key_path))


def test_a_regenerated_key_keeps_its_restrictive_mode(tmp_path):
    """SECURITY-NEGATIVE: durability must not be bought with permissions.

    The fsync happens while the temp file is still open, i.e. BEFORE the chmod
    to 0400.  An implementation that reordered those — syncing after the chmod
    by reopening, or dropping the chmod to keep the handle writable — would
    leave a world-readable RSA private key behind.
    """
    pytest.importorskip("cryptography")
    from make_token import TokenIssuer  # noqa: PLC0415

    issuer = TokenIssuer(str(tmp_path))
    issuer.init_keys()

    mode = os.stat(issuer.key_path).st_mode & 0o777
    assert mode == 0o400, f"signing key ended up at mode {mode:o}, not 0400"


def test_no_temporary_key_material_is_left_behind(tmp_path):
    """SECURITY-NEGATIVE: the pre-chmod temp file is world-default-readable.

    It exists for the width of the write, at whatever the umask allows.  If a
    failure path ever leaves one, the private key sits in the tokens directory
    readable by anyone who can list it.
    """
    pytest.importorskip("cryptography")
    from make_token import TokenIssuer  # noqa: PLC0415

    TokenIssuer(str(tmp_path)).init_keys()

    leftovers = [p.name for p in tmp_path.iterdir() if ".tmp." in p.name]
    assert leftovers == [], f"temporary key material left behind: {leftovers}"


# --- non-vacuity -------------------------------------------------------------

def test_the_reuse_gate_no_longer_asks_only_for_existence():
    """Pin the wiring, not just the behaviour.

    Every negative above passes if `SigningKeyStep` regenerates unconditionally
    for some unrelated reason, so assert the gate is the predicate — a revert to
    `.exists()` here is the exact defect and must fail loudly.
    """
    body = (Path(prep_steps.__file__)).read_text(encoding="utf-8")
    gate = body[body.index("class SigningKeyStep"):]
    gate = gate[:gate.index("class ", 10)]

    assert '_is_loadable_pem(self.paths.tokens_dir / "signing_key.pem")' in gate, (
        "the signing-key reuse gate no longer runs the usability predicate")
    assert '.exists()' not in gate, (
        "the reuse gate is back on an existence check; a zero-length key "
        "survives it")
    assert "if not _is_usable(p)" in body, (
        "_missing_sentinels no longer runs the usability predicate, so a "
        "crash-damaged tree can be snapshotted as a valid restore")


def test_the_key_generator_still_runs_standalone(tmp_path):
    """The generator is a CLI first; the fsync must not have broken that."""
    pytest.importorskip("cryptography")
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "utils" / "make_token.py"),
         "init", str(tmp_path / "tok")],
        capture_output=True, text=True)

    assert proc.returncode == 0, proc.stderr
    assert _is_usable(tmp_path / "tok" / "signing_key.pem")
