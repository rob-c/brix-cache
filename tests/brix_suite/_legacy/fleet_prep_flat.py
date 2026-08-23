"""ARCHIVE — the pre-TS-4 flat `fleet_prep.py`, frozen.

Unlike the other `_legacy` archives this one is NOT byte-identical to
its successor: TS-4 item 6 lifted `prepare()`'s inline generation
block into `PrepStep` objects so the core `FleetPrep` engine and the
shim path run the same code.  Kept as the record of what that block
said before the lift, and diffed by
`test_ci_ts4_prep_and_declares.py` only for the bodies that did not
move.  Nothing imports it.
"""

from __future__ import annotations

def _guard_run_1(tolerate, proc, argv):
    if proc.returncode != 0 and not tolerate:
        raise RuntimeError(
            f"{' '.join(map(str, argv))} exited {proc.returncode}\n{proc.stderr}"
        )

def _guard_run_2(quiet, proc, argv):
    if proc.returncode != 0 and not quiet:
        _warn(f"{argv[0]} rc={proc.returncode}: {proc.stderr.strip()[:200]}")

def _guard_prepare_3(test_root, tokens_dir, pki_dir, env, jwks_refresh_dir):
    if not _restore_session_artifacts(test_root, Path(pki_dir), tokens_dir):
        # 1) PKI + user proxies.
        regenerate_pki(pki_dir, env)
    
        # 2) jwks-refresh signing authority (separate key from the main tokens key).
        _make_token(str(jwks_refresh_dir), "init", str(jwks_refresh_dir), env=env)
    
        # 3) main tokens signing key (only if absent — reuse across sessions).
        if not (tokens_dir / "signing_key.pem").exists():
            _make_token(str(tokens_dir), "init", str(tokens_dir), env=env)
    
        # 4) multi-key JWKS + scitokens.cfg (tolerant: needs `cryptography`).
        _run([sys.executable, str(TESTS_DIR / "tokenforge.py"), "fleet-artifacts", str(tokens_dir)],
             env=env, tolerate=True, quiet=True)
    
        # 5) issued JWTs: upstream bridge token + chaos identity-shift token.
        _make_token(str(tokens_dir), "gen", str(tokens_dir),
                    "--sub", "nginx-bridge",
                    "--scope", "storage.read:/ storage.modify:/",
                    "--lifetime", "86400",
                    "--output", str(tokens_dir / "upstream.jwt"), env=env)
        _make_token(str(tokens_dir), "gen", str(tokens_dir),
                    "--sub", "chaos-test-user",
                    "--scope", "storage.read:/ storage.modify:/",
                    "--lifetime", "86400",
                    "--output", str(Path(pki_dir) / "wlcg_token.txt"), env=env)
    
        _store_session_artifacts(test_root, Path(pki_dir), tokens_dir)

def _guard_prepare_4(user_crl, crl_dir):
    if user_crl.exists():
        (crl_dir / "ca.r0").write_bytes(user_crl.read_bytes())

def _guard_prepare_5(authdb_file):
    if not authdb_file.exists():
        authdb_file.write_text(
            "# placeholder written by fleet_prep; authdb_setup fixture overwrites\n",
            encoding="utf-8",
        )


"""Session artifact generation for the registry-native fleet.

Pure-Python successor to the top of bash ``start_all_dedicated`` (in
``tests/lib/dedicated.sh``) and ``regenerate_pki`` (``tests/lib/pki.sh``): the
one-time, fleet-wide setup that must complete *before* any instance is launched
— PKI + proxies, token signing keys + issued JWTs, multi-key JWKS artifacts, CRL
drop directories, the authdb placeholder, and the kXR_prepare stage hook.

``prepare()`` is idempotent and tolerant: a missing optional dependency
(``cryptography`` for tokenforge, ``xrdcp`` for TPC) logs and continues rather
than aborting the session, mirroring the bash ``|| true`` guards.  It is called
once from ``conftest`` before ``register_full_fleet`` + ``start_registered``.

The crypto artifacts (PKI blitz + proxies, signing keys, JWKS, issued JWTs)
cost ~11 s to generate yet are byte-identical run to run, and sessionfinish
destroys TEST_ROOT — so repeated sessions paid that cost every time.  They are
now snapshotted OUTSIDE the test root and restored on the next session for the
same TEST_ROOT (absolute paths are baked into scitokens.cfg, so a snapshot is
only valid at the tree it was generated in).  The snapshot self-invalidates on
generator-source change and on age: proxies live 12 h (make_proxy.py) and the
issued JWTs 24 h, so a 4 h TTL keeps every restored credential comfortably
inside its validity window.  Set ``BRIX_FLEET_PREP_CACHE=0`` to force full
regeneration.  Per-session artifacts (CRL drops, authdb, stage hook) are cheap
and always rebuilt, and each session still starts from a wiped tree — the
snapshot is the pristine post-generation state, never a mutated mid-run one.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
UTILS_DIR = REPO_ROOT / "utils"

_CACHE_VERSION = 1
_CACHE_TTL_SECONDS = 4 * 3600
# Any change to these regenerates from scratch (stamps are part of the meta).
_GENERATOR_SOURCES = (
    Path(__file__).resolve(),
    TESTS_DIR / "pki_helpers.py",
    TESTS_DIR / "tokenforge.py",
    UTILS_DIR / "make_proxy.py",
    UTILS_DIR / "make_token.py",
)


def _run(argv, *, cwd=None, env=None, tolerate=False, quiet=False):
    """Run a helper CLI; on failure raise (or warn+continue if ``tolerate``)."""
    try:
        proc = subprocess.run(
            argv, cwd=str(cwd) if cwd else None, env=env,
            capture_output=True, text=True,
        )
    except OSError as exc:
        if tolerate:
            _warn(f"{argv[0]}: {exc}")
            return None
        raise
    _guard_run_1(tolerate, proc, argv)
    _guard_run_2(quiet, proc, argv)
    return proc


def _warn(msg: str) -> None:
    sys.stderr.write(f"[fleet_prep] {msg}\n")


def regenerate_pki(pki_dir: str, env: dict) -> None:
    """Blitz-regenerate the test PKI + user proxies (bash ``regenerate_pki``)."""
    root = Path(pki_dir)
    for sub in ("ca", "server", "user", "voms", "vomsdir"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    # blitz_test_pki keys off PKI_DIR in the environment; set it, import, call.
    prev = os.environ.get("PKI_DIR")
    os.environ["PKI_DIR"] = pki_dir
    try:
        import importlib

        import pki_helpers  # noqa: PLC0415 — imported for its side-effecting generator

        importlib.reload(pki_helpers)
        try:
            pki_helpers.blitz_test_pki()
        except Exception as exc:  # bash: "WARNING: PKI regeneration failed, continuing"
            _warn(f"PKI regeneration failed, continuing: {exc}")
    finally:
        if prev is None:
            os.environ.pop("PKI_DIR", None)
        else:
            os.environ["PKI_DIR"] = prev
    _run([sys.executable, str(UTILS_DIR / "make_proxy.py"), pki_dir],
         env=env, tolerate=True)


def _make_token(token_dir: str, subcmd: str, *args, env: dict) -> None:
    _run([sys.executable, str(UTILS_DIR / "make_token.py"), subcmd, *map(str, args)],
         env=env, tolerate=(subcmd == "gen"))


def _cache_enabled() -> bool:
    return os.environ.get("BRIX_FLEET_PREP_CACHE", "1") != "0"


def _cache_dir(test_root: Path, pki_dir: Path) -> Path:
    """Per-lane snapshot location, outside TEST_ROOT so sessionfinish's rmtree
    never touches it.  Keyed on the resolved tree paths because the artifacts
    embed them (scitokens.cfg → jwks paths).  Lives under the user cache dir,
    NOT /tmp: /tmp on a shared dev box is scrubbed by concurrent lanes'
    ``rm -rf /tmp/brix*`` tidying (observed 2026-08-17) and by reboots."""
    key = hashlib.sha256(f"{test_root}\x00{pki_dir}".encode()).hexdigest()[:16]
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "nginx-xrootd" / "fleet-prep" / key


def _generator_stamps() -> dict:
    return {p.name: [p.stat().st_mtime_ns, p.stat().st_size]
            for p in _GENERATOR_SOURCES}


def _missing_sentinels(pki_dir: Path, tokens_dir: Path) -> list:
    """Artifacts whose absence proves generation (or a restore) went wrong —
    one per tolerated generator, so a warn-and-continue failure upstream can
    never be snapshotted or accepted as a valid restore."""
    expected = (
        pki_dir / "ca" / "ca.pem",            # pki_helpers.blitz_test_pki
        pki_dir / "user" / "proxy_std.pem",   # make_proxy.py
        tokens_dir / "signing_key.pem",       # make_token.py init
        tokens_dir / "upstream.jwt",          # make_token.py gen
    )
    return [p for p in expected if not p.exists()]


def _force_rmtree(path: Path) -> None:
    """rmtree that also clears read-only trees (the PKI keeps 0555 dirs)."""
    if not path.exists():
        return
    try:
        shutil.rmtree(path)
    except OSError:
        for root, dirs, files in os.walk(path):
            for name in dirs:
                _chmod_quiet(os.path.join(root, name), 0o700)
            for name in files:
                _chmod_quiet(os.path.join(root, name), 0o600)
        shutil.rmtree(path, ignore_errors=True)


def _chmod_quiet(path: str, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _restore_session_artifacts(test_root: Path, pki_dir: Path,
                               tokens_dir: Path) -> bool:
    """Copy a fresh snapshot's pki/ + tokens/ into the wiped tree.

    Returns False (caller regenerates) on ANY doubt: cache disabled, missing,
    stale by TTL, generator sources changed, corrupt meta, or a copy error.
    """
    if not _cache_enabled():
        return False
    cache = _cache_dir(test_root, pki_dir)
    try:
        meta = json.loads((cache / "meta.json").read_text(encoding="utf-8"))
        if meta.get("v") != _CACHE_VERSION:
            return False
        if meta.get("stamps") != _generator_stamps():
            return False
        if time.time() - meta.get("created", 0) >= _CACHE_TTL_SECONDS:
            return False
        shutil.copytree(cache / "pki", pki_dir, symlinks=True,
                        dirs_exist_ok=True)
        shutil.copytree(cache / "tokens", tokens_dir, symlinks=True,
                        dirs_exist_ok=True)
    except (OSError, ValueError):
        return False
    if _missing_sentinels(pki_dir, tokens_dir):
        return False
    return True


def _store_session_artifacts(test_root: Path, pki_dir: Path,
                             tokens_dir: Path) -> None:
    """Snapshot the pristine post-generation pki/ + tokens/ trees.

    Built in a pid-unique sibling then renamed into place so a reader never
    sees a half-written snapshot.  Best-effort: a failure warns and the
    session continues on the freshly generated artifacts.
    """
    if not _cache_enabled():
        return
    missing = _missing_sentinels(pki_dir, tokens_dir)
    if missing:
        _warn(f"artifact snapshot skipped, incomplete generation: {missing[0]}")
        return
    cache = _cache_dir(test_root, pki_dir)
    tmp = cache.with_name(f"{cache.name}.tmp{os.getpid()}")
    try:
        _force_rmtree(tmp)
        tmp.mkdir(parents=True)
        shutil.copytree(pki_dir, tmp / "pki", symlinks=True)
        shutil.copytree(tokens_dir, tmp / "tokens", symlinks=True)
        (tmp / "meta.json").write_text(
            json.dumps({"v": _CACHE_VERSION, "created": time.time(),
                        "stamps": _generator_stamps()}),
            encoding="utf-8",
        )
        _force_rmtree(cache)
        os.rename(tmp, cache)
    except OSError as exc:
        _warn(f"artifact snapshot failed, continuing: {exc}")
        _force_rmtree(tmp)


def prepare(env=None) -> dict:
    """Generate every pre-instance session artifact. Returns the env used."""
    env = dict(os.environ if env is None else env)
    test_root = Path(env.get("TEST_ROOT", "/tmp/xrd-test"))
    pki_dir = env.get("PKI_DIR", str(test_root / "pki"))
    log_dir = Path(env.get("LOG_DIR", str(test_root / "logs")))
    tokens_dir = test_root / "tokens"
    jwks_refresh_dir = tokens_dir / "jwks-refresh"
    artifacts_dir = test_root / "artifacts"

    for d in (test_root, log_dir, tokens_dir, jwks_refresh_dir, artifacts_dir):
        d.mkdir(parents=True, exist_ok=True)

    # 1-5) Crypto artifacts: restored from the per-lane snapshot when fresh,
    # regenerated (then re-snapshotted) otherwise — see the module docstring.
    _guard_prepare_3(test_root, tokens_dir, pki_dir, env, jwks_refresh_dir)

    # 6) CRL drop directories: seed crls/ca.r0 from the generated user CRL.
    crl_dir = test_root / "crls"
    crl_reload_dir = test_root / "crl-reload"
    for d in (crl_dir, crl_reload_dir):
        d.mkdir(parents=True, exist_ok=True)
        for stale in d.iterdir():
            stale.unlink()
    user_crl = Path(pki_dir) / "ca" / "test-user.crl.pem"
    _guard_prepare_4(user_crl, crl_dir)

    # 7) authdb placeholder so nginx_authdb.conf can start (fixture overwrites).
    authdb_root = test_root / "data-authdb"
    authdb_root.mkdir(parents=True, exist_ok=True)
    authdb_file = authdb_root / "authdb"
    _guard_prepare_5(authdb_file)

    # 8) kXR_prepare stage hook — a committed self-contained Python script
    # (cmdscripts.prepare_stage_hook) copied in with its log-path sidecar;
    # brix_prepare_command execs it with the staged paths.
    _write_stage_hook(test_root)

    return env


def _write_stage_hook(test_root: Path) -> None:
    """Install the prepare-command staging hook the ``prepare-command`` role execs.

    Logs ``BRIX_PREPARE_COLOC`` (when set) then each staged path to
    ``data-prepare-command/staged.log``. The hook is the committed
    ``cmdscripts/prepare_stage_hook.py`` script; its log path travels in a JSON
    sidecar so the executable stays generic. The on-disk log contract is
    byte-for-byte identical to the retired shell hook.
    """
    from cmdscripts import prepare_stage_hook

    hook_dir = test_root / "dedicated" / "prepare-command"
    hook_dir.mkdir(parents=True, exist_ok=True)
    (test_root / "data-prepare-command").mkdir(parents=True, exist_ok=True)
    log_path = test_root / "data-prepare-command" / "staged.log"
    prepare_stage_hook.install(hook_dir, log=log_path)


if __name__ == "__main__":
    prepare()
    print("fleet_prep: session artifacts generated")
