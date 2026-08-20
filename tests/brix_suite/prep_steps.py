"""Session artifact generation for the registry-native fleet — the steps.

TS-4 item 6 (§9.2.4).  The eight pipeline stages are `PrepStep` objects
(`CRYPTO_STEPS` + `SESSION_STEPS`) structurally matching
`brixtest.fleet.prep.PrepStep`, so the core `FleetPrep` engine can drive
exactly the code `prepare()` drives — there is one implementation of the
pipeline, not one per caller.

`prepare()` keeps the snapshot cache it grew (below) rather than delegating
to the core engine's lane-rooted `snapshot_dir`.  The two disagree on where
a snapshot lives and what stamps it, and `test_fleet_prep_cache.py` pins the
grown layout by reading `meta.json` and `_CACHE_TTL_SECONDS` directly.  The
plan schedules that conversion for TS-7, when editing the pinning suite is
allowed.

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

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# The flat `tests/` tree, NOT this package's directory.  `UTILS_DIR` and
# `_GENERATOR_SOURCES` below name real scripts under it, and the obvious
# `Path(__file__).resolve().parent` would have started resolving into
# `tests/brix_suite` after the move — making `UTILS_DIR` `tests/utils`, which
# does not exist.  Fifth instance of the move-hazard class the item 1 note
# names; this one is live rather than latent.
from brix_suite.settings import TESTS_DIR as _TESTS_DIR

#: `settings.TESTS_DIR` is a str; the flat module's was a Path and every use
#: below is a `/` join, so it is re-wrapped rather than rewritten at each site.
TESTS_DIR = Path(_TESTS_DIR)
REPO_ROOT = TESTS_DIR.parent
UTILS_DIR = REPO_ROOT / "utils"

_CACHE_VERSION = 1
_CACHE_TTL_SECONDS = 4 * 3600


def _sources(path: Path) -> tuple:
    """Every source file behind one generator, package or module.

    A generator that has been through a §10.2 move is a *package*: the flat
    spelling left behind is a shim that carries no logic, so stamping it
    reports "unchanged" for every edit to the code that actually mints the
    artifacts.  That is worse than stamping nothing — the cache would happily
    restore a tree built by the previous generator, with every sentinel file
    present and every mtime plausible.  Expand a package to its modules so an
    edit anywhere inside it still busts the cache.
    """
    if path.is_dir():
        return tuple(sorted(q for q in path.glob("*.py") if q.name != "__init__.py"))
    return (path,)


_SECURITY = TESTS_DIR / "brix_suite" / "security"

# Any change to these regenerates from scratch (stamps are part of the meta).
_GENERATOR_SOURCES = (
    # This module's own source.  Post-move that resolves to
    # `brix_suite/prep_steps.py` rather than the flat `fleet_prep.py`, which is
    # correct: the shim carries no logic, so an edit to it cannot change what
    # gets generated.
    Path(__file__).resolve(),
    *_sources(_SECURITY / "pki.py"),
    *_sources(_SECURITY / "tokens"),
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
    if proc.returncode != 0 and not tolerate:
        raise RuntimeError(
            f"{' '.join(map(str, argv))} exited {proc.returncode}\n{proc.stderr}"
        )
    if proc.returncode != 0 and not quiet:
        _warn(f"{argv[0]} rc={proc.returncode}: {proc.stderr.strip()[:200]}")
    return proc


def _warn(msg: str) -> None:
    sys.stderr.write(f"[fleet_prep] {msg}\n")


def regenerate_pki(pki_dir: str, env: dict) -> None:
    """Blitz-regenerate the test PKI + user proxies (bash ``regenerate_pki``)."""
    root = Path(pki_dir)
    for sub in ("ca", "server", "user", "voms", "vomsdir"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    # `PKI_DIR` in the environment is published for the child processes this
    # step spawns (make_proxy.py, make_crl.py).  It does NOT steer
    # `blitz_test_pki`, whatever the shape of this block suggests: that reads
    # `settings.PKI_DIR`, which is `TEST_ROOT/pki` computed at settings-import
    # time and never re-read from the environment.  The two agree for every
    # real caller — `paths.pki_dir` is the same join — so the reload below is
    # about picking up an edited generator, not about the path.  Say so when
    # they diverge rather than letting the blitz rmtree a tree nobody asked
    # about; `_missing_sentinels` would report the empty result, but not why.
    prev = os.environ.get("PKI_DIR")
    os.environ["PKI_DIR"] = pki_dir
    try:
        import importlib

        import pki_helpers  # noqa: PLC0415 — imported for its side-effecting generator

        importlib.reload(pki_helpers)
        if str(Path(pki_helpers.PKI_DIR)) != str(root):
            _warn(f"PKI target mismatch: asked for {root}, "
                  f"blitz_test_pki writes {pki_helpers.PKI_DIR}")
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
    #: Keyed on `parent/name`, not `name`: the sources are no longer all
    #: siblings, and two packages may each hold a `mint.py`.  A collision here
    #: would silently drop one generator out of the stamp set.
    return {f"{p.parent.name}/{p.name}": [p.stat().st_mtime_ns, p.stat().st_size]
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
        tokens_dir / "scitokens.cfg",         # tokenforge.py fleet-artifacts
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


@dataclass(frozen=True)
class PrepPaths:
    """Where one lane's artifacts go, resolved from the session env.

    Resolved once and handed to the steps rather than re-derived inside each
    of them: `PKI_DIR` may point outside `TEST_ROOT`, and a step that
    recomputed the default would quietly write to the wrong tree.
    """

    env: dict
    test_root: Path
    pki_dir: Path
    log_dir: Path
    tokens_dir: Path
    jwks_refresh_dir: Path
    artifacts_dir: Path

    @classmethod
    def resolve(cls, env: dict) -> "PrepPaths":
        test_root = Path(env.get("TEST_ROOT", "/tmp/xrd-test"))
        tokens_dir = test_root / "tokens"
        return cls(
            env=env,
            test_root=test_root,
            pki_dir=Path(env.get("PKI_DIR", str(test_root / "pki"))),
            log_dir=Path(env.get("LOG_DIR", str(test_root / "logs"))),
            tokens_dir=tokens_dir,
            jwks_refresh_dir=tokens_dir / "jwks-refresh",
            artifacts_dir=test_root / "artifacts",
        )

    def mkdirs(self) -> None:
        for d in (self.test_root, self.log_dir, self.tokens_dir,
                  self.jwks_refresh_dir, self.artifacts_dir):
            d.mkdir(parents=True, exist_ok=True)


class PrepStep:
    """One stage of the pipeline.

    Structurally a `brixtest.fleet.prep.PrepStep`: `name`, `stamp()`,
    `build()`.  The core protocol passes an `ArtifactSet` to `build`; these
    steps ignore it and write to the paths in `PrepPaths`, because
    `scitokens.cfg` bakes absolute paths and the tree location is therefore
    fixed by the lane's env rather than chosen by the engine.  The parameter
    is kept so the same objects satisfy both callers.

    Every step reads its generators (`regenerate_pki`, `_make_token`, `_run`)
    out of this module's globals inside `build()`, never captured at
    construction: `test_fleet_prep_cache.py` rebinds all three, and a step
    that had closed over the originals would silently run the real openssl.
    """

    name = ""

    def __init__(self, paths: PrepPaths) -> None:
        self.paths = paths

    def stamp(self) -> str:
        """Changes whenever any generator source changes.

        One shared stamp for every step rather than per-step inputs: that is
        what the grown cache does (`_generator_stamps` over
        `_GENERATOR_SOURCES`), and splitting it would let an edit to one
        generator leave another step's stale output restored.
        """
        return json.dumps(_generator_stamps(), sort_keys=True)

    def build(self, artifacts=None) -> None:
        raise NotImplementedError


class PkiStep(PrepStep):
    """1) PKI + user proxies."""

    name = "pki"

    def build(self, artifacts=None) -> None:
        regenerate_pki(str(self.paths.pki_dir), self.paths.env)


class JwksRefreshKeyStep(PrepStep):
    """2) jwks-refresh signing authority (separate key from the main tokens key)."""

    name = "jwks-refresh-key"

    def build(self, artifacts=None) -> None:
        _make_token(str(self.paths.jwks_refresh_dir), "init",
                    str(self.paths.jwks_refresh_dir), env=self.paths.env)


class SigningKeyStep(PrepStep):
    """3) main tokens signing key (only if absent — reuse across sessions)."""

    name = "signing-key"

    def build(self, artifacts=None) -> None:
        if (self.paths.tokens_dir / "signing_key.pem").exists():
            return
        _make_token(str(self.paths.tokens_dir), "init",
                    str(self.paths.tokens_dir), env=self.paths.env)


class FleetArtifactsStep(PrepStep):
    """4) multi-key JWKS + scitokens.cfg (tolerant: needs ``cryptography``)."""

    name = "fleet-artifacts"

    def build(self, artifacts=None) -> None:
        _run([sys.executable, str(TESTS_DIR / "tokenforge.py"),
              "fleet-artifacts", str(self.paths.tokens_dir)],
             env=self.paths.env, tolerate=True, quiet=True)


class IssuedTokensStep(PrepStep):
    """5) issued JWTs: upstream bridge token + chaos identity-shift token."""

    name = "issued-tokens"

    def build(self, artifacts=None) -> None:
        tokens_dir = self.paths.tokens_dir
        _make_token(str(tokens_dir), "gen", str(tokens_dir),
                    "--sub", "nginx-bridge",
                    "--scope", "storage.read:/ storage.modify:/",
                    "--lifetime", "86400",
                    "--output", str(tokens_dir / "upstream.jwt"),
                    env=self.paths.env)
        _make_token(str(tokens_dir), "gen", str(tokens_dir),
                    "--sub", "chaos-test-user",
                    "--scope", "storage.read:/ storage.modify:/",
                    "--lifetime", "86400",
                    "--output", str(self.paths.pki_dir / "wlcg_token.txt"),
                    env=self.paths.env)


class CrlDropStep(PrepStep):
    """6) CRL drop directories: seed crls/ca.r0 from the generated user CRL."""

    name = "crl-drops"

    def build(self, artifacts=None) -> None:
        test_root = self.paths.test_root
        for d in (test_root / "crls", test_root / "crl-reload"):
            d.mkdir(parents=True, exist_ok=True)
            for stale in d.iterdir():
                stale.unlink()
        user_crl = self.paths.pki_dir / "ca" / "test-user.crl.pem"
        if user_crl.exists():
            (test_root / "crls" / "ca.r0").write_bytes(user_crl.read_bytes())


class AuthdbPlaceholderStep(PrepStep):
    """7) authdb placeholder so nginx_authdb.conf can start (fixture overwrites)."""

    name = "authdb-placeholder"

    def build(self, artifacts=None) -> None:
        authdb_root = self.paths.test_root / "data-authdb"
        authdb_root.mkdir(parents=True, exist_ok=True)
        authdb_file = authdb_root / "authdb"
        if authdb_file.exists():
            return
        authdb_file.write_text(
            "# placeholder written by fleet_prep; authdb_setup fixture overwrites\n",
            encoding="utf-8",
        )


class StageHookStep(PrepStep):
    """8) kXR_prepare stage hook."""

    name = "stage-hook"

    def build(self, artifacts=None) -> None:
        _write_stage_hook(self.paths.test_root)


#: Snapshotted as a set: expensive, byte-identical run to run, and restored
#: together or not at all.
CRYPTO_STEPS = (PkiStep, JwksRefreshKeyStep, SigningKeyStep,
                FleetArtifactsStep, IssuedTokensStep)

#: Never snapshotted: cheap, and each one is per-session state a restore
#: would carry over from a run whose tree no longer exists.
SESSION_STEPS = (CrlDropStep, AuthdbPlaceholderStep, StageHookStep)


def crypto_steps(paths: PrepPaths) -> tuple:
    return tuple(step(paths) for step in CRYPTO_STEPS)


def session_steps(paths: PrepPaths) -> tuple:
    return tuple(step(paths) for step in SESSION_STEPS)


def prepare(env=None) -> dict:
    """Generate every pre-instance session artifact. Returns the env used."""
    env = dict(os.environ if env is None else env)
    paths = PrepPaths.resolve(env)
    paths.mkdirs()

    # 1-5) Crypto artifacts: restored from the per-lane snapshot when fresh,
    # regenerated (then re-snapshotted) otherwise — see the module docstring.
    if not _restore_session_artifacts(paths.test_root, paths.pki_dir,
                                      paths.tokens_dir):
        for step in crypto_steps(paths):
            step.build()
        _store_session_artifacts(paths.test_root, paths.pki_dir,
                                 paths.tokens_dir)

    # 6-8) Per-session artifacts: cheap, always rebuilt, never snapshotted.
    for step in session_steps(paths):
        step.build()

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


def main(argv=None) -> int:
    """Generate the session artifacts and say so, for the two script spellings.

    Named rather than left inline in the ``__main__`` guard below: guards are a
    property of how the interpreter was started, not a name, so they do not
    reach the flat ``tests/fleet_prep.py`` spelling that imports this module.
    Leaving it inline made ``python3 tests/fleet_prep.py`` a script that exited
    0 having generated nothing — found by ``tools/ci/check_shim_entrypoints.py``
    (guard #11), which now pins both spellings.
    """
    prepare()
    print("fleet_prep: session artifacts generated")  # operators grep this exact line
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
