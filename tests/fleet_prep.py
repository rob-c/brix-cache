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
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
UTILS_DIR = REPO_ROOT / "utils"


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


def prepare(env=None) -> dict:
    """Generate every pre-instance session artifact. Returns the env used."""
    env = dict(os.environ if env is None else env)
    test_root = Path(env.get("TEST_ROOT", "/tmp/xrd-test"))
    pki_dir = env.get("PKI_DIR", str(test_root / "pki"))
    log_dir = Path(env.get("LOG_DIR", str(test_root / "logs")))
    tokens_dir = test_root / "tokens"
    jwks_refresh_dir = tokens_dir / "jwks-refresh"

    for d in (test_root, log_dir, tokens_dir, jwks_refresh_dir):
        d.mkdir(parents=True, exist_ok=True)

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

    # 6) CRL drop directories: seed crls/ca.r0 from the generated user CRL.
    crl_dir = test_root / "crls"
    crl_reload_dir = test_root / "crl-reload"
    for d in (crl_dir, crl_reload_dir):
        d.mkdir(parents=True, exist_ok=True)
        for stale in d.iterdir():
            stale.unlink()
    user_crl = Path(pki_dir) / "ca" / "test-user.crl.pem"
    if user_crl.exists():
        (crl_dir / "ca.r0").write_bytes(user_crl.read_bytes())

    # 7) authdb placeholder so nginx_authdb.conf can start (fixture overwrites).
    authdb_root = test_root / "data-authdb"
    authdb_root.mkdir(parents=True, exist_ok=True)
    authdb_file = authdb_root / "authdb"
    if not authdb_file.exists():
        authdb_file.write_text(
            "# placeholder written by fleet_prep; authdb_setup fixture overwrites\n",
            encoding="utf-8",
        )

    # 8) kXR_prepare stage hook (bash generated a shell heredoc; keep it minimal
    # and executable — brix_prepare_command execs it with the staged paths).
    _write_stage_hook(test_root)

    return env


def _write_stage_hook(test_root: Path) -> None:
    """Write the prepare-command staging hook the ``prepare-command`` role execs.

    Logs ``BRIX_PREPARE_COLOC`` (when set) then each staged path to
    ``data-prepare-command/staged.log`` — a faithful port of the bash heredoc,
    still a ``/bin/sh`` script (nginx execs it directly, no interpreter choice
    matters) so the on-disk contract the test reads is byte-for-byte identical.
    """
    hook_dir = test_root / "dedicated" / "prepare-command"
    hook_dir.mkdir(parents=True, exist_ok=True)
    log_path = test_root / "data-prepare-command" / "staged.log"
    (test_root / "data-prepare-command").mkdir(parents=True, exist_ok=True)
    hook = hook_dir / "stage_hook.sh"
    hook.write_text(
        "#!/bin/sh\n"
        "# Log BRIX_PREPARE_COLOC env var if set (for test verification).\n"
        'if [ -n "$BRIX_PREPARE_COLOC" ]; then\n'
        f"    printf 'COLOC=%s\\n' \"$BRIX_PREPARE_COLOC\" >> {log_path}\n"
        "fi\n"
        f"printf '%s\\n' \"$@\" >> {log_path}\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)


if __name__ == "__main__":
    prepare()
    print("fleet_prep: session artifacts generated")
