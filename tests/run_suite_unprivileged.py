#!/usr/bin/env python3
"""run_suite_unprivileged.py — run the suite with TEST USER == SERVER USER.

WHY THIS EXISTS
    The fleet's nginx configs carry no ``user`` directive.  Run the harness as
    root and every master drops its workers to ``nobody``, while the harness
    creates the export roots as root — so a worker cannot write its own export
    (403 on every PUT/upload), and cannot chmod a file the test process created.
    That second one is NOT fixable with permission bits: chmod(2) requires
    OWNERSHIP, so the xrdcl chmod/stat parity suites fail however open the mode is.

    The historical workaround is brix-test-nginx injecting ``user root;``
    (TESTING.md §4b) so workers stay root.  That trades one distortion for
    another: root bypasses every permission check, so the suite stops testing the
    authorization semantics it exists to verify — and it cannot be applied to the
    reference xrootd, which REFUSES to run as the superuser ("Security reasons
    prohibit running as superuser").  Our side becomes root, stock stays
    ``nobody``, and the two diverge *by construction* in exactly the parity tests.

    Running everything as ONE unprivileged user deletes the whole class: pytest,
    the nginx master+workers and the reference xrootd all share an identity, so
    ownership and permission behaviour is REAL rather than root-bypassed.  This is
    the configuration upstream validated (the phase-79 burndown's 6977-pass run).

WHY A COPY OF THE CHECKOUT (root mode)
    The canonical checkout may live somewhere the test user cannot reach — on this
    box /root, mode 0750, which is exactly why TESTING.md §6c concluded "running
    the whole fleet as root [is] necessary here".  Rather than open a path into
    root's home (an ACL/``o+x`` on /root would grant traversal to a real account —
    and ``nobody`` in particular is shared by other daemons, so that would widen
    far beyond this suite), we SYNC the tree to a neutral location the user owns.
    /root keeps its 0750 untouched.  The trade-off is honest: you are validating a
    copy, so the sync happens on every run and --delete keeps it exact.

TWO MODES, AUTO-DETECTED
    unprivileged   You are already a normal user -> run in place, no copy, no
                   sudo, nothing to grant.  This is the "single user" mode: a
                   developer who CANNOT sudo runs exactly what root runs.
    root           Sync the checkout to $BRIX_TEST_TREE, hand it plus the test
                   root to $BRIX_TEST_USER, and re-exec there as that user.  Root
                   only does what a normal user cannot do for itself: clear a
                   root-owned fleet off the fixed ports and chown the trees.

The suite itself is the Python runner ``cmdscripts.operator_runtime suite`` (the
former ``run_suite.sh``, ported in phase-81); all arguments pass through to it
verbatim.

USAGE
    tests/run_suite_unprivileged.py --fast
    BRIX_TEST_USER=nobody tests/run_suite_unprivileged.py --fast
    BRIX_TEST_TREE=/srv/brix-test tests/run_suite_unprivileged.py --fast
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# A dedicated account, not `nobody`: nothing else on the box runs as it, so the
# trees we hand it are not implicitly shared with unrelated daemons.  `nobody`
# still works (BRIX_TEST_USER=nobody) — with the neutral copy there is no /root
# exposure either way — but it has no writable home and is shared, so it is not
# the default.
BRIX_TEST_USER = os.environ.get("BRIX_TEST_USER", "brixtest")
BRIX_TEST_TREE = os.environ.get("BRIX_TEST_TREE", "/srv/brix-test")

# Per-user test root, deliberately NOT the root harness's /tmp/xrd-test: the two
# must never share file ownership, so a root run and a user run cannot corrupt
# each other's PKI/exports.  (They still share the fixed ports — see
# _clear_foreign_fleet.)
TEST_ROOT_DEFAULT = f"/tmp/xrd-test-{BRIX_TEST_USER}"


def log(msg: str) -> None:
    print(f"[unpriv] {msg}", flush=True)


def die(msg: str) -> None:
    print(f"[unpriv] ERROR: {msg}", file=sys.stderr, flush=True)
    raise SystemExit(1)


# --------------------------------------------------------------------------- #
# nginx selection                                                             #
# --------------------------------------------------------------------------- #
# Respect an explicit choice; otherwise prefer the wrapper that drives the SYSTEM
# nginx.  Note the wrapper only injects `user root;` when it IS root — run
# unprivileged it is a plain module-loading shim, so workers stay this user,
# which is the entire point of this script.
def _pick_nginx() -> str:
    if os.environ.get("NGINX_BIN"):
        return os.environ["NGINX_BIN"]
    if os.environ.get("TEST_NGINX_BIN"):
        return os.environ["TEST_NGINX_BIN"]
    if os.access("/usr/local/bin/brix-test-nginx", os.X_OK):
        return "/usr/local/bin/brix-test-nginx"
    return "/tmp/nginx-1.28.3/objs/nginx"


# --------------------------------------------------------------------------- #
# Fixed-port hand-off                                                          #
# --------------------------------------------------------------------------- #
# The fleet binds a fixed port list, so a root-owned fleet and a user-owned fleet
# cannot coexist.  Worse, the user's start-all CANNOT reap a root-owned nginx
# (force_stop_nginx would have to kill another uid's process), so a leftover root
# fleet becomes an unfixable "Address already in use".  Clear it here, while we
# still have the privileges to do it.
def _clear_foreign_fleet() -> None:
    log("clearing any root-owned fleet off the fixed ports")
    subprocess.run(
        [sys.executable, "-m", "cmdscripts.manage_test_servers", "stop-all"],
        cwd=str(REPO / "tests"),
        env={**os.environ, "TEST_ROOT": "/tmp/xrd-test"},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    # stop-all only knows the servers it launched via its own pidfiles.  Test
    # fixtures and the registry harness also spawn nginx/brix/xrootd directly on
    # fixed ports; an interrupted run leaks them and they hold the ports, which
    # makes the next start fail to bind.  Reap any candidate whose OWN cmdline
    # references a test path (never a broad `pkill -f`, which would also match
    # this process).  Two passes: TERM, settle, then KILL.
    for sig in ("-TERM", "-KILL"):
        _reap_test_servers(sig)


def _reap_test_servers(sig: str) -> None:
    markers = ("/tmp/xrd", "/tmp/hsproto", "/tmp/xrd-test")
    for name in ("nginx", "xrootd", "krb5kdc", "kadmind"):
        try:
            out = subprocess.run(
                ["pgrep", "-x", name], capture_output=True, text=True, check=False
            ).stdout
        except FileNotFoundError:
            return
        for pid in out.split():
            try:
                cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(
                    errors="replace"
                )
            except OSError:
                continue
            if any(m in cmdline for m in markers):
                subprocess.run(["kill", sig, pid], check=False,
                               stderr=subprocess.DEVNULL)


def _suite_argv(extra: list[str]) -> list[str]:
    """The canonical Python full-suite runner (former run_suite.sh), plus args."""
    return [sys.executable, "-m", "cmdscripts.operator_runtime", "suite", *extra]


def _run_in_place(nginx: str, extra: list[str]) -> "int":
    # ---- single-user mode: already unprivileged, run in place --------------- #
    # No copy: this checkout is one we can already read, which is the normal case
    # for a developer running out of their own home.
    test_root = os.environ.get("TEST_ROOT", TEST_ROOT_DEFAULT)
    try:
        os.makedirs(test_root, exist_ok=True)
    except OSError:
        die(f"cannot create TEST_ROOT={test_root}")
    if not os.access(test_root, os.W_OK):
        die(f"TEST_ROOT={test_root} is not writable by {_whoami()}")
    if not os.access(nginx, os.X_OK):
        die(f"nginx not executable by {_whoami()}: {nginx}")

    env = dict(os.environ)
    env["TEST_ROOT"] = test_root
    env["NGINX_BIN"] = nginx
    env["TEST_NGINX_BIN"] = nginx
    # The tree may be read-only to us: keep pytest's cache (--lf needs it) and the
    # .pyc files out of it.  PYTEST_ADDOPTS reaches every lane and every xdist
    # worker; PYTHONDONTWRITEBYTECODE keeps .pyc out of a read-only checkout.
    env["PYTEST_ADDOPTS"] = (
        f"{env.get('PYTEST_ADDOPTS', '')} -o cache_dir={test_root}/.pytest_cache".strip()
    )
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # The runner cd's to REPO and expects tests/ on PYTHONPATH.
    env["PYTHONPATH"] = f"tests{os.pathsep}{env.get('PYTHONPATH', '')}".rstrip(os.pathsep)

    os.chdir(REPO)
    log(f"user={_whoami()} uid={os.getuid()}  tree={REPO}")
    log(f"TEST_ROOT={test_root}  nginx={nginx}")
    log("test user == server user: permission semantics are REAL (no root bypass)")
    os.execvpe(_suite_argv(extra)[0], _suite_argv(extra), env)


def _run_root_handoff(nginx: str, extra: list[str]) -> None:
    # ---- root mode: sync to a neutral tree, hand over, drop ------------------ #
    if subprocess.run(["id", BRIX_TEST_USER], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False).returncode != 0:
        die(f"no such user: {BRIX_TEST_USER} (create it, e.g.: "
            f"useradd -r -m -d /var/lib/{BRIX_TEST_USER} {BRIX_TEST_USER})")
    target_uid = subprocess.run(["id", "-u", BRIX_TEST_USER], capture_output=True,
                                text=True, check=True).stdout.strip()
    if target_uid == "0":
        die("BRIX_TEST_USER must not be root")
    if shutil.which("rsync") is None:
        die("rsync not found (needed to sync the checkout)")

    test_root = os.environ.get("TEST_ROOT", TEST_ROOT_DEFAULT)
    log(f"target user: {BRIX_TEST_USER} (uid {target_uid})")

    _clear_foreign_fleet()

    # Sync the checkout to somewhere the user can actually reach.  --delete so a
    # removed/renamed file cannot linger and silently pass a stale test; .git is
    # excluded (no test reads it, and it is the bulk of the tree).  Build outputs
    # are excluded too — they are rebuilt/installed separately and are large.
    log(f"syncing checkout -> {BRIX_TEST_TREE} (/root is left untouched)")
    os.makedirs(BRIX_TEST_TREE, exist_ok=True)
    subprocess.run(
        ["rsync", "-a", "--delete",
         "--exclude", ".git/", "--exclude", "build/",
         "--exclude", "__pycache__/", "--exclude", ".pytest_cache/",
         f"{REPO}/", f"{BRIX_TEST_TREE}/"],
        check=True,
    )
    subprocess.run(["chown", "-R", BRIX_TEST_USER, BRIX_TEST_TREE], check=True)
    os.chmod(BRIX_TEST_TREE, 0o755)
    log(f"tree owned by {BRIX_TEST_USER}")

    # The user owns its whole test tree: exports, PKI, logs, tmp — so nginx
    # workers and the reference xrootd (which runs un-shimmed as this user) can
    # write what they must.
    os.makedirs(os.path.join(test_root, "home"), exist_ok=True)
    subprocess.run(["chown", "-R", BRIX_TEST_USER, test_root], check=True)
    os.chmod(test_root, 0o755)
    log(f"TEST_ROOT={test_root} owned by {BRIX_TEST_USER}")

    if not os.access(nginx, os.R_OK):
        die(f"nginx not readable: {nginx}")
    if subprocess.run(["runuser", "-u", BRIX_TEST_USER, "--", "test", "-x", nginx],
                      check=False).returncode != 0:
        die(f"'{BRIX_TEST_USER}' cannot execute {nginx}")
    log(f"nginx={nginx}")
    log(f"dropping to '{BRIX_TEST_USER}' — test user == server user from here on")

    # HOME must exist and be writable: `nobody`'s passwd home is / and Python/tools
    # will try to write there.  Re-exec the COPY, not REPO — the user cannot read
    # REPO, which is the whole reason for the sync.
    tree_script = os.path.join(BRIX_TEST_TREE, "tests", "run_suite_unprivileged.py")
    argv = [
        "runuser", "-u", BRIX_TEST_USER, "--", "env",
        f"HOME={test_root}/home",
        f"TEST_ROOT={test_root}",
        f"NGINX_BIN={nginx}",
        f"TEST_NGINX_BIN={nginx}",
        "PYTHONDONTWRITEBYTECODE=1",
        f"PYTEST_ADDOPTS={os.environ.get('PYTEST_ADDOPTS', '')} "
        f"-o cache_dir={test_root}/.pytest_cache".strip(),
        f"BRIX_TEST_USER={BRIX_TEST_USER}",
        sys.executable, tree_script, *extra,
    ]
    os.execvp(argv[0], argv)


def _whoami() -> str:
    import pwd
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return str(os.getuid())


def main(argv: list[str]) -> int:
    nginx = _pick_nginx()
    if os.geteuid() != 0:
        return _run_in_place(nginx, argv)
    _run_root_handoff(nginx, argv)
    return 0  # unreachable: _run_root_handoff execs


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
