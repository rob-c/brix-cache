"""Python command modules replacing former shell test entry points."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable, Sequence


def _maybe_open_tree_for_deescalated_worker(argv: list[str]) -> list[str]:
    """Open a raw nginx server launch's tree for the de-escalated worker.

    Live scenarios start their own nginx via ``run([nginx, "-p", .., "-c", ..])``.
    Under a root harness the master starts as root but the always-on worker
    de-escalation (src/auth/impersonate/lifecycle_worker.c) drops every worker to
    ``brix_worker_user`` (default ``nobody``) — it refuses a uid-0 worker even
    with an explicit ``user root;``, so forcing the config (the old approach
    here) no longer works.  Instead make the throwaway per-scenario tree usable
    by that worker: a+rwX the ``-p`` prefix, a+rx its ancestors (pytest tmp dirs
    are 0700), and open the shared user proxy the GSI credential blocks hand to
    the worker at runtime (chown to the worker user, keep 0600 — XrdCl refuses a
    group/other-accessible proxy, and the root-run client bypasses modes anyway).
    Only a genuine server start is treated (has ``-c``, not a ``-t`` config-test
    / ``-s`` signal / ``-v`` version probe).
    """
    if os.geteuid() != 0 or not argv:
        return argv
    first = str(argv[0])
    if not (first == "nginx" or first.endswith("/nginx")):
        return argv
    if "-c" not in argv:
        return argv
    if any(flag in argv for flag in ("-t", "-T", "-s", "-v", "-V")):
        return argv
    try:
        prefix = argv[argv.index("-p") + 1]
    except (ValueError, IndexError):
        return argv
    try:
        conf = argv[argv.index("-c") + 1]
    except (ValueError, IndexError):
        conf = None
    open_tree_for_worker(prefix, conf)
    return argv


def open_tree_for_worker(tree, conf=None) -> None:
    """Make `tree` (a scenario prefix or LiveRun root) usable by the worker.

    Under a root harness the de-escalated worker (``nobody``) cannot traverse
    the 0700 pytest/mkdtemp trees the harnesses build, nor read the root-owned
    credentials they reference.  Open the tree (a+rwX), its ancestors (a+rx),
    re-tighten in-tree private keys to worker-owned 0600 (the GSI loaders
    refuse lax keys), open the shared TEST_ROOT PKI, and — when `conf` is given
    — hand any ``brix_storage_credential_dir`` store in it to the worker
    (owner + 0700, exactly what shared_conf's ensure expects). No-op unless
    running as root.
    """
    if os.geteuid() != 0:
        return
    tree = str(tree)
    # The blanket chmod below would leave every minted client proxy/key 0666 —
    # and XrdSecgsi refuses a group/other-accessible credential ("cannot load
    # proxy credential"), killing the ROOT-RUN test clients. Snapshot PEM/key
    # modes+owners first and restore them right after, so credential material
    # keeps exactly the posture the harness gave it.
    snap = {}
    for walk_root, _dirs, files in os.walk(tree):
        for name in files:
            if name.endswith((".pem", ".key", ".p12")):
                path = os.path.join(walk_root, name)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                snap[path] = (st.st_uid, st.st_gid, st.st_mode & 0o7777)
    subprocess.run(["chmod", "-R", "a+rwX", tree], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for path, (uid, gid, mode) in snap.items():
        try:
            os.chown(path, uid, gid)
            os.chmod(path, mode)
        except OSError:
            pass
    parent = os.path.dirname(os.path.abspath(tree))
    while parent not in ("/", ""):
        subprocess.run(["chmod", "a+rx", parent], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        parent = os.path.dirname(parent)
    _open_shared_user_proxy_for_worker()
    if conf is not None:
        _hand_conf_credentials_to_worker(conf, tree)


def _hand_conf_credentials_to_worker(conf, tree) -> None:
    """Give the WORKER the credentials `conf` makes it read/write.

    Resolved from the rendered nginx config so client-side proxies are never
    touched:
      * `brix_storage_credential_dir` stores — delegation writes happen in the
        worker, and shared_conf's ensure refuses to adopt a foreign-owned
        pre-existing store, so a root-created (or blanket-chmodded 0777) store
        dir would only ever warn and delegation would fail.  Worker-owned 0700.
      * private credential FILES the worker loads at upstream-login/TLS time
        (`x509_proxy` / `x509_key` / `brix_certificate_key`):
          - under the scenario tree: chown to the worker (nothing else uses
            them; the GSI loaders demand euid-owned, tight-mode files);
          - OUTSIDE the tree (the shared TEST_ROOT proxy_std etc.): those are
            ALSO loaded by root-run test clients, and XrdSecgsi demands the
            file be owned by the loading process's euid — one file cannot
            satisfy both, so copy it to a worker-owned twin inside the
            scenario tree and rewrite the (throwaway, regenerated-per-start)
            config to point at the twin.
    """
    import re  # noqa: PLC0415
    import shutil as _shutil  # noqa: PLC0415
    worker = _worker_user()
    if worker is None:
        return
    tree = os.path.abspath(str(tree))
    try:
        text = open(conf, encoding="utf-8", errors="replace").read()
    except OSError:
        return
    for store in re.findall(r"\bbrix_storage_credential_dir\s+([^;\s]+)\s*;",
                            text):
        store = store.strip('"')
        if store and os.path.isdir(store):
            subprocess.run(["chown", "-R", worker, store], check=False)
            os.chmod(store, 0o700)
    rewritten = text
    twin_dir = os.path.join(tree, ".worker-creds")
    for path in set(re.findall(
            r"\b(?:x509_proxy|x509_key|brix_certificate_key)\s+([^;\s]+)\s*;",
            text)):
        path = path.strip('"')
        if not path or not os.path.isfile(path):
            continue
        if os.path.abspath(path).startswith(tree + os.sep):
            try:
                _shutil.chown(path, worker)
            except OSError:
                pass
            continue
        twin = os.path.join(twin_dir, os.path.basename(path))
        try:
            os.makedirs(twin_dir, exist_ok=True)
            os.chmod(twin_dir, 0o755)
            _shutil.copy2(path, twin)
            _shutil.chown(twin, worker)
            os.chmod(twin, 0o600)
        except OSError:
            continue
        rewritten = rewritten.replace(path, twin)
    if rewritten != text:
        try:
            with open(conf, "w", encoding="utf-8") as fh:
                fh.write(rewritten)
        except OSError:
            pass


def _worker_user() -> str | None:
    import pwd  # noqa: PLC0415
    worker = os.environ.get("BRIX_WORKER_USER", "nobody")
    try:
        pwd.getpwnam(worker)
    except KeyError:
        return None
    return worker


def _open_shared_user_proxy_for_worker() -> None:
    """Hand the shared TEST_ROOT proxy/user key to the runtime worker identity.

    ``brix_credential { x509_proxy ...; }`` is read by the WORKER (nobody) at
    upstream-login time, not by the root master at config time.  A root-owned
    0600 proxy is therefore unreadable exactly when it is needed; chown it (and
    the traversal path to it) to the worker user.  0600 stays: XrdCl's GSI
    loader refuses a lax proxy, and the tests' root-run clients ignore modes.
    """
    import shutil as _shutil  # noqa: PLC0415
    worker = _worker_user()
    if worker is None:
        return
    from settings import PKI_DIR  # noqa: PLC0415 — import cycle at module load
    user_dir = os.path.join(PKI_DIR, "user")
    server_dir = os.path.join(PKI_DIR, "server")
    ca_dir = os.path.join(PKI_DIR, "ca")
    for d in (PKI_DIR, user_dir, server_dir, ca_dir):
        if os.path.isdir(d):
            subprocess.run(["chmod", "a+rx", d], check=False)
    if os.path.isdir(ca_dir):
        subprocess.run(["chmod", "a+r"] + [
            os.path.join(ca_dir, f) for f in os.listdir(ca_dir)
        ], check=False)
    if os.path.isfile(os.path.join(server_dir, "hostcert.pem")):
        subprocess.run(["chmod", "a+r", os.path.join(server_dir, "hostcert.pem")],
                       check=False)
    # The hostkey stays 0400 but moves to the worker identity (same treatment
    # server_launcher._xrootd_runas_user gives the fleet's hostkey). The USER
    # proxy is deliberately NOT touched: root-run test clients load it, and
    # XrdSecgsi demands the file be owned by the loading euid — worker-side
    # references get a worker-owned twin via _hand_conf_credentials_to_worker.
    path = os.path.join(PKI_DIR, "server", "hostkey.pem")
    if os.path.isfile(path):
        try:
            _shutil.chown(path, worker)
            os.chmod(path, 0o400)
        except OSError:
            pass


def run(argv: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a real command-line client with captured text output.

    A default 120s timeout keeps a wedged client from hanging the whole
    pytest process; on expiry the caller sees rc=124 with the timeout noted
    in stderr, mirroring coreutils `timeout`.
    """
    kwargs.setdefault("timeout", 120)
    argv = _maybe_open_tree_for_deescalated_worker(list(argv))
    try:
        return subprocess.run(list(argv), capture_output=True, text=True, **kwargs)
    except subprocess.TimeoutExpired as exc:
        def _text(stream):
            if stream is None:
                return ""
            return stream.decode(errors="replace") if isinstance(stream, bytes) else stream
        return subprocess.CompletedProcess(
            list(argv), 124, stdout=_text(exc.stdout),
            stderr=_text(exc.stderr) + f"\n[timed out after {kwargs['timeout']}s]")


def main(entry: Callable[[list[str]], int | None] | None = None, argv: Sequence[str] | None = None) -> int:
    """Shared direct-execution helper for command-script modules."""
    args = list(sys.argv[1:] if argv is None else argv)
    if entry is None:
        return 0
    result = entry(args)
    return 0 if result is None else int(result)


__all__ = ["main", "open_tree_for_worker", "run"]
