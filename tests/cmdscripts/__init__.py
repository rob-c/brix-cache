"""Python command modules replacing former shell test entry points."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path


def _argv_value(argv, flag, default=None):
    try:
        return argv[argv.index(flag) + 1]
    except (ValueError, IndexError):
        return default


def _is_nginx_command(argv):
    if not argv:
        return False
    first = str(argv[0])
    return first == "nginx" or first.endswith("/nginx")


def _is_nginx_start(argv):
    probes = ("-t", "-T", "-s", "-v", "-V")
    return _is_nginx_command(argv) and "-c" in argv and not any(
        flag in argv for flag in probes
    )


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
    if os.geteuid() != 0 or not _is_nginx_start(argv):
        return argv
    prefix = _argv_value(argv, "-p")
    if prefix is None:
        return argv
    conf = _argv_value(argv, "-c")
    open_tree_for_worker(prefix, conf)
    return argv


def _prepare_nginx_config(argv: list[str]) -> list[str]:
    """Apply the suite's dynamic-module/runtime policy to raw nginx calls.

    A sizeable set of command scenarios predates ``LiveRun`` and deliberately
    shares this small command wrapper.  With a packaged nginx those scenarios
    must receive the same ``load_module`` preamble as registry-owned servers;
    otherwise every stream/project directive is reported as unknown.
    """
    if not _is_nginx_command(argv) or "-c" not in argv:
        return argv
    config_value = _argv_value(argv, "-c")
    if config_value is None:
        return argv
    config_arg = Path(config_value)
    prefix = Path(_argv_value(argv, "-p", config_arg.parent))
    config = config_arg if config_arg.is_absolute() else prefix / config_arg
    if not config.is_file():
        return argv
    # Lazy import avoids making cmdscripts.live_common -> cmdscripts an import
    # cycle during test collection.
    from cmdscripts.live_common import (  # noqa: PLC0415
        inject_nginx_load_modules,
        inject_nginx_runtime_paths,
    )
    inject_nginx_load_modules(config)
    inject_nginx_runtime_paths(config, prefix)
    return argv


def _credential_snapshot(tree):
    snapshot = {}
    for walk_root, _dirs, files in os.walk(tree):
        for name in files:
            if not name.endswith((".pem", ".key", ".p12")):
                continue
            path = os.path.join(walk_root, name)
            try:
                stat = os.stat(path)
            except OSError:
                continue
            snapshot[path] = (stat.st_uid, stat.st_gid, stat.st_mode & 0o7777)
    return snapshot


def _restore_credentials(snapshot):
    for path, (uid, gid, mode) in snapshot.items():
        try:
            os.chown(path, uid, gid)
            os.chmod(path, mode)
        except OSError:
            pass


def _open_tree_ancestors(tree):
    parent = os.path.dirname(os.path.abspath(tree))
    while parent not in ("/", ""):
        subprocess.run(["chmod", "a+rx", parent], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        parent = os.path.dirname(parent)


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
    snapshot = _credential_snapshot(tree)
    subprocess.run(["chmod", "-R", "a+rwX", tree], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _restore_credentials(snapshot)
    _open_tree_ancestors(tree)
    _open_shared_user_proxy_for_worker()
    if conf is not None:
        _hand_conf_credentials_to_worker(conf, tree)


def _read_config(conf):
    try:
        return open(conf, encoding="utf-8", errors="replace").read()
    except OSError:
        return None


def _handoff_stores(text, worker):
    import re  # noqa: PLC0415
    stores = re.findall(r"\bbrix_storage_credential_dir\s+([^;\s]+)\s*;", text)
    for raw_store in stores:
        handoff_credential_store(raw_store.strip('"'), worker)


def handoff_credential_store(store, worker=None) -> None:
    """Give one credential store directory to the nginx worker: owner + 0700.

    The path-taking public form of the store handoff, for standalone live-lab
    launchers that build their store directly rather than through
    ``open_tree_for_worker`` (which is root-gated and so does nothing under a
    non-root harness).  The PERSISTENT arm of ``brix_cred_write``
    (``cred_stage.c`` ``cred_dir_check``) refuses a store that is group/other
    accessible or not owned by the writing worker, returning ``EPERM`` — surfaced
    as ``507``.  Under a root harness the recursive chown hands the tree to
    ``nobody``; under a non-root harness the chown to ``nobody`` harmlessly fails
    and the ``0700`` directory stays owned by the launching user, which is also
    the worker, satisfying ``cred_dir_check``'s euid test either way.
    """
    store = str(store)
    if not store or not os.path.isdir(store):
        return
    worker = worker if worker is not None else _worker_user()
    if worker:
        subprocess.run(["chown", "-R", worker, store], check=False)
    os.chmod(store, 0o700)


def _worker_credential_path(path, tree, twin_dir, worker):
    import shutil as _shutil  # noqa: PLC0415
    path = path.strip('"')
    if not path or not os.path.isfile(path):
        return path
    if os.path.abspath(path).startswith(tree + os.sep):
        try:
            _shutil.chown(path, worker)
        except OSError:
            pass
        return path
    twin = os.path.join(twin_dir, os.path.basename(path))
    try:
        os.makedirs(twin_dir, exist_ok=True)
        os.chmod(twin_dir, 0o755)
        _shutil.copy2(path, twin)
        _shutil.chown(twin, worker)
        os.chmod(twin, 0o600)
        return twin
    except OSError:
        return path


def _rewrite_worker_credentials(text, tree, worker):
    import re  # noqa: PLC0415
    pattern = r"\b(?:x509_proxy|x509_key|brix_certificate_key)\s+([^;\s]+)\s*;"
    rewritten = text
    twin_dir = os.path.join(tree, ".worker-creds")
    for path in set(re.findall(pattern, text)):
        twin = _worker_credential_path(path, tree, twin_dir, worker)
        rewritten = rewritten.replace(path.strip('"'), twin)
    return rewritten


def _write_rewritten_config(conf, text, rewritten):
    if rewritten == text:
        return
    try:
        with open(conf, "w", encoding="utf-8") as handle:
            handle.write(rewritten)
    except OSError:
        pass


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
    worker = _worker_user()
    if worker is None:
        return
    tree = os.path.abspath(str(tree))
    text = _read_config(conf)
    if text is None:
        return
    _handoff_stores(text, worker)
    rewritten = _rewrite_worker_credentials(text, tree, worker)
    _write_rewritten_config(conf, text, rewritten)


def _worker_user() -> str | None:
    import pwd  # noqa: PLC0415
    worker = os.environ.get("BRIX_WORKER_USER", "nobody")
    try:
        pwd.getpwnam(worker)
    except KeyError:
        return None
    return worker


def _open_pki_directories(paths):
    for directory in paths:
        if os.path.isdir(directory):
            subprocess.run(["chmod", "a+rx", directory], check=False)


def _open_ca_files(ca_dir):
    if not os.path.isdir(ca_dir):
        return
    paths = [os.path.join(ca_dir, name) for name in os.listdir(ca_dir)]
    subprocess.run(["chmod", "a+r", *paths], check=False)


def _open_host_certificate(server_dir):
    certificate = os.path.join(server_dir, "hostcert.pem")
    if os.path.isfile(certificate):
        subprocess.run(["chmod", "a+r", certificate], check=False)


def _handoff_host_key(server_dir, worker):
    import shutil as _shutil  # noqa: PLC0415
    key = os.path.join(server_dir, "hostkey.pem")
    if not os.path.isfile(key):
        return
    try:
        _shutil.chown(key, worker)
        os.chmod(key, 0o400)
    except OSError:
        pass


def _open_shared_user_proxy_for_worker() -> None:
    """Hand the shared TEST_ROOT proxy/user key to the runtime worker identity.

    ``brix_credential { x509_proxy ...; }`` is read by the WORKER (nobody) at
    upstream-login time, not by the root master at config time.  A root-owned
    0600 proxy is therefore unreadable exactly when it is needed; chown it (and
    the traversal path to it) to the worker user.  0600 stays: XrdCl's GSI
    loader refuses a lax proxy, and the tests' root-run clients ignore modes.
    """
    worker = _worker_user()
    if worker is None:
        return
    from settings import PKI_DIR  # noqa: PLC0415 — import cycle at module load
    user_dir = os.path.join(PKI_DIR, "user")
    server_dir = os.path.join(PKI_DIR, "server")
    ca_dir = os.path.join(PKI_DIR, "ca")
    _open_pki_directories((PKI_DIR, user_dir, server_dir, ca_dir))
    _open_ca_files(ca_dir)
    _open_host_certificate(server_dir)
    _handoff_host_key(server_dir, worker)


def run(argv: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a real command-line client with captured text output.

    A default 120s timeout keeps a wedged client from hanging the whole
    pytest process; on expiry the caller sees rc=124 with the timeout noted
    in stderr, mirroring coreutils `timeout`.
    """
    kwargs.setdefault("timeout", 120)
    argv = _prepare_nginx_config(list(argv))
    argv = _maybe_open_tree_for_deescalated_worker(argv)
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
