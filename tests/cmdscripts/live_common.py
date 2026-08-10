"""Small, explicit primitives shared by Python ports of live command scripts."""

from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Iterable

from cmdscripts.compile_run import REPO_ROOT
from lib_py.util import kill_pid_list, pids_on_port, wait_tcp
from settings import BIND_HOST


class LiveFailure(RuntimeError):
    """A failed external command with its captured diagnostic output."""


def _configured_nginx_modules() -> list[str]:
    value = os.environ.get("TEST_NGINX_LOAD_MODULES", "")
    return [path for path in value.split(os.pathsep) if path]


def _missing_module_directives(body: str, modules: list[str]) -> list[str]:
    directives = [f"load_module {json.dumps(path)};" for path in modules]
    existing = set(body.splitlines())
    return [directive for directive in directives if directive not in existing]


def inject_nginx_load_modules(config: str | Path,
                              nginx_bin: str | Path | None = None) -> None:
    """Apply runner-selected dynamic modules to any generated nginx config.

    STATIC/DYNAMIC SEPARATION GUARD: the fleet keeps a static build (stream
    compiled in) and a `--with-stream=dynamic` build in SEPARATE trees. When
    nginx_bin is given and points at a static build, injecting a
    ngx_stream_module.so is refused — a dynamic stream module dlopen'd into a
    static binary fails with `undefined symbol: ngx_stat_active` (or double-
    registers stream). Modules belong only to the dynamic build, resolved from
    its own objs/ dir. This turns a cryptic startup crash into a clear error.
    """
    modules = _configured_nginx_modules()
    if not modules:
        return
    if nginx_bin is not None and any(
            Path(m).name == "ngx_stream_module.so" for m in modules):
        try:
            probe = subprocess.run([str(nginx_bin), "-V"],
                                   capture_output=True, text=True)
            vout = f"{probe.stdout}\n{probe.stderr}"
        except OSError:
            vout = ""
        if "--with-stream=dynamic" not in vout:
            raise LiveFailure(
                f"static/dynamic build overlap: {nginx_bin} is a STATIC nginx build "
                f"(stream compiled in) but TEST_NGINX_LOAD_MODULES injects a "
                f"ngx_stream_module.so ({modules}). Mixing the two builds' trees "
                f"dlopen-fails on undefined ngx_stat_active. Use the "
                f"--with-stream=dynamic build (its own tree, its own modules) for "
                f"module testing, or unset TEST_NGINX_LOAD_MODULES for the static build.")
    target = Path(config)
    body = target.read_text(encoding="utf-8")
    missing = _missing_module_directives(body, modules)
    if missing:
        target.write_text("\n".join(missing) + "\n\n" + body, encoding="utf-8")


def _main_runtime_directives(body: str, logs: Path, pid_path: str | Path | None):
    directives = []
    if not re.search(r"\bpid\s+", body):
        selected = Path(pid_path) if pid_path is not None else logs / "nginx.pid"
        directives.append(f"pid {json.dumps(str(selected))};")
    if not re.search(r"\berror_log\s+", body):
        directives.append(f"error_log {json.dumps(str(logs / 'error.log'))} notice;")
    return directives


def _http_runtime_directives(body: str, logs: Path, tmp: Path) -> list[str]:
    paths = {
        "access_log": logs / "access.log",
        "client_body_temp_path": tmp / "client-body",
        "proxy_temp_path": tmp / "proxy",
        "fastcgi_temp_path": tmp / "fastcgi",
        "uwsgi_temp_path": tmp / "uwsgi",
        "scgi_temp_path": tmp / "scgi",
    }
    return [
        f"    {name} {json.dumps(str(path))};"
        for name, path in paths.items()
        if not re.search(rf"\b{name}\s+", body)
    ]


def _inject_http_runtime_directives(body: str, directives: list[str]) -> str:
    if not directives or not re.search(r"\bhttp\s*\{", body):
        return body
    addition = "\n" + "\n".join(directives)
    return re.sub(r"(\bhttp\s*\{)", rf"\1{addition}", body, count=1)


def inject_nginx_runtime_paths(
    config: str | Path,
    prefix: str | Path,
    *,
    pid_path: str | Path | None = None,
) -> None:
    """Confine packaged-nginx runtime files to a test-owned prefix."""
    target = Path(config)
    prefix = Path(prefix)
    logs = prefix / "logs"
    tmp = prefix / "tmp"
    logs.mkdir(parents=True, exist_ok=True)
    tmp.mkdir(parents=True, exist_ok=True)
    body = target.read_text(encoding="utf-8")
    main = _main_runtime_directives(body, logs, pid_path)
    if main:
        body = "\n".join(main) + "\n\n" + body
    missing = _http_runtime_directives(body, logs, tmp)
    body = _inject_http_runtime_directives(body, missing)
    target.write_text(body, encoding="utf-8")


# Per-source cache: {realpath(src) -> frozen copy}. Keyed on the SOURCE binary,
# not a single slot, so a process that freezes more than one nginx (e.g. the plain
# fleet binary AND an ASan build) never returns the wrong cached copy.
_FROZEN_NGINX: dict[str, Path] = {}

# Literal /tmp, NOT tempfile.gettempdir(): the test lane exports
# TMPDIR=/tmp/xrd-test/tmp, which pytest's basetemp garbage-rotation
# rm -rf's mid-session — a frozen copy under it vanishes under a running
# lane (seen live: every LifecycleHarness nginx exec failing rc=1).
# Module-level so tests can point the freeze at a private root instead of
# colliding with (and ETXTBSY-ing against) this process's real frozen binary.
_FREEZE_ROOT = Path("/tmp")


def _session_freeze_dir() -> Path:
    """The one freeze directory shared by every process of a test session.

    Keyed off ``TEST_ROOT`` so all xdist workers (and every ``LiveRun``) of a
    single session resolve to the SAME frozen binary — one shared copy, never a
    per-process private one — while sessions that run under a distinct private
    ``TEST_ROOT`` stay isolated and cannot clobber each other's binary.  Lives
    under ``_FREEZE_ROOT`` (literal ``/tmp`` — deliberately NOT under the lane's
    ``TMPDIR``, which pytest's basetemp rotation rm -rf's mid-session).
    """
    try:
        from settings import TEST_ROOT  # noqa: PLC0415 — lazy, avoids import cycle
        key = str(TEST_ROOT)
    except Exception:
        key = os.environ.get("TEST_ROOT", "/tmp/xrd-test")
    tag = hashlib.sha1(key.encode()).hexdigest()[:12]
    return _FREEZE_ROOT / f"brix-nginx-session-{tag}"


def _nginx_validates(binary: Path) -> bool:
    try:
        return subprocess.run([str(binary), "-v"], capture_output=True).returncode == 0
    except OSError:
        return False


def _ensure_freeze_cache() -> bool:
    global _FROZEN_NGINX
    was_reset = _FROZEN_NGINX is None
    if was_reset:
        _FROZEN_NGINX = {}
    return was_reset


def _cached_frozen_binary(real: str) -> Path | None:
    cached = _FROZEN_NGINX.get(real)
    if cached is None or not cached.exists():
        return None
    return cached


def _matches_source(frozen: Path, source_stat: os.stat_result) -> bool:
    if not frozen.exists():
        return False
    frozen_stat = frozen.stat()
    same_size = frozen_stat.st_size == source_stat.st_size
    same_time = int(frozen_stat.st_mtime) == int(source_stat.st_mtime)
    return same_size and same_time and _nginx_validates(frozen)


def _remove_if_present(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def _copy_frozen_binary(source: Path, temporary: Path, frozen: Path, real: str) -> bool:
    try:
        shutil.copy2(source, temporary)
        temporary.chmod(0o755)
        if not _nginx_validates(temporary):
            temporary.unlink()
            return False
        os.replace(temporary, frozen)
        _FROZEN_NGINX[real] = frozen
        return True
    except OSError:
        return False


def _retry_frozen_copy(source: Path, temporary: Path, frozen: Path, real: str) -> bool:
    for _ in range(6):
        if _copy_frozen_binary(source, temporary, frozen, real):
            return True
        time.sleep(0.5)
    return False


def freeze_nginx(src: str | Path) -> Path:
    """Return the session's single immutable copy of the nginx binary.

    The shared build tree's ``objs/nginx`` can be relinked by a concurrent
    incremental build; ``exec`` of a binary during its relink window fails with
    EACCES, surfacing as a flaky ``PermissionError`` the moment a scenario spawns
    a server.  Freeze the binary ONCE per session to a stable, session-shared
    path so every server the harness starts execs the same frozen binary no
    build can disturb.  The first process to reach here copies it; every later
    process (and every xdist worker) reuses that copy as long as it still matches
    the current source — ``copy2`` preserves size+mtime, so a rebuilt source no
    longer matches and is re-frozen.  The copy is validated (``nginx -v``) and
    the swap is atomic (``os.replace``), so no process ever execs a half-written
    binary.  Falls back to the live path if no stable copy can be taken.

    The frozen file is keyed on the SOURCE binary (a short hash of its realpath),
    not just on TEST_ROOT: an ASan/UBSan nginx and the plain fleet binary share a
    TEST_ROOT but must never share one ``nginx`` file.  If they did, whichever
    process copied last would win and the other's servers would exec the wrong
    binary — e.g. the ASan STATIC build (stream+brix compiled in) then fails to
    dlopen the distro DYNAMIC modules with ``undefined symbol: ngx_stat_active``,
    failing every server's ``nginx -t``.  Distinct source -> distinct frozen file,
    so the two never collide or race.
    """
    global _FROZEN_NGINX
    src = Path(src)
    if not src.exists():
        return src
    cache_was_reset = _ensure_freeze_cache()
    real = os.path.realpath(src)
    cached = _cached_frozen_binary(real)
    if cached is not None:
        return cached
    srctag = hashlib.sha1(real.encode()).hexdigest()[:8]
    frozen = _session_freeze_dir() / f"nginx-{srctag}"
    frozen.parent.mkdir(parents=True, exist_ok=True)
    sstat = src.stat()
    # Reuse a copy an earlier process (the controller, another xdist worker)
    # already froze of THIS source — the common path once the session is warm.
    if _matches_source(frozen, sstat):
        _FROZEN_NGINX[real] = frozen
        return frozen
    tmp = frozen.with_name(f".{frozen.name}.{os.getpid()}.tmp")
    if _retry_frozen_copy(src, tmp, frozen, real):
        return frozen
    _remove_if_present(tmp)
    if cache_was_reset:
        _FROZEN_NGINX = None
    return src


def _fuse_mounts_under(prefix: str) -> list[str]:
    try:
        lines = Path("/proc/mounts").read_text().splitlines()
    except OSError:
        return []
    points = []
    for line in lines:
        fields = line.split()
        if len(fields) >= 3 and fields[2].startswith("fuse") and fields[1].startswith(prefix):
            points.append(fields[1])
    return points


def _unmount_fuse_points(points: list[str]) -> None:
    fusermount = shutil.which("fusermount3") or shutil.which("fusermount")
    if not fusermount:
        return
    for point in points:
        subprocess.run(
            [fusermount, "-uz", point],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )


def _referencing_pids(prefix: str) -> list[int]:
    survey = subprocess.run(
        ["pgrep", "-f", prefix], stdout=subprocess.PIPE, text=True, check=False
    )
    pids = []
    for value in survey.stdout.split():
        try:
            pids.append(int(value))
        except ValueError:
            pass
    return pids


def _kill_other_processes(pids: list[int]) -> None:
    current = os.getpid()
    for pid in pids:
        if pid == current:
            continue
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def _wait_for_fuse_unmount(prefix: str) -> None:
    deadline = time.monotonic() + 3
    while _fuse_mounts_under(prefix) and time.monotonic() < deadline:
        time.sleep(0.1)


def _reap_fuse_mounts(root: Path) -> None:
    """Tear down any FUSE mount left under root, whatever killed its scenario.

    A run that dies mid-mount (pytest-timeout, crash) leaves a daemonized
    cvmfs2/brixcvmfs mount behind that process cleanup can't reach, and the
    first rmtree to walk into the dead mount — ours here, or the whole
    session teardown sweeping /tmp/xrd-test — hangs forever in the kernel's
    FUSE wait.  Lazy unmount alone is not enough: in-flight requests stay
    wedged until the daemon dies, so kill every process still referencing
    the ephemeral tree as well."""
    prefix = f"{str(root).rstrip('/')}/"
    points = _fuse_mounts_under(prefix)
    if not points:
        return
    _unmount_fuse_points(points)
    _kill_other_processes(_referencing_pids(prefix))
    _wait_for_fuse_unmount(prefix)


def _terminate_pidfiles(pidfiles: list[Path]) -> None:
    for pidfile in reversed(pidfiles):
        try:
            os.kill(int(pidfile.read_text().strip()), signal.SIGTERM)
        except (OSError, ValueError):
            pass


def _terminate_processes(processes: list[subprocess.Popen[str]]) -> None:
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()


def _wait_processes(processes: list[subprocess.Popen[str]]) -> None:
    deadline = time.monotonic() + 2
    for process in reversed(processes):
        remaining = max(0, deadline - time.monotonic())
        try:
            process.wait(remaining)
        except subprocess.TimeoutExpired:
            process.kill()


def _call_text_mode(input_data: str | bytes | None, binary: bool) -> bool:
    return not binary and not isinstance(input_data, bytes)


def _call_cwd(cwd: Path | None) -> str | None:
    return str(cwd) if cwd else None


def _call_stdin(input_data: str | bytes | None):
    return subprocess.PIPE if input_data is not None else None


def _call_environment(environment: dict[str, str] | None) -> dict[str, str]:
    return {**os.environ, **(environment or {})}


def _raise_call_failure(result: subprocess.CompletedProcess[str]) -> None:
    output = result.stderr or result.stdout
    command = " ".join(result.args)
    raise LiveFailure(f"{command} failed ({result.returncode}): {output}")


def _reap_port(port: int) -> None:
    stale = pids_on_port(port)
    if not stale:
        return
    kill_pid_list(stale)
    for _ in range(30):
        if not pids_on_port(port):
            return
        time.sleep(0.1)


def _nginx_error_detail(prefix: Path) -> str:
    error_log = prefix / "logs/e.log"
    if not error_log.exists():
        return ""
    return error_log.read_text(errors="replace")


from split_continuation import load as _load_continuation
_load_continuation(globals(), __file__, "live_common_runtime.py")

