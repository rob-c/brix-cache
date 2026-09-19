"""Python ports of CVMFS core/client/brixcvmfs shell runners."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from cmdscripts.compile_run import REPO_ROOT, compile_binary, result, run
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST


# The dependency lists (CVMFS_CORE_DEPS, CVMFS_CLIENT_DEPS, CVMFS_WALK_DEPS,
# BRIXCVMFS_CORE_DEPS, BRIXCVMFS_DRIVER_SRCS) live in the loader, not here.
#
# The file-size split copied them verbatim into this shard, and because
# `split_continuation.load` execs a shard INTO the loader's globals — at the
# very end of it — the copies did not shadow harmlessly: they WON.  Every site
# that reads `cmdscripts.cvmfs_driver_units.BRIXCVMFS_DRIVER_SRCS` got the copy,
# `_compile_brixcvmfs` (defined in the loader) resolved the copy through its own
# module globals, and an entry added to the list beside that function changed
# nothing at all.  Adding the client PAL body `client/lib/platform/<host>/posix.c`
# to the loader's list left `brixcvmfs` still failing to link on
# `brix_plat_fuse_host_opts`, with both lists on screen reading as if it were
# there.  Nothing in this shard needs them — its functions call
# `_compile_brixcvmfs()` — so the second copy is simply gone.


def brixcvmfs_check(base: Path) -> tuple[bool, str]:
    ok, _, _, message = _fuse3_flags()
    if not ok:
        return result(True, message)
    context = _prepare_check(base)
    failure = _compile_check_binaries(context)
    if failure:
        return failure
    created = run(
        [str(context["mkrepo"]), context["repo"],
         str(context["web"]), str(context["pub"])], cwd=REPO_ROOT,
    )
    if created.returncode != 0:
        return result(False, f"brix_mkrepo failed: {_tail(created)}")
    try:
        port = cmdscript_ports("cvmfs_driver_units")[0]
    except PermissionError as exc:
        return result(True, f"SKIP: sockets unavailable for --check: {exc}")
    server = _start_check_server(context["web"], port)
    try:
        return _exercise_check(context, port)
    finally:
        _stop_check_server(server)


def _prepare_check(base):
    repo = "test.cern.ch"
    web = base / "web"
    cache = base / "cache"
    tmp = base / "tmp"
    pub = base / "repo.pub"
    bad_pub = base / "repo.bad.pub"
    for path in (web, cache, tmp):
        path.mkdir(parents=True, exist_ok=True)
    return {"repo": repo, "web": web, "cache": cache, "tmp": tmp,
            "pub": pub, "bad_pub": bad_pub,
            "mkrepo": base / "brix_mkrepo", "brixcvmfs": base / "brixcvmfs"}


def _compile_check_binaries(context):
    mkrepo_built = compile_binary(
        context["mkrepo"],
        [
            "-Wall",
            "-I",
            "shared",
            "tests/cvmfs/brix_mkrepo.c",
            "shared/cvmfs/grammar/hash.c",
            "shared/cvmfs/object/object.c",
            "shared/cvmfs/catalog/catalog.c",
            "-lsqlite3",
            "-lcrypto",
            "-lz",
        ],
        cwd=REPO_ROOT,
    )
    if mkrepo_built.returncode != 0:
        return result(False, f"compile brix_mkrepo failed: {_tail(mkrepo_built)}")
    built = _compile_brixcvmfs(context["brixcvmfs"])
    if isinstance(built, str):
        return result(True, built)
    if built.returncode != 0:
        return result(False, f"compile brixcvmfs failed: {_tail(built)}")
    return None


def _start_check_server(web, port):
    return subprocess.Popen(
        ["python3", "-m", "http.server", str(port), "--bind", BIND_HOST],
        cwd=str(web),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def _exercise_check(context, port):
    if not _wait_http(port):
        return result(False, f"python http.server failed to listen on {port}")
    env = {"BRIXCVMFS_SERVER": f"http://{HOST}:{port}/cvmfs/{context['repo']}",
           "BRIXCVMFS_CACHE": str(context["cache"]),
           "BRIXCVMFS_TMP": str(context["tmp"])}
    healthy = _run_check(context, env, context["pub"])
    if healthy.returncode != 0 or "HEALTHY" not in healthy.stdout:
        return result(False, f"healthy brixcvmfs --check failed: {_tail(healthy)}")
    key_error = _generate_wrong_key(context["bad_pub"])
    if key_error:
        return result(False, f"bad-key generation failed: {key_error}")
    rejected = _run_check(context, env, context["bad_pub"])
    if rejected.returncode == 0:
        return result(False, "brixcvmfs --check accepted a wrong public key")
    return result(True, "BRIXCVMFS --check OK; bad key rejected")


def _run_check(context, env, public_key):
    return run(
        [str(context["brixcvmfs"]), "--check", context["repo"]],
        cwd=REPO_ROOT,
        env={**env, "BRIXCVMFS_PUBKEY": str(public_key)},
    )


def _generate_wrong_key(bad_pub):
    genrsa = subprocess.Popen(
        ["openssl", "genrsa"], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=False,
    )
    pubout = subprocess.Popen(
            ["openssl", "rsa", "-pubout", "-out", str(bad_pub)],
            stdin=genrsa.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
    )
    if genrsa.stdout is not None:
        genrsa.stdout.close()
    _, rsa_err = genrsa.communicate()
    _, pub_err = pubout.communicate()
    if genrsa.returncode == 0 and pubout.returncode == 0:
        return ""
    return (rsa_err or pub_err).decode(errors="replace")[-1000:]


def _stop_check_server(server):
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=3)


RUNNERS = {
    "core": core_unit,
    "client": client_unit,
    "walk": walk_unit,
    "xorf": xorf_unit,
    "bundle": bundle_unit,
    "dict": dict_unit,
    "pack": pack_unit,
    "pathidx": pathidx_unit,
    "build": brixcvmfs_build,
    "check": brixcvmfs_check,
}


def run_checks(base: Path, names: Iterable[str] | None = None) -> list[tuple[bool, str]]:
    selected = list(names or RUNNERS)
    results = []
    for name in selected:
        if name not in RUNNERS:
            results.append(result(False, f"unknown CVMFS driver runner: {name}"))
            continue
        work = base / name
        work.mkdir(parents=True, exist_ok=True)
        results.append(RUNNERS[name](work))
    return results


def entry(argv: list[str]) -> int:
    selected = argv or list(RUNNERS)
    with tempfile.TemporaryDirectory(prefix="cvmfs_driver.") as tmp:
        results = run_checks(Path(tmp), selected)
    _print_driver_results(results)
    return 0 if all(ok for ok, _ in results) else 1


def _print_driver_results(results):
    for passed, message in results:
        label = "ok  " if passed else "FAIL"
        print(f"  {label} {message}")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
