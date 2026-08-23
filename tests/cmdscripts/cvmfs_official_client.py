"""Phase-96 S9 — official CVMFS client oracle (live, container-gated).

Everything before this lane verifies our published repositories with OUR OWN
read stack — a shared-bug in writer and reader would cancel out. This lane
closes that hole: it publishes a repository with the standalone repotool
(hardlink pair, symlink, .cvmfsdirtab nested catalog, chunked file, xattr),
serves it over loopback HTTP, and has the OFFICIAL cvmfs2 client (the
registry.cern.ch/cvmfs/service container) mount it through the full trust
chain (whitelist signature -> cert fingerprint -> manifest -> catalog) and
walk it. The dump (names, types, sizes, link counts, sha1 of contents,
symlink targets) is compared byte-for-byte against the upper-tree truth.

Ritual: success — official mount + walk matches the published tree exactly
        (chunk reassembly proven by sha1); error/security — a wrong public
        key, a flipped byte in the root catalog object and a flipped byte in
        the whitelist signature must each refuse to mount; after restore the
        mount works again.

Runtime-direct (docker OR rootless podman via cmdscripts.container_runtime,
no fleet server); self-skips without a runtime, /dev/fuse or the image.
"""

from __future__ import annotations

import hashlib
import http.server
import os
import subprocess
import threading
from functools import partial
from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT
from cmdscripts.container_runtime import container_runtime
from cmdscripts.cvmfs_repo_cli import _build_repotool
from cmdscripts.cvmfs_publish_txn import cas_path, parse_manifest, repotool
from settings import HOST

FQRN = "oracle.brix.io"
IMAGE = os.environ.get("BRIX_CVMFS_SERVICE_IMAGE",
                       "registry.cern.ch/cvmfs/service:latest")

BIG = bytes(range(256)) * 40            # 10240 B -> 3 chunks at --chunk-size 4096
FILES = {                               # path-in-repo -> bytes (ground truth)
    "hello.txt": b"hello official world\n",
    "docs/guide.md": b"# guide\n",
    "hl_a.txt": b"hardlinked payload\n",
    "hl_b.txt": b"hardlinked payload\n",
    "nest/one.txt": b"nested one\n",
    "nest/big.bin": BIG,
}
DIRS = {"docs", "nest"}

MOUNT_SH = (
    "set -e\n"
    "mkdir -p /mnt/repo /tmp/cache\n"
    "cvmfs2 -o config=/brix/client.conf " + FQRN + " /mnt/repo"
    " >/tmp/mount.out 2>&1"
    " || { echo MOUNT_FAIL; cat /tmp/mount.out /tmp/cvmfs.log 2>/dev/null;"
    " exit 7; }\n"
)
WALK_SH = MOUNT_SH + (
    "cd /mnt/repo\n"
    "echo ===LIST===\n"
    "find . -mindepth 1 | sort\n"
    "echo ===STAT===\n"
    "find . -mindepth 1 | sort | while read p;"
    " do stat -c '%n|%F|%s|%h' \"$p\"; done\n"
    "echo ===SHA===\n"
    "find . -type f | sort | xargs -r sha1sum\n"
    "echo ===SYM===\n"
    "find . -type l | sort | while read p;"
    " do echo \"$p -> $(readlink \"$p\")\"; done\n"
    "echo ===OK===\n"
)
PROBE_SH = MOUNT_SH + "echo MOUNT_OK\n"


def preflight() -> str | None:
    """Skip reason, or None when the lab can run."""
    rt = container_runtime()
    if rt is None:
        return "no container runtime (docker/podman)"
    if not os.path.exists("/dev/fuse"):
        return "no /dev/fuse on this host"
    if subprocess.run([rt, "image", "inspect", IMAGE],
                      capture_output=True).returncode != 0:
        pull = subprocess.run([rt, "pull", IMAGE], capture_output=True,
                              text=True, timeout=600)
        if pull.returncode != 0:
            return f"cannot pull {IMAGE}: {pull.stderr.strip()[-200:]}"
    return None


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):     # noqa: D102 — silence per-request spam
        pass


def _serve(repo: Path) -> http.server.ThreadingHTTPServer:
    srv = http.server.ThreadingHTTPServer(
        (HOST, 0), partial(_QuietHandler, directory=str(repo)))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _client_run(rt: str, pub: Path, script: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [rt, "run", "--rm", "--network=host", "--device", "/dev/fuse",
         "--cap-add", "SYS_ADMIN", "-v", f"{pub}:/brix:ro",
         "--entrypoint", "/bin/sh", IMAGE, "-c", script],
        capture_output=True, text=True, timeout=300)


def _sections(out: str) -> dict[str, list[str]]:
    sec, cur = {}, None
    for line in out.splitlines():
        if line.startswith("===") and line.endswith("==="):
            cur = line.strip("=")
            sec[cur] = []
        elif cur is not None:
            sec[cur].append(line)
    return sec


def _populate(repo: Path, binary: Path):
    """Open a transaction, lay down the ground-truth tree, publish."""
    up = repo / ".brixtxn" / "upper"
    (up / "docs").mkdir(parents=True)
    (up / "nest").mkdir()
    for rel, body in FILES.items():
        if rel == "hl_b.txt":
            os.link(up / "hl_a.txt", up / rel)   # true hardlink, not a copy
        else:
            (up / rel).write_bytes(body)
    os.symlink("hello.txt", up / "ln")
    try:                                          # xattr: fs-dependent, optional
        os.setxattr(up / "hello.txt", "user.color", b"red")
        xattr_ok = True
    except OSError:
        xattr_ok = False
    dirtab = repo.parent / "dirtab"
    dirtab.write_text("/nest\n")
    pub = repotool(binary, "publish", str(repo), "--dirtab", str(dirtab),
                   "--chunk-size", "4096")
    return pub, xattr_ok


def _check_walk(out: str, xattr_ok: bool, ck) -> None:
    sec = _sections(out)
    _check_listing(sec, ck)
    _check_stats(sec, ck)
    _check_hashes(sec, ck)
    ck("symlink", sec.get("SYM") == ["./ln -> hello.txt"],
       str(sec.get("SYM")))
    _check_xattrs(sec, xattr_ok, ck)


def _check_listing(sections, ck):
    expect_list = sorted(f"./{p}" for p in set(FILES) | DIRS | {"ln"})
    ck("walk-list", sections.get("LIST") == expect_list,
       str(sections.get("LIST"))[:400])


def _check_stats(sections, ck):
    stats = {}
    for line in sections.get("STAT", []):
        name, ftype, size, links = line.split("|")
        stats[name] = (ftype, int(size), int(links))
    ck("stat-sizes", _sizes_match(stats), str(stats)[:400])
    ck("stat-dirs", _directories_match(stats))
    ck("stat-hardlinks", _hardlinks_match(stats),
       str({k: v for k, v in stats.items() if k.startswith("./hl")}))


def _sizes_match(stats):
    return all(stats.get(f"./{path}", ("", -1, 0))[1] == len(body)
               for path, body in FILES.items())


def _directories_match(stats):
    return all(stats.get(f"./{directory}", ("",))[0] == "directory"
               for directory in DIRS)


def _hardlinks_match(stats):
    if stats.get("./hl_a.txt", ("", 0, 0))[2] != 2:
        return False
    return stats.get("./hl_b.txt", ("", 0, 0))[2] == 2


def _check_hashes(sections, ck):
    shas = {}
    for line in sections.get("SHA", []):
        digest, _, name = line.partition("  ")
        shas[name.strip()] = digest
    ck("sha-contents", all(shas.get(f"./{p}") == hashlib.sha1(b).hexdigest()
                           for p, b in FILES.items()), str(shas)[:400])
    ck("chunk-reassembly", shas.get("./nest/big.bin")
       == hashlib.sha1(BIG).hexdigest())


def _check_xattrs(sections, xattr_ok, ck):
    if not xattr_ok:
        return
    values = sections.get("XATTR")
    if not values or "no-getfattr" in values[0]:
        return
    ck("xattr", any('user.color="red"' in line for line in values),
       str(values)[:200])


def _flip_byte(path: Path, offset: int) -> bytes:
    """Flip one byte at offset (negative = from end); returns the original."""
    orig = path.read_bytes()
    idx = offset if offset >= 0 else len(orig) + offset
    path.write_bytes(orig[:idx] + bytes([orig[idx] ^ 0xFF]) + orig[idx + 1:])
    return orig


def _record(results, name, passed, message=""):
    results.append((bool(passed), f"s9:{name} {message}".rstrip()))


def _publish_repo(base, results):
    binary, error = _build_repotool(base)
    _record(results, "build", binary is not None, error)
    if binary is None:
        return None
    repo = base / "repo"
    _initialize_repo(binary, repo, results)
    return _publish_transaction(binary, repo, results)


def _initialize_repo(binary, repo, results):
    created = repotool(binary, "mkfs", FQRN, str(repo))
    _record(results, "mkfs", created.returncode == 0)
    transaction = repotool(binary, "transaction", str(repo))
    _record(results, "txn", transaction.returncode == 0)


def _publish_transaction(binary, repo, results):
    published, xattr_ok = _populate(repo, binary)
    _record(results, "publish", published.returncode == 0, published.stderr)
    if published.returncode != 0:
        return None
    return binary, repo, xattr_ok


def _client_directory(base, repo, server_port):
    public = base / "pub"
    public.mkdir()
    trusted_key = repo / "keys" / f"{FQRN}.pub"
    (public / f"{FQRN}.pub").write_bytes(trusted_key.read_bytes())
    config = (f"CVMFS_SERVER_URL=http://{HOST}:{server_port}\n"
              "CVMFS_HTTP_PROXY=DIRECT\n"
              f"CVMFS_PUBLIC_KEY=/brix/{FQRN}.pub\n"
              "CVMFS_CACHE_BASE=/tmp/cache\n"
              "CVMFS_RELOAD_SOCKETS=/tmp/cache\n"
              "CVMFS_USYSLOG=/tmp/cvmfs.log\n")
    (public / "client.conf").write_text(config)
    return public


def _official_walk(runtime, public, xattr_ok, results):
    walk = _client_run(runtime, public, WALK_SH)
    mounted = walk.returncode == 0 and "===OK===" in walk.stdout
    _record(results, "official-mount", mounted,
            (walk.stdout + walk.stderr)[-500:])
    if walk.returncode == 0:
        _check_walk(
            walk.stdout, xattr_ok,
            lambda name, passed, message="": _record(
                results, name, passed, message
            ),
        )


def _probe_refused(result):
    if result.returncode == 0:
        return False
    return "MOUNT_FAIL" in result.stdout


def _wrong_key_check(base, runtime, public, repo, binary, results):
    decoy = base / "decoy"
    created = repotool(binary, "mkfs", "decoy.brix.io", str(decoy))
    _record(results, "decoy-mkfs", created.returncode == 0)
    key_path = public / f"{FQRN}.pub"
    key_path.write_bytes((decoy / "keys" / "decoy.brix.io.pub").read_bytes())
    wrong = _client_run(runtime, public, PROBE_SH)
    _record(results, "wrong-key-refused", _probe_refused(wrong),
            wrong.stdout[-300:])
    key_path.write_bytes((repo / "keys" / f"{FQRN}.pub").read_bytes())


def _tamper_check(runtime, public, path, offset, name, results):
    original = _flip_byte(path, offset)
    try:
        probe = _client_run(runtime, public, PROBE_SH)
        _record(results, name, _probe_refused(probe), probe.stdout[-300:])
    finally:
        path.write_bytes(original)


def _restored_mount_check(runtime, public, results):
    restored = _client_run(runtime, public, PROBE_SH)
    passed = restored.returncode == 0 and "MOUNT_OK" in restored.stdout
    _record(results, "restored-mounts", passed,
            (restored.stdout + restored.stderr)[-300:])


def _security_checks(base, runtime, public, repo, binary, results):
    _wrong_key_check(base, runtime, public, repo, binary, results)
    manifest = parse_manifest(repo)
    catalog = cas_path(repo, manifest["C"], "C")
    _tamper_check(runtime, public, catalog, len(catalog.read_bytes()) // 2,
                  "catalog-tamper-refused", results)
    _tamper_check(runtime, public, repo / ".cvmfswhitelist", -16,
                  "whitelist-tamper-refused", results)
    _restored_mount_check(runtime, public, results)


def run_checks(base: Path) -> list:
    results: list = []

    rt = container_runtime()
    published = _publish_repo(base, results)
    if published is None:
        return results
    binary, repo, xattr_ok = published
    server = _serve(repo)
    public = _client_directory(base, repo, server.server_address[1])
    try:
        _official_walk(rt, public, xattr_ok, results)
        _security_checks(base, rt, public, repo, binary, results)
    finally:
        server.shutdown()
    return results


if __name__ == "__main__":
    reason = preflight()
    if reason:
        print(f"SKIP: {reason}")
        raise SystemExit(0)
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        res = run_checks(Path(td))
        for ok, msg in res:
            print(("ok  " if ok else "FAIL"), msg)
        raise SystemExit(0 if all(ok for ok, _ in res) else 1)
