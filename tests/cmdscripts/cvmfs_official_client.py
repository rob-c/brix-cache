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
    expect_list = sorted(f"./{p}" for p in set(FILES) | DIRS | {"ln"})
    ck("walk-list", sec.get("LIST") == expect_list,
       str(sec.get("LIST"))[:400])

    stats = {}
    for line in sec.get("STAT", []):
        name, ftype, size, links = line.split("|")
        stats[name] = (ftype, int(size), int(links))
    ck("stat-sizes", all(stats.get(f"./{p}", ("", -1, 0))[1] == len(b)
                         for p, b in FILES.items()), str(stats)[:400])
    ck("stat-dirs", all(stats.get(f"./{d}", ("",))[0] == "directory"
                        for d in DIRS))
    ck("stat-hardlinks", stats.get("./hl_a.txt", ("", 0, 0))[2] == 2
       and stats.get("./hl_b.txt", ("", 0, 0))[2] == 2,
       str({k: v for k, v in stats.items() if k.startswith("./hl")}))

    shas = {}
    for line in sec.get("SHA", []):
        digest, _, name = line.partition("  ")
        shas[name.strip()] = digest
    ck("sha-contents", all(shas.get(f"./{p}") == hashlib.sha1(b).hexdigest()
                           for p, b in FILES.items()), str(shas)[:400])
    ck("chunk-reassembly", shas.get("./nest/big.bin")
       == hashlib.sha1(BIG).hexdigest())
    ck("symlink", sec.get("SYM") == ["./ln -> hello.txt"], str(sec.get("SYM")))
    if xattr_ok and sec.get("XATTR") and "no-getfattr" not in sec["XATTR"][0]:
        ck("xattr", any('user.color="red"' in l for l in sec["XATTR"]),
           str(sec["XATTR"])[:200])


def _flip_byte(path: Path, offset: int) -> bytes:
    """Flip one byte at offset (negative = from end); returns the original."""
    orig = path.read_bytes()
    idx = offset if offset >= 0 else len(orig) + offset
    path.write_bytes(orig[:idx] + bytes([orig[idx] ^ 0xFF]) + orig[idx + 1:])
    return orig


def run_checks(base: Path) -> list:
    results: list = []
    ck = lambda name, ok, msg="": results.append(
        (bool(ok), f"s9:{name} {msg}".rstrip()))

    rt = container_runtime()
    binary, err = _build_repotool(base)
    ck("build", binary is not None, err)
    if binary is None:
        return results

    repo = base / "repo"
    ck("mkfs", repotool(binary, "mkfs", FQRN, str(repo)).returncode == 0)
    ck("txn", repotool(binary, "transaction", str(repo)).returncode == 0)
    pub, xattr_ok = _populate(repo, binary)
    ck("publish", pub.returncode == 0, pub.stderr)
    if pub.returncode != 0:
        return results

    srv = _serve(repo)
    pubdir = base / "pub"
    pubdir.mkdir()
    (pubdir / f"{FQRN}.pub").write_bytes(
        (repo / "keys" / f"{FQRN}.pub").read_bytes())
    conf = (f"CVMFS_SERVER_URL=http://{HOST}:{srv.server_address[1]}\n"
            "CVMFS_HTTP_PROXY=DIRECT\n"
            f"CVMFS_PUBLIC_KEY=/brix/{FQRN}.pub\n"
            "CVMFS_CACHE_BASE=/tmp/cache\n"
            "CVMFS_RELOAD_SOCKETS=/tmp/cache\n"
            "CVMFS_USYSLOG=/tmp/cvmfs.log\n")
    (pubdir / "client.conf").write_text(conf)
    try:
        walk = _client_run(rt, pubdir, WALK_SH)
        ck("official-mount", walk.returncode == 0 and "===OK===" in walk.stdout,
           (walk.stdout + walk.stderr)[-500:])
        if walk.returncode == 0:
            _check_walk(walk.stdout, xattr_ok, ck)

        # security 1: a mismatched public key must break the trust chain
        decoy = base / "decoy"
        ck("decoy-mkfs",
           repotool(binary, "mkfs", "decoy.brix.io", str(decoy)).returncode == 0)
        (pubdir / f"{FQRN}.pub").write_bytes(
            (decoy / "keys" / "decoy.brix.io.pub").read_bytes())
        wrong = _client_run(rt, pubdir, PROBE_SH)
        ck("wrong-key-refused",
           wrong.returncode != 0 and "MOUNT_FAIL" in wrong.stdout,
           wrong.stdout[-300:])
        (pubdir / f"{FQRN}.pub").write_bytes(
            (repo / "keys" / f"{FQRN}.pub").read_bytes())

        # security 2: one flipped byte in the root catalog object
        man = parse_manifest(repo)
        cat_obj = cas_path(repo, man["C"], "C")
        orig = _flip_byte(cat_obj, len(cat_obj.read_bytes()) // 2)
        bad = _client_run(rt, pubdir, PROBE_SH)
        ck("catalog-tamper-refused",
           bad.returncode != 0 and "MOUNT_FAIL" in bad.stdout, bad.stdout[-300:])
        cat_obj.write_bytes(orig)

        # security 3: one flipped byte in the whitelist signature
        wl = repo / ".cvmfswhitelist"
        orig = _flip_byte(wl, -16)
        bad = _client_run(rt, pubdir, PROBE_SH)
        ck("whitelist-tamper-refused",
           bad.returncode != 0 and "MOUNT_FAIL" in bad.stdout, bad.stdout[-300:])
        wl.write_bytes(orig)

        good = _client_run(rt, pubdir, PROBE_SH)
        ck("restored-mounts", good.returncode == 0 and "MOUNT_OK" in good.stdout,
           (good.stdout + good.stderr)[-300:])
    finally:
        srv.shutdown()
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
