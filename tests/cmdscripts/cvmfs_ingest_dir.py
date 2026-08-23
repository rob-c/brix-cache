"""Phase-104 D9 — `brixcvmfs ingest dir` (folder → Stratum-0) + `ingest prune`.

Pure-local (no servers): builds a standalone ingesttool (the ingest front-end
+ dir/prune verbs over the phase-96 publish engine; the registry-backed image
verb stays weak/unlinked) plus the phase-96 repotool for mkfs, then verifies
every publish independently in Python (manifest parse, zlib-inflated catalogs
via sqlite3, CAS byte round-trips):

  I1  the demo path: mkfs → ingest a tree under --prefix; files, nested dirs,
      an empty dir and a verbatim symlink all land; synthesized ancestor
      chain; dry-run publishes nothing.
  I2  incremental + mirror: re-ingest updates in place (add-only default
      keeps deleted files); --delete makes the prefix mirror-exact.
  I3  fail-closed negatives: reserved .brix.* grammar in src, bad prefixes,
      prefix colliding with a published file (no_clobber), busy-lock exit 7,
      crash-hook exit 66 with old revision intact + stale-lock self-heal,
      empty prune ledger no-op.
  I4  scale budget: a 10k-file tree publishes inside the lane budget.
"""

from __future__ import annotations

import os
import subprocess
import time
import zlib
from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT, compile_binary
from cmdscripts.cvmfs_publish_txn import (
    FLAG_DIR, FLAG_FILE, FLAG_LINK,
    cas_path, open_catalog, lookup, parse_manifest,
)
from cmdscripts.cvmfs_repo_cli import (
    REPO_CLI_LIBS, REPO_CLI_SOURCES, _build_repotool,
)

def _expression_1(ck, wh):
    return (
        ck("whiteout-refused", wh.returncode == 5 and ".brix.wh" in wh.stderr,
               wh.stderr)
    )

def _expression_2(ck, opq):
    return (
        ck("opaque-refused", opq.returncode == 5 and ".brix.opq" in opq.stderr,
               opq.stderr)
    )

def _expression_3(ck, col):
    return (
        ck("collision-refused", col.returncode == 5
               and "not a directory" in col.stderr, col.stderr)
    )

def _expression_4(ck, heal):
    return (
        ck("stale-lock-heals", heal.returncode == 0
               and "breaking stale lock" in heal.stderr, heal.stderr)
    )

def _expression_5(ck, prune):
    return (
        ck("prune-noop", prune.returncode == 0
               and "nothing to prune" in prune.stdout, prune.stdout)
    )

def _expression_6(ck, dry):
    return (
        ck("dry-run-ok", dry.returncode == 0 and "dry-run:" in dry.stdout,
               dry.stdout + dry.stderr)
    )

def _expression_7(ck, path, row):
    return (
        ck(f"dir{path}", row is not None and row[0] & FLAG_DIR)
    )

def _expression_8(ck, row):
    return (
        ck("file-row", row is not None and row[0] & FLAG_FILE and row[1] == 6)
    )

def _expression_9(ck, row):
    return (
        ck("symlink-verbatim", row is not None and row[0] & FLAG_LINK
               and row[2] == "a.txt", repr(row))
    )


FQRN = "ingest.brix.io"
PREFIX = "/sw/demo/1.0"

INGEST_CLI_SOURCES = REPO_CLI_SOURCES + [
    "client/apps/fs/brixcvmfs_ingest.c",
    "client/apps/fs/brixcvmfs_ingest_prune.c",
    # prune's second pass retires orphaned layer roots, whose ledgers the
    # layout TU owns — a hand-listed source set turns that into a LINK error
    # here rather than a build error, so it has to be listed.
    "client/apps/fs/brixcvmfs_ingest_layout.c",
    # prune re-parses the digest each ingest root is named after rather than
    # trusting its width, so the standalone build needs the OCI grammar too.
    "shared/oci/digest.c",
]


def _build_ingesttool(base: Path) -> tuple[Path | None, str]:
    binary = base / "ingesttool"
    built = compile_binary(
        binary,
        ["-Wall", "-Wextra", "-Werror", "-I", "shared",
         "-DBRIXCVMFS_INGEST_STANDALONE"]
        + INGEST_CLI_SOURCES + REPO_CLI_LIBS,
        cwd=REPO_ROOT,
    )
    if built.returncode != 0:
        return None, (built.stderr or built.stdout)[-2000:]
    return binary, ""


def run_tool(binary: Path, *args: str, env: dict | None = None):
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run([str(binary), *args], capture_output=True,
                          text=True, env=full_env)


def _ingest(tool: Path, src: Path, repo: Path, *extra: str,
            env: dict | None = None):
    return run_tool(tool, "dir", str(src), "--repo", str(repo),
                    "--prefix", PREFIX, *extra, env=env)


def _revision(repo: Path) -> str:
    return parse_manifest(repo)["S"]


def _root_catalog(repo: Path, base: Path):
    return open_catalog(repo, parse_manifest(repo)["C"], base)


# ---- I1: the demo path ------------------------------------------------------

def check_i1(ingest: Path, repotool: Path, base: Path, results: list) -> None:
    ck = lambda name, ok, msg="": results.append(
        (bool(ok), f"i1:{name} {msg}".rstrip()))

    repo, src = base / "i1repo", base / "i1src"
    (src / "sub").mkdir(parents=True)
    (src / "hollow").mkdir()
    (src / "a.txt").write_bytes(b"alpha\n")
    (src / "sub" / "b.bin").write_bytes(os.urandom(1024))
    os.symlink("a.txt", src / "ln")

    ck("mkfs", run_tool(repotool, "mkfs", FQRN, str(repo)).returncode == 0)

    dry = _ingest(ingest, src, repo, "--dry-run")
    _expression_6(ck, dry)
    ck("dry-run-publishes-nothing", _revision(repo) == "1")

    pub = _ingest(ingest, src, repo)
    ck("publish", pub.returncode == 0, pub.stderr)
    ck("rev-2", _revision(repo) == "2")

    cat = _root_catalog(repo, base)
    for path in ("/sw", "/sw/demo", PREFIX, f"{PREFIX}/sub",
                 f"{PREFIX}/hollow"):
        row = lookup(cat, path)
        _expression_7(ck, path, row)
    row = lookup(cat, f"{PREFIX}/a.txt")
    _expression_8(ck, row)
    if row is not None:
        stored = cas_path(repo, row[3].hex()).read_bytes()
        ck("file-bytes", zlib.decompress(stored) == b"alpha\n")
    row = lookup(cat, f"{PREFIX}/ln")
    _expression_9(ck, row)
    cat.close()


# ---- I2: incremental + mirror ----------------------------------------------

def check_i2(ingest: Path, repotool: Path, base: Path, results: list) -> None:
    ck = lambda name, ok, msg="": results.append(
        (bool(ok), f"i2:{name} {msg}".rstrip()))

    repo, src = base / "i2repo", base / "i2src"
    src.mkdir()
    (src / "keep.txt").write_bytes(b"keep-v1\n")
    (src / "gone.txt").write_bytes(b"gone\n")
    run_tool(repotool, "mkfs", FQRN, str(repo))
    ck("seed", _ingest(ingest, src, repo).returncode == 0)

    # add-only default: a file deleted from src stays published
    (src / "keep.txt").write_bytes(b"keep-v2\n")
    (src / "gone.txt").unlink()
    ck("update", _ingest(ingest, src, repo).returncode == 0)
    cat = _root_catalog(repo, base)
    row = lookup(cat, f"{PREFIX}/keep.txt")
    ck("updated-bytes", row is not None and zlib.decompress(
        cas_path(repo, row[3].hex()).read_bytes()) == b"keep-v2\n")
    ck("add-only-keeps-deleted", lookup(cat, f"{PREFIX}/gone.txt") is not None)
    cat.close()

    # --delete: mirror-exact
    ck("mirror", _ingest(ingest, src, repo, "--delete").returncode == 0)
    cat = _root_catalog(repo, base)
    ck("mirror-removed", lookup(cat, f"{PREFIX}/gone.txt") is None)
    ck("mirror-kept", lookup(cat, f"{PREFIX}/keep.txt") is not None)
    cat.close()


# ---- I3: fail-closed negatives ----------------------------------------------

def check_i3(ingest: Path, repotool: Path, base: Path, results: list) -> None:
    ck = lambda name, ok, msg="": results.append(
        (bool(ok), f"i3:{name} {msg}".rstrip()))

    repo, src = base / "i3repo", base / "i3src"
    src.mkdir()
    (src / "ok.txt").write_bytes(b"ok\n")
    run_tool(repotool, "mkfs", FQRN, str(repo))
    ck("seed", _ingest(ingest, src, repo).returncode == 0)
    rev = _revision(repo)

    # reserved overlay grammar in a src tree is refused, never interpreted
    evil = base / "i3evil"
    evil.mkdir()
    (evil / ".brix.wh.x").write_bytes(b"")
    wh = _ingest(ingest, evil, repo)
    _expression_1(ck, wh)
    (evil / ".brix.wh.x").unlink()
    (evil / ".brix.opq").write_bytes(b"")
    opq = _ingest(ingest, evil, repo)
    _expression_2(ck, opq)

    # prefix grammar is validated before any scan
    for bad in ("../escape", "relative", "/sw/../up", "/sw/.brix.evil", "/."):
        r = run_tool(ingest, "dir", str(src), "--repo", str(repo),
                     "--prefix", bad)
        ck(f"prefix-refused:{bad}", r.returncode == 2, r.stderr)

    # a prefix colliding with a published FILE fails the publish (no_clobber)
    col = run_tool(ingest, "dir", str(src), "--repo", str(repo),
                   "--prefix", f"{PREFIX}/ok.txt")
    _expression_3(ck, col)

    # a missing src fails cleanly
    gone = _ingest(ingest, base / "i3nosrc", repo)
    ck("missing-src", gone.returncode == 5, gone.stderr)

    # a live `repo transaction` blocks: --no-wait reports busy (exit 7)
    run_tool(repotool, "transaction", str(repo))
    busy = _ingest(ingest, src, repo, "--no-wait")
    ck("busy-exit-7", busy.returncode == 7, busy.stderr)
    run_tool(repotool, "abort", str(repo))

    # crash hook: _exit(66) pre-swap, old revision intact, and the stale
    # ingest lock (dead holder, no upper tree) self-heals on the next run
    crash = _ingest(ingest, src, repo, env={"BRIXCVMFS_PUBLISH_CRASH": "1"})
    ck("crash-exit-66", crash.returncode == 66, str(crash.returncode))
    ck("crash-rev-intact", _revision(repo) == rev)
    heal = _ingest(ingest, src, repo)
    _expression_4(ck, heal)

    # prune with an empty ledger is a clean no-op
    prune = run_tool(ingest, "prune", "--repo", str(repo))
    _expression_5(ck, prune)


# ---- I4: scale budget --------------------------------------------------------

def check_i4(ingest: Path, repotool: Path, base: Path, results: list) -> None:
    ck = lambda name, ok, msg="": results.append(
        (bool(ok), f"i4:{name} {msg}".rstrip()))

    repo, src = base / "i4repo", base / "i4src"
    payload = b"x" * 64
    for d in range(100):
        sub = src / f"d{d:03d}"
        sub.mkdir(parents=True)
        for f in range(100):
            (sub / f"f{f:03d}").write_bytes(payload + b"%03d%03d" % (d, f))
    run_tool(repotool, "mkfs", FQRN, str(repo))

    t0 = time.monotonic()
    pub = _ingest(ingest, src, repo)
    took = time.monotonic() - t0
    ck("publish-10k", pub.returncode == 0, pub.stderr)
    # Guards the per-object-durability pathology (one fsync per CAS put ran
    # 150 s here); the batched engine measured 39 s on a load-38 host.
    ck("budget", took < 90.0, f"{took:.2f}s")

    cat = _root_catalog(repo, base)
    (n,) = cat.execute("SELECT count(*) FROM catalog").fetchone()
    ck("row-count", n >= 10_000 + 100, str(n))
    cat.close()


def run_checks(base: Path) -> list[tuple[bool, str]]:
    results: list[tuple[bool, str]] = []
    ingest, err = _build_ingesttool(base)
    results.append((ingest is not None, f"ingesttool builds standalone {err}"))
    repotool, err = _build_repotool(base)
    results.append((repotool is not None, f"repotool builds standalone {err}"))
    if ingest is None or repotool is None:
        return results
    check_i1(ingest, repotool, base, results)
    check_i2(ingest, repotool, base, results)
    check_i3(ingest, repotool, base, results)
    check_i4(ingest, repotool, base, results)
    return results
