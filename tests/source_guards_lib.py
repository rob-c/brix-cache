"""Pure-Python ports of the tools/ci/*.sh source-tree guards.

The test-suite must not shell out to bash. Each function below reimplements one
tools/ci guard's verdict in Python and returns ``(ok, messages)`` — ``ok`` False
with human-readable ``messages`` on violation, mirroring the shell script's
stderr. The shell scripts remain the CI / pre-push copies (guards.yml); these
ports keep the identical red/green inside pytest (tests/test_source_guards.py).

Guards ported:
  config_coverage        <- check_config_coverage.sh
  http_helper_reimpl     <- check_http_helper_reimpl.sh
  metric_cardinality     <- check_metric_cardinality.sh   (scan dir overridable)
  auth_verdict_sentinel  <- check_auth_verdict_sentinel.sh (scan dir overridable)
  todo_fixme             <- check_todo_fixme.sh
  complexity             <- check_complexity.py (+ readability.py --gate-csv)
"""

from __future__ import annotations

import csv
import io
import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# McCabe cap — kept in lockstep with tools/readability.py CCN_MAX.
CCN_MAX = 15


def _read(path: Path) -> str:
    """Byte-tolerant read (grep is byte-based; .c/.h may carry stray bytes)."""
    return path.read_text(errors="ignore")


def _is_comment_line(code: str) -> bool:
    """True when a source line is a comment continuation (``*``) or a ``//``/
    ``/*`` line — the same drop the shell guards do with a leading-``\\s*``
    comment-marker regex."""
    s = code.lstrip()
    return s.startswith(("*", "//", "/*"))


# ---------------------------------------------------------------------------
# check_config_coverage.sh — every src/ .c is built via ./config, allowlisted,
# or a *_unittest.c; no stale ./config entry; no stale allowlist row.
# ---------------------------------------------------------------------------
_CONFIG_ALLOWLIST = (
    "src/core/compat/kxr_names.c",
    "src/fs/cache/noop.c",
    "src/fs/scan/scan_drift.c",
    "src/net/guard/guard_test.c",
    "src/observability/dashboard/noop.c",
    "src/tpc/engine/noop.c",
)
_CONFIG_RE = re.compile(r"\$ngx_addon_dir/(src/[A-Za-z0-9_/.-]*\.c)")


def _config_tree(root: Path) -> list[str]:
    return sorted(
        str(p.relative_to(root))
        for p in (root / "src").rglob("*.c")
        # Exclude standalone-built unit tests, including the per-group TUs a large
        # `*_unittest.c` is split into (e.g. `sd_pblock_unittest_core.c`).
        if not (p.name.endswith("_unittest.c") or "_unittest_" in p.name)
    )


def _config_unbuilt(tree: list[str], config: set[str], allow: set[str]) -> list[str]:
    return [
        f"NOT BUILT: {path} — add it to ./config, or allowlist it with a reason"
        for path in tree
        if path not in config and path not in allow
    ]


def _config_allowlist_messages(root: Path, config: set[str]) -> list[str]:
    messages = []
    for path in _CONFIG_ALLOWLIST:
        if not (root / path).is_file():
            messages.append(f"STALE ALLOWLIST: {path} no longer exists — remove it")
        elif path in config:
            messages.append(f"STALE ALLOWLIST: {path} is now in ./config — remove it")
    return messages


def _stale_config_messages(root: Path, config: set[str]) -> list[str]:
    return [
        f"STALE CONFIG: ./config lists {path} but the file does not exist"
        for path in sorted(config)
        if not (root / path).is_file()
    ]


def config_coverage(root: Path = ROOT) -> tuple[bool, list[str]]:
    tree = _config_tree(root)
    config = set(_CONFIG_RE.findall((root / "config").read_text()))
    msgs = _config_unbuilt(tree, config, set(_CONFIG_ALLOWLIST))
    msgs.extend(_config_allowlist_messages(root, config))
    msgs.extend(_stale_config_messages(root, config))

    return (not msgs, msgs)


# ---------------------------------------------------------------------------
# check_client_build_coverage.py — every client/ and shared/{cvmfs,cache} .c is
# named by client/Makefile, or is a standalone-built driver, or is allowlisted.
# ---------------------------------------------------------------------------
_CLIENT_SCAN = ("client", "shared/cvmfs", "shared/cache")
_CLIENT_ALLOWLIST: tuple[str, ...] = ()
_CLIENT_EXCUSED_DIRS = ("client/tests/", "client/examples/", "client/bin/")


def _client_tree(root: Path) -> list[str]:
    out = []
    for top in _CLIENT_SCAN:
        for p in (root / top).rglob("*.c"):
            rel = str(p.relative_to(root))
            if (
                p.name.endswith("_unittest.c")
                or "_unittest_" in p.name
                or p.name.endswith("_unit.c")
                or rel.startswith(_CLIENT_EXCUSED_DIRS)
            ):
                continue
            out.append(rel)
    return sorted(out)


def _owner_includes(root: Path, owner: Path) -> set[str]:
    included = set()
    names = re.findall(
        r'^\s*#\s*include\s+"([^"]+\.c)"',
        owner.read_text(errors="replace"),
        re.MULTILINE,
    )
    for name in names:
        target = (owner.parent / name).resolve()
        try:
            included.add(str(target.relative_to(root.resolve())))
        except ValueError:
            continue
    return included


def _included_client_sources(root: Path) -> set[str]:
    included = set()
    for top in _CLIENT_SCAN:
        for owner in (root / top).rglob("*.c"):
            included |= _owner_includes(root, owner)
    return included


def _client_object_stem(relative: str) -> str:
    stem = relative[: -len(".c")]
    for prefix in ("client/", "shared/"):
        if stem.startswith(prefix):
            return stem[len(prefix) :]
    return stem


def _named_in_makefile(relative: str, makefile: str) -> bool:
    stem = _client_object_stem(relative)
    return any(f"{stem}{extension}" in makefile for extension in (".c", ".o", ".pic.o"))


def _unbuilt_client_sources(
    root: Path, makefile: str, allow: set[str], included: set[str]
) -> list[str]:
    messages = []
    for relative in _client_tree(root):
        known = (
            relative in allow
            or relative in included
            or _named_in_makefile(relative, makefile)
        )
        if not known:
            messages.append(
                f"NOT BUILT: {relative} — add it to client/Makefile, or "
                f"allowlist it here with a reason"
            )
    return messages


def _stale_client_allowlist(root: Path) -> list[str]:
    return [
        f"STALE ALLOWLIST: {path} no longer exists — remove it"
        for path in _CLIENT_ALLOWLIST
        if not (root / path).is_file()
    ]


def client_build_coverage(root: Path = ROOT) -> tuple[bool, list[str]]:
    makefile = (root / "client/Makefile").read_text()
    allow = set(_CLIENT_ALLOWLIST)
    included = _included_client_sources(root)
    msgs = _unbuilt_client_sources(root, makefile, allow, included)
    msgs.extend(_stale_client_allowlist(root))

    return (not msgs, msgs)


# ---------------------------------------------------------------------------
# check_http_helper_reimpl.sh — protocols must not regrow private copies of the
# shared HTTP helpers (raw header scan / precondition logic / hand-rolled ETag).
# ---------------------------------------------------------------------------
_HTTP_SCOPE = (
    "src/protocols",
    "src/observability",
    "src/net/ratelimit",
    "src/net/mirror",
    "src/net/httpguard",
    "src/fs/scan",
)
_HTTP_ALLOWLIST = {
    "src/protocols/s3/conditional.c",
    "src/protocols/webdav/proxy_request.c",
    "src/protocols/webdav/xrdhttp_filter.c",
    "src/protocols/webdav/tpc_headers.c",
    "src/protocols/s3/usermeta.c",
    "src/net/mirror/http_mirror.c",
    "src/protocols/oci/oci_mirror.c",
}
_HTTP_CHECKS = (
    ("raw header scan", re.compile(r"&r->headers_in\.headers\.part")),
    (
        "precondition logic",
        re.compile(
            r"headers_in\.(if_match|if_none_match|if_modified_since|if_unmodified_since)"
        ),
    ),
    ("hand-rolled etag", re.compile(r'"\\?"?%l?lx-%l?lx')),
)


def _http_matches(path: Path, pattern) -> list[tuple[int, str]]:
    return [
        (line_number, line)
        for line_number, line in enumerate(_read(path).splitlines(), 1)
        if pattern.search(line) and not _is_comment_line(line)
    ]


def _http_file_messages(root: Path, path: Path, name: str, pattern) -> list[str]:
    relative = str(path.relative_to(root))
    if relative in _HTTP_ALLOWLIST:
        return []
    return [
        f"REIMPLEMENTATION ({name}): {relative}:{line_number}:"
        f"{line.strip()}\n  → use the shared helper in src/core/http/ "
        f"(or allowlist it)"
        for line_number, line in _http_matches(path, pattern)
    ]


def _http_check_messages(root: Path, name: str, pattern) -> list[str]:
    messages = []
    for relative in _HTTP_SCOPE:
        directory = root / relative
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*.c")):
            messages.extend(_http_file_messages(root, path, name, pattern))
    return messages


def http_helper_reimpl(root: Path = ROOT) -> tuple[bool, list[str]]:
    msgs: list[str] = []
    for name, pattern in _HTTP_CHECKS:
        msgs.extend(_http_check_messages(root, name, pattern))
    return (not msgs, msgs)


# ---------------------------------------------------------------------------
# check_metric_cardinality.sh — INVARIANT #8: interpolated metric-label VALUES
# only under a curated low-cardinality label-NAME vocabulary.
# ---------------------------------------------------------------------------
_MC_APPROVED = {
    # ENUM (fixed compile-time value set)
    "proto",
    "op",
    "status",
    "status_class",
    "method",
    "direction",
    "class",
    "le",
    "auth",
    "plane",
    "action",
    "source",
    "result",
    "state",
    "surface",
    "reason",
    "staging",
    # ENUM: cred-deleg gate — 6 fixed modes × 3 fixed outcomes (unified.c name
    # tables).  Kept in lock-step with tools/ci/check_metric_cardinality.py.
    "mode",
    "outcome",
    # ENUM: publish precondition and registered storage-driver vocabularies.
    "kind",
    "driver",
    # ENUM: storage domain (BRIX_VFS_DOMAIN_METRIC_COUNT fixed domains,
    # brix_metric_vfs_domain_name table — phase-108 C11).
    "domain",
    # CONFIG-N (deployment-bounded named resources)
    "export",
    "backend",
    "origin",
    "upstream",
    "zone",
    "repo",
    "vo",
    "server",
    "port",
}
_MC_LABEL = re.compile(r'[{,]([a-z_]+)=\\"%')


def _metric_names(line: str) -> list[str]:
    if "metric-cardinality-allow" in line or _is_comment_line(line):
        return []
    return _MC_LABEL.findall(line)


def _metric_line_messages(path: Path, line_number: int, line: str) -> list[str]:
    location = f"{path}:{line_number}"
    return [
        f"{location}: {name} — UNBOUNDED metric label value "
        f"(INVARIANT #8, CWE-770); add to the vocabulary or a per-line "
        f"metric-cardinality-allow marker"
        for name in _metric_names(line)
        if name not in _MC_APPROVED
    ]


def _metric_file_messages(path: Path) -> list[str]:
    messages = []
    for line_number, line in enumerate(_read(path).splitlines(), 1):
        messages.extend(_metric_line_messages(path, line_number, line))
    return messages


def metric_cardinality(scan_dir: Path | str | None = None) -> tuple[bool, list[str]]:
    base = (
        Path(scan_dir) if scan_dir is not None else ROOT / "src/observability/metrics"
    )
    msgs: list[str] = []
    if not base.exists():
        return (True, msgs)
    for path in sorted(base.rglob("*.c")):
        msgs.extend(_metric_file_messages(path))
    return (not msgs, msgs)


# ---------------------------------------------------------------------------
# check_auth_verdict_sentinel.sh — C-3: `login.auth_done = 1` may be raised only
# by a sanctioned credential handler / session login-bind path.
# ---------------------------------------------------------------------------
_AV_ALLOW = {
    "auth/gsi/auth.c",
    "auth/gsi/token.c",
    "auth/host/auth.c",
    "auth/krb5/auth.c",
    "auth/pwd/auth.c",
    "auth/sss/auth_request.c",
    "auth/unix/auth.c",
    "protocols/root/session/login.c",
    "protocols/root/session/bind.c",
}
_AV_PATTERN = re.compile(r"login\.auth_done\s*=\s*1\s*;")


def _auth_verdict_hits(path: Path) -> list[tuple[int, str]]:
    return [
        (number, line.strip())
        for number, line in enumerate(_read(path).splitlines(), 1)
        if _AV_PATTERN.search(line) and not _is_comment_line(line)
    ]


def _auth_verdict_message(base: Path, path: Path) -> str | None:
    hits = _auth_verdict_hits(path)
    relative = str(path.relative_to(base))
    if not hits or relative in _AV_ALLOW:
        return None
    detail = "; ".join(f"{number}: {code}" for number, code in hits)
    return (
        f"{relative} — 'login.auth_done = 1' set outside the sanctioned "
        f"auth setters (C-3 verdict-sentinel discipline) [{detail}]"
    )


def auth_verdict_sentinel(srcdir: Path | str | None = None) -> tuple[bool, list[str]]:
    base = Path(srcdir) if srcdir is not None else ROOT / "src"
    msgs: list[str] = []
    if not base.exists():
        return (True, msgs)
    for path in sorted(base.rglob("*.c")):
        message = _auth_verdict_message(base, path)
        if message is not None:
            msgs.append(message)
    return (not msgs, msgs)


# ---------------------------------------------------------------------------
# check_todo_fixme.sh — no new / growing TODO|FIXME|XXX|HACK markers vs backlog.
# ---------------------------------------------------------------------------
_TODO_PATTERN = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b")
_TODO_BACKLOG = ROOT / "tools/ci/todo_fixme_backlog.txt"


def _todo_directory_counts(root: Path, directory: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    base = root / directory
    if not base.is_dir():
        return counts
    for path in base.rglob("*"):
        if path.suffix not in (".c", ".h") or not path.is_file():
            continue
        count = sum(
            1 for line in _read(path).splitlines() if _TODO_PATTERN.search(line)
        )
        if count:
            counts[str(path.relative_to(root))] = count
    return counts


def _todo_counts(root: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for directory in ("src", "client", "shared"):
        counts.update(_todo_directory_counts(root, directory))
    return counts


def _read_backlog(path: Path) -> dict[str, int]:
    frozen: dict[str, int] = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        p, _, c = line.partition("\t")
        frozen[p] = int(c)
    return frozen


def todo_fixme(root: Path = ROOT) -> tuple[bool, list[str]]:
    if not _TODO_BACKLOG.is_file():
        return (False, [f"backlog missing: {_TODO_BACKLOG}"])
    frozen = _read_backlog(_TODO_BACKLOG)
    msgs: list[str] = []
    for path, count in sorted(_todo_counts(root).items()):
        recorded = frozen.get(path)
        if recorded is None:
            msgs.append(
                f"new TODO/FIXME debt: {path} ({count} marker(s)) — resolve, don't defer"
            )
        elif count > recorded:
            msgs.append(f"added a TODO/FIXME: {path} ({count} > recorded {recorded})")
    return (not msgs, msgs)


# ---------------------------------------------------------------------------
# check_complexity.py + readability.py --gate-csv — absolute CCN 15 cap.
# ---------------------------------------------------------------------------


def find_lizard() -> str | None:
    """Mirror readability.find_lizard: lizard on PATH or ~/.local/bin/lizard."""
    for c in ("lizard", os.path.expanduser("~/.local/bin/lizard")):
        if shutil.which(c) or os.path.exists(c):
            return c
    return None


def lizard_available() -> bool:
    return find_lizard() is not None


def _gate_rows(lizard: str, root: Path) -> list[tuple[str, str, int]]:
    """Replicate readability.py --gate-csv: (file, func, ccn) for funcs over the
    CCN cap. lizard --csv columns: nloc,ccn,token,param,length,location,file,name,…"""
    out = subprocess.run(
        [lizard, "--csv", "-l", "c", "src", "client", "shared"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    rows: list[tuple[str, str, int]] = []
    for row in csv.reader(io.StringIO(out)):
        if len(row) < 8:
            continue
        try:
            ccn = int(row[1])
        except ValueError:  # header / malformed row — skip like readability.py
            continue
        if ccn > CCN_MAX:
            rows.append((row[6], row[7], ccn))
    return sorted(rows, key=lambda r: (r[0], r[1], -r[2]))


def complexity(root: Path = ROOT) -> tuple[bool, list[str]]:
    lizard = find_lizard()
    if lizard is None:
        raise RuntimeError("lizard not found. Install: pip install --user lizard")
    msgs = [
        f"over-complex function: {file}::{func} (CCN {ccn} > {CCN_MAX}) — decompose it"
        for file, func, ccn in _gate_rows(lizard, root)
    ]
    return (not msgs, msgs)
