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


def config_coverage(root: Path = ROOT) -> tuple[bool, list[str]]:
    tree = sorted(
        str(p.relative_to(root))
        for p in (root / "src").rglob("*.c")
        if not p.name.endswith("_unittest.c")
    )
    config = set(_CONFIG_RE.findall((root / "config").read_text()))
    allow = set(_CONFIG_ALLOWLIST)
    msgs: list[str] = []

    for f in tree:  # forward: unbuilt and not allowlisted
        if f not in config and f not in allow:
            msgs.append(
                f"NOT BUILT: {f} — add it to ./config, or allowlist it with a reason"
            )
    for a in _CONFIG_ALLOWLIST:  # allowlist hygiene
        if not (root / a).is_file():
            msgs.append(f"STALE ALLOWLIST: {a} no longer exists — remove it")
        elif a in config:
            msgs.append(f"STALE ALLOWLIST: {a} is now in ./config — remove it")
    for f in sorted(config):  # reverse: ./config lists a vanished file
        if not (root / f).is_file():
            msgs.append(f"STALE CONFIG: ./config lists {f} but the file does not exist")

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


def http_helper_reimpl(root: Path = ROOT) -> tuple[bool, list[str]]:
    msgs: list[str] = []
    for name, rx in _HTTP_CHECKS:
        for base in _HTTP_SCOPE:
            d = root / base
            if not d.is_dir():
                continue
            for path in sorted(d.rglob("*.c")):
                rel = str(path.relative_to(root))
                for lineno, line in enumerate(_read(path).splitlines(), 1):
                    if not rx.search(line) or _is_comment_line(line):
                        continue
                    if rel in _HTTP_ALLOWLIST:
                        continue
                    msgs.append(
                        f"REIMPLEMENTATION ({name}): {rel}:{lineno}:{line.strip()}"
                        "\n  → use the shared helper in src/core/http/ (or allowlist it)"
                    )
    return (not msgs, msgs)


# ---------------------------------------------------------------------------
# check_metric_cardinality.sh — INVARIANT #8: interpolated metric-label VALUES
# only under a curated low-cardinality label-NAME vocabulary.
# ---------------------------------------------------------------------------
_MC_APPROVED = {
    # ENUM (fixed compile-time value set)
    "proto", "op", "status", "status_class", "method", "direction", "class", "le",
    "auth", "plane", "action", "source", "result", "state", "surface",
    "reason", "staging",
    # CONFIG-N (deployment-bounded named resources)
    "export", "backend", "origin", "upstream", "zone", "repo", "vo",
    "server", "port",
}
_MC_LABEL = re.compile(r'[{,]([a-z_]+)=\\"%')


def metric_cardinality(scan_dir: Path | str | None = None) -> tuple[bool, list[str]]:
    base = Path(scan_dir) if scan_dir is not None else ROOT / "src/observability/metrics"
    msgs: list[str] = []
    if not base.exists():
        return (True, msgs)
    for path in sorted(base.rglob("*.c")):
        for lineno, line in enumerate(_read(path).splitlines(), 1):
            if "metric-cardinality-allow" in line or _is_comment_line(line):
                continue
            names = _MC_LABEL.findall(line)
            if not names:
                continue
            loc = f"{path}:{lineno}"
            for n in names:
                if n not in _MC_APPROVED:
                    msgs.append(
                        f"{loc}: {n} — UNBOUNDED metric label value (INVARIANT #8, "
                        "CWE-770); add to the vocabulary or a per-line "
                        "metric-cardinality-allow marker"
                    )
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


def auth_verdict_sentinel(srcdir: Path | str | None = None) -> tuple[bool, list[str]]:
    base = Path(srcdir) if srcdir is not None else ROOT / "src"
    msgs: list[str] = []
    if not base.exists():
        return (True, msgs)
    for path in sorted(base.rglob("*.c")):
        hits = [
            (n, line.strip())
            for n, line in enumerate(_read(path).splitlines(), 1)
            if _AV_PATTERN.search(line) and not _is_comment_line(line)
        ]
        if not hits:
            continue
        rel = str(path.relative_to(base))
        if rel in _AV_ALLOW:
            continue
        detail = "; ".join(f"{n}: {code}" for n, code in hits)
        msgs.append(
            f"{rel} — 'login.auth_done = 1' set outside the sanctioned auth "
            f"setters (C-3 verdict-sentinel discipline) [{detail}]"
        )
    return (not msgs, msgs)


# ---------------------------------------------------------------------------
# check_todo_fixme.sh — no new / growing TODO|FIXME|XXX|HACK markers vs backlog.
# ---------------------------------------------------------------------------
_TODO_PATTERN = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b")
_TODO_BACKLOG = ROOT / "tools/ci/todo_fixme_backlog.txt"


def _todo_counts(root: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for d in ("src", "client", "shared"):
        base = root / d
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.suffix not in (".c", ".h") or not path.is_file():
                continue
            n = sum(1 for line in _read(path).splitlines() if _TODO_PATTERN.search(line))
            if n:
                counts[str(path.relative_to(root))] = n
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
            msgs.append(f"new TODO/FIXME debt: {path} ({count} marker(s)) — resolve, don't defer")
        elif count > recorded:
            msgs.append(f"added a TODO/FIXME: {path} ({count} > recorded {recorded})")
    return (not msgs, msgs)


# ---------------------------------------------------------------------------
# check_complexity.py + readability.py --gate-csv — CCN 15 ratchet.
# ---------------------------------------------------------------------------
_CCN_BACKLOG = ROOT / "tools/ci/complexity_backlog.txt"


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
        [lizard, "--csv", "-l", "c", "src", "client"],
        cwd=root, capture_output=True, text=True,
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
    if not _CCN_BACKLOG.is_file():
        return (False, [f"backlog missing: {_CCN_BACKLOG}"])
    frozen = _read_backlog(_CCN_BACKLOG)  # key "path::func" -> ccn
    msgs: list[str] = []
    for file, func, ccn in _gate_rows(lizard, root):
        key = f"{file}::{func}"
        recorded = frozen.get(key)
        if recorded is None:
            msgs.append(f"new over-complex function: {key} (CCN {ccn} > {CCN_MAX}) — decompose it")
        elif ccn > recorded:
            msgs.append(f"grew past frozen ceiling: {key} (CCN {ccn} > recorded {recorded})")
    return (not msgs, msgs)
