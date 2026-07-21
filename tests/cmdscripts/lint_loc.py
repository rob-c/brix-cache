"""Logical-LoC lint and ratchet checks."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re

from cmdscripts.compile_run import REPO_ROOT, run

HARD = 800
BASELINE = REPO_ROOT / "tests" / "loc_baseline.txt"
COMMENT_RE = re.compile(r"^\s*$|^\s*//|^\s*/?\*")


def in_scope() -> list[Path]:
    patterns = [
        "src/*.c",
        "src/*.h",
        "client/*.c",
        "client/*.h",
        "tests/*.sh",
        "k8s-tests/*.sh",
        "utils/*.sh",
        "tests/*.py",
        "utils/*.py",
    ]
    proc = run(["git", "-C", str(REPO_ROOT), "ls-files", *patterns], cwd=REPO_ROOT)
    if proc.returncode == 0:
        lines = proc.stdout.splitlines()
    elif "not a git repository" in (proc.stderr or proc.stdout):
        # Synced checkout without .git (the unprivileged runner's rsync copy):
        # walk the tree with the same pathspecs (git's * matches across slashes).
        lines = []
        for pattern in patterns:
            top, glob = pattern.split("/", 1)
            for p in (REPO_ROOT / top).rglob(glob):
                lines.append(str(p.relative_to(REPO_ROOT)))
    else:
        raise RuntimeError(proc.stderr or proc.stdout)
    paths = []
    for line in sorted(set(lines)):
        if line.startswith("shared/xrdproto/"):
            continue
        path = REPO_ROOT / line
        if path.is_file():
            paths.append(path)
    return paths


def is_exempt(path: Path) -> bool:
    head = path.read_text(encoding="utf-8", errors="ignore").splitlines()[:40]
    return any("loc-lint:" in line and "exempt" in line for line in head)


def logical_loc(path: Path) -> int:
    return sum(1 for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if not COMMENT_RE.search(line))


def measurements() -> list[tuple[int, str]]:
    items = []
    for path in in_scope():
        if is_exempt(path):
            continue
        items.append((logical_loc(path), str(path.relative_to(REPO_ROOT))))
    return sorted(items, reverse=True)


def read_baseline() -> dict[str, int]:
    if not BASELINE.is_file():
        return {}
    out: dict[str, int] = {}
    for line in BASELINE.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) == 2:
            out[parts[0]] = int(parts[1])
    return out


def render_report(items: list[tuple[int, str]]) -> str:
    counts: Counter[str] = Counter()
    lines = ["== file-size tiers (logical LoC) =="]
    for loc, path in items:
        tier = "ideal" if loc <= 500 else "watch" if loc <= 650 else "should" if loc <= 800 else "must"
        counts[tier] += 1
        if tier in {"should", "must"}:
            lines.append(f"  {tier.upper():<6} {loc:5d}  {path}")
    total = sum(counts.values())
    lines.append("")
    lines.append(
        f"  total={total}  ideal={counts['ideal']} watch={counts['watch']} "
        f"should={counts['should']} must={counts['must']}"
    )
    return "\n".join(lines)


def run_checks(mode: str = "report") -> tuple[int, str]:
    if mode not in {"report", "strict", "baseline"}:
        return 2, "usage: lint_loc.py [--report|--strict|--baseline]"
    items = measurements()
    if mode == "baseline":
        offenders = [f"{path}\t{loc}" for loc, path in items if loc > HARD]
        BASELINE.write_text("\n".join(offenders) + ("\n" if offenders else ""), encoding="utf-8")
        return 0, f"wrote {len(offenders)} baselined offender(s) to tests/loc_baseline.txt"
    report = render_report(items)
    if mode == "report":
        return 0, report
    baseline = read_baseline()
    failures = []
    for loc, path in items:
        recorded = baseline.get(path)
        if recorded is None and loc > HARD:
            failures.append(f"NEW over-threshold: {path} ({loc} > {HARD})")
        elif recorded is not None and loc > recorded:
            failures.append(f"baselined file grew: {path} ({loc} > recorded {recorded})")
    status = "lint_loc: ratchet OK" if not failures else "lint_loc: ratchet FAILED"
    return (1 if failures else 0), "\n".join([report, *failures, status])


def entry(argv: list[str]) -> int:
    mode = "report"
    if argv:
        arg = argv[0]
        mode = {"--report": "report", "--strict": "strict", "--baseline": "baseline"}.get(arg, "invalid")
    rc, output = run_checks(mode)
    print(output)
    return rc


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
