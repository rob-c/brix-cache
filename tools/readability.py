#!/usr/bin/env python3
"""
readability.py — rank source files by how hard they are to read / refactor need.

Thin wrapper over `lizard` (McCabe cyclomatic complexity analyzer). Lizard does
all the parsing; this script only aggregates lizard's per-function metrics up to
a per-file "refactor priority" score and prints a ranked table.

Difficulty proxies (all standard, all from lizard, no extra parsing):
  CCN     cyclomatic complexity  — branch density, the #1 readability killer
  LEN     lines per function     — long functions overflow working memory
  PARAM   parameter count        — high arity = opaque call semantics
  DENS    tokens / line          — expression density (clever one-liners)

A function is a "hotspot" if it trips any threshold. File score sums each
function's *excess* over the thresholds, so a file is ranked high only for the
parts that are genuinely over-budget — not merely for being large.

Usage:
    tools/readability.py [paths...]        # default: src client
    tools/readability.py --top 40
    tools/readability.py --funcs           # list worst functions instead of files
    tools/readability.py --csv             # machine-readable, for CI gating
    tools/readability.py --gate-csv        # file,func,ccn for funcs over CCN cap
                                           #   (stable output consumed by
                                           #    tools/ci/check_complexity.py)

Requires: lizard  (pip install --user lizard  →  ~/.local/bin/lizard)
"""
import csv
import io
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from typing import Any

# Readability budgets. Over these a function starts contributing to the score.
CCN_MAX, LEN_MAX, PARAM_MAX, DENS_MAX = 15, 60, 6, 12

# Score weights — normalize each excess to "roughly one unit per meaningful step".
W_CCN, W_LEN, W_PARAM, W_DENS = 1.0, 0.10, 2.0, 0.5


def find_lizard() -> str:
    for c in ("lizard", os.path.expanduser("~/.local/bin/lizard")):
        if shutil.which(c) or os.path.exists(c):
            return c
    sys.exit("lizard not found. Install: pip install --user lizard")


def func_score(ccn: int, length: int, param: int, dens: float) -> float:
    return (
        max(0, ccn - CCN_MAX) * W_CCN
        + max(0, length - LEN_MAX) * W_LEN
        + max(0, param - PARAM_MAX) * W_PARAM
        + max(0, dens - DENS_MAX) * W_DENS
    )


def run_lizard(lizard: str, paths: list[str]) -> Iterator[dict[str, Any]]:
    out = subprocess.run(
        [lizard, "--csv", "-l", "c", *paths],
        capture_output=True, text=True,
    ).stdout
    # CSV: nloc, ccn, token, param, length, location, file, name, longname, start, end
    for row in csv.reader(io.StringIO(out)):
        if len(row) < 8:
            continue
        try:
            nloc, ccn, token, param, length = (int(row[i]) for i in range(5))
        except ValueError:
            continue
        dens = token / nloc if nloc else 0
        yield {
            "file": row[6], "func": row[7], "loc": row[5].split("@")[-2] if "@" in row[5] else "",
            "ccn": ccn, "len": length, "param": param, "dens": round(dens, 1),
            "score": func_score(ccn, length, param, dens),
        }


def main():
    args = sys.argv[1:]
    top = 30
    mode_funcs = "--funcs" in args
    mode_csv = "--csv" in args
    mode_gate = "--gate-csv" in args
    if "--top" in args:
        i = args.index("--top")
        top = int(args[i + 1])
        del args[i : i + 2]
    paths = [a for a in args if not a.startswith("--")] or ["src", "client"]

    funcs = list(run_lizard(find_lizard(), paths))

    if mode_gate:
        # Stable, weight-free ratchet feed: one row per function over the CCN cap,
        # sorted by identity so diffs are deterministic. See check_complexity.py.
        rows = sorted(
            ((f["file"], f["func"], f["ccn"]) for f in funcs if f["ccn"] > CCN_MAX),
            key=lambda r: (r[0], r[1], -r[2]),
        )
        w = csv.writer(sys.stdout, lineterminator="\n")  # no \r into the ratchet
        for file, func, ccn in rows:
            w.writerow([file, func, ccn])
        return

    if mode_funcs:
        rows = sorted((f for f in funcs if f["score"] > 0), key=lambda x: -x["score"])[:top]
        _print(rows, ["score", "ccn", "len", "param", "dens", "func", "file"], mode_csv)
        return

    files = {}
    for f in funcs:
        d = files.setdefault(f["file"], {"file": f["file"], "score": 0.0, "hot": 0,
                                         "funcs": 0, "worst_ccn": 0, "worst": ""})
        d["funcs"] += 1
        d["score"] += f["score"]
        if f["score"] > 0:
            d["hot"] += 1
        if f["ccn"] > d["worst_ccn"]:
            d["worst_ccn"] = f["ccn"]
            d["worst"] = f["func"]
    rows = sorted((d for d in files.values() if d["score"] > 0),
                  key=lambda x: -x["score"])[:top]
    for d in rows:
        d["score"] = round(d["score"], 1)
    _print(rows, ["score", "hot", "funcs", "worst_ccn", "worst", "file"], mode_csv)


def _print(rows, cols, as_csv):
    if as_csv:
        w = csv.writer(sys.stdout, lineterminator="\n")
        w.writerow(cols)
        for r in rows:
            w.writerow([r[c] for c in cols])
        return
    if not rows:
        print("No hotspots — everything is within readability budgets.")
        return
    widths = {c: max(len(c), *(len(str(r[c])) for r in rows)) for c in cols}
    print("  ".join(c.ljust(widths[c]) for c in cols))
    print("  ".join("-" * widths[c] for c in cols))
    for r in rows:
        print("  ".join(str(r[c]).ljust(widths[c]) for c in cols))


if __name__ == "__main__":
    main()
