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


def run_lizard(lizard: str, paths: list[str],
               lang: str = "c") -> Iterator[dict[str, Any]]:
    out = subprocess.run(
        [lizard, "--csv", "-l", lang, *paths],
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
    paths, top, mode = _parse_args(sys.argv[1:])
    funcs = list(run_lizard(find_lizard(), paths))
    if mode["gate"]:
        _print_gate(funcs)
        return
    rows, columns = _ranked_rows(funcs, top, mode["funcs"])
    _print(rows, columns, mode["csv"])


def _parse_args(argv):
    args = list(argv)
    top = 30
    if "--top" in args:
        i = args.index("--top")
        top = int(args[i + 1])
        del args[i : i + 2]
    paths = [a for a in args if not a.startswith("--")] or ["src", "client"]
    mode = {
        "funcs": "--funcs" in args,
        "csv": "--csv" in args,
        "gate": "--gate-csv" in args,
    }
    return paths, top, mode


def _print_gate(funcs):
    rows = sorted(
        ((f["file"], f["func"], f["ccn"]) for f in funcs if f["ccn"] > CCN_MAX),
        key=lambda row: (row[0], row[1], -row[2]),
    )
    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerows(rows)


def _ranked_rows(funcs, top, mode_funcs):
    if mode_funcs:
        rows = sorted((f for f in funcs if f["score"] > 0), key=lambda x: -x["score"])[:top]
        return rows, ["score", "ccn", "len", "param", "dens", "func", "file"]
    rows = _rank_files(funcs, top)
    return rows, ["score", "hot", "funcs", "worst_ccn", "worst", "file"]


def _rank_files(funcs, top):
    files = {}
    for f in funcs:
        _add_function(files, f)
    rows = sorted(
        (item for item in files.values() if item["score"] > 0),
        key=lambda item: -item["score"],
    )[:top]
    for item in rows:
        item["score"] = round(item["score"], 1)
    return rows


def _add_function(files, function):
    item = files.setdefault(
        function["file"],
        {"file": function["file"], "score": 0.0, "hot": 0,
         "funcs": 0, "worst_ccn": 0, "worst": ""},
    )
    item["funcs"] += 1
    item["score"] += function["score"]
    if function["score"] > 0:
        item["hot"] += 1
    if function["ccn"] > item["worst_ccn"]:
        item["worst_ccn"] = function["ccn"]
        item["worst"] = function["func"]


def _print(rows, cols, as_csv):
    if as_csv:
        _print_csv(rows, cols)
        return
    if not rows:
        print("No hotspots — everything is within readability budgets.")
        return
    _print_table(rows, cols)


def _print_csv(rows, cols):
    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(cols)
    for row in rows:
        writer.writerow([row[column] for column in cols])


def _print_table(rows, cols):
    widths = _column_widths(rows, cols)
    print(_table_row(cols, cols, widths))
    print("  ".join("-" * widths[column] for column in cols))
    for row in rows:
        print(_table_row(row, cols, widths))


def _column_widths(rows, columns):
    return {
        column: max(len(column), *(len(str(row[column])) for row in rows))
        for column in columns
    }


def _table_row(row, columns, widths):
    return "  ".join(str(row[column]).ljust(widths[column]) for column in columns)


if __name__ == "__main__":
    main()
