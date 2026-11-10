"""Merge execution onto a fixed production-build LCOV line/function inventory.

Standalone tests compile extra harnesses and alternate preprocessor branches.
Their execution can cover a production line, but must not add test code to the
denominator or remove production code that no test executed. The initial gcno
capture defines that inventory before any tests rebuild or delete their inputs.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path


def _records(path: Path):
    """Read complete LCOV records; malformed counts are rejected by the caller."""
    for block in path.read_text().split("end_of_record"):
        rows = block.strip().splitlines()
        source = next((row[3:] for row in rows if row.startswith("SF:")), None)
        if source is not None:
            yield source, rows


def _count(value: str) -> int:
    count = int(value)
    if count < 0:
        raise ValueError("negative execution count in coverage report")
    return count


def _execution(paths: list[Path]):
    """Accumulate real execution counts by source location and function name."""
    lines, functions = defaultdict(int), defaultdict(int)
    for path in paths:
        for source, rows in _records(path):
            _add_execution(source, rows, lines, functions)
    return lines, functions


def _add_execution(source, rows, lines, functions):
    """Read one record's line and function counters without inventing hits."""
    for row in rows:
        if row.startswith("DA:"):
            number, count, *_checksum = row[3:].split(",")
            lines[source, int(number)] += _count(count)
        elif row.startswith("FNDA:"):
            count, name = row[5:].split(",", 1)
            functions[source, name] += _count(count)


def _covered_record(source, rows, lines, functions):
    """Keep the initial inventory intact while replacing its zero counters."""
    output, line_hits, function_hits = [], 0, 0
    for row in rows:
        if row.startswith("DA:"):
            number, _initial, *checksum = row[3:].split(",")
            count = lines.get((source, int(number)), 0)
            line_hits += count > 0
            output.append("DA:" + ",".join([number, str(count), *checksum]))
        elif row.startswith("FNDA:"):
            _initial, name = row[5:].split(",", 1)
            count = functions.get((source, name), 0)
            function_hits += count > 0
            output.append(f"FNDA:{count},{name}")
        elif not row.startswith(("LH:", "FNH:")):
            output.append(row)
    return [*output, f"LH:{line_hits}", f"FNH:{function_hits}", "end_of_record"]


def merge_execution(initial: Path, captures: list[Path], output: Path) -> None:
    """Write measured coverage with exactly the initial production denominator."""
    lines, functions = _execution(captures)
    records = [_covered_record(source, rows, lines, functions)
               for source, rows in _records(initial)]
    if not records:
        raise ValueError("initial production coverage inventory is empty")
    output.write_text("\n".join(row for record in records for row in record) + "\n")


def line_rate(report: Path) -> str:
    """Compute the gate's percentage without lcov's one-decimal rounding."""
    counts = [_count(row[3:].split(",")[1]) for _source, rows in _records(report)
              for row in rows if row.startswith("DA:")]
    return str(100 * sum(count > 0 for count in counts) / len(counts)) if counts else ""
