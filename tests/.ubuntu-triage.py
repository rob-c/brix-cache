#!/usr/bin/env python3
"""Parse a junit.xml from the Ubuntu full-suite pass into a triage table.

Scratch tool for the phase-100 drilldown, not part of the repo's harness.

Groups failures by (file, first-line-of-message) so a systemic cause shows up
once with a count instead of N times, which is what makes a 36k-test run
triageable by hand.
"""
from __future__ import annotations

import collections
import re
import sys
import xml.etree.ElementTree as ET


def norm(msg: str) -> str:
    """Collapse run-specific noise so identical causes group together."""
    m = (msg or "").strip().split("\n")[0][:200]
    m = re.sub(r"/tmp/[^\s'\"]+", "<tmp>", m)
    m = re.sub(r"\b\d{2,}\b", "<n>", m)
    m = re.sub(r"0x[0-9a-f]+", "<hex>", m)
    return m


def _case_file(case) -> str:
    filename = case.get("file")
    if filename:
        return filename
    parts = _class_parts(case)
    for part in parts:
        if part.startswith("test_"):
            return part
    return parts[-1] if parts else "?"


def _class_parts(case):
    classname = case.get("classname")
    return classname.split(".") if classname else []


def _record_case(case, buckets, skip_reasons) -> bool:
    failure = case.find("failure")
    error = case.find("error")
    skipped = case.find("skipped")
    node = failure if failure is not None else error
    if node is not None:
        kind = "FAIL" if failure is not None else "ERROR"
        key = kind, _case_file(case), norm(node.get("message", ""))
        buckets[key].append(case.get("name", ""))
        return False
    if skipped is not None:
        skip_reasons[norm(skipped.get("message", ""))] += 1
        return False
    return True


def _result_counts(buckets, skip_reasons):
    failed = sum(len(names) for key, names in buckets.items() if key[0] == "FAIL")
    errors = sum(len(names) for key, names in buckets.items() if key[0] == "ERROR")
    return failed, errors, sum(skip_reasons.values())


def _print_failure_group(kind, filename, message, names):
    print(f"\n[{kind} x{len(names)}] {filename}")
    print(f"    {message}")
    for name in names[:4]:
        print(f"      · {name}")
    if len(names) > 4:
        print(f"      · … +{len(names)-4} more")


def _print_failures(buckets):
    print("=" * 100)
    print("FAILURE / ERROR SIGNATURES (by count)")
    print("=" * 100)
    ranked = sorted(buckets.items(), key=lambda item: -len(item[1]))
    for (kind, filename, message), names in ranked:
        _print_failure_group(kind, filename, message, names)


def _print_skips(skip_reasons):
    print("\n" + "=" * 100)
    print("TOP SKIP REASONS")
    print("=" * 100)
    for message, count in skip_reasons.most_common(30):
        print(f"  {count:6d}  {message}")


def main(path: str) -> int:
    cases = ET.parse(path).getroot().iter("testcase")

    total = passed = 0
    buckets: dict[tuple[str, str, str], list[str]] = collections.defaultdict(list)
    skip_reasons: collections.Counter = collections.Counter()

    for case in cases:
        total += 1
        passed += int(_record_case(case, buckets, skip_reasons))

    nfail, nerr, nskip = _result_counts(buckets, skip_reasons)
    print(f"TOTAL {total}   passed {passed}   failed {nfail}   errored {nerr}   skipped {nskip}")
    print(f"distinct failure signatures: {len(buckets)}\n")
    _print_failures(buckets)
    _print_skips(skip_reasons)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/suite/junit.xml"))
