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


def main(path: str) -> int:
    root = ET.parse(path).getroot()
    cases = root.iter("testcase")

    total = passed = 0
    buckets: dict[tuple[str, str, str], list[str]] = collections.defaultdict(list)
    skip_reasons: collections.Counter = collections.Counter()

    for c in cases:
        total += 1
        f = c.find("failure")
        e = c.find("error")
        s = c.find("skipped")
        node = f if f is not None else e
        if node is not None:
            kind = "FAIL" if f is not None else "ERROR"
            # Prefer junit's `file` attr; fall back to the classname, whose
            # dots are path separators ("tests.test_x" / "tests.test_x.TestC")
            # so the module is the first component that looks like a test file.
            fil = c.get("file") or ""
            if not fil:
                parts = (c.get("classname") or "").split(".")
                fil = next((p for p in parts if p.startswith("test_")),
                           parts[-1] if parts else "?")
            buckets[(kind, fil, norm(node.get("message", "")))].append(c.get("name", ""))
        elif s is not None:
            skip_reasons[norm(s.get("message", ""))] += 1
        else:
            passed += 1

    nfail = sum(len(v) for k, v in buckets.items() if k[0] == "FAIL")
    nerr = sum(len(v) for k, v in buckets.items() if k[0] == "ERROR")
    nskip = sum(skip_reasons.values())

    print(f"TOTAL {total}   passed {passed}   failed {nfail}   errored {nerr}   skipped {nskip}")
    print(f"distinct failure signatures: {len(buckets)}\n")

    print("=" * 100)
    print("FAILURE / ERROR SIGNATURES (by count)")
    print("=" * 100)
    for (kind, fil, msg), names in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
        print(f"\n[{kind} x{len(names)}] {fil}")
        print(f"    {msg}")
        for n in names[:4]:
            print(f"      · {n}")
        if len(names) > 4:
            print(f"      · … +{len(names)-4} more")

    print("\n" + "=" * 100)
    print("TOP SKIP REASONS")
    print("=" * 100)
    for msg, n in skip_reasons.most_common(30):
        print(f"  {n:6d}  {msg}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/suite/junit.xml"))
