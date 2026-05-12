#!/usr/bin/env python3
"""Aggregate pytest-junit XML results from parallel test Jobs.

Supports two collection modes:
  - local:   Results in a shared directory (minikube PVC/emptyDir)
  - s3:      Results pushed to S3-compatible storage (CI/GitHub Actions)

Usage:
    python aggregate_results.py --results-dir /test-results [--summary-out summary.json]
    python aggregate_results.py --s3-bucket k8s-test-results --prefix test-xml/
"""

import argparse
import glob
import json
import os
import sys
from datetime import datetime, timezone
from xml.etree import ElementTree as ET


def parse_junit_xml(file_path):
    """Parse a single pytest-junit XML file and return structured results."""
    tree = ET.parse(file_path)
    root = tree.getroot()

    test_cases = []
    errors = 0
    failures = 0
    skipped = 0
    passed = 0
    duration = 0.0

    for testsuite in root.findall("testsuite"):
        suite_name = testsuite.get("name", "unknown")
        suite_errors = int(testsuite.get("errors", 0))
        suite_failures = int(testsuite.get("failures", 0))
        suite_skipped = int(testsuite.get("skips", testsuite.get("skipped", 0)))

        for testcase in testsuite.findall("testcase"):
            case_duration = float(testcase.get("time", 0))
            duration += case_duration

            error = testcase.find("error")
            failure = testcase.find("failure")
            skip = testcase.find("skipped")

            if error is not None:
                errors += 1
                test_cases.append({
                    "name": testcase.get("name"),
                    "suite": suite_name,
                    "status": "error",
                    "duration": case_duration,
                    "message": (error.text or "").strip()[:500],
                })
            elif failure is not None:
                failures += 1
                test_cases.append({
                    "name": testcase.get("name"),
                    "suite": suite_name,
                    "status": "failed",
                    "duration": case_duration,
                    "message": (failure.text or "").strip()[:500],
                })
            elif skip is not None:
                skipped += 1
                test_cases.append({
                    "name": testcase.get("name"),
                    "suite": suite_name,
                    "status": "skipped",
                    "message": (skip.text or "").strip()[:200],
                })
            else:
                passed += 1

    return {
        "file": os.path.basename(file_path),
        "tests": len(test_cases) + skipped,
        "passed": passed,
        "failed": failures,
        "errors": errors,
        "skipped": skipped,
        "duration": round(duration, 2),
        "cases": test_cases,
    }


def collect_local_results(results_dir):
    """Collect XML files from a local directory."""
    patterns = [
        os.path.join(results_dir, "*.xml"),
        os.path.join(results_dir, "**", "*.xml"),
    ]

    xml_files = []
    for pattern in patterns:
        xml_files.extend(glob.glob(pattern, recursive=True))

    # Deduplicate and sort
    return sorted(set(xml_files))


def collect_s3_results(bucket_name, prefix="test-xml/"):
    """Collect XML files from an S3-compatible bucket."""
    try:
        import boto3
    except ImportError:
        print("ERROR: boto3 required for S3 result collection. Install with: pip install boto3", file=sys.stderr)
        sys.exit(1)

    s3 = boto3.client("s3")
    objects = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)

    xml_files = []
    for obj in objects.get("Contents", []):
        if obj["Key"].endswith(".xml"):
            # Download to temp directory
            import tempfile
            tmpdir = tempfile.mkdtemp(prefix="k8s-test-agg-")
            local_path = os.path.join(tmpdir, os.path.basename(obj["Key"]))
            s3.download_file(bucket_name, obj["Key"], local_path)
            xml_files.append(local_path)

    return xml_files


def summarize(results):
    """Generate a human-readable summary of all test results."""
    total_tests = sum(r["tests"] for r in results)
    total_passed = sum(r["passed"] for r in results)
    total_failed = sum(r["failed"] for r in results)
    total_errors = sum(r["errors"] for r in results)
    total_skipped = sum(r["skipped"] for r in results)
    max_duration = max((r["duration"] for r in results), default=0)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_jobs": len(results),
        "total_tests": total_tests,
        "passed": total_passed,
        "failed": total_failed,
        "errors": total_errors,
        "skipped": total_skipped,
        "duration_seconds": round(max_duration, 2),
        "status": "PASS" if (total_failed == 0 and total_errors == 0) else "FAIL",
    }


def main():
    parser = argparse.ArgumentParser(description="Aggregate pytest test results")
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--results-dir", help="Local directory containing XML result files")
    mode_group.add_argument("--s3-bucket", help="S3 bucket name for remote result collection")
    parser.add_argument("--prefix", default="test-xml/", help="Prefix/key path for S3 collection (default: test-xml/)")
    parser.add_argument("--summary-out", "-o", help="Write JSON summary to file instead of stdout")

    args = parser.parse_args()

    # Collect XML files
    if args.results_dir:
        xml_files = collect_local_results(args.results_dir)
    else:
        xml_files = collect_s3_results(args.s3_bucket, prefix=args.prefix)

    if not xml_files:
        print("WARNING: No XML result files found", file=sys.stderr)
        summary = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_jobs": 0,
            "status": "NO_RESULTS",
        }
        if args.summary_out:
            with open(args.summary_out, "w") as f:
                json.dump(summary, f, indent=2)
        else:
            print(json.dumps(summary, indent=2))
        return 1

    # Parse and aggregate
    results = [parse_junit_xml(f) for f in xml_files]
    summary = summarize(results)

    output = json.dumps(summary, indent=2)
    if args.summary_out:
        with open(args.summary_out, "w") as f:
            f.write(output + "\n")
    else:
        print(output)

    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
