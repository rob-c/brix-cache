#!/usr/bin/env python3
"""Detect platform and CPU features for the BriX-Cache build.

The command preserves the JSON and GitHub Actions key=value formats. Probe
families live in platform_detect_* modules; public detection functions remain
importable here for existing tooling.
"""

import argparse
import json
import platform
import subprocess
import sys

from platform_detect_build import (
    detect_compiler_support, detect_optimization_flags,
    generate_build_recommendations,
)
from platform_detect_command import run_command
from platform_detect_cpu import (
    detect_architecture, detect_arm_features, detect_arm64_features,
    detect_x86_features,
)
from platform_detect_host import detect_platform, detect_runtime_info


def _metadata():
    timestamp = "unknown"
    if platform.system() != "Windows":
        timestamp = subprocess.run(
            ["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
            capture_output=True, text=True,
        ).stdout.strip()
    return {"script": "detect_platform_features.py", "version": "1.0.0",
            "timestamp": timestamp}


def collect_detection():
    """Collect the original schema in its original field order."""
    result = {"platform": detect_platform(), "architecture": detect_architecture(),
              "compiler": detect_compiler_support(),
              "optimization_flags": detect_optimization_flags(),
              "runtime": detect_runtime_info(), "recommendations": None}
    result["recommendations"] = generate_build_recommendations(result)
    result["metadata"] = _metadata()
    return result


def _arguments(argv):
    parser = argparse.ArgumentParser(
        description="Detect platform features for BriX-Cache build configuration")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--ci-format", action="store_true",
                        help="Output in CI-friendly format (GitHub Actions compatible)")
    parser.add_argument("--output", "-o", type=str,
                        help="Output file path (default: stdout)")
    return parser.parse_args(argv)


def _format(result, ci_format):
    if ci_format:
        return "\n".join(f"{key}={json.dumps(value)}" for key, value in result.items())
    return json.dumps(result, indent=2)


def _write_output(output, arguments):
    if not arguments.output:
        print(output)
        return
    with open(arguments.output, 'w') as stream:
        stream.write(output + "\n")
    if arguments.verbose:
        print(f"Output written to {arguments.output}", file=sys.stderr)


def _summary(result):
    print("\n=== Platform Detection Summary ===", file=sys.stderr)
    print(f"Platform: {result['platform']['name']} "
          f"({result['platform']['release']})", file=sys.stderr)
    print(f"Architecture: {result['architecture']['normalized']} "
          f"({result['architecture']['family']})", file=sys.stderr)
    print(f"Compiler: {result['compiler']['name']} "
          f"{result['compiler']['version']}", file=sys.stderr)
    print(f"CPU Cores: {result['runtime']['cpu_count']}", file=sys.stderr)
    if result['runtime']['total_memory_mb']:
        print(f"Memory: {result['runtime']['total_memory_mb']} MB", file=sys.stderr)
    print(f"LTO Support: {result['compiler']['supports_lto']}", file=sys.stderr)
    print(f"Recommended march: {' '.join(result['optimization_flags']['march'])}",
          file=sys.stderr)


def main(argv=None):
    """Run host probes and emit the selected format."""
    arguments = _arguments(argv)
    result = collect_detection()
    _write_output(_format(result, arguments.ci_format), arguments)
    if arguments.verbose:
        _summary(result)


if __name__ == "__main__":
    main()
