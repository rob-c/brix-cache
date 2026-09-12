#!/usr/bin/env python3
"""
tests/platform/report_coverage.py - Generate PAL function coverage report

This script analyzes test files and generates a coverage report showing:
- Which PAL functions are tested
- Test coverage percentage per function category
- Missing tests for untested functions
- Platform-specific coverage

Usage:
    python report_coverage.py [--json] [--markdown] [--verbose]
"""

import os
import re
import sys
import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple


# =============================================================================
# PAL Function Registry
# =============================================================================

PAL_FUNCTIONS = {
    "Platform Information": [
        "brix_plat_name",
        "brix_plat_version",
        "brix_plat_arch",
        "brix_plat_is_root",
        "brix_plat_cpu_count",
        "brix_plat_total_memory",
        "brix_plat_available_memory",
    ],
    "Initialization": [
        "brix_plat_init",
        "brix_plat_cleanup",
    ],
    "Byte Order": [
        "brix_plat_htobe64",
        "brix_plat_be64toh",
        "brix_plat_htobe32",
        "brix_plat_be32toh",
        "brix_plat_htobe16",
        "brix_plat_be16toh",
    ],
    "File Descriptors": [
        "brix_plat_anon_fd",
        "brix_plat_fadvise",
        "brix_plat_fsync_data",
        "brix_plat_sync",
        "brix_plat_sync_tree",
    ],
    "Zero-Copy": [
        "brix_plat_sendfile",
        "brix_plat_splice",
        "brix_plat_copy_range",
    ],
    "Events": [
        "brix_plat_eventfd",
        "brix_plat_pipe2",
    ],
    "Filesystem Watcher": [
        "brix_plat_fs_watcher_init",
        "brix_plat_fs_watcher_add",
        "brix_plat_fs_watcher_rm",
        "brix_plat_fs_watcher_next",
        "brix_plat_fs_watcher_destroy",
    ],
    "Security": [
        "brix_plat_security_init",
        "brix_plat_security_enter",
        "brix_plat_setfsuid",
        "brix_plat_setfsgid",
    ],
    "Random": [
        "brix_plat_random",
    ],
    "Extended Attributes": [
        "brix_plat_getxattr",
        "brix_plat_fgetxattr",
        "brix_plat_setxattr",
        "brix_plat_fsetxattr",
        "brix_plat_removexattr",
        "brix_plat_fremovexattr",
        "brix_plat_listxattr",
        "brix_plat_flistxattr",
    ],
    "Process Execution": [
        "brix_plat_execvpe",
    ],
}

# Flatten for easy lookup
ALL_FUNCTIONS = set()
for category, funcs in PAL_FUNCTIONS.items():
    ALL_FUNCTIONS.update(funcs)


# =============================================================================
# Test File Analyzer
# =============================================================================

class TestAnalyzer:
    """Analyze test files for PAL function coverage"""
    
    def __init__(self, test_dir: Path):
        self.test_dir = test_dir
        self.test_files = list(test_dir.glob("test_*.py"))
        self.coverage = defaultdict(lambda: {
            "tested": False,
            "test_count": 0,
            "test_names": [],
            "platforms": set(),
        })
    
    def analyze(self):
        """Analyze all test files"""
        for test_file in self.test_files:
            self._analyze_file(test_file)
        
        return self.coverage
    
    def _analyze_file(self, test_file: Path):
        """Analyze a single test file"""
        content = test_file.read_text()
        
        # Find all @pytest.mark.pal_function decorators
        pattern = r'@pytest\.mark\.pal_function\("([^"]+)"\)'
        matches = re.findall(pattern, content)
        
        for func_name in matches:
            self.coverage[func_name]["tested"] = True
            self.coverage[func_name]["test_count"] += 1
        
        # Find test function names
        test_pattern = r'def (test_[^(]+)\([^)]*\):'
        test_funcs = re.findall(test_pattern, content)
        
        # Map test functions to PAL functions
        for test_func in test_funcs:
            for func_name in matches:
                self.coverage[func_name]["test_names"].append(test_func)
        
        # Find platform markers
        if "@pytest.mark.linux" in content:
            for func_name in matches:
                self.coverage[func_name]["platforms"].add("linux")
        
        if "@pytest.mark.darwin" in content:
            for func_name in matches:
                self.coverage[func_name]["platforms"].add("darwin")
        
        if "@pytest.mark.windows" in content:
            for func_name in matches:
                self.coverage[func_name]["platforms"].add("windows")


# =============================================================================
# Report Generators
# =============================================================================

class ReportGenerator:
    """Generate coverage reports in various formats"""
    
    def __init__(self, coverage: Dict, all_functions: Set[str], categories: Dict):
        self.coverage = coverage
        self.all_functions = all_functions
        self.categories = categories
    
    def generate_text_report(self) -> str:
        """Generate plain text report"""
        lines = []
        lines.append("=" * 80)
        lines.append("PAL FUNCTION COVERAGE REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        total_functions = len(self.all_functions)
        tested_functions = sum(1 for f in self.all_functions if self.coverage[f]["tested"])
        coverage_pct = (tested_functions / total_functions * 100) if total_functions > 0 else 0
        
        lines.append(f"Total Functions: {total_functions}")
        lines.append(f"Tested Functions: {tested_functions}")
        lines.append(f"Coverage: {coverage_pct:.1f}%")
        lines.append("")
        
        # Coverage by category
        lines.append("-" * 80)
        lines.append("COVERAGE BY CATEGORY")
        lines.append("-" * 80)
        
        for category, funcs in self.categories.items():
            tested = sum(1 for f in funcs if self.coverage[f]["tested"])
            pct = (tested / len(funcs) * 100) if funcs else 0
            
            status = "✓" if pct == 100 else "◐" if pct > 0 else "✗"
            lines.append(f"\n{status} {category}: {tested}/{len(funcs)} ({pct:.0f}%)")
            
            for func in funcs:
                if self.coverage[func]["tested"]:
                    test_count = self.coverage[func]["test_count"]
                    lines.append(f"  ✓ {func} ({test_count} tests)")
                else:
                    lines.append(f"  ✗ {func} (NOT TESTED)")
        
        # Untested functions
        untested = [f for f in self.all_functions if not self.coverage[f]["tested"]]
        if untested:
            lines.append("")
            lines.append("-" * 80)
            lines.append("UNTESTED FUNCTIONS")
            lines.append("-" * 80)
            for func in sorted(untested):
                lines.append(f"  - {func}")
        
        # Platform coverage
        lines.append("")
        lines.append("-" * 80)
        lines.append("PLATFORM COVERAGE")
        lines.append("-" * 80)
        
        for platform in ["linux", "darwin", "windows"]:
            platform_funcs = set()
            for func in self.all_functions:
                if platform in self.coverage[func]["platforms"]:
                    platform_funcs.add(func)
            
            lines.append(f"\n{platform.upper()}: {len(platform_funcs)} functions")
        
        lines.append("")
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    def generate_json_report(self) -> str:
        """Generate JSON report"""
        report = {
            "summary": {
                "total_functions": len(self.all_functions),
                "tested_functions": sum(1 for f in self.all_functions if self.coverage[f]["tested"]),
                "coverage_percentage": 0,
            },
            "categories": {},
            "untested_functions": [],
            "platform_coverage": {
                "linux": [],
                "darwin": [],
                "windows": [],
            }
        }
        
        tested = sum(1 for f in self.all_functions if self.coverage[f]["tested"])
        report["summary"]["coverage_percentage"] = (tested / len(self.all_functions) * 100) if self.all_functions else 0
        
        for category, funcs in self.categories.items():
            report["categories"][category] = {
                "total": len(funcs),
                "tested": sum(1 for f in funcs if self.coverage[f]["tested"]),
                "functions": []
            }
            
            for func in funcs:
                func_info = {
                    "name": func,
                    "tested": self.coverage[func]["tested"],
                    "test_count": self.coverage[func]["test_count"],
                    "test_names": self.coverage[func]["test_names"],
                    "platforms": list(self.coverage[func]["platforms"]),
                }
                report["categories"][category]["functions"].append(func_info)
        
        report["untested_functions"] = [f for f in self.all_functions if not self.coverage[f]["tested"]]
        
        for platform in ["linux", "darwin", "windows"]:
            report["platform_coverage"][platform] = [
                f for f in self.all_functions 
                if platform in self.coverage[f]["platforms"]
            ]
        
        return json.dumps(report, indent=2)
    
    def generate_markdown_report(self) -> str:
        """Generate Markdown report"""
        lines = []
        lines.append("# PAL Function Coverage Report")
        lines.append("")
        
        total = len(self.all_functions)
        tested = sum(1 for f in self.all_functions if self.coverage[f]["tested"])
        pct = (tested / total * 100) if total > 0 else 0
        
        lines.append("## Summary")
        lines.append("")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total Functions | {total} |")
        lines.append(f"| Tested Functions | {tested} |")
        lines.append(f"| Coverage | {pct:.1f}% |")
        lines.append("")
        
        lines.append("## Coverage by Category")
        lines.append("")
        
        for category, funcs in self.categories.items():
            cat_tested = sum(1 for f in funcs if self.coverage[f]["tested"])
            cat_pct = (cat_tested / len(funcs) * 100) if funcs else 0
            
            lines.append(f"### {category} ({cat_pct:.0f}%)")
            lines.append("")
            lines.append("| Function | Status | Tests | Platforms |")
            lines.append("|----------|--------|-------|-----------|")
            
            for func in funcs:
                status = "✅" if self.coverage[func]["tested"] else "❌"
                test_count = self.coverage[func]["test_count"]
                platforms = ", ".join(self.coverage[func]["platforms"]) or "None"
                lines.append(f"| `{func}` | {status} | {test_count} | {platforms} |")
            
            lines.append("")
        
        untested = [f for f in self.all_functions if not self.coverage[f]["tested"]]
        if untested:
            lines.append("## Untested Functions")
            lines.append("")
            for func in sorted(untested):
                lines.append(f"- `{func}`")
            lines.append("")
        
        return "\n".join(lines)


# =============================================================================
# Main
# =============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate PAL function coverage report")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--markdown", action="store_true", help="Output as Markdown")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--test-dir", type=str, default=str(Path(__file__).parent),
                       help="Test directory to analyze")
    
    args = parser.parse_args()
    
    # Analyze tests
    test_dir = Path(args.test_dir)
    analyzer = TestAnalyzer(test_dir)
    coverage = analyzer.analyze()
    
    # Generate report
    generator = ReportGenerator(coverage, ALL_FUNCTIONS, PAL_FUNCTIONS)
    
    if args.json:
        print(generator.generate_json_report())
    elif args.markdown:
        print(generator.generate_markdown_report())
    else:
        print(generator.generate_text_report())
    
    # Exit with error if coverage is below threshold
    tested = sum(1 for f in ALL_FUNCTIONS if coverage[f]["tested"])
    coverage_pct = (tested / len(ALL_FUNCTIONS) * 100) if ALL_FUNCTIONS else 0
    
    if coverage_pct < 50:
        print(f"\n⚠️  Warning: Coverage is below 50% ({coverage_pct:.1f}%)")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
