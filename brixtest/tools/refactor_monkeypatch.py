#!/usr/bin/env python3
"""Automated refactoring tool for eliminating monkeypatch usage in BrixTest.

This script helps identify and refactor monkeypatch usage patterns:
1. Scans test files for monkeypatch calls
2. Categorizes by type (setenv, setattr, etc.)
3. Generates refactored code using dependency injection
4. Updates source files to accept config/injected parameters

Usage:
    python tools/refactor_monkeypatch.py --scan tests/
    python tools/refactor_monkeypatch.py --refactor test_file.py
    python tools/refactor_monkeypatch.py --report
"""

import ast
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional


class MonkeypatchScanner:
    """Scan Python files for monkeypatch usage."""
    
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.findings = defaultdict(list)
    
    def scan_all(self) -> dict:
        """Scan all test files for monkeypatch usage."""
        test_files = list(self.root_dir.glob("**/test_*.py"))
        
        for file_path in test_files:
            self.scan_file(file_path)
        
        return dict(self.findings)
    
    def scan_file(self, file_path: Path) -> list:
        """Scan a single file for monkeypatch usage."""
        try:
            content = file_path.read_text()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return []
        
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if 'monkeypatch.' in line:
                finding = self._analyze_line(line_num, line, file_path)
                if finding:
                    findings.append(finding)
                    self.findings[str(file_path)].append(finding)
        
        return findings
    
    def _analyze_line(self, line_num: int, line: str, file_path: Path) -> Optional[dict]:
        """Analyze a line with monkeypatch usage."""
        line = line.strip()
        
        # Categorize by method
        if 'monkeypatch.setenv' in line:
            return self._categorize_setenv(line_num, line, file_path)
        elif 'monkeypatch.setattr' in line:
            return self._categorize_setattr(line_num, line, file_path)
        elif 'monkeypatch.setitem' in line:
            return self._categorize_setitem(line_num, line, file_path)
        elif 'monkeypatch.delenv' in line:
            return self._categorize_delenv(line_num, line, file_path)
        elif 'monkeypatch.chdir' in line:
            return {'type': 'chdir', 'line': line_num, 'code': line, 'file': str(file_path)}
        elif 'monkeypatch.undo' in line:
            return {'type': 'undo', 'line': line_num, 'code': line, 'file': str(file_path)}
        
        return None
    
    def _categorize_setenv(self, line_num: int, line: str, file_path: Path) -> dict:
        """Categorize setenv calls."""
        match = re.search(r'setenv\(["\']([^"\']+)["\']', line)
        var_name = match.group(1) if match else 'UNKNOWN'
        
        category = 'environment'
        if 'BRIXTEST_' in var_name:
            category = 'brixtest_config'
        elif 'TEST_' in var_name:
            category = 'test_config'
        
        return {
            'type': 'setenv',
            'line': line_num,
            'code': line,
            'file': str(file_path),
            'variable': var_name,
            'category': category
        }
    
    def _categorize_setattr(self, line_num: int, line: str, file_path: Path) -> dict:
        """Categorize setattr calls."""
        match = re.search(r'setattr\(([^,]+)', line)
        target = match.group(1).strip().strip('"\'') if match else 'UNKNOWN'
        
        category = 'module_function'
        if 'subprocess' in target:
            category = 'subprocess'
        elif 'shutil' in target:
            category = 'filesystem'
        elif 'urllib' in target or 'http' in target:
            category = 'network'
        elif 'time' in target:
            category = 'time'
        elif target.startswith('brixtest.'):
            category = 'internal_module'
        
        return {
            'type': 'setattr',
            'line': line_num,
            'code': line,
            'file': str(file_path),
            'target': target,
            'category': category
        }
    
    def _categorize_setitem(self, line_num: int, line: str, file_path: Path) -> dict:
        """Categorize setitem calls."""
        return {
            'type': 'setitem',
            'line': line_num,
            'code': line,
            'file': str(file_path),
            'category': 'dict_item'
        }
    
    def _categorize_delenv(self, line_num: int, line: str, file_path: Path) -> dict:
        """Categorize delenv calls."""
        match = re.search(r'delenv\(["\']([^"\']+)["\']', line)
        var_name = match.group(1) if match else 'UNKNOWN'
        
        return {
            'type': 'delenv',
            'line': line_num,
            'code': line,
            'file': str(file_path),
            'variable': var_name,
            'category': 'environment'
        }
    
    def generate_report(self) -> str:
        """Generate a summary report."""
        report = ["# Monkeypatch Usage Report\n"]
        
        # Summary by type
        type_counts = defaultdict(int)
        category_counts = defaultdict(int)
        
        for file_path, findings in self.findings.items():
            for finding in findings:
                type_counts[finding['type']] += 1
                if 'category' in finding:
                    category_counts[finding['category']] += 1
        
        report.append("## Summary by Type")
        for type_name, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            report.append(f"- {type_name}: {count}")
        
        report.append("\n## Summary by Category")
        for category, count in sorted(category_counts.items(), key=lambda x: -x[1]):
            report.append(f"- {category}: {count}")
        
        report.append(f"\n## Total: {sum(type_counts.values())} monkeypatch calls\n")
        
        # Details by file
        report.append("## Details by File\n")
        for file_path, findings in sorted(self.findings.items()):
            report.append(f"### {file_path}\n")
            for finding in findings:
                report.append(f"- Line {finding['line']}: `{finding['type']}` - {finding.get('variable', finding.get('target', 'N/A'))}")
            report.append("")
        
        return '\n'.join(report)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Refactor monkeypatch usage in BrixTest')
    parser.add_argument('--scan', type=Path, help='Scan directory for monkeypatch usage')
    parser.add_argument('--report', action='store_true', help='Generate report')
    parser.add_argument('--output', type=Path, help='Output file for report')
    
    args = parser.parse_args()
    
    if args.scan:
        scanner = MonkeypatchScanner(args.scan)
        scanner.scan_all()
        
        if args.report:
            report = scanner.generate_report()
            if args.output:
                args.output.write_text(report)
                print(f"Report written to {args.output}")
            else:
                print(report)
        else:
            # Print JSON summary
            print(json.dumps(dict(scanner.findings), indent=2))
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
