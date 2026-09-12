#!/usr/bin/env python3
"""
check_pal_seam.py - Verify Platform Abstraction Layer integrity

This script ensures that:
1. No platform-specific syscalls outside src/platform/*/
2. All byte-order operations use brix_plat_*() functions
3. No direct #include of platform-specific headers in business logic
4. All PAL API functions are properly implemented
"""

import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Forbidden includes in business logic code
FORBIDDEN_INCLUDES = [
    r'#include\s+<endian\.h>',
    r'#include\s+<libkern/OSByteOrder\.h>',
    r'#include\s+<sys/epoll\.h>',
    r'#include\s+<sys/inotify\.h>',
    r'#include\s+<sys/event\.h>',
    r'#include\s+<linux/',
    r'#include\s+<asm/',
    r'#include\s+<mach/',
]

# Forbidden function calls (should use brix_plat_* instead)
FORBIDDEN_CALLS = {
    'byte_order': [
        (r'\bhtobe64\b', 'brix_plat_htobe64'),
        (r'\bbe64toh\b', 'brix_plat_be64toh'),
        (r'\bhtobe32\b', 'brix_plat_htobe32'),
        (r'\bbe32toh\b', 'brix_plat_be32toh'),
        (r'\bhtobe16\b', 'brix_plat_htobe16'),
        (r'\bbe16toh\b', 'brix_plat_be16toh'),
        (r'\bhtonl\b', 'brix_plat_htobe32 (or keep htonl for network)'),
        (r'\bntohl\b', 'brix_plat_be32toh (or keep ntohl for network)'),
        (r'\bhtons\b', 'brix_plat_htobe16 (or keep htons for network)'),
        (r'\bntohs\b', 'brix_plat_be16toh (or keep ntohs for network)'),
    ],
    'file_ops': [
        (r'\bmemfd_create\b', 'brix_plat_anon_fd'),
        (r'\bopenat2\b', 'brix_plat_openat (openat2 not available on macOS)'),
        (r'\brenameat2\b', 'brix_plat_renameat (renameat2 not available on macOS)'),
        (r'\bcopy_file_range\b', 'brix_plat_copy_range'),
        (r'\bsplice\b', 'brix_plat_splice'),
        (r'\bposix_fadvise\b', 'brix_plat_fadvise'),
        (r'\bfdatasync\b', 'brix_plat_fsync_data'),
    ],
    'event_ops': [
        (r'\bepoll_create', 'brix_plat_event_init (Linux epoll)'),
        (r'\bepoll_ctl', 'brix_plat_event_*'),
        (r'\bepoll_wait', 'brix_plat_event_wait'),
        (r'\beventfd\b', 'brix_plat_eventfd'),
        (r'\bkqueue\b', 'brix_plat_event_init (macOS kqueue)'),
        (r'\bkevent\b', 'brix_plat_event_*'),
    ],
    'fs_watch': [
        (r'\binotify_init', 'brix_plat_fs_watcher_init'),
        (r'\binotify_add_watch', 'brix_plat_fs_watcher_add'),
        (r'\bFSEvents', 'brix_plat_fs_watcher_*'),
    ],
    'random': [
        (r'\bgetrandom\b', 'brix_plat_random'),
        (r'\brand\b(?!_R)', 'brix_plat_random (for cryptographic randomness)'),
    ],
    'xattr': [
        (r'\bgetxattr\b(?!attr)', 'brix_plat_getxattr'),
        (r'\bsetxattr\b', 'brix_plat_setxattr'),
        (r'\bremovexattr\b', 'brix_plat_removexattr'),
        (r'\blistxattr\b', 'brix_plat_listxattr'),
    ],
}

# Required PAL API functions
REQUIRED_PAL_FUNCTIONS = [
    'brix_plat_name',
    'brix_plat_version',
    'brix_plat_arch',
    'brix_plat_anon_fd',
    'brix_plat_fadvise',
    'brix_plat_fsync_data',
    'brix_plat_sendfile',
    'brix_plat_random',
    'brix_plat_getxattr',
    'brix_plat_setxattr',
    'brix_plat_removexattr',
    'brix_plat_listxattr',
    'brix_plat_execvpe',
    'brix_plat_htobe64',
    'brix_plat_be64toh',
    'brix_plat_htobe32',
    'brix_plat_be32toh',
]

# Directories allowed to use platform-specific code
ALLOWED_PLATFORM_DIRS = [
    'src/platform/',
    'shared/cvmfs/platform/',
]

# Patterns that indicate PAL API usage (good)
PAL_API_PATTERNS = [
    r'brix_plat_[a-z_]+\(',
    r'#include\s+"platform/platform_api\.h"',
    r'#include\s+"platform/platform\.h"',
]

class PALChecker:
    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir)
        self.violations: List[str] = []
        self.warnings: List[str] = []
        self.files_scanned = 0
        self.files_with_pal = 0
        
    def is_platform_directory(self, filepath: Path) -> bool:
        """Check if file is in an allowed platform-specific directory"""
        path_str = str(filepath)
        for allowed_dir in ALLOWED_PLATFORM_DIRS:
            if allowed_dir in path_str:
                return True
        return False
    
    def check_includes(self, filepath: Path, content: str, lines: List[str]):
        """Check for forbidden includes"""
        for line_num, line in enumerate(lines, 1):
            for pattern in FORBIDDEN_INCLUDES:
                if re.search(pattern, line):
                    # Check if it's in a platform-specific file
                    if not self.is_platform_directory(filepath):
                        self.violations.append(
                            f"{filepath}:{line_num}: Forbidden include - {line.strip()}"
                        )
    
    def check_function_calls(self, filepath: Path, content: str, lines: List[str]):
        """Check for forbidden function calls"""
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith('//') or line.strip().startswith('/*'):
                continue
            
            for category, checks in FORBIDDEN_CALLS.items():
                for forbidden, replacement in checks:
                    if re.search(forbidden, line):
                        # Check if it's already using PAL API
                        if f'brix_plat_' in line:
                            continue
                        
                        # Check if it's in a platform-specific file
                        if not self.is_platform_directory(filepath):
                            self.violations.append(
                                f"{filepath}:{line_num}: Use {replacement} instead of '{forbidden}' - {line.strip()}"
                            )
    
    def check_pal_usage(self, filepath: Path, content: str):
        """Track PAL API usage"""
        has_pal_usage = False
        for pattern in PAL_API_PATTERNS:
            if re.search(pattern, content):
                has_pal_usage = True
                break
        
        if has_pal_usage:
            self.files_with_pal += 1
    
    def check_file(self, filepath: Path):
        """Check a single file for PAL violations"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            self.warnings.append(f"Error reading {filepath}: {e}")
            return
        
        self.files_scanned += 1
        
        # Skip platform-specific directories
        if self.is_platform_directory(filepath):
            return
        
        # Skip test files
        if 'test' in str(filepath).lower():
            return
        
        # Run checks
        self.check_includes(filepath, content, lines)
        self.check_function_calls(filepath, content, lines)
        self.check_pal_usage(filepath, content)
    
    def scan(self):
        """Scan directory tree"""
        for ext in ['*.c', '*.h']:
            for filepath in self.root_dir.rglob(ext):
                # Only scan src/ directory
                if 'src' not in str(filepath):
                    continue
                
                self.check_file(filepath)
    
    def check_pal_implementation(self):
        """Check that all required PAL functions are implemented"""
        platform_dirs = ['linux', 'darwin', 'windows']
        
        for platform in platform_dirs:
            platform_path = self.root_dir / 'src' / 'platform' / platform
            if not platform_path.exists():
                self.warnings.append(f"Platform directory not found: {platform_path}")
                continue
            
            # Read all source files in platform directory
            impl_content = ""
            for src_file in platform_path.glob('*.c'):
                try:
                    with open(src_file, 'r', encoding='utf-8', errors='ignore') as f:
                        impl_content += f.read() + "\n"
                except:
                    pass
            
            # Check for required functions
            for func in REQUIRED_PAL_FUNCTIONS:
                # Some functions are inline in headers
                if 'htobe' in func or 'be64' in func or 'be32' in func or 'be16' in func:
                    continue
                
                if func not in impl_content:
                    # Check if it's a stub (platform doesn't support it)
                    if platform == 'windows' or platform == 'darwin':
                        self.warnings.append(
                            f"Platform {platform}: {func}() not found (may be stubbed)"
                        )
                    else:
                        self.violations.append(
                            f"Platform {platform}: Required function {func}() not implemented"
                        )
    
    def report(self) -> int:
        """Print report and return exit code"""
        print("=" * 80)
        print("PAL Seam Check Report")
        print("=" * 80)
        print()
        print(f"Files scanned: {self.files_scanned}")
        print(f"Files using PAL API: {self.files_with_pal}")
        print()
        
        if self.violations:
            print(f"❌ VIOLATIONS ({len(self.violations)}):")
            print("-" * 80)
            for v in self.violations[:50]:  # Limit output
                print(f"  {v}")
            if len(self.violations) > 50:
                print(f"  ... and {len(self.violations) - 50} more")
            print()
        
        if self.warnings:
            print(f"⚠️  WARNINGS ({len(self.warnings)}):")
            print("-" * 80)
            for w in self.warnings[:20]:  # Limit output
                print(f"  {w}")
            if len(self.warnings) > 20:
                print(f"  ... and {len(self.warnings) - 20} more")
            print()
        
        if not self.violations and not self.warnings:
            print("✅ No violations or warnings found!")
            return 0
        elif not self.violations:
            print("✅ No violations found (warnings only)")
            return 0
        else:
            print("❌ PAL seam check FAILED")
            return 1

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Verify Platform Abstraction Layer integrity'
    )
    parser.add_argument(
        '--directory', '-d',
        default='src',
        help='Directory to scan (default: src)'
    )
    parser.add_argument(
        '--check-implementation', '-i',
        action='store_true',
        help='Also check that all PAL functions are implemented'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Only show violations, not summary'
    )
    
    args = parser.parse_args()
    
    if not args.quiet:
        print(f"Scanning {args.directory} for PAL violations...")
        print()
    
    checker = PALChecker(args.directory)
    checker.scan()
    
    if args.check_implementation:
        if not args.quiet:
            print("Checking PAL implementation completeness...")
            print()
        checker.check_pal_implementation()
    
    exit_code = checker.report()
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
