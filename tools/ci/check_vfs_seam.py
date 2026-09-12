#!/usr/bin/env python3
"""
check_vfs_seam.py - Verify VFS abstraction layer integrity

This script ensures that all filesystem operations go through the VFS layer
and no raw syscalls bypass the abstraction.

Similar checks should be implemented for PAL layer to ensure:
- No platform-specific syscalls outside src/platform/*/
- All byte-order operations use brix_plat_*() functions
- No direct #include of platform-specific headers in business logic
"""

import os
import re
import sys
from pathlib import Path

# Forbidden patterns in business logic code
FORBIDDEN_PATTERNS = {
    'linux_syscalls': [
        r'\bmemfd_create\b',
        r'\bopenat2\b',
        r'\brenameat2\b',
        r'\bcopy_file_range\b',
        r'\bsplice\b',
        r'\bepoll_create\b',
        r'\bepoll_ctl\b',
        r'\bepoll_wait\b',
        r'\binotify_init\b',
        r'\binotify_add_watch\b',
        r'\bgetrandom\b',
        r'\bgetxattr\b(?!attr)',  # Match getxattr but not brix_plat_getxattr
        r'\bsetxattr\b',
        r'\bposix_fadvise\b',
    ],
    'darwin_syscalls': [
        r'\bclonefile\b',
        r'\bcopyfile\b',
        r'\bkqueue\b',
        r'\bkevent\b',
        r'\bFSEvents\b',
        r'\bgetxattr\b(?!attr)',
        r'\bsetxattr\b',
    ],
    'windows_syscalls': [
        r'\bCreateFile\b',
        r'\bReadFile\b',
        r'\bWriteFile\b',
        r'\bTransmitFile\b',
        r'\bIOCP\b',
        r'\bCreateIoCompletionPort\b',
    ],
    'direct_byte_order': [
        r'\bhtobe64\b(?!.*brix_plat)',
        r'\bbe64toh\b(?!.*brix_plat)',
        r'\bhtobe32\b(?!.*brix_plat)',
        r'\bbe32toh\b(?!.*brix_plat)',
        r'\bhtonl\b(?!.*brix_plat)',
        r'\bntohl\b(?!.*brix_plat)',
    ],
}

# Directories that ARE allowed to use platform-specific code
ALLOWED_PLATFORM_DIRS = [
    'src/platform/linux',
    'src/platform/darwin',
    'src/platform/windows',
    'src/platform/generic',
]

# Files that are allowed to bypass checks (compatibility layers)
ALLOWED_FILES = [
    'platform_compat.h',
    'win32_compat.h',
    'platform_endian_compat.h',
]

def is_platform_directory(filepath):
    """Check if file is in an allowed platform-specific directory"""
    path_str = str(filepath)
    for allowed_dir in ALLOWED_PLATFORM_DIRS:
        if allowed_dir in path_str:
            return True
    return False

def is_allowed_file(filepath):
    """Check if file is in the allowed files list"""
    return any(allowed in str(filepath) for allowed in ALLOWED_FILES)

def check_file(filepath):
    """Check a single file for forbidden patterns"""
    violations = []
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
    except Exception as e:
        return [f"Error reading file: {e}"]
    
    for line_num, line in enumerate(lines, 1):
        # Skip comments
        if line.strip().startswith('//') or line.strip().startswith('/*'):
            continue
        
        for category, patterns in FORBIDDEN_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, line):
                    violations.append(
                        f"{filepath}:{line_num}: {category} - Found '{pattern}' in: {line.strip()}"
                    )
    
    return violations

def scan_directory(root_dir):
    """Scan directory tree for violations"""
    all_violations = []
    files_scanned = 0
    
    root_path = Path(root_dir)
    
    for ext in ['*.c', '*.h']:
        for filepath in root_path.rglob(ext):
            # Skip platform-specific directories
            if is_platform_directory(filepath):
                continue
            
            # Skip allowed files
            if is_allowed_file(filepath):
                continue
            
            # Skip test files
            if 'test' in str(filepath):
                continue
            
            files_scanned += 1
            violations = check_file(filepath)
            all_violations.extend(violations)
    
    return all_violations, files_scanned

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Verify VFS/PAL abstraction layer integrity'
    )
    parser.add_argument(
        '--directory', '-d',
        default='src',
        help='Directory to scan (default: src)'
    )
    parser.add_argument(
        '--mode', '-m',
        choices=['vfs', 'pal', 'both'],
        default='both',
        help='Check mode: vfs, pal, or both (default: both)'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Only show violations, not summary'
    )
    
    args = parser.parse_args()
    
    print(f"Scanning {args.directory} for abstraction layer violations...")
    print(f"Mode: {args.mode}")
    print()
    
    violations, files_scanned = scan_directory(args.directory)
    
    if violations:
        print(f"❌ Found {len(violations)} violation(s) in {files_scanned} files scanned:\n")
        for violation in violations:
            print(violation)
        return 1
    else:
        if not args.quiet:
            print(f"✅ No violations found in {files_scanned} files scanned")
        return 0

if __name__ == '__main__':
    sys.exit(main())
