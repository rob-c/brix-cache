#!/usr/bin/env python3
"""Check PAL header/definition ownership and configured common API source closure.

This is a source-structure gate, not proof of native ABI or runtime portability.
VFS guards own storage syscalls and mutation policy; existing OS adapters and
portable network byte-order functions are not a PAL migration violation.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from pal_source_contract import (
    COMMON_API, INLINE_API, HOSTS, configured_sources, definitions,
    include_targets, is_owner, production_files, repository_root,
    private_pal_header,
)


class PALChecker:
    """Judge explicit ownership and actual function bodies in selected sources."""

    def __init__(self, root_dir):
        self.root_dir = Path(root_dir)
        self.root = repository_root(self.root_dir)
        self.violations = []
        self.files_scanned = 0

    def check_source(self, path, content):
        if is_owner(path):
            return
        for line, target in include_targets(content):
            if private_pal_header(path, target):
                self.violations.append(
                    f'{path}:{line}: private PAL header {target}; use a public umbrella')
        for name, line in definitions(content):
            self.violations.append(
                f'{path}:{line}: PAL definition {name} outside its implementation owner')

    def scan(self):
        try:
            files = production_files(self.root)
            for path in files:
                self.check_source(path.relative_to(self.root), path.read_text())
            self.files_scanned = len(files)
        except (OSError, ValueError) as error:
            self.violations.append(f'source scan failed: {error}')

    def _definition_sites(self, paths):
        sites = {}
        for relative in paths:
            path = self.root / relative
            for name, line in definitions(path.read_text()):
                sites.setdefault(name, []).append(f'{relative}:{line}')
        return sites

    def _require_bodies(self, label, paths, required):
        sites = self._definition_sites(paths)
        for name in required:
            owners = sites.get(name, [])
            if len(owners) != 1:
                self.violations.append(
                    f'{label}: {name} requires one actual definition; '
                    f'found {len(owners)}: {", ".join(owners)}')

    def check_pal_implementation(self):
        try:
            selection = configured_sources(self.root)
            for host in HOSTS:
                self._require_bodies(host, selection[host], COMMON_API)
            self._require_inline_api()
        except (OSError, ValueError) as error:
            self.violations.append(f'implementation source closure failed: {error}')

    def _require_inline_api(self):
        umbrella = self.root / 'src/platform/platform_api.h'
        included = {target for _, target in include_targets(umbrella.read_text())}
        if 'platform_api_endian.h' not in included:
            raise ValueError('public PAL umbrella does not include common endian API')
        self._require_bodies(
            'public inline API', ['src/platform/platform_api_endian.h'], INLINE_API)

    def report(self, quiet=False):
        for message in self.violations:
            print(message)
        if not quiet:
            verdict = 'FAIL' if self.violations else 'OK'
            print(f'check_pal_seam: {verdict} ({self.files_scanned} production files; '
                  'ownership and common API source closure only)')
        return int(bool(self.violations))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', '-d', default=str(Path(__file__).resolve().parents[2]),
                        help='repository root or its src directory')
    parser.add_argument('--check-implementation', '-i', action='store_true',
                        help='compatibility flag; common API source closure is always checked')
    parser.add_argument('--quiet', '-q', action='store_true')
    args = parser.parse_args(argv)
    checker = PALChecker(args.directory)
    checker.scan()
    checker.check_pal_implementation()
    return checker.report(args.quiet)


if __name__ == '__main__':
    raise SystemExit(main())
