#!/usr/bin/env python3
"""BriX rebrand engine — deterministic, idempotent, case-sensitive token rewrite.

Renames the project's OWN namespace (xrootd_/XROOTD_/ngx_xrootd*/xrdc_) to the
BriX namespace, leaving upstream XRootD/protocol references untouched. Rules are
anchored (trailing '_' or \\b) so prose 'XRootD', 'root://', 'nginx-xrootd', and
tool names 'xrdcp'/'xrdfs' are never matched. Non-underscore self-references
(dashboard routes, log prefixes) are handled by Task 2, NOT here. See
docs/refactor/2026-07-03-brix-symbol-rebrand.md for the authoritative rule table.
"""
import argparse
import os
import re
import sys

SERVER_RULES = [
    (re.compile(r'ngx_http_xrootd_'),   'ngx_http_brix_'),
    (re.compile(r'ngx_stream_xrootd_'), 'ngx_stream_brix_'),
    (re.compile(r'ngx_xrootd_'),        'ngx_brix_'),
    (re.compile(r'XROOTD_'),            'BRIX_'),
    (re.compile(r'xrootd_'),            'brix_'),
]
CLIENT_RULES = [
    (re.compile(r'libxrdposix_preload'), 'libbrixposix_preload'),
    (re.compile(r'xrdposix_preload'),    'brixposix_preload'),
    (re.compile(r'libxrdc'),             'libbrix'),
    (re.compile(r'xrdc_'),               'brix_'),
    (re.compile(r'\bxrdc\b'),            'brix'),
]

EXCLUDE = {
    'docs/refactor/phase-66-map.tsv',
    'docs/refactor/phase-67-map.tsv',
    'docs/09-developer-guide/postmortem-shmtx-semaphore-stall.md',
    'docs/refactor/2026-07-03-brix-symbol-rebrand.md',
    'tools/refactor/brix_rebrand.py',
    'tools/refactor/brix_verify.sh',
    '.git-blame-ignore-revs',
}


def rules_for(scope):
    return CLIENT_RULES if scope == 'client' else SERVER_RULES


def is_binary(path):
    try:
        with open(path, 'rb') as fh:
            return b'\x00' in fh.read(8192)
    except OSError:
        return True


def iter_files(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
        else:
            for root, _dirs, files in os.walk(p):
                for name in files:
                    yield os.path.join(root, name)


def rewrite_text(text, rules):
    out, changed = [], 0
    for line in text.splitlines(keepends=True):
        new = line
        for pat, repl in rules:
            new = pat.sub(repl, new)
        if new != line:
            changed += 1
        out.append(new)
    return ''.join(out), changed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--scope', choices=('server', 'client', 'docs'), required=True)
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--emit-map', metavar='PATH')
    ap.add_argument('paths', nargs='+')
    args = ap.parse_args()
    rules = rules_for(args.scope)

    total_files = total_lines = 0
    mapping = {}
    token_re = re.compile(r'"(xrootd_[a-z0-9_]+|XROOTD_[A-Z0-9_]+)"')

    for path in iter_files(args.paths):
        rel = os.path.relpath(path)
        if rel in EXCLUDE or is_binary(path):
            continue
        with open(path, 'r', encoding='utf-8', errors='surrogateescape') as fh:
            original = fh.read()
        new_text, changed = rewrite_text(original, rules)
        if changed == 0:
            continue
        total_files += 1
        total_lines += changed
        if args.emit_map:
            for m in token_re.finditer(original):
                old = m.group(1)
                new, _ = rewrite_text(old, rules)
                mapping[old] = new
        if args.dry_run:
            print(f'--- {rel}  ({changed} lines)')
        else:
            with open(path, 'w', encoding='utf-8', errors='surrogateescape') as fh:
                fh.write(new_text)

    if args.emit_map and mapping:
        with open(args.emit_map, 'w', encoding='utf-8') as fh:
            fh.write('# BriX rename migration map (old -> new)\n')
            for old in sorted(mapping):
                fh.write(f'{old}\t{mapping[old]}\n')

    verb = 'would change' if args.dry_run else 'changed'
    print(f'{verb} {total_lines} lines in {total_files} files (scope={args.scope})',
          file=sys.stderr)


if __name__ == '__main__':
    main()
