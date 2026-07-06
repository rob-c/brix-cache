#!/usr/bin/env python3
"""
migrate_composable_root.py — rewrite legacy export-root directives to the phase-64
composable storage-backend grammar in test configs / scripts.

  brix_export        <path>  ->  brix_storage_backend        posix:<path>
  brix_export <path>  ->  brix_storage_backend posix:<path>
  brix_export     <path>  ->  brix_storage_backend     posix:<path>

A `posix:<path>` storage backend is a verified drop-in for the legacy root (the
brix_storage_backend_posix_root helper rewrites common->root to <path>); this holds
for read AND write across stream / webdav / s3.

SAFETY:
  * A file that already carries ANY composable/cache/stage/origin directive ("Group B")
    is one where the root is a local anchor beside a remote backend or a cache
    materialisation dir — a naive posix: swap would emit a duplicate directive or break
    cache semantics. Such files are SKIPPED (reported) and migrated deliberately, not by
    this mechanical pass. Detected: *storage_backend, brix_cache*, brix_write_through,
    *storage_staging, brix_stage*.
  * Comment lines (#, //, *) and doc prose are left untouched.
  * The value token (incl. {TEMPLATE} placeholders, $VARS) is preserved verbatim.

Usage:
  migrate_composable_root.py --dry-run <file>...    # show diffs, change nothing
  migrate_composable_root.py <file>...              # apply in place
"""
import re
import sys

# the root directive (optional proto infix) + ws + value + ';' — matched ANYWHERE on a
# line, so a one-liner `stream { server { ...; brix_export X; ... } }` is handled too.
ROOT_TOKEN = re.compile(
    r'\bxrootd(?P<proto>_webdav|_s3)?_root(?P<ws>\s+)(?P<val>\S+?)(?P<semi>\s*;)'
)
# A file that carries ANY composable backend or cache/stage tier ("Group B") is one
# whose remaining brix_export lines are namespace ANCHORS beside a remote backend (or
# cache-materialisation dirs). A naive posix: swap there would duplicate a
# storage_backend within the block or break cache semantics — and reliable block
# detection is unsafe because the embedded heredoc/f-string configs use ${VAR} / {PH}
# braces that defeat brace-counting. So such files are SKIPPED whole and migrated
# deliberately; only PURELY legacy plain-export files are rewritten mechanically.
GROUP_B = re.compile(
    r'xrootd(_webdav|_s3)?_storage_backend'
    r'|xrootd(_webdav|_s3)?_cache'
    r'|xrootd(_webdav|_s3)?_stage'
    r'|xrootd(_webdav|_s3)?_write_through'
    r'|storage_staging'
)
COMMENT = re.compile(r'^\s*(#|//|\*)')


def _swap(m):
    proto = m.group('proto') or ''
    return (f"xrootd{proto}_storage_backend{m.group('ws')}"
            f"posix:{m.group('val')}{m.group('semi')}")


def migrate_text(text):
    """Return (new_text, n_changed). Caller skips legacy-cache files up front."""
    out, n = [], 0
    for line in text.splitlines(keepends=True):
        nl = '\n' if line.endswith('\n') else ''
        body = line[:-1] if nl else line
        if COMMENT.match(body) or not ROOT_TOKEN.search(body):
            out.append(line)
            continue
        newbody, k = ROOT_TOKEN.subn(_swap, body)
        out.append(newbody + nl)
        n += k
    return ''.join(out), n


def is_group_b(text):
    for line in text.splitlines():
        if COMMENT.match(line):
            continue
        if GROUP_B.search(line):
            return True
    return False


def main(argv):
    dry = '--dry-run' in argv
    files = [a for a in argv[1:] if not a.startswith('--')]
    changed_files, skipped, total = 0, [], 0
    for path in files:
        try:
            with open(path, 'r') as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError) as e:
            print(f"  ERR  {path}: {e}", file=sys.stderr)
            continue
        if is_group_b(text):
            skipped.append(path)
            continue
        new, n = migrate_text(text)
        if n == 0:
            continue
        total += n
        changed_files += 1
        if dry:
            print(f"  would change {path} ({n} directive(s))")
        else:
            with open(path, 'w') as fh:
                fh.write(new)
            print(f"  migrated {path} ({n} directive(s))")
    print(f"\n{'DRY-RUN: ' if dry else ''}{changed_files} file(s), "
          f"{total} directive(s); {len(skipped)} Group-B file(s) skipped")
    if skipped:
        print("Skipped (already composable / cache-stage — migrate deliberately):")
        for s in skipped:
            print(f"  {s}")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
