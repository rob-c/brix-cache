"""
corpus — the deterministic server-side data set the read-only cases run over.

WHAT
    A fixed tree of files (varied sizes, names, nesting) seeded once under the
    shared data root that every endpoint exports.  Read-only cases (stat, ls,
    cat, download, cksum, ...) fan out over this corpus, which is the honest way
    the suite reaches its scale: each (operation × corpus-entry × endpoint) is a
    real path/size/name combination, not a duplicated assertion.

WHY
    All five endpoints (anon/gsi/tls/token nginx + ref xrootd) export the same
    on-disk directory, so seeding once makes the corpus visible everywhere and
    keeps stock-vs-ours comparisons reading identical server truth.

HOW
    ``seed(root)`` writes the tree deterministically (content is a function of
    name+size, so re-seeding is idempotent and reproducible).  ``FILES`` /
    ``DIRS`` / the ``*_NAMES`` lists drive parametrization in the case tables.
"""

import hashlib
import os

# Namespace so the suite's fixtures never collide with other tests' artefacts
# under the shared data root.
PREFIX = "clientconf"


def _content(name, size):
    """Deterministic bytes for (name, size): a keystream seeded by the name."""
    if size == 0:
        return b""
    seed = hashlib.sha256(name.encode()).digest()
    out = bytearray()
    block = seed
    while len(out) < size:
        block = hashlib.sha256(block).digest()
        out.extend(block)
    return bytes(out[:size])


# (relpath-under-PREFIX, size) — varied sizes incl. page boundaries and odd
# lengths that exercise short-read/last-page handling.
_FILE_SPECS = [
    ("empty.bin", 0),
    ("one.bin", 1),
    ("two.bin", 2),
    ("tiny.txt", 13),
    ("sub1023.bin", 1023),
    ("page.bin", 4096),
    ("page_plus.bin", 4097),
    ("sub4095.bin", 4095),
    ("k32.bin", 32768),
    ("k64.bin", 65536),
    ("k128.bin", 131072),
    ("odd_12345.bin", 12345),
    ("odd_99991.bin", 99991),
    ("mib1.bin", 1 << 20),
    # name edge cases (all POSIX-safe, no shell metachars)
    ("name.with.dots.bin", 257),
    ("name-with-dashes.bin", 333),
    ("name_with_underscores.bin", 480),
    ("UPPER_and_mixed.BIN", 512),
    ("spaces are ok.bin", 200),
    # nested
    ("d1/inner.bin", 2050),
    ("d1/d2/leaf.bin", 700),
    ("d1/d2/d3/deep.bin", 4095),
]

# Directories that must exist (for ls / rmdir-on-nonempty / tree tests).
_DIRS = ["d1", "d1/d2", "d1/d2/d3", "emptydir"]


class Entry:
    """A seeded corpus file: its remote path and authoritative fingerprint."""

    def __init__(self, rel, size):
        self.rel = rel                       # path under PREFIX
        self.size = size
        self.remote = "/%s/%s" % (PREFIX, rel)   # absolute server path

    @property
    def name(self):
        return self.rel

    def __repr__(self):
        return "<Entry %s %dB>" % (self.remote, self.size)


FILES = [Entry(rel, size) for rel, size in _FILE_SPECS]
BY_REL = {e.rel: e for e in FILES}

# Parametrization slices (kept small + meaningful per category).
ALL_NAMES = [e.rel for e in FILES]
SMALL_NAMES = [e.rel for e in FILES if e.size <= 4097]
NONEMPTY_NAMES = [e.rel for e in FILES if e.size > 0]
TEXTISH_NAMES = ["tiny.txt", "page.bin", "sub1023.bin"]
EDGE_NAME_NAMES = ["name.with.dots.bin", "name-with-dashes.bin",
                   "UPPER_and_mixed.BIN", "spaces are ok.bin"]
NESTED_NAMES = ["d1/inner.bin", "d1/d2/leaf.bin", "d1/d2/d3/deep.bin"]

DIRS = list(_DIRS)
ROOT = "/%s" % PREFIX


def seed(root):
    """Create the corpus under ``root`` (idempotent). Returns the FILES list."""
    base = os.path.join(root, PREFIX)
    for d in _DIRS:
        os.makedirs(os.path.join(base, d), exist_ok=True)
    for e in FILES:
        path = os.path.join(base, e.rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = _content(e.rel, e.size)
        # Idempotent: only (re)write when missing or wrong size.
        if not os.path.exists(path) or os.path.getsize(path) != e.size:
            with open(path, "wb") as fh:
                fh.write(data)
    return FILES


def local_bytes(entry):
    """The authoritative bytes for a corpus entry (for byte-compare/cksum)."""
    return _content(entry.rel, entry.size)
