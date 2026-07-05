"""
flag_inventory — the authoritative stock client surface, parsed from source.

WHAT
    Extracts the set of stock ``xrdcp`` options and ``xrdfs`` sub-commands
    directly from the upstream sources under ``/tmp/brix-src`` so coverage is
    measured against the REAL stock surface, not a hand-kept guess.

WHY
    Two guarantees fall out of this:
      1. every stock flag/command must be exercised by at least one case
         (a rebased upstream that adds a flag is reported as untested), and
      2. every project-only flag must be registered as a divergence
         (so an added knob cannot silently bypass review).

HOW
    ``stock_xrdcp_options()`` parses the ``{OPT_TYPE "name", takes_arg, ...}``
    table in ``XrdApps/XrdCpConfig.cc``.  ``stock_xrdfs_commands()`` parses the
    ``executor->AddCommand("name", ...)`` registrations in
    ``XrdCl/XrdClFS.cc``.  Both degrade to a pinned fallback list (with a clear
    marker) when the source tree is absent, so the suite still runs on a host
    without ``/tmp/brix-src``.
"""

import os
import re

BRIX_SRC = os.environ.get("BRIX_SRC_DIR", "/tmp/brix-src")
_CPCONFIG = os.path.join(BRIX_SRC, "src", "XrdApps", "XrdCpConfig.cc")
_FS = os.path.join(BRIX_SRC, "src", "XrdCl", "XrdClFS.cc")

# Pinned fallbacks (kept in sync with the sources above) for hosts without the
# upstream checkout.  ``source_available()`` lets a test note when it is using
# the fallback rather than the live parse.
_FALLBACK_XRDCP = {
    "cksum": 1, "coerce": 0, "continue": 0, "debug": 1, "dynamic-src": 0,
    "force": 0, "help": 0, "infiles": 1, "license": 0, "nopbar": 0,
    "notlsok": 0, "parallel": 1, "path": 0, "posc": 0, "proxy": 1,
    "recursive": 0, "retry": 1, "retry-policy": 1, "rm-bad-cksum": 0,
    "server": 0, "silent": 0, "sources": 1, "streams": 1, "tlsmetalink": 0,
    "tlsnodata": 0, "tpc": 1, "verbose": 0, "version": 0, "xattr": 0,
    "xrate": 1, "xrate-threshold": 1, "zip": 1, "zip-append": 0,
    "zip-mtln-cksum": 0,
}
_FALLBACK_XRDFS = [
    "cache", "cd", "chmod", "ls", "help", "stat", "statvfs", "locate", "mv",
    "mkdir", "rm", "rmdir", "query", "truncate", "prepare", "cat", "tail",
    "spaceinfo", "xattr",
]


def source_available():
    """True when the upstream source tree is present for live parsing."""
    return os.path.exists(_CPCONFIG) and os.path.exists(_FS)


def stock_xrdcp_options():
    """Map of stock xrdcp long-option name -> takes-argument (1/0).

    Parses lines of the form ``{OPT_TYPE "name", 1, 0, XrdCpConfig::OpXxx},``.
    """
    if not os.path.exists(_CPCONFIG):
        return dict(_FALLBACK_XRDCP)
    rx = re.compile(r'\{\s*OPT_TYPE\s+"([a-zA-Z][a-zA-Z0-9-]*)"\s*,\s*(\d)')
    out = {}
    with open(_CPCONFIG, "r", errors="replace") as fh:
        for line in fh:
            m = rx.search(line)
            if m:
                out[m.group(1)] = int(m.group(2))
    return out or dict(_FALLBACK_XRDCP)


def stock_xrdfs_commands():
    """List of stock xrdfs sub-command names (excluding shell-only cd/help)."""
    if not os.path.exists(_FS):
        cmds = list(_FALLBACK_XRDFS)
    else:
        rx = re.compile(r'AddCommand\(\s*"([a-zA-Z][a-zA-Z0-9-]*)"')
        cmds = []
        with open(_FS, "r", errors="replace") as fh:
            for line in fh:
                m = rx.search(line)
                if m:
                    cmds.append(m.group(1))
        cmds = cmds or list(_FALLBACK_XRDFS)
    # cd/help are interactive-shell affordances, not wire operations.
    return [c for c in cmds if c not in ("cd", "help")]
