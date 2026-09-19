"""
flag_inventory — the stock client surface this project measures coverage against.

WHAT
    The set of stock ``xrdcp`` options and ``xrdfs`` sub-commands the project's
    own tools are expected to cover, as a pinned table maintained here.

WHY
    Two guarantees fall out of this:
      1. every stock flag/command must be exercised by at least one case
         (a flag added to the table is reported as untested until covered), and
      2. every project-only flag must be registered as a divergence
         (so an added knob cannot silently bypass review).

    This table used to be parsed live out of a checkout of the upstream XRootD
    sources.  That reliance on the XRootD project's source tree has been removed: the
    suite must build and run from this repository alone, and a clean-room
    client must not have its test surface derived by reading upstream code.
    The surface below is the observable command-line contract — the flag names
    a user types — which is what conformance is measured against.

HOW
    ``stock_xrdcp_options()`` and ``stock_xrdfs_commands()`` return copies of
    the tables so callers cannot mutate the shared inventory. Extending the
    surface is a deliberate edit here, reviewed like any other change.
"""

# Stock xrdcp long-option name -> takes an argument (1) or is a switch (0).
_STOCK_XRDCP = {
    "cksum": 1, "coerce": 0, "continue": 0, "debug": 1, "dynamic-src": 0,
    "force": 0, "help": 0, "infiles": 1, "license": 0, "nopbar": 0,
    "notlsok": 0, "parallel": 1, "path": 0, "posc": 0, "proxy": 1,
    "recursive": 0, "retry": 1, "retry-policy": 1, "rm-bad-cksum": 0,
    "server": 0, "silent": 0, "sources": 1, "streams": 1, "tlsmetalink": 0,
    "tlsnodata": 0, "tpc": 1, "verbose": 0, "version": 0, "xattr": 0,
    "xrate": 1, "xrate-threshold": 1, "zip": 1, "zip-append": 0,
    "zip-mtln-cksum": 0,
}

# Stock xrdfs sub-commands, including the shell-only ones filtered out below.
_STOCK_XRDFS = [
    "cache", "cd", "chmod", "ls", "help", "stat", "statvfs", "locate", "mv",
    "mkdir", "rm", "rmdir", "query", "truncate", "prepare", "cat", "tail",
    "spaceinfo", "xattr",
]


def stock_xrdcp_options():
    """Map of stock xrdcp long-option name -> takes-argument (1/0)."""
    return dict(_STOCK_XRDCP)


def stock_xrdfs_commands():
    """List of stock xrdfs sub-command names (excluding shell-only cd/help)."""
    return [command for command in _STOCK_XRDFS if command not in ("cd", "help")]
