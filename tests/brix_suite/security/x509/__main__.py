"""``python -m brix_suite.security.x509 [outdir]`` -- forge every scenario.

The flat stack carried this as a bare ``if __name__ == "__main__":`` at the
foot of ``x509forge_part3.py``.  That fired only because shard 3 was
``exec``-ed into ``x509forge.py``'s globals and so saw the parent's
``__name__``; under real imports the guard belongs to the shard and never fires
for someone running ``x509forge.py``.  The same trap silently disarmed the
token forge's ``fleet-artifacts`` CLI earlier in TS-5, so the entry point is a
named function here and both spellings call it.
"""

from pathlib import Path

from brix_suite.security.x509.catalogue import forge_all


def main(argv=None):
    import sys

    argv = sys.argv[1:] if argv is None else list(argv)
    out = Path(argv[0] if argv else "/tmp/x509conf")
    forged = forge_all(out)
    for nm, sc in forged.items():
        print(f"{nm}: {len(sc.manifest)} manifest entries \u2192 {sc.dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
