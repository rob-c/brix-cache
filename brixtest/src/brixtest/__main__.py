"""``python -m brixtest`` — same entry point as the installed CLI."""

from brixtest.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
