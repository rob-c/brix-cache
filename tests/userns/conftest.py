"""Standalone conftest for tests/userns/.

Its presence (together with pytest.ini in this directory)
keeps the user-namespace impersonation tests self-contained: when invoked as
`pytest tests/userns/`, pytest's rootdir resolves here and the parent
`tests/conftest.py` — which starts the whole nginx server fleet in
pytest_sessionstart — is not collected.  These tests fork their own broker inside
a user namespace and need none of that infrastructure. Only expose tests/ on
the import path so standalone native drivers reuse the canonical nginx SDK
header layout, including QUIC and a separate configured object directory.
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
