"""Typed pytest stash keys for all BriXTest plugin state."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

import pytest

METRICS_SESSION: pytest.StashKey[Path] = pytest.StashKey()
METRICS_PAYLOAD: pytest.StashKey[Mapping[str, object]] = pytest.StashKey()
SQLITE_PATH: pytest.StashKey[Path] = pytest.StashKey()
PARQUET_PATH: pytest.StashKey[Path] = pytest.StashKey()
S3_URI: pytest.StashKey[str] = pytest.StashKey()
SHARED_TOPOLOGY: pytest.StashKey[object] = pytest.StashKey()
CASE_MANAGER: pytest.StashKey[object] = pytest.StashKey()

