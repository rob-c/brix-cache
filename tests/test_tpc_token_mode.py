"""
tests/test_tpc_token_mode.py

Tests for the native XRootD TPC OAuth2/OIDC token delegation opaque parameter
parser.  Verifies that tpc.token_mode is correctly parsed from the opaque
query string appended to a kXR_open path.

Run:
    pytest tests/test_tpc_token_mode.py -v
"""

import os
import sys
from pathlib import Path

import pytest

# Ensure test helpers are importable
sys.path.insert(0, str(Path(__file__).parent))

from tpc_parse_helpers import (
    parse_tpc_opaque,
    TpcOpaqueResult,
)


class TestTpcTokenModeParsing:
    """Unit tests for tpc.token_mode opaque parameter parsing."""

    def test_token_mode_none(self):
        """tpc.token_mode=none is parsed and recorded."""
        result = parse_tpc_opaque(
            "/data/file.txt?tpc.src=root://src//data&tpc.token_mode=none"
        )
        assert result.has_src
        assert result.has_token_mode
        assert result.token_mode == "none"

    def test_token_mode_oidc_agent(self):
        """tpc.token_mode=oidc-agent is parsed correctly."""
        result = parse_tpc_opaque(
            "/data/file.txt?tpc.src=root://src//data"
            "&tpc.token_mode=oidc-agent"
        )
        assert result.has_src
        assert result.has_token_mode
        assert result.token_mode == "oidc-agent"

    def test_token_mode_token_exchange(self):
        """tpc.token_mode=token-exchange is parsed correctly."""
        result = parse_tpc_opaque(
            "/data/file.txt?tpc.src=root://src//data"
            "&tpc.token_mode=token-exchange"
        )
        assert result.has_token_mode
        assert result.token_mode == "token-exchange"

    def test_token_mode_without_src(self):
        """tpc.token_mode can appear without tpc.src."""
        result = parse_tpc_opaque("/data/file.txt?tpc.token_mode=oidc-agent")
        assert result.has_token_mode
        assert result.token_mode == "oidc-agent"

    def test_no_token_mode(self):
        """Absent tpc.token_mode leaves has_token_mode=False."""
        result = parse_tpc_opaque("/data/file.txt?tpc.src=root://src//data")
        assert result.has_src
        assert not result.has_token_mode

    def test_token_mode_case_sensitive(self):
        """Token mode values are case-sensitive."""
        result = parse_tpc_opaque(
            "/data/file.txt?tpc.token_mode=OIDC-AGENT"
        )
        assert result.has_token_mode
        assert result.token_mode == "OIDC-AGENT"

    def test_token_mode_with_other_params(self):
        """tpc.token_mode coexists with other tpc.* parameters."""
        result = parse_tpc_opaque(
            "/data/file.txt?tpc.src=root://src//data"
            "&tpc.key=abc123"
            "&tpc.token_mode=token-exchange"
            "&tpc.org=origin@host"
        )
        assert result.has_src
        assert result.has_key
        assert result.has_token_mode
        assert result.has_org
        assert result.token_mode == "token-exchange"

    def test_token_mode_empty_value(self):
        """tpc.token_mode= (empty value) is parsed but empty."""
        result = parse_tpc_opaque("/data/file.txt?tpc.token_mode=")
        assert result.has_token_mode
        assert result.token_mode == ""

    def test_token_mode_long_value(self):
        """Long token_mode values are truncated to buffer size."""
        long_mode = "a" * 100
        result = parse_tpc_opaque(f"/data/file.txt?tpc.token_mode={long_mode}")
        assert result.has_token_mode
        assert len(result.token_mode) < 128  # field is 32 bytes
