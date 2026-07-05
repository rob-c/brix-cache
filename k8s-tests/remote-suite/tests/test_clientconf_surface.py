"""
Client-conformance: CLI-surface coverage.

Proves the project tools' flag/command surface is reconciled with stock:

  * every stock xrdcp flag (live parse of XrdCpConfig.cc) is classified in
    surface_map.yaml — a new upstream flag with no entry FAILS as "unmapped";
  * the map does not classify flags stock no longer has;
  * every stock xrdfs command (live parse of XrdClFS.cc) is classified;
  * every project-only extra is genuinely advertised by our client's --help,
    so the divergence documentation cannot drift from the binary.

These tests need only our binaries + the stock source tree; they do not touch a
server, so they run even when every endpoint is down.
"""

import shutil
import subprocess

import pytest

from clientconf import flag_inventory as fi
from clientconf import surface
from clientconf.diffcore import binary

VALID_STATUS = {"same", "alias", "default", "unsupported"}


def _our_help(tool):
    path = binary("ours", tool)
    if path is None:
        pytest.skip("our %s not built" % tool)
    proc = subprocess.run([path, "--help"], capture_output=True, text=True,
                          timeout=30)
    # tools may print help to stdout or stderr and exit non-zero
    return (proc.stdout or "") + (proc.stderr or "")


# --------------------------------------------------------------------------- #
# xrdcp flag surface                                                          #
# --------------------------------------------------------------------------- #
def test_every_stock_xrdcp_flag_is_classified():
    stock = set(fi.stock_xrdcp_options())
    mapped = set(surface.xrdcp_flags())
    missing = stock - mapped
    assert not missing, (
        "stock xrdcp flags with no surface_map entry (untested surface): %s"
        % sorted(missing))


def test_no_stale_xrdcp_flag_classifications():
    stock = set(fi.stock_xrdcp_options())
    mapped = set(surface.xrdcp_flags())
    stale = mapped - stock
    assert not stale, (
        "surface_map classifies xrdcp flags stock no longer has: %s"
        % sorted(stale))


@pytest.mark.parametrize("flag,info", sorted(surface.xrdcp_flags().items()))
def test_xrdcp_flag_status_valid(flag, info):
    assert info.get("status") in VALID_STATUS, \
        "flag %s has invalid status %r" % (flag, info.get("status"))


@pytest.mark.parametrize("flag", sorted(surface.xrdcp_extras()))
def test_xrdcp_extra_is_advertised(flag):
    help_text = _our_help("xrdcp")
    assert flag in help_text, \
        "project-only flag %s not advertised in xrdcp --help" % flag


# --------------------------------------------------------------------------- #
# xrdfs command surface                                                       #
# --------------------------------------------------------------------------- #
def test_every_stock_xrdfs_command_is_classified():
    stock = set(fi.stock_xrdfs_commands())
    mapped = set(surface.xrdfs_commands())
    missing = stock - mapped
    assert not missing, (
        "stock xrdfs commands with no surface_map entry: %s" % sorted(missing))


def test_no_stale_xrdfs_command_classifications():
    stock = set(fi.stock_xrdfs_commands())
    mapped = set(surface.xrdfs_commands())
    stale = mapped - stock
    assert not stale, (
        "surface_map classifies xrdfs commands stock no longer has: %s"
        % sorted(stale))


@pytest.mark.parametrize("cmd,info", sorted(surface.xrdfs_commands().items()))
def test_xrdfs_command_status_valid(cmd, info):
    assert info.get("status") in VALID_STATUS, \
        "command %s has invalid status %r" % (cmd, info.get("status"))


@pytest.mark.parametrize("cmd", sorted(surface.xrdfs_extras()))
def test_xrdfs_extra_is_advertised(cmd):
    help_text = _our_help("xrdfs")
    assert cmd in help_text, \
        "project-only xrdfs sub-command %s not advertised in --help" % cmd


def test_source_tree_present_for_live_parse():
    # Not a hard requirement (fallbacks exist), but record when we are running
    # against the pinned fallback rather than the live upstream surface.
    if not fi.source_available():
        pytest.skip("xrootd source tree absent — using pinned fallback surface")
    assert shutil.which  # trivial truthy; the skip above carries the signal
