"""Breadth-first differential conformance across EVERY xrdfs subcommand.

This suite is deliberately wide rather than deep: it exercises the whole
`xrdfs` command surface (ls / stat / statvfs / locate / query{config,checksum,
opaque,space,stats} / cat / tail / mkdir / rmdir / rm / mv / chmod / truncate /
prepare / spaceinfo) and compares results across the four conformance
quadrants. The narrow field-level oracles live in test_conf_stat.py; the
transfer-option breadth lives in test_conf_client.py. This file owns the
"does every subcommand behave the same on our server as on the reference"
question, plus the Q2 axis "does our xrdfs client behave the same as the
reference client against the reference server".

Quadrants (see official_interop_lib.py):
  * STOCK xrdfs -> OUR server   vs   STOCK xrdfs -> STOCK server  (the gold diff)
  * OUR   xrdfs -> STOCK server (Q2: a failure is a BUG IN OUR CLIENT)

Philosophy (per the maintainer): a divergence is a bug in THIS implementation
unless there is positive evidence otherwise. The stock toolchain is the oracle;
we pin to it. Where the stock *data server* lacks a feature (e.g. the checksum
plugin) the test asserts category parity and, where the prompt demands it,
falls back to an independent oracle (zlib.adler32) so OUR server is still held
to a correct answer.

Self-provisioning on high ports; the whole module skips without the stock
xrootd toolchain. Mutation paths are unique per test so the shared module
fixture stays deterministic.
"""

import os
import subprocess
import zlib

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]

OUR_PORT = L.worker_port(14034)
OFF_PORT = L.worker_port(14035)
# --------------------------------------------------------------------------- #
# Module fixture — our server + stock server on identical rich trees.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("confxrdfs"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair launch failed: {e}")
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# Runners — `fs` is the STOCK xrdfs (the probe); `ourfs` is OUR xrdfs (Q2).
# --------------------------------------------------------------------------- #
def fs(url, *args, timeout=60):
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


def ourfs(url, *args, timeout=60):
    return L.run([L.OUR_XRDFS, url, *args], timeout=timeout)


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #
def _names(out):
    """Basenames of an `ls` listing, dropping any internal artifacts."""
    names = set()
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        base = os.path.basename(s.rstrip("/"))
        if base.startswith(".nginx-xrootd"):
            continue
        names.add(base)
    return names


def _fields(out):
    """Parse 'Key: value' output (stat / statvfs / spaceinfo) into a dict."""
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            d[k.strip()] = v.strip()
    return d


def _read(p):
    with open(p, "rb") as f:
        return f.read()


def _ondisk(srv, side, rel):
    return os.path.join(srv[f"{side}_data"], rel.lstrip("/"))


# =========================================================================== #
# ls — plain, file, dir, empty, nonexistent, -l, -R                           (10)
# =========================================================================== #
