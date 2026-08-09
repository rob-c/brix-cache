"""Differential conformance for `xrdcp` OPTION breadth, RECURSIVE copies,
multi-stream transfers, and round-trips — against BOTH our nginx-xrootd server
and the stock xrootd server (and exercising our own native xrdcp client).

Sibling files own the neighbouring ground; this file does not duplicate them:
  * test_official_interop.py  — broad xrdfs op matrix + a couple of xrdcp probes
  * test_conf_io_read.py      — the raw read data-plane (read/readv/pgread bytes)
  * test_conf_client.py       — Q2 client parity + a first slice of -f/-N/-s/-r

Here the focus is the `xrdcp` TRANSFER-OPTION surface itself, end to end:
  -f/--force, -N/--nopbar, -s/--silent, default(progress), -p/--path(MakeDir),
  --posc, --cksum (adler32:source / adler32:print), -r/--recursive (download,
  upload, whole-tree), -S/--streams (multi-stream), --retry, stdout("-") sink,
  stdin("-") source, the empty file, and large round-trips.

Philosophy (per the maintainer): a divergence is a BUG IN THIS IMPLEMENTATION
(our server, or our client) unless there is positive evidence otherwise. The
oracle is the stock toolchain on the stock server. Every assertion either:
  * pins stock-correct behaviour (the stock client/server is the reference), or
  * is DIFFERENTIAL (same op, our vs stock server, byte-compared), or
  * is a Q2 check of OUR client against the stock server.

When an xrdcp option is genuinely unsupported by the installed build, the test
asserts the only thing that is non-negotiable — that it does NOT corrupt data —
and REPORTS the option as unsupported via the captured output, rather than
silently passing as if the option worked.

Self-provisioning on dedicated high ports; skips entirely without the stock
toolchain (xrootd/xrdfs/xrdcp on PATH).

xrdcp option reference consulted (not modified):
  /tmp/brix-src/src/XrdApps/XrdCpConfig.cc   opLetters / opVec / defCks
  /tmp/brix-src/src/XrdClient .../XrdClClassicCopyJob.cc
"""

import hashlib
import os
import subprocess
import zlib

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]


# --------------------------------------------------------------------------- #
# Module fixture: our server + the stock server on identical rich data trees.  #
# Dedicated ports so this file never collides with the sibling suites.         #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("conf_xrdcp"))
    try:
        procs, ctx = L.start_pair(base, our_port=L.worker_port(14036), off_port=L.worker_port(14037))
    except Exception as e:  # noqa: BLE001 - any launch failure -> skip cleanly
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #
def _read(p):
    with open(p, "rb") as f:
        return f.read()


def _src_bytes(ctx, name):
    """Authoritative source bytes for `name` (identical on both data dirs)."""
    return _read(os.path.join(ctx["our_data"], name))


def _md5(b):
    return hashlib.md5(b).hexdigest()


def _adler_hex(b):
    return f"{zlib.adler32(b) & 0xffffffff:08x}"


def _timeout_for(name):
    return 180 if ("big1m" in name or name == "/") else 90


def _cp(xrdcp, *args, timeout=90):
    return L.run([xrdcp, *args], timeout=timeout)


def _download(xrdcp, url, name, dst, *opts, timeout=90):
    return _cp(xrdcp, *opts, f"{url}//{name}", dst, timeout=timeout)


def _unsupported(out, err):
    """True when xrdcp signalled the OPTION (not the data) is unavailable."""
    blob = (out + err).lower()
    return any(k in blob for k in ("unsupported", "not supported",
                                   "invalid option", "unknown option",
                                   "unrecognized"))


def _make_local_tree(root):
    """A small deterministic local tree for recursive UPLOAD tests."""
    j = os.path.join
    os.makedirs(j(root, "x", "y"), exist_ok=True)
    files = {
        "top.txt": b"top\n",
        os.path.join("x", "mid.bin"): bytes((i * 13 + 1) & 0xff for i in range(777)),
        os.path.join("x", "y", "leaf.bin"): bytes((i * 29 + 5) & 0xff for i in range(2050)),
    }
    for rel, data in files.items():
        with open(j(root, rel), "wb") as f:
            f.write(data)
    return files


# =========================================================================== #
# OPTION: -f / --force — overwrite an existing local target, byte-exact, and   #
# do it twice to prove the overwrite path itself is correct (not a no-op).     #
# =========================================================================== #
