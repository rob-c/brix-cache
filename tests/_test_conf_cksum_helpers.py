"""Differential CHECKSUM conformance: the stock XRootD client (xrdfs/xrdcp)
against BOTH our nginx-xrootd server and the stock xrootd data server.

Scope: the kXR_Qcksum query path and its surfaces (`xrdfs query checksum`,
the `?cks.type=<algo>` CGI selector, `xrdcp --cksum`, and `xrdfs ls -C`
per-entry directory checksums). This file goes DEEPER than the handful of
checksum probes already in test_conf_io_read.py / test_official_interop.py —
it pins every advertised algorithm against an INDEPENDENT reference value.

Reference oracle problem (important): the bare stock xrootd data server in this
harness ships NO checksum calculator plugin, so `xrdfs query checksum` against
it returns "[3013] query chksum is not supported". We therefore cannot diff our
hex against the stock server's hex. Instead, where the stock server has no
plugin, we pin OUR server's hex against an INDEPENDENT Python computation over
the exact same bytes — the value the reference XRootD checksum library WOULD
emit (verified: zlib.adler32, zlib.crc32, a software CRC-32C/Castagnoli, a
software CRC-64/XZ and /NVME, and hashlib md5/sha1/sha256, all cross-checked
against XRootD's own client-side calculators and the published CRC catalogue
check vectors).

Wire format consulted (not modified):
  /tmp/brix-src/src/XrdCl/XrdClFS.cc      DoQuery / BuildPath (xrdfs arg path)
  /tmp/brix-src/src/XrdCl/XrdClUtils.cc   appends "?cks.type=<algo>" CGI
  src/protocols/root/query/checksum_qcksum.c               our kXR_Qcksum handler

Philosophy (per the maintainer): a divergence — wrong hex, wrong reply shape,
or an error where the reference computes a value — is a BUG IN OUR SERVER, and
the assertion is written to fail. No xfail/skip is used to paper over a real
diff; the only skips are environmental (toolchain or server-pair unavailable).

Self-provisioning on high ports; skips entirely without the stock toolchain.
"""

import hashlib
import os
import zlib

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]


# --------------------------------------------------------------------------- #
# The deterministic rich tree (identical bytes on both servers).              #
# --------------------------------------------------------------------------- #
SZ_FILES = ["sz_1.bin", "sz_255.bin", "sz_4095.bin", "sz_4096.bin",
            "sz_4097.bin", "sz_8192.bin", "sz_65536.bin"]

# Every regular file the rich tree plants at the namespace root.
ROOT_FILES = (["hello.txt", "data.bin", "cksum.bin", "empty.txt", "big1m.bin"]
              + SZ_FILES)

MANY_FILES = [f"f{i:02d}.txt" for i in range(12)]


# --------------------------------------------------------------------------- #
# Independent reference checksums (the value the reference library emits).     #
# --------------------------------------------------------------------------- #
def _build_table(poly, width):
    """Reflected CRC table for a reflected polynomial of the given bit width."""
    mask = (1 << width) - 1
    tab = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ poly if (c & 1) else (c >> 1)
        tab.append(c & mask)
    return tab


_CRC32C_POLY = 0x82F63B78                 # Castagnoli, reflected
_CRC32C_TAB = _build_table(_CRC32C_POLY, 32)
_CRC64XZ_POLY = 0xC96C5795D7870F42        # CRC-64/XZ, reflected
_CRC64XZ_TAB = _build_table(_CRC64XZ_POLY, 64)
_CRC64NVME_POLY = 0x9A6C9329AC4BC9B5      # CRC-64/NVME, reflected
_CRC64NVME_TAB = _build_table(_CRC64NVME_POLY, 64)


def _crc_reflected(data, tab, width):
    mask = (1 << width) - 1
    crc = mask
    for b in data:
        crc = tab[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ mask


def ref_adler32(data):
    return f"{zlib.adler32(data) & 0xffffffff:08x}"


def ref_crc32(data):
    return f"{zlib.crc32(data) & 0xffffffff:08x}"


def ref_crc32c(data):
    return f"{_crc_reflected(data, _CRC32C_TAB, 32):08x}"


def ref_crc64(data):
    return f"{_crc_reflected(data, _CRC64XZ_TAB, 64):016x}"


def ref_crc64nvme(data):
    return f"{_crc_reflected(data, _CRC64NVME_TAB, 64):016x}"


def ref_md5(data):
    return hashlib.md5(data).hexdigest()


def ref_sha1(data):
    return hashlib.sha1(data).hexdigest()


def ref_sha256(data):
    return hashlib.sha256(data).hexdigest()


# algo name -> (reference fn, expected hex width). adler32/crc32/crc32c/zcrc32
# are 8 hex; crc64* are 16; the digests are their native widths.
REF = {
    "adler32":   (ref_adler32, 8),
    "crc32":     (ref_crc32, 8),
    "zcrc32":    (ref_crc32, 8),     # XRootD's alias for the zlib CRC-32
    "crc32c":    (ref_crc32c, 8),
    "crc64":     (ref_crc64, 16),
    "crc64nvme": (ref_crc64nvme, 16),
    "md5":       (ref_md5, 32),
    "sha1":      (ref_sha1, 40),
    "sha256":    (ref_sha256, 64),
}


# --------------------------------------------------------------------------- #
# Module-scoped server pair (our nginx-xrootd + stock xrootd, identical tree). #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("conf_cksum"))
    try:
        procs, ctx = L.start_pair(base, our_port=L.worker_port(14020), off_port=L.worker_port(14021))
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    except Exception as e:  # noqa: BLE001 - any launch failure -> skip
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #
def _ourfs(url, *args, timeout=120):
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


def _bytes(ctx, name, sub=None):
    p = os.path.join(ctx["our_data"], *( [sub, name] if sub else [name] ))
    with open(p, "rb") as f:
        return f.read()


def _cksum_reply(url, path, timeout=120):
    """`xrdfs query checksum <path>` -> (rc, tokens, raw_out, raw_err)."""
    rc, out, err = _ourfs(url, "query", "checksum", path, timeout=timeout)
    return rc, out.split(), out, err


def _query_hex(url, name, algo=None, timeout=120):
    """Trailing hex of a checksum query, optionally selecting `algo` via the
    standard `?cks.type=<algo>` CGI. Returns (rc, hex_or_None, raw)."""
    path = f"/{name}" + (f"?cks.type={algo}" if algo else "")
    rc, toks, out, err = _cksum_reply(url, path, timeout=timeout)
    if rc != 0 or len(toks) < 2:
        return rc, None, (out + err)
    return rc, toks[-1].lower(), (out + err)


def _timeout_for(name):
    return 150 if "big1m" in name else 90


def _stock_has_plugin(ctx):
    """True if the stock data server can answer query checksum at all."""
    rc, _, _, _ = _cksum_reply(ctx["off"], "/data.bin")
    return rc == 0


# =========================================================================== #
# 1. REPLY SHAPE — every rich-tree file: `<algo> <hex>`, two tokens, the hex   #
#    width matching the default adler32 (8 hex chars). (12 cases)              #
# =========================================================================== #

def _ls_C_map(url, directory):
    """Parse `xrdfs ls -C <dir>` into {basename: adler32_hex}. Each line ends
    with `... adler32:<hex> <date> <time> <path>`; pull the algo:hex token and
    the trailing path."""
    rc, out, err = _ourfs(url, "ls", "-C", directory)
    if rc != 0:
        return rc, {}, (out + err)
    result = {}
    for line in out.splitlines():
        toks = line.split()
        if not toks:
            continue
        path = toks[-1]
        base = os.path.basename(path)
        cks = next((t for t in toks if t.startswith("adler32:")), None)
        if cks:
            result[base] = cks.split(":", 1)[1].lower()
    return rc, result, ""
