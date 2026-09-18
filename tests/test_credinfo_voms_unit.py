"""Compile + run the VOMS attribute-certificate narration unit suite
(client/lib/auth/cred/credinfo_voms_unittest.c).

`xrddiag`'s credential dump decodes a GSI proxy's VOMS AC to show the caller's
FQANs (``/lhcb/Role=user/...``). The AC also embeds the VOMS server URI and the
signer certificate's CRL/AIA/OCSP distribution-point URIs; the historical blind
ASCII scan mislabelled all of those as FQANs and over-read each string into the
next DER tag byte (the ``…Capability=NULL0`` / ``…:4430B`` junk). The client
now hands the proxy leaf + chain to the shared native decoder/verifier
(``shared/voms/``) — the same code the nginx module uses — and
``credinfo_voms.c`` renders one line per FQAN, a per-VO summary and the
verifier's verdict. This suite proves that over the shared GENUINE LHCb-proxy
AC fixture: exactly two FQANs once each, a ``vo=lhcb`` summary, none of the
URI/junk noise, and graceful handling of degenerate input (no extension →
``VOMS:  none``; truncated DER → ``undecodable``; a certificate that is not the
AC's holder → ``NOT verified``, never ``verified``).

The real credinfo.c and credinfo_voms.c are #included (their helpers are
static), so the suite links against the built ``client/libbrix.a`` for the
remaining symbols and compiles the four shared/voms sources directly; if the
client hasn't been built it skips rather than failing.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess

from cmdscripts.c_regression_units import _gcov_flags
import pytest
from cmdscripts.compile_run import LZ4_LINK_FLAGS

def _guard_voms_bin_1(cc):
    if cc is None:
        pytest.skip("no C compiler")

def _guard_voms_bin_3():
    if not os.path.exists(LIBBRIX):
        pytest.skip("client/libbrix.a not built (run `make` in client/)")

def _guard_voms_bin_4(r):
    if r.returncode != 0:
        pytest.fail("credinfo VOMS suite failed to COMPILE/LINK "
                    f"(warnings are errors):\n{r.stderr}")

def _guard_voms_bin_2(f):
    if not os.path.exists(f):
        pytest.skip(f"credinfo VOMS sources missing: {f}")


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(REPO, "client")
CRED = os.path.join(CLIENT, "lib", "auth", "cred")
SHARED_VOMS = os.path.join(REPO, "shared", "voms")
SRC = os.path.join(CRED, "credinfo.c")
SRC_VOMS = os.path.join(CRED, "credinfo_voms.c")
TEST = os.path.join(CRED, "credinfo_voms_unittest.c")
FIXTURE = os.path.join(SHARED_VOMS, "voms_ac_fixture.h")
LIBBRIX = os.path.join(CLIENT, "libbrix.a")
LIBXRDPROTO = os.path.join(CLIENT, "..", "shared", "xrdproto", "libxrdproto.a")

# The shared native VOMS library, compiled from source so the suite is
# independent of whether libbrix.a already carries these objects.
VOMS_SRCS = [
    os.path.join("..", "shared", "voms", f)
    for f in ("voms_asn1.c", "voms_decode.c", "voms_verify.c", "voms_lsc.c")
]

# Fallback flags when the Makefile cannot be queried (Linux CI shape).
FALLBACK_CFLAGS = [
    "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Ilib", "-I../src",
    "-I../shared", "-DXRDPROTO_NO_NGX", "-DBRIX_PLATFORM_HOST=linux",
]
FALLBACK_LDLIBS = [
    "-lssl", "-lcrypto", "-lz", "-lkrb5", "-lk5crypto", "-lcom_err",
    "-lzstd", "-llzma", "-lbrotlienc", "-lbrotlidec", "-lbz2",
    *LZ4_LINK_FLAGS, "-luring",
]


def _client_make_flags():
    """(ALL_CFLAGS, LDLIBS) of the client Makefile, so the suite compiles
    credinfo.c with exactly the macros libbrix.a was built with (krb5/liburing/
    codec gates, the PAL's BRIX_PLATFORM_HOST) and links exactly its libraries.
    `make -pn` dumps the evaluated database; the xrdproto sub-make prints its
    own ALL_CFLAGS too, so the client's is the one carrying `-Ilib`."""
    r = subprocess.run(["make", "-s", "-pn", "-f", "Makefile"], cwd=CLIENT,
                       capture_output=True, text=True)
    cflags = [m.split() for m in re.findall(r"^ALL_CFLAGS :?= (.*)$", r.stdout, re.M)
              if "-Ilib" in m.split()]
    ldlibs = re.findall(r"^LDLIBS :?= (.*)$", r.stdout, re.M)
    return (cflags[-1] if cflags else FALLBACK_CFLAGS,
            ldlibs[-1].split() if ldlibs else FALLBACK_LDLIBS)


@pytest.fixture(scope="module")
def voms_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    _guard_voms_bin_1(cc)
    for f in (SRC, SRC_VOMS, TEST, FIXTURE):
        _guard_voms_bin_2(f)
    _guard_voms_bin_3()
    out = str(tmp_path_factory.mktemp("vomsut") / "ut")
    cflags, ldlibs = _client_make_flags()
    cmd = [
        cc, *cflags, "-Werror",
        os.path.join("lib", "auth", "cred", "credinfo_voms_unittest.c"),
        *VOMS_SRCS,
        "libbrix.a", os.path.join("..", "shared", "xrdproto", "libxrdproto.a"),
        *_gcov_flags([Path(LIBBRIX), Path(LIBXRDPROTO)]),
        *ldlibs, "-o", out,
    ]
    r = subprocess.run(cmd, cwd=CLIENT, capture_output=True, text=True)
    _guard_voms_bin_4(r)
    return out


def test_credinfo_voms_suite(voms_bin):
    r = subprocess.run([voms_bin], capture_output=True, text=True, timeout=120)
    print(r.stdout)
    assert r.returncode == 0, \
        f"credinfo VOMS suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "all VOMS AC parser checks passed" in r.stdout
