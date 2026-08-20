"""Compile + run the VOMS attribute-certificate FQAN-parser unit suite
(client/lib/auth/cred/credinfo_voms_unittest.c).

`xrddiag`'s credential dump decodes a GSI proxy's VOMS AC to show the caller's
FQANs (``/lhcb/Role=user/...``). The AC also embeds the VOMS server URI and the
signer certificate's CRL/AIA/OCSP distribution-point URIs; a blind ASCII scan
mislabels all of those as FQANs and over-reads each string into the next DER tag
byte (the ``…Capability=NULL0`` / ``…:4430B`` junk). The real ``voms_scan`` now
walks the DER structurally — locating the FQAN attribute OID
1.3.6.1.4.1.8005.100.100.4 and printing only its OCTET STRING values at exact
length — and this suite proves that over a GENUINE LHCb-proxy AC fixture: exactly
two FQANs, none of the URI/junk noise, and graceful handling of degenerate input.

The real credinfo.c is #included (its parser is static), so the suite links
against the built ``client/libbrix.a`` for the remaining symbols; if the client
hasn't been built it skips rather than failing.
"""
import os
from pathlib import Path
import shutil
import subprocess

from cmdscripts.c_regression_units import _gcov_flags
import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(REPO, "client")
CRED = os.path.join(CLIENT, "lib", "auth", "cred")
SRC = os.path.join(CRED, "credinfo.c")
TEST = os.path.join(CRED, "credinfo_voms_unittest.c")
FIXTURE = os.path.join(CRED, "voms_ac_fixture.h")
LIBBRIX = os.path.join(CLIENT, "libbrix.a")
LIBXRDPROTO = os.path.join(CLIENT, "..", "shared", "xrdproto", "libxrdproto.a")

# Matches client/Makefile's link line (kept in sync with xrddiag_LDLIBS).
LDLIBS = [
    "-lssl", "-lcrypto", "-lz", "-lkrb5", "-lk5crypto", "-lcom_err",
    "-lzstd", "-llzma", "-lbrotlienc", "-lbrotlidec", "-lbz2",
    "-l:liblz4.so.1", "-luring",
]


@pytest.fixture(scope="module")
def voms_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    for f in (SRC, TEST, FIXTURE):
        if not os.path.exists(f):
            pytest.skip(f"credinfo VOMS sources missing: {f}")
    if not os.path.exists(LIBBRIX):
        pytest.skip("client/libbrix.a not built (run `make` in client/)")
    out = str(tmp_path_factory.mktemp("vomsut") / "ut")
    cmd = [
        cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-Ilib", "-I../src", "-I../shared", "-DXRDPROTO_NO_NGX",
        "-DBRIX_HAVE_KRB5", "-DBRIX_HAVE_LIBURING",
        os.path.join("lib", "auth", "cred", "credinfo_voms_unittest.c"),
        "libbrix.a", os.path.join("..", "shared", "xrdproto", "libxrdproto.a"),
        *_gcov_flags([Path(LIBBRIX), Path(LIBXRDPROTO)]),
        *LDLIBS, "-o", out,
    ]
    r = subprocess.run(cmd, cwd=CLIENT, capture_output=True, text=True)
    if r.returncode != 0:
        pytest.fail("credinfo VOMS suite failed to COMPILE/LINK "
                    f"(warnings are errors):\n{r.stderr}")
    return out


def test_credinfo_voms_suite(voms_bin):
    r = subprocess.run([voms_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, \
        f"credinfo VOMS suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "all VOMS AC parser checks passed" in r.stdout
