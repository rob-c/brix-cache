"""The C unit suite behind the native VOMS attribute-certificate verifier.

``shared/voms/`` replaced the HEP ``libvomsapi`` dependency: the module and
the client decode and verify VOMS ACs (RFC 5755) natively over OpenSSL.
``voms_ac_unittest.c`` pins the verifier over a GENUINE LHCb VOMS extension
(a real ``lhcb-auth.cern.ch`` signature): decode, the signature verifying,
validity windows, holder binding, a tampered signature, an empty trust store,
the vomsdir/LSC states, malformed DER and retrieval from a non-holder.  This
wrapper compiles and runs it so a change to the engine fails the Python tier
on every host, and a second test keeps the dependency gone: no production C
may name ``libvomsapi`` or ``VOMS_Retrieve`` again.

Run: cd tests && PYTHONPATH=$PWD:$PWD/../brixtest/src ../.venv/bin/python \\
         -m pytest test_voms_native_ac_unit.py -q -p no:cacheprovider
"""
import os
import re
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHARED = os.path.join(REPO, "shared")
VOMS = os.path.join(SHARED, "voms")
SOURCES = [os.path.join(VOMS, name)
           for name in ("voms_ac_unittest.c", "voms_asn1.c", "voms_decode.c",
                        "voms_verify.c", "voms_lsc.c")]
#: Homebrew OpenSSL on an Intel Mac; the system toolchain ships no headers.
BREW_OPENSSL = "/usr/local/opt/openssl@3"


def _openssl_flags():
    if os.path.isdir(BREW_OPENSSL):
        return [f"-I{BREW_OPENSSL}/include", f"-L{BREW_OPENSSL}/lib"]
    return []


@pytest.fixture(scope="module")
def unit_binary(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler on PATH")
    out = str(tmp_path_factory.mktemp("voms") / "voms_ut")
    build = subprocess.run([cc, "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
                            "-Werror", "-I", SHARED, *_openssl_flags(), *SOURCES,
                            "-o", out, "-lcrypto"],
                           capture_output=True, text=True, timeout=300)
    if build.returncode != 0:
        pytest.fail(f"voms_ac unit suite failed to compile:\n{build.stderr}")
    return out


def test_unit_suite_passes(unit_binary):
    """success (genuine LHCb signature verifies, LSC pair accepted) + error
    (expired / not-yet / malformed) + security-negative (wrong holder, tampered
    signature, untrusted chain, wrong LSC, path-escaping VO name) all live in
    the C suite; one exit code and one sentinel line cover them."""
    run = subprocess.run([unit_binary], capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "all checks passed" in run.stdout


# --- the dependency stays gone -----------------------------------------------

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_FORBIDDEN = re.compile(r"libvomsapi|\bVOMS_Retrieve\b")


def _code_only(text: str) -> str:
    """The C source with comments removed; string literals are kept on
    purpose — ``dlopen("libvomsapi.so.1")`` must be caught."""
    return _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub("", text))


def _is_production_c(name: str) -> bool:
    return name.endswith((".c", ".h")) and not name.endswith(("_unittest.c", "_test.c"))


def _production_c_files():
    for top in ("src", "client", "shared"):
        for root, _dirs, files in os.walk(os.path.join(REPO, top)):
            yield from (os.path.join(root, n) for n in files if _is_production_c(n))


def test_no_production_c_names_libvomsapi():
    """No dlopen target, no ABI struct, no ``VOMS_Retrieve`` call anywhere in
    the production tree: the native engine is the only VOMS code path."""
    offenders = []
    for path in _production_c_files():
        with open(path, encoding="utf-8", errors="replace") as fh:
            code = _code_only(fh.read())
        for lineno, line in enumerate(code.splitlines(), 1):
            if _FORBIDDEN.search(line):
                offenders.append(f"{os.path.relpath(path, REPO)}:{lineno}: {line.strip()}")
    assert not offenders, "libvomsapi / VOMS_Retrieve still referenced:\n" + "\n".join(offenders)
