"""
Phase 27 W6c — regression guards for the two Valgrind-Memcheck-found defects,
plus an optional end-to-end Memcheck run of the committed harness.

Findings (see docs/07-security/valgrind-findings.md):
  1. Uninitialised read of addr_text in src/observability/dashboard/http_tracking.c — the
     dashboard client-IP copy ran ngx_cpystrn() over a non-NUL-terminated
     ngx_str_t.  Fix: a length-bounded, NUL-terminated copy into a caller buffer.
  2. JWKS EVP_PKEY leak on every config reload in src/auth/token/jwks.c — the keys
     loaded into the pool-allocated conf array were never freed when the pool was
     destroyed.  Fix: register an ngx_pool_cleanup_t at both conf load sites.

The static marker tests are fast and always run; each FAILS if its fix is
reverted (e.g. dropping the cleanup-registration call reintroduces the reload
leak).  The end-to-end Memcheck test actually runs the harness and asserts the
module code is leak/uninitialised-clean — gated on valgrind + the test PKI
fixtures and opt-in via RUN_VALGRIND=1 (a full Memcheck run takes ~1-2 min).
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from settings import NGINX_BIN

ROOT = Path(__file__).resolve().parents[1]


def _read(rel):
    p = ROOT / rel
    assert p.exists(), f"missing {rel}"
    return p.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Finding 1 — addr_text bounded copy                                          #
# --------------------------------------------------------------------------- #

def test_finding1_addr_text_bounded_copy():
    c = _read("src/observability/dashboard/http_tracking.c")
    # The helper takes a caller-supplied buffer + size (not returning raw .data).
    assert re.search(
        r"dashboard_http_client\s*\(\s*ngx_http_request_t\s*\*\s*r\s*,"
        r"\s*char\s*\*\s*buf\s*,\s*size_t\s+bufsz",
        c,
    ), "dashboard_http_client must take (r, char *buf, size_t bufsz)"
    # Length-bounded, NUL-terminated copy.
    assert "ngx_min(r->connection->addr_text.len" in c
    assert "buf[n] = '\\0';" in c
    # Call site uses a stack buffer sized for a socket address.
    assert "NGX_SOCKADDR_STRLEN + 1" in c


# --------------------------------------------------------------------------- #
# Finding 2 — JWKS EVP_PKEY pool-cleanup registered at both load sites         #
# --------------------------------------------------------------------------- #

def test_finding2_jwks_pool_cleanup_defined():
    j = _read("src/auth/token/jwks.c")
    assert "brix_jwks_register_cleanup" in j
    assert "ngx_pool_cleanup_add" in j
    # The cleanup handler frees the keys.
    assert "brix_jwks_free" in j
    # Declared in the public header.
    assert "brix_jwks_register_cleanup" in _read("src/auth/token/token.h")


def test_finding2_jwks_cleanup_called_at_both_sites():
    # Reverting EITHER call reintroduces the per-reload EVP_PKEY leak.
    # phase-79 split: the proxy/token half of webdav config.c (which registers
    # the JWKS cleanup) moved into config_proxy.c.
    assert "brix_jwks_register_cleanup" in _read("src/protocols/webdav/config_proxy.c"), (
        "HTTP/WebDAV conf must register the JWKS pool cleanup"
    )
    assert "brix_jwks_register_cleanup" in _read("src/auth/token/config.c"), (
        "stream token conf must register the JWKS pool cleanup"
    )


# --------------------------------------------------------------------------- #
# Harness is committed                                                         #
# --------------------------------------------------------------------------- #

def test_valgrind_harness_committed():
    for f in (
        "tests/valgrind/nginx.conf.in",
        "tests/valgrind/run_valgrind.sh",
        "tests/valgrind/valgrind.supp",
        "tests/valgrind/README.md",
    ):
        assert (ROOT / f).exists(), f"missing {f}"
    # Suppressions must use native valgrind syntax, never suppress module frames.
    supp = _read("tests/valgrind/valgrind.supp")
    assert "Memcheck:Leak" in supp
    # No directive line may use the ASan/LSan `leak:<substr>` format (comments,
    # which start with '#', are allowed to mention it).
    for line in supp.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert not stripped.startswith("leak:"), (
            "valgrind.supp must not use LSan 'leak:' syntax"
        )


# --------------------------------------------------------------------------- #
# End-to-end Memcheck run (opt-in)                                            #
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(shutil.which("valgrind") is None,
                    reason="valgrind not installed")
@pytest.mark.skipif(os.environ.get("RUN_VALGRIND") != "1",
                    reason="set RUN_VALGRIND=1 to run the full Memcheck harness (~1-2 min)")
def test_harness_reports_module_clean(tmp_path):
    """Run the committed harness under Memcheck; module frames must be clean.

    Exercises GSI/TLS x509, bearer JWT (jansson+EVP), macaroon, libcurl TPC and
    S3 SigV4. Asserts the harness' MODULE-FRAME HITS section is empty — i.e. no
    leak / uninitialised read / invalid access in any brix_*/src/<module>/ frame.
    """
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    pki = Path(os.environ.get("PKI_DIR", "/tmp/xrd-test/pki"))
    if not (pki / "ca" / "ca.pem").exists():
        pytest.skip("test PKI fixtures missing; run manage_test_servers.sh start-all")

    work = tmp_path / "vg"
    env = dict(os.environ, VG_WORK=str(work))
    subprocess.run(
        ["bash", str(ROOT / "tests" / "valgrind" / "run_valgrind.sh")],
        env=env, timeout=600, check=False,
    )

    results_path = work / "results.txt"
    assert results_path.exists(), "harness produced no results.txt"
    results = results_path.read_text(encoding="utf-8")
    assert "FINISHED" not in results or "DONE" in results, results
    # Guard against a silent under-exercise (e.g. the worker never bound): the
    # request mix must have actually run against the GSI/TLS plane.
    assert "up after" in results, f"harness worker never came up:\n{results}"
    assert "gsi usercert=" in results, f"request mix did not run:\n{results}"

    marker = "MODULE-FRAME HITS (should be empty) ----"
    assert marker in results, f"harness did not run to triage:\n{results}"
    section = results.split(marker, 1)[1].split("DONE", 1)[0].strip()
    assert section == "(none)", f"valgrind found module-frame issues:\n{section}"
