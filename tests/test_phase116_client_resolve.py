"""
test_phase116_client_resolve.py — phase-116 W6: the client's one DNS seam.

WHAT: brix_resolve() (client/lib/net/resolve.c) is the only libc resolver
      call site under client/ and shared/, and src/ keeps exactly one
      forward (resolve_thread.c) and one reverse (reverse.c) seam.  Its C
      unit runs in both cache modes (default 60 s answer cache, and
      XRDC_RESOLVE_CACHE_S=0), and the curl users under client/ never let
      libcurl follow a redirect on its own.
WHY:  "fix ALL of the code in the clients/plugins": a client that resolved
      through three different paths could not be pointed at one resolv.conf
      policy, and a cached answer that outlived a record swap would have
      undone the server-side work from the other end of the wire.
HOW:  The C unit is built by the c_regression_units runner and re-run with
      the cache disabled; the census is a comment-stripped grep, the same
      stripping the guard uses, so a mention in a WHY block does not count.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

from cmdscripts.c_regression_units import run_checks

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.xdist_group("p116-client-resolve")]

REPO = Path(__file__).resolve().parent.parent
CALL = re.compile(r"\b(getaddrinfo|getnameinfo|gethostbyname2?|gethostbyaddr|res_n?query|res_n?search)\s*\(")
COMMENT_LINE = re.compile(r"^\s*(\*|//|/\*)")
TRAILING = re.compile(r"/\*.*?\*/|//.*$")


def _calls_in(path: Path) -> set[str]:
    """Resolver functions called from code lines of one file (comments out)."""
    names = set()
    for line in path.read_text(errors="replace").splitlines():
        if COMMENT_LINE.match(line):
            continue
        m = CALL.search(TRAILING.sub("", line))
        if m:
            names.add(m.group(1))
    return names


def _is_source(p: Path) -> bool:
    return p.suffix in (".c", ".h") and p.is_file()


def _call_sites(sub: str) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for p in sorted((REPO / sub).rglob("*")):
        if not _is_source(p):
            continue
        names = _calls_in(p)
        if names:
            found[p.relative_to(REPO).as_posix()] = names
    return found


def test_c_unit_with_the_answer_cache(tmp_path):
    ok, msg = run_checks(tmp_path, ["client_resolve"])[0]
    assert ok, msg
    assert "cache on" in msg, msg


def test_c_unit_with_the_answer_cache_disabled(tmp_path):
    ok, msg = run_checks(tmp_path, ["client_resolve"])[0]
    assert ok, msg
    binary = tmp_path / "client_resolve" / "client_resolve_test"
    assert binary.exists(), binary
    env = {**os.environ, "XRDC_RESOLVE_CACHE_S": "0", "ASAN_OPTIONS": "detect_leaks=0"}
    r = subprocess.run([str(binary), "nocache"], capture_output=True, text=True,
                       env=env, timeout=60, cwd=REPO)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "cache off" in r.stdout, r.stdout


def test_client_and_shared_trees_have_one_resolver_call_site():
    assert _call_sites("client") == {"client/lib/net/resolve.c": {"getaddrinfo"}}
    assert _call_sites("shared") == {}


def test_server_tree_has_one_forward_and_one_reverse_seam():
    assert _call_sites("src") == {
        "src/net/dns/resolve_thread.c": {"getaddrinfo"},
        "src/net/dns/reverse.c": {"getnameinfo"},
    }


def test_client_curl_users_never_follow_redirects_on_their_own():
    for sub in ("client", "shared"):
        for p in (REPO / sub).rglob("*.[ch]"):
            body = "\n".join(TRAILING.sub("", l) for l in p.read_text(errors="replace").splitlines()
                             if not COMMENT_LINE.match(l))
            assert "CURLOPT_FOLLOWLOCATION" not in body, p
            if "CURLOPT_URL" in body:
                assert re.search(r"\b(cvmfs_curl_perform_pinned|brix_dns_curl_pin)\s*\(", body), \
                    f"{p} sets CURLOPT_URL without pinning the address"


def test_client_facade_documents_its_cache_knob():
    h = (REPO / "client" / "lib" / "net" / "resolve.h").read_text()
    assert re.search(r"\bbrix_resolve\s*\(", h), "brix_resolve() is the client façade"
    assert "XRDC_RESOLVE_CACHE_S" in h, "the cache knob must be documented at the façade"
    assert (REPO / "client" / "apps" / "fs" / "brixcvmfs_curl_pin.h").exists()
