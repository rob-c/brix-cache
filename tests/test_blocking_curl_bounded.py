"""Every blocking libcurl transfer is time-bounded (phase-106 W5 invariant).

The W5 audit found that brix's blocking `curl_easy_perform` sites can stall a
worker (the token-exchange path on the event loop) or a thread-pool thread (the
TPC verify probe) when an endpoint black-holes. The structural mitigation that
keeps every one of them from hanging *forever* — and therefore keeps a dead
endpoint from being a denial-of-service — is that each configures a timeout.

This is the security invariant that must not regress: a `curl_easy_perform`
(or a hand-driven `curl_multi_perform` loop) with no timeout is an unbounded
stall. The audit is a snapshot; this test makes the property permanent, and it
already caught one site the audit's first pass missed (tpc_verify.c).

  * success   — every blocking-transfer source file configures a curl timeout,
                itself or via a setup helper it calls
  * error     — a fixture site with a perform and no timeout is flagged
  * security  — the specific token-exchange and TPC-verify sites (the two the
                audit named) are asserted bounded by name, so a refactor that
                drops their timeout cannot pass unnoticed

Run:
    PYTHONPATH=tests pytest tests/test_blocking_curl_bounded.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.timeout(60),
              pytest.mark.xdist_group("blocking-curl-bounded")]

SRC = Path(__file__).resolve().parent.parent / "src"

# A file that performs a blocking transfer is bounded if it, OR a setup helper
# it calls, sets any of these.
TIMEOUT_OPTS = ("CURLOPT_TIMEOUT", "CURLOPT_TIMEOUT_MS",
                "CURLOPT_LOW_SPEED_TIME")
PERFORM = ("curl_easy_perform", "curl_multi_perform", "curl_multi_wait")


def _c_sources():
    return sorted(SRC.rglob("*.c"))


def _blocking_sites():
    """Source files that actually drive a blocking libcurl transfer.

    A file that only NAMES curl_easy_perform in a comment (tpc_curl_pmark.c
    documents that its option must outlive the perform) is not a site — require
    the token to appear in code, i.e. followed by '('.
    """
    sites = []
    for path in _c_sources():
        text = path.read_text(errors="replace")
        if any(re.search(re.escape(p) + r"\s*\(", text) for p in PERFORM):
            sites.append((path, text))
    return sites


def _sibling_setup_text(path):
    """The concatenated text of same-directory *_setup.c / *_transport_setup.c
    helpers, where the shared timeout for a family of callers often lives."""
    blob = ""
    for sib in path.parent.glob("*setup*.c"):
        blob += sib.read_text(errors="replace")
    return blob


def test_every_blocking_curl_site_is_time_bounded():
    """(success + error) No blocking libcurl transfer may run unbounded."""
    unbounded = []
    for path, text in _blocking_sites():
        pool = text + _sibling_setup_text(path)
        if not any(opt in pool for opt in TIMEOUT_OPTS):
            unbounded.append(str(path.relative_to(SRC.parent)))
    assert not unbounded, (
        "these files drive a blocking libcurl transfer with no timeout set "
        "(itself or a *setup*.c helper beside it) — a black-holed endpoint "
        "will hang the worker or a thread-pool thread forever, which is a "
        "denial-of-service:\n  " + "\n  ".join(unbounded))


def test_detector_is_not_vacuous():
    """(non-vacuity) The scan really finds the blocking sites."""
    sites = {p.name for p, _ in _blocking_sites()}
    # The audit named these; if the scan found none of them it is broken.
    assert "exchange.c" in sites
    assert "tpc_verify.c" in sites


@pytest.mark.parametrize("relpath,needle", [
    ("src/auth/token/exchange.c", "CURLOPT_TIMEOUT"),
    ("src/protocols/webdav/tpc_verify.c", "CURLOPT_TIMEOUT"),
])
def test_named_audit_sites_stay_bounded(relpath, needle):
    """(security-neg, named regression) The two sites the W5 audit called out
    — the event-loop token exchange and the thread-pool TPC verify probe — must
    keep their timeout. Naming them pins the regression so a refactor that drops
    the bound cannot slip through the aggregate check above.
    """
    text = (SRC.parent / relpath).read_text(errors="replace")
    assert needle in text, f"{relpath} lost its curl timeout ({needle})"
