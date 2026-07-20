import shutil
import tempfile
from pathlib import Path

import pytest

from cmdscripts.c_auth_units import (
    RUNNERS,
    X509_HARNESS_TUS,
    X509_POLICY_SOURCES,
    link_x509_harness,
    run_checks,
    x509_fixture_dir,
)


@pytest.fixture
def private_tmp():
    # Deliberately NOT tmp_path: pytest's basetemp lives under the shared
    # TMPDIR=/tmp/xrd-test/tmp, and concurrent sessions rotate active roots to
    # garbage-* and rm_rf them mid-run — long-running legs (the ~5 min oracle
    # forge) lose their work dir, and even fixture *setup* can FileNotFoundError.
    d = Path(tempfile.mkdtemp(prefix="c_auth_units_test.", dir="/tmp"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.mark.parametrize("name", sorted(RUNNERS))
@pytest.mark.timeout(600)   # x509_oracle forges the full 559-clause fixture set (~5 min)
def test_c_auth_unit(name, private_tmp):
    results = run_checks(private_tmp, names=[name])
    if results and results[0][1].startswith("SKIP"):
        pytest.skip(results[0][1])
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )


def test_x509_link_guard_registered():
    # The fast link guard must stay in RUNNERS and cover every x509 harness;
    # dropping it would let a stale compile list hide until the slow oracle run.
    assert "x509_link" in RUNNERS
    assert set(X509_HARNESS_TUS) == {"x509_conformance", "x509_oracle"}


@pytest.mark.parametrize("name", sorted(X509_HARNESS_TUS))
def test_x509_link_guard_detects_stale_source_list(name, private_tmp):
    # Re-create the original failure (store_policy.c split without updating the
    # compile list) and prove the guard reports it as a link failure.
    stale = [s for s in X509_POLICY_SOURCES if not s.endswith("store_policy_store.c")]
    ok, detail = link_x509_harness(private_tmp, name, sources=stale)
    assert not ok, f"stale source list unexpectedly linked for {name}"
    assert "undefined reference" in detail


def test_x509_fixture_dir_avoids_shared_basetemp(monkeypatch, private_tmp):
    # Forged fixtures must never land under TMPDIR: conftest points TMPDIR at
    # the shared /tmp/xrd-test/tmp basetemp, which concurrent pytest sessions
    # rotate to garbage-* and rm_rf mid-run — deleting the CAs turns every
    # accept clause into a fail-closed reject (554/201 flake, 2026-07-20).
    monkeypatch.delenv("BRIX_X509_FIXTURES", raising=False)
    monkeypatch.setenv("TMPDIR", str(private_tmp))
    fixtures, owned = x509_fixture_dir("x509oracle")
    try:
        assert owned is not None
        assert fixtures.is_dir()
        assert not str(fixtures).startswith(str(private_tmp))
    finally:
        if owned:
            shutil.rmtree(owned, ignore_errors=True)

    monkeypatch.setenv("BRIX_X509_FIXTURES", str(private_tmp / "pinned"))
    fixtures, owned = x509_fixture_dir("x509oracle")
    assert owned is None and fixtures == private_tmp / "pinned"
