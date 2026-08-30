import os

import pytest

from cmdscripts.xroot_gateway_regress import run_checks
from settings import NGINX_BIN

def _check_test_xroot_gateway_regressions_1(results):
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )

def _check_test_xroot_gateway_regressions_2(messages):
    assert "truncate grew the origin file to 100 bytes" in messages


pytestmark = pytest.mark.xdist_group("cmd-xroot_gateway_regress")


def test_xroot_gateway_regressions(tmp_path):
    """Regression guards for the brix→root:// gateway fixes: concurrent-open
    handle collision, staged nested-subdir write, >1 MiB driver read, and
    explicit remote mkdir. See cmdscripts/xroot_gateway_regress.py."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    if results and results[0][1].startswith("SKIP "):
        pytest.skip(results[0][1])

    _check_test_xroot_gateway_regressions_1(results)

    messages = [message for _, message in results]
    # The four bug-specific guards must all be present and green.
    def _assert_test_xroot_gateway_regressions_1():
        assert "concurrent opens return distinct handles" in messages
        assert "peer handle survives close of the other" in messages

    _assert_test_xroot_gateway_regressions_1()
    def _assert_test_xroot_gateway_regressions_2():
        assert "staged write to nested subdir lands byte-exact on origin" in messages
        assert "multi-MiB driver read byte-exact" in messages

    _assert_test_xroot_gateway_regressions_2()
    def _assert_test_xroot_gateway_regressions_3():
        assert "explicit mkdir -p lands on remote origin" in messages
        # Remote-metadata gap regressions (keystone kXR_stat + routed handlers).
        assert "stat of a directory over root:// reports isDir" in messages

    _assert_test_xroot_gateway_regressions_3()
    def _assert_test_xroot_gateway_regressions_4():
        assert "stat of a file over root:// reports NOT isDir" in messages
        assert "statx of an existing file over root:// returns ok" in messages

    _assert_test_xroot_gateway_regressions_4()
    def _assert_test_xroot_gateway_regressions_5():
        assert "locate of an existing file over root:// returns ok" in messages
        assert "mv (rename) over root:// returns ok" in messages

    _assert_test_xroot_gateway_regressions_5()
    def _assert_test_xroot_gateway_regressions_6():
        assert "mv landed on the origin (dst present, src gone)" in messages
        assert "truncate (shrink) over root:// returns ok" in messages

    _assert_test_xroot_gateway_regressions_6()
    def _assert_test_xroot_gateway_regressions_7():
        assert "truncate shrank the origin file to 4 bytes" in messages
        assert "truncate (grow) over root:// returns ok" in messages

    _assert_test_xroot_gateway_regressions_7()

    def _assert_test_xroot_gateway_regressions_8():
        # §4.6: chmod forwarding to the origin (was a silent no-op before .setattr).
        assert "chmod over root:// returns ok" in messages
        assert "chmod landed on the origin (mode is now 0600)" in messages
        assert "chmod of a missing origin path is refused" in messages

    _assert_test_xroot_gateway_regressions_8()
    _check_test_xroot_gateway_regressions_2(messages)
    def _assert_test_xroot_gateway_regressions_8():
        # Checksum offload (driver query_checksum slot): success + fallback +
        # security-neg, with the origin access log as the read/query witness.
        assert "gateway Qcksum (default alg) returns the origin digest" in messages
        assert "offloaded Qcksum queried the origin without reading bytes" in messages

    _assert_test_xroot_gateway_regressions_8()
    def _assert_test_xroot_gateway_regressions_9():
        assert "non-origin algorithm falls back to compute correctly" in messages
        assert "compute fallback read the object bytes from the origin" in messages
        assert "Qcksum errors on missing and traversal paths" in messages

    _assert_test_xroot_gateway_regressions_9()
    def _assert_test_xroot_gateway_regressions_10():
        # Space delegation (driver space slot): success + origin-log witness +
        # security-neg + origin-down statvfs fallback.
        assert "gateway Qspace reports origin-derived totals" in messages
        assert "gateway Qspace delegated to the origin (origin QUERY space logged)" in messages

    _assert_test_xroot_gateway_regressions_10()
    def _assert_test_xroot_gateway_regressions_11():
        assert "gateway Qspace rejects an empty (relative) path" in messages
        assert "gateway Qspace falls back to local statvfs when the origin is down" in messages

    _assert_test_xroot_gateway_regressions_11()
