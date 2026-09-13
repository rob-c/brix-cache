"""2.0 F7 — native root:// TPC multihop delegation.

Before F7 a kXR_redirect from the TPC source ended the pull with "unexpected
status 4004". Now the destination follows it: the redirect body is decoded
(`xrd_redirect_body_decode`), the new host passes the same source guard as the
host the client named, the hop is logged, and the pull re-bootstraps on the
target with a fresh session. `brix_tpc_max_hops` bounds the chain (default 4,
0 = never follow); a hop refused by the allowlist bumps
`brix_stream_tpc_egress_refused_total`.

The lab is a real posix source behind a splice (`SourceSplice`) that answers the
first kXR_open with a redirect of the test's choosing — the only way to make an
anonymous loopback source redirect without a redirector fleet.
"""

import subprocess

import pytest

from _release20_tpc_helpers import (
    SRC_LFN, XERR_NOT_AUTHORIZED, XERR_SERVER_ERROR, SourceSplice, err_text,
    log_since, log_size, published, pull, start_lab,
)
from _test_audit15g_helpers import pattern
from _test_release20_metrics_helpers import scrape, total, wait_for
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN
from test_phase25_ratelimit import KXR_OK

pytestmark = [
    pytest.mark.serial,
    pytest.mark.timeout(240),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-r20-tpc-multihop"),
]

NAME = "lc-r20-tpc-multihop"
SEED = pattern(3 * 1024 * 1024 + 4097, 0x77)      # three full 1 MiB rounds plus a tail
REFUSED = "brix_stream_tpc_egress_refused_total"
# A second spelling of loopback that the allowlist (which names only HOST)
# does not carry.
OTHER_LOOPBACK = "localhost" if HOST != "localhost" else "127.0.0.1"  # net-literal-allow: the guard test needs an allowlist-rejected host


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    node = start_lab(
        tmp_path_factory, name=NAME, template="nginx_release20_tpc_multihop.conf",
        roots=("src", "dst", "nohop", "guard"), seed_roots=("src",), seed=SEED,
        extra_ports=("SRC_PORT", "NOHOP_PORT", "GUARD_PORT", "METRICS_PORT"),
        reason="2.0 F7: native TPC multihop delegation")
    splice = SourceSplice(node["ports"]["SRC_PORT"]).start()
    node["splice"] = splice
    yield node
    splice.stop()
    node["harness"].close()


def _pull_via(lab, dst_key, dest, *, src_port=None):
    ports = lab["ports"]
    return pull(ports[dst_key], src_port or lab["splice"].listen, dest,
                arm_port=ports["SRC_PORT"], size=len(SEED), tag=dst_key.lower())


# -- success ----------------------------------------------------------------


def test_one_hop_redirect_is_followed_and_byte_exact(lab):
    splice, ports, endpoint = lab["splice"], lab["ports"], lab["endpoint"]
    splice.reset()
    splice.arm_redirect(HOST, ports["SRC_PORT"])
    mark = log_size(endpoint)

    status, body = _pull_via(lab, "PORT", "/hop1.bin")

    assert status == KXR_OK, err_text(body)
    assert published(lab["dirs"]["dst"], "/hop1.bin", SEED)
    assert splice.redirects == 1
    fresh = log_since(endpoint, mark)
    assert (f"brix: TPC hop 1: {HOST}:{splice.listen} -> {HOST}:{ports['SRC_PORT']}"
            f" for {SRC_LFN}") in fresh


def test_two_hop_chain_is_followed_within_the_default_budget(lab):
    splice, ports, endpoint = lab["splice"], lab["ports"], lab["endpoint"]
    second = SourceSplice(ports["SRC_PORT"]).start()
    try:
        second.arm_redirect(HOST, ports["SRC_PORT"])
        splice.reset()
        splice.arm_redirect(HOST, second.listen)
        mark = log_size(endpoint)

        status, body = _pull_via(lab, "PORT", "/hop2.bin")

        assert status == KXR_OK, err_text(body)
        assert published(lab["dirs"]["dst"], "/hop2.bin", SEED)
        assert (splice.redirects, second.redirects) == (1, 1)
        fresh = log_since(endpoint, mark)
        assert f"brix: TPC hop 1: {HOST}:{splice.listen} -> {HOST}:{second.listen}" in fresh
        assert f"brix: TPC hop 2: {HOST}:{second.listen} -> {HOST}:{ports['SRC_PORT']}" in fresh
    finally:
        second.stop()


def test_disarmed_source_still_pulls_single_hop(lab):
    splice, endpoint = lab["splice"], lab["endpoint"]
    splice.reset()
    mark = log_size(endpoint)

    status, body = _pull_via(lab, "PORT", "/direct.bin")

    assert status == KXR_OK, err_text(body)
    assert published(lab["dirs"]["dst"], "/direct.bin", SEED)
    assert splice.redirects == 0
    assert "TPC hop" not in log_since(endpoint, mark)


# -- error ------------------------------------------------------------------


def test_hop_budget_zero_refuses_the_first_redirect(lab):
    splice, ports = lab["splice"], lab["ports"]
    splice.reset()
    splice.arm_redirect(HOST, ports["SRC_PORT"])

    status, body = _pull_via(lab, "NOHOP_PORT", "/nohop.bin")

    assert status != KXR_OK
    code, msg = err_text(body)
    assert code == XERR_NOT_AUTHORIZED, msg
    assert "brix_tpc_max_hops is 0" in msg
    assert splice.redirects == 1
    assert not published(lab["dirs"]["nohop"], "/nohop.bin", SEED)


def test_redirect_back_to_the_same_source_is_a_loop(lab):
    splice = lab["splice"]
    splice.reset()
    splice.arm_redirect(HOST, splice.listen)

    status, body = _pull_via(lab, "PORT", "/loop.bin")

    assert status != KXR_OK
    code, msg = err_text(body)
    assert code == XERR_SERVER_ERROR, msg
    assert "loops back to itself" in msg
    assert not published(lab["dirs"]["dst"], "/loop.bin", SEED)


def test_malformed_redirect_body_is_refused(lab):
    splice = lab["splice"]
    splice.reset()
    splice.arm_malformed()

    status, body = _pull_via(lab, "PORT", "/malformed.bin")

    assert status != KXR_OK
    code, msg = err_text(body)
    assert code == XERR_SERVER_ERROR, msg
    assert "redirect body malformed" in msg
    assert not published(lab["dirs"]["dst"], "/malformed.bin", SEED)


# -- security-negative ------------------------------------------------------


def test_redirect_outside_the_source_allowlist_is_refused_and_counted(lab):
    splice, ports = lab["splice"], lab["ports"]
    before = total(scrape(ports["METRICS_PORT"]), REFUSED)

    # Control: the host the client named passes the allowlist.
    splice.reset()
    status, body = _pull_via(lab, "GUARD_PORT", "/guard-ok.bin")
    assert status == KXR_OK, err_text(body)
    assert published(lab["dirs"]["guard"], "/guard-ok.bin", SEED)
    assert total(scrape(ports["METRICS_PORT"]), REFUSED) == before

    # The redirect target is not on the list: refused before any dial.
    splice.arm_redirect(OTHER_LOOPBACK, ports["SRC_PORT"])
    status, body = _pull_via(lab, "GUARD_PORT", "/guard-hop.bin")

    assert status != KXR_OK
    code, msg = err_text(body)
    assert code == XERR_NOT_AUTHORIZED, msg
    assert f"TPC redirect to {OTHER_LOOPBACK} refused" in msg
    assert "not permitted" in msg
    assert not published(lab["dirs"]["guard"], "/guard-hop.bin", SEED)

    def bumped():
        now = total(scrape(ports["METRICS_PORT"]), REFUSED)
        return now if now > before else None

    assert wait_for(bumped, timeout=10) == before + 1


# -- grammar ----------------------------------------------------------------


def _render_and_test(lifecycle, tmp_path, line):
    reg = lifecycle.register(NginxInstanceSpec(
        name="lc-r20-tpc-validate", template="nginx_release20_tpc_validate.conf",
        protocol="none", readiness="none", port=SHARED_PARSE_PLACEHOLDER_PORT,
        data_root=str(tmp_path),
        template_values={"BIND_HOST": BIND_HOST, "TPC_LINES": f"        {line}\n"},
        reason="2.0 F7: brix_tpc_max_hops grammar"))
    endpoint = lifecycle.launcher.render_nginx(reg)
    return subprocess.run([NGINX_BIN, "-t", "-p", endpoint.prefix, "-c", "conf/nginx.conf"],
                          capture_output=True, text=True, timeout=30)


class TestGrammar:
    @pytest.mark.parametrize("line", ["brix_tpc_max_hops 0;", "brix_tpc_max_hops 16;"])
    def test_in_range_values_parse(self, lifecycle, tmp_path, line):
        result = _render_and_test(lifecycle, tmp_path, line)
        assert result.returncode == 0, result.stderr

    @pytest.mark.parametrize("line,needle", [
        ("brix_tpc_max_hops 17;", "brix_tpc_max_hops must be between 0 and 16"),
        ("brix_tpc_max_hops -1;", "invalid number"),
        ("brix_tpc_max_hops many;", "invalid number"),
    ])
    def test_out_of_range_values_are_refused(self, lifecycle, tmp_path, line, needle):
        result = _render_and_test(lifecycle, tmp_path, line)
        assert result.returncode != 0
        assert needle in result.stderr
