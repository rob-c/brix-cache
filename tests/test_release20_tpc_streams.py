"""2.0 F7 — native root:// TPC multi-stream pulls (`ofs.tpc streams` parity).

A destination now honours the client's `tpc.str=N` hint up to
`brix_tpc_streams` (default 1, so nothing changes for a site that does not opt
in): after the primary source session it opens N-1 further connections, binds
each to the primary session with kXR_bind, and pulls the file as rounds of one
1 MiB read per stream (`tpc_stream_plan_round`). A source that refuses
kXR_bind, a hint that fails to parse, or a cap of one all degrade to the
single-stream loop — never to an error.

The witness for "N streams" is the splice in front of the source: it counts
accepted connections, and the destination's own log says how many sub-streams
were bound. XrdCl 5.9 never emits `tpc.str`, so the destination open is driven
raw with the hint appended to the opaque.
"""

import subprocess

import pytest

from _release20_tpc_helpers import (
    SourceSplice, err_text, log_since, log_size, published, pull, start_lab,
)
from _test_audit15g_helpers import pattern
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, NGINX_BIN
from test_phase25_ratelimit import KXR_OK

pytestmark = [
    pytest.mark.serial,
    pytest.mark.timeout(240),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-r20-tpc-streams"),
]

NAME = "lc-r20-tpc-streams"
# Six full 1 MiB slots plus a short tail: with four streams that is one full
# round, one round with two full reads, one short read and one empty slot.
SEED = pattern(6 * 1024 * 1024 + 12345, 0x5A)
BOUND_ALL = "brix: TPC multi-stream: 3 of 3 requested sub-streams bound"


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    node = start_lab(
        tmp_path_factory, name=NAME, template="nginx_release20_tpc_streams.conf",
        roots=("src", "src2", "dst", "one"), seed_roots=("src", "src2"), seed=SEED,
        extra_ports=("SRC_PORT", "ONE_PORT", "NOBIND_PORT"),
        reason="2.0 F7: native TPC multi-stream")
    splice = SourceSplice(node["ports"]["SRC_PORT"]).start()
    node["splice"] = splice
    yield node
    splice.stop()
    node["harness"].close()


def _pull(lab, dst_key, dest, *, extra="", splice=None, arm_key="SRC_PORT"):
    ports = lab["ports"]
    splice = splice or lab["splice"]
    splice.reset()
    mark = log_size(lab["endpoint"])
    status, body = pull(ports[dst_key], splice.listen, dest, arm_port=ports[arm_key],
                        size=len(SEED), tag=dst_key.lower(), extra=extra)
    return status, body, log_since(lab["endpoint"], mark)


# -- success ----------------------------------------------------------------


def test_four_streams_pull_over_four_connections_byte_exact(lab):
    status, body, fresh = _pull(lab, "PORT", "/four.bin", extra="&tpc.str=4")

    assert status == KXR_OK, err_text(body)
    assert published(lab["dirs"]["dst"], "/four.bin", SEED)
    assert lab["splice"].accepted == 4
    assert BOUND_ALL in fresh


def test_two_streams_pull_over_two_connections(lab):
    status, body, fresh = _pull(lab, "PORT", "/two.bin", extra="&tpc.str=2")

    assert status == KXR_OK, err_text(body)
    assert published(lab["dirs"]["dst"], "/two.bin", SEED)
    assert lab["splice"].accepted == 2
    assert "brix: TPC multi-stream: 1 of 1 requested sub-streams bound" in fresh


def test_no_hint_stays_single_stream(lab):
    status, body, fresh = _pull(lab, "PORT", "/plain.bin")

    assert status == KXR_OK, err_text(body)
    assert published(lab["dirs"]["dst"], "/plain.bin", SEED)
    assert lab["splice"].accepted == 1
    assert "multi-stream" not in fresh


# -- error ------------------------------------------------------------------


@pytest.mark.parametrize("hint", ["abc", "0", "-3", ""])
def test_unusable_hint_degrades_to_single_stream(lab, hint):
    dest = f"/hint-{hint or 'empty'}.bin"
    status, body, fresh = _pull(lab, "PORT", dest, extra=f"&tpc.str={hint}")

    assert status == KXR_OK, err_text(body)
    assert published(lab["dirs"]["dst"], dest, SEED)
    assert lab["splice"].accepted == 1
    assert "multi-stream" not in fresh


def test_source_without_kxr_bind_degrades_to_single_stream(lab):
    nobind = SourceSplice(lab["ports"]["NOBIND_PORT"]).start()
    try:
        status, body, fresh = _pull(lab, "PORT", "/nobind.bin", extra="&tpc.str=4",
                                    splice=nobind, arm_key="NOBIND_PORT")

        assert status == KXR_OK, err_text(body)
        assert published(lab["dirs"]["dst"], "/nobind.bin", SEED)
        assert "brix: TPC multi-stream: 0 of 3 requested sub-streams bound" in fresh
        assert "TPC kXR_bind rejected" in fresh
        assert nobind.accepted == 2            # the primary plus the one refused bind
    finally:
        nobind.stop()


# -- security-negative ------------------------------------------------------


def test_hint_cannot_exceed_the_server_cap(lab):
    status, body, fresh = _pull(lab, "PORT", "/greedy.bin", extra="&tpc.str=999")

    assert status == KXR_OK, err_text(body)
    assert published(lab["dirs"]["dst"], "/greedy.bin", SEED)
    assert lab["splice"].accepted == 4
    assert BOUND_ALL in fresh


def test_cap_of_one_ignores_the_hint(lab):
    status, body, fresh = _pull(lab, "ONE_PORT", "/capped.bin", extra="&tpc.str=4")

    assert status == KXR_OK, err_text(body)
    assert published(lab["dirs"]["one"], "/capped.bin", SEED)
    assert lab["splice"].accepted == 1
    assert "multi-stream" not in fresh


# -- grammar ----------------------------------------------------------------


def _render_and_test(lifecycle, tmp_path, line):
    reg = lifecycle.register(NginxInstanceSpec(
        name="lc-r20-tpc-validate", template="nginx_release20_tpc_validate.conf",
        protocol="none", readiness="none", port=SHARED_PARSE_PLACEHOLDER_PORT,
        data_root=str(tmp_path),
        template_values={"BIND_HOST": BIND_HOST, "TPC_LINES": f"        {line}\n"},
        reason="2.0 F7: brix_tpc_streams grammar"))
    endpoint = lifecycle.launcher.render_nginx(reg)
    return subprocess.run([NGINX_BIN, "-t", "-p", endpoint.prefix, "-c", "conf/nginx.conf"],
                          capture_output=True, text=True, timeout=30)


class TestGrammar:
    @pytest.mark.parametrize("line", ["brix_tpc_streams 1;", "brix_tpc_streams 15;"])
    def test_in_range_values_parse(self, lifecycle, tmp_path, line):
        result = _render_and_test(lifecycle, tmp_path, line)
        assert result.returncode == 0, result.stderr

    @pytest.mark.parametrize("line,needle", [
        ("brix_tpc_streams 0;", "brix_tpc_streams must be between 1 and 15"),
        ("brix_tpc_streams 16;", "brix_tpc_streams must be between 1 and 15"),
        ("brix_tpc_streams lots;", "invalid number"),
    ])
    def test_out_of_range_values_are_refused(self, lifecycle, tmp_path, line, needle):
        result = _render_and_test(lifecycle, tmp_path, line)
        assert result.returncode != 0
        assert needle in result.stderr
