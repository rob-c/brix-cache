"""2.0 F16 — the native root:// TPC PUSH dialect (`tpc.stage=push`).

Stock xrootd's native TPC is destination-side PULL only: the destination dials
the source and reads. A site whose storage may only make OUTBOUND connections
(an egress-only firewall) therefore cannot participate in a native copy at all.
F16 adds the mirrored leg — a BriX dialect, so both legs carry
`tpc.stage=push` and a stock peer never mistakes one for a pull:

  leg 1  client -> destination   write-open `?tpc.key=K&tpc.stage=push`
                                 registers K and CREATES the file; no dial.
  leg 2  client -> source        read-open  `?tpc.key=K&tpc.dst=host[:port]
                                 &tpc.dlfn=/dst/path&tpc.stage=push[&tpc.str=N]`
                                 parks the push intent behind the ordinary
                                 read-open; two kXR_syncs arm it, then fire it.
  leg 3  source -> destination   write-open `?tpc.key=K&tpc.org=<client>
                                 &tpc.stage=push` CONSUMES K, kXR_open_updt
                                 only — the push can only write where a client
                                 already registered a key.

Both roles are behind `brix_tpc_push` (off by default): the source dials out,
the destination accepts bytes from a server rather than a client, and an
operator opts into both postures at once.

The witness for "N connections" is a splice in front of the DESTINATION: a push
inverts who dials, so the source's outbound sockets land there. The destination
plane's registration (leg 1) is driven straight at the real port so only the
source's own dials are counted.
"""

import os
import struct
import subprocess
import time

import pytest

from _release20_tpc_helpers import (
    SRC_LFN, TPC_FLAGS, SourceSplice, err_text, log_since, log_size,
    open_frame, published, start_lab,
)
from _test_a_robustness_helpers import make_close_req
from _test_audit15g_helpers import pattern
from _test_phase25_ratelimit_helpers import _xrd_login, _xrd_recv_status
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN
from test_audit15c_tpc_token_exchange import _drive_pull
from test_phase25_ratelimit import KXR_OK

pytestmark = [
    pytest.mark.serial,
    pytest.mark.timeout(240),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-r20-tpc-push"),
]

NAME = "lc-r20-tpc-push"

# Five full 1 MiB slots plus a short tail: with four streams that is one full
# round, then a round with one full read, one short read and two idle slots —
# so the round loop's clamp to push_size and its idle slots are both exercised.
SEED = pattern(5 * 1024 * 1024 + 12345, 0x3C)

KXR_ERROR = 4003
KXR_OPEN_READ = 0x0010                # a push SOURCE leg is an ordinary read open
XERR_NOT_AUTHORIZED = 3010
XERR_UNSUPPORTED = 3013
XERR_FS_READ_ONLY = 3025

KXR_SYNC = 3016
KXR_RM = 3014

BOUND_ALL = "brix: TPC multi-stream: 3 of 3 requested sub-streams bound"


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    node = start_lab(
        tmp_path_factory, name=NAME, template="nginx_release20_tpc_push.conf",
        roots=("src", "one", "off", "dst", "guard"),
        seed_roots=("src", "one", "off", "guard"), seed=SEED,
        extra_ports=("ONE_PORT", "OFF_PORT", "DST_PORT", "GUARD_PORT"),
        reason="2.0 F16: native TPC push")
    splice = SourceSplice(node["ports"]["DST_PORT"]).start()
    node["splice"] = splice
    yield node
    splice.stop()
    node["harness"].close()


# -- the push driver --------------------------------------------------------


def _new_key(tag):
    return f"{tag}-{os.getpid()}-{time.monotonic_ns()}"


def register(lab, dest, key):
    """Leg 1: the client registers `key` at the destination and creates `dest`."""
    sock = _xrd_login(HOST, lab["ports"]["DST_PORT"])
    sock.settimeout(60)
    try:
        status, body = open_frame(sock, f"{dest}?tpc.key={key}&tpc.stage=push",
                                  TPC_FLAGS)
        assert status == KXR_OK, ("push registration refused", err_text(body))
        sock.sendall(make_close_req(body[:4]))
        _xrd_recv_status(sock)
    finally:
        sock.close()


def push(lab, src_key, dest, *, key, dst_port=None, extra="", timeout=180):
    """Leg 2: drive one push of SRC_LFN from the `src_key` plane into `dest`.

    `dst_port` names the destination the SOURCE is told to dial — a splice port
    when the test counts connections, the real port otherwise. Returns the final
    (status, body): the open's when the open is refused, else the fired sync's.
    """
    port = dst_port if dst_port is not None else lab["ports"]["DST_PORT"]
    sock = _xrd_login(HOST, lab["ports"][src_key])
    sock.settimeout(timeout)
    try:
        opaque = (f"?tpc.key={key}&tpc.dst={HOST}:{port}&tpc.dlfn={dest}"
                  f"&tpc.stage=push{extra}")
        status, body = open_frame(sock, SRC_LFN + opaque, KXR_OPEN_READ)
        if status != KXR_OK:
            return status, body
        fhandle = body[:4]
        status, body = _drive_pull(sock, fhandle)
        sock.sendall(make_close_req(fhandle))
        _xrd_recv_status(sock)
        return status, body
    finally:
        sock.close()


def run_push(lab, src_key, dest, *, extra="", dst_port=None, tag="f16",
             registered=True, key=None):
    """One whole push (register + drive) plus the error-log delta it produced."""
    key = key or _new_key(tag)
    if registered:
        register(lab, dest, key)
    mark = log_size(lab["endpoint"])
    status, body = push(lab, src_key, dest, key=key, dst_port=dst_port,
                        extra=extra)
    return status, body, log_since(lab["endpoint"], mark)


def source_intact(lab, plane):
    """True while the pushing plane's own copy of SRC_LFN is untouched."""
    return published(lab["dirs"][plane], SRC_LFN, SEED)


# -- success ----------------------------------------------------------------


def test_single_stream_push_publishes_byte_exact(lab):
    status, body, _ = run_push(lab, "ONE_PORT", "/one.bin", tag="one")

    assert status == KXR_OK, err_text(body)
    assert published(lab["dirs"]["dst"], "/one.bin", SEED)
    assert source_intact(lab, "one")


def test_four_stream_push_dials_four_connections(lab):
    splice = lab["splice"]
    splice.reset()

    status, body, fresh = run_push(lab, "PORT", "/four.bin", extra="&tpc.str=4",
                                   dst_port=splice.listen, tag="four")

    assert status == KXR_OK, err_text(body)
    assert published(lab["dirs"]["dst"], "/four.bin", SEED)
    assert splice.accepted == 4
    assert BOUND_ALL in fresh
    assert source_intact(lab, "src")


def test_push_without_a_hint_stays_single_stream(lab):
    splice = lab["splice"]
    splice.reset()

    status, body, fresh = run_push(lab, "PORT", "/plain.bin",
                                   dst_port=splice.listen, tag="plain")

    assert status == KXR_OK, err_text(body)
    assert published(lab["dirs"]["dst"], "/plain.bin", SEED)
    assert splice.accepted == 1
    assert "multi-stream" not in fresh


# -- error ------------------------------------------------------------------


def test_unregistered_key_fails_and_never_removes_the_source(lab):
    """A push whose key was never registered is refused by the destination at
    leg 3 — and the SOURCE file, which the task carries in dst_path, survives.

    This is the push's one genuine data-loss hazard: done.c removes dst_path on
    a failed PULL, where it is the half-written destination copy. On a push that
    same field names the operator's own file.
    """
    status, body, _ = run_push(lab, "ONE_PORT", "/never.bin", registered=False,
                               tag="never")

    assert status == KXR_ERROR, (status, body)
    code, msg = err_text(body)
    assert code == XERR_NOT_AUTHORIZED, (code, msg)
    assert source_intact(lab, "one"), "a failed push removed its own source file"
    assert not os.path.exists(os.path.join(str(lab["dirs"]["dst"]), "never.bin"))


def test_push_disabled_refuses_the_source_leg(lab):
    status, body, _ = run_push(lab, "OFF_PORT", "/off-src.bin", tag="offsrc")

    assert status == KXR_ERROR, (status, body)
    code, msg = err_text(body)
    assert code == XERR_UNSUPPORTED, (code, msg)
    assert "brix_tpc_push off" in msg


def test_push_disabled_refuses_the_target_leg_before_the_write_gate(lab):
    """A push write-open on a plane with the dialect off is refused
    kXR_Unsupported — the TPC role runs before path resolution and the
    write gate, so `brix_tpc_push off` answers first."""
    sock = _xrd_login(HOST, lab["ports"]["OFF_PORT"])
    sock.settimeout(30)
    try:
        key = _new_key("offdst")
        status, body = open_frame(
            sock, f"/off-dst.bin?tpc.key={key}&tpc.stage=push", TPC_FLAGS)
    finally:
        sock.close()

    assert status == KXR_ERROR, (status, body)
    code, msg = err_text(body)
    assert code == XERR_UNSUPPORTED, (code, msg)
    assert "brix_tpc_push off" in msg


# -- security-negative ------------------------------------------------------


def test_the_rendezvous_key_is_single_use(lab):
    """Leg 3 CONSUMES the key, so a replayed push cannot write a second time."""
    key = _new_key("replay")
    register(lab, "/replay.bin", key)

    status, body = push(lab, "ONE_PORT", "/replay.bin", key=key)
    assert status == KXR_OK, err_text(body)
    assert published(lab["dirs"]["dst"], "/replay.bin", SEED)

    status, body = push(lab, "ONE_PORT", "/replay.bin", key=key)
    assert status == KXR_ERROR, (status, body)
    code, msg = err_text(body)
    assert code == XERR_NOT_AUTHORIZED, (code, msg)


def test_destination_outside_the_permit_set_is_refused_before_any_dial(lab):
    """`brix_tpc_source_guard` names the peers this server may originate to —
    and a push originates to its destination, so the same allowlist bounds it.
    The refusal must land at the OPEN, before a socket is dialled."""
    guard = SourceSplice(lab["ports"]["DST_PORT"]).start()
    try:
        status, body, fresh = run_push(lab, "GUARD_PORT", "/guarded.bin",
                                       dst_port=guard.listen, tag="guard")

        assert status == KXR_ERROR, (status, body)
        code, msg = err_text(body)
        assert code == XERR_NOT_AUTHORIZED, (code, msg)
        assert guard.accepted == 0, "the refused destination was dialled anyway"
        assert "signal=tpc_egress" in fresh
        assert source_intact(lab, "guard")
    finally:
        guard.stop()


def test_a_greedy_stream_hint_cannot_exceed_the_server_cap(lab):
    splice = lab["splice"]
    splice.reset()

    status, body, fresh = run_push(lab, "ONE_PORT", "/greedy.bin",
                                   extra="&tpc.str=999",
                                   dst_port=splice.listen, tag="greedy")

    assert status == KXR_OK, err_text(body)
    assert published(lab["dirs"]["dst"], "/greedy.bin", SEED)
    assert splice.accepted == 1, "brix_tpc_streams 1 must clamp tpc.str=999"
    assert "multi-stream" not in fresh


def _sync_frame(fhandle):
    return (struct.pack(">BBH", 0, 1, KXR_SYNC) + fhandle[:4]
            + b"\x00" * 12 + struct.pack(">I", 0))


def _rm_frame(path):
    body = path.encode() + b"\x00"
    return (struct.pack(">BBH", 0, 1, KXR_RM) + b"\x00" * 16
            + struct.pack(">I", len(body)) + body)


def test_a_plain_sync_on_the_push_source_is_still_read_only(lab):
    """The write gate exempts the arm/fire sync of a PUSH handle and nothing
    else: an ordinary read handle on the same read-only plane still meets
    kXR_fsReadOnly when it is sync'd.

    This is the negative half of the exemption in brix_dispatch_require_write.
    kXR_sync is routed through the WRITE dispatch table, so without a scope this
    narrow the fix would have turned every read-only export into one that
    silently accepts a sync.
    """
    sock = _xrd_login(HOST, lab["ports"]["PORT"])
    sock.settimeout(30)
    try:
        status, body = open_frame(sock, SRC_LFN, KXR_OPEN_READ)
        assert status == KXR_OK, err_text(body)
        sock.sendall(_sync_frame(body[:4]))
        status, body = _xrd_recv_status(sock)
    finally:
        sock.close()

    assert status == KXR_ERROR, (status, body)
    code, msg = err_text(body)
    assert code == XERR_FS_READ_ONLY, (code, msg)
    assert "read-only server" in msg


def test_a_namespace_mutation_on_the_push_source_is_still_read_only(lab):
    """The exemption is keyed on the opcode as well as the handle: kXR_rm on the
    push source plane is refused exactly as it was before F16, so enabling the
    push dialect grants a client no mutation privilege on the export."""
    sock = _xrd_login(HOST, lab["ports"]["PORT"])
    sock.settimeout(30)
    try:
        sock.sendall(_rm_frame(SRC_LFN))
        status, body = _xrd_recv_status(sock)
    finally:
        sock.close()

    assert status == KXR_ERROR, (status, body)
    code, msg = err_text(body)
    assert code == XERR_FS_READ_ONLY, (code, msg)
    assert source_intact(lab, "src")


def test_the_exemption_expires_with_the_transfer(lab):
    """A third kXR_sync — after the push has completed and the handle carries
    tpc_done — is refused kXR_fsReadOnly again. The exemption covers the two
    syncs the dialect defines, not the handle for the rest of its life."""
    key = _new_key("expire")
    register(lab, "/expire.bin", key)

    sock = _xrd_login(HOST, lab["ports"]["ONE_PORT"])
    sock.settimeout(180)
    try:
        opaque = (f"?tpc.key={key}&tpc.dst={HOST}:{lab['ports']['DST_PORT']}"
                  f"&tpc.dlfn=/expire.bin&tpc.stage=push")
        status, body = open_frame(sock, SRC_LFN + opaque, KXR_OPEN_READ)
        assert status == KXR_OK, err_text(body)
        fhandle = body[:4]

        status, body = _drive_pull(sock, fhandle)
        assert status == KXR_OK, err_text(body)

        sock.sendall(_sync_frame(fhandle))
        status, body = _xrd_recv_status(sock)
    finally:
        sock.close()

    assert published(lab["dirs"]["dst"], "/expire.bin", SEED)
    assert status == KXR_ERROR, (status, body)
    code, msg = err_text(body)
    assert code == XERR_FS_READ_ONLY, (code, msg)


# -- grammar ----------------------------------------------------------------


def _render_and_test(lifecycle, tmp_path, line):
    reg = lifecycle.register(NginxInstanceSpec(
        name="lc-r20-tpc-push-validate", template="nginx_release20_tpc_validate.conf",
        protocol="none", readiness="none", port=SHARED_PARSE_PLACEHOLDER_PORT,
        data_root=str(tmp_path),
        template_values={"BIND_HOST": BIND_HOST, "TPC_LINES": f"        {line}\n"},
        reason="2.0 F16: brix_tpc_push grammar"))
    endpoint = lifecycle.launcher.render_nginx(reg)
    return subprocess.run([NGINX_BIN, "-t", "-p", endpoint.prefix, "-c", "conf/nginx.conf"],
                          capture_output=True, text=True, timeout=30)


class TestGrammar:
    @pytest.mark.parametrize("line", ["brix_tpc_push on;", "brix_tpc_push off;"])
    def test_the_flag_parses(self, lifecycle, tmp_path, line):
        result = _render_and_test(lifecycle, tmp_path, line)
        assert result.returncode == 0, result.stderr

    def test_a_non_flag_value_is_refused(self, lifecycle, tmp_path):
        result = _render_and_test(lifecycle, tmp_path, "brix_tpc_push maybe;")
        assert result.returncode != 0
        assert 'invalid value "maybe"' in result.stderr
