from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cms_hostile_conformance_helpers")
from test_cms_hostile_conformance_h import _BYTE_IDS, _DENSE_SIDS, _FULL_BYTE
from test_cms_hostile_conformance_e import _SWEEP_GARBAGE

class TestServerStreamidDenseSweep:
    """A ping at each of 256 densely-spread streamids is parsed as the unsigned
    wire value and answered -- no streamid word can misframe or drop the ping."""

    @pytest.mark.parametrize("sid", _DENSE_SIDS, ids=["0x%08x" % s for s in _DENSE_SIDS])
    def test_dense_streamid_ping_answered(self, sweep_server, sid):
        sock = socket.create_connection((H, sweep_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(_build_frame(sid, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a ping at streamid 0x%08x was not answered" % sid
        finally:
            sock.close()


# Every pipeline depth 1..128, spanning the 64-per-wakeup fairness batch edge.
_PIPE_FINE = list(range(1, 129))


class TestServerPipeliningFineSweep:
    """Every pipeline depth 1..128 in a single write draws EXACTLY that many
    pongs -- no frame is dropped at the 64-per-wakeup fairness boundary, and
    every excess frame reassembles across subsequent wakeups."""

    @pytest.mark.parametrize("n", _PIPE_FINE, ids=[str(n) for n in _PIPE_FINE])
    def test_pipelined_depth_all_answered(self, sweep_server, n):
        sock = socket.create_connection((H, sweep_server.port), timeout=10)
        sock.settimeout(10)
        try:
            sock.sendall(b"".join(
                _build_frame(_SID | (i & 0xFFFF), CMS_RR_PING, 0) for i in range(n)))
            got = 0
            for _ in range(n):
                if _recv_code(sock, CMS_RR_PONG, timeout=8) is None:
                    break
                got += 1
            assert got == n, "pipelined %d pings drew only %d pongs" % (n, got)
        finally:
            sock.close()


# --- node-leg full-byte sweeps (appended LAST) -----------------------------

class TestNodeStatusFullModifierSweep:
    """kYR_status DOWN into the node across the ENTIRE modifier byte range -- the
    node's manager-leg status handler never permanently hangs up the upward leg."""

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_node_status_modifier_survives(self, sweep_node, mod):
        try:
            sweep_node.send_to_node(_SID | 0x210, CMS_RR_STATUS, mod)
        except (AssertionError, OSError, AttributeError):
            pass
        assert _node_survives(sweep_node), \
            "the node upward leg died after kYR_status modifier 0x%02x" % mod


class TestNodeHaveFullModifierSweep:
    """kYR_have (empty body) DOWN into the node across the ENTIRE modifier byte
    range -- dropped for every online/pending/raw combination, upward leg alive."""

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_node_have_modifier_survives(self, sweep_node, mod):
        try:
            sweep_node.send_to_node(_SID | 0x220, CMS_RR_HAVE, mod)
        except (AssertionError, OSError, AttributeError):
            pass
        assert _node_survives(sweep_node), \
            "the node upward leg died after kYR_have modifier 0x%02x" % mod


class TestNodeLoadFullModifierSweep:
    """kYR_load (empty body) DOWN into the node across the ENTIRE modifier byte
    range -- a bounded metric update for every modifier, upward leg alive."""

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_node_load_modifier_survives(self, sweep_node, mod):
        try:
            sweep_node.send_to_node(_SID | 0x230, CMS_RR_LOAD, mod)
        except (AssertionError, OSError, AttributeError):
            pass
        assert _node_survives(sweep_node), \
            "the node upward leg died after kYR_load modifier 0x%02x" % mod


class TestNodeAvailFullModifierSweep:
    """kYR_avail (empty body) DOWN into the node across the ENTIRE modifier byte
    range -- a bounded free-space update for every modifier, upward leg alive."""

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_node_avail_modifier_survives(self, sweep_node, mod):
        try:
            sweep_node.send_to_node(_SID | 0x240, CMS_RR_AVAIL, mod)
        except (AssertionError, OSError, AttributeError):
            pass
        assert _node_survives(sweep_node), \
            "the node upward leg died after kYR_avail modifier 0x%02x" % mod


class TestNodeOpcodeByteFullSweep:
    """Every rrCode byte 0..255, garbage-bodied, DOWN into the node.  No opcode
    value can permanently hang up the node's upward leg -- a manager ping is
    answered after each (through a forced reconnect if any)."""

    @pytest.mark.parametrize("code", _FULL_BYTE, ids=_BYTE_IDS)
    def test_node_opcode_byte_survives(self, sweep_node, code):
        try:
            sweep_node.send_to_node(_SID | (code & 0xFF), code, 0, _SWEEP_GARBAGE)
        except (AssertionError, OSError, AttributeError):
            pass
        assert _node_survives(sweep_node), \
            "the node upward leg died after opcode byte 0x%02x" % code
