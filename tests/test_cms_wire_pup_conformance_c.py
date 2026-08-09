from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cms_wire_pup_conformance_helpers")

class TestSupervisorValidOps:
    """Phase-61 W7 PR-B, supervisor leg: supVOps (stock initSUProuting)
    admits namespace mutations but marks them Forward — the supervisor fans
    them DOWN to its own data nodes instead of executing locally — and
    excludes kYR_update entirely."""

    CHILD_DPORT = NODE_DATA_PORT + 11

    def _login_child(self, peer):
        sock = _node_login_dialog(
            peer.node_port,
            _login_payload_with_mode(self.CHILD_DPORT, CMS_MODE_SERVER,
                                     paths=b"r /data"))
        time.sleep(0.4)
        return sock

    def test_supervisor_fans_forwarded_mkdir_down(self, super_stack):
        """kYR_mkdir IS in supVOps, flagged Forward: the supervisor must relay
        it down to its logged-in child — and must NOT create the directory
        locally (a supervisor is a routing tier, not an executor)."""
        child = self._login_child(super_stack)
        try:
            super_stack.send_to_node(
                0x61E00001, CMS_RR_MKDIR, 0,
                _fwd_a_payload(b"mgr", b"755", b"/fan_down_dir"))
            fr = _recv_code(child, CMS_RR_MKDIR, timeout=8.0)
            assert fr is not None, \
                "supervisor must fan a forwarded kYR_mkdir down to its child"
            assert b"/fan_down_dir" in fr[3], \
                "fanned-down op must carry the original path"
            local = os.path.join(_DIR, "lc_cms_wire_super_data",
                                 "fan_down_dir")
            assert not os.path.isdir(local), \
                "supervisor executed a Forward-flagged op locally"
        finally:
            child.close()

    def test_supervisor_drops_update_outside_supvops(self, super_stack):
        """Security-neg: kYR_update is NOT in supVOps — no kYR_status reply
        may come back (auto-role nodes answer update with status), and the
        connection survives."""
        # The upward leg announces kYR_status once right after login
        # (connect.c) — wait it out so collect_reply below can only match a
        # status provoked by the update.
        assert super_stack.wait_for_code(CMS_RR_STATUS, timeout=20.0) \
            is not None, "supervisor never sent its login-time kYR_status"
        super_stack.send_to_node(0x61E00002, CMS_RR_UPDATE, 0)
        assert super_stack.collect_reply(CMS_RR_STATUS, timeout=2.5) is None, \
            "supVOps must drop kYR_update on a supervisor"
        ping_sid = 0x61E00003
        super_stack.send_to_node(ping_sid, CMS_RR_PING, 0)
        alive = super_stack.collect_reply(CMS_RR_PONG, timeout=8.0)
        assert alive is not None and alive[0] == ping_sid, \
            "connection must survive a dropped invalid op"


class TestServerAdmitRoles:
    """Phase-61 W7 PR-C: the CMS server leg classifies a node's login Mode
    like stock Admit — (manager|subman) ? (server ? R : M) : S — and stamps
    the role into the registry (visible in the registration NOTICE)."""

    def test_supervisor_mode_login_admits_role_r(self, cms_server_ep):
        """Mode kYR_manager|kYR_server (0x0A) -> admitted as role R and still
        a fully-functional registrant (statfs sees its advertised space)."""
        dport = NODE_DATA_PORT + 1
        sock = _node_login_dialog(
            cms_server_ep.port, _login_payload_with_mode(dport, 0x0A))
        try:
            assert _wait_log_contains(
                cms_server_ep, f":{dport} role=R".encode()), \
                "supervisor-mode login must register with role=R"
            time.sleep(0.2)
            assert _statfs_wfree(sock, 61) == 5000, \
                "an R-role registrant must still serve/aggregate normally"
        finally:
            sock.close()

    def test_manager_mode_login_admits_role_m(self, cms_server_ep):
        """Mode kYR_manager alone (0x02) -> admitted as role M."""
        dport = NODE_DATA_PORT + 2
        sock = _node_login_dialog(
            cms_server_ep.port, _login_payload_with_mode(dport, 0x02))
        try:
            assert _wait_log_contains(
                cms_server_ep, f":{dport} role=M".encode()), \
                "manager-mode login must register with role=M"
            sock.sendall(_build_frame(62, CMS_RR_PING, 0))
            fr = _recv_code(sock, CMS_RR_PONG, timeout=5.0)
            assert fr is not None, "M-role registrant must stay serviceable"
        finally:
            sock.close()

    def test_unrelated_mode_bits_default_role_s(self, cms_server_ep):
        """Security-neg: a Mode word carrying only non-role bits (kYR_nostage,
        0x200) grants nothing — the node is classified plain server (role=S),
        the safe default."""
        dport = NODE_DATA_PORT + 3
        sock = _node_login_dialog(
            cms_server_ep.port, _login_payload_with_mode(dport, 0x200))
        try:
            assert _wait_log_contains(
                cms_server_ep, f":{dport} role=S".encode()), \
                "non-role Mode bits must fall back to role=S"
        finally:
            sock.close()


class TestStateRelayRecursion:
    """Phase-61 W7 PR-D: ``brix_cms_state_relay`` — on a registry miss a
    supervisor re-asks its own children and echoes the first kYR_have back up
    under the parent's streamid.  Default is OFF (silent miss)."""

    CHILD_DPORT = NODE_DATA_PORT + 10

    def _login_child(self, peer):
        """Register a Python child under the supervisor with a NARROW export
        (r /data) so a probe outside it is a registry miss."""
        sock = _node_login_dialog(
            peer.node_port,
            _login_payload_with_mode(self.CHILD_DPORT, CMS_MODE_SERVER,
                                     paths=b"r /data"))
        time.sleep(0.4)
        return sock

    def test_supervisor_login_mode_word(self, super_stack):
        """brix_cms_role supervisor -> upward LOGIN Mode is exactly
        kYR_manager|kYR_server (0x0A), the stock supervisor Pander word."""
        fr = super_stack.wait_for_code(CMS_RR_LOGIN, timeout=20.0)
        assert fr is not None, "supervisor did not emit a LOGIN frame"
        login = _decode_login(fr[3])
        assert login["mode"] == (CMS_MODE_MANAGER | CMS_MODE_SERVER), \
            f"supervisor must log in with Mode 0x0A, got {login['mode']:#x}"

    def test_state_relay_round_trip(self, super_stack):
        """Parent kYR_state for a path outside every child export (registry
        miss) is relayed DOWN to the child; the child's kYR_have is echoed
        back UP under the parent's original streamid.  The relayed probe MUST
        carry kYR_metaman: a brix_manager_mode instance keeps root_canon empty
        (no confined local export, process_server_init.c), so it holds nothing
        itself — stock do_State stamps kYR_metaman for exactly such a
        non-server sender."""
        child = self._login_child(super_stack)
        try:
            up_sid = 0x61D00001
            path = b"/elsewhere/wanted.bin"
            super_stack.send_to_node(up_sid, CMS_RR_STATE, CMS_MOD_RAW,
                                     path + b"\x00")
            fr = _recv_code(child, CMS_RR_STATE, timeout=8.0)
            assert fr is not None, \
                "relay-on supervisor must re-ask its child on a registry miss"
            down_sid, _code, mod, payload = fr
            assert payload.rstrip(b"\x00") == path, \
                "relayed probe must carry the parent's path verbatim"
            assert mod & CMS_MOD_RAW, "relayed kYR_state must be raw"
            assert mod & CMS_STATE_METAMAN, \
                "a no-local-export manager tier must stamp kYR_metaman"
            child.sendall(_build_frame(down_sid, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       path + b"\x00"))
            up = super_stack.wait_for_code(CMS_RR_HAVE, timeout=8.0)
            assert up is not None, \
                "child kYR_have must be echoed up to the parent"
            assert up[0] == up_sid, \
                "upward kYR_have must carry the PARENT's original streamid"
            assert up[3].rstrip(b"\x00") == path
        finally:
            child.close()

    def test_state_relay_default_off_is_silent(self, super_stack_norelay):
        """Default (brix_cms_state_relay off): a registry miss stays silent —
        nothing is relayed to the child and the parent gets no kYR_have."""
        child = self._login_child(super_stack_norelay)
        try:
            super_stack_norelay.send_to_node(0x61D00002, CMS_RR_STATE,
                                             CMS_MOD_RAW,
                                             b"/elsewhere/wanted.bin\x00")
            assert _recv_code(child, CMS_RR_STATE, timeout=3.0) is None, \
                "relay must be OFF by default — child saw a relayed probe"
            # Full-history scan (fresh peer): no kYR_have may EVER go upward.
            assert super_stack_norelay.wait_for_code(CMS_RR_HAVE, timeout=2.0) \
                is None, "silent miss must stay silent upward"
        finally:
            child.close()

    def test_relay_to_no_eligible_node_is_silent_but_logged(self, super_stack):
        """With relay ON and NO child logged in, a registry miss parks a leg
        that nobody can answer.  The parent still reads silence (unchanged
        wire behaviour), but the drop is visible at INFO — a debug-only
        counter would be invisible in every build that hits this."""
        super_stack.send_to_node(0x61D0000A, CMS_RR_STATE, CMS_MOD_RAW,
                                 b"/elsewhere/nobody.bin\x00")
        assert _wait_log_contains(
            super_stack.ep, b"down to no eligible node"), \
            "a relay that reached no node must say so in the error log"
        assert super_stack.wait_for_code(CMS_RR_HAVE, timeout=2.0) is None, \
            "a relay that reached no node must stay silent upward"

    def test_state_probe_path_is_escaped_in_the_error_log(self, super_stack):
        """Security-neg (WS6): the kYR_state path is manager-controlled and
        ``cms_state_extract_path`` accepts every byte but NUL — including
        CR/LF.  Logged raw it would let a hostile manager forge whole
        ``cmsd-action`` lines into error.log; every log site must render it
        through ``brix_sanitize_log_string``."""
        forged = b"/elsewhere/x\ncmsd-action op=login peer=evil dir=in"
        super_stack.send_to_node(0x61D0000B, CMS_RR_STATE, CMS_MOD_RAW,
                                 forged + b"\x00")
        # the escaped form must appear; the injected raw newline must not
        assert _wait_log_contains(super_stack.ep, rb"/elsewhere/x\x0A"), \
            "the probed path must reach the log hex-escaped"
        path = os.path.join(super_stack.ep.prefix, "logs", "error.log")
        with open(path, "rb") as fh:
            for line in fh:
                assert not line.startswith(b"cmsd-action"), \
                    f"forged log line landed unescaped: {line!r}"

    def test_supervisor_fan_down_to_no_node_is_logged(self, super_stack):
        """A forwarded mutation that reaches no data node is a silently
        dropped op — the one outcome of the fan-down worth a WARN."""
        super_stack.send_to_node(
            0x61D0000C, CMS_RR_MKDIR, 0,
            _fwd_a_payload(b"mgr", b"755", b"/fan_down_nobody"))
        assert _wait_log_contains(super_stack.ep, b"reached no node"), \
            "a fan-down that reached no node must be logged"

    def test_unsolicited_child_have_cannot_reach_parent(self, super_stack):
        """Security-neg: a child kYR_have whose streamid was never issued by
        the relay (a forged/unsolicited claim) must NOT surface upward as a
        parent-facing kYR_have."""
        child = self._login_child(super_stack)
        try:
            child.sendall(_build_frame(0x0666BEEF, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       b"/forged/claim.bin\x00"))
            # Full-history scan (fresh peer): a forged HAVE that leaked up
            # before this call would still be caught.
            assert super_stack.wait_for_code(CMS_RR_HAVE, timeout=3.0) is None, \
                "unsolicited child kYR_have leaked up to the parent"
        finally:
            child.close()

    def test_forged_path_on_issued_streamid_refused_then_honest_lands(
            self, super_stack):
        """Security-neg + success: the relay trust anchor is streamid AND
        exact probed path.  A kYR_have on the REAL relay streamid but a
        different path must be refused WITHOUT consuming the entry — the
        honest answer for the probed path must still be echoed upward."""
        child = self._login_child(super_stack)
        try:
            up_sid = 0x61D00004
            path = b"/elsewhere/wanted.bin"
            super_stack.send_to_node(up_sid, CMS_RR_STATE, CMS_MOD_RAW,
                                     path + b"\x00")
            fr = _recv_code(child, CMS_RR_STATE, timeout=8.0)
            assert fr is not None, "child never saw the relayed probe"
            down_sid = fr[0]
            child.sendall(_build_frame(down_sid, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       b"/elsewhere/DECOY.bin\x00"))
            # Full-history scan (fresh peer): nothing has been echoed yet,
            # so any upward kYR_have here is the forgery leaking through.
            assert super_stack.wait_for_code(CMS_RR_HAVE, timeout=2.5) \
                is None, "forged-path kYR_have on a real streamid leaked up"
            child.sendall(_build_frame(down_sid, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       path + b"\x00"))
            up = super_stack.wait_for_code(CMS_RR_HAVE, timeout=8.0)
            assert up is not None, \
                "forged path consumed the relay entry — honest answer lost"
            assert up[0] == up_sid and up[3].rstrip(b"\x00") == path, \
                "upward echo must carry the parent streamid + probed path"
        finally:
            child.close()

    def test_relay_entry_is_single_use(self, super_stack):
        """A consumed relay entry is gone: replaying the identical honest
        kYR_have must not produce a second upward echo (no amplification /
        stale-entry reuse)."""
        child = self._login_child(super_stack)
        try:
            up_sid = 0x61D00005
            path = b"/elsewhere/wanted.bin"
            super_stack.send_to_node(up_sid, CMS_RR_STATE, CMS_MOD_RAW,
                                     path + b"\x00")
            fr = _recv_code(child, CMS_RR_STATE, timeout=8.0)
            assert fr is not None, "child never saw the relayed probe"
            have = _build_frame(fr[0], CMS_RR_HAVE,
                                CMS_MOD_RAW | CMS_HAVE_ONLINE, path + b"\x00")
            child.sendall(have)
            assert super_stack.wait_for_code(CMS_RR_HAVE, timeout=8.0) \
                is not None, "honest kYR_have was not echoed upward"
            before = super_stack.count_frames(CMS_RR_HAVE)
            child.sendall(have)
            time.sleep(2.0)
            assert super_stack.count_frames(CMS_RR_HAVE) == before, \
                "replayed kYR_have re-used a consumed relay entry"
        finally:
            child.close()

    def test_unsolicited_have_does_not_poison_loc_cache(self, super_stack):
        """Security-neg: a dropped unsolicited kYR_have must leave NO trace —
        a later parent probe for that very path must still be a miss that is
        relayed down to the child (a cached forgery would answer it directly
        and short-circuit the relay)."""
        child = self._login_child(super_stack)
        try:
            path = b"/elsewhere/poison.bin"
            child.sendall(_build_frame(0x0666AAAA, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       path + b"\x00"))
            time.sleep(0.5)
            super_stack.send_to_node(0x61D00006, CMS_RR_STATE, CMS_MOD_RAW,
                                     path + b"\x00")
            fr = _recv_code(child, CMS_RR_STATE, timeout=8.0)
            assert fr is not None, \
                "probe was not relayed — the forged kYR_have was cached"
            assert fr[3].rstrip(b"\x00") == path
            # And the forgery itself must never have surfaced upward.
            assert super_stack.wait_for_code(CMS_RR_HAVE, timeout=2.0) \
                is None, "forged kYR_have surfaced upward"
        finally:
            child.close()
