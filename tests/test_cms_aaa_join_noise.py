from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cms_aaa_join_noise_helpers")

class TestJoinAcrossImpairedWan:

    def test_joins_through_latency_and_jitter(self, site):
        """A WAN-like link (120ms base + up to 80ms jitter) must not stop the
        join: the redirector receives a LOGIN and the node reports itself in."""
        site.link.ctl("latency 120")
        site.link.ctl("jitter 80")

        assert site.peer.wait_connections(1, timeout=JOIN_TIMEOUT), \
            "node never dialed the redirector across the impaired link"
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT), \
            "no LOGIN frame reached the redirector"
        assert site.wait_registered(True, timeout=JOIN_TIMEOUT), \
            "node did not report itself registered after a successful LOGIN"
        assert site.counter("brix_cms_logins_total") >= 1

    def test_login_survives_segmentation_and_reordering(self, site):
        """The LOGIN frame chopped into 4-byte segments, half of them held back
        and delivered late, must still parse as ONE well-formed frame upstream —
        the redirector's parser is the oracle, so a desynced stream would show
        up as a missing or garbage-coded frame, not a passing test."""
        site.link.ctl("chunk 4")
        site.link.ctl("reorder 50 40")

        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT), \
            "segmented + reordered LOGIN never reassembled upstream"
        # Nothing ahead of the LOGIN: a desync would surface as a bogus code
        # parsed out of misaligned bytes before it.
        assert site.peer.frame_codes[0] == CMS_RR_LOGIN, \
            f"stream desynced: first frame code was {site.peer.frame_codes[0]}"

    def test_heartbeats_continue_under_sustained_noise(self, site):
        """Staying joined is the hard part: with the link still degrading every
        chunk, the 1s LOAD heartbeat must keep arriving and the gauge must not
        flap back to 0."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        site.link.ctl("latency 60")
        site.link.ctl("chunk 8")

        assert site.peer.wait_frames(CMS_RR_LOAD, 3, timeout=JOIN_TIMEOUT), \
            "heartbeats stopped once the link started degrading every chunk"
        assert site.counter("brix_cms_registered_links") == 1, \
            "node dropped out of the mesh while merely slow (not disconnected)"


# --------------------------------------------------------------------------- #
# ERROR — outage, refusal, sever; and the data plane through all of it         #
# --------------------------------------------------------------------------- #

class TestOutageAndRejoin:

    def test_silent_redirector_drops_gauge_and_keeps_data_plane(self, site):
        """A black-holed redirector (accepts, never answers) must be caught by
        the read deadline: the join gauge falls to 0 — the node knows it is OUT
        of the mesh — while physics clients keep getting served."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        site.link.ctl("hang")

        assert site.wait_registered(False, timeout=REJOIN_TIMEOUT), \
            "black-holed redirector never dropped the registration gauge"
        assert site.counter("brix_cms_read_timeouts_total") >= 1, \
            "read-liveness never fired against a silent redirector"
        assert site.data_plane_alive(), \
            "a silent redirector took the data plane down with it"

    def test_refused_link_counts_failures_without_busy_spin(self, site):
        """With nothing listening, the node must keep trying — but on a backoff,
        not a hot loop.  Ten seconds of outage may legitimately produce a
        handful of attempts; hundreds would mean a 0ms-timer footgun burning a
        core at every AAA site in the federation."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        site.link.down()

        before = site.counter("brix_cms_connect_failures_total")
        assert site.wait_registered(False, timeout=REJOIN_TIMEOUT), \
            "refused link never dropped the registration gauge"
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            time.sleep(0.5)
        after = site.counter("brix_cms_connect_failures_total")
        attempts = after - before

        assert attempts >= 1, \
            f"a refused dial produced no connect failures ({before} -> {after})"
        assert attempts < 100, \
            f"{attempts} dial attempts in 3s — retry is busy-spinning, not backing off"
        assert site.data_plane_alive(), \
            "a refused federation leg took the data plane down with it"

    def test_accept_then_close_redirector_is_bounded(self, site):
        """A redirector that accepts and instantly closes — an overloaded cmsd,
        or a load balancer with no live backend behind it — is the nastiest
        outage shape, because every cycle looks like a fresh successful login
        and so resets the backoff.  The reconnect rate must still stay bounded
        by the heartbeat interval rather than becoming a hot loop."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        site.link.ctl("block")          # accept-then-close, not refuse

        before = site.counter("brix_cms_logins_total")
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            time.sleep(0.5)
        cycles = site.counter("brix_cms_logins_total") - before

        assert cycles < 100, \
            f"{cycles} login cycles in 3s against a closing redirector — hot loop"
        assert site.data_plane_alive(), \
            "an accept-then-close redirector took the data plane down with it"
        assert not site.worker_crashes(), \
            f"worker died against a closing redirector: {site.worker_crashes()}"

    def test_rejoins_when_the_link_heals(self, site):
        """The whole point of the retry loop: when the WAN comes back the site
        must re-register itself without operator action."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        logins_before = site.counter("brix_cms_logins_total")
        site.link.down()
        assert site.wait_registered(False, timeout=REJOIN_TIMEOUT), \
            "link outage never dropped the registration gauge"

        site.link.up()
        assert site.wait_registered(True, timeout=REJOIN_TIMEOUT), \
            "node never rejoined after the link healed"
        assert site.counter("brix_cms_logins_total") > logins_before, \
            "rejoin did not re-issue a LOGIN"
        assert site.peer.wait_frames(CMS_RR_LOGIN, 2, timeout=REJOIN_TIMEOUT), \
            "the redirector never saw the second registration"

    def test_midstream_sever_reregisters(self, site):
        """A link that severs established connections (the classic WAN reset)
        must be recovered from in-place, not just at cold start."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        conns_before = site.peer.connections
        site.link.ctl("lossy 100")

        deadline = time.monotonic() + 15.0
        while site.peer.connections <= conns_before and time.monotonic() < deadline:
            time.sleep(0.25)
        assert site.peer.connections > conns_before, \
            "severing link never forced a reconnect"

        site.link.ctl("clear")
        assert site.wait_registered(True, timeout=REJOIN_TIMEOUT), \
            "node did not re-register after the severing stopped"
        assert not site.worker_crashes(), \
            f"worker died during sever/recover: {site.worker_crashes()}"


# --------------------------------------------------------------------------- #
# SECURITY / NEG — a hostile redirector on the far side of a noisy link        #
# --------------------------------------------------------------------------- #

class TestHostileRedirectorAcrossLink:

    def test_corrupted_downstream_bytes_never_crash_the_node(self, site):
        """Bit-flipped manager→node traffic is indistinguishable from a MITM.
        The node must treat it as garbage — drop/recycle the link — and never
        fault, and must keep serving data throughout."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        site.link.ctl("corrupt 25 down")

        for _ in range(20):
            site.peer.send_to_node(0, CMS_RR_LOAD, 0, b"\x00" * 32)
            time.sleep(0.1)

        assert site.data_plane_alive(), \
            "corrupted federation traffic wedged the data plane"
        assert not site.worker_crashes(), \
            f"worker died on corrupted CMS input: {site.worker_crashes()}"

    def test_oversized_downstream_frame_is_refused_not_buffered(self, site):
        """A redirector claiming a 64KiB frame body (past the 4KiB CMS ceiling)
        must be refused rather than believed: the node recycles the link and
        rejoins, with no unbounded read behind it."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        conns_before = site.peer.connections

        # Header advertises 0xFFFF bytes; only a few follow — a node that
        # trusted dlen would block forever waiting for the rest.
        site.peer.send_to_node(0, CMS_RR_LOAD, 0, b"")
        with site.peer._lock:
            conn = site.peer.conn
        if conn is not None:
            try:
                conn.sendall(struct.pack(">IBBH", 0, CMS_RR_LOAD, 0, 0xFFFF)
                             + b"\x41" * 16)
            except OSError:
                pass

        assert site.peer.wait_connections(conns_before + 1, timeout=REJOIN_TIMEOUT), \
            "node neither refused nor recycled the oversized-framing link"
        assert site.data_plane_alive(), \
            "an oversized CMS frame wedged the data plane"
        assert not site.worker_crashes(), \
            f"worker died on an oversized CMS frame: {site.worker_crashes()}"

    def test_unsolicited_frame_storm_does_not_starve_the_data_plane(self, site):
        """Phase-61 proved a flood cannot wedge the CMS leg itself.  The AAA
        question is the other direction: a redirector spraying frames must not
        starve the worker that physics clients share with it."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)

        for i in range(400):
            site.peer.send_to_node(i, CMS_RR_LOAD, 0, _build_frame(0, 0, 0)[:4])

        assert site.data_plane_alive(), \
            "a redirector frame storm starved the data plane"
        assert not site.worker_crashes(), \
            f"worker died under a redirector frame storm: {site.worker_crashes()}"


# --------------------------------------------------------------------------- #
# NOISE — heavy data-plane activity must not cost the site its registration    #
# --------------------------------------------------------------------------- #

class TestDataPlaneNoise:

    def test_connection_storm_keeps_the_site_registered(self, site):
        """The realistic AAA noise case: a job burst opens hundreds of client
        connections at once.  The single worker that carries them ALSO carries
        the federation leg — if the storm starves it, the redirector times the
        site out and the site silently leaves the mesh.  Heartbeats must keep
        flowing straight through the storm."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        loads_before = site.peer.count_frames(CMS_RR_LOAD)

        socks = []
        try:
            for _ in range(200):
                try:
                    s = socket.create_connection((HOST, site.port), timeout=5)
                    s.sendall(struct.pack(">5i", 0, 0, 0, 4, 2012))
                    socks.append(s)
                except OSError:
                    break
            def _assert_test_connection_storm_keeps_the_site_registered_2():
                assert len(socks) >= 50, \
                    f"only {len(socks)} of 200 storm connections were accepted"
    
                assert site.peer.wait_frames(CMS_RR_LOAD, loads_before + 3,
                                             timeout=JOIN_TIMEOUT), \
                    "heartbeats stalled under a client connection storm — the site " \
                    "would be timed out of the federation"

            _assert_test_connection_storm_keeps_the_site_registered_2()
            assert site.counter("brix_cms_registered_links") == 1, \
                "site dropped out of the mesh under data-plane load"
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass

        def _assert_test_connection_storm_keeps_the_site_registered_1():
            assert site.data_plane_alive(), \
                "node stopped accepting clients after the storm drained"
            assert not site.worker_crashes(), \
                f"worker died under a connection storm: {site.worker_crashes()}"

        _assert_test_connection_storm_keeps_the_site_registered_1()

    def test_storm_churn_does_not_leak_the_registration(self, site):
        """Repeated connect/abort churn (jobs dying on the batch farm) must
        leave the join gauge at exactly 1 — not incremented per churn cycle,
        which would make the fleet-wide 'sites in the mesh' panel meaningless."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)

        for _ in range(150):
            try:
                s = socket.create_connection((HOST, site.port), timeout=3)
                s.sendall(struct.pack(">5i", 0, 0, 0, 4, 2012))
                s.close()          # abort without a graceful close
            except OSError:
                pass

        assert site.wait_registered(True, timeout=JOIN_TIMEOUT), \
            "connection churn cost the site its registration"
        assert site.counter("brix_cms_registered_links") == 1, \
            "registration gauge drifted above 1 — the login/teardown pair leaks"
