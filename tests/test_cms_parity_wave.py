# test_cms_parity_wave.py - the CMS parity wave's test bodies.  The suite's
# docstring, wire constants, fake data node, stub manager and the client/probe
# helpers live in _test_cms_parity_wave_helpers.py; `reexport` pulls that whole
# namespace (private helpers included) in here, so each test reads exactly as it
# did before the split.
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cms_parity_wave_helpers")


# ═══ §2.2 SUPCount floor ══════════════════════════════════════════════════

def test_floor_holds_then_serves(lifecycle):
    """success+error: below the floor locate answers kXR_wait(delay_hold);
    reaching it flips to redirects."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "brix_cms_delay_servers 2; brix_cms_delay_hold 3;",
              "§2.2 SUPCount floor: hold below 2 registered servers.")
    n1 = FakeNode(cms_port, 42201)
    try:
        # One node registered: every locate is held with kXR_wait(3).
        deadline = time.time() + 8
        status = body = None
        while time.time() < deadline:
            status, body = _locate(root_port, "/floor.dat")
            if status == kXR_wait:
                break
            time.sleep(0.2)
        assert status == kXR_wait, f"expected kXR_wait below floor: {status}"
        assert struct.unpack(">I", body[:4])[0] == 3, body

        # Second node: the floor is met — locates redirect.
        n2 = FakeNode(cms_port, 42202)
        try:
            got = _wait_selectable(root_port, "/floor.dat", None)
            assert got in (42201, 42202)
        finally:
            n2.close()
    finally:
        n1.close()


# ═══ §2.3 cms.sched component weights + maxload ═══════════════════════════

def test_sched_picks_cooler_cpu(lifecycle):
    """success: with cpu-weighted sched, the node reporting the lower cpu
    byte wins even though both are otherwise identical."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "brix_cms_sched cpu 100 maxload 50;",
              "§2.3 cms.sched: cpu-weighted selection + maxload ceiling.")
    hot = FakeNode(cms_port, 42211)
    cool = FakeNode(cms_port, 42212)
    try:
        hot.send(CMS_RR_LOAD, 0, _load_payload(cpu=90))
        cool.send(CMS_RR_LOAD, 0, _load_payload(cpu=10))
        time.sleep(0.5)   # let the manager ingest both LOADs
        got = _wait_selectable(root_port, "/sched.dat", 42212)
        assert got == 42212
    finally:
        hot.close()
        cool.close()


def test_sched_maxload_degrades_not_refuses(lifecycle):
    """error-path: when EVERY matching node is over maxload, selection
    degrades to the least-loaded overloaded node instead of failing."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "brix_cms_sched cpu 100 maxload 50;",
              "§2.3 cms.sched: cpu-weighted selection + maxload ceiling.")
    hot = FakeNode(cms_port, 42213)
    try:
        hot.send(CMS_RR_LOAD, 0, _load_payload(cpu=95))
        time.sleep(0.5)
        got = _wait_selectable(root_port, "/sched2.dat", 42213)
        assert got == 42213
    finally:
        hot.close()


# ═══ §2.5 stage-aware selection ═══════════════════════════════════════════

def test_stage_select_prefers_stage_node(lifecycle):
    """success: a read of a file no node holds goes to the stage-capable
    node, even though the disk-only node is far less utilised."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "brix_cms_stage_select on;",
              "§2.5 stage-aware selection.")
    disk = FakeNode(cms_port, 42221, util=1)
    tape = FakeNode(cms_port, 42222, util=90)
    try:
        tape.send(CMS_RR_STATUS, CMS_ST_STAGE)      # advertise staging
        time.sleep(0.5)
        got = _wait_selectable(root_port, "/on-tape-only.dat", 42222)
        assert got == 42222
    finally:
        disk.close()
        tape.close()


def test_stage_select_off_keeps_util_pick(lifecycle):
    """error/negative: withOUT the directive the least-utilised node keeps
    winning — the stage bit alone must not divert selection."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr", "",
              "§2.5 control: stage bit without brix_cms_stage_select.")
    disk = FakeNode(cms_port, 42223, util=1)
    tape = FakeNode(cms_port, 42224, util=90)
    try:
        tape.send(CMS_RR_STATUS, CMS_ST_STAGE)
        time.sleep(0.5)
        got = _wait_selectable(root_port, "/no-stage-sel.dat", 42223)
        assert got == 42223
    finally:
        disk.close()
        tape.close()


# ═══ §2.6/§2.7 negative location cache + kXR_refresh ══════════════════════

def test_emptylife_negative_cache(lifecycle):
    """success: after a fan-out expires with no kYR_have, the retry answers
    kXR_NotFound immediately from the negative entry."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "brix_cms_locate_window 400ms; brix_cms_emptylife 10s;",
              "§2.6 negative location cache (emptylife).")
    node = FakeNode(cms_port, 42231)      # never answers kYR_state
    try:
        node.wait_frame(CMS_RR_PING)     # wait until fully registered
        status, body = _first_wait_then(root_port, "/neg-cached.dat")
        assert status == kXR_error, f"expected NotFound, got {status}"
        assert struct.unpack(">I", body[:4])[0] == kXR_NotFound
        # The node WAS probed (the fan-out ran once).
        assert node.count(CMS_RR_STATE) >= 1
    finally:
        node.close()


def test_refresh_bypasses_negative_cache(lifecycle):
    """§2.7: a kXR_refresh locate must NOT be answered from the negative
    entry — it re-probes the cluster (parks again: kXR_wait)."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "brix_cms_locate_window 400ms; brix_cms_emptylife 10s;",
              "§2.6 negative location cache (emptylife).")
    node = FakeNode(cms_port, 42232)
    try:
        node.wait_frame(CMS_RR_PING)
        status, body = _first_wait_then(root_port, "/neg-refresh.dat")
        assert status == kXR_error       # negative entry in place
        probes_before = node.count(CMS_RR_STATE)
        status, _body = _locate(root_port, "/neg-refresh.dat",
                                options=kXR_refresh)
        assert status == kXR_wait, (
            f"refresh must re-probe (park), got {status}")
        deadline = time.time() + 4
        while time.time() < deadline \
                and node.count(CMS_RR_STATE) <= probes_before:
            time.sleep(0.1)
        assert node.count(CMS_RR_STATE) > probes_before, (
            "refresh locate never re-probed the node")
    finally:
        node.close()


def test_no_emptylife_keeps_reparking(lifecycle):
    """control: without emptylife the retry parks again (kXR_wait) — the
    negative path must be strictly opt-in."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "brix_cms_locate_window 400ms;",
              "§2.6 control: fan-out without emptylife.")
    node = FakeNode(cms_port, 42233)
    try:
        node.wait_frame(CMS_RR_PING)
        status, _body = _first_wait_then(root_port, "/no-neg.dat")
        assert status == kXR_wait, f"expected re-park, got {status}"
    finally:
        node.close()


# ═══ §2.8 cms.dfs shared-filesystem mode ══════════════════════════════════

def test_dfs_skips_state_fanout(lifecycle):
    """success: with cms.dfs the locate never probes the node (no kYR_state)
    and redirects immediately by load."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "brix_cms_locate_window 400ms; brix_cms_dfs on;",
              "§2.8 cms.dfs: shared-FS mode skips the per-file probe.")
    node = FakeNode(cms_port, 42241)
    try:
        got = _wait_selectable(root_port, "/dfs-any-file.dat", 42241)
        assert got == 42241
        assert node.count(CMS_RR_STATE) == 0, (
            "dfs mode must not send kYR_state probes")
    finally:
        node.close()


# ═══ §2.9 ManTree-style supervisor offload ════════════════════════════════

def test_max_direct_offloads_to_supervisor(lifecycle):
    """success: past max_direct, a NEW server login gets kYR_try naming the
    registered supervisor and the connection is closed."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "",
              "§2.9 ManTree: login offload to the supervisor at the cap.",
              srv_extra="brix_cms_server_max_direct 1;")
    sup = FakeNode(cms_port, 42251, mode=MODE_SERVER | MODE_MANAGER)
    s1 = FakeNode(cms_port, 42252)
    try:
        s1.wait_frame(CMS_RR_PING)       # s1 registered: cap reached
        s2 = FakeNode(cms_port, 42253)
        try:
            frame = s2.wait_frame(CMS_RR_TRY)
            assert frame is not None, "second server never got kYR_try"
            _c, _m, payload = frame
            host = payload.split(b"\x00")[0].decode()
            port = struct.unpack(">H", payload[len(host) + 1:
                                               len(host) + 3])[0]
            assert host == NODE_IP and port == 42251, (host, port)
            assert s2.wait_closed(), "offloaded login must be closed"
        finally:
            s2.close()
    finally:
        sup.close()
        s1.close()


def test_max_direct_without_supervisor_admits(lifecycle):
    """error-path: at the cap with NO supervisor registered, the login is
    admitted directly — never refused outright."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "",
              "§2.9 ManTree: no supervisor -> direct admission.",
              srv_extra="brix_cms_server_max_direct 1;")
    # Disjoint exports so /d2/* matches ONLY the second node — otherwise the
    # first node (exporting "/") would also be a valid selection target.
    s1 = FakeNode(cms_port, 42254, paths=b"r /d1")
    try:
        s1.wait_frame(CMS_RR_PING)
        s2 = FakeNode(cms_port, 42255, paths=b"r /d2")
        try:
            got = _wait_selectable(root_port, "/d2/x.dat", 42255)
            assert got == 42255
        finally:
            s2.close()
    finally:
        s1.close()


# ═══ §2.13 blacklist patterns / redirect / whitelist ══════════════════════

def test_blacklist_pattern_drains(lifecycle, tmp_path):
    """success: a `*` host pattern (XrdOucNList rules) drains the node —
    locate stops redirecting to it."""
    bl = tmp_path / "bl.txt"
    bl.write_text("127.0.0.*\n")   # net-literal-allow: pattern under test
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "",
              "§2.13 blacklist `*` host patterns.",
              srv_extra=f"brix_cms_blacklist_file {bl};")
    node = FakeNode(cms_port, 42261)
    try:
        node.wait_frame(CMS_RR_PING)
        # Drained from registration: locate must answer NotFound, never a
        # redirect to the pattern-banned node.
        deadline = time.time() + 8
        status = None
        while time.time() < deadline:
            status, body = _locate(root_port, "/blpat.dat")
            if status == kXR_error \
                    and struct.unpack(">I", body[:4])[0] == kXR_NotFound:
                break
            assert status != kXR_redirect, "pattern-banned node was selected"
            time.sleep(0.2)
        assert status == kXR_error
    finally:
        node.close()


def test_blacklist_redirect_entry_bounces_login(lifecycle, tmp_path):
    """success: a `redirect <host:port>` action answers the login with
    kYR_try naming the alternate manager and closes."""
    bl = tmp_path / "bl.txt"
    bl.write_text(f"{NODE_IP} redirect {NODE_IP}:42999\n")
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "",
              "§2.13 blacklist redirect action.",
              srv_extra=f"brix_cms_blacklist_file {bl};")
    node = FakeNode(cms_port, 42262)
    try:
        frame = node.wait_frame(CMS_RR_TRY)
        assert frame is not None, "blacklist-redirected login got no kYR_try"
        _c, _m, payload = frame
        host = payload.split(b"\x00")[0].decode()
        port = struct.unpack(">H", payload[len(host) + 1:len(host) + 3])[0]
        assert (host, port) == (NODE_IP, 42999)
        assert node.wait_closed()
    finally:
        node.close()


def test_whitelist_drains_unlisted_admits_listed(lifecycle, tmp_path):
    """security-neg + success: whitelist mode — a login from an UNLISTED host
    is refused at admission (connection closed) and the host never registers;
    a login from a LISTED host is admitted and selectable."""
    wl = tmp_path / "wl.txt"
    wl.write_text("10.99.99.99\n")   # net-literal-allow: whitelist WITHOUT us
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "",
              "§2.13 whitelist mode.",
              srv_extra=f"brix_cms_whitelist_file {wl};")

    # security-neg: unlisted 127.0.0.1 is refused at login (closed) and never
    # becomes selectable.
    unlisted = FakeNode(cms_port, 42263)
    try:
        assert unlisted.wait_closed(), "unlisted login was not refused"
        status, _body = _locate(root_port, "/wl.dat")
        assert status != kXR_redirect, "unlisted host was selected"
    finally:
        unlisted.close()

    # success: list our host (mtime bump) — a fresh login is admitted, and the
    # admission-time forced poll re-reads the file so the new node registers.
    st = os.stat(wl)
    wl.write_text(f"{NODE_IP}\n")
    os.utime(wl, (st.st_atime, st.st_mtime + 2))
    listed = FakeNode(cms_port, 42264)
    try:
        got = _wait_selectable(root_port, "/wl.dat", 42264, timeout=20.0)
        assert got == 42264
    finally:
        listed.close()


# ═══ §2.17 peer role ══════════════════════════════════════════════════════

def test_peer_selected_only_on_local_miss(lifecycle):
    """success + negative: a peer-mode registrant is never selected while a
    local server matches; it IS selected when the local server leaves."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr", "",
              "§2.17 peer role: last-resort selection.")
    local = FakeNode(cms_port, 42271)
    peer = FakeNode(cms_port, 42272, mode=MODE_PEER)
    try:
        got = _wait_selectable(root_port, "/peer.dat", 42271)
        assert got == 42271     # local server wins while present

        local.close()
        # Local gone (unregistered/blacklisted on disconnect): the peer is
        # the last resort before NotFound.
        got = _wait_selectable(root_port, "/peer.dat", 42272, timeout=10.0)
        assert got == 42272
    finally:
        peer.close()
        local.close()


# ═══ §2.11 cms.perf pgm + §2.12 cms.altds (node side) ═════════════════

def test_altds_advertises_foreign_port(lifecycle):
    """§2.12 success: the login's dPort is the altds port, not listen_port."""
    stub = StubManager()
    try:
        _node(lifecycle, "lc-cms-parity-node", stub,
              "brix_cms_altds 42901;",
              "§2.12 cms.altds: advertise the foreign data port.")
        frame = stub.wait(CMS_RR_LOGIN)
        assert frame is not None, "node never logged in"
        info = _login_dport(frame[2])
        assert info["dport"] == 42901, info
    finally:
        stub.stop()


def test_altds_monitor_suspends_and_resumes(lifecycle):
    """§2.12 monitor: with nothing on the altds port the node suspends
    itself; a listener appearing resumes it."""
    stub = StubManager()
    try:
        _node(lifecycle, "lc-cms-parity-node", stub,
              "brix_cms_altds 42902 monitor; brix_cms_altds_interval 300ms;",
              "§2.12 cms.altds liveness monitor.")
        frame = stub.wait(CMS_RR_STATUS,
                          pred=lambda m, p: m & CMS_ST_SUSPEND, timeout=12.0)
        assert frame is not None, "altds-down never suspended the node"

        n_before = len(stub.frames)
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind((BIND_HOST, 42902))
        lsock.listen(4)
        try:
            deadline = time.time() + 12
            resumed = None
            while time.time() < deadline and resumed is None:
                for c, m, _p in stub.frames[n_before:]:
                    if c == CMS_RR_STATUS and (m & CMS_ST_RESUME):
                        resumed = True
                        break
                time.sleep(0.1)
            assert resumed, "altds recovery never resumed the node"
        finally:
            lsock.close()
    finally:
        stub.stop()


def test_perf_pgm_overrides_meter(lifecycle, tmp_path):
    """§2.11 success: the external feed's cpu figure (77) rides the LOAD
    heartbeat in place of the /proc meter's."""
    pgm = tmp_path / "perf.sh"
    pgm.write_text("#!/bin/sh\nwhile true; do echo '77 1 2 3 4'; sleep 1; done\n")
    pgm.chmod(0o755)
    stub = StubManager()
    try:
        _node(lifecycle, "lc-cms-parity-node", stub,
              f"brix_cms_perf_pgm \"{pgm}\";",
              "§2.11 cms.perf pgm external load feed.")
        frame = stub.wait(CMS_RR_LOAD,
                          pred=lambda m, p: len(p) >= 8 and p[2] == 77,
                          timeout=15.0)
        assert frame is not None, (
            f"no LOAD carried the fed cpu=77: {stub.frames[-5:]}")
    finally:
        stub.stop()


def test_peer_role_login_mode_bits(lifecycle):
    """§2.17 client side: brix_cms_role peer logs in with the kYR_peer Mode
    bit and without kYR_server."""
    stub = StubManager()
    try:
        _node(lifecycle, "lc-cms-parity-node", stub,
              "brix_cms_role peer;",
              "§2.17 peer role: login Mode bits.")
        frame = stub.wait(CMS_RR_LOGIN)
        assert frame is not None
        info = _login_dport(frame[2])
        assert info["mode"] & MODE_PEER, info
        assert not (info["mode"] & MODE_SERVER), info
    finally:
        stub.stop()
