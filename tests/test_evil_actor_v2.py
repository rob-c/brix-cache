from split_continuation import reexport as _reexport
_reexport(globals(), "_test_evil_actor_v2_helpers")

def test_p1_bind_handle_inode_swap_race(srv):
    """A bound secondary reads a primary-published handle while the file is
    close+unlink+recreate'd underneath (shim holds the secondary's worker pread
    open across the swap). Must not crash/UAF a worker."""
    srv.mark()
    shared = os.path.join(srv.datadir, "shared.bin")
    orig = open(shared, "rb").read()
    for i in range(ROUNDS):
        p = None; sec = None
        try:
            p, sid = _session(srv.root_port)
            st, body = _open(p, "/shared.bin", flags=0x0010)
            if st != kXR_ok or len(body) < 4:
                continue
            fh = body[:4]
            sec = _connect(srv.root_port)
            if _bind(sec, sid)[0] != kXR_ok:
                _rst(sec); sec = None; continue
            # secondary fires a large read (offloads; shim widens the pread)
            sec.sendall(_frame(kXR_pgread, struct.pack("!4sqi", fh, 0, 8 << 20),
                               sid=b"\x00\x0a"))
            # ... and DURING that read, the primary closes + the file is swapped
            time.sleep(0.002)
            p.sendall(_frame(kXR_close, fh + b"\x00" * 12, sid=b"\x00\x0b"))
            try:
                os.unlink(shared)
            except OSError:
                pass
            with open(shared, "wb") as f:           # new inode, attacker content
                f.write(b"SWAPPED!" * 4096)
            try:
                sec.settimeout(3.0); _read_response(sec)   # consume / let it land
            except Exception:
                pass
        except Exception:
            pass
        finally:
            for c in (sec, p):
                if c is not None:
                    _rst(c)
        if i % 40 == 0:
            # restore the file so later rounds have a clean handle to open
            with open(shared, "wb") as f:
                f.write(orig)
    with open(shared, "wb") as f:
        f.write(orig)
    srv.assert_healthy("P1 bind inode-swap race")


def test_p1b_many_secondaries_close_race(srv):
    """N bound secondaries with in-flight reads on one primary handle while the
    primary closes it — exercises the per-secondary revocation/in-flight window."""
    srv.mark()
    for _ in range(max(20, ROUNDS // 4)):
        p = None; secs = []
        try:
            p, sid = _session(srv.root_port)
            st, body = _open(p, "/big.bin", flags=0x0010)
            if st != kXR_ok or len(body) < 4:
                continue
            fh = body[:4]
            for _k in range(5):
                c = _connect(srv.root_port)
                if _bind(c, sid)[0] == kXR_ok:
                    secs.append(c)
            off = random.randrange(0, (BIGFILE_MB - 8) * 1024 * 1024)
            for c in secs:                          # fire all in-flight at once
                try:
                    c.sendall(_frame(kXR_pgread, struct.pack("!4sqi", fh, off, 8 << 20),
                                     sid=b"\x00\x0a"))
                except OSError:
                    pass
            p.sendall(_frame(kXR_close, fh + b"\x00" * 12, sid=b"\x00\x0b"))
        except Exception:
            pass
        finally:
            for c in secs + [p]:
                if c is not None:
                    _rst(c)
    srv.assert_healthy("P1b many-secondaries close race")


# --------------------------- P2: cross-session bind security contract --------

def test_p2_bind_security_contract(srv):
    """A secondary needs only a captured sessid to inherit identity + read the
    primary's handle (bearer-token model); a forged/random sessid is rejected."""
    srv.mark()
    p, sid = _session(srv.root_port)
    try:
        st, body = _open(p, "/big.bin", flags=0x0010)
        assert st == kXR_ok and len(body) >= 4
        fh = body[:4]
        # captured sessid => bind succeeds + can read the primary's handle
        sec = _connect(srv.root_port)
        st_b, pbody = _bind(sec, sid)
        assert st_b == kXR_ok, "bind with captured sessid should succeed"
        rst, _ = _read(sec, fh, 0, 65536, sid=b"\x00\x0c")
        assert rst in (kXR_ok, kXR_status), \
            "bound secondary should read the primary handle: %r" % rst
        _rst(sec)
        # forged/random sessids must NOT grant a session
        forged_ok = 0
        for _ in range(64):
            f = _connect(srv.root_port)
            try:
                fake = bytes(random.randrange(256) for _ in range(16))
                if _bind(f, fake)[0] == kXR_ok:
                    forged_ok += 1
            except Exception:
                pass
            finally:
                _rst(f)
        assert forged_ok == 0, (
            "%d/64 RANDOM sessids were accepted by kXR_bind — the session id is "
            "guessable/forgeable (it is not a CSPRNG): session-hijack risk" % forged_ok)
    finally:
        _rst(p)
    srv.assert_healthy("P2 bind security contract")


# --------------------------- P3: disconnect-mid-AIO (shim-widened) -----------


def test_p3_disconnect_mid_aio_widened(srv):
    srv.mark()
    counter = [0]; stop_at = time.time() + 70
    ts = [threading.Thread(target=_aio_rst_worker,
                           args=(srv.root_port, srv.datadir, ROUNDS, stop_at, counter))
          for _ in range(6)]
    for t in ts: t.start()
    for t in ts: t.join(timeout=120)
    print("\n[evil2] P3 shim-widened AIO-RST rounds: %d" % counter[0])
    srv.assert_healthy("P3 disconnect-mid-AIO (widened)")


# --------------------------- P4: pipelined scratch reuse ---------------------

def test_p4_pipelined_scratch_reuse(srv):
    srv.mark()
    for _ in range(max(40, ROUNDS // 2)):
        s = None
        try:
            s = _connect(srv.root_port, 4)
            _login(s)
            st, body = _open(s, "/big.bin", flags=0x0010)
            if st != kXR_ok or len(body) < 4:
                if s: _rst(s)
                continue
            fh = body[:4]
            # pipeline read -> readv -> pgread in one segment, then RST
            pkt = _frame(kXR_read, struct.pack("!4sqi", fh, 0, 4 << 20), sid=b"\x00\x21")
            pkt += _frame(kXR_readv, b"",
                          b"".join(struct.pack("!4siq", fh, 1 << 20, i << 20)
                                   for i in range(4)), sid=b"\x00\x22")
            pkt += _frame(kXR_pgread, struct.pack("!4sqi", fh, 0, 4 << 20), sid=b"\x00\x23")
            s.sendall(pkt)
        except Exception:
            pass
        if s is not None:
            _rst(s)
    srv.assert_healthy("P4 pipelined scratch reuse")


# --------------------------- P5: stateful / less-tested opcode fuzz ----------

def test_p5_stateful_opcode_fuzz(srv):
    srv.mark()
    rng = random.Random(1337)
    for _ in range(max(60, ROUNDS)):
        s = None
        try:
            s = _connect(srv.root_port, 4)
            _login(s)
            st, body = _open(s, "/w.bin", flags=0x0010 | 0x0020)
            fh = body[:4] if (st == kXR_ok and len(body) >= 4) else b"\x00\x00\x00\x00"
            op = rng.choice((kXR_chkpoint, kXR_truncate, kXR_fattr, kXR_sync,
                             kXR_endsess, kXR_chkpoint))
            if op == kXR_truncate:
                s.sendall(_frame(kXR_truncate, fh + struct.pack("!q", rng.choice(
                    (-1, 0, 1 << 62))) + b"\x00" * 4))
            elif op == kXR_chkpoint:
                # subcode + maybe an embedded sub-request with mismatched fhandle
                sub = _frame(kXR_write, struct.pack("!4sqB3s", b"\x07\x00\x00\x00",
                             0, 0, b"\x00" * 3), b"x" * 16)
                s.sendall(_frame(kXR_chkpoint, fh + bytes([rng.randrange(6)]) + b"\x00" * 11,
                                 sub if rng.random() < 0.5 else b""))
            elif op == kXR_fattr:
                s.sendall(_frame(kXR_fattr, fh + bytes([rng.randrange(256)]) +
                                 bytes([rng.choice((0, 1, 16, 255))]) + b"\x00" * 10,
                                 b"\xff" * rng.choice((0, 2, 40))))
            elif op == kXR_sync:
                s.sendall(_frame(kXR_sync, fh + b"\x00" * 12))
            else:  # endsess with a random (cross-session) sessid then a pipelined read
                pkt = _frame(kXR_endsess, bytes(rng.randrange(256) for _ in range(16)))
                pkt += _frame(kXR_read, struct.pack("!4sqi", fh, 0, 4 << 20))
                s.sendall(pkt)
            try:
                s.settimeout(1.0); _read_response(s)
            except Exception:
                pass
        except Exception:
            pass
        if s is not None:
            _rst(s)
    srv.assert_healthy("P5 stateful opcode fuzz")


# --------------------------- P6: cross-protocol simultaneous assault ---------


def test_p6_cross_protocol_assault(srv):
    srv.mark()
    _XP_HTTP[0] = srv.webdav_port
    _XP_S3[0] = srv.s3_port
    shared = os.path.join(srv.datadir, "xp.bin")
    orig = open(shared, "rb").read()
    stop = time.time() + 25

    def root_rw():
        while time.time() < stop:
            s = None
            try:
                s = _connect(srv.root_port, 3); _login(s)
                st, b = _open(s, "/xp.bin", flags=0x0010)
                if st == kXR_ok and len(b) >= 4:
                    _read(s, b[:4], 0, 1 << 20)
            except Exception:
                pass
            if s: _rst(s)

    def webdav_get():
        while time.time() < stop:
            _http("GET", "/xp.bin")
            _http("PROPFIND", "/xp.bin",
                  body=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>')

    def s3_ops():
        while time.time() < stop:
            _http("GET", "/s3b/xp.bin", port=_XP_S3[0])
            _http("HEAD", "/s3b/xp.bin", port=_XP_S3[0])

    def swapper():
        while time.time() < stop:
            try:
                with open(shared, "wb") as f:
                    f.write(b"X" * random.randrange(4096, 1 << 20))
                time.sleep(0.01)
                os.unlink(shared)
            except OSError:
                pass
            with open(shared, "wb") as f:
                f.write(orig)
            time.sleep(0.01)

    ts = ([threading.Thread(target=root_rw) for _ in range(4)] +
          [threading.Thread(target=webdav_get) for _ in range(3)] +
          [threading.Thread(target=s3_ops) for _ in range(2)] +
          [threading.Thread(target=swapper) for _ in range(2)])
    for t in ts: t.start()
    for t in ts: t.join(timeout=60)
    with open(shared, "wb") as f:
        f.write(orig)
    srv.assert_healthy("P6 cross-protocol assault")


# --------------------------- P7: survival + integrity -----------------------

def test_p7_integrity(srv):
    srv.mark()
    expected = bytes((i * 31 + 7) & 0xFF for i in range(65536))
    s, _ = _session(srv.root_port)
    try:
        st, body = _open(s, "/big.bin", flags=0x0010)
        assert st == kXR_ok and len(body) >= 4
        fh = body[:4]
        st, data = _read(s, fh, 0, 65536)
        assert st == kXR_ok, "post-assault read failed: %r" % st
        assert data == expected, "post-assault read returned wrong bytes"
    finally:
        _rst(s)
    srv.assert_healthy("P7 final integrity")
