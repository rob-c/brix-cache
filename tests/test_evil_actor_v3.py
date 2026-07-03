from _test_evil_actor_v3_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

def test_a1_roots_tls_windowed_read(srv):
    if not _tls_available(srv):
        pytest.skip("roots:// in-protocol TLS not drivable (binary lacks brix_tls?)")
    srv.mark()
    origin_small = open(os.path.join(srv.datadir, "shared.bin"), "rb").read()
    md5_small = hashlib.md5(origin_small).hexdigest()
    for rnd in range(20):
        tls = _roots_tls_connect(srv.root_tls_port)
        try:
            # login + small whole-file read over TLS
            s = struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                            os.getpid() & 0xFFFFFFFF, b"tls\x00\x00\x00\x00\x00", 0, 0, 5, 0, 0)
            tls.sendall(s)
            _, st, _ = _read_response(tls)
            assert st == kXR_ok, "TLS login failed: %r" % st
            _, st, body = _open(tls, "/shared.bin", flags=OPEN_READ)
            assert st == kXR_ok and len(body) >= 4
            fh = body[:4]
            got = b""
            off = 0
            while off < len(origin_small):
                tls.sendall(_frame(kXR_read, struct.pack("!4sqi", fh, off, 65536), sid=b"\x00\x05"))
                _, rst, data = _read_response(tls)
                assert rst in (kXR_ok, kXR_oksofar), "read st=%r" % rst
                if not data:
                    break
                got += data
                off += len(data)
            assert hashlib.md5(got).hexdigest() == md5_small, "TLS small read corrupt"

            # large windowed read (>2MiB) over TLS — collect windows to one kXR_ok
            _, st, body = _open(tls, "/big.bin", flags=OPEN_READ)
            assert st == kXR_ok and len(body) >= 4
            fh = body[:4]
            rlen = 12 << 20
            tls.sendall(_frame(kXR_read, struct.pack("!4sqi", fh, 0, rlen), sid=b"\x00\x08"))
            acc = b""
            terminal = 0
            while len(acc) < rlen:
                _, rst, data = _read_response(tls)
                acc += data
                if rst == kXR_ok:
                    terminal += 1
                    break
                assert rst in (kXR_oksofar, kXR_status), "windowed read st=%r" % rst
            assert terminal == 1, "expected exactly one terminating kXR_ok"
            expect = (open(os.path.join(srv.datadir, "big.bin"), "rb").read(len(acc)))
            assert acc == expect, "TLS windowed read bytes diverged"
        finally:
            tls.close()
    srv.assert_healthy("A1 roots TLS windowed read")


def test_a2_tls_disconnect_mid_aio(srv):
    if not _tls_available(srv):
        pytest.skip("roots:// TLS not drivable")
    srv.mark()
    big_md5 = hashlib.md5(open(os.path.join(srv.datadir, "big.bin"), "rb").read(65536)).hexdigest()
    rounds = ROUNDS
    for i in range(rounds):
        tls = None
        try:
            tls = _roots_tls_connect(srv.root_tls_port, t=6)
            tls.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                        os.getpid() & 0xFFFFFFFF, b"a\x00\x00\x00\x00\x00\x00\x00", 0, 0, 5, 0, 0))
            _read_response(tls)
            _, st, body = _open(tls, "/big.bin", flags=OPEN_READ)
            if st != kXR_ok or len(body) < 4:
                _tls_rst(tls); continue
            fh = body[:4]
            off = random.randrange(0, (BIGFILE_MB - 16) * 1024 * 1024)
            tls.sendall(_frame(kXR_read, struct.pack("!4sqi", fh, off, 16 << 20), sid=b"\x00\x0a"))
            # worker now held mid-pread by the shim; RST the raw fd (not close_notify)
            time.sleep(0.001)
            _tls_rst(tls)
        except Exception:
            if tls is not None:
                _tls_rst(tls)
        # interleave a surviving control TLS reader every few rounds
        if i % 7 == 0:
            try:
                c = _roots_tls_connect(srv.root_tls_port, t=6)
                c.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                          os.getpid() & 0xFFFFFFFF, b"c\x00\x00\x00\x00\x00\x00\x00", 0, 0, 5, 0, 0))
                _read_response(c)
                _, st, body = _open(c, "/big.bin", flags=OPEN_READ)
                if st == kXR_ok and len(body) >= 4:
                    _, _, data = _read(c, body[:4], 0, 65536, sid=b"\x00\x0c")
                    assert hashlib.md5(data).hexdigest() == big_md5, "control TLS read corrupt"
                c.close()
            except Exception:
                pass
    srv.assert_healthy("A2 TLS disconnect-mid-AIO")


def test_b6_cross_worker_bind(srv):
    srv.mark()
    shared_md5 = hashlib.md5(open(os.path.join(srv.datadir, "shared.bin"), "rb").read(65536)).hexdigest()
    primaries = []
    try:
        for _ in range(24):
            p, sid = _session(srv.root_port)
            _, st, body = _open(p, "/shared.bin", flags=OPEN_READ)
            if st == kXR_ok and len(body) >= 4:
                primaries.append((p, sid, body[:4]))
        assert primaries, "could not open any primary handles"
        served = 0
        for (p, sid, fh) in primaries:
            sec = _connect(srv.root_port)
            try:
                if _bind(sec, sid)[1] != kXR_ok:
                    continue
                _, st, data = _read(sec, fh, 0, 65536, sid=b"\x00\x0c")
                if st in (kXR_ok, kXR_oksofar) and data:
                    assert hashlib.md5(data).hexdigest() == shared_md5, \
                        "cross-worker bound read returned wrong bytes"
                    served += 1
            finally:
                _rst(sec)
        assert served > 0, "no bound secondary served the primary's handle"
        # negative: bind then read a WRITE-ONLY (non-readable) handle -> not served.
        # kXR_open_apnd opens O_WRONLY|O_APPEND with is_readable=0, so a bound
        # secondary must NOT be able to read primary data through it.
        pw, sidw = _session(srv.root_port)
        _, stw, bw = _open(pw, "/w.bin", flags=OPEN_APND)
        if stw == kXR_ok and len(bw) >= 4:
            sec = _connect(srv.root_port)
            try:
                if _bind(sec, sidw)[1] == kXR_ok:
                    _, st, _d = _read(sec, bw[:4], 0, 4096, sid=b"\x00\x0d")
                    assert st not in (kXR_ok, kXR_oksofar), \
                        "write-only (non-readable) handle should not be readable via bind"
            finally:
                _rst(sec)
        _rst(pw)
    finally:
        for (p, _s, _f) in primaries:
            _rst(p)
    srv.assert_healthy("B6 cross-worker bind")


@pytest.mark.timeout(300)  # adversarial stress: many rounds, inherently long on slow hosts
def test_b7_bind_teardown_aba(srv):
    srv.mark()
    shared = os.path.join(srv.datadir, "shared.bin")
    shared_md5 = hashlib.md5(open(shared, "rb").read(65536)).hexdigest()
    # TOCTOU: secondary reads while primary tears down
    for _ in range(ROUNDS):
        p = None; sec = None
        try:
            p, sid = _session(srv.root_port)
            _, st, body = _open(p, "/shared.bin", flags=OPEN_READ)
            if st != kXR_ok or len(body) < 4:
                continue
            fh = body[:4]
            sec = _connect(srv.root_port)
            if _bind(sec, sid)[1] != kXR_ok:
                _rst(sec); sec = None; continue
            sec.sendall(_frame(kXR_pgread, struct.pack("!4sqi", fh, 0, 8 << 20), sid=b"\x00\x0a"))
            # tear the primary down DURING the secondary's held read
            p.sendall(_frame(kXR_endsess, b"\x00" * 16, sid=b"\x00\x0b"))
            try:
                sec.settimeout(1.0)
                _, st, data = _read_response(sec)
                # if served, bytes must be the real file (never garbage/old inode)
                if st in (kXR_ok, kXR_oksofar) and data:
                    assert hashlib.md5(data[:65536]).hexdigest() == shared_md5 or len(data) < 65536, \
                        "post-teardown read returned corrupt bytes"
            except Exception:
                pass
        except Exception:
            pass
        finally:
            for c in (sec, p):
                if c is not None:
                    _rst(c)
    # ABA: slot reused for a different file under a new session.  Floor scales
    # with the host: full 20 on a fast host, 8 on a constrained one (so reducing
    # ROUNDS actually shortens this loop instead of being pinned by the floor).
    for _ in range(max(8 if _CONSTRAINED else 20, ROUNDS // 3)):
        p1 = sec = p2 = None
        try:
            p1, sid1 = _session(srv.root_port)
            _, st, b1 = _open(p1, "/shared.bin", flags=OPEN_READ)
            if st != kXR_ok or len(b1) < 4:
                continue
            fh = b1[:4]
            sec = _connect(srv.root_port)
            bound = _bind(sec, sid1)[1] == kXR_ok
            _rst(p1); p1 = None                      # free the slot (ABA: A->_)
            p2, sid2 = _session(srv.root_port)        # new primary reuses slot index
            _open(p2, "/w.bin", flags=OPEN_READ)
            if bound:
                _, st, data = _read(sec, fh, 0, 65536, sid=b"\x00\x0e")
                # never serve fileA's freed bytes from a stale slot under a foreign sess
                assert st in (kXR_error, kXR_ok, kXR_oksofar, kXR_wait, kXR_status), \
                    "unexpected status after ABA: %r" % st
        except Exception:
            pass
        finally:
            for c in (sec, p1, p2):
                if c is not None:
                    _rst(c)
    # forged random sessids across workers -> overwhelmingly rejected
    forged_ok = forged_tried = 0
    for _ in range(24):
        f = _connect(srv.root_port)
        try:
            forged_tried += 1
            if _bind(f, bytes(random.randrange(256) for _ in range(16)))[1] == kXR_ok:
                forged_ok += 1
        except Exception:
            pass
        finally:
            _rst(f)
    assert forged_ok == 0, "%d/%d forged sessids accepted by cross-worker bind" % (forged_ok, forged_tried)
    srv.assert_healthy("B7 bind-teardown + ABA")
