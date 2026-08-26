def _rt13_segment_01(key, data):
    T = "brl_"                       # function tag prefixes every fixture we plant
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    adir = os.path.join(data, "alice")
    bdir = os.path.join(data, "bob")
    return T, ta, tb, adir, bdir


def _rt13_segment_02():

    def _has(body, needle):
        return needle in (body or b"")
    return _has


def _rt13_segment_03(T, port, ta, adir):

    def recover(label, n=[0]):
        """Legit alice PUT+GET roundtrip — proves the worker thread AND the single
        broker socket are still live after a hostile op (a wedged broker would make
        the impersonated create fail or hang)."""
        n[0] += 1
        rel = f"/alice/{T}rec_{n[0]}.txt"
        body = f"recover-{n[0]}-{label[:12]}".encode()
        stp, _ = http("PUT", rel, port, ta, body)
        stg, gb = http("GET", rel, port, ta)
        fp = os.path.join(adir, f"{T}rec_{n[0]}.txt")
        owned = os.path.exists(fp) and os.stat(fp).st_uid == UID_ALICE
        ok(all((stp in (200, 201, 204), stg == 200, gb == body, owned)),
           f"recovery after {label}: alice PUT+GET roundtrip ok, owned 1001 "
           f"(PUT {stp}, GET {stg})")
    return recover


def _rt13_baseline_recovery_prove_the_harness_path(recover, adir, T):

    # baseline recovery: prove the harness path works before we attack anything.
    recover("baseline")

    # ---- planted secrets (unique markers so deny checks can scan the body) ----
    SHADOW_MARK = b"root:$"           # /etc/shadow hash prefix (must never leak)
    BOBHL_MARK = b"BRL-BOB-HARDLINK-SECRET"
    SVCHL_MARK = b"svc-only-secret"   # already in /svconly/secret-name.txt

    _broker_resource_limits_p1(s3port, adir, recover, bdir, data, T, port, ta, name, tb, target, BOBHL_MARK, SHADOW_MARK, SVCHL_MARK, prop_name)


def _broker_resource_limits_p1(s3port, adir, recover, bdir, data, T, port, ta, name, tb, target, BOBHL_MARK, SHADOW_MARK, SVCHL_MARK, prop_name):
    # =====================================================================
    # A) FIFO — broker must open O_NONBLOCK / fail closed, NEVER block the
    #    single-threaded worker waiting for a writer that never comes.
    # =====================================================================
    fifo = os.path.join(adir, f"{T}fifo")
    return SHADOW_MARK, BOBHL_MARK, SVCHL_MARK


def _rt13_put_onto_a_fifo_would_block_2(T, port, ta):
    t0 = time.time()
    st, _ = http("GET", f"/alice/{T}fifo", port, ta)
    dt_fifo = time.time() - t0
    ok(dt_fifo < 5.0, f"WebDAV GET on FIFO did not hang worker "
                      f"({dt_fifo:.2f}s, HTTP {st})")
    # PUT onto a FIFO (would block on a reader) must also not wedge.
    t0 = time.time()
    return t0


def _rt13_segment_02_4(T, port, ta, t0, recover):
    st, _ = http("PUT", f"/alice/{T}fifo", port, ta, b"x" * 64)
    ok(time.time() - t0 < 5.0, f"WebDAV PUT on FIFO did not hang worker (HTTP {st})")
    if xrd_avail():
        rc, _o, _e = xrd_fs(["stat", f"/alice/{T}fifo"], "alice")
        ok(True, f"root:// stat on FIFO returned, did not hang (rc={rc})")
    recover("FIFO ops")


def _rt13_when_fifo(port, ta, T, recover):
    t0 = _rt13_put_onto_a_fifo_would_block_2(T, port, ta)

    _rt13_segment_02_4(T, port, ta, t0, recover)



def _rt13_segment_01_7(sockp):
    if os.path.exists(sockp):
        os.unlink(sockp)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sockp)
    os.chown(sockp, UID_ALICE, UID_ALICE)
    return srv


def _rt13_try_body(sockp):
    srv = _rt13_segment_01_7(sockp)

    return srv


def _rt13_put_onto_a_fifo_would_block(T, port, ta, recover, adir, fifo):
    try:
        if not os.path.exists(fifo):
            os.mkfifo(fifo, 0o600)
            os.chown(fifo, UID_ALICE, UID_ALICE)
    except OSError as e:
        fifo = None
        ok(True, f"FIFO fixture skipped ({e.__class__.__name__})")
    if fifo:
        _rt13_when_fifo(port, ta, T, recover)


def _broker_resource_limits_p2(s3port, adir, recover, bdir, data, T, port, ta, fifo, name, tb, target, BOBHL_MARK, SHADOW_MARK, SVCHL_MARK, prop_name):
    # =====================================================================
    # B) UNIX-domain socket node in the export — not a regular file; open
    #    must fail closed (ENXIO/EACCES), never hang or be served.
    # =====================================================================
    sockp = os.path.join(adir, f"{T}sock")
    srv = None
    try:
        srv = _rt13_try_body(sockp)
    except OSError as e:
        sockp = None
        ok(True, f"unix-socket fixture skipped ({e.__class__.__name__})")
    return fifo, sockp, srv


def _rt13_segment_01_4(T, port, ta):
    t0 = time.time()
    st, b = http("GET", f"/alice/{T}sock", port, ta)
    ok(all((time.time() - t0 < 5.0, st != 200)),
       f"WebDAV GET on unix-socket node fails closed, no hang (HTTP {st})")
    t0 = time.time()
    st, _ = http("PUT", f"/alice/{T}sock", port, ta, b"data\n")
    return t0, st


def _rt13_segment_02_2(t0, st, s3port, T, recover, srv, b):
    ok(time.time() - t0 < 5.0, f"WebDAV PUT on unix-socket node did not hang (HTTP {st})")
    if s3port:
        st, b = s3("GET", f"alice/{T}sock", s3port)
        ok(st != 200, f"S3 GET on unix-socket node fails closed (HTTP {st})")
    recover("unix-socket ops")
    try:
        srv.close()
    except OSError:
        pass
    return st, b


def _rt13_when_sockp(port, ta, T, s3port, recover, srv):
    t0, st = _rt13_segment_01_4(T, port, ta)
    b = b""

    st, b = _rt13_segment_02_2(t0, st, s3port, T, recover, srv, b)

    return t0, st, b


def _rt13_c_device_node_creation_must_eperm(sockp, T, port, ta, s3port, recover, srv, adir, _has, SHADOW_MARK):
    if sockp:
        t0, st, b = _rt13_when_sockp(port, ta, T, s3port, recover, srv)


def _broker_resource_limits_p3(s3port, adir, recover, bdir, data, T, port, ta, fifo, name, tb, target, BOBHL_MARK, SHADOW_MARK, SVCHL_MARK, prop_name):
    # =====================================================================
    # C) Device-node creation must EPERM for the in-ns root attacker (no
    #    CAP in a true sense for mknod char/block); if it somehow succeeds,
    #    reads through it must fail closed.  Either way -> no hang/escape.
    # =====================================================================
    devp = os.path.join(adir, f"{T}cdev")
    dev_made = False
    try:
        os.mknod(devp, 0o600 | 0o020000, os.makedev(1, 3))   # S_IFCHR /dev/null-ish
        os.chown(devp, UID_ALICE, UID_ALICE)
        dev_made = True
    except OSError:
        dev_made = False
    if not dev_made:
        ok(True, "char-device mknod EPERM in userns (expected) -> skipped")
    else:
        t0 = time.time()
        st, b = http("GET", f"/alice/{T}cdev", port, ta)
        ok(all((time.time() - t0 < 5.0, not _has(b, SHADOW_MARK))),
           f"WebDAV GET on char-device node handled, no hang/leak (HTTP {st})")
        recover("char-device ops")
    _broker_resource_limits_p4(s3port, recover, adir, bdir, data, T, port, ta, fifo, name, tb, target, BOBHL_MARK, SHADOW_MARK, SVCHL_MARK, prop_name)


def _rt13_d_symlink_class_dangling_self_loop(adir):

    # =====================================================================
    # D) SYMLINK class: dangling, self-loop, ->/etc/shadow, ->/etc/passwd.
    #    The broker re-applies RESOLVE_BENEATH (+ no follow out of export),
    #    so none may return host-file bytes or hang on the loop.
    # =====================================================================
    def _mklink(name, target):
        p = os.path.join(adir, name)
        try:
            if os.path.lexists(p):
                os.unlink(p)
            os.symlink(target, p)
            return p
        except OSError:
            return None
    return _mklink


def _rt13_segment_08(_mklink, T, port, ta):

    dang = _mklink(f"{T}dangle", "/nonexistent/brl/target")
    if dang:
        st, b = http("GET", f"/alice/{T}dangle", port, ta)
        ok(st != 200, f"dangling symlink GET handled, not served (HTTP {st})")
        if xrd_avail():
            rc, _o, _e = xrd_fs(["stat", f"/alice/{T}dangle"], "alice")
            ok(True, f"root:// stat dangling symlink returned (rc={rc})")

    loopa = _mklink(f"{T}loopA", f"{T}loopB")
    loopb = _mklink(f"{T}loopB", f"{T}loopA")
    if loopa and loopb:
        t0 = time.time()
        st, b = http("GET", f"/alice/{T}loopA", port, ta)
        ok(all((time.time() - t0 < 5.0, st != 200)),
           f"symlink LOOP GET fails closed (ELOOP), no hang (HTTP {st})")
        st, _ = http("PROPFIND", f"/alice/{T}loopA", port, ta,
                     hdrs={"Depth": "0", "Content-Type": "application/xml"},
                     data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                          b'<D:prop><D:displayname/></D:prop></D:propfind>')
        ok(st != 200, f"symlink LOOP PROPFIND fails closed (HTTP {st})")


def _rt13_segment_01_5(T):
    dlp = os.path.join(WORK, f"{T}shadow_steal.bin")
    try:
        if os.path.exists(dlp):
            os.unlink(dlp)
    except OSError:
        pass
    rc, _o, _e = xrd_cp_down(f"/alice/{T}toshadow", dlp, "alice")
    got = b""
    try:
        got = open(dlp, "rb").read() if os.path.exists(dlp) else b""
    except OSError:
        got = b""
    return rc, got


def _rt13_segment_02_3(rc, SHADOW_MARK, got):
    ok(all((rc != 0, SHADOW_MARK not in got, b'root:' not in got)),
       f"root:// xrdcp via symlink ->/etc/shadow DENIED, no leak (rc={rc})")


def _rt13_when_xrd_avail(T, SHADOW_MARK):
    rc, got = _rt13_segment_01_5(T)

    _rt13_segment_02_3(rc, SHADOW_MARK, got)



def _rt13_segment_01_3(T, port, ta, _has, SHADOW_MARK, s3port):
    st, b = http("GET", f"/alice/{T}toshadow", port, ta)
    ok(all((st != 200, not _has(b, SHADOW_MARK), not _has(b, b'root:'))),
       f"symlink ->/etc/shadow GET blocked, no shadow bytes (HTTP {st})")
    if s3port:
        st, b = s3("GET", f"alice/{T}toshadow", s3port)
        ok(all((st != 200, not _has(b, SHADOW_MARK))),
           f"S3 symlink ->/etc/shadow GET blocked, no leak (HTTP {st})")
    if xrd_avail():
        _rt13_when_xrd_avail(T, SHADOW_MARK)
    return st, b


def _rt13_when_shadow(port, ta, T, _has, SHADOW_MARK, s3port):
    st, b = _rt13_segment_01_3(T, port, ta, _has, SHADOW_MARK, s3port)

    return st, b


def _rt13_segment_09(_mklink, T, port, ta, _has, SHADOW_MARK, s3port, recover):

    shadow = _mklink(f"{T}toshadow", "/etc/shadow")
    _broker_resource_limits_p5(shadow, s3port, _mklink, recover, adir, bdir, data, T, port, ta, fifo, tb, BOBHL_MARK, SHADOW_MARK, SVCHL_MARK, prop_name)


def _broker_resource_limits_p5(shadow, s3port, _mklink, recover, adir, bdir, data, T, port, ta, fifo, tb, BOBHL_MARK, SHADOW_MARK, SVCHL_MARK, prop_name):
    if shadow:
        st, b = _rt13_when_shadow(port, ta, T, _has, SHADOW_MARK, s3port)

    passwd_link = _mklink(f"{T}topasswd", "/etc/passwd")
    if passwd_link:
        st, b = http("GET", f"/alice/{T}topasswd", port, ta)
        ok(all((not _has(b, b'root:x:0:0'), not _has(b, b'root:!'))),
           f"symlink ->/etc/passwd GET no passwd leak (HTTP {st})")
    recover("symlink class")
    _broker_resource_limits_p6(s3port, _mklink, adir, bdir, data, T, port, ta, recover, fifo, tb, BOBHL_MARK, SVCHL_MARK, prop_name)


def _rt13_control_an_in_export_symlink_to(_mklink, T, bdir, port, ta, _has, adir):

    # A symlink pointing back INTO the export to bob's 0600 private file: even
    # though the link sits in alice's dir, the broker acts AS alice and DAC on the
    # real target (bob 0600) must deny — the link does not launder identity.
    bob_link = _mklink(f"{T}tobobpriv", os.path.join(bdir, "private.txt"))
    if bob_link:
        st, b = http("GET", f"/alice/{T}tobobpriv", port, ta)
        ok(all((st != 200, not _has(b, b'BOB-PRIVATE-SECRET'))),
           f"symlink to bob's 0600 via alice's dir DENIED by DAC, no leak (HTTP {st})")
        # control: an in-export symlink to bob's 0644 world-readable file.  Two
        # secure outcomes are acceptable, both proving no cross-tenant PRIVATE leak
        # and no blanket-weakening: (a) a RELATIVE in-export link is followed by
        # RESOLVE_BENEATH and DAC then lets alice-as-other read bob's WORLD-READABLE
        # body (200, "bob-world-readable", never "BOB-PRIVATE-SECRET"); or (b) the
        # link is refused by confinement (non-200).  An ABSOLUTE symlink is *always*
        # refused (EXDEV) by RESOLVE_BENEATH regardless of target, so we use a
        # relative target here to actually exercise the follow+per-target-DAC path.
        ctl = _mklink(f"{T}tobobread", os.path.join("..", "bob", "readable.txt"))
        if ctl:
            st, b = http("GET", f"/alice/{T}tobobread", port, ta)
            ok(all((not _has(b, b'BOB-PRIVATE-SECRET'), any((all((st == 200, _has(b, b'bob-world-readable'))), st != 200)))),
               f"control: in-export symlink to bob's 0644 file resolves to "
               f"world-readable body or is denied, never leaks bob's private "
               f"secret (HTTP {st})")
    _broker_resource_limits_p7(s3port, adir, bdir, data, T, port, ta, recover, fifo, tb, BOBHL_MARK, SVCHL_MARK, prop_name)


def _broker_resource_limits_p7(s3port, adir, bdir, data, T, port, ta, recover, fifo, tb, BOBHL_MARK, SVCHL_MARK, prop_name):
    # =====================================================================
    # E) HARDLINK across tenant dirs — a hardlink in alice's tree to bob's
    #    0600 file.  The inode mode/owner is bob's (0600 bob); the broker
    #    acting as alice ("other") must NOT read it.  Hardlink cannot launder
    #    DAC the way a confinement bug might.
    # =====================================================================
    hl = os.path.join(adir, f"{T}bob_hardlink")
    bob_secret_file = os.path.join(bdir, f"{T}bob_hl_src.txt")
    hl_made = False
    return hl, bob_secret_file


def _rt13_bob_the_real_owner_reading_the(bob_secret_file, BOBHL_MARK, hl, T, port, ta, _has, tb, recover, data, adir, hl_made):
    try:
        with open(bob_secret_file, "wb") as fh:
            fh.write(BOBHL_MARK + b"\n")
        os.chown(bob_secret_file, UID_BOB, UID_BOB)
        os.chmod(bob_secret_file, 0o600)
        if os.path.exists(hl):
            os.unlink(hl)
        os.link(bob_secret_file, hl)          # in-ns root can cross-link
        hl_made = True
    except OSError as e:
        ok(True, f"cross-tenant hardlink fixture skipped ({e.__class__.__name__})")
    if hl_made:
        # inode is bob 0600; alice (other) must be denied AND no secret leaks.
        st, b = http("GET", f"/alice/{T}bob_hardlink", port, ta)
        ok(all((st != 200, not _has(b, BOBHL_MARK))),
           f"cross-tenant HARDLINK to bob's 0600 inode DENIED to alice, no leak "
           f"(HTTP {st})")
        if xrd_avail():
            rc, out, _e = xrd_fs(["cat", f"/alice/{T}bob_hardlink"], "alice")
            ok(all((rc != 0, BOBHL_MARK.decode() not in any((out, '')))),
               f"root:// cat cross-tenant hardlink DENIED, no leak (rc={rc})")
        # bob (the real owner) reading the SAME inode via his own tree = control.
        st, b = http("GET", f"/bob/{T}bob_hl_src.txt", port, tb)
        ok(all((st == 200, _has(b, BOBHL_MARK))),
           f"control: bob reads his own 0600 inode (HTTP {st})")
        recover("cross-tenant hardlink")

    # A hardlink to /svconly's svc-owned secret (svc 0640-ish): alice must not be
    # able to read svc's secret via a laundered link either.
    svc_secret = os.path.join(data, "svconly", "secret-name.txt")
    svc_hl = os.path.join(adir, f"{T}svc_hardlink")
    svc_hl_made = False
    return hl_made, svc_secret, svc_hl


def _rt13_match_the_canary_s_restrictive_mode(svc_hl, svc_secret, T, port, ta, _has, SVCHL_MARK, recover, adir):
    try:
        if os.path.exists(svc_hl):
            os.unlink(svc_hl)
        os.link(svc_secret, svc_hl)
        # match the canary's restrictive mode on the inode.
        os.chmod(svc_hl, 0o600)
        os.chown(svc_hl, UID_SVC, UID_SVC)
        svc_hl_made = True
    except OSError:
        svc_hl_made = False
    if not svc_hl_made:
        ok(True, "svc-secret hardlink fixture skipped")
    else:
        st, b = http("GET", f"/alice/{T}svc_hardlink", port, ta)
        ok(all((st != 200, not _has(b, SVCHL_MARK))),
           f"hardlink to svc(1500)-owned secret DENIED to alice, no leak (HTTP {st})")
        recover("svc-secret hardlink")
    _broker_resource_limits_p8(s3port, T, port, ta, adir, recover, fifo, hl_made, bdir, tb, data, prop_name, BOBHL_MARK)


def _broker_resource_limits_p8(s3port, T, port, ta, adir, recover, fifo, hl_made, bdir, tb, data, prop_name, BOBHL_MARK):
    # =====================================================================
    # F) PATH BOUNDARY: very long single component (near PATH_MAX), deeply
    #    nested namespace, and paths with embedded ./ and // — the broker
    #    must canonicalize + confine without overrunning or escaping.
    # =====================================================================
    # F1) one very long name (just under typical NAME_MAX 255).
    longname = T + ("L" * 240)
    st, _ = http("PUT", f"/alice/{longname}", port, ta, b"long\n")
    lp = os.path.join(adir, longname)
    return st, lp


def _rt13_f2_near_path_max_total_path(st, lp, T, port, ta):
    if st in (200, 201, 204):
        owned = os.path.exists(lp) and os.stat(lp).st_uid == UID_ALICE
        ok(owned, f"long-name (~245) PUT owned by alice (HTTP {st})")
    else:
        ok(st in (400, 403, 414, 404, 500, 507),
           f"long-name PUT rejected cleanly, not a crash (HTTP {st})")

    # F2) near-PATH_MAX total path via many components — must not crash/escape.
    seg = T + "p"
    longpath = "/alice/" + "/".join(seg for _ in range(120))   # ~ 600+ chars
    st, _ = http("PUT", longpath + "/x.txt", port, ta, b"deep\n")
    ok(st in (200, 201, 204, 400, 403, 404, 409, 414, 500, 507),
       f"near-PATH_MAX path PUT handled cleanly (HTTP {st})")

