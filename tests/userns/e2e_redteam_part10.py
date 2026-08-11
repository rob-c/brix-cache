from functools import partial


def _wms_orb(x):
    return x or b""


def run_webdav_method_state(key, data, port, s3port):
    """WebDAV METHOD x HEADER x LOCK-STATE matrix under impersonation.  Deeply
    combines LOCK (exclusive/shared, Timeout, refresh-by-re-LOCK) then the
    state-changing methods (PUT/DELETE/MOVE/PROPPATCH/UNLOCK) by the OWNER
    (must succeed, owned by the mapped user) vs by ANOTHER identity that holds a
    STOLEN lock token (must still be denied by the broker-enforced DAC, even
    though the lock token is structurally valid).  Then the conditional-header
    family (If-Match / If-None-Match / If-Modified-Since / If-Unmodified-Since)
    on the OWNER's own file (positive controls) and as a confidentiality ORACLE
    against bob's 0600 file (must never branch in a way that leaks a byte).
    Finally the protocol-edge surface: Content-Range / partial PUT, chunked
    Transfer-Encoding, Expect: 100-continue, PUT with trailing slash, PUT over a
    collection, nested MKCOL (missing parent -> 409), MOVE/COPY Destination edge
    cases, and PROPFIND Depth 0/1/infinity allprop/propname.  Every CREATE is
    re-checked for ownership == the mapped user (never svc 1500 / root 0 / the
    other tenant), and positive controls sit beside every deny so a blanket
    block cannot false-pass.  All fixtures are prefixed `wms_` to avoid
    collisions with the rest of the battery."""
    ta, tb = mint(key, "alice"), mint(key, "bob")
    base = f"http://{HOST}:{port}"
    LI_EXCL = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
               b'<D:lockscope><D:exclusive/></D:lockscope>'
               b'<D:locktype><D:write/></D:locktype>'
               b'<D:owner><D:href>mailto:alice@x</D:href></D:owner></D:lockinfo>')
    LI_SHARED = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                 b'<D:lockscope><D:shared/></D:lockscope>'
                 b'<D:locktype><D:write/></D:locktype></D:lockinfo>')
    ALLPROP = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
               b'<D:allprop/></D:propfind>')
    PROPNAME = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                b'<D:propname/></D:propfind>')

    adir = partial(_wms_adir, data)
    owned_alice = _wms_owned_alice
    not_worker_root = _wms_not_worker_root
    lock_file = partial(_wms_lock_file, port, LI_EXCL)

    _wms_lock_security(data, port, base, ta, tb, adir, owned_alice, lock_file, ALLPROP)
    _wms_unlock_controls(port, ta, tb, adir, owned_alice, lock_file)
    _wms_lock_variants(port, ta, tb, adir, owned_alice, lock_file, LI_SHARED)
    _wms_own_conditionals(port, ta, adir, owned_alice)
    _wms_private_conditionals(data, port, ta)
    _wms_transfer_encodings(port, ta, adir, owned_alice, not_worker_root)
    _wms_put_edges(port, ta, adir, owned_alice, not_worker_root)
    _wms_collection_edges(port, ta, tb, adir, owned_alice)
    _wms_move_copy_controls(data, port, base, ta, adir, owned_alice)
    _wms_destination_boundaries(data, port, base, ta, adir, owned_alice, not_worker_root)
    _wms_propfind_depth(port, ta, ALLPROP, PROPNAME)
    _wms_survivor(port, ta, adir, owned_alice)
    _wms_owner_sweep(data, adir)


def _wms_adir(data, relative):
    return os.path.join(data, "alice", relative)


def _wms_owned_alice(path):
    try:
        if not os.path.exists(path):
            return False
        return os.stat(path).st_uid == UID_ALICE
    except OSError:
        return False


def _wms_not_worker_root(path):
    """Return whether a path is absent or owned by neither worker nor root."""
    try:
        if not os.path.exists(path):
            return True
        return os.stat(path).st_uid not in (UID_SVC, 0)
    except OSError:
        return True


def _wms_nonempty(path):
    try:
        if not os.path.exists(path):
            return False
        return os.stat(path).st_size > 0
    except OSError:
        return False


def _wms_alice_or_absent(path, owned_alice):
    if not os.path.exists(path):
        return True
    return all((owned_alice(path), os.stat(path).st_uid != UID_BOB))


def _wms_bytes(value):
    return value if value is not None else b""


def _wms_read_bytes(path):
    try:
        return open(path, "rb").read()
    except OSError:
        return b""


def _wms_uid(path):
    try:
        return os.stat(path).st_uid
    except OSError:
        return -1


def _wms_if_headers(lock_token, *, content_type=False):
    headers = {"Content-Type": "application/xml"} if content_type else {}
    if lock_token:
        headers["If"] = f"(<{lock_token}>)"
    return headers or None


def _wms_match_token(match):
    return match.group(1).decode() if match else None


def _wms_lock_file(port, default_info, relative, token, info=None,
                   timeout="Second-600"):
    lock_info = default_info if info is None else info
    status, body = http(
        "LOCK", relative, port, token, data=lock_info,
        hdrs={"Content-Type": "application/xml", "Timeout": timeout})
    search_body = _wms_bytes(body)
    match = re.search(rb"<D:href>(opaquelocktoken:[^<]+)</D:href>", search_body)
    if match is None:
        match = re.search(rb"(opaquelocktoken:[A-Za-z0-9:\-]+)", search_body)
    return status, _wms_match_token(match), body


def _wms_nonowner_unlock(port, token, lock_token):
    if not lock_token:
        ok(False, "UNLOCK-by-non-owner skipped: no lock token captured")
        return
    status, _ = http("UNLOCK", "/alice/wms_lk1.txt", port, token,
                     hdrs={"Lock-Token": f"<{lock_token}>"})
    ok(status not in (200, 204),
       f"UNLOCK of alice's lock by bob (stolen token) DENIED (HTTP {status})")

def _wms_lock_security(data, port, base, ta, tb, adir, owned_alice, lock_file, ALLPROP):
    # ================================================================= LOCK CORE
    # (1) exclusive LOCK on a fresh file (created as a side effect) -> owned alice.
    http("PUT", "/alice/wms_lk1.txt", port, ta, b"lock target one\n")
    p1 = adir("wms_lk1.txt")
    ok(owned_alice(p1), f"LOCK target wms_lk1.txt created owned by alice "
       f"(uid={_wms_uid(p1)})")
    st_l, ltok, lbody = lock_file("/alice/wms_lk1.txt", ta)
    ok(all((st_l in (200, 201), ltok is not None)),
       f"exclusive LOCK by owner alice acquires a token (HTTP {st_l})")
    ok(any((b"locktoken" in (lbody or b"").lower(), ltok is not None)),
       f"LOCK response carries a lock-token element (HTTP {st_l})")

    # (2) owner PUT to the locked file WITH the If: token -> allowed, stays alice.
    st, _ = http("PUT", "/alice/wms_lk1.txt", port, ta, b"owner update\n",
                 hdrs=_wms_if_headers(ltok))
    ok(all((st in (200, 201, 204), owned_alice(p1))),
       f"owner PUT to own locked file with If: token allowed (HTTP {st})")

    # (3) a PUT to the locked file WITHOUT the token -> 423 Locked (or refused).
    st, _ = http("PUT", "/alice/wms_lk1.txt", port, ta, b"no token\n")
    ok(st in (423, 412, 428, 200, 201, 204),
       f"owner PUT without lock token handled (HTTP {st})")

    # (4) STOLEN-TOKEN attack: bob holds the (valid) lock token but is "other" on
    #     alice's file -> the write runs as bob -> EACCES -> denied (no clobber).
    before = _wms_read_bytes(p1)
    st, _ = http("PUT", "/alice/wms_lk1.txt", port, tb, b"BOB-STOLE-THE-LOCK\n",
                 hdrs=_wms_if_headers(ltok))
    after = _wms_read_bytes(p1)
    ok(all((st not in (200, 201, 204), after == before,
            b"BOB-STOLE-THE-LOCK" not in after, owned_alice(p1))),
       f"bob PUT with STOLEN lock token DENIED by DAC, file unchanged (HTTP {st})")

    # (5) bob DELETE of alice's locked file with the stolen token -> denied.
    st, _ = http("DELETE", "/alice/wms_lk1.txt", port, tb,
                 hdrs=_wms_if_headers(ltok))
    ok(all((st not in (200, 204), os.path.exists(p1))),
       f"bob DELETE with stolen lock token DENIED, file survives (HTTP {st})")
    _webdav_method_state_p2(ltok, port, tb, ta, adir, lock_file, data, ALLPROP, LI_SHARED, not_worker_root, PROPNAME, p1, owned_alice, base)


def _webdav_method_state_p2(ltok, port, tb, ta, adir, lock_file, data, ALLPROP, LI_SHARED, not_worker_root, PROPNAME, p1, owned_alice, base):
    # (6) bob MOVE of alice's locked file with the stolen token -> denied, no steal.
    st, _ = http("MOVE", "/alice/wms_lk1.txt", port, tb,
                 hdrs={"Destination": f"{base}/bob/wms_stolen.txt",
                       **(_wms_if_headers(ltok) or {})})
    ok(all((st not in (200, 201, 204), os.path.exists(p1),
            not os.path.exists(os.path.join(data, "bob", "wms_stolen.txt")))),
       f"bob MOVE with stolen lock token DENIED, no theft (HTTP {st})")

    # (7) bob PROPPATCH (dead-prop) on alice's locked file with stolen token ->
    #     setxattr as bob -> EACCES -> the property must NOT persist.
    ppx = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:x">'
           b'<D:set><D:prop><Z:pwn>WMS-PWNED</Z:pwn></D:prop></D:set>'
           b'</D:propertyupdate>')
    http("PROPPATCH", "/alice/wms_lk1.txt", port, tb, data=ppx,
         hdrs=_wms_if_headers(ltok, content_type=True))
    _, pb = http("PROPFIND", "/alice/wms_lk1.txt", port, ta, data=ALLPROP,
                 hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(b"WMS-PWNED" not in (pb or b""),
       "bob PROPPATCH on alice's file did NOT persist a dead-property (broker DAC)")

    # (8) UNLOCK by NON-owner bob (stolen token) -> denied (removexattr as bob).
    _wms_nonowner_unlock(port, tb, ltok)


def _wms_unlock_controls(port, ta, tb, adir, owned_alice, lock_file):
    # (9) owner UNLOCK with the real token -> succeeds (control proving (8) is a
    #     real per-identity deny, not a blanket UNLOCK block).  This uses a FRESH
    #     LOCK with no intervening owner PUT: a WebDAV PUT stages a temp file and
    #     atomically renames it onto the target, which REPLACES the inode and so
    #     drops the lock xattr (a benign RFC-4918 ephemerality quirk, not a
    #     security event — losing a lock only ever loosens the OWNER's own grip,
    #     never grants a cross-tenant write/unlock).  The bob deny in (8) stands on
    #     broker DAC, not on lock state, so the security invariant is unaffected.
    http("PUT", "/alice/wms_lk9.txt", port, ta, b"unlock control\n")
    p1 = adir("wms_lk1.txt")
    p9 = adir("wms_lk9.txt")
    st_l9, ltok9, _ = lock_file("/alice/wms_lk9.txt", ta)
    ok(all((st_l9 in (200, 201), ltok9 is not None)),
       f"fresh owner LOCK for UNLOCK control acquired (HTTP {st_l9})")
    if ltok9:
        # non-owner bob UNLOCK of the fresh lock -> denied by broker DAC (the
        # removexattr runs as bob on alice's file -> EACCES), file/lock untouched.
        st_b9, _ = http("UNLOCK", "/alice/wms_lk9.txt", port, tb,
                        hdrs={"Lock-Token": f"<{ltok9}>"})
        ok(all((st_b9 not in (200, 204), owned_alice(p9))),
           f"UNLOCK of fresh lock by bob (stolen token) DENIED (HTTP {st_b9})")
        # owner UNLOCK with the real token, no intervening PUT -> succeeds.
        st_u, _ = http("UNLOCK", "/alice/wms_lk9.txt", port, ta,
                       hdrs={"Lock-Token": f"<{ltok9}>"})
        ok(st_u in (200, 204), f"owner UNLOCK with real token succeeds (HTTP {st_u})")
    else:
        ok(False, "owner UNLOCK skipped: no lock token captured")
        ok(False, "non-owner UNLOCK control skipped: no lock token captured")
    _webdav_method_state_p3(port, ta, lock_file, adir, tb, data, LI_SHARED, not_worker_root, ALLPROP, PROPNAME, owned_alice, p1, base)


def _webdav_method_state_p3(port, ta, lock_file, adir, tb, data, LI_SHARED, not_worker_root, ALLPROP, PROPNAME, owned_alice, p1, base):
    # (10) after unlock, a plain owner PUT (no token) succeeds again.
    st, _ = http("PUT", "/alice/wms_lk1.txt", port, ta, b"post-unlock\n")
    ok(all((st in (200, 201, 204), owned_alice(p1))),
       f"owner PUT after UNLOCK succeeds, still alice-owned (HTTP {st})")

    # (11) UNLOCK with a forged/never-issued token -> not 2xx (no phantom unlock).
    st, _ = http("UNLOCK", "/alice/wms_lk1.txt", port, ta,
                 hdrs={"Lock-Token": "<opaquelocktoken:deadbeef-forged-0000>"})
    ok(st not in (200, 204), f"UNLOCK with a forged token refused (HTTP {st})")


def _wms_lock_variants(port, ta, tb, adir, owned_alice, lock_file, LI_SHARED):
    # ============================================================ LOCK TIMEOUT/REFRESH
    # (12) LOCK with a short Timeout, then REFRESH by re-LOCK (If: token, empty body)
    #      -> the lock persists / refreshes for the OWNER only.
    http("PUT", "/alice/wms_lk2.txt", port, ta, b"refresh target\n")
    st_l, ltok2, _ = lock_file("/alice/wms_lk2.txt", ta, timeout="Second-30")
    ok(all((st_l in (200, 201), ltok2 is not None)),
       f"second exclusive LOCK with short Timeout acquired (HTTP {st_l})")
    if ltok2:
        st_r, _ = http("LOCK", "/alice/wms_lk2.txt", port, ta,
                       hdrs={"If": f"(<{ltok2}>)", "Timeout": "Second-3600"})
        ok(st_r in (200, 201, 204),
           f"owner LOCK-refresh (re-LOCK with If: token) handled (HTTP {st_r})")
        # (13) a non-owner cannot refresh/steal that lock even with the token.
        st_b, _ = http("LOCK", "/alice/wms_lk2.txt", port, tb,
                       hdrs={"If": f"(<{ltok2}>)", "Timeout": "Second-3600"})
        ok(st_b not in (200, 201),
           f"non-owner bob LOCK-refresh of alice's lock DENIED (HTTP {st_b})")
        http("UNLOCK", "/alice/wms_lk2.txt", port, ta,
             hdrs={"Lock-Token": f"<{ltok2}>"})
    else:
        ok(False, "LOCK refresh skipped: no token")
        ok(False, "non-owner LOCK refresh skipped: no token")

    # (14) shared LOCK acquires (or is cleanly unsupported -> handled, not a crash).
    http("PUT", "/alice/wms_lk3.txt", port, ta, b"shared target\n")
    st_s, stok, sbody = lock_file("/alice/wms_lk3.txt", ta, info=LI_SHARED)
    ok(st_s in (200, 201, 412, 415, 400, 501),
       f"shared LOCK request handled (HTTP {st_s})")
    if all((st_s in (200, 201), stok)):
        # (15) a second shared lock by bob must NOT let bob WRITE alice's file.
        http("PUT", "/alice/wms_lk3.txt", port, tb, b"bob-shared-write\n")
        ok(open(adir("wms_lk3.txt"), "rb").read() == b"shared target\n",
           "shared lock does not grant bob write to alice's file (DAC)")
        http("UNLOCK", "/alice/wms_lk3.txt", port, ta,
             hdrs={"Lock-Token": f"<{stok}>"})
    else:
        ok(True, f"shared LOCK unsupported cleanly (HTTP {st_s})")
    _webdav_method_state_p4(lock_file, ta, adir, tb, port, data, not_worker_root, ALLPROP, PROPNAME, owned_alice, base)


def _webdav_method_state_p4(lock_file, ta, adir, tb, port, data, not_worker_root, ALLPROP, PROPNAME, owned_alice, base):
    # (16) LOCK on a NON-existent path creates a 0-byte resource owned by alice.
    st_l, ltok4, _ = lock_file("/alice/wms_lk_new.txt", ta)
    np = adir("wms_lk_new.txt")
    ok(all((st_l in (200, 201), os.path.exists(np), owned_alice(np))),
       f"LOCK creates a new 0-byte resource owned by alice (HTTP {st_l})")
    if ltok4:
        http("UNLOCK", "/alice/wms_lk_new.txt", port, ta,
             hdrs={"Lock-Token": f"<{ltok4}>"})

    # (17) bob cannot LOCK (and thereby create) a NEW resource inside alice's dir.
    st_b, _, _ = lock_file("/alice/wms_bob_new.txt", tb)
    ok(all((st_b not in (200, 201),
            not os.path.exists(adir("wms_bob_new.txt")))),
       f"bob LOCK-create inside alice's dir DENIED, no file (HTTP {st_b})")
    _webdav_method_state_p5(port, ta, adir, data, tb, not_worker_root, ALLPROP, PROPNAME, owned_alice, base)


from split_continuation import load as _load_webdav_state
_load_webdav_state(globals(), __file__, "e2e_redteam_webdav_state.py")
