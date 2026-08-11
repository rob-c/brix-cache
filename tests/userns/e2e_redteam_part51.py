def _rt51_segment_01(key, port, data):
    ta, tb = mint(key, "alice"), mint(key, "bob")
    base = f"http://{HOST}:{port}"
    bpriv = os.path.join(data, "bob", "private.txt")
    adir = os.path.join(data, "alice")
    return ta, base, bpriv, adir


def _rt51_segment_02():

    def snap(p):
        """(exists, content_or_None, uid_or_-1, mode_or_-1) for a path."""
        try:
            stt = os.stat(p)
        except OSError:
            return (False, None, -1, -1)
        try:
            c = open(p, "rb").read()
        except OSError:
            c = None
        return (True, c, stt.st_uid, stt.st_mode & 0o7777)
    return snap


def _rt51_segment_03():

    def not_svc_root(p):
        """True iff p is absent or owned by neither svc(1500) nor root(0)."""
        try:
            if not os.path.lexists(p):
                return True
            return os.lstat(p).st_uid not in (UID_SVC, 0)
        except OSError:
            return True
    return not_svc_root


def _rt51_clean_rejection_status_family_nginx_core(snap, bpriv, port, ta):

    # Clean-rejection status family: nginx core 400 for unknown method tokens,
    # 405 for TRACE/CONNECT, plus the other honest refusals a router might emit.
    REJECT = (400, 401, 403, 404, 405, 411, 415, 501, 505)

    SECRET = b"BOB-PRIVATE-SECRET"

    # Canonical snapshot of bob's 0600 secret (reset_fixtures ran first), used to
    # prove NO undispatched method / override smuggling mutated or deleted it.
    b0 = snap(bpriv)
    ok(all((b0[0], b0[1] == b'BOB-PRIVATE-SECRET\n', b0[2] == UID_BOB, b0[3] == 384)),
       "control: bob/private.txt canonical 0600 bob-owned secret before attack")

    # ============================================================ READ-CLASS VERBS
    # Methods that, IF the router mistook them for a read, would expose bytes.
    # Each must NOT return bob's secret body (the read would run as alice=other).
    for m in ("REPORT", "SEARCH", "ACL", "LABEL", "PROPPATCH-NOPE"):
        st, b = http(m, "/bob/private.txt", port, ta)
        ok(all((st in REJECT + (207, 200, 422), SECRET not in any((b, b'')))),
           f"undispatched {m} on bob's 0600 leaks no secret body (HTTP {st})")
    return REJECT, SECRET


def _rt51_the_same_read_class_probe_must(port, ta, SECRET, snap, bpriv, REJECT, data):
    # The same read-class probe must also not leak via the world-readable name in
    # bob's 0700 secret DIR (directory-listing confusion): bobsecret/s.txt body.
    st, b = http("SEARCH", "/bobsecret/", port, ta,
                 data=b"<?xml version='1.0'?><searchrequest/>",
                 hdrs={"Content-Type": "application/xml"})
    ok(all((SECRET not in any((b, b'')), b'bob-only' not in any((b, b'')))),
       f"undispatched SEARCH of bob's 0700 dir enumerates/leaks nothing (HTTP {st})")

    _webdav_undispatched_methods_p1(data, snap, port, ta, adir, bpriv, not_svc_root, SECRET, REJECT, base)


def _webdav_undispatched_methods_p1(data, snap, port, ta, adir, bpriv, not_svc_root, SECRET, REJECT, base):
    # ============================================================ MUTATE-CLASS VERBS
    # Methods that, IF routed as a write/patch, would alter or destroy bob's file.
    # After each, bob's secret must be byte-identical, mode 0600, still bob-owned.
    for m, body in (("PATCH", b"PATCHED-BY-ATTACKER\n"),
                    ("ORDERPATCH", b"REORDERED\n"),
                    ("MERGE", b"MERGED\n"),
                    ("UPDATEREDIRECTREF", b"REDIR\n")):
        st, _ = http(m, "/bob/private.txt", port, ta, body,
                     hdrs={"Content-Type": "application/xml"})
        now = snap(bpriv)
        ok(all((st in REJECT + (422,), now[1] == b'BOB-PRIVATE-SECRET\n', now[2] == UID_BOB, now[3] == 384)),
           f"undispatched {m} did NOT mutate bob's 0600 secret (HTTP {st})")

    # A mutate-class verb aimed at DELETING bob's readable.txt must not unlink it.
    bread = os.path.join(data, "bob", "readable.txt")
    r0 = snap(bread)
    return bread, r0


def _rt51_artifact_create_verbs(port, ta, REJECT, snap, bread, r0, adir, not_svc_root):
    st, _ = http("UNBIND", "/bob/readable.txt", port, ta,
                 data=(b'<?xml version="1.0"?><D:unbind xmlns:D="DAV:">'
                       b"<D:segment>readable.txt</D:segment></D:unbind>"),
                 hdrs={"Content-Type": "application/xml"})
    ok(all((st in REJECT + (422,), snap(bread) == r0, os.path.exists(bread))),
       f"undispatched UNBIND did NOT delete bob's readable.txt (HTTP {st})")

    # ============================================================ ARTIFACT-CREATE VERBS
    # DeltaV/CalDAV "make-something" verbs: if the router runs them they must (a) be
    # confined to the export and (b) never leave an svc(1500)/root(0)-owned object.
    create_verbs = ("MKCALENDAR", "MKWORKSPACE", "MKACTIVITY", "VERSION-CONTROL",
                    "CHECKOUT", "CHECKIN", "UNCHECKOUT", "MKREDIRECTREF",
                    "BIND", "REBIND")
    for m in create_verbs:
        tgt = f"und_{m.lower().replace('-', '_')}"
        st, _ = http(m, f"/alice/{tgt}", port, ta)
        fp = os.path.join(adir, tgt)
        # Either cleanly refused (nothing created) OR, if created, owned by the
        # MAPPED user alice -- never the worker/root, and never escaping the dir.
        created_ok = (not os.path.lexists(fp)) or (
            os.lstat(fp).st_uid == UID_ALICE and os.lstat(fp).st_uid not in (UID_SVC, 0))
        ok(all((st in REJECT + (200, 201, 204), created_ok, not_svc_root(fp))),
           f"undispatched {m} in alice's dir: no worker/root artifact (HTTP {st})")
    # An artifact verb pointed at the world-writable pub dir must NOT yield a file
    # owned by the worker uid masquerading as a tenant write.
    st, _ = http("MKACTIVITY", "/pub/und_act", port, ta)
    return st


def _rt51_method_override_smuggling(data, st, REJECT, not_svc_root, snap, bpriv, port, ta, adir):
    pubp = os.path.join(data, "pub", "und_act")
    ok(all((st in REJECT + (200, 201, 204), not_svc_root(pubp))),
       f"undispatched MKACTIVITY in world-writable pub creates no svc/root file (HTTP {st})")
    _webdav_undispatched_methods_p2(adir, port, ta, data, snap, bpriv, not_svc_root, SECRET, REJECT, base)


def _webdav_undispatched_methods_p2(adir, port, ta, data, snap, bpriv, not_svc_root, SECRET, REJECT, base):
    # ============================================================ METHOD-OVERRIDE SMUGGLING
    # POST/PUT carrying X-HTTP-Method-Override: DELETE on bob/private.txt -- the
    # server must NOT honour the header to delete/mutate bob's file.  Snapshot the
    # file around EACH override-header variant (each is a distinct parse path).
    override_hdrs = ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method")
    for oh in override_hdrs:
        pre = snap(bpriv)
        st, _ = http("POST", "/bob/private.txt", port, ta, b"",
                     hdrs={oh: "DELETE"})
        post = snap(bpriv)
        ok(all((post == pre, post[0], post[1] == b'BOB-PRIVATE-SECRET\n')),
           f"POST + {oh}: DELETE did NOT delete/alter bob's 0600 (HTTP {st})")
    # PUT body carrying an override to MOVE bob's file into alice's space (theft):
    # the override must be ignored -> no copy/move lands in alice's dir.
    stolen = os.path.join(adir, "und_stolen_via_override.txt")
    return stolen


def _rt51_override_pointed_at_alice_s_own(port, ta, base, stolen, snap, bpriv, adir, st):
    st, _ = http("PUT", "/bob/private.txt", port, ta, b"x\n",
                 hdrs={"X-HTTP-Method-Override": "MOVE",
                       "Destination": f"{base}/alice/und_stolen_via_override.txt"})
    ok(all((not os.path.exists(stolen), snap(bpriv)[1] == b'BOB-PRIVATE-SECRET\n')),
       f"PUT + override MOVE did NOT steal bob's file into alice's dir (HTTP {st})")
    # Override pointed at alice's OWN file: even if a server honoured override, the
    # result must stay alice-owned and the privilege must not change (no escalation).
    http("PUT", "/alice/und_ov_self.txt", port, ta, b"self\n")
    selfp = os.path.join(adir, "und_ov_self.txt")
    st, _ = http("POST", "/alice/und_ov_self.txt", port, ta, b"",
                 hdrs={"X-HTTP-Method-Override": "DELETE"})
    return st, selfp


def _rt51_if_the_override_were_honoured_as(not_svc_root, selfp, st, data, snap, port, ta):
    # If the override were honoured as a real DELETE-by-alice it would be legal, so
    # we don't forbid removal; we forbid the file becoming worker/root-owned and we
    # forbid a smuggled override from creating a DIFFERENT-owner artifact.
    ok(not_svc_root(selfp),
       f"override on alice's OWN file never yields a worker/root artifact (HTTP {st})")
    # Override DELETE on bob via the keep-alive-free path must also not work when
    # the visible verb is itself a write the server DOES route (PUT) -- targeting a
    # path alice cannot write: bob's 0700 secret dir child.
    sx = os.path.join(data, "bobsecret", "s.txt")
    sx0 = snap(sx)
    st, _ = http("PUT", "/bobsecret/s.txt", port, ta, b"OVERRIDE-PWN\n",
                 hdrs={"X-HTTP-Method": "PUT"})
    ok(all((snap(sx) == sx0, sx0[0])),
       f"override-tagged PUT into bob's 0700 dir DENIED, child unchanged (HTTP {st})")


def _rt51_case_folding_verbs(port, ta, REJECT, SECRET, adir):

    # ============================================================ CASE-FOLDING VERBS
    # Lowercase get/put must NOT be silently upcased into a routed GET/PUT.  Even if
    # the server case-folds, the DAC still applies: lowercase get on bob's 0600 must
    # not leak; lowercase put into alice's dir must (if honoured) stay alice-owned.
    st, b = http("get", "/bob/private.txt", port, ta)
    ok(all((st in REJECT + (200,), SECRET not in any((b, b'')))),
       f"lowercase 'get' on bob's 0600 leaks no secret (HTTP {st})")
    st, _ = http("put", "/alice/und_lower.txt", port, ta, b"lower\n")
    lp = os.path.join(adir, "und_lower.txt")
    ok(any((not os.path.lexists(lp), os.lstat(lp).st_uid == UID_ALICE)),
       f"lowercase 'put' into alice's dir is rejected or stays alice-owned (HTTP {st})")


def _rt51_lowercase_put_into_bob_s_dir(data, port, ta, REJECT, adir):
    # lowercase 'put' into BOB's dir must never write a file there.
    lbob = os.path.join(data, "bob", "und_lower_bob.txt")
    http("put", "/bob/und_lower_bob.txt", port, ta, b"x\n")
    ok(not os.path.exists(lbob),
       "lowercase 'put' into bob's dir created no file (case-fold cannot bypass DAC)")
    _webdav_undispatched_methods_p3(port, ta, adir, snap, bpriv, REJECT)


def _webdav_undispatched_methods_p3(port, ta, adir, snap, bpriv, REJECT):
    # ============================================================ BOGUS VERB
    # A wholly-unknown verb must be cleanly rejected and mutate nothing.
    st, b = http("FOOBAR", "/alice/und_foobar.txt", port, ta, b"x\n")
    ok(all((st in REJECT, not os.path.exists(os.path.join(adir, 'und_foobar.txt')))),
       f"bogus FOOBAR verb cleanly rejected, nothing created (HTTP {st})")


def _rt51_bogus_verb_against_the_etc_symlink(port, ta):
    # Bogus verb against the /etc-symlink escape must not read /etc/passwd.
    st, b = http("FOOBAR", "/escape/passwd", port, ta)
    ok(b'root:x:0:0' not in any((b, b'')),
       f"bogus verb on /escape symlink does not read /etc/passwd (HTTP {st})")

    # ============================================================ TRACE / CONNECT (raw)
    # TRACE must NOT reflect the request (Cross-Site-Tracing): the bearer token and
    # a marker header must be absent from the response body.  Use raw_http so we can
    # plant the Authorization header verbatim and inspect the raw bytes.
    trace_raw = (
        "TRACE /alice/und_trace HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Authorization: Bearer {ta}\r\n"
        "X-Reflect-Marker: UND-XST-REFLECT-7Q\r\n"
        "Connection: close\r\n\r\n"
    )
    resp = raw_http(trace_raw, port)
    ok(all((b'UND-XST-REFLECT-7Q' not in resp, ta.encode() not in resp)),
       "TRACE does not reflect the bearer token / marker header (no XST leak)")
    return resp


def _rt51_connect_authority_form_must_not_open(resp, port):
    ok(b"200" not in resp.split(b"\r\n", 1)[0],
       f"TRACE is not answered 200 (refused: {resp.split(chr(13).encode(),1)[0][:40]!r})")
    # CONNECT (authority-form) must not open a tunnel / be answered 2xx -- the
    # worker must refuse to become a forward proxy.
    connect_raw = (
        "CONNECT 169.254.169.254:80 HTTP/1.1\r\n"
        "Host: 169.254.169.254:80\r\n"
        "Connection: close\r\n\r\n"
    )
    cresp = raw_http(connect_raw, port)
    first = cresp.split(b"\r\n", 1)[0] if cresp else b""
    ok(all((b'200' not in first, b'Connection established' not in cresp)),
       f"CONNECT tunnel refused (no SSRF forward-proxy): {first[:40]!r}")
    _webdav_undispatched_methods_p4(port, ta, adir, snap, bpriv)


def _rt51_worker_survival(port, ta, adir):

    # ============================================================ WORKER SURVIVAL
    # After the whole undispatched/override barrage a legit op must still work and
    # land owned by the mapped user -> no verb wedged or crashed the worker/broker.
    st, _ = http("PUT", "/alice/und_survivor.txt", port, ta, b"alive\n")
    sp = os.path.join(adir, "und_survivor.txt")
    ok(all((st in (200, 201, 204), os.path.exists(sp), os.stat(sp).st_uid == UID_ALICE)),
       f"worker SURVIVED undispatched/override barrage; legit PUT owned alice (HTTP {st})")
    st, b = http("GET", "/alice/und_survivor.txt", port, ta)
    ok(all((st == 200, b == b'alive\n')),
       f"post-barrage GET returns the survivor body (worker healthy) (HTTP {st})")


def _rt51_final_sweep_nothing_und_in_alice(adir, snap, bpriv):
    # Final sweep: nothing und_* in alice's dir may be owned by svc(1500)/root(0).
    bad = []
    try:
        for f in os.listdir(adir):
            if not f.startswith("und_"):
                continue
            fp = os.path.join(adir, f)
            try:
                if os.lstat(fp).st_uid in (UID_SVC, 0):
                    bad.append(f)
            except OSError:
                pass
    except OSError:
        pass
    ok(not bad,
       f"no und_ artifact in alice's tree is worker(1500)/root(0)-owned: {bad[:4]}")
    # And bob's secret is STILL canonical after everything (end-to-end invariant).
    bend = snap(bpriv)
    ok(all((bend[1] == b'BOB-PRIVATE-SECRET\n', bend[2] == UID_BOB, bend[3] == 384)),
       "bob's 0600 secret unchanged end-to-end after the full undispatched barrage")


def run_webdav_undispatched_methods(key, data, port, s3port):
    """Undispatched/exotic HTTP+WebDAV methods and HTTP-method-override smuggling
    under impersonation: every method nginx-xrootd does NOT route (REPORT, SEARCH,
    PATCH, the DeltaV/CalDAV/RFC-5842 verbs, TRACE, CONNECT, a bogus verb, and
    lowercase get/put) must either be cleanly REJECTED or, if dispatched, enforce
    the broker DAC -- and NO override header (X-HTTP-Method-Override / X-Method-
    Override / X-HTTP-Method) may smuggle a DELETE/MOVE/PUT past the visible verb to
    mutate, delete, escalate, escape, or create an svc/root-owned artifact.  WHY:
    the verb is the first dispatch key; a method the router silently treats as a
    mutating op, or an override header the router honours, bypasses the entire
    auth->impersonation->DAC chain.  Distinct from run_webdav_methods (HEAD/OPTIONS/
    UNLOCK/COPY/Overwrite/Depth -- all ROUTED verbs) and run_webdav_method_state
    (LOCK-state x conditional x PUT/MKCOL/MOVE edge matrix on ROUTED verbs): this
    batch attacks the UN-routed verb space + override smuggling, a surface neither
    touches.  All fixtures prefixed `und_`."""
    ta, base, bpriv, adir = _rt51_segment_01(key, port, data)

    snap = _rt51_segment_02()

    not_svc_root = _rt51_segment_03()

    REJECT, SECRET = _rt51_clean_rejection_status_family_nginx_core(snap, bpriv, port, ta)

    bread, r0 = _rt51_the_same_read_class_probe_must(port, ta, SECRET, snap, bpriv, REJECT, data)

    st = _rt51_artifact_create_verbs(port, ta, REJECT, snap, bread, r0, adir, not_svc_root)

    stolen = _rt51_method_override_smuggling(data, st, REJECT, not_svc_root, snap, bpriv, port, ta, adir)

    st, selfp = _rt51_override_pointed_at_alice_s_own(port, ta, base, stolen, snap, bpriv, adir, st)

    _rt51_if_the_override_were_honoured_as(not_svc_root, selfp, st, data, snap, port, ta)

    _rt51_case_folding_verbs(port, ta, REJECT, SECRET, adir)

    _rt51_lowercase_put_into_bob_s_dir(data, port, ta, REJECT, adir)

    resp = _rt51_bogus_verb_against_the_etc_symlink(port, ta)

    _rt51_connect_authority_form_must_not_open(resp, port)

    _rt51_worker_survival(port, ta, adir)

    _rt51_final_sweep_nothing_und_in_alice(adir, snap, bpriv)
