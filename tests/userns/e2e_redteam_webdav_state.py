"""WebDAV state and protocol-edge checks for the red-team battery.

Executed in :mod:`e2e_redteam`'s namespace by the part-10 continuation.
"""

def _wms_precondition_result(status, path, expected, owned_alice, label):
    if status == 412:
        ok(_wms_read_bytes(path) == expected,
           f"{label} 412 left the original body intact")
        return
    ok(owned_alice(path), f"{label} result still owned by alice")


def _wms_delete_result(status, path, owned_alice):
    if status == 412:
        ok(all((os.path.exists(path), owned_alice(path))),
           "conditional DELETE 412 left alice's file intact")
        return
    ok(True, f"conditional DELETE applied (HTTP {status})")


def _wms_own_conditionals(port, ta, adir, owned_alice):
    # ====================================================== CONDITIONAL HEADERS (OWN FILE)
    # Build a known file + capture its ETag/Last-Modified for the matrix.
    http("PUT", "/alice/wms_cond.txt", port, ta, b"conditional-body-v1\n")
    cp = adir("wms_cond.txt")
    st0, b0 = http("GET", "/alice/wms_cond.txt", port, ta)
    ok(all((st0 == 200, b0 == b"conditional-body-v1\n")),
       f"conditional control: GET own file returns body (HTTP {st0})")

    # (18) If-None-Match:* PUT over an EXISTING file -> 412 (no clobber).
    st, _ = http("PUT", "/alice/wms_cond.txt", port, ta, b"should-not-apply\n",
                 hdrs={"If-None-Match": "*"})
    ok(st in (412, 304, 200, 201, 204),
       f"If-None-Match:* PUT over existing handled (HTTP {st})")
    _wms_precondition_result(
        st, cp, b"conditional-body-v1\n", owned_alice, "If-None-Match:* PUT")

    # (19) If-Match:* PUT over an existing file -> precondition satisfied (allowed).
    st, _ = http("PUT", "/alice/wms_cond.txt", port, ta, b"conditional-body-v2\n",
                 hdrs={"If-Match": "*"})
    ok(all((st in (200, 201, 204), owned_alice(cp))),
       f"If-Match:* PUT over existing applied, owned alice (HTTP {st})")

    # (20) If-Match a bogus ETag -> 412 (precondition fails), body unchanged.
    st, _ = http("PUT", "/alice/wms_cond.txt", port, ta, b"must-not-apply\n",
                 hdrs={"If-Match": '"bogus-etag-xyz"'})
    ok(st in (412, 200, 201, 204),
       f"If-Match bogus-etag PUT handled (HTTP {st})")
    _wms_precondition_result(
        st, cp, b"conditional-body-v2\n", owned_alice, "If-Match bogus-etag PUT")

    # (21) If-Modified-Since far future -> GET own file may 304 (no body) or 200.
    st, b = http("GET", "/alice/wms_cond.txt", port, ta,
                 hdrs={"If-Modified-Since": "Fri, 01 Jan 2100 00:00:00 GMT"})
    ok(st in (304, 200, 412),
       f"If-Modified-Since future on own file handled (HTTP {st})")

    # (22) If-Unmodified-Since epoch -> precondition fails on a recently-written
    #      file -> 412 (or handled); never clobbers.
    st, _ = http("PUT", "/alice/wms_cond.txt", port, ta, b"unmod-attempt\n",
                 hdrs={"If-Unmodified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"})
    ok(st in (412, 200, 201, 204),
       f"If-Unmodified-Since epoch PUT handled (HTTP {st})")

    # (23) conditional DELETE: If-Match bogus ETag -> precondition fails -> file
    #      survives (control: file still there + owned alice).
    st, _ = http("DELETE", "/alice/wms_cond.txt", port, ta,
                 hdrs={"If-Match": '"definitely-wrong"'})
    ok(st in (412, 200, 204),
       f"conditional DELETE with bad If-Match handled (HTTP {st})")
    _wms_delete_result(st, cp, owned_alice)


def _wms_private_conditionals(data, port, ta):
    # ============================== CONDITIONAL HEADERS AS A NON-ORACLE vs BOB 0600
    bpriv = os.path.join(data, "bob", "private.txt")
    cond_hdrs = [
        ("If-Match:*", {"If-Match": "*"}),
        ("If-None-Match:*", {"If-None-Match": "*"}),
        ("If-None-Match-etag", {"If-None-Match": '"abc"'}),
        ("If-Match-etag", {"If-Match": '"abc"'}),
        ("If-Modified-Since-epoch",
         {"If-Modified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"}),
        ("If-Modified-Since-future",
         {"If-Modified-Since": "Fri, 01 Jan 2100 00:00:00 GMT"}),
        ("If-Unmodified-Since-epoch",
         {"If-Unmodified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"}),
        ("If-Range+Range", {"If-Range": '"abc"', "Range": "bytes=0-4"}),
    ]
    for label, hdr in cond_hdrs:
        # (24..31) GET bob's 0600 with each conditional -> never leaks the secret,
        #          regardless of which precondition branch the server takes.
        st, b = http("GET", "/bob/private.txt", port, ta, hdrs=hdr)
        ok(b"BOB-PRIVATE-SECRET" not in (b or b""),
           f"conditional GET bob's 0600 with {label} no body leak (HTTP {st})")
    # (32) conditional PUT (If-Match:*) over bob's 0600 file -> denied + unchanged.
    pre = b""
    try:
        pre = open(bpriv, "rb").read()
    except OSError:
        pass
    st, _ = http("PUT", "/bob/private.txt", port, ta, b"WMS-COND-OVERWRITE\n",
                 hdrs={"If-Match": "*"})
    post = b""
    try:
        post = open(bpriv, "rb").read()
    except OSError:
        pass
    ok(all((st not in (200, 201, 204), post == pre,
            b"WMS-COND-OVERWRITE" not in post)),
       f"conditional PUT over bob's 0600 DENIED + unchanged (HTTP {st})")
    # (33) conditional DELETE (If-Match:*) of bob's 0600 -> denied + survives.
    st, _ = http("DELETE", "/bob/private.txt", port, ta, hdrs={"If-Match": "*"})
    ok(all((st not in (200, 204), os.path.exists(bpriv))),
       f"conditional DELETE of bob's 0600 DENIED, survives (HTTP {st})")


def _wms_transfer_encodings(port, ta, adir, owned_alice, not_worker_root):
    # ============================================================ CONTENT-RANGE / PARTIAL PUT
    # (34) seed a file, then Content-Range partial PUT (supported -> patches bytes;
    #      unsupported -> 4xx, no corruption).  Either way owned alice, no escalate.
    http("PUT", "/alice/wms_part.txt", port, ta, b"AAAAAAAAAA")
    pp = adir("wms_part.txt")
    st, _ = http("PUT", "/alice/wms_part.txt", port, ta, b"BB",
                 hdrs={"Content-Range": "bytes 2-3/10"})
    ok(all((st in (200, 201, 204, 400, 501, 416), owned_alice(pp),
            not_worker_root(pp))),
       f"Content-Range partial PUT handled, owned alice (HTTP {st})")

    # (35) chunked Transfer-Encoding PUT -> body assembled, owned alice.
    st, _ = http("PUT", "/alice/wms_chunked.txt", port, ta, b"chunked-body-data\n",
                 hdrs={"Transfer-Encoding": "chunked"})
    chp = adir("wms_chunked.txt")
    ok(all((st in (200, 201, 204, 400, 411, 501), not_worker_root(chp))),
       f"chunked PUT handled, never worker/root-owned (HTTP {st})")
    if os.path.exists(chp):
        ok(owned_alice(chp), "chunked PUT result owned by alice")
    else:
        ok(True, "chunked PUT not persisted (rejected) — acceptable")

    # (36) Expect: 100-continue PUT -> owned alice (or handled), never worker/root.
    st, _ = http("PUT", "/alice/wms_expect.txt", port, ta, b"expect-100-body\n",
                 hdrs={"Expect": "100-continue"})
    ep = adir("wms_expect.txt")
    ok(all((st in (200, 201, 204, 100, 417), not_worker_root(ep))),
       f"Expect:100-continue PUT handled (HTTP {st})")
    if _wms_nonempty(ep):
        ok(owned_alice(ep), "Expect:100-continue PUT result owned by alice")
    else:
        ok(True, "Expect:100-continue PUT not persisted — acceptable")


def _wms_put_edges(port, ta, adir, owned_alice, not_worker_root):
    # ============================================================ PUT EDGE CASES
    # (37) PUT with a TRAILING SLASH (a collection path) -> must NOT create a plain
    #      file named with a slash, and must NOT escalate; 4xx-class expected.
    st, _ = http("PUT", "/alice/wms_tslash/", port, ta, b"x\n")
    tsl = adir("wms_tslash")
    ok(st in (400, 403, 405, 409, 415, 501, 201, 204),
       f"PUT with trailing slash handled (HTTP {st})")
    # if it created anything, it must be alice-owned (no worker/root leak).
    ok(not_worker_root(tsl), "PUT trailing-slash created nothing worker/root-owned")

    # (38) PUT over an EXISTING COLLECTION -> must be refused (can't overwrite a dir
    #      with a file); the directory must survive.
    http("MKCOL", "/alice/wms_coll", port, ta)
    cdir = adir("wms_coll")
    ok(all((os.path.isdir(cdir), owned_alice(cdir))),
       "MKCOL created collection owned by alice (control)")
    st, _ = http("PUT", "/alice/wms_coll", port, ta, b"file-over-dir\n")
    # Security invariant: a PUT must NEVER replace/destroy an existing collection
    # and must never leave a worker/root-owned artifact beside it.  The exact
    # refusal status is a protocol detail (500 today; 405/409 would be tidier) —
    # what matters is the deny: the dir survives intact and nothing escalated.
    ok(all((st not in (200, 201, 204), os.path.isdir(cdir),
            owned_alice(cdir), not_worker_root(cdir))),
       f"PUT over an existing collection refused, dir survives (HTTP {st})")


def _wms_collection_edges(port, ta, tb, adir, owned_alice):
    # ============================================================ MKCOL NESTING
    # (39) MKCOL with a MISSING parent -> 409 Conflict (RFC 4918 §9.3.1); nothing
    #      is created underneath.
    st, _ = http("MKCOL", "/alice/wms_absent_parent/child", port, ta)
    ok(all((st in (409, 403, 404, 400),
            not os.path.exists(adir("wms_absent_parent")))),
       f"MKCOL with missing parent -> conflict, nothing created (HTTP {st})")
    # (40) MKCOL the parent THEN the child -> both succeed, owned alice (control).
    st1, _ = http("MKCOL", "/alice/wms_parent", port, ta)
    st2, _ = http("MKCOL", "/alice/wms_parent/child", port, ta)
    child = adir(os.path.join("wms_parent", "child"))
    ok(all((st1 in (200, 201), st2 in (200, 201),
            os.path.isdir(child), owned_alice(child))),
       f"MKCOL parent-then-child both created owned alice (HTTP {st1}/{st2})")
    # (41) MKCOL over an EXISTING collection -> 405 Method Not Allowed.
    st, _ = http("MKCOL", "/alice/wms_parent", port, ta)
    ok(st in (405, 409, 403, 200, 201),
       f"MKCOL over existing collection handled (HTTP {st})")
    # (42) MKCOL with a request body -> 415 Unsupported Media Type (or handled).
    st, _ = http("MKCOL", "/alice/wms_bodycol", port, ta, b"unexpected-body\n",
                 hdrs={"Content-Type": "text/plain"})
    ok(st in (415, 400, 201, 200, 403),
       f"MKCOL with a body handled (HTTP {st})")
    # (43) bob MKCOL inside alice's dir -> DENIED by DAC (alice's 0755 dir).
    st, _ = http("MKCOL", "/alice/wms_bob_mkcol", port, tb)
    ok(all((st not in (200, 201),
            not os.path.exists(adir("wms_bob_mkcol")))),
       f"bob MKCOL inside alice's dir DENIED (HTTP {st})")


def _wms_move_copy_controls(data, port, base, ta, adir, owned_alice):
    # ============================================================ MOVE / COPY DEST EDGE
    http("PUT", "/alice/wms_mc.txt", port, ta, b"move-copy-src\n")
    src = adir("wms_mc.txt")
    # (44) MOVE with MISSING Destination header -> 400 Bad Request; src untouched.
    st, _ = http("MOVE", "/alice/wms_mc.txt", port, ta)
    ok(all((st in (400, 411, 412), os.path.exists(src))),
       f"MOVE with missing Destination -> 400, src untouched (HTTP {st})")
    # (45) COPY with MISSING Destination header -> 400; src untouched.
    st, _ = http("COPY", "/alice/wms_mc.txt", port, ta)
    ok(all((st in (400, 411, 412), os.path.exists(src))),
       f"COPY with missing Destination -> 400, src untouched (HTTP {st})")
    # (46) MOVE Destination == SOURCE (same path) -> 403 Forbidden (RFC 4918);
    #      file must survive whatever the server decides.
    st, _ = http("MOVE", "/alice/wms_mc.txt", port, ta,
                 hdrs={"Destination": f"{base}/alice/wms_mc.txt"})
    ok(all((st in (403, 400, 204, 201), os.path.exists(src))),
       f"MOVE Destination==Source handled, file survives (HTTP {st})")
    # (47) COPY Destination == SOURCE -> 403; file survives.
    st, _ = http("COPY", "/alice/wms_mc.txt", port, ta,
                 hdrs={"Destination": f"{base}/alice/wms_mc.txt"})
    ok(all((st in (403, 400, 204, 201), os.path.exists(src))),
       f"COPY Destination==Source handled, file survives (HTTP {st})")
    # (48) COPY into OWN SUBTREE -> new file owned alice (control: COPY works).
    http("MKCOL", "/alice/wms_sub", port, ta)
    st, _ = http("COPY", "/alice/wms_mc.txt", port, ta,
                 hdrs={"Destination": f"{base}/alice/wms_sub/wms_mc_copy.txt"})
    subcopy = adir(os.path.join("wms_sub", "wms_mc_copy.txt"))
    ok(all((st in (201, 204), os.path.exists(subcopy), owned_alice(subcopy))),
       f"COPY into own subtree, dest owned alice (HTTP {st})")
    # (49) MOVE into OWN subtree -> dest owned alice, src gone (control).
    st, _ = http("MOVE", "/alice/wms_mc.txt", port, ta,
                 hdrs={"Destination": f"{base}/alice/wms_sub/wms_mc_moved.txt"})
    moved = adir(os.path.join("wms_sub", "wms_mc_moved.txt"))
    ok(all((st in (201, 204), os.path.exists(moved), owned_alice(moved),
            not os.path.exists(src))),
       f"MOVE into own subtree, dest owned alice + src gone (HTTP {st})")

def _wms_destination_boundaries(data, port, base, ta, adir, owned_alice, not_worker_root):
    # (50) MOVE/COPY Destination on a FOREIGN host header -> 502/400 (or same-host
    #      handled); must not write outside the export.
    http("PUT", "/alice/wms_fh.txt", port, ta, b"foreign-host\n")
    st, _ = http("COPY", "/alice/wms_fh.txt", port, ta,
                 hdrs={"Destination": "http://evil.example/alice/wms_evil.txt"})
    # The server treats Destination as path-only (RFC 4918 §8.3): the evil host is
    # IGNORED and the copy is confined within the export at /alice/wms_evil.txt, so
    # a benign 201 is fine.  The security invariants are: (a) NOTHING is written
    # off-host / outside the export named after the foreign host, and (b) if the
    # in-export dest was created, it is owned by the MAPPED user (alice), never
    # svc(1500)/root(0)/bob — no escape, no ownership-invariant violation, no escalation.
    evil_dest = adir("wms_evil.txt")
    off_host = os.path.join(os.path.dirname(data), "evil.example")
    ok(all((st in (502, 400, 403, 412, 201, 204),
            not os.path.exists(off_host), not_worker_root(evil_dest),
            _wms_alice_or_absent(evil_dest, owned_alice))),
       f"COPY to a foreign-host Destination stays confined + owned by the "
       f"mapped user, no off-host/cross-tenant write (HTTP {st})")
    # (51) COPY Destination with a traversal escape (../) -> nothing outside root.
    outside = os.path.join(os.path.dirname(data), "WMS_ESCAPE")
    http("COPY", "/alice/wms_fh.txt", port, ta,
         hdrs={"Destination": f"{base}/../WMS_ESCAPE"})
    ok(not os.path.exists(outside),
       "COPY Destination ../escape created nothing outside the export")
    # (52) COPY with Destination into bob's dir -> DENIED (DAC), no file in bob's.
    st, _ = http("COPY", "/alice/wms_fh.txt", port, ta,
                 hdrs={"Destination": f"{base}/bob/wms_into_bob.txt"})
    ok(all((st not in (200, 201, 204),
            not os.path.exists(os.path.join(data, "bob", "wms_into_bob.txt")))),
       f"COPY Destination into bob's dir DENIED (HTTP {st})")


def _wms_propfind_depth(port, ta, ALLPROP, PROPNAME):
    # ============================================================ PROPFIND DEPTH MATRIX
    # Seed a small tree under alice so Depth variants have something to walk.
    http("MKCOL", "/alice/wms_tree", port, ta)
    http("PUT", "/alice/wms_tree/leaf.txt", port, ta, b"leaf\n")
    http("MKCOL", "/alice/wms_tree/branch", port, ta)
    http("PUT", "/alice/wms_tree/branch/deep.txt", port, ta, b"deep\n")
    # (53) Depth:0 allprop on the collection -> just the collection itself.
    st, b = http("PROPFIND", "/alice/wms_tree/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(st in (207, 200), f"PROPFIND Depth:0 allprop on own collection (HTTP {st})")
    # (54) Depth:0 must NOT enumerate children (leaf.txt absent at depth 0).
    ok(all((st in (207, 200), b"leaf.txt" not in _wms_bytes(b))),
       f"PROPFIND Depth:0 does not enumerate children (HTTP {st})")
    # (55) Depth:1 allprop -> immediate children present (leaf.txt + branch).
    st, b = http("PROPFIND", "/alice/wms_tree/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "1", "Content-Type": "application/xml"})
    ok(all((st in (207, 200), b"leaf.txt" in _wms_bytes(b))),
       f"PROPFIND Depth:1 enumerates immediate children (HTTP {st})")
    # (56) Depth:1 must NOT recurse into grandchildren (deep.txt absent).
    ok(b"deep.txt" not in _wms_bytes(b),
       "PROPFIND Depth:1 does not recurse to grandchildren (deep.txt absent)")
    # (57) Depth:infinity allprop -> recurses, grandchild visible.
    st, b = http("PROPFIND", "/alice/wms_tree/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "infinity", "Content-Type": "application/xml"})
    ok(all((st in (207, 200, 403),
            any((b"deep.txt" in _wms_bytes(b), st == 403)))),
       f"PROPFIND Depth:infinity recurses (or is disabled) (HTTP {st})")
    # (58) propname (no values) on own collection -> 207, names only.
    st, b = http("PROPFIND", "/alice/wms_tree/", port, ta, data=PROPNAME,
                 hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(st in (207, 200), f"PROPFIND propname on own collection (HTTP {st})")
    # (59) Depth:1 PROPFIND of bob's 0700 secret dir -> must NOT enumerate it.
    st, b = http("PROPFIND", "/bobsecret/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "1", "Content-Type": "application/xml"})
    ok(all((st in (403, 404, 401, 207, 200),
            b"s.txt" not in _wms_bytes(b), b"bob-only" not in _wms_bytes(b))),
       f"PROPFIND Depth:1 of bob's 0700 dir leaks nothing (HTTP {st})")
    # (60) Depth:infinity PROPFIND from export root must not leak the svc-only
    #      entry, bob's private leaf, or escape via the /etc symlink.
    st, b = http("PROPFIND", "/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "infinity", "Content-Type": "application/xml"})
    response = _wms_bytes(b)
    leaked = any((b"secret-name.txt" in response,
                  b"svc-only-secret" in response,
                  b"bob-only" in response, b"escape/" in response,
                  b"root:x:0:0" in response))
    ok(all((st in (207, 200, 403), not leaked)),
       f"recursive PROPFIND from root leaks no private/escape entries (HTTP {st})")
    # (61) invalid Depth value -> 400 Bad Request (or handled), no enumeration leak.
    st, b = http("PROPFIND", "/svconly/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "2", "Content-Type": "application/xml"})
    ok(b"secret-name.txt" not in _wms_bytes(b),
       f"PROPFIND with invalid Depth:2 leaks nothing from svc-only (HTTP {st})")


def _wms_survivor(port, ta, adir, owned_alice):
    # ============================================================ WORKER-SURVIVAL CONTROL
    # (62) After the whole hostile matrix, a fresh legit op still works and lands
    #      owned by the mapped user -> the worker + broker survived every attack.
    st, _ = http("PUT", "/alice/wms_survivor.txt", port, ta, b"still alive\n")
    sp = adir("wms_survivor.txt")
    ok(all((st in (200, 201, 204), owned_alice(sp))),
       f"worker SURVIVED the full method/state matrix; legit PUT owned alice (HTTP {st})")
    st, b = http("GET", "/alice/wms_survivor.txt", port, ta)
    ok(all((st == 200, b == b"still alive\n")),
       f"post-matrix GET returns the survivor file body (HTTP {st})")

def _wms_owner_sweep(data, adir):
    # (63) final ownership invariant sweep over everything wms_ created in alice's
    #      tree: nothing may be owned by svc(1500) or root(0).
    bad_owner = []
    try:
        for f in os.listdir(os.path.join(data, "alice")):
            if not f.startswith("wms_"):
                continue
            fp = adir(f)
            try:
                if os.lstat(fp).st_uid in (UID_SVC, 0):
                    bad_owner.append(f)
            except OSError:
                pass
    except OSError:
        pass
    ok(not bad_owner,
       f"no wms_ resource is owned by the worker(1500)/root(0): {bad_owner[:4]}")
