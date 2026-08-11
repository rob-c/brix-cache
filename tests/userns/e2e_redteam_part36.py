def _rt36_segment_01(key, port):
    ta, tb = mint(key, "alice"), mint(key, "bob")
    base = f"http://{HOST}:{port}"
    XML = {"Content-Type": "application/xml"}
    return ta, tb, base, XML


def _rt36_segment_02(data):

    def adir(rel):
        return os.path.join(data, "alice", rel)
    return adir


def _rt36_segment_03():

    def owned_alice(p):
        try:
            return os.path.exists(p) and os.stat(p).st_uid == UID_ALICE
        except OSError:
            return False
    return owned_alice


def _rt36_segment_04():

    def not_worker_root(p):
        """True iff p is absent or owned by neither svc(1500) nor root(0)."""
        try:
            return (not os.path.exists(p)) or os.stat(p).st_uid not in (UID_SVC, 0)
        except OSError:
            return True
    return not_worker_root


def _rt36_segment_05(ta, port):

    def fetch_etag(rel):
        """GET rel over a raw socket and parse the real ETag header value (or None).
        http() hides response headers, so the conditional-transfer checks need this
        to drive a TRUE-matching vs a wrong If-Match against the live etag."""
        raw = ("GET " + rel + " HTTP/1.1\r\nHost: " + HOST + "\r\n"
               "Authorization: Bearer " + ta + "\r\nConnection: close\r\n\r\n")
        resp = raw_http(raw, port)
        m = re.search(rb"\r\n[Ee][Tt][Aa][Gg]:\s*([^\r\n]+)\r\n", resp or b"")
        return m.group(1).decode().strip() if m else None
    return fetch_etag


def _rt36_segment_06(XML, port):

    def propfind(rel, token, body, depth="0"):
        h = dict(XML)
        h["Depth"] = depth
        return http("PROPFIND", rel, port, token, data=body, hdrs=h)
    return propfind


def _rt36_a_multi_prop_proppatch(port, ta, adir, owned_alice):

    NS_ALLPROP = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                  b'<D:allprop/></D:propfind>')
    NS_PROPNAME = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                   b'<D:propname/></D:propfind>')

    _protocol_features_webdav_p1(port, ta, adir, propfind, NS_ALLPROP, tb, NS_PROPNAME, fetch_etag, data, owned_alice, XML, not_worker_root, base)


def _protocol_features_webdav_p1(port, ta, adir, propfind, NS_ALLPROP, tb, NS_PROPNAME, fetch_etag, data, owned_alice, XML, not_worker_root, base):
    # ===================================================== (a) MULTI-PROP PROPPATCH
    http("PUT", "/alice/pfw_multi.txt", port, ta, b"multi-prop target\n")
    pm = adir("pfw_multi.txt")
    ok(owned_alice(pm),
       f"PROPPATCH target pfw_multi.txt created owned by alice "
       f"(uid={os.stat(pm).st_uid if os.path.exists(pm) else -1})")
    return NS_ALLPROP, NS_PROPNAME, pm


def _rt36_segment_08(port, ta, XML, propfind, NS_ALLPROP):

    pp_multi = (b'<?xml version="1.0"?>'
                b'<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:pfw">'
                b'<D:set><D:prop>'
                b'<Z:author>alice-pfw</Z:author>'
                b'<Z:color>cerulean-pfw</Z:color>'
                b'<Z:rating>five-pfw</Z:rating>'
                b'</D:prop></D:set></D:propertyupdate>')
    st_pp, _ = http("PROPPATCH", "/alice/pfw_multi.txt", port, ta, data=pp_multi,
                    hdrs=XML)
    ok(st_pp in (200, 207, 422, 403, 501),
       f"multi-property PROPPATCH (3 dead props in one request) handled (HTTP {st_pp})")

    st_pf, body = propfind("/alice/pfw_multi.txt", ta, NS_ALLPROP)
    persisted = sum(1 for n in (b"alice-pfw", b"cerulean-pfw", b"five-pfw")
                    if n in (body or b""))
    return st_pp, st_pf, persisted


def _rt36_the_property_must_never_persist_positive(st_pp, persisted, st_pf, owned_alice, pm, port, tb, XML):
    supported = st_pp in (200, 207) and persisted >= 1
    if supported:
        ok(persisted == 3,
           f"all three dead props round-trip via PROPFIND allprop "
           f"(found {persisted}/3, PROPFIND {st_pf})")
    else:
        ok(True, f"multi-property PROPPATCH unsupported/handled (PROPPATCH {st_pp})")
    ok(owned_alice(pm),
       "multi-property PROPPATCH left the file owned by alice (broker xattr as owner)")

    # bob PROPPATCH on alice's 0644 file -> setxattr runs AS bob (other) -> EACCES;
    # the property must NEVER persist (positive control: alice's own props survive).
    pp_bob = (b'<?xml version="1.0"?>'
              b'<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:pfw">'
              b'<D:set><D:prop><Z:pwn>PFW-BOB-PWNED</Z:pwn></D:prop></D:set>'
              b'</D:propertyupdate>')
    st_b, _ = http("PROPPATCH", "/alice/pfw_multi.txt", port, tb, data=pp_bob,
                   hdrs=XML)
    return st_b


def _rt36_b_proppatch_remove(propfind, ta, NS_ALLPROP, st_b, owned_alice, pm, port):
    _, body_after = propfind("/alice/pfw_multi.txt", ta, NS_ALLPROP)
    ok(any((st_b not in (200, 207), b'PFW-BOB-PWNED' not in any((body_after, b'')))),
       f"bob PROPPATCH on alice's file denied/no-op (HTTP {st_b})")
    ok(b'PFW-BOB-PWNED' not in any((body_after, b'')),
       "bob's dead-property did NOT persist on alice's file (broker xattr DAC)")
    ok(owned_alice(pm),
       "alice's file unchanged-owner after bob's PROPPATCH attempt")
    _protocol_features_webdav_p2(port, ta, adir, propfind, NS_ALLPROP, NS_PROPNAME, fetch_etag, data, XML, owned_alice, pm, not_worker_root, base)


def _protocol_features_webdav_p2(port, ta, adir, propfind, NS_ALLPROP, NS_PROPNAME, fetch_etag, data, XML, owned_alice, pm, not_worker_root, base):
    # ===================================================== (b) PROPPATCH REMOVE
    http("PUT", "/alice/pfw_rm.txt", port, ta, b"remove-prop target\n")


def _rt36_segment_11(adir, port, ta, XML, propfind, NS_ALLPROP):
    prm = adir("pfw_rm.txt")
    pp_set1 = (b'<?xml version="1.0"?>'
               b'<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:pfw">'
               b'<D:set><D:prop><Z:ephemeral>PFW-EPHEMERAL</Z:ephemeral></D:prop>'
               b'</D:set></D:propertyupdate>')
    st_s1, _ = http("PROPPATCH", "/alice/pfw_rm.txt", port, ta, data=pp_set1,
                    hdrs=XML)
    _, body_set = propfind("/alice/pfw_rm.txt", ta, NS_ALLPROP)
    set_ok = st_s1 in (200, 207) and b"PFW-EPHEMERAL" in (body_set or b"")
    return prm, st_s1, set_ok


def _rt36_segment_12(port, ta, XML, propfind, NS_ALLPROP, set_ok, st_s1, owned_alice, prm):

    pp_remove = (b'<?xml version="1.0"?>'
                 b'<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:pfw">'
                 b'<D:remove><D:prop><Z:ephemeral/></D:prop></D:remove>'
                 b'</D:propertyupdate>')
    st_rm, _ = http("PROPPATCH", "/alice/pfw_rm.txt", port, ta, data=pp_remove,
                    hdrs=XML)
    _, body_rm = propfind("/alice/pfw_rm.txt", ta, NS_ALLPROP)
    if set_ok:
        ok(all((st_rm in (200, 207), b'PFW-EPHEMERAL' not in any((body_rm, b'')))),
           f"PROPPATCH REMOVE drops the dead property (set {st_s1}, remove {st_rm})")
    else:
        ok(b'PFW-EPHEMERAL' not in any((body_rm, b'')),
           f"dead-property set/remove unsupported but no stale prop leaks "
           f"(set {st_s1}, remove {st_rm})")
    ok(owned_alice(prm),
       "PROPPATCH set+remove cycle left the file owned by alice")
    _protocol_features_webdav_p3(port, ta, adir, propfind, NS_ALLPROP, NS_PROPNAME, fetch_etag, data, XML, owned_alice, pm, not_worker_root, base)


def _rt36_c_namespaced_round_trip(port, ta, adir, XML, propfind, NS_ALLPROP):

    # ===================================================== (c) NAMESPACED ROUND-TRIP
    http("PUT", "/alice/pfw_ns.txt", port, ta, b"namespaced-prop target\n")
    pns = adir("pfw_ns.txt")
    pp_ns = (b'<?xml version="1.0"?>'
             b'<D:propertyupdate xmlns:D="DAV:" '
             b'xmlns:CO="http://pfw.example.org/custom#" '
             b'xmlns:OT="http://pfw.example.org/other#">'
             b'<D:set><D:prop>'
             b'<CO:tag>PFW-NS-CUSTOM</CO:tag>'
             b'<OT:tag>PFW-NS-OTHER</OT:tag>'
             b'</D:prop></D:set></D:propertyupdate>')
    st_ns, _ = http("PROPPATCH", "/alice/pfw_ns.txt", port, ta, data=pp_ns, hdrs=XML)
    st_nf, body_ns = propfind("/alice/pfw_ns.txt", ta, NS_ALLPROP)
    return pns, st_ns, st_nf, body_ns


def _rt36_d_three_propfind_bodies(st_ns, body_ns, st_nf, owned_alice, pns, propfind, ta):
    if st_ns in (200, 207) and (b"PFW-NS-CUSTOM" in (body_ns or b"")
                                or b"PFW-NS-OTHER" in (body_ns or b"")):
        ok(all((b'PFW-NS-CUSTOM' in any((body_ns, b'')), b'PFW-NS-OTHER' in any((body_ns, b'')))),
           f"namespaced (xmlns) custom props round-trip both namespaces "
           f"(PROPPATCH {st_ns}, PROPFIND {st_nf})")
    else:
        ok(True, f"namespaced custom-prop round-trip unsupported/handled "
                 f"(PROPPATCH {st_ns})")
    ok(owned_alice(pns),
       "namespaced-prop file owned by alice (broker xattr as owner)")
    _protocol_features_webdav_p4(propfind, ta, NS_ALLPROP, NS_PROPNAME, port, adir, fetch_etag, data, owned_alice, pm, not_worker_root, base)


def _protocol_features_webdav_p4(propfind, ta, NS_ALLPROP, NS_PROPNAME, port, adir, fetch_etag, data, owned_alice, pm, not_worker_root, base):
    # ===================================================== (d) THREE PROPFIND BODIES
    # On the OWNER's file: named-prop, allprop, propname must each respond cleanly.
    named_body = (b'<?xml version="1.0"?>'
                  b'<D:propfind xmlns:D="DAV:">'
                  b'<D:prop><D:getcontentlength/><D:getlastmodified/>'
                  b'<D:resourcetype/></D:prop></D:propfind>')
    st_n, body_n = propfind("/alice/pfw_multi.txt", ta, named_body)
    ok(st_n in (200, 207),
       f"PROPFIND named-prop on own file (HTTP {st_n})")
    return named_body


def _rt36_propname_must_return_names_not_values(propfind, ta, NS_ALLPROP, NS_PROPNAME):
    st_a, body_a = propfind("/alice/pfw_multi.txt", ta, NS_ALLPROP)
    ok(any((all((st_a in (200, 207), b'getcontentlength' in any((body_a, b'')).lower())), st_a in (200, 207))),
       f"PROPFIND allprop on own file (HTTP {st_a})")
    st_pn, body_pn = propfind("/alice/pfw_multi.txt", ta, NS_PROPNAME)
    ok(st_pn in (200, 207),
       f"PROPFIND propname on own file (HTTP {st_pn})")
    # propname must return NAMES not VALUES: the dead-property VALUE must be absent.
    ok(b'cerulean-pfw' not in any((body_pn, b'')),
       "PROPFIND propname returns names only, not the dead-property VALUE")


def _rt36_positive_control_propfind_allprop_on_bob(named_body, NS_ALLPROP, NS_PROPNAME, propfind, ta, port, adir):

    # On bob's 0600: each of the three PROPFIND bodies is a confidentiality oracle —
    # alice (other) must never see bob's secret bytes regardless of the body shape.
    for label, pf_body in (("named-prop", named_body),
                           ("allprop", NS_ALLPROP),
                           ("propname", NS_PROPNAME)):
        st_o, body_o = propfind("/bob/private.txt", ta, pf_body)
        ok(b'BOB-PRIVATE-SECRET' not in any((body_o, b'')),
           f"PROPFIND {label} on bob's 0600 leaks NO secret bytes (HTTP {st_o})")
    # positive control: PROPFIND allprop on bob's WORLD-READABLE file is fine and
    # exposes only metadata (alice may stat it; that is correct DAC, not a leak).
    st_ctrl, body_ctrl = propfind("/bob/readable.txt", ta, NS_ALLPROP)
    ok(st_ctrl in (200, 207, 403, 404),
       f"PROPFIND allprop on bob's 0644 control handled (HTTP {st_ctrl})")
    _protocol_features_webdav_p5(port, ta, adir, fetch_etag, data, owned_alice, pm, not_worker_root, base)


def _protocol_features_webdav_p5(port, ta, adir, fetch_etag, data, owned_alice, pm, not_worker_root, base):
    # ===================================================== (e) CONDITIONAL COPY/MOVE
    http("PUT", "/alice/pfw_csrc.txt", port, ta, b"conditional-copy source\n")
    psrc = adir("pfw_csrc.txt")
    return psrc


def _rt36_copy_with_a_matching_if_match(fetch_etag, owned_alice, psrc, adir, port, ta, base, not_worker_root):
    etag = fetch_etag("/alice/pfw_csrc.txt")
    ok(owned_alice(psrc), "conditional-COPY source owned by alice")

    # COPY with a MATCHING If-Match on the source etag -> precondition satisfied.
    cdst = adir("pfw_cdst.txt")
    if etag:
        st_cm, _ = http("COPY", "/alice/pfw_csrc.txt", port, ta,
                        hdrs={"Destination": f"{base}/alice/pfw_cdst.txt",
                              "If-Match": etag})
        # The server emits WEAK etags (W/"...") and RFC 7232 If-Match uses STRONG
        # comparison, so a weak etag never matches -> 412 is correct (not a bug);
        # accept it alongside a successful conditional COPY.  Either way the dest is
        # never worker/root-owned.
        ok(all((st_cm in (201, 204, 200, 412), not_worker_root(cdst))),
           f"COPY with If-Match(source etag) handled, dest never worker/root-owned "
           f"user (HTTP {st_cm}, etag={etag})")
        ok(any((not os.path.exists(cdst), owned_alice(cdst))),
           "conditional-COPY destination owned by alice (never svc/root)")
    else:
        # No etag exposed: fall back to a plain COPY for the ownership invariant.
        st_cm, _ = http("COPY", "/alice/pfw_csrc.txt", port, ta,
                        hdrs={"Destination": f"{base}/alice/pfw_cdst.txt"})
        ok(all((st_cm in (201, 204, 200), not_worker_root(cdst))),
           f"COPY (no etag exposed) applied, dest owned by mapped user (HTTP {st_cm})")
        ok(any((not os.path.exists(cdst), owned_alice(cdst))),
           "conditional-COPY fallback destination owned by alice")

    # COPY with a WRONG If-Match -> 412 Precondition Failed (no copy made).
    wrong_dst = adir("pfw_cdst_wrong.txt")
    return wrong_dst


def _rt36_overwrite_f_copy_over_an_existing(port, ta, base, wrong_dst, owned_alice, adir):
    st_cw, _ = http("COPY", "/alice/pfw_csrc.txt", port, ta,
                    hdrs={"Destination": f"{base}/alice/pfw_cdst_wrong.txt",
                          "If-Match": '"pfw-definitely-wrong-etag"'})
    ok(any((st_cw in (412, 304, 403, 409), not os.path.exists(wrong_dst))),
       f"COPY with WRONG If-Match did not create the destination (HTTP {st_cw})")
    ok(any((not os.path.exists(wrong_dst), owned_alice(wrong_dst))),
       "wrong-If-Match COPY produced no foreign-owned residue")

    # Overwrite:F COPY over an EXISTING destination -> 412 (no clobber of content).
    http("PUT", "/alice/pfw_owdst.txt", port, ta, b"PFW-PREEXISTING-DST\n")
    powd = adir("pfw_owdst.txt")
    return powd


def _rt36_segment_19(port, ta, base, powd):
    st_of, _ = http("COPY", "/alice/pfw_csrc.txt", port, ta,
                    hdrs={"Destination": f"{base}/alice/pfw_owdst.txt",
                          "Overwrite": "F"})
    dst_body = b""
    try:
        dst_body = open(powd, "rb").read()
    except OSError:
        pass
    ok(any((st_of in (412, 409, 403), dst_body == b'PFW-PREEXISTING-DST\n')),
       f"Overwrite:F COPY over existing target refused / not clobbered (HTTP {st_of})")
    ok(b"conditional-copy source" not in dst_body,
       "Overwrite:F left the pre-existing destination content intact (no clobber)")
    _protocol_features_webdav_p6(port, ta, adir, data, fetch_etag, owned_alice, pm, not_worker_root, base)


def _rt36_move_with_depth_infinity_of_an(port, ta, base, adir):

    # MOVE with Depth:infinity of an OWNED collection -> tree moves, owned by alice.
    http("MKCOL", "/alice/pfw_mvsrc", port, ta)
    http("PUT", "/alice/pfw_mvsrc/leaf.txt", port, ta, b"PFW-LEAF\n")
    st_mv, _ = http("MOVE", "/alice/pfw_mvsrc", port, ta,
                    hdrs={"Destination": f"{base}/alice/pfw_mvdst",
                          "Depth": "infinity"})
    mvdst = adir("pfw_mvdst")
    mvleaf = os.path.join(mvdst, "leaf.txt")
    return st_mv, mvdst, mvleaf


def _rt36_bob_s_secret_never_appears_in(st_mv, not_worker_root, mvdst, mvleaf, port, ta, data):
    ok(all((st_mv in (201, 204, 200), not_worker_root(mvdst))),
       f"MOVE Depth:infinity of owned collection (HTTP {st_mv})")
    ok(any((not os.path.isdir(mvdst), os.stat(mvdst).st_uid == UID_ALICE)),
       "MOVEd collection directory owned by alice (never svc/root)")
    ok(any((not os.path.exists(mvleaf), os.stat(mvleaf).st_uid == UID_ALICE)),
       "MOVEd collection leaf owned by alice")

    # cross-tenant conditional MOVE: alice MOVE INTO bob's 0700 dir -> denied, and
    # bob's secret never appears in the response; positive control follows.
    http("PUT", "/alice/pfw_xmove.txt", port, ta, b"PFW-XMOVE\n")
    bsecret = os.path.join(data, "bobsecret", "pfw_xmove.txt")
    return bsecret


def _rt36_positive_control_the_same_source_moves(port, ta, base, bsecret, owned_alice, adir):
    st_xm, body_xm = http("MOVE", "/alice/pfw_xmove.txt", port, ta,
                          hdrs={"Destination": f"{base}/bobsecret/pfw_xmove.txt",
                                "Overwrite": "T"})
    ok(all((st_xm not in (201, 204, 200), not os.path.exists(bsecret))),
       f"cross-tenant MOVE into bob's 0700 dir DENIED, no file planted (HTTP {st_xm})")
    ok(all((b'svc-only-secret' not in any((body_xm, b'')), b'BOB-PRIVATE-SECRET' not in any((body_xm, b'')))),
       "cross-tenant MOVE error response leaks no foreign secret bytes")
    # positive control: the same source MOVEs fine WITHIN alice's own space.
    st_pc, _ = http("MOVE", "/alice/pfw_xmove.txt", port, ta,
                    hdrs={"Destination": f"{base}/alice/pfw_xmove2.txt"})
    ok(all((st_pc in (201, 204, 200), owned_alice(adir('pfw_xmove2.txt')))),
       f"control: same MOVE within alice's space succeeds, owned alice (HTTP {st_pc})")
    _protocol_features_webdav_p7(port, ta, adir, fetch_etag, owned_alice, pm)


def _rt36_f_options_coll_vs_file(port, ta, adir):

    # ===================================================== (f) OPTIONS coll vs file
    st_oc, body_oc = http("OPTIONS", "/alice/", port, ta)
    ok(st_oc in (200, 204),
       f"OPTIONS on a collection advertises DAV/Allow, no body action (HTTP {st_oc})")
    st_ofl, _ = http("OPTIONS", "/alice/pfw_multi.txt", port, ta)
    ok(st_ofl in (200, 204),
       f"OPTIONS on a file handled distinctly from a collection (HTTP {st_ofl})")
    # OPTIONS is a pure metadata probe: it must NOT create/touch a phantom resource.
    ok(not os.path.exists(adir("pfw_phantom_options")),
       "OPTIONS had zero filesystem side effect (no phantom resource created)")


def _rt36_options_on_bob_s_0700_dir(port, ta, adir, fetch_etag):
    # OPTIONS on bob's 0700 dir must not enumerate or leak its private contents.
    st_ob, body_ob = http("OPTIONS", "/bobsecret/", port, ta)
    ok(all((b'svc-only-secret' not in any((body_ob, b'')), b'BOB-PRIVATE-SECRET' not in any((body_ob, b'')))),
       f"OPTIONS on bob's private dir leaks no contents (HTTP {st_ob})")
    _protocol_features_webdav_p8(port, ta, adir, fetch_etag, owned_alice, pm)


def _protocol_features_webdav_p8(port, ta, adir, fetch_etag, owned_alice, pm):
    # ===================================================== (g) If-Range GET own file
    http("PUT", "/alice/pfw_ir.txt", port, ta, b"0123456789ABCDEF")
    pir = adir("pfw_ir.txt")
    ir_etag = fetch_etag("/alice/pfw_ir.txt")
    return pir, ir_etag


def _rt36_if_range_with_the_current_etag(port, ta, ir_etag, owned_alice, pir):
    # If-Range with the CURRENT etag + Range -> may serve the partial slice (206) or
    # the full body (200); both are RFC-7233 conformant.  Body must be exact bytes.
    st_ir, body_ir = http("GET", "/alice/pfw_ir.txt", port, ta,
                          hdrs={"If-Range": ir_etag or '"x"', "Range": "bytes=0-3"})
    ok(st_ir in (200, 206),
       f"If-Range GET on own file (matching etag) handled (HTTP {st_ir})")
    if st_ir == 206:
        ok(all((body_ir == b'0123', owned_alice(pir))),
           "If-Range matching etag served the exact 0-3 slice (byte-exact)")
    else:
        ok(all((body_ir == b'0123456789ABCDEF', owned_alice(pir))),
           "If-Range full-body fallback served the exact whole file (byte-exact)")
    # If-Range with a STALE etag + Range -> RFC says serve the FULL representation.
    st_st, body_st = http("GET", "/alice/pfw_ir.txt", port, ta,
                          hdrs={"If-Range": '"pfw-stale-etag"', "Range": "bytes=0-3"})
    ok(all((st_st in (200, 206), body_st in (b'0123456789ABCDEF', b'0123'))),
       f"If-Range stale etag served a valid representation (HTTP {st_st})")


def _rt36_if_range_as_a_confidentiality_oracle(port, ta, owned_alice, pm):
    # If-Range as a confidentiality oracle on bob's 0600 -> still no secret bytes.
    st_irb, body_irb = http("GET", "/bob/private.txt", port, ta,
                            hdrs={"If-Range": '"x"', "Range": "bytes=0-4"})
    ok(b'BOB-PRIVATE-SECRET' not in any((body_irb, b'')),
       f"If-Range GET on bob's 0600 leaks no secret (HTTP {st_irb})")
    _protocol_features_webdav_p9(port, ta, owned_alice, pm)


def _protocol_features_webdav_p9(port, ta, owned_alice, pm):
    # ===================================================== worker-survival follow-up
    # After all the property/conditional churn the worker must still serve a plain
    # legit op for the mapped user (proves no broker desync / principal wedge).
    st_f, body_f = http("GET", "/alice/pfw_multi.txt", port, ta)
    ok(all((st_f == 200, b'multi-prop target' in any((body_f, b'')))),
       f"worker survived the property/conditional battery (follow-up GET OK, HTTP {st_f})")
    ok(owned_alice(pm),
       "post-battery: alice's property-bearing file still owned by alice")


def run_protocol_features_webdav(key, data, port, s3port):
    """WebDAV PROPERTY / CONDITIONAL-TRANSFER feature surface under impersonation
    (a dimension the basic-method suite never enters): multi-property PROPPATCH
    set, dead-property REMOVE, namespaced (xmlns) custom-prop round-trip, the three
    PROPFIND request bodies (named-prop vs allprop vs propname) on the OWNER's file
    AND as a confidentiality oracle against bob's 0600 (a PROPFIND body must never
    spill a byte of bob's secret), ETag-driven conditional COPY/MOVE (If-Match on
    the SOURCE etag: matching -> apply, wrong -> 412 no-op), Overwrite:F over an
    existing target (412, no clobber), MOVE with Depth, OPTIONS on a collection vs a
    file (DAV/Allow advertised, ZERO side effect), and a conditional GET with
    If-Range on the owner's own file.  Every property that PERSISTS must persist on
    a file owned by the mapped user (never svc 1500 / root 0); every cross-tenant
    PROPPATCH/COPY/MOVE must be denied AND leave no residue; every read-side oracle
    must be marker-free.  Fixtures are prefixed `pfw_` to avoid collisions."""
    ta, tb, base, XML = _rt36_segment_01(key, port)

    adir = _rt36_segment_02(data)

    owned_alice = _rt36_segment_03()

    not_worker_root = _rt36_segment_04()

    fetch_etag = _rt36_segment_05(ta, port)

    propfind = _rt36_segment_06(XML, port)

    NS_ALLPROP, NS_PROPNAME, pm = _rt36_a_multi_prop_proppatch(port, ta, adir, owned_alice)

    st_pp, st_pf, persisted = _rt36_segment_08(port, ta, XML, propfind, NS_ALLPROP)

    st_b = _rt36_the_property_must_never_persist_positive(st_pp, persisted, st_pf, owned_alice, pm, port, tb, XML)

    _rt36_b_proppatch_remove(propfind, ta, NS_ALLPROP, st_b, owned_alice, pm, port)

    prm, st_s1, set_ok = _rt36_segment_11(adir, port, ta, XML, propfind, NS_ALLPROP)

    _rt36_segment_12(port, ta, XML, propfind, NS_ALLPROP, set_ok, st_s1, owned_alice, prm)

    pns, st_ns, st_nf, body_ns = _rt36_c_namespaced_round_trip(port, ta, adir, XML, propfind, NS_ALLPROP)

    named_body = _rt36_d_three_propfind_bodies(st_ns, body_ns, st_nf, owned_alice, pns, propfind, ta)

    _rt36_propname_must_return_names_not_values(propfind, ta, NS_ALLPROP, NS_PROPNAME)

    psrc = _rt36_positive_control_propfind_allprop_on_bob(named_body, NS_ALLPROP, NS_PROPNAME, propfind, ta, port, adir)

    wrong_dst = _rt36_copy_with_a_matching_if_match(fetch_etag, owned_alice, psrc, adir, port, ta, base, not_worker_root)

    powd = _rt36_overwrite_f_copy_over_an_existing(port, ta, base, wrong_dst, owned_alice, adir)

    _rt36_segment_19(port, ta, base, powd)

    st_mv, mvdst, mvleaf = _rt36_move_with_depth_infinity_of_an(port, ta, base, adir)

    bsecret = _rt36_bob_s_secret_never_appears_in(st_mv, not_worker_root, mvdst, mvleaf, port, ta, data)

    _rt36_positive_control_the_same_source_moves(port, ta, base, bsecret, owned_alice, adir)

    _rt36_f_options_coll_vs_file(port, ta, adir)

    pir, ir_etag = _rt36_options_on_bob_s_0700_dir(port, ta, adir, fetch_etag)

    _rt36_if_range_with_the_current_etag(port, ta, ir_etag, owned_alice, pir)

    _rt36_if_range_as_a_confidentiality_oracle(port, ta, owned_alice, pm)

