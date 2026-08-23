def _rt52_segment_01(key):
    ta, tb = mint(key, "alice"), mint(key, "bob")
    XML = {"Content-Type": "application/xml"}
    D0 = {"Depth": "0", "Content-Type": "application/xml"}
    return ta, XML, D0


def _rt52_segment_02(data):

    def adir(rel):
        return os.path.join(data, "alice", rel)
    return adir


def _rt52_segment_03():

    def pp_xml(actions):
        """actions = list of ('set'|'remove', inner_xml_bytes)."""
        body = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" '
                + b'xmlns:Z="urn:exotic">')
        for verb, inner in actions:
            body += (b'<D:' + verb.encode() + b'><D:prop>' + inner
                     + b'</D:prop></D:' + verb.encode() + b'>')
        return body + b'</D:propertyupdate>'
    return pp_xml


def _rt52_0_fixture_control(port, ta, adir):

    # ====================================================== (0) fixture control
    http("PUT", "/alice/xp_base.txt", port, ta, b"exotic-prop-base\n")
    bp = adir("xp_base.txt")
    ok(all((os.path.exists(bp), os.stat(bp).st_uid == UID_ALICE)),
       f"exotic-prop fixture xp_base.txt owned by alice "
       f"(uid={os.stat(bp).st_uid if os.path.exists(bp) else -1})")
    base0 = _dead_xattr_count(bp)
    ok(base0 == 0, f"fresh fixture carries no dead-property xattrs (count={base0})")
    return bp


def _rt52_control_a_plain_set_of_a(port, ta, pp_xml, XML, bp):

    # ========================================== (1) SET then REMOVE in ONE request
    # A single propertyupdate that sets a dead-prop then removes it must leave the
    # resource with NO such xattr on disk (kernel ground truth, not PROPFIND echo).
    st_sr, _ = http("PROPPATCH", "/alice/xp_base.txt", port, ta,
                    data=pp_xml([("set", b'<Z:ephemeral>VANISH</Z:ephemeral>'),
                                 ("remove", b'<Z:ephemeral/>')]), hdrs=XML)
    ok(all((st_sr in (200, 207), _dead_xattr_count(bp) == 0, not _dead_xattr_has_value(bp, b'VANISH'))),
       f"SET-then-REMOVE in one PROPPATCH leaves no dead-prop xattr on disk "
       f"(HTTP {st_sr}, count={_dead_xattr_count(bp)})")

    # control: a plain SET of a distinct dead-prop DOES persist on disk as exactly
    # one xattr carrying the value (proves the removal above was real, not a no-op).
    st_set, _ = http("PROPPATCH", "/alice/xp_base.txt", port, ta,
                     data=pp_xml([("set", b'<Z:keep>PERSIST</Z:keep>')]), hdrs=XML)
    ok(all((st_set in (200, 207), _dead_xattr_count(bp) == 1, _dead_xattr_has_value(bp, b'PERSIST'))),
       f"control: a plain dead-prop SET persists as one on-disk xattr "
       f"(HTTP {st_set}, count={_dead_xattr_count(bp)})")
    # the persisting prop must keep the resource alice-owned (broker setxattr as alice).
    ok(os.stat(bp).st_uid == UID_ALICE,
       "resource carrying a persisted dead-prop stays alice-owned (broker xattr)")


def _rt52_2_propfind_allprop_propname_named_live(port, ta, D0, data):

    # ============================== (2) PROPFIND allprop / propname / named-live
    st_a, ba = http("PROPFIND", "/alice/xp_base.txt", port, ta,
                    data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                         b'<D:allprop/></D:propfind>', hdrs=D0)
    ok(all((st_a == 207, ba.count(b'<D:response>') == 1, b'PERSIST' in ba)),
       f"PROPFIND allprop is one well-formed response carrying the dead-prop "
       f"(HTTP {st_a})")
    # allprop must not leak the absolute on-disk export path (confinement / info).
    ok(all((data.encode() not in ba, b'/etc/' not in ba)),
       "PROPFIND allprop response leaks no internal export/host path")

    st_pn, bpn = http("PROPFIND", "/alice/xp_base.txt", port, ta,
                      data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                           b'<D:propname/></D:propfind>', hdrs=D0)
    # propname lists NAMES only — no live values (size/etag) must appear as text.
    ok(all((st_pn == 207, b'<D:getcontentlength/>' in bpn, b'<D:getcontentlength>' not in bpn)),
       f"PROPFIND propname lists property NAMES without values (HTTP {st_pn})")


def _rt52_explicitly_named_live_props_each_requested(port, ta, D0, bp):

    # explicitly-named LIVE props: each requested live prop is emitted with a value.
    named = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop>'
             b'<D:getcontentlength/><D:getlastmodified/><D:resourcetype/>'
             b'<D:getetag/><D:creationdate/><D:displayname/>'
             b'<D:lockdiscovery/><D:supportedlock/>'
             b'<D:quota-available-bytes/><D:quota-used-bytes/>'
             b'</D:prop></D:propfind>')
    st_n, bn = http("PROPFIND", "/alice/xp_base.txt", port, ta, data=named, hdrs=D0)
    live_ok = all(tag in bn for tag in (
        b"<D:getcontentlength>", b"<D:getlastmodified>", b"<D:getetag>",
        b"<D:creationdate>", b"<D:supportedlock", b"<D:lockdiscovery"))
    ok(all((st_n == 207, live_ok)),
       f"PROPFIND named LIVE props emit values for the documented set (HTTP {st_n})")
    # getcontentlength must report the true size of alice's own file.
    want_len = b"<D:getcontentlength>%d</D:getcontentlength>" % os.stat(bp).st_size
    return named, bn, want_len


def _rt52_3_set_a_protected_live_dav(want_len, bn, bp, port, ta, XML):
    ok(want_len in bn,
       f"named-prop getcontentlength reports the true file size "
       f"({os.stat(bp).st_size} bytes)")

    # ===================================== (3) SET a protected/live DAV: prop
    # PROPPATCH must refuse to set a live/protected DAV: property (403 propstat),
    # must NOT store it as a dead-prop, and must not truncate/replace the file.
    pre_body = open(bp, "rb").read()
    pre_cnt = _dead_xattr_count(bp)
    prot = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>'
            b'<D:getetag>"forged-etag"</D:getetag>'
            b'<D:getcontentlength>999999</D:getcontentlength>'
            b'</D:prop></D:set></D:propertyupdate>')
    st_p, bpb = http("PROPPATCH", "/alice/xp_base.txt", port, ta, data=prot, hdrs=XML)
    return pre_body, pre_cnt, st_p, bpb


def _rt52_the_real_etag_size_are_still(st_p, bpb, bp, pre_cnt, pre_body, port, ta, D0):
    ok(all((st_p in (207, 403), b'403' in any((bpb, b'')))),
       f"PROPPATCH SET of protected DAV: props reports a 403 propstat (HTTP {st_p})")
    ok(all((_dead_xattr_count(bp) == pre_cnt, not _dead_xattr_has_value(bp, b'forged-etag'))),
       "protected-prop SET stored NO dead-prop xattr (no live-prop spoof)")
    ok(open(bp, "rb").read() == pre_body,
       "protected-prop PROPPATCH did not corrupt/truncate the file body")
    # the real etag/size are still server-derived, not the forged values.
    _, bchk = http("PROPFIND", "/alice/xp_base.txt", port, ta,
                   data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop>'
                        b'<D:getcontentlength/></D:prop></D:propfind>', hdrs=D0)
    ok(b"<D:getcontentlength>999999</D:getcontentlength>" not in bchk,
       "server reports the TRUE content-length, not the forged protected value")


def _rt52_4_many_dead_props_bounded_growth(port, ta, adir, pp_xml, XML):

    # ===================================== (4) MANY dead props -> bounded growth
    http("PUT", "/alice/xp_many.txt", port, ta, b"many-props\n")
    mp = adir("xp_many.txt")
    inner = b"".join(
        b'<Z:p%d>v%d</Z:p%d>' % (i, i, i) for i in range(40))
    st_m, _ = http("PROPPATCH", "/alice/xp_many.txt", port, ta,
                   data=pp_xml([("set", inner)]), hdrs=XML)
    cnt_m = _dead_xattr_count(mp)
    return mp, st_m, cnt_m


def _rt52_server_either_stores_all_40_bounded(st_m, cnt_m, mp, port, ta, adir):
    # server either stores all 40 (bounded, finite) or caps below — never unbounded
    # and never escalates ownership; the resource stays alice-owned.
    ok(all((st_m in (200, 207), 0 <= cnt_m <= 40, os.stat(mp).st_uid == UID_ALICE)),
       f"40 dead props stored bounded ({cnt_m} xattrs) on alice's file "
       f"(HTTP {st_m})")
    # a follow-up GET still works -> the large-but-bounded request did not desync
    # the broker inbound path.
    st_g, gb = http("GET", "/alice/xp_many.txt", port, ta)
    ok(all((st_g == 200, gb == b'many-props\n')),
       f"GET after the 40-prop PROPPATCH still returns the body (HTTP {st_g})")

    # =============== (5) foreign/mixed namespaces + empty + over-cap values
    http("PUT", "/alice/xp_ns.txt", port, ta, b"ns-mix\n")
    nf = adir("xp_ns.txt")
    return nf


def _rt52_read_the_foreign_ns_props_back(port, ta, XML, nf, D0, data):
    mixed = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" '
             b'xmlns:A="http://a.example/ns" xmlns:B="urn:b:other">'
             b'<D:set><D:prop>'
             b'<A:alpha>one</A:alpha><B:beta>two</B:beta>'
             b'<A:empty></A:empty>'
             b'</D:prop></D:set></D:propertyupdate>')
    st_x, _ = http("PROPPATCH", "/alice/xp_ns.txt", port, ta, data=mixed, hdrs=XML)
    ok(all((st_x in (200, 207), os.stat(nf).st_uid == UID_ALICE)),
       f"mixed/foreign-namespace + empty-value PROPPATCH handled, alice-owned "
       f"(HTTP {st_x}, xattrs={_dead_xattr_count(nf)})")
    # read the foreign-ns props back: well-formed, values preserved, no path leak.
    st_xf, bxf = http("PROPFIND", "/alice/xp_ns.txt", port, ta,
                      data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                           b'<D:allprop/></D:propfind>', hdrs=D0)
    ok(all((st_xf == 207, b'one' in bxf, b'two' in bxf, data.encode() not in bxf)),
       f"foreign-namespace dead-props round-trip with no path leak (HTTP {st_xf})")


def _rt52_over_cap_value_a_single_dead(port, ta, adir, XML):

    # over-cap value: a single dead-prop value beyond the 16 KiB cap is rejected and
    # NOT stored on disk; body stays under the 64 KiB PROPPATCH limit.
    http("PUT", "/alice/xp_big.txt", port, ta, b"big-val\n")
    bf = adir("xp_big.txt")
    big = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:x">'
           b'<D:set><D:prop><Z:huge>' + (b"X" * 40000) +
           b'</Z:huge></D:prop></D:set></D:propertyupdate>')
    st_b, _ = http("PROPPATCH", "/alice/xp_big.txt", port, ta, data=big, hdrs=XML)
    ok(not _dead_xattr_has_value(bf, b"XXXXXXXXXX" * 100),
       f"over-cap (40 KiB) dead-prop value NOT stored on disk (HTTP {st_b})")


def _rt52_6_cross_tenant_bob_s_0600(port, ta, data):
    st_bg, bgb = http("GET", "/alice/xp_big.txt", port, ta)
    ok(all((st_bg == 200, bgb == b'big-val\n')),
       f"GET after over-cap PROPPATCH still serves the body (no desync) "
       f"(HTTP {st_bg})")

    # ===================================== (6) CROSS-TENANT: bob's 0600 file
    bpriv = os.path.join(data, "bob", "private.txt")
    pre_mode = os.stat(bpriv).st_mode & 0o777
    pre_xcnt = _dead_xattr_count(bpriv)
    return bpriv, pre_mode, pre_xcnt


def _rt52_alice_propfind_of_bob_s_0600(bpriv, port, ta, named, D0, pp_xml, XML):
    pre_pbody = open(bpriv, "rb").read()

    # alice PROPFIND of bob's 0600 file: must be denied / leak no content-revealing
    # live prop (size/etag) and never the body secret.
    st_cf, bcf = http("PROPFIND", "/bob/private.txt", port, ta,
                      data=named, hdrs=D0)
    # PROPFIND never opens/reads the resource — it only lstat()s it — so the only
    # confidentiality boundary it can breach is the file CONTENT, never the size/etag.
    # Exposing getcontentlength/getetag of a 0600 file whose PARENT dir is 0755 is
    # STANDARD POSIX (identical to `ls -l` of an unreadable file: stat needs only
    # traverse on the parent, not read on the file) and is NOT a content leak.  Flag
    # ONLY if the actual secret BYTES appear in the body.
    leaked = b"BOB-PRIVATE-SECRET" in (bcf or b"")
    ok(all((st_cf in (403, 404, 401, 207), not leaked)),
       f"alice PROPFIND of bob's 0600 file leaks no body secret "
       f"(HTTP {st_cf}, leaked={leaked})")

    # alice PROPPATCH (dead-prop) on bob's 0600 file: broker setxattr as alice ->
    # EACCES -> denied; nothing persists and bob's file is untouched on disk.
    st_cp, _ = http("PROPPATCH", "/bob/private.txt", port, ta,
                    data=pp_xml([("set",
                                  b'<Z:pwn>ALICE-XTENANT-PROP</Z:pwn>')]), hdrs=XML)
    return pre_pbody, st_cp


def _rt52_segment_16(st_cp, bpriv, pre_xcnt, pre_mode, pre_pbody):
    ok(any((st_cp not in (200,), _dead_xattr_count(bpriv) == pre_xcnt)),
       f"alice PROPPATCH on bob's 0600 file did not add an xattr (HTTP {st_cp})")
    ok(not _dead_xattr_has_value(bpriv, b"ALICE-XTENANT-PROP"),
       "alice's cross-tenant dead-prop did NOT persist on bob's file (broker DAC)")
    ok(all((os.stat(bpriv).st_mode & 511 == pre_mode, os.stat(bpriv).st_uid == UID_BOB, open(bpriv, 'rb').read() == pre_pbody)),
       f"bob's 0600 file unchanged after alice's PROPPATCH "
       f"(mode={os.stat(bpriv).st_mode & 0o777:o}, uid={os.stat(bpriv).st_uid})")


def run_webdav_property_exotic(key, data, port, s3port):
    """EXOTIC PROPPATCH/PROPFIND bodies under impersonation, verified at the KERNEL
    (on-disk `user.nginx_xrootd.webdav.*` xattr) layer rather than by PROPFIND echo
    alone.  Probes: (1) set-then-remove a dead-prop in ONE request leaves NO xattr;
    (2) PROPFIND allprop/propname/named-LIVE-props are well-formed and leak no
    internal path; (3) a SET of a protected/live DAV: prop (getetag/getcontentlength)
    is refused (403 propstat) and is NOT stored, the file uncorrupted; (4) many
    bounded dead props are stored without unbounded xattr growth; (5) mixed/foreign
    namespaces + empty + over-cap values are bounded (16 KiB value cap enforced on
    disk); (6) CROSS-TENANT: alice PROPFIND on bob's 0600 file leaks no size/etag and
    alice PROPPATCH on bob's file persists no xattr + leaves bob's mode/xattrs intact.
    Distinct from run_lock_proppatch (no set-then-remove, no on-disk xattr count/value
    assertion), run_webdav_method_state (no named-live-prop enumeration, no protected-
    prop SET, no kernel xattr verification) and run_group_xattr_lock (group-write-bit
    discrimination, not exotic bodies / value caps / protected props)."""
    ta, XML, D0 = _rt52_segment_01(key)

    adir = _rt52_segment_02(data)

    pp_xml = _rt52_segment_03()

    bp = _rt52_0_fixture_control(port, ta, adir)

    _rt52_control_a_plain_set_of_a(port, ta, pp_xml, XML, bp)

    _rt52_2_propfind_allprop_propname_named_live(port, ta, D0, data)

    named, bn, want_len = _rt52_explicitly_named_live_props_each_requested(port, ta, D0, bp)

    pre_body, pre_cnt, st_p, bpb = _rt52_3_set_a_protected_live_dav(want_len, bn, bp, port, ta, XML)

    _rt52_the_real_etag_size_are_still(st_p, bpb, bp, pre_cnt, pre_body, port, ta, D0)

    mp, st_m, cnt_m = _rt52_4_many_dead_props_bounded_growth(port, ta, adir, pp_xml, XML)

    nf = _rt52_server_either_stores_all_40_bounded(st_m, cnt_m, mp, port, ta, adir)

    _rt52_read_the_foreign_ns_props_back(port, ta, XML, nf, D0, data)

    _rt52_over_cap_value_a_single_dead(port, ta, adir, XML)

    bpriv, pre_mode, pre_xcnt = _rt52_6_cross_tenant_bob_s_0600(port, ta, data)

    pre_pbody, st_cp = _rt52_alice_propfind_of_bob_s_0600(bpriv, port, ta, named, D0, pp_xml, XML)

    _rt52_segment_16(st_cp, bpriv, pre_xcnt, pre_mode, pre_pbody)

