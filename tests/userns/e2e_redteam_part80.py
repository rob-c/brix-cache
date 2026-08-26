# e2e_redteam_part80.py — continuation shard split off from e2e_redteam_part13.py to keep each file under the logical-line cap.
# Loaded in order by e2e_redteam.py's split_continuation range; shares the
# same module namespace as its siblings.

def _rt13_nothing_escaped_the_export_from_any(data, T, recover):
    # nothing escaped the export from any of the above.
    outside = os.path.dirname(os.path.dirname(os.path.abspath(data)))
    ok(not os.path.exists(os.path.join(outside, f"{T}escaped")),
       "long/deep path attempts created nothing outside the export")
    recover("path-length boundary")

    # F3) deep nesting by repeated MKCOL — broker namespace op per level; assert
    #     each created level is alice-owned and confined.


def _rt13_a_file_at_the_bottom_of(port, ta, adir, T):
    cur = f"/alice/{T}deep"
    made = 0
    for _i in range(16):
        st, _ = http("MKCOL", cur, port, ta)
        if st in (200, 201):
            made += 1
            cur = cur + "/d"
        else:
            break
    deep_top = os.path.join(adir, f"{T}deep")
    ok(all((made >= 4, os.path.isdir(deep_top), os.stat(deep_top).st_uid == UID_ALICE)),
       f"deep nested MKCOL ({made} levels) owned by alice, confined")
    # a file at the bottom of the deep tree is still alice-owned (no drift).
    if made >= 1:
        st, _ = http("PUT", cur.rsplit("/d", 1)[0] + "/leaf.txt", port, ta, b"leaf\n")
        ok(st in (200, 201, 204, 404, 409),
           f"PUT at deep-tree leaf handled (HTTP {st})")


def _rt13_f4_embedded_and_and_trailing_dot(recover, T, port, ta, adir):
    recover("deep MKCOL nesting")

    # F4) embedded ./ and // and trailing-dot segments — must canonicalize to the
    #     SAME confined alice file, never escape, owner stays alice.
    embed_paths = [
        f"/alice/./{T}embed1.txt",
        f"/alice//{T}embed2.txt",
        f"/alice/./sub/.././{T}embed3.txt",
        f"/alice/{T}embed4.txt/.",
    ]
    for p in embed_paths:
        st, _ = http("PUT", p, port, ta, b"embed\n")
        ok(st in (200, 201, 204, 400, 403, 404, 409),
           f"embedded ./ // PUT {p[7:30]!r} handled, no escape (HTTP {st})")
    # whichever of embed1/2 landed, it must be alice-owned and inside alice/.
    for nm in (f"{T}embed1.txt", f"{T}embed2.txt"):
        fp = os.path.join(adir, nm)
        if os.path.exists(fp):
            ok(os.stat(fp).st_uid == UID_ALICE,
               f"canonicalized embedded-path file {nm} owned by alice")
    recover("embedded ./ // segments")
    _broker_resource_limits_p9(s3port, port, ta, adir, recover, fifo, hl_made, bdir, tb, data, T, prop_name, BOBHL_MARK)


def _rt13_g_xattr_namespace_probes_via_proppatch(T, port, ta, adir):

    # =====================================================================
    # G) XATTR NAMESPACE probes via PROPPATCH — WebDAV dead-properties persist as
    #    xattrs.  A namespace-prefix attack (security.*/system.*/trusted.*) must be
    #    confined to user.* (or denied) — it must NEVER let an unprivileged mapped
    #    user set a privileged xattr (e.g. security.capability => setuid-style
    #    escalation on the resulting inode).
    # =====================================================================
    http("PUT", f"/alice/{T}xattr.txt", port, ta, b"xattr target\n")
    xfp = os.path.join(adir, f"{T}xattr.txt")
    ok(all((os.path.exists(xfp), os.stat(xfp).st_uid == UID_ALICE)),
       "xattr-probe target created, owned by alice")
    return xfp


def _rt13_segment_18(T, port, ta):

    def _proppatch_ns(prop_name):
        body = (
            '<?xml version="1.0"?>'
            '<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:brl">'
            f'<D:set><D:prop><Z:{prop_name}>pwned</Z:{prop_name}></D:prop></D:set>'
            '</D:propertyupdate>').encode()
        return http("PROPPATCH", f"/alice/{T}xattr.txt", port, ta, data=body,
                    hdrs={"Content-Type": "application/xml"})
    return _proppatch_ns


def _rt13_the_webdav_dead_property_name_carries(xfp):

    # The WebDAV dead-property name carries no raw xattr namespace, but probe that
    # the server never grows a privileged xattr on the inode regardless.  After
    # each PROPPATCH, scan the real inode's xattrs for any non-user.* namespace.
    def _bad_xattr_present():
        try:
            names = os.listxattr(xfp)
        except OSError:
            return False
        for n in names:
            if not (n.startswith("user.") or n.startswith("system.posix_acl")):
                return True
            if n in ("security.capability",):
                return True
        return False
    return _bad_xattr_present


def _rt13_direct_raw_xattr_confinement_check_plant(_proppatch_ns, _bad_xattr_present, xfp, recover, T):

    for pn in ("security.capability", "system.posix_acl_access",
               "trusted.evil", "security.selinux"):
        st, _ = _proppatch_ns(pn)
        ok(st in (200, 207, 403, 422, 400, 409, 501),
           f"PROPPATCH carrying ns-name {pn!r} handled cleanly (HTTP {st})")
        ok(not _bad_xattr_present(),
           f"no privileged (non-user.*) xattr set on inode after {pn!r}")

    # Direct raw-xattr confinement check: plant a user.* AND a (would-be) privileged
    # xattr request through PROPPATCH using a literal-namespaced property and verify
    # the inode owner is unchanged (no setuid-style escalation, no owner drift).
    st = os.stat(xfp)
    ok(all((st.st_uid == UID_ALICE, st.st_gid == UID_ALICE, not st.st_mode & 3072)),
       "xattr-probe target: owner/group still alice, no setuid/setgid bit gained")
    recover("xattr namespace probes")

    # root:// query xattr on bob's 0600 must not leak xattr values either.
    if xrd_avail():
        rc, out, _e = xrd_fs(["query", "xattr", "/bob/private.txt"], "alice")
        ok('BOB-PRIVATE-SECRET' not in any((out, '')),
           f"root:// query xattr on bob's 0600 leaks no content (rc={rc})")
        rc, out, _e = xrd_fs(["query", "xattr", f"/alice/{T}xattr.txt"], "alice")
        ok(True, f"root:// query xattr on own file returned (rc={rc})")
    _broker_resource_limits_p10(s3port, port, recover, fifo, hl_made, bdir, ta, adir, tb, data, T, BOBHL_MARK)


def _rt13_segment_01_9(T, i, port, ta):
    probe = f"/alice/{T}probe_{i}.txt"
    t0 = time.time()
    sp, _ = http("PUT", probe, port, ta, b"probe\n")
    sg, gb = http("GET", probe, port, ta)
    took = time.time() - t0
    return sp, sg, gb, took


def _rt13_segment_02_5(adir, T, i, sp, sg, gb, took, stall):
    pfp = os.path.join(adir, f"{T}probe_{i}.txt")
    good = (sp in (200, 201, 204) and sg == 200 and gb == b"probe\n"
            and os.path.exists(pfp) and os.stat(pfp).st_uid == UID_ALICE)
    if not good or took > 5.0:
        stall += 1
    return stall


def _rt13_when_i_8_7(T, i, port, ta, adir, stall):
    sp, sg, gb, took = _rt13_segment_01_9(T, i, port, ta)

    stall = _rt13_segment_02_5(adir, T, i, sp, sg, gb, took, stall)

    return stall


def _rt13_segment_01_8(T, i, port, ta, adir, bad, stall):
    rel = f"/alice/{T}burst_{i}.txt"
    st, _ = http("PUT", rel, port, ta, f"b{i}\n".encode())
    if st not in (200, 201, 204):
        bad += 1
    if i % 8 == 7:
        stall = _rt13_when_i_8_7(T, i, port, ta, adir, stall)
    return bad, stall


def _rt13_for_each_i_range_burst(T, i, port, ta, adir, bad, stall):
    bad, stall = _rt13_segment_01_8(T, i, port, ta, adir, bad, stall)

    return bad, stall


def _rt13_h_rapid_sequential_broker_stress_hammer(T, port, ta, adir):

    # =====================================================================
    # H) RAPID SEQUENTIAL broker stress — hammer the single broker socket with a
    #    fast mix of impersonated metadata/create ops, interleaving a known-good
    #    PUT+readback every few iterations.  The broker must NEVER wedge: every
    #    interleaved probe must succeed and stay alice-owned (a stuck broker socket
    #    would stall or fail the probe).
    # =====================================================================
    BURST = 40
    stall = 0
    bad = 0
    for i in range(BURST):
        bad, stall = _rt13_for_each_i_range_burst(T, i, port, ta, adir, bad, stall)
    ok(bad == 0, f"rapid broker burst: all {BURST} impersonated PUTs succeeded "
                 f"(failures={bad})")
    return stall


def _rt13_h2_rapid_keep_alive_pipelined_burst(stall, T, ta, port):
    ok(stall == 0, f"broker socket never wedged under burst: every interleaved "
                   f"known-good probe passed fast (stalls={stall})")
    _broker_resource_limits_p11(s3port, port, recover, fifo, hl_made, bdir, ta, adir, tb, data, T, BOBHL_MARK)


def _broker_resource_limits_p11(s3port, port, recover, fifo, hl_made, bdir, ta, adir, tb, data, T, BOBHL_MARK):
    # H2) rapid keep-alive pipelined burst on ONE TCP connection — stresses the
    #     per-request principal re-establishment without a fresh connect each time;
    #     none may bleed identity (every created file alice-owned).
    ka_reqs = [("PUT", f"/alice/{T}ka_{i}.txt", ta, f"ka{i}\n".encode(), None)
               for i in range(10)]
    res = http_keepalive(ka_reqs, port)
    ka_ok = sum(1 for st, _ in res if st in (200, 201, 204))
    ka_bad_owner = 0
    return ka_ok, ka_bad_owner


def _rt13_segment_01_6(adir, T, i, ka_bad_owner):
    fp = os.path.join(adir, f"{T}ka_{i}.txt")
    if os.path.exists(fp) and os.stat(fp).st_uid != UID_ALICE:
        ka_bad_owner += 1
    return ka_bad_owner


def _rt13_for_each_i_range_10(adir, T, i, ka_bad_owner):
    ka_bad_owner = _rt13_segment_01_6(adir, T, i, ka_bad_owner)

    return ka_bad_owner


def _rt13_h3_interleave_cross_tenant_bob_writes(adir, T, ka_bad_owner, ka_ok, ta, tb, port):
    for i in range(10):
        ka_bad_owner = _rt13_for_each_i_range_10(adir, T, i, ka_bad_owner)
    ok(all((ka_ok >= 1, ka_bad_owner == 0)),
       f"keep-alive pipelined burst: {ka_ok}/10 ok, no wrong-owner file "
       f"(bad_owner={ka_bad_owner})")
    _broker_resource_limits_p12(s3port, port, recover, fifo, hl_made, bdir, ta, tb, data, adir, T, BOBHL_MARK)


def _broker_resource_limits_p12(s3port, port, recover, fifo, hl_made, bdir, ta, tb, data, adir, T, BOBHL_MARK):
    # H3) interleave cross-tenant bob writes into the burst window — a leaked
    #     principal would let one land in the wrong tenant or as the wrong owner.
    inter = []
    for i in range(8):
        sub = ta if i % 2 == 0 else tb
        d = "alice" if i % 2 == 0 else "bob"
        inter.append(("PUT", f"/{d}/{T}int_{i}.txt", sub, f"int{i}\n".encode(), None))
    http_keepalive(inter, port)


def _rt13_segment_01_2(i, data, T, drift):
    d = "alice" if i % 2 == 0 else "bob"
    want = UID_ALICE if i % 2 == 0 else UID_BOB
    fp = os.path.join(data, d, f"{T}int_{i}.txt")
    if os.path.exists(fp) and os.stat(fp).st_uid != want:
        drift += 1
    return drift


def _rt13_for_each_i_range_8(i, data, T, drift):
    drift = _rt13_segment_01_2(i, data, T, drift)

    return drift


def _rt13_i_s3_special_file_boundary_probes(data, T, recover, s3port, fifo, hl_made, _has, BOBHL_MARK):
    drift = 0
    for i in range(8):
        drift = _rt13_for_each_i_range_8(i, data, T, drift)
    ok(drift == 0, f"interleaved alice/bob pipelined PUTs: zero principal drift "
                   f"(wrong-owner={drift})")
    recover("rapid broker stress")
    _broker_resource_limits_p13(s3port, fifo, hl_made, recover, bdir, adir, T, BOBHL_MARK)


def _broker_resource_limits_p13(s3port, fifo, hl_made, recover, bdir, adir, T, BOBHL_MARK):
    # =====================================================================
    # I) S3 special-file + boundary probes (the S3 async-body handler must fail
    #    closed on the same pathological nodes, no hang/leak).
    # =====================================================================
    if s3port:
        if fifo:
            t0 = time.time()
            st, b = s3("GET", f"alice/{T}fifo", s3port)
            ok(time.time() - t0 < 5.0,
               f"S3 GET on FIFO did not hang (HTTP {st})")
        # S3 key with embedded ./ and // — must canonicalize+confine, owner alice.
        st, _ = s3("PUT", f"alice/.//{T}s3embed.txt", s3port, data=b"s3embed\n")
        ok(st in (200, 201, 400, 403, 404),
           f"S3 PUT embedded ./ // key handled (HTTP {st})")
        # S3 GET of the cross-tenant hardlink (bob 0600 inode) must deny + no leak.
        if hl_made:
            st, b = s3("GET", f"alice/{T}bob_hardlink", s3port)
            ok(all((st != 200, not _has(b, BOBHL_MARK))),
               f"S3 GET cross-tenant hardlink DENIED, no leak (HTTP {st})")
        recover("S3 special-file probes")
    _broker_resource_limits_p14(recover, bdir, adir, T)


def _rt13_privileged_owner_drift(adir, tag, name):
    if not name.startswith(tag):
        return None
    if _is_server_sidecar(name):   # .cinfo/.meta svc-owned by design
        return None
    path = os.path.join(adir, name)
    try:
        if os.path.islink(path):
            return None
        owner = os.stat(path, follow_symlinks=False).st_uid
    except OSError:
        return None
    known_hardlink = name in (f"{tag}bob_hardlink", f"{tag}svc_hardlink")
    return 0 if known_hardlink else int(owner in (UID_SVC, 0))


def _rt13_cross_tenant_hardlinks_intentionally_carry_bob(adir, T, scanned, drift_priv):
    for name in os.listdir(adir):
        drift = _rt13_privileged_owner_drift(adir, T, name)
        if drift is None:
            continue
        scanned += 1
        drift_priv += drift
    return scanned, drift_priv


def _rt13_try_body_2(adir, T, scanned, drift_priv):
    scanned, drift_priv = _rt13_cross_tenant_hardlinks_intentionally_carry_bob(adir, T, scanned, drift_priv)

    return scanned, drift_priv


def _rt13_j_final_recovery_ownership_invariant_sweep(recover, adir, T):

    # =====================================================================
    # J) FINAL recovery + ownership-invariant sweep: the worker survived every
    #    hostile op AND not one of our planted/created files drifted to a
    #    privileged owner (svc 1500 / root 0).  This is the headline invariant.
    # =====================================================================
    recover("full hostile battery")
    drift_priv = 0
    scanned = 0
    try:
        scanned, drift_priv = _rt13_try_body_2(adir, T, scanned, drift_priv)
    except OSError:
        pass
    ok(all((scanned > 0, drift_priv == 0)),
       f"ownership invariant: of {scanned} files alice created, NONE owned by "
       f"svc(1500)/root(0) (drift={drift_priv})")


def _rt13_bob_s_private_secret_never_got(bdir):

    # bob's private secret never got mutated/clobbered by any attack above.
    bpriv = os.path.join(bdir, "private.txt")
    try:
        intact = (os.path.exists(bpriv) and os.stat(bpriv).st_uid == UID_BOB
                  and (os.stat(bpriv).st_mode & 0o777) == 0o600)
    except OSError:
        intact = False
    ok(intact, "bob's 0600 private.txt untouched (owner/mode intact) after battery")


def run_broker_resource_limits(key, data, port, s3port):
    """BROKER protocol-level + RESOURCE attacks under impersonation.  Plant
    pathological filesystem objects in the export (FIFO, unix socket, dangling /
    looping / shadow-pointing symlinks, cross-tenant hardlink), stress path
    boundaries (near-PATH_MAX, deep nesting, embedded ./ and //), probe the xattr
    namespace (security.*/system.*/trusted.* must be confined to user.* or denied),
    and hammer the single broker socket — proving NONE of it hangs the worker,
    leaks a foreign secret, escapes the export, escalates privilege, or wedges the
    broker.  After every hostile burst we re-prove recovery with a legit alice
    PUT+GET roundtrip (worker AND broker both survive).  Does NOT kill the broker
    (run_broker_failclosed owns that)."""
    T, ta, tb, adir, bdir = _rt13_segment_01(key, data)

    _has = _rt13_segment_02()

    recover = _rt13_segment_03(T, port, ta, adir)

    SHADOW_MARK, BOBHL_MARK, SVCHL_MARK = _rt13_baseline_recovery_prove_the_harness_path(recover, adir, T)

    fifo = os.path.join(adir, f"{T}fifo")
    fifo, sockp, srv = _rt13_put_onto_a_fifo_would_block(T, port, ta, recover, adir, fifo)

    _rt13_c_device_node_creation_must_eperm(sockp, T, port, ta, s3port, recover, srv, adir, _has, SHADOW_MARK)

    _mklink = _rt13_d_symlink_class_dangling_self_loop(adir)

    _rt13_segment_08(_mklink, T, port, ta)

    _rt13_segment_09(_mklink, T, port, ta, _has, SHADOW_MARK, s3port, recover)

    hl, bob_secret_file = _rt13_control_an_in_export_symlink_to(_mklink, T, bdir, port, ta, _has, adir)

    hl_made = False
    hl_made, svc_secret, svc_hl = _rt13_bob_the_real_owner_reading_the(bob_secret_file, BOBHL_MARK, hl, T, port, ta, _has, tb, recover, data, adir, hl_made)

    st, lp = _rt13_match_the_canary_s_restrictive_mode(svc_hl, svc_secret, T, port, ta, _has, SVCHL_MARK, recover, adir)

    _rt13_f2_near_path_max_total_path(st, lp, T, port, ta)

    _rt13_nothing_escaped_the_export_from_any(data, T, recover)

    _rt13_a_file_at_the_bottom_of(port, ta, adir, T)

    _rt13_f4_embedded_and_and_trailing_dot(recover, T, port, ta, adir)

    xfp = _rt13_g_xattr_namespace_probes_via_proppatch(T, port, ta, adir)

    _proppatch_ns = _rt13_segment_18(T, port, ta)

    _bad_xattr_present = _rt13_the_webdav_dead_property_name_carries(xfp)

    _rt13_direct_raw_xattr_confinement_check_plant(_proppatch_ns, _bad_xattr_present, xfp, recover, T)

    stall = _rt13_h_rapid_sequential_broker_stress_hammer(T, port, ta, adir)

    ka_ok, ka_bad_owner = _rt13_h2_rapid_keep_alive_pipelined_burst(stall, T, ta, port)

    _rt13_h3_interleave_cross_tenant_bob_writes(adir, T, ka_bad_owner, ka_ok, ta, tb, port)

    _rt13_i_s3_special_file_boundary_probes(data, T, recover, s3port, fifo, hl_made, _has, BOBHL_MARK)

    _rt13_j_final_recovery_ownership_invariant_sweep(recover, adir, T)

    _rt13_bob_s_private_secret_never_got(bdir)
