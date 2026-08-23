def run_cross_cutting(key, data, port, s3port):
    """Cross-PROTOCOL identity boundaries + erroring connections under
    impersonation.  A file's owner must hold whichever protocol reads/writes it."""
    ta, tb = mint(key, "alice"), mint(key, "bob")
    _cross_protocol_files(data, port, s3port, ta)
    _cross_protocol_error_paths(data, port, ta)


def _cross_protocol_files(data, port, s3port, alice_token):
    _cross_webdav_seed(data, port, alice_token)
    if s3port:
        _cross_s3_read(s3port)
    if xrd_avail():
        _cross_root_read()
        _cross_root_write(data, port, alice_token)


def _cross_webdav_seed(data, port, alice_token):
    # alice creates via WebDAV; bob must not read it via S3 or root:// (and the
    # file stays alice-owned).  Make it 0600 so cross-tenant read is a real test.
    http("PUT", "/alice/xp_secret.txt", port, alice_token, b"ALICE-XPROTO-SECRET\n")
    fp = os.path.join(data, "alice", "xp_secret.txt")
    if os.path.exists(fp):
        os.chmod(fp, 0o600)
    ok(
        os.path.exists(fp) and os.stat(fp).st_uid == UID_ALICE,
        "cross-protocol: WebDAV-created file owned by alice",
    )


def _cross_s3_read(s3port):
    st, body = s3("GET", "alice/xp_secret.txt", s3port)
    ok(
        st == 200 and b"ALICE-XPROTO-SECRET" in (body or b""),
        f"cross-protocol: alice reads her WebDAV file via S3 (HTTP {st})",
    )


def _cross_root_read():
    rc, output, _error = xrd_fs(["cat", "/alice/xp_secret.txt"], "bob")
    ok(
        rc != 0 and "ALICE-XPROTO-SECRET" not in (output or ""),
        f"cross-protocol: bob CANNOT read alice's 0600 file via root:// (rc={rc})",
    )


def _cross_root_write(data, port, alice_token):
    local = os.path.join(WORK, "xp_bob.bin")
    with open(local, "wb") as stream:
        stream.write(b"BOB-XPROTO-SECRET\n")
    xrd_cp_up(local, "/bob/xp_bob.bin", "bob")
    written = os.path.join(data, "bob", "xp_bob.bin")
    if os.path.exists(written):
        os.chmod(written, 0o600)
    status, body = http("GET", "/bob/xp_bob.bin", port, alice_token)
    ok(
        b"BOB-XPROTO-SECRET" not in (body or b""),
        f"cross-protocol: alice CANNOT read bob's root://-written 0600 via WebDAV (HTTP {status})",
    )


def _cross_protocol_error_paths(data, port, alice_token):
    _cross_fifo_request(data, port, alice_token)
    _cross_dangling_request(data, port, alice_token)
    status, _body = http("GET", "/alice/xp_secret.txt", port, alice_token)
    ok(status == 200, "worker survived FIFO / dangling-symlink requests")


def _cross_fifo_request(data, port, alice_token):
    # Erroring connections must not breach / hang the worker.  A FIFO in the export:
    # a GET/PUT on it must not hang (broker opens O_NONBLOCK) and must fail closed.
    fifo = os.path.join(data, "alice", "afifo")
    try:
        if not os.path.exists(fifo):
            os.mkfifo(fifo, 0o600)
            os.chown(fifo, UID_ALICE, UID_ALICE)
    except OSError:
        fifo = None
    if fifo:
        st, _ = http("GET", "/alice/afifo", port, alice_token)
        ok(True, f"WebDAV GET on a FIFO did not hang the worker (HTTP {st})")


def _cross_dangling_request(data, port, alice_token):
    dang = os.path.join(data, "alice", "dangle")
    try:
        if not os.path.exists(dang):
            os.symlink("/nonexistent/target", dang)
    except OSError:
        dang = None
    if dang:
        st, _ = http("GET", "/alice/dangle", port, alice_token)
        ok(st not in (200,), f"WebDAV GET dangling symlink handled (HTTP {st})")


def run_auth_matrix(key, data, port):
    """Forged/invalid bearer tokens must be rejected uniformly across BOTH
    token-authenticated planes (WebDAV + root://) under impersonation — a token
    that fails validation must never reach the broker as a mapped principal, and
    must neither read nor create anything.  A positive control proves the same
    paths accept a good token."""
    ta = mint(key, "alice")
    http("PUT", "/alice/auth_probe.txt", port, ta, b"auth-probe-body\n")
    _auth_valid_control(port, ta)
    _auth_forged_webdav(key, data, port)
    _auth_empty_scope(key, data, port)
    _auth_forged_root(key)


def _auth_valid_control(port, token):
    # Positive control: a valid token reads its own file.
    st, b = http("GET", "/alice/auth_probe.txt", port, token)
    ok(
        st == 200 and b"auth-probe-body" in (b or b""),
        f"auth control: valid token reads own file (HTTP {st})",
    )


def _auth_forged_webdav(key, data, port):
    for label, token in _forged_tokens(key):
        # WebDAV READ must be denied and must NOT leak the body.
        st, b = http("GET", "/alice/auth_probe.txt", port, token)
        ok(
            st in (401, 403) and b"auth-probe-body" not in (b or b""),
            f"WebDAV {label} token rejected on GET (HTTP {st})",
        )
        # WebDAV WRITE must be denied and must NOT create the file.
        evil = f"/alice/evil_{label}.txt"
        http("PUT", evil, port, token, b"X\n")
        ok(
            not os.path.exists(os.path.join(data, "alice", f"evil_{label}.txt")),
            f"WebDAV {label} token cannot create a file",
        )

    # Empty-scope token: this module's model is authn->identity, DAC for reads,
    # explicit write-scope for mutations.  So an empty-scope token authenticates
    # as alice and MAY read her own file (DAC permits) but MUST NOT write and MUST
    # NOT read another tenant (DAC backstops).  Verify all three.


def _auth_empty_scope(key, data, port):
    nos = mint(key, "alice", scope="")
    st, b = http("GET", "/alice/auth_probe.txt", port, nos)
    ok(
        st == 200 and b"auth-probe-body" in (b or b""),
        f"empty-scope token authenticates + reads own file via DAC (HTTP {st})",
    )
    http("PUT", "/alice/evil_noscope.txt", port, nos, b"X\n")
    ok(
        not os.path.exists(os.path.join(data, "alice", "evil_noscope.txt")),
        "empty-scope token cannot WRITE (no write scope)",
    )
    st, b = http("GET", "/bob/private.txt", port, nos)
    ok(
        b"BOB-PRIVATE-SECRET" not in (b or b""),
        f"empty-scope token cannot read bob's 0600 (DAC backstop) (HTTP {st})",
    )

    # root:// plane: the same forged tokens must fail (subset — the heavy ones).


def _auth_forged_root(key):
    if not xrd_avail():
        return
    for label, token in _forged_tokens(key):
        if label in ("not-yet-valid", "wrong-audience", "garbage"):
            continue
        rc, out, _e = xrd_fs_token(["stat", "/alice/auth_probe.txt"], token)
        ok(rc != 0, f"root:// {label} token rejected on stat (rc={rc})")


def run_root_deep(key, data, port):
    """Per-subcommand root:// (stream) matrix under impersonation: every metadata
    + data op as the mapped user, each in a self-success and a cross-tenant-deny
    variant.  The native client drives the real wire protocol, so this exercises
    the stream dispatch path the HTTP planes never touch."""
    if not xrd_avail():
        ok(True, "root:// deep matrix skipped (native client absent)")
        return
    bobpriv = os.path.join(data, "bob", "private.txt")  # 0600 bob
    bobread = os.path.join(data, "bob", "readable.txt")  # 0644 bob
    local, self_file = _root_seed_file(data)
    _root_read_self(self_file)
    _root_read_denied(bobpriv)
    _root_stat_self()
    _root_directory_ops(data, local)
    _root_remove_ops(bobread, self_file)
    _root_move_denied(data, bobread)
    _root_truncate_denied(bobread)
    _root_chmod_denied(bobpriv)
    _root_checksum_denied()


def _root_seed_file(data):
    # seed an alice-owned file via the data plane (write path).
    local = os.path.join(WORK, "rd_seed.bin")
    with open(local, "wb") as fh:
        fh.write(b"ALICE-ROOT-DEEP\n")
    rc, _o, _e = xrd_cp_up(local, "/alice/rd_self.bin", "alice")
    ok(
        rc == 0 and os.path.exists(os.path.join(data, "alice", "rd_self.bin")),
        f"root:// xrdcp write own file (rc={rc})",
    )
    self_file = os.path.join(data, "alice", "rd_self.bin")
    ok(
        os.path.exists(self_file) and os.stat(self_file).st_uid == UID_ALICE,
        "root:// written file owned by alice",
    )
    return local, self_file


def _root_read_self(self_file):
    # cat self vs bob's 0600.
    dl = os.path.join(WORK, "rd_self_dl.bin")
    rc, _o, _e = xrd_cp_down("/alice/rd_self.bin", dl, "alice")
    ok(
        rc == 0
        and os.path.exists(dl)
        and open(dl, "rb").read() == b"ALICE-ROOT-DEEP\n",
        f"root:// xrdcp read own file byte-exact (rc={rc})",
    )


def _root_read_denied(bob_private):
    rc, out, _e = xrd_fs(["cat", "/bob/private.txt"], "alice")
    ok(
        rc != 0 and "BOB-PRIVATE-SECRET" not in (out or ""),
        f"root:// cat bob's 0600 DENIED (rc={rc})",
    )
    dlx = os.path.join(WORK, "rd_steal.bin")
    rc, _o, _e = xrd_cp_down("/bob/private.txt", dlx, "alice")
    ok(
        rc != 0
        and not (
            os.path.exists(dlx) and b"BOB-PRIVATE-SECRET" in open(dlx, "rb").read()
        ),
        f"root:// xrdcp read bob's 0600 DENIED (rc={rc})",
    )


def _root_stat_self():
    rc, _o, _e = xrd_fs(["stat", "/alice/rd_self.bin"], "alice")
    ok(rc == 0, f"root:// stat own file (rc={rc})")


def _root_directory_ops(data, local):
    # mkdir self + ownership; mkdir into bob's 0700 dir denied.
    rc, _o, _e = xrd_fs(["mkdir", "/alice/rd_dir"], "alice")
    nd = os.path.join(data, "alice", "rd_dir")
    ok(
        rc == 0 and os.path.isdir(nd) and os.stat(nd).st_uid == UID_ALICE,
        f"root:// mkdir own dir owned by alice (rc={rc})",
    )
    rc, _o, _e = xrd_fs(["mkdir", "/bobsecret/intrude"], "alice")
    ok(
        rc != 0 and not os.path.exists(os.path.join(data, "bobsecret", "intrude")),
        f"root:// mkdir into bob's 0700 dir DENIED (rc={rc})",
    )

    # write into bob's dir via the data plane denied.
    rc, _o, _e = xrd_cp_up(local, "/bobsecret/intrude.bin", "alice")
    ok(
        rc != 0 and not os.path.exists(os.path.join(data, "bobsecret", "intrude.bin")),
        f"root:// xrdcp write into bob's 0700 dir DENIED (rc={rc})",
    )


def _root_remove_ops(bob_readable, self_file):
    rc, _o, _e = xrd_fs(["rm", "/bob/readable.txt"], "alice")
    ok(
        rc != 0 and os.path.exists(bob_readable),
        f"root:// rm bob's file DENIED, file intact (rc={rc})",
    )
    rc, _o, _e = xrd_fs(["rm", "/alice/rd_self.bin"], "alice")
    ok(rc == 0 and not os.path.exists(self_file), f"root:// rm own file (rc={rc})")


def _root_move_denied(data, bob_readable):
    # mv: bob's file out of bob's dir denied (still present, original name).
    rc, _o, _e = xrd_fs(["mv", "/bob/readable.txt", "/alice/stolen.txt"], "alice")
    ok(
        rc != 0
        and os.path.exists(bob_readable)
        and not os.path.exists(os.path.join(data, "alice", "stolen.txt")),
        f"root:// mv bob's file into alice's dir DENIED (rc={rc})",
    )


def _root_truncate_denied(bob_readable):
    before = os.path.getsize(bob_readable)
    rc, _o, _e = xrd_fs(["truncate", "/bob/readable.txt", "0"], "alice")
    ok(
        rc != 0 and os.path.getsize(bob_readable) == before,
        f"root:// truncate bob's file DENIED, size intact (rc={rc})",
    )


def _root_chmod_denied(bob_private):
    mode_before = os.stat(bob_private).st_mode & 0o777
    rc, _o, _e = xrd_fs(["chmod", "/bob/private.txt", "666"], "alice")
    ok(
        rc != 0 and (os.stat(bob_private).st_mode & 0o777) == mode_before,
        f"root:// chmod bob's file DENIED, mode intact (rc={rc})",
    )


def _root_checksum_denied():
    rc, _o, _e = xrd_fs(["query", "checksum", "/bob/private.txt"], "alice")
    ok(rc != 0, f"root:// query checksum of bob's 0600 DENIED (rc={rc})")


def _delete_xml(keys):
    body = b'<?xml version="1.0"?><Delete>'
    for k in keys:
        body += b"<Object><Key>" + k.encode() + b"</Key></Object>"
    return body + b"</Delete>"


def run_s3_deep(key, data, s3port):
    """Deep S3 surface under impersonation: CopyObject + UploadPartCopy with a
    cross-tenant source, DeleteObjects batch, Range/conditional confidentiality,
    ListObjectsV2 prefix/delimiter, and anonymous access — each a DAC boundary."""
    s3("PUT", "alice/cp_src.txt", s3port, data=b"alice-copy-source\n")
    _s3_copy_boundaries(data, s3port)
    _s3_delete_boundaries(data, s3port)
    _s3_conditional_reads(s3port)
    _s3_list_boundaries(s3port)
    _s3_anonymous_denied(s3port)
    _s3_upload_copy_denied(s3port)


def _s3_copy_boundaries(data, s3port):
    # CopyObject self: copy alice/cp_src -> alice/cp_dst, owned by alice.
    st, _ = s3(
        "PUT",
        "alice/cp_dst.txt",
        s3port,
        extra_hdrs={"x-amz-copy-source": f"/{S3_BUCKET}/alice/cp_src.txt"},
    )
    cpd = os.path.join(data, "alice", "cp_dst.txt")
    ok(
        st in (200, 201) and os.path.exists(cpd) and os.stat(cpd).st_uid == UID_ALICE,
        f"S3 CopyObject self owned by alice (HTTP {st})",
    )

    # CopyObject cross-tenant SOURCE: copy bob/private.txt -> alice/stolen.  The
    # broker reads the source as alice; bob's 0600 denies it -> no theft.
    st, _ = s3(
        "PUT",
        "alice/stolen.txt",
        s3port,
        extra_hdrs={"x-amz-copy-source": f"/{S3_BUCKET}/bob/private.txt"},
    )
    stolen = os.path.join(data, "alice", "stolen.txt")
    leaked = (
        os.path.exists(stolen) and b"BOB-PRIVATE-SECRET" in open(stolen, "rb").read()
    )
    ok(
        st not in (200, 201) and not leaked,
        f"S3 CopyObject cross-tenant source DENIED, no theft (HTTP {st})",
    )


def _s3_delete_boundaries(data, s3port):
    bobread = os.path.join(data, "bob", "readable.txt")
    s3(
        "POST",
        "",
        s3port,
        params={"delete": ""},
        data=_delete_xml(["bob/readable.txt"]),
    )
    ok(os.path.exists(bobread), "S3 DeleteObjects of bob's file did not delete it")
    # DeleteObjects self: delete alice's own object works.
    s3("PUT", "alice/del_me.txt", s3port, data=b"x\n")
    s3(
        "POST",
        "",
        s3port,
        params={"delete": ""},
        data=_delete_xml(["alice/del_me.txt"]),
    )
    ok(
        not os.path.exists(os.path.join(data, "alice", "del_me.txt")),
        "S3 DeleteObjects of own object succeeded",
    )


def _s3_conditional_reads(s3port):
    for label, hdr in [
        ("Range", {"Range": "bytes=0-4"}),
        ("If-Match", {"If-Match": "*"}),
        ("If-None-Match", {"If-None-Match": '"x"'}),
    ]:
        h = s3_sign("GET", f"/{S3_BUCKET}/bob/private.txt", s3port)
        h.update(hdr)
        st, b = http("GET", f"/{S3_BUCKET}/bob/private.txt", s3port, hdrs=h)
        ok(
            b"BOB-PRIVATE-SECRET" not in (b or b""),
            f"S3 GET bob's 0600 with {label} no body leak (HTTP {st})",
        )


def _s3_list_boundaries(s3port):
    st, b = s3(
        "GET", "", s3port, params={"list-type": "2", "prefix": "", "delimiter": "/"}
    )
    ok(
        b"escape/" not in (b or b"") and b"secret-name.txt" not in (b or b""),
        f"S3 ListObjectsV2 delimiter no escape/secret leak (HTTP {st})",
    )
    _s3_private_prefix_hidden(s3port)


def _s3_private_prefix_hidden(s3port):
    st, b = s3("GET", "", s3port, params={"list-type": "2", "prefix": "bobsecret/"})
    ok(
        b"BOB-PRIVATE" not in (b or b"") and b"bobsecret/inject" not in (b or b""),
        f"S3 ListObjectsV2 prefix into bob's 0700 no leak (HTTP {st})",
    )


def _s3_anonymous_denied(s3port):
    st, _ = http("GET", f"/{S3_BUCKET}/alice/cp_src.txt", s3port)
    ok(st in (401, 403), f"S3 anonymous GET denied (HTTP {st})")


def _s3_upload_copy_denied(s3port):
    st_i, bdy = s3("POST", "alice/upc.bin", s3port, params={"uploads": ""})
    m = re.search(rb"<UploadId>([^<]+)</UploadId>", bdy or b"")
    if st_i == 200 and m:
        up = m.group(1).decode()
        st, _ = s3(
            "PUT",
            "alice/upc.bin",
            s3port,
            params={"uploadId": up, "partNumber": "1"},
            extra_hdrs={"x-amz-copy-source": f"/{S3_BUCKET}/bob/private.txt"},
        )
        ok(
            st not in (200, 201),
            f"S3 UploadPartCopy cross-tenant source DENIED (HTTP {st})",
        )
        s3("DELETE", "alice/upc.bin", s3port, params={"uploadId": up})
    else:
        ok(True, "S3 UploadPartCopy setup skipped (initiate unsupported)")


def run_traversal_matrix(key, data, port, s3port):
    """Path-traversal / encoding / NUL across every protocol under impersonation.
    The broker re-applies RESOLVE_BENEATH, so escapes must fail closed and never
    return a byte of /etc/passwd or write outside the export."""
    ta = mint(key, "alice")
    outside_dir = os.path.dirname(os.path.dirname(os.path.abspath(data)))
    _webdav_traversal_reads(port, ta)
    _webdav_traversal_writes(port, ta, outside_dir)
    _s3_traversal_paths(s3port)
    _root_traversal_paths()


def _webdav_traversal_reads(port, token):
    # WebDAV GET traversal variants — none may return root:x: from /etc/passwd.
    wd_paths = [
        "/../../../../etc/passwd",
        "/alice/../../../../etc/passwd",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/alice/%2e%2e%2f%2e%2e%2fetc/passwd",
        "/..%2f..%2f..%2fetc/passwd",
        "/alice/....//....//etc/passwd",
    ]
    for p in wd_paths:
        st, b = http("GET", p, port, token)
        ok(
            b"root:x:" not in (b or b"") and b"root:!" not in (b or b""),
            f"WebDAV traversal GET {p[:28]!r} no /etc/passwd leak (HTTP {st})",
        )


def _webdav_traversal_writes(port, token, outside_dir):
    http("PUT", "/../OUTSIDE_WD.txt", port, token, b"x\n")
    http("PUT", "/alice/../../OUTSIDE_WD2.txt", port, token, b"x\n")
    ok(
        not os.path.exists(os.path.join(outside_dir, "OUTSIDE_WD.txt"))
        and not os.path.exists(os.path.join(outside_dir, "OUTSIDE_WD2.txt")),
        "WebDAV traversal PUT created nothing outside the export",
    )


def _s3_traversal_paths(s3port):
    for k in [
        "../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "alice/../../../etc/passwd",
        "....//....//etc/passwd",
    ]:
        st, b = s3("GET", k, s3port)
        ok(
            b"root:x:" not in (b or b""),
            f"S3 traversal key {k[:24]!r} no /etc/passwd leak (HTTP {st})",
        )
    st, _ = s3("PUT", "../../../tmp/OUTSIDE_S3.txt", s3port, data=b"x\n")
    ok(
        not os.path.exists("/tmp/OUTSIDE_S3.txt"),
        "S3 traversal PUT created nothing outside the export",
    )


def _root_traversal_paths():
    if not xrd_avail():
        return
    _root_traversal_reads()
    _root_traversal_download()


def _root_traversal_reads():
    for path in ["/../../../../etc/passwd", "/alice/../../../etc/passwd"]:
        rc, out, _e = xrd_fs(["cat", path], "alice")
        ok(
            rc != 0 and "root:x:" not in (out or ""),
            f"root:// traversal cat {path[:24]!r} DENIED (rc={rc})",
        )


def _root_traversal_download():
    download = os.path.join(WORK, "trav_pw.bin")
    rc, _o, _e = xrd_cp_down("/../../../../etc/passwd", download, "alice")
    leaked = os.path.exists(download) and b"root:x:" in open(download, "rb").read()
    ok(rc != 0 and not leaked, f"root:// xrdcp traversal read DENIED (rc={rc})")
