def _path_uid(path):
    if not os.path.exists(path):
        return -1
    return os.stat(path).st_uid


def _s3_put_owned(data, port, key):
    status, _ = s3("PUT", key, port, data=b"s3 object body\n")
    uid = _path_uid(os.path.join(data, key))
    ok(status in (200, 201) and uid == UID_ALICE,
       f"S3 PUT object owned by mapped user alice (HTTP {status}, uid={uid})")


def _s3_get_owned(port, key):
    status, body = s3("GET", key, port)
    ok(status == 200 and body == b"s3 object body\n",
       f"S3 GET returns alice's object (HTTP {status})")


def _multipart_completion(upload_id, etag):
    return (f"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
            f"<ETag>{etag}</ETag></Part></CompleteMultipartUpload>").encode()


def _upload_id(init_status, body):
    match = re.search(rb"<UploadId>([^<]+)</UploadId>", body or b"")
    if init_status != 200 or match is None:
        return None
    return match.group(1).decode()


def _part_etag(body):
    match = re.search(rb'ETag>\\?"?([^"<\\]+)', body or b"")
    if match is None:
        return "etag"
    return match.group(1).decode()


def _complete_multipart_owned(data, port, key, upload_id, etag, statuses):
    complete_status, _ = s3(
        "POST", key, port, params={"uploadId": upload_id},
        data=_multipart_completion(upload_id, etag),
    )
    uid = _path_uid(os.path.join(data, key))
    init_status, part_status = statuses
    ok(complete_status in (200, 201) and uid == UID_ALICE,
       "S3 multipart-complete object owned by alice "
       f"(init {init_status}, part {part_status}, complete {complete_status}, uid={uid})")


def _s3_multipart_owned(data, port):
    key = "alice/s3mpu.bin"
    init_status, body = s3("POST", key, port, params={"uploads": ""})
    upload_id = _upload_id(init_status, body)
    if upload_id is None:
        ok(False, f"S3 multipart initiate failed (HTTP {init_status})")
        return
    part_status, part_body = s3(
        "PUT", key, port,
        params={"uploadId": upload_id, "partNumber": "1"},
        data=b"Z" * 4096,
    )
    _complete_multipart_owned(
        data, port, key, upload_id, _part_etag(part_body),
        (init_status, part_status),
    )


def _s3_delete_owned(data, port, key):
    status, _ = s3("DELETE", key, port)
    ok(status in (200, 204) and not os.path.exists(os.path.join(data, key)),
       f"S3 DELETE removes alice's object (HTTP {status})")


def run_s3(data, port):
    """Exercise mapped-user ownership through the S3 data path."""
    key = "alice/s3put.txt"
    _s3_put_owned(data, port, key)
    _s3_get_owned(port, key)
    _s3_multipart_owned(data, port)
    _s3_delete_owned(data, port, key)


def _has(body, needle):
    return needle in (body or b"")


def _webdav_cross_tenant_read(port, token):
    status, body = http("GET", "/bob/private.txt", port, token)
    denied = status in (403, 404, 401) and not _has(body, b"BOB-PRIVATE-SECRET")
    ok(denied, f"WebDAV GET of bob's 0600 file DENIED (HTTP {status})")
    status, body = http("GET", "/bob/readable.txt", port, token)
    allowed = status == 200 and _has(body, b"bob-world-readable")
    ok(allowed, f"control: WebDAV GET of bob's 0644 file ALLOWED (HTTP {status})")


def _s3_cross_tenant_read(port):
    status, body = s3("GET", "bob/private.txt", port)
    denied = status in (403, 404) and not _has(body, b"BOB-PRIVATE-SECRET")
    ok(denied, f"S3 GET of bob's 0600 object DENIED (HTTP {status})")
    status, body = s3("GET", "bob/readable.txt", port)
    allowed = status == 200 and _has(body, b"bob-world-readable")
    ok(allowed, f"control: S3 GET of bob's 0644 object ALLOWED (HTTP {status})")


def _s3_list_confidentiality(port):
    status, body = s3("GET", "", port, params={"list-type": "2"})
    leaked = any(_has(body, needle) for needle in (b"secret-name.txt", b"escape/", b"passwd"))
    passed = status == 200 and _has(body, b"alice/") and not leaked
    ok(passed, "S3 ListObjects: no svc-only/symlink-escape leak + lists own keys "
       f"(HTTP {status}, leaked={leaked})")


def run_cross_tenant_read(key, data, port, s3port):
    """Verify private data stays hidden while public controls remain readable."""
    _webdav_cross_tenant_read(port, mint(key, "alice"))
    if s3port:
        _s3_cross_tenant_read(s3port)
        _s3_list_confidentiality(s3port)


def _bob_file_unchanged(path):
    if not os.path.exists(path) or os.stat(path).st_uid != UID_BOB:
        return False
    with open(path, "rb") as handle:
        return handle.read() == b"bob-world-readable\n"


def _deny_webdav_overwrite(port, token, readable):
    status, _ = http("PUT", "/bob/readable.txt", port, token, b"HACKED\n")
    ok(status not in (200, 201, 204) and _bob_file_unchanged(readable),
       f"WebDAV PUT over bob's file DENIED + unchanged (HTTP {status})")


def _deny_webdav_create(data, port, token):
    status, _ = http("PUT", "/bob/alice_was_here.txt", port, token, b"x\n")
    path = os.path.join(data, "bob", "alice_was_here.txt")
    ok(status not in (200, 201, 204) and not os.path.exists(path),
       f"WebDAV PUT new file into bob's dir DENIED (HTTP {status})")


def _deny_webdav_delete(port, token, readable):
    status, _ = http("DELETE", "/bob/readable.txt", port, token)
    ok(status not in (200, 204) and os.path.exists(readable),
       f"WebDAV DELETE of bob's file DENIED (HTTP {status})")


def _deny_webdav_move(data, port, token, readable):
    status, _ = http("MOVE", "/bob/readable.txt", port, token,
                 hdrs={"Destination": f"http://{HOST}:{port}/alice/stolen.txt"})
    stolen = os.path.join(data, "alice", "stolen.txt")
    denied = status not in (200, 201, 204) and os.path.exists(readable)
    ok(denied and not os.path.exists(stolen),
       f"WebDAV MOVE of bob's file DENIED (HTTP {status})")


def _deny_webdav_copy(data, port, token):
    status, _ = http("COPY", "/bob/private.txt", port, token,
                 hdrs={"Destination": f"http://{HOST}:{port}/alice/copied.txt"})
    copied = os.path.join(data, "alice", "copied.txt")
    ok(status not in (200, 201, 204) and not os.path.exists(copied),
       f"WebDAV COPY of bob's 0600 file DENIED (HTTP {status})")


def _deny_webdav_property(port, token):
    update = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:x">'
          b'<D:set><D:prop><Z:pwn>XT-PWNED</Z:pwn></D:prop></D:set>'
          b'</D:propertyupdate>')
    http("PROPPATCH", "/bob/readable.txt", port, token, data=update,
         hdrs={"Content-Type": "application/xml"})
    _, body = http("PROPFIND", "/bob/readable.txt", port, token,
                   data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                        b'<D:allprop/></D:propfind>',
                   hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(not _has(body, b"XT-PWNED"),
       "WebDAV PROPPATCH on bob's file did NOT persist a dead-property")


def _deny_s3_overwrite(port, readable):
    status, _ = s3("PUT", "bob/readable.txt", port, data=b"S3HACK\n")
    ok(status not in (200, 201) and _bob_file_unchanged(readable),
       f"S3 PUT over bob's object DENIED + unchanged (HTTP {status})")


def _deny_s3_delete(port, readable):
    status, _ = s3("DELETE", "bob/readable.txt", port)
    ok(status not in (200, 204) and os.path.exists(readable),
       f"S3 DELETE of bob's object DENIED (HTTP {status})")


def _deny_s3_copy(data, port):
    status, _ = s3("PUT", "alice/from_bob.bin", port,
                   extra_hdrs={"x-amz-copy-source": f"/{S3_BUCKET}/bob/private.txt"})
    destination = os.path.join(data, "alice", "from_bob.bin")
    ok(status not in (200, 201) and not os.path.exists(destination),
       f"S3 CopyObject of bob's 0600 object DENIED (HTTP {status})")


def _deny_s3_bulk_delete(port, readable):
    request = (b'<?xml version="1.0"?><Delete><Object><Key>bob/readable.txt</Key>'
              b'</Object></Delete>')
    s3("POST", "", port, params={"delete": ""}, data=request)
    ok(os.path.exists(readable) and _bob_file_unchanged(readable),
       "S3 DeleteObjects of bob's key did NOT delete it (broker DAC)")


def _deny_s3_part_copy(port):
    init_status, body = s3("POST", "alice/upc.bin", port, params={"uploads": ""})
    match = re.search(rb"<UploadId>([^<]+)</UploadId>", body or b"")
    if init_status != 200 or match is None:
        return
    upload_id = match.group(1).decode()
    status, _ = s3("PUT", "alice/upc.bin", port,
                       params={"uploadId": upload_id, "partNumber": "1"},
                       extra_hdrs={"x-amz-copy-source": f"/{S3_BUCKET}/bob/private.txt"})
    ok(status not in (200, 201),
       f"S3 UploadPartCopy from bob's 0600 object DENIED (HTTP {status})")


def _deny_s3_writes(data, port, readable):
    _deny_s3_overwrite(port, readable)
    _deny_s3_delete(port, readable)
    _deny_s3_copy(data, port)
    _deny_s3_bulk_delete(port, readable)
    _deny_s3_part_copy(port)


def run_cross_tenant_write(key, data, port, s3port):
    """Verify mapped-user writes cannot mutate another user's data."""
    token = mint(key, "alice")
    readable = os.path.join(data, "bob", "readable.txt")
    _deny_webdav_overwrite(port, token, readable)
    _deny_webdav_create(data, port, token)
    _deny_webdav_delete(port, token, readable)
    _deny_webdav_move(data, port, token, readable)
    _deny_webdav_copy(data, port, token)
    _deny_webdav_property(port, token)
    if s3port:
        _deny_s3_writes(data, s3port, readable)


def run_create_ownership(key, data, port, s3port):
    """Every remaining CREATE path lands owned by the mapped user (1001), never the
    worker (1500) or root (0): WebDAV LOCK-creates-a-resource, and S3 CopyObject."""
    ta = mint(key, "alice")

    # LOCK on a NON-existent path must create a zero-byte resource (RFC 4918
    # §9.10.4) — owned by the mapped user (create + lock xattr both via broker).
    li = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
          b'<D:lockscope><D:exclusive/></D:lockscope>'
          b'<D:locktype><D:write/></D:locktype></D:lockinfo>')
    st, _ = http("LOCK", "/alice/lock_created.txt", port, ta, data=li,
                 hdrs={"Content-Type": "application/xml", "Timeout": "Second-60"})
    lp = os.path.join(data, "alice", "lock_created.txt")
    ok(st in (200, 201) and os.path.exists(lp) and os.stat(lp).st_uid == UID_ALICE,
       f"WebDAV LOCK-creates-resource owned by alice (HTTP {st})")

    if s3port:
        # CopyObject of alice's OWN object -> new object owned by alice.
        s3("PUT", "alice/copy_src.txt", s3port, data=b"copy me\n")
        st, _ = s3("PUT", "alice/copy_dst.txt", s3port,
                   extra_hdrs={"x-amz-copy-source": f"/{S3_BUCKET}/alice/copy_src.txt"})
        cp = os.path.join(data, "alice", "copy_dst.txt")
        ok(st in (200, 201) and os.path.exists(cp) and os.stat(cp).st_uid == UID_ALICE,
           f"S3 CopyObject result owned by alice (HTTP {st})")


def run_recursive_propfind(key, data, port):
    """PROPFIND Depth: infinity from the export root must not leak the CONTENTS of
    subtrees the mapped user cannot read (svc-only 0750, bob's 0700 private dir)."""
    ta = mint(key, "alice")
    st, body = http("PROPFIND", "/", port, ta,
                    data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                         b'<D:prop><D:displayname/></D:prop></D:propfind>',
                    hdrs={"Depth": "infinity", "Content-Type": "application/xml"})
    # secret-name.txt lives in svconly (0750, svc) and s.txt in bobsecret (0700,
    # bob) — neither readable/traversable by alice, so neither may appear.  Nor may
    # the walk FOLLOW /escape (-> /etc) and enumerate the host filesystem.
    leaked = _has(body, b"secret-name.txt") or _has(body, b"bob-only") \
        or _has(body, b">s.txt<") or _has(body, b"escape/") or _has(body, b"passwd")
    ok(st in (207, 200, 403) and not leaked,
       f"recursive PROPFIND did not leak private subtrees / escape via symlink "
       f"(HTTP {st}, leaked={leaked})")


def run_confinement_extended(key, data, port, s3port):
    """Path-confinement across protocols: traversal in S3 keys and in COPY/MOVE
    Destination headers must not read or write outside the export root."""
    ta = mint(key, "alice")
    outside = os.path.join(os.path.dirname(data), "ESCAPE_SENTINEL")

    # WebDAV COPY with a Destination pointing outside the root (../) must not
    # create the file outside.
    http("PUT", "/alice/exfil.txt", port, ta, b"secret\n")
    st, _ = http("COPY", "/alice/exfil.txt", port, ta,
                 hdrs={"Destination": f"http://{HOST}:{port}/../ESCAPE_SENTINEL"})
    ok(not os.path.exists(outside),
       f"WebDAV COPY Destination ../escape blocked (HTTP {st})")

    if s3port:
        # S3 GET with a traversal key must not read /etc/passwd.
        st, body = s3("GET", "../../../../etc/passwd", s3port)
        ok(not _has(body, b"root:x:0:0"),
           f"S3 GET traversal key did not read /etc/passwd (HTTP {st})")
        # S3 PUT with a traversal key must not write outside the export.
        s3("PUT", "../ESCAPE_SENTINEL", s3port, data=b"x\n")
        ok(not os.path.exists(outside), "S3 PUT traversal key blocked")


def run_token_principal_attacks(key, data, port):
    """The token subject is the string the broker maps to a UNIX user.  Malformed /
    hostile subjects must be DENIED (not mapped to a privileged or arbitrary uid),
    and must never be interpreted as a path."""
    def attack(sub, label):
        tok = mint(key, sub)
        path = f"/pub/tokatk_{abs(hash(sub)) % 100000}.txt"
        st, _ = http("PUT", path, port, tok, b"x\n")
        fp = os.path.join(data, "pub", os.path.basename(path))
        created = os.path.exists(fp)
        bad = created and os.stat(fp).st_uid < 1000
        ok(st not in (200, 201, 204) and not created and not bad,
           f"token subject {label} -> DENIED (HTTP {st}, created={created})")

    attack("", "empty")
    attack("alice/../bob", "path-traversal-like 'alice/../bob'")
    attack("../../root", "traversal-to-root")
    attack("0", "numeric '0'")
    attack("a" * 600, "overlong (600 chars)")
    attack("alice\x00root", "embedded NUL")
    attack(" alice", "leading-space ' alice'")        # getpwnam is exact
    attack("alice ", "trailing-space 'alice '")
    attack("ALICE", "case-variant 'ALICE'")           # getpwnam is case-sensitive

    # No token at all -> unauthenticated -> rejected before any mapping.
    st, _ = http("PUT", "/pub/notoken.txt", port, None, b"x\n")
    ok(st in (401, 403)
       and not os.path.exists(os.path.join(data, "pub", "notoken.txt")),
       f"unauthenticated request rejected (HTTP {st})")


def _mixed_alice_put(index, data, port, token_alice, token_bob, breaches):
    http("PUT", f"/alice/mc_a_{index}.txt", port, token_alice,
         f"a{index}\n".encode())


def _mixed_bob_put(index, data, port, token_alice, token_bob, breaches):
    http("PUT", f"/bob/mc_b_{index}.txt", port, token_bob,
         f"b{index}\n".encode())


def _mixed_alice_lock(index, data, port, token_alice, token_bob, breaches):
    path = f"/alice/mc_lk_{index}.txt"
    http("PUT", path, port, token_alice, b"x\n")
    lock_info = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                 b'<D:lockscope><D:exclusive/></D:lockscope>'
                 b'<D:locktype><D:write/></D:locktype></D:lockinfo>')
    http("LOCK", path, port, token_alice, data=lock_info,
         hdrs={"Content-Type": "application/xml"})


def _mixed_cross_tenant_put(index, data, port, token_alice, token_bob, breaches):
    status, _ = http("PUT", f"/bob/mc_x_{index}.txt", port, token_alice, b"X\n")
    path = os.path.join(data, "bob", f"mc_x_{index}.txt")
    if status in (200, 201, 204) or os.path.exists(path):
        breaches.append(("xtenant-put", index, status))


def _mixed_public_read(index, data, port, token_alice, token_bob, breaches):
    http("GET", "/alice/hello.txt", port, token_bob)


def _mixed_job(index, data, port, token_alice, token_bob, breaches):
    handlers = (
        _mixed_alice_put,
        _mixed_bob_put,
        _mixed_alice_lock,
        _mixed_cross_tenant_put,
        _mixed_public_read,
    )
    try:
        handlers[index % len(handlers)](
            index, data, port, token_alice, token_bob, breaches
        )
    except Exception as error:  # noqa: BLE001
        breaches.append(("exc", index, repr(error)))


def _owner_mismatches(data, subject, expected_uid):
    mismatches = 0
    directory = os.path.join(data, subject)
    for name in os.listdir(directory):
        if not name.startswith("mc_"):
            continue
        path = os.path.join(directory, name)
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        mismatches += os.lstat(path).st_uid != expected_uid
    return mismatches


def run_mixed_concurrency(key, data, port, s3port):
    """Interleave mapped-user operations and verify process-global isolation."""
    token_alice, token_bob = mint(key, "alice"), mint(key, "bob")
    count = 40
    breaches = []
    args = (data, port, token_alice, token_bob, breaches)
    threads = [
        threading.Thread(target=_mixed_job, args=(index, *args))
        for index in range(count)
    ]
    _start_threads(threads)
    _join_threads(threads)
    mismatches = _owner_mismatches(data, "alice", UID_ALICE)
    mismatches += _owner_mismatches(data, "bob", UID_BOB)
    ok(not breaches and mismatches == 0,
       f"mixed-op concurrency ({count} jobs): no principal leak "
       f"(cross-tenant breaches={breaches[:3]}, owner-mismatches={mismatches})")
