def _resp_status(resp):
    """Return a raw HTTP response status, or -1 when it cannot be parsed."""
    try:
        if resp.startswith(b"HTTP/"):
            return int(resp.split(b" ", 2)[1])
    except (ValueError, IndexError):
        pass
    return -1


def _seed_http_abuse_files(port, token):
    http("PUT", "/alice/hpa_own.txt", port, token, b"HPA-OWN-BODY\n")
    http("PUT", "/alice/hpa_rng.txt", port, token, b"0123456789ABCDEF")


def _check_duplicate_content_length(data, port, token):
    request = (
        f"PUT /alice/hpa_s1.txt HTTP/1.1\r\nHost: {HOST}\r\n"
        f"Authorization: Bearer {token}\r\nContent-Length: 5\r\n"
        f"Content-Length: 120\r\n\r\nhelloPUT /alice/hpa_SMUGGLED.txt "
        f"HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {token}\r\n"
        "Content-Length: 4\r\n\r\nevil"
    )
    status = _resp_status(raw_http(request, port))
    created = os.path.exists(os.path.join(data, "alice", "hpa_SMUGGLED.txt"))
    ok(not created, f"duplicate Content-Length smuggle not executed (HTTP {status})")
    ok(
        status == -1 or status >= 400,
        f"duplicate Content-Length rejected (HTTP {status})",
    )


def _check_cl_te_smuggling(data, port, token):
    request = (
        f"POST /alice/hpa_s2.txt HTTP/1.1\r\nHost: {HOST}\r\n"
        f"Authorization: Bearer {token}\r\nContent-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nPUT /alice/hpa_TE.txt "
        f"HTTP/1.1\r\nHost: {HOST}\r\n\r\n"
    )
    status = _resp_status(raw_http(request, port))
    created = os.path.exists(os.path.join(data, "alice", "hpa_TE.txt"))
    ok(not created, f"CL+TE smuggle not executed (HTTP {status})")


def _check_duplicate_host(port, token):
    request = (
        f"GET /alice/hpa_own.txt HTTP/1.1\r\nHost: {HOST}\r\n"
        f"Host: evil.example\r\nAuthorization: Bearer {token}\r\n\r\n"
    )
    response = raw_http(request, port)
    status = _resp_status(response)
    safe = b"HPA-OWN-BODY" not in response or status == 200
    ok(safe, f"duplicate Host handled without anomaly (HTTP {status})")


def _check_http_10(port, token):
    request = (
        f"GET /alice/hpa_own.txt HTTP/1.0\r\nAuthorization: Bearer {token}\r\n\r\n"
    )
    status = _resp_status(raw_http(request, port))
    ok(status in (200, 400, 404, 426, 505, -1), f"HTTP/1.0 handled (HTTP {status})")


def _check_absolute_uri(port, token):
    request = (
        f"GET http://evil.example/bob/private.txt HTTP/1.1\r\nHost: {HOST}\r\n"
        f"Authorization: Bearer {token}\r\n\r\n"
    )
    response = raw_http(request, port)
    ok(
        b"BOB-PRIVATE-SECRET" not in response,
        f"absolute URI leaks no bob secret (HTTP {_resp_status(response)})",
    )


def _check_line_and_body_framing(port, token):
    bare_lf = (
        f"GET /alice/hpa_own.txt HTTP/1.1\nHost: {HOST}\n"
        f"Authorization: Bearer {token}\n\n"
    )
    status = _resp_status(raw_http(bare_lf, port))
    ok(status in (200, 400, -1), f"bare-LF framing handled (HTTP {status})")
    body_get = (
        f"GET /alice/hpa_own.txt HTTP/1.1\r\nHost: {HOST}\r\n"
        f"Authorization: Bearer {token}\r\nContent-Length: 5\r\n\r\nXXXXX"
    )
    status = _resp_status(raw_http(body_get, port))
    ok(status in (200, 400, 413, -1), f"body-on-GET handled (HTTP {status})")


def _range_request(path, token, range_value):
    return (
        f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\n"
        f"Authorization: Bearer {token}\r\nRange: {range_value}\r\n\r\n"
    )


def _check_multi_range_access(port, token):
    request = _range_request("/alice/hpa_rng.txt", token, "bytes=0-2,5-7")
    status = _resp_status(raw_http(request, port))
    ok(status in (200, 206, 416), f"multi-range own-file GET handled (HTTP {status})")
    request = _range_request("/bob/private.txt", token, "bytes=0-4,6-10")
    response = raw_http(request, port)
    ok(
        b"BOB-PRIVATE-SECRET" not in response,
        f"multi-range bob-file GET leaks no secret (HTTP {_resp_status(response)})",
    )


def _check_unusual_ranges(port, token):
    ranges = ("bytes=0-0,0-0,0-0", "bytes=-99999", "bytes=5-2", "bytes=0-999999")
    for range_value in ranges:
        request = _range_request("/alice/hpa_rng.txt", token, range_value)
        status = _resp_status(raw_http(request, port))
        ok(
            status in (200, 206, 416, 400, -1),
            f"range '{range_value}' handled (HTTP {status})",
        )


def _check_header_pressure(port, token):
    padding = "".join(f"X-Pad-{index}: {index}\r\n" for index in range(200))
    request = (
        f"GET /alice/hpa_own.txt HTTP/1.1\r\nHost: {HOST}\r\n"
        f"Authorization: Bearer {token}\r\n{padding}\r\n"
    )
    status = _resp_status(raw_http(request, port))
    ok(
        status in (200, 400, 431, 494, -1),
        f"200-header request handled (HTTP {status})",
    )


def _check_alice_chunked_put(data, port, token):
    body = b"chunked-body-data"
    request = (
        (
            f"PUT /alice/hpa_chunked.txt HTTP/1.1\r\nHost: {HOST}\r\n"
            f"Authorization: Bearer {token}\r\nTransfer-Encoding: chunked\r\n\r\n"
            f"{len(body):x}\r\n"
        ).encode()
        + body
        + b"\r\n0\r\n\r\n"
    )
    status = _resp_status(raw_http(request, port))
    path = os.path.join(data, "alice", "hpa_chunked.txt")
    ok(
        status in (200, 201, 204, 400, 411, 501, -1),
        f"chunked PUT handled (HTTP {status})",
    )
    correct_owner = not os.path.exists(path) or os.stat(path).st_uid == UID_ALICE
    ok(correct_owner, "chunked PUT object is owned by alice when created")


def _check_bob_chunked_put(data, key, port):
    token = mint(key, "bob")
    request = (
        f"PUT /alice/hpa_bobchunk.txt HTTP/1.1\r\nHost: {HOST}\r\n"
        f"Authorization: Bearer {token}\r\nTransfer-Encoding: chunked\r\n\r\n"
        "3\r\nXXX\r\n0\r\n\r\n"
    ).encode()
    raw_http(request, port)
    created = os.path.exists(os.path.join(data, "alice", "hpa_bobchunk.txt"))
    ok(not created, "bob chunked PUT into alice's directory denied")


def _check_request_pipeline(port, token):
    request = (
        f"GET /alice/hpa_own.txt HTTP/1.1\r\nHost: {HOST}\r\n"
        f"Authorization: Bearer {token}\r\n\r\n"
        f"GET /bob/private.txt HTTP/1.1\r\nHost: {HOST}\r\n"
        f"Authorization: Bearer {token}\r\n\r\n"
        f"GET /alice/hpa_own.txt HTTP/1.1\r\nHost: {HOST}\r\n"
        f"Authorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    )
    response = raw_http(request, port)
    safe = b"BOB-PRIVATE-SECRET" not in response
    ok(safe and response.count(b"HPA-OWN-BODY") >= 1, "pipeline preserves identity")


def _wrong_http_owner_count(data):
    count = 0
    directory = os.path.join(data, "alice")
    for name in os.listdir(directory):
        if not name.startswith("hpa_"):
            continue
        try:
            owner = os.lstat(os.path.join(directory, name)).st_uid
        except OSError:
            continue
        if owner in (UID_SVC, 0):
            count += 1
    return count


def _check_http_worker_survival(data, port, token):
    status, body = http("GET", "/alice/hpa_own.txt", port, token)
    ok(
        status == 200 and body == b"HPA-OWN-BODY\n",
        f"worker survived abuse (HTTP {status})",
    )
    mismatches = _wrong_http_owner_count(data)
    ok(mismatches == 0, f"no hpa_* file is worker/root-owned (mismatches={mismatches})")


def run_http_protocol_abuse(key, data, port, s3port):
    """Exercise hostile HTTP framing while preserving identity and worker health."""
    token = mint(key, "alice")
    _seed_http_abuse_files(port, token)
    _check_duplicate_content_length(data, port, token)
    _check_cl_te_smuggling(data, port, token)
    _check_duplicate_host(port, token)
    _check_http_10(port, token)
    _check_absolute_uri(port, token)
    _check_line_and_body_framing(port, token)
    _check_multi_range_access(port, token)
    _check_unusual_ranges(port, token)
    _check_header_pressure(port, token)
    _check_alice_chunked_put(data, port, token)
    _check_bob_chunked_put(data, key, port)
    _check_request_pipeline(port, token)
    _check_http_worker_survival(data, port, token)


def _presigned_get(s3port, object_name, **options):
    url = s3_presign("GET", object_name, s3port, **options)
    return http("GET", url, s3port)


def _check_presigned_get_controls(s3port):
    status, body = _presigned_get(s3port, "alice/ps_obj.txt", expires=300)
    valid = status == 200 and b"PRESIGN-OWN-OBJECT" in (body or b"")
    ok(valid, f"valid presigned GET reads own object (HTTP {status})")
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
    status, body = _presigned_get(s3port, "alice/ps_obj.txt", expires=60, when=old)
    denied = status in (401, 403) and b"PRESIGN-OWN-OBJECT" not in (body or b"")
    ok(denied, f"expired URL denied (HTTP {status})")


def _check_presigned_tamper(s3port):
    status, _body = _presigned_get(s3port, "alice/ps_obj.txt", tamper=True)
    ok(status in (401, 403), f"tampered presigned signature denied (HTTP {status})")


def _check_presigned_expiry_bounds(s3port):
    for expiry in (0, 999999999):
        status, _body = _presigned_get(s3port, "alice/ps_obj.txt", expires=expiry)
        ok(
            status in (401, 403, 400),
            f"X-Amz-Expires={expiry} rejected (HTTP {status})",
        )


def _check_presigned_cross_tenant(s3port):
    status, body = _presigned_get(s3port, "bob/private.txt")
    ok(
        b"BOB-PRIVATE-SECRET" not in (body or b""),
        f"presigned cross-tenant GET leaks no secret (HTTP {status})",
    )


def _check_presigned_put_owner(data, s3port):
    url = s3_presign("PUT", "alice/ps_put.txt", s3port, expires=300)
    status, _body = http("PUT", url, s3port, data=b"presigned-put\n")
    path = os.path.join(data, "alice", "ps_put.txt")
    created = os.path.exists(path)
    ok(
        status in (200, 201, 204) or not created,
        f"presigned PUT handled (HTTP {status})",
    )
    if created:
        owner = os.stat(path).st_uid
        ok(owner == UID_ALICE, f"presigned PUT object owned by alice (uid={owner})")
        return
    ok(True, "presigned PUT unsupported without creating an object")


def _check_presigned_foreign_put(data, s3port):
    url = s3_presign("PUT", "bobsecret/ps_evil.txt", s3port)
    status, _body = http("PUT", url, s3port, data=b"x\n")
    created = os.path.exists(os.path.join(data, "bobsecret", "ps_evil.txt"))
    ok(not created, f"presigned PUT into bob's directory denied (HTTP {status})")


def _check_presigned_method_binding(data, s3port):
    url = s3_presign("GET", "alice/ps_mm.txt", s3port)
    status, _body = http("PUT", url, s3port, data=b"x\n")
    created = os.path.exists(os.path.join(data, "alice", "ps_mm.txt"))
    ok(
        status in (401, 403) and not created,
        f"presigned method mismatch denied (HTTP {status})",
    )


def _check_presigned_unknown_key(s3port):
    status, body = _presigned_get(
        s3port, "alice/ps_obj.txt", access_key="nonexistent-key"
    )
    denied = status in (401, 403) and b"PRESIGN-OWN-OBJECT" not in (body or b"")
    ok(denied, f"unknown access key denied (HTTP {status})")


def _check_presigned_deleted_replay(s3port):
    s3("PUT", "alice/ps_gone.txt", s3port, data=b"soon-gone\n")
    url = s3_presign("GET", "alice/ps_gone.txt", s3port, expires=300)
    s3("DELETE", "alice/ps_gone.txt", s3port)
    status, body = http("GET", url, s3port)
    missing = status in (403, 404) and b"soon-gone" not in (body or b"")
    ok(missing, f"deleted object is not replayed (HTTP {status})")


def run_s3_presigned(key, data, port, s3port):
    """Verify query-string SigV4 authentication and signer DAC confinement."""
    if not s3port:
        ok(True, "S3 presigned skipped (no S3 port)")
        return
    s3("PUT", "alice/ps_obj.txt", s3port, data=b"PRESIGN-OWN-OBJECT\n")
    _check_presigned_get_controls(s3port)
    _check_presigned_tamper(s3port)
    _check_presigned_expiry_bounds(s3port)
    _check_presigned_cross_tenant(s3port)
    _check_presigned_put_owner(data, s3port)
    _check_presigned_foreign_put(data, s3port)
    _check_presigned_method_binding(data, s3port)
    _check_presigned_unknown_key(s3port)
    _check_presigned_deleted_replay(s3port)


def _mode(path):
    if not os.path.exists(path):
        return -1
    return os.stat(path).st_mode & 0o777


def _normalize_mode(path, mode):
    if os.path.exists(path):
        os.chmod(path, mode)


def _check_chmod_read_controls(port, s3port, bob_token, marker):
    status, body = http("GET", "/alice/cpc1.bin", port, bob_token)
    ok(marker in (body or b""), f"bob reads alice's 0644 via WebDAV (HTTP {status})")
    status, body = s3("GET", "alice/cpc1.bin", s3port)
    ok(marker in (body or b""), f"0644 file is readable via S3 (HTTP {status})")


def _apply_owner_only_mode(path):
    result, _stdout, _stderr = xrd_fs(["chmod", "/alice/cpc1.bin", "600"], "alice")
    mode = _mode(path)
    ok(
        result == 0 and mode == 0o600,
        f"root chmod 600 applied (rc={result}, mode={mode:o})",
    )
    owned = os.path.exists(path) and os.stat(path).st_uid == UID_ALICE
    ok(owned, "chmod preserves alice ownership")


def _check_webdav_chmod_denial(port, bob_token, marker):
    status, body = http("GET", "/alice/cpc1.bin", port, bob_token)
    ok(
        marker not in (body or b""),
        f"bob WebDAV read denied after chmod (HTTP {status})",
    )


def _check_root_cat_chmod_denial(marker):
    result, stdout, _stderr = xrd_fs(["cat", "/alice/cpc1.bin"], "bob")
    safe = marker.decode() not in (stdout or "")
    ok(result != 0 and safe, f"bob root cat denied after chmod (rc={result})")


def _download_contains(path, marker):
    if not os.path.exists(path):
        return False
    with open(path, "rb") as stream:
        return marker in stream.read()


def _check_root_copy_chmod_denial(marker):
    destination = os.path.join(WORK, "cpc_steal.bin")
    result, _stdout, _stderr = xrd_cp_down("/alice/cpc1.bin", destination, "bob")
    leaked = _download_contains(destination, marker)
    ok(result != 0 and not leaked, f"bob xrdcp denied (rc={result})")


def _check_owner_chmod_access(port, alice_token, marker):
    status, body = http("GET", "/alice/cpc1.bin", port, alice_token)
    ok(
        status == 200 and marker in (body or b""),
        f"alice still reads chmod file (HTTP {status})",
    )


def _run_root_created_chmod_chain(
    data, port, s3port, alice_token, bob_token, source, marker
):
    xrd_cp_up(source, "/alice/cpc1.bin", "alice")
    path = os.path.join(data, "alice", "cpc1.bin")
    _normalize_mode(path, 0o644)
    _check_chmod_read_controls(port, s3port, bob_token, marker)
    _apply_owner_only_mode(path)
    _check_webdav_chmod_denial(port, bob_token, marker)
    _check_root_cat_chmod_denial(marker)
    _check_root_copy_chmod_denial(marker)
    _check_owner_chmod_access(port, alice_token, marker)


def _run_s3_created_chmod_chain(data, port, s3port, bob_token, marker):
    s3("PUT", "alice/cpc2.bin", s3port, data=marker + b"-S3\n")
    path = os.path.join(data, "alice", "cpc2.bin")
    result, _stdout, _stderr = xrd_fs(["chmod", "/alice/cpc2.bin", "600"], "alice")
    mode = _mode(path)
    owned = os.path.exists(path) and os.stat(path).st_uid == UID_ALICE
    ok(
        result == 0 and mode == 0o600 and owned,
        f"S3 file chmod 600 (rc={result}, mode={mode:o})",
    )
    status, body = http("GET", "/alice/cpc2.bin", port, bob_token)
    ok(marker + b"-S3" not in (body or b""), f"bob WebDAV read denied (HTTP {status})")


def _run_webdav_created_chmod_chain(data, port, alice_token, bob_token):
    http("PUT", "/alice/cpc3.bin", port, alice_token, b"CPC3-PUBLIC\n")
    path = os.path.join(data, "alice", "cpc3.bin")
    _normalize_mode(path, 0o600)
    status, body = http("GET", "/alice/cpc3.bin", port, bob_token)
    ok(b"CPC3-PUBLIC" not in (body or b""), f"0600 file denied to bob (HTTP {status})")
    result, _stdout, _stderr = xrd_fs(["chmod", "/alice/cpc3.bin", "644"], "alice")
    mode = _mode(path)
    ok(
        result == 0 and mode == 0o644,
        f"root chmod widened to 644 (rc={result}, mode={mode:o})",
    )
    status, body = http("GET", "/alice/cpc3.bin", port, bob_token)
    allowed = status == 200 and b"CPC3-PUBLIC" in (body or b"")
    ok(allowed, f"bob WebDAV read allowed after chmod (HTTP {status})")
    return path


def _check_foreign_chmod_denied(path):
    before = _mode(path)
    result, _stdout, _stderr = xrd_fs(["chmod", "/alice/cpc3.bin", "777"], "bob")
    after = _mode(path)
    ok(
        result != 0 and after == before,
        f"bob chmod denied, mode intact ({before:o}->{after:o})",
    )


def _write_chmod_source(marker):
    path = os.path.join(WORK, "cpc_seed.bin")
    with open(path, "wb") as stream:
        stream.write(marker + b"\n")
    return path


def run_crossproto_chmod_chains(key, data, port, s3port):
    """Verify kernel mode changes and ownership across every exposed protocol."""
    if not xrd_avail():
        ok(True, "cross-protocol chmod chains skipped (native client absent)")
        return
    alice_token = mint(key, "alice")
    bob_token = mint(key, "bob")
    marker = b"CPC-ALICE-SECRET"
    source = _write_chmod_source(marker)
    _run_root_created_chmod_chain(
        data, port, s3port, alice_token, bob_token, source, marker
    )
    _run_s3_created_chmod_chain(data, port, s3port, bob_token, marker)
    path = _run_webdav_created_chmod_chain(data, port, alice_token, bob_token)
    _check_foreign_chmod_denied(path)
