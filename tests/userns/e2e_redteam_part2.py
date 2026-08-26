def wait_port(port, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):  # net-literal-allow: loopback inside the userns sandbox's own net namespace
                return True
        except OSError:
            time.sleep(0.1)
    return False



def _s3_policy(access_key, key, when, expires_min, conditions, cred_override):
    now = when or dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    credential = cred_override or f"{access_key}/{date}/{S3_REGION}/s3/aws4_request"
    expires = (now + dt.timedelta(minutes=expires_min)).strftime("%Y-%m-%dT%H:%M:%SZ")
    policy_conditions = [{"bucket": S3_BUCKET}, ["starts-with", "$key", ""]]
    policy_conditions.extend(conditions or [])
    policy = {"expiration": expires, "conditions": policy_conditions}
    encoded = base64.b64encode(
        json.dumps(policy, separators=(",", ":")).encode()
    ).decode()
    return amz_date, date, credential, encoded


def _s3_policy_signature(date, encoded_policy, tamper):
    key = hmac.new(
        ("AWS4" + S3_SECRET).encode(), date.encode(), hashlib.sha256
    ).digest()
    key = hmac.new(key, S3_REGION.encode(), hashlib.sha256).digest()
    key = hmac.new(key, b"s3", hashlib.sha256).digest()
    key = hmac.new(key, b"aws4_request", hashlib.sha256).digest()
    signature = hmac.new(key, encoded_policy.encode(), hashlib.sha256).hexdigest()
    if not tamper:
        return signature
    return ("0" * 64) if signature[0] != "0" else ("f" * 64)


def _s3_form_field(boundary, name, value):
    return (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
        f"{value}\r\n"
    )


def _s3_auth_fields(boundary, credential, amz_date, policy, signature):
    values = (
        ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
        ("x-amz-credential", credential),
        ("x-amz-date", amz_date),
        ("policy", policy),
        ("x-amz-signature", signature),
    )
    return [_s3_form_field(boundary, name, value) for name, value in values]


def _s3_success_field(boundary, status, redirect):
    if redirect is not None:
        return _s3_form_field(boundary, "success_action_redirect", redirect)
    if status is not None:
        return _s3_form_field(boundary, "success_action_status", status)
    return ""


def _s3_file_header(boundary, filename, content_type):
    return (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
    )


def _finish_s3_form(boundary, parts, file_bytes, omit_file):
    head = "".join(parts).encode("latin-1")
    ending = f"\r\n--{boundary}--\r\n".encode("latin-1")
    if omit_file:
        return head + ending[2:]
    return head + file_bytes + ending


def _s3_post_form(access_key, key, file_bytes, when=None, expires_min=60,
                  conditions=None, success_status="201", success_redirect=None,
                  content_type="text/plain", tamper_sig=False, omit_policy=False,
                  cred_override=None, filename="upload.bin", omit_file=False):
    """Build a browser S3 POST Object multipart/form-data body + Content-Type.

    Returns (content_type_header, body_bytes).  Mirrors the server's POST-policy
    auth (src/protocols/s3/post_object.c): the x-amz-signature is HMAC-SHA256(signing_key,
    base64_policy) hex-encoded, where signing_key is the AWS4 date/region-scoped
    key.  `tamper_sig` corrupts that signature; `omit_policy` drops the auth
    fields; `cred_override` forges the x-amz-credential access key; `when`
    backdates the policy (with expires_min<=0 for an already-expired policy);
    `omit_file` produces a form with no file part.  Bodies are tiny.
    """
    boundary = "----rtFormBoundary7XzQp"
    amz_date, date, credential, policy = _s3_policy(
        access_key, key, when, expires_min, conditions, cred_override
    )
    signature = _s3_policy_signature(date, policy, tamper_sig)
    parts = [_s3_form_field(boundary, "key", key)]
    if not omit_policy:
        parts.extend(
            _s3_auth_fields(boundary, credential, amz_date, policy, signature)
        )
    success_field = _s3_success_field(boundary, success_status, success_redirect)
    if success_field:
        parts.append(success_field)
    if not omit_file:
        parts.append(_s3_file_header(boundary, filename, content_type))
    body = _finish_s3_form(boundary, parts, file_bytes, omit_file)
    return f"multipart/form-data; boundary={boundary}", body

DEAD_PREFIX = "user.nginx_xrootd.webdav."


def _dead_xattr_count(fp):
    """Count on-disk WebDAV dead-property xattrs on `fp` (the kernel ground truth,
    independent of any PROPFIND echo).  WebDAV PROPPATCH stores each dead property
    under the `user.nginx_xrootd.webdav.` xattr prefix (src/protocols/webdav/dead_props.c).
    Returns -1 if the path is unreadable."""
    try:
        names = os.listxattr(fp)
    except OSError:
        return -1
    return sum(1 for n in names if n.startswith(DEAD_PREFIX))


def _dead_xattr_has_value(fp, needle):
    """True iff any WebDAV dead-property xattr value on `fp` contains `needle`
    (bytes).  Used to assert a property was (or was NOT) actually persisted at the
    kernel layer rather than merely echoed in a PROPFIND response."""
    needle_b = needle if isinstance(needle, bytes) else needle.encode()
    try:
        names = os.listxattr(fp)
    except OSError:
        return False
    for n in names:
        if not n.startswith(DEAD_PREFIX):
            continue
        try:
            if needle_b in os.getxattr(fp, n):
                return True
        except OSError:
            continue
    return False

def _raw_get_request(path, token, extra):
    lines = [f"GET {path} HTTP/1.1", "Host: 127.0.0.1", "Connection: close"]  # net-literal-allow: loopback inside the userns sandbox's own net namespace
    if token:
        lines.append(f"Authorization: Bearer {token}")
    lines.extend(f"{key}: {value}" for key, value in (extra or {}).items())
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def _response_status(status_line):
    match = re.match(rb"HTTP/\d\.\d\s+(\d{3})", status_line)
    if match is None:
        return 0
    return int(match.group(1))


def _validator_headers(lines):
    validators = {b"etag": None, b"last-modified": None}
    for line in lines:
        name, _, value = line.partition(b":")
        key = name.strip().lower()
        if key in validators and validators[key] is None:
            validators[key] = value.strip().decode("latin1")
    return validators[b"etag"], validators[b"last-modified"]


def _raw_get_validators(path, port, token=None, extra=None, read_timeout=4.0):
    """Authenticated raw GET that PARSES the response headers (the http() helper
    discards them) so a conditional-header batch can capture a file's REAL ETag
    and Last-Modified validators.  Returns (status_int, etag_or_None,
    lastmod_or_None, body_bytes); status 0 on a framing/conn failure.  `etag`
    keeps its surrounding quotes verbatim so it can be replayed in If-Match /
    If-None-Match exactly as the server emitted it."""
    request = _raw_get_request(path, token, extra)
    resp = raw_http(request, port, read_timeout=read_timeout)
    if not resp or b"\r\n" not in resp:
        return 0, None, None, b""
    head, _, body = resp.partition(b"\r\n\r\n")
    head_lines = head.split(b"\r\n")
    status = _response_status(head_lines[0])
    etag, lastmod = _validator_headers(head_lines[1:])
    return status, etag, lastmod, body

_KXR_PROTOCOL  = 3006
_KXR_LOGIN     = 3007
_KXR_STAT      = 3017
_KXR_BIND      = 3024
_KXR_READV     = 3025
_KXR_OK        = 0
_KXR_ERROR     = 4003
_KXR_HS_FOURTH = 4
_KXR_HS_FIFTH  = 2012        # ROOTD_PQ handshake magic word
_KXR_PROTOVER  = 0x00000520


def _kxr_recv_exact(sock, n):
    """Read exactly n bytes, or None if the peer closes/errs before n arrive."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (OSError, socket.timeout):
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def _kxr_response_header(sock):
    header = _kxr_recv_exact(sock, 8)
    if header is None or len(header) < 8:
        return None
    _stream_id, status, data_length = struct.unpack("!2sHI", header)
    return status, data_length


def _kxr_body(sock, data_length):
    if data_length <= 0 or data_length > (1 << 20):
        return b""
    return _kxr_recv_exact(sock, data_length) or b""


def _drain_kxr_page_data(sock, status, body):
    if status != 4007 or len(body) < 16:
        return
    inner_length = struct.unpack("!I", body[12:16])[0]
    if 0 < inner_length <= (1 << 20):
        _kxr_recv_exact(sock, inner_length)





















# ===== Round-8 batch helpers (workflow-authored) =====
def _crc64nvme(data):
    """CRC-64/NVME (reflected poly 0x9A6C9329AC4BC9B5, init/xorout all-FF, refin/
    refout): the algorithm behind AWS S3 x-amz-checksum-crc64nvme and this module's
    src/core/compat/crc64.c.  Returns the 64-bit integer (verify: crc64nvme(b"123456789")
    == 0xAE8B14860A799888, the published check constant)."""
    poly = 0x9A6C9329AC4BC9B5
    crc = 0xFFFFFFFFFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ poly if (crc & 1) else (crc >> 1)
    return crc ^ 0xFFFFFFFFFFFFFFFF


def _crc64nvme_b64(data):
    """AWS wire form of CRC-64/NVME: base64 of the 8 big-endian CRC bytes (NOT hex —
    that is the root:///WebDAV digest form).  Matches s3_object_crc64nvme_b64()."""
    return base64.b64encode(struct.pack(">Q", _crc64nvme(data))).decode("ascii")


def _raw_response_status(row):
    if not row.startswith("HTTP/"):
        return -1
    parts = row.split()
    if len(parts) < 2 or not parts[1].isdigit():
        return -1
    return int(parts[1])


def _raw_response_headers(rows):
    headers = {}
    for row in rows:
        if ":" not in row:
            continue
        key, _, value = row.partition(":")
        headers[key.strip().lower()] = value.strip()
    return headers


def _decoded_head(head):
    try:
        return head.decode("latin-1")
    except Exception:  # noqa: BLE001
        return ""


def _raw_get_header(method, path, port, hdrs):
    """Issue a raw HTTP request (so response HEADERS are visible — the http() helper
    returns only status+body) and return (status_int, {lower_header: value}, body).
    Used to read the Digest:/x-amz-checksum-* response headers that carry a content
    fingerprint.  status -1 / empty dict on a connection failure."""
    lines = ["%s %s HTTP/1.1" % (method, path), "Host: 127.0.0.1:%d" % port,  # net-literal-allow: loopback inside the userns sandbox's own net namespace
             "Connection: close"]
    for k, v in (hdrs or {}).items():
        lines.append("%s: %s" % (k, v))
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode()
    resp = raw_http(raw, port)
    if not resp:
        return -1, {}, b""
    head, _, body = resp.partition(b"\r\n\r\n")
    rows = _decoded_head(head).split("\r\n")
    status = _raw_response_status(rows[0]) if rows else -1
    return status, _raw_response_headers(rows[1:]), body

# Additional kXR opcodes (the file already defines PROTOCOL/LOGIN/STAT/BIND/READV).
_KXR_AUTH      = 3000
_KXR_CLOSE     = 3003
_KXR_DIRLIST   = 3004
_KXR_OPEN      = 3010
_KXR_READ      = 3013
_KXR_STATX     = 3022
_KXR_PGWRITE   = 3026
_KXR_TRUNCATE  = 3028
_KXR_PGREAD    = 3030

_KXR_OPEN_READ = 0x0010      # kXR_open_read
_KXR_OPEN_UPDT = 0x0020      # kXR_open_updt (read/write)
_KXR_NEW       = 0x0008      # kXR_new
_KXR_MKPATH    = 0x0100      # kXR_mkpath

# kXR_pgPageSZ from XProtocol.hh: page size used to interleave per-page CRC32c.
_KXR_PG_PAGESZ = 4096
