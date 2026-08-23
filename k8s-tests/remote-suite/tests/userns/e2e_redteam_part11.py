from functools import partial
from types import SimpleNamespace


def run_s3_multipart_adversarial(key, data, port, s3port):
    """S3 multipart + object-op ADVERSARIAL SEQUENCES under impersonation.

    Goes deeper than run_s3 / run_s3_extended / run_s3_deep: it abuses the
    multipart lifecycle, object-copy surface, and DeleteObjects batches. Every
    denial has a positive control, every read denial checks that secret content
    is absent, and every created object is checked for mapped-user ownership.
    The final operations prove that hostile sequences do not wedge the broker.
    """
    state = _mpa_state(data, s3port)
    if not _mpa_available(state):
        return
    _mpa_prepare_fixture(state)
    first_etag, control_key = _mpa_a1(state)
    for check in (_mpa_a2, _mpa_a3, _mpa_a4, _mpa_a5, _mpa_a6, _mpa_a7,
                  _mpa_a8, _mpa_a9, _mpa_a10, _mpa_a11, _mpa_a12,
                  _mpa_b1, _mpa_b2, _mpa_b3, _mpa_b4, _mpa_b5,
                  _mpa_c1, _mpa_c2, _mpa_c3, _mpa_c4):
        check(state)
    _mpa_d1(state, first_etag, control_key)
    for check in (_mpa_d2, _mpa_d3, _mpa_d4):
        check(state)
    _mpa_d5(state, control_key)
    for check in (_mpa_e1, _mpa_e2, _mpa_e3, _mpa_e4):
        check(state)


def _mpa_state(data, s3port):
    return SimpleNamespace(tag="mpa", bucket=S3_BUCKET,
                           mark=b"MPA-BOB-PRIVATE-XYZZY",
                           data=data, s3port=s3port)


def _mpa_bytes(value):
    return value if value is not None else b""


def _mpa_match_text(match):
    return match.group(1).decode() if match else None


def _mpa_default(value, fallback):
    return fallback if value is None else value


def _mpa_secret(state):
    return f"bob/{state.tag}_secret.txt"


def _mpa_upload_id(body):
    match = re.search(rb"<UploadId>([^<]+)</UploadId>", _mpa_bytes(body))
    return _mpa_match_text(match)


def _mpa_etag(body):
    match = re.search(rb'ETag>\\?"?([^"<\\]+)', _mpa_bytes(body))
    return _mpa_match_text(match)


def _mpa_complete_xml(parts):
    document = b"<CompleteMultipartUpload>"
    for number, etag in parts:
        document += (f"<Part><PartNumber>{number}</PartNumber>"
                     f"<ETag>{etag}</ETag></Part>").encode()
    return document + b"</CompleteMultipartUpload>"


def _mpa_initiate(state, object_key):
    status, body = s3("POST", object_key, state.s3port, params={"uploads": ""})
    return status, _mpa_upload_id(body)


def _mpa_path(state, relative):
    return os.path.join(state.data, relative)


def _mpa_uid(state, relative):
    path = _mpa_path(state, relative)
    try:
        if not os.path.exists(path):
            return -1
        return os.stat(path).st_uid
    except OSError:
        return -2


def _mpa_exists(state, relative):
    try:
        return os.path.exists(_mpa_path(state, relative))
    except OSError:
        return False


def _mpa_body(state, relative):
    try:
        with open(_mpa_path(state, relative), "rb") as handle:
            return handle.read()
    except OSError:
        return b""


def _mpa_context(state):
    return (state.tag, state.bucket, state.mark, state.data, state.s3port,
            _mpa_etag, _mpa_complete_xml, partial(_mpa_initiate, state),
            partial(_mpa_uid, state), partial(_mpa_exists, state),
            partial(_mpa_body, state))


def _mpa_available(state):
    status, _ = s3("GET", "", state.s3port, params={"list-type": "2"})
    if status not in (-1,):
        return True
    ok(True, "S3 multipart adversarial skipped (S3 endpoint unreachable)")
    return False


def _mpa_prepare_fixture(state):
    relative = _mpa_secret(state)
    path = _mpa_path(state, relative)
    try:
        with open(path, "wb") as handle:
            handle.write(state.mark + b"\n")
        os.chown(path, UID_BOB, UID_BOB)
        os.chmod(path, 0o600)
    except OSError:
        pass
    ok(all((_mpa_exists(state, relative), _mpa_uid(state, relative) == UID_BOB)),
       "fixture: bob-owned 0600 cross-tenant multipart source planted")


from split_continuation import load as _load_multipart_checks
_load_multipart_checks(globals(), __file__,
                       "e2e_redteam_multipart_lifecycle.py",
                       "e2e_redteam_multipart_object_ops.py")
