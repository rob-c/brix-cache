"""S3 folder markers — a key ending in '/' names a directory, not an object.

The AWS convention for "create a folder" is a zero-byte PUT to a key ending in
'/', and that is exactly what our own s3:// storage driver emits: sd_remote's
.mkdir slot PUTs "path/", and its stat classifies a path as a directory by
HEADing "path/" (sd_remote_meta.c).  Both sides of that convention were missing
on the S3 SERVER, so brix-talking-to-brix could not create or see a folder:

  * PUT "dir/" fell through to the object-write path.  Its parent-prefix mkdir
    created the directory as a side effect and the atomic publish then tried to
    rename the staged temp file ONTO that directory — EINVAL → 500, with the
    directory left behind.  Over root:// that surfaced as xrdfs mkdir → EIO.
  * HEAD "dir/" answered 404 NoSuchKey along with every other directory path, so
    even a directory that did exist stat'd as absent and a rename into it was
    refused with "invalid destination path".

Cases:
  1. success      — PUT "dir/" → 200, HEAD "dir/" → 200 with zero length; the
                    marker is idempotent (a second PUT is also 200).
  2. error        — PUT "dir/" carrying a body → 400 InvalidRequest (a marker
                    has no bytes; silently discarding them would lose data).
  3. security/neg — the marker path is confined and narrow: a traversal key must
                    not create a directory outside the export, and a plain
                    (slash-free) key that resolves to a directory must still be
                    404 NoSuchKey, not a phantom zero-byte object.

Uses the pre-started nginx_shared S3 instance (anonymous + write).
"""

import http.client
import uuid
from urllib.parse import urlsplit

import pytest
import requests

from settings import S3_BUCKET

BUCKET = S3_BUCKET


@pytest.fixture(scope="module")
def s3_url(test_env):
    return test_env["s3_url"]


def _folder(s3_url):
    """A fresh, never-used folder key (with its trailing marker slash)."""
    return f"{s3_url}/{BUCKET}/marker_{uuid.uuid4().hex}/"


def _raw(s3_url, method, path, body=b""):
    """Send `path` VERBATIM (no client-side dot-segment collapsing); return the
    status.  requests/urllib3 normalize "/a/../b" away before the socket write,
    which would make a traversal assertion pass without testing anything."""
    parts = urlsplit(s3_url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=10)
    try:
        conn.request(method, path, body=body)
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


def test_marker_put_creates_folder(s3_url):
    url = _folder(s3_url)

    r = requests.put(url, data=b"", timeout=10)
    assert r.status_code == 200, f"marker PUT must succeed, got {r.status_code}"

    # The read side: HEAD on the marker key reports the folder as present with
    # zero length — this is the probe sd_remote's stat uses to answer is_dir.
    h = requests.head(url, timeout=10)
    assert h.status_code == 200, f"HEAD on the marker must be 200, got {h.status_code}"
    assert h.headers.get("Content-Length") == "0", h.headers

    # PUT is idempotent: re-landing the marker is success, not 409/500.
    assert requests.put(url, data=b"", timeout=10).status_code == 200

    # And the folder is usable as a prefix — an object lands inside it.
    obj = url + "inside.bin"
    try:
        assert requests.put(obj, data=b"payload", timeout=10).status_code == 200
        assert requests.get(obj, timeout=10).content == b"payload"
    finally:
        requests.delete(obj, timeout=10)


def test_marker_put_with_body_rejected(s3_url):
    url = _folder(s3_url)

    r = requests.put(url, data=b"not-a-folder", timeout=10)
    assert r.status_code == 400, \
        f"a marker carrying bytes must be refused, got {r.status_code}"
    assert "InvalidRequest" in r.text, r.text

    # Refused means refused: no folder was created as a side effect.
    assert requests.head(url, timeout=10).status_code == 404


@pytest.mark.parametrize("dots", ["..", "%2e%2e", "%2E%2E"])
def test_marker_traversal_key_confined(s3_url, dots):
    # A traversal in the marker key must never create a directory outside the
    # export root.  Sent with http.client, not requests: requests collapses dot
    # segments client-side, so the server would never see the traversal and the
    # assertion would pass vacuously.  The encoded forms matter too — the
    # resolver must decode before deciding, not after.
    name = "marker_escape_%s" % uuid.uuid4().hex
    path = "/%s/%s/%s/" % (BUCKET, dots, name)

    assert _raw(s3_url, "PUT", path) != 200, \
        "traversal marker must not be created: %s" % path
    # ...and nothing was left behind at the escape target either.
    assert _raw(s3_url, "HEAD", "/%s/" % name) != 200


def test_directory_without_marker_slash_still_404(s3_url):
    # The 200 is scoped to the marker FORM. A key that merely resolves to a
    # directory is not an object and must stay 404 NoSuchKey, or every prefix
    # would stat as a zero-byte file and sd_remote would classify folders as
    # regular files.
    url = _folder(s3_url)
    assert requests.put(url, data=b"", timeout=10).status_code == 200

    bare = url.rstrip("/")
    h = requests.head(bare, timeout=10)
    assert h.status_code == 404, \
        f"a directory without the marker slash must be 404, got {h.status_code}"

    g = requests.get(bare, timeout=10)
    assert g.status_code == 404, \
        f"GET of a directory key must be 404, got {g.status_code}"
    assert "NoSuchKey" in g.text, g.text
