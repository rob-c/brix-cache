# tests/test_cvmfs_mock.py
import hashlib, json, os, subprocess, sys, time, urllib.request, urllib.error
import pytest

PORT = 12811
BASE = f"http://127.0.0.1:{PORT}"
# conftest chdir()s into a scratch dir at session start — resolve the mock
# script against this file, never the cwd.
MOCK = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "cvmfs", "mock_stratum1.py")

@pytest.fixture(scope="module")
def mock():
    p = subprocess.Popen([sys.executable, MOCK,
                          "--port", str(PORT), "--repo", "test.cern.ch",
                          "--objects", "8", "--seed", "42"])
    for _ in range(50):
        try:
            urllib.request.urlopen(BASE + "/ctl/log", timeout=0.2); break
        except Exception:
            time.sleep(0.1)
    yield BASE
    p.terminate(); p.wait()

def _objects(base):
    return json.load(urllib.request.urlopen(base + "/ctl/objects"))

def test_cas_object_name_is_sha1_of_body(mock):
    for url in _objects(mock)[:3]:
        body = urllib.request.urlopen(mock + url).read()
        hexd = url.rsplit("/", 2)[-2] + url.rsplit("/", 2)[-1]
        hexd = hexd.rstrip("C")                      # catalog suffix
        assert hashlib.sha1(body).hexdigest() == hexd

def test_manifest_present_and_bumpable(mock):
    m1 = urllib.request.urlopen(mock + "/cvmfs/test.cern.ch/.cvmfspublished").read()
    urllib.request.urlopen(mock + "/ctl/manifest/bump")
    m2 = urllib.request.urlopen(mock + "/cvmfs/test.cern.ch/.cvmfspublished").read()
    assert m1 != m2

def test_fault_corrupt_flips_bytes_once(mock):
    url = _objects(mock)[0]
    good = urllib.request.urlopen(mock + url).read()
    req = urllib.request.Request(mock + "/ctl/fault", method="POST",
        data=json.dumps({"mode": "corrupt", "count": 1}).encode())
    urllib.request.urlopen(req)
    bad = urllib.request.urlopen(mock + url).read()
    assert bad != good and len(bad) == len(good)
    assert urllib.request.urlopen(mock + url).read() == good   # fault consumed

def test_fault_reset_drops_connection(mock):
    url = _objects(mock)[0]
    req = urllib.request.Request(mock + "/ctl/fault", method="POST",
        data=json.dumps({"mode": "reset", "count": 1}).encode())
    urllib.request.urlopen(req)
    with pytest.raises(Exception):
        urllib.request.urlopen(mock + url, timeout=3).read()

def test_request_log_records_paths(mock):
    url = _objects(mock)[1]
    urllib.request.urlopen(mock + url).read()
    log = json.load(urllib.request.urlopen(mock + "/ctl/log"))
    assert any(e["path"] == url for e in log)

def test_geo_api_returns_server_order(mock):
    r = urllib.request.urlopen(
        mock + "/cvmfs/test.cern.ch/api/v1.0/geo/x/a.cern.ch,b.cern.ch").read()
    assert r.strip() in (b"1,2", b"2,1")
