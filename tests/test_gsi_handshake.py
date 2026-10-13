import json
import socket
import struct
import threading
from contextlib import contextmanager
from pathlib import Path

from settings import HOST
from ephemeral_port import free_port

from split_continuation import reexport as _reexport
def _expression_1(proxy, pki):
    return (
        _split_for_curl(proxy, pki["base"], "wc") if proxy else (None, None)
    )

def _expression_2(cf, kf):
    return (
        cf and kf
    )


_reexport(globals(), "_test_gsi_handshake_helpers")

pytestmark = [*pytestmark, pytest.mark.xdist_group("test_gsi_handshake"),
              pytest.mark.timeout(150)]


def _recv_exact(connection, length):
    data = b""
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise ConnectionError("peer closed")
        data += chunk
    return data


def _recv_request(connection):
    header = _recv_exact(connection, 24)
    request_id = struct.unpack("!H", header[2:4])[0]
    length = struct.unpack("!I", header[20:24])[0]
    if length > 1024 * 1024:
        raise ConnectionError("request exceeds hostile-peer bound")
    body = _recv_exact(connection, length) if length else b""
    return header, request_id, body


class _GsiTranscriptFaultProxy:
    """Proxy a real GSI peer while falsifying its legacy transcript."""

    def __init__(self, backend_host, backend_port):
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((HOST, free_port(HOST)))
        self.listener.listen(32)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.closing = False
        self.thread = threading.Thread(target=self._accept, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.closing = True
        self.listener.close()
        self.thread.join(timeout=5)

    def _accept(self):
        while not self.closing:
            try:
                client, _address = self.listener.accept()
            except (OSError, socket.timeout):
                continue
            threading.Thread(target=self._serve, args=(client,),
                             daemon=True).start()

    @staticmethod
    def _corrupt_login_challenge(body, request_id):
        if request_id != 3007 or len(body) < 16:
            return body
        altered = bytearray(body)
        terminator = altered.find(0, 16)
        end = terminator if terminator >= 0 else len(altered)
        if end > 16:
            altered[end - 1] = 0x7f
        return bytes(altered)

    @staticmethod
    def _premature_auth_success(response, body, request_id, first_auth):
        consumed = request_id == 3000 and first_auth
        if not consumed:
            return response, body, False
        stream_id = response[:2]
        return stream_id + struct.pack("!HI", 0, 0), b"", True

    @classmethod
    def _forward_response(cls, backend, client, request_id, first_auth):
        response = _recv_exact(backend, 8)
        status = struct.unpack("!H", response[2:4])[0]
        length = struct.unpack("!I", response[4:8])[0]
        body = _recv_exact(backend, length) if length else b""
        body = cls._corrupt_login_challenge(body, request_id)
        response, body, consumed = cls._premature_auth_success(
            response, body, request_id, first_auth,
        )
        client.sendall(response + body)
        return status, consumed

    def _serve(self, client):
        backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        backend.settimeout(5)
        first_auth = True
        try:
            backend.connect((self.backend_host, self.backend_port))
            handshake = _recv_exact(client, 20)
            backend.sendall(handshake)
            client.sendall(_recv_exact(backend, 16))
            while not self.closing:
                header, request_id, body = _recv_request(client)
                backend.sendall(header + body)
                _status, consumed = self._forward_response(
                    backend, client, request_id, first_auth,
                )
                if consumed:
                    first_auth = False
        except (ConnectionError, OSError, struct.error):
            return
        finally:
            backend.close()
            client.close()


@contextmanager
def _gsi_transcript_fault_peer(target):
    parsed = target.removeprefix("root://").split("/", 1)[0]
    host, port = parsed.rsplit(":", 1)
    with _GsiTranscriptFaultProxy(host, int(port)) as proxy:
        yield f"root://{HOST}:{proxy.port}"


class _SigverFaultProxy(_GsiTranscriptFaultProxy):
    """Keep real GSI crypto, but falsify one post-auth signing outcome."""

    def __init__(self, backend_host, backend_port, clause):
        super().__init__(backend_host, backend_port)
        self.clause = clause

    @staticmethod
    def _error(stream_id):
        body = struct.pack("!I", 3022) + b"controlled sigver fault\x00"
        return stream_id + struct.pack("!HI", 4003, len(body)) + body

    @staticmethod
    def _success(stream_id, request_id):
        if request_id == 3017:
            body = b"0 20 0 0\x00"
        elif request_id == 3013:
            body = b"x"
        else:
            body = b""
        return stream_id + struct.pack("!HI", 0, len(body)) + body

    def _read_response(self, backend, request_id):
        response = _recv_exact(backend, 8)
        length = struct.unpack("!I", response[4:8])[0]
        body = _recv_exact(backend, length) if length else b""
        if self.clause == "SIG-010" and request_id == 3006 \
                and len(body) >= 12 and body[8] == ord("S"):
            altered = bytearray(body)
            altered[11] |= 0x02
            body = bytes(altered)
        return response[:4] + struct.pack("!I", len(body)) + body

    def _rewrite_covered(self, response, request_id, pending):
        handler = getattr(self, "_rewrite_" + self.clause.replace("-", "_"), None)
        return handler(response, request_id, pending) if handler else response

    def _rewrite_SIG_001(self, response, request_id, pending):
        if not pending and request_id == 3017:
            return self._success(response[:2], request_id)
        return response

    def _rewrite_SIG_002(self, response, request_id, pending):
        if pending and request_id == 3017:
            return self._error(response[:2])
        return response

    def _rewrite_SIG_003(self, response, request_id, pending):
        if pending and pending["expectrid"] != request_id:
            return self._success(response[:2], request_id)
        return response

    def _rewrite_SIG_005(self, response, request_id, pending):
        del request_id
        if pending and pending["sequence"] == 1 << 40:
            return self._error(response[:2])
        return response

    def _rewrite_SIG_006(self, response, request_id, pending):
        del request_id
        if pending and pending["flags"] & 0x01:
            return self._error(response[:2])
        return response

    def _rewrite_SIG_009(self, response, request_id, pending):
        del pending
        if request_id == 3013:
            return self._success(response[:2], request_id)
        return response

    def _rewrite_invalid_prefix(self, response, version, crypto, replay):
        if ((self.clause == "SIG-004" and replay)
                or (self.clause == "SIG-007" and crypto != 0x01)
                or (self.clause == "SIG-008" and version != 0)):
            return self._success(response[:2], 3029)
        return response

    @staticmethod
    def _prefix_state(header, last_sequence):
        version = header[6]
        flags = header[7]
        sequence = struct.unpack("!Q", header[8:16])[0]
        crypto = header[16]
        replay = sequence <= last_sequence
        pending = {
            "expectrid": struct.unpack("!H", header[4:6])[0],
            "flags": flags,
            "sequence": sequence,
        }
        return version, crypto, replay, sequence, pending

    def _forward_prefix(self, backend, client, header, last_sequence):
        version, crypto, replay, sequence, pending = self._prefix_state(
            header, last_sequence,
        )
        if version == 0 and crypto == 0x01 and not replay:
            return pending, sequence
        response = self._read_response(backend, 3029)
        client.sendall(self._rewrite_invalid_prefix(
            response, version, crypto, replay,
        ))
        return None, last_sequence

    def _forward_covered(self, backend, client, request_id, pending):
        response = self._read_response(backend, request_id)
        client.sendall(self._rewrite_covered(response, request_id, pending))

    def _serve(self, client):
        backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(8)
        backend.settimeout(8)
        pending = None
        last_sequence = 0
        try:
            backend.connect((self.backend_host, self.backend_port))
            handshake = _recv_exact(client, 20)
            backend.sendall(handshake)
            client.sendall(_recv_exact(backend, 16))
            while not self.closing:
                header, request_id, body = _recv_request(client)
                backend.sendall(header + body)
                if request_id == 3029:
                    pending, last_sequence = self._forward_prefix(
                        backend, client, header, last_sequence,
                    )
                    continue
                self._forward_covered(backend, client, request_id, pending)
                pending = None
        except (ConnectionError, OSError, struct.error):
            return
        finally:
            backend.close()
            client.close()


@contextmanager
def _sigver_fault_peer(target, clause):
    parsed = target.removeprefix("root://").split("/", 1)[0]
    host, port = parsed.rsplit(":", 1)
    with _SigverFaultProxy(host, int(port), clause) as proxy:
        yield f"root://{HOST}:{proxy.port}"

def _rejected(http_code):
    """A WebDAV auth rejection is any non-2xx outcome — the request was refused
    by the TLS/cert layer (400), the access phase (401/403), or curl failed the
    handshake outright (000).  The only failure that matters is being *served*."""
    code = (http_code or "").strip()
    return bool(code) and not code.startswith("2")


@pytest.fixture(scope="module")
def sigver_conform_results(pki, nginx_root_sigver, tmp_path_factory):
    """Run the Phase-118 active-signing ledger against a real GSI session."""
    xrd = Path(REPO) / "client" / "bin" / "xrd"
    output = tmp_path_factory.mktemp("xrd-conform-gsi-sigver")
    target = nginx_root_sigver["url"] + "//hello.txt"

    assert xrd.exists(), "native client/bin/xrd must be built (make -C client)"
    result = _run(
        [str(xrd), "conform", "accept", target, "--auth", "gsi",
         "--families", "SIG", "--fail-on", "divergent",
         "--wall-seconds", "60", "--request-limit", "128",
         "--byte-limit", "1048576", "--out", str(output)],
        env=pki["env"])
    assert result.returncode == 0, result.stderr + result.stdout
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return {row["id"]: row for row in report["results"]}


def test_conform_sigver_serves_valid_signed_shapes(sigver_conform_results):
    """Success: signed shapes work and bound streams retain signing policy."""
    for clause in ("SIG-002", "SIG-005", "SIG-006", "SIG-009"):
        assert sigver_conform_results[clause]["verdict"] == "conformant"


def test_conform_sigver_refuses_unsigned_and_malformed_shapes(
        sigver_conform_results):
    """Security-negative: unsigned, mismatched, replayed and unknown forms fail."""
    for clause in ("SIG-001", "SIG-003", "SIG-004", "SIG-007", "SIG-008"):
        assert sigver_conform_results[clause]["verdict"] == "conformant"


def test_conform_sigver_does_not_green_unavailable_crosses(
        sigver_conform_results):
    """Error honesty: an unadvertised signing option is claim-skipped."""
    assert sigver_conform_results["SIG-010"]["verdict"] == "skipped"
    assert sigver_conform_results["SIG-010"]["reason"] == \
        "claim-absent:secOFrce"


@pytest.mark.parametrize("clause", ("LOG-009", "LOG-010", "LOG-011",
                                    "LOG-012"))
def test_conform_rejects_falsified_legacy_gsi_transcript(
        clause, pki, nginx_root_sigver, tmp_path):
    """Security-negative: a round-one success cannot forge GSI evidence."""
    xrd = Path(REPO) / "client" / "bin" / "xrd"
    output = tmp_path / clause.lower()
    with _gsi_transcript_fault_peer(nginx_root_sigver["url"]) as peer:
        result = _run(
            [str(xrd), "conform", "accept", peer + "//hello.txt",
             "--auth", "gsi", "--families", "LOG", "--only", clause,
             "--verify-negative", clause, "--fail-on", "divergent",
             "--wall-seconds", "30", "--request-limit", "96",
             "--byte-limit", "1048576", "--out", str(output)],
            env=pki["env"])
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    rows = {row["id"]: row for row in report["results"]}
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[clause]["verdict"] == "divergent", rows[clause]
    assert f"verify-negative={clause} result=passed" in result.stdout


@pytest.mark.parametrize("clause", tuple(f"SIG-{index:03d}"
                                         for index in range(1, 11)))
def test_conform_detects_hostile_sigver_peer(
        clause, pki, nginx_root_sigver, tmp_path):
    """Security-negative: each signing contract has executable red evidence."""
    xrd = Path(REPO) / "client" / "bin" / "xrd"
    output = tmp_path / clause.lower()
    with _sigver_fault_peer(nginx_root_sigver["url"], clause) as peer:
        result = _run(
            [str(xrd), "conform", "accept", peer + "//hello.txt",
             "--auth", "gsi", "--families", "SIG", "--only", clause,
             "--verify-negative", clause, "--fail-on", "divergent",
             "--wall-seconds", "45", "--request-limit", "128",
             "--byte-limit", "1048576", "--out", str(output)],
            env=pki["env"])
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    rows = {row["id"]: row for row in report["results"]}
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[clause]["verdict"] == "divergent", rows[clause]
    assert f"verify-negative={clause} result=passed" in result.stdout


def _curl(pki, webdav, proxy, *args, method=None, upload=None):
    cf, kf = _expression_1(proxy, pki)
    cmd = ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}"]
    if _expression_2(cf, kf):
        cmd += ["--cert", cf, "--key", kf]
    if method:
        cmd += ["-X", method]
    if upload:
        cmd += ["-T", upload]
    cmd += list(args)
    return _run(cmd)



class TestRootStockClient:
    def test_ls(self, pki, nginx_root):
        r = _run([STOCK_XRDFS, nginx_root["url"], "ls", "/"], env=pki["env"])
        assert r.returncode == 0, f"{nginx_root['policy']}: {r.stderr}"
        assert "/hello.txt" in r.stdout

    def test_stat(self, pki, nginx_root):
        r = _run([STOCK_XRDFS, nginx_root["url"], "stat", "/hello.txt"],
                 env=pki["env"])
        assert r.returncode == 0, f"{nginx_root['policy']}: {r.stderr}"
        assert "Size" in r.stdout or "size" in r.stdout.lower()

    def test_read(self, pki, nginx_root, tmp_path):
        out = str(tmp_path / f"dl_{nginx_root['policy']}")
        r = _run([STOCK_XRDCP, "-f", f"{nginx_root['url']}//hello.txt", out],
                 env=pki["env"])
        assert r.returncode == 0, f"{nginx_root['policy']}: {r.stderr}"
        assert open(out).read() == "hello-gsi-handshake\n"

    def test_write_then_read(self, pki, nginx_root, tmp_path):
        src = str(tmp_path / "up.txt")
        payload = f"signed={nginx_root['policy']}-roundtrip\n" * 8
        open(src, "w").write(payload)
        key = f"/up_stock_{nginx_root['policy']}.txt"
        up = _run([STOCK_XRDCP, "-f", src, f"{nginx_root['url']}/{key}"],
                  env=pki["env"])
        assert up.returncode == 0, f"upload {nginx_root['policy']}: {up.stderr}"
        back = str(tmp_path / "back.txt")
        dl = _run([STOCK_XRDCP, "-f", f"{nginx_root['url']}/{key}", back],
                  env=pki["env"])
        assert dl.returncode == 0, f"download {nginx_root['policy']}: {dl.stderr}"
        assert open(back).read() == payload

    def test_large_write_then_read(self, pki, nginx_root, tmp_path):
        # 5 MiB: the session cipher must hold over thousands of AES-CBC blocks
        # in BOTH directions, not just the tiny single-block proxy-chain main.
        src = str(tmp_path / "big.bin")
        blob = _big(src, 5 * 1024 * 1024)
        key = f"/big_stock_{nginx_root['policy']}.bin"
        up = _run([STOCK_XRDCP, "-f", src, f"{nginx_root['url']}/{key}"],
                  env=pki["env"])
        assert up.returncode == 0, f"big upload {nginx_root['policy']}: {up.stderr}"
        back = str(tmp_path / "bigback.bin")
        dl = _run([STOCK_XRDCP, "-f", f"{nginx_root['url']}/{key}", back],
                  env=pki["env"])
        assert dl.returncode == 0, f"big download: {dl.stderr}"
        assert open(back, "rb").read() == blob

    def test_mkdir_stat_rmdir(self, pki, nginx_root):
        d = f"/dir_stock_{nginx_root['policy']}"
        u = pki["env"]
        assert _run([STOCK_XRDFS, nginx_root["url"], "mkdir", d],
                    env=u).returncode == 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "stat", d],
                    env=u).returncode == 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "rmdir", d],
                    env=u).returncode == 0
        # gone now
        assert _run([STOCK_XRDFS, nginx_root["url"], "stat", d],
                    env=u).returncode != 0

    def test_mv_then_rm(self, pki, nginx_root, tmp_path):
        src = str(tmp_path / "mv.txt")
        open(src, "w").write("mv-payload\n")
        a = f"/mv_a_{nginx_root['policy']}.txt"
        b = f"/mv_b_{nginx_root['policy']}.txt"
        u = pki["env"]
        assert _run([STOCK_XRDCP, "-f", src, f"{nginx_root['url']}/{a}"],
                    env=u).returncode == 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "mv", a, b],
                    env=u).returncode == 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "stat", b],
                    env=u).returncode == 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "stat", a],
                    env=u).returncode != 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "rm", b],
                    env=u).returncode == 0

    def test_query_checksum(self, pki, nginx_root):
        r = _run([STOCK_XRDFS, nginx_root["url"], "query", "checksum",
                  "/hello.txt"], env=pki["env"])
        assert r.returncode == 0, f"query checksum: {r.stderr}"
        # the response is "<algo> <hexdigest>"
        assert len(r.stdout.split()) >= 2, f"unexpected checksum reply: {r.stdout!r}"


class TestRootNativeClient:
    def _skip_if_unbuilt(self):
        assert os.path.exists(NATIVE_XRDFS) and os.path.exists(NATIVE_XRDCP), \
            "native client/bin/xrd{fs,cp} must be built (make -C client)"

    def test_ls(self, pki, nginx_root):
        self._skip_if_unbuilt()
        r = _run([NATIVE_XRDFS, "--auth", "gsi", nginx_root["url"], "ls", "/"],
                 env=pki["env"])
        assert r.returncode == 0, f"{nginx_root['policy']}: {r.stderr}"
        assert "/hello.txt" in r.stdout

    def test_read(self, pki, nginx_root, tmp_path):
        self._skip_if_unbuilt()
        out = str(tmp_path / f"ndl_{nginx_root['policy']}")
        r = _run([NATIVE_XRDCP, "--auth", "gsi", "-f",
                  f"{nginx_root['url']}//hello.txt", out], env=pki["env"])
        assert r.returncode == 0, f"{nginx_root['policy']}: {r.stderr}"
        assert open(out).read() == "hello-gsi-handshake\n"

    def test_write_then_read(self, pki, nginx_root, tmp_path):
        self._skip_if_unbuilt()
        src = str(tmp_path / "nup.txt")
        payload = f"native={nginx_root['policy']}-roundtrip\n" * 8
        open(src, "w").write(payload)
        key = f"/up_native_{nginx_root['policy']}.txt"
        up = _run([NATIVE_XRDCP, "--auth", "gsi", "-f", src,
                   f"{nginx_root['url']}/{key}"], env=pki["env"])
        assert up.returncode == 0, f"upload {nginx_root['policy']}: {up.stderr}"
        back = str(tmp_path / "nback.txt")
        dl = _run([NATIVE_XRDCP, "--auth", "gsi", "-f",
                   f"{nginx_root['url']}/{key}", back], env=pki["env"])
        assert dl.returncode == 0, f"download {nginx_root['policy']}: {dl.stderr}"
        assert open(back).read() == payload

    def test_large_write_then_read(self, pki, nginx_root, tmp_path):
        self._skip_if_unbuilt()
        src = str(tmp_path / "nbig.bin")
        blob = _big(src, 5 * 1024 * 1024)
        key = f"/nbig_{nginx_root['policy']}.bin"
        up = _run([NATIVE_XRDCP, "--auth", "gsi", "-f", src,
                   f"{nginx_root['url']}/{key}"], env=pki["env"])
        assert up.returncode == 0, f"native big upload: {up.stderr}"
        back = str(tmp_path / "nbigback.bin")
        dl = _run([NATIVE_XRDCP, "--auth", "gsi", "-f",
                   f"{nginx_root['url']}/{key}", back], env=pki["env"])
        assert dl.returncode == 0, f"native big download: {dl.stderr}"
        assert open(back, "rb").read() == blob

    def test_mkdir_rmdir(self, pki, nginx_root):
        self._skip_if_unbuilt()
        d = f"/ndir_{nginx_root['policy']}"
        u = pki["env"]
        assert _run([NATIVE_XRDFS, "--auth", "gsi", nginx_root["url"],
                     "mkdir", d], env=u).returncode == 0
        assert _run([NATIVE_XRDFS, "--auth", "gsi", nginx_root["url"],
                     "stat", d], env=u).returncode == 0
        assert _run([NATIVE_XRDFS, "--auth", "gsi", nginx_root["url"],
                     "rmdir", d], env=u).returncode == 0


# --------------------------------------------------------------------------- #
# root:// — GSI authentication followed by an in-protocol TLS upgrade (roots://)
# --------------------------------------------------------------------------- #
class TestRootGsiTls:
    def test_stock_read_over_tls(self, pki, nginx_root_tls, tmp_path):
        out = str(tmp_path / "tls.txt")
        r = _run([STOCK_XRDCP, "-f", f"{nginx_root_tls['url']}//hello.txt", out],
                 env=pki["env"])
        assert r.returncode == 0, f"GSI+TLS read: {r.stderr}"
        assert open(out).read() == "hello-gsi-handshake\n"

    def test_stock_write_then_read_over_tls(self, pki, nginx_root_tls, tmp_path):
        src = str(tmp_path / "tlsup.bin")
        blob = _big(src, 2 * 1024 * 1024)
        key = "/tls_rt.bin"
        up = _run([STOCK_XRDCP, "-f", src, f"{nginx_root_tls['url']}/{key}"],
                  env=pki["env"])
        assert up.returncode == 0, f"GSI+TLS upload: {up.stderr}"
        back = str(tmp_path / "tlsback.bin")
        dl = _run([STOCK_XRDCP, "-f", f"{nginx_root_tls['url']}/{key}", back],
                  env=pki["env"])
        assert dl.returncode == 0, f"GSI+TLS download: {dl.stderr}"
        assert open(back, "rb").read() == blob


# --------------------------------------------------------------------------- #
# root:// — concurrent GSI handshakes (the ephemeral-DH keypool under load)
# --------------------------------------------------------------------------- #
class TestRootConcurrency:
    def test_many_concurrent_signed_handshakes(self, pki, nginx_root):
        # Fire N independent stat handshakes at once; the per-worker DH keypool
        # must answer every certreq without head-of-line blocking, for signed and
        # unsigned alike.
        import concurrent.futures as cf

        def one(_):
            return _run([STOCK_XRDFS, nginx_root["url"], "stat", "/hello.txt"],
                        env=pki["env"]).returncode

        with cf.ThreadPoolExecutor(max_workers=12) as ex:
            rcs = list(ex.map(one, range(12)))
        assert all(rc == 0 for rc in rcs), \
            f"{nginx_root['policy']}: concurrent handshakes failed: {rcs}"


# --------------------------------------------------------------------------- #
# root:// — protocol-version advertisement (the signed-vs-unsigned switch)
# --------------------------------------------------------------------------- #
class TestVersionAdvertisement:
    # off → unsigned v:10000; auto/require → signed-capable v:10600.
    EXPECT = {"off": "v:10000", "auto": "v:10600", "require": "v:10600"}

    def test_advertised_version_matches_policy(self, pki, nginx_root):
        env = dict(pki["env"], XrdSecDEBUG="3")
        # XrdSecDEBUG=3 dumps raw handshake bytes; decode tolerantly or the
        # subprocess text-mode reader throws UnicodeDecodeError.
        r = _run([STOCK_XRDFS, nginx_root["url"], "ls", "/"], env=env,
                 errors="replace")
        m = re.search(r"token='([^']*P=gsi[^']*)'", r.stdout + r.stderr)
        assert m, ("could not capture the advertised &P=gsi token from the "
                   f"stock client debug output:\n{(r.stdout + r.stderr)[:400]}")
        want = self.EXPECT[nginx_root["policy"]]
        assert want in m.group(1), \
            f"policy {nginx_root['policy']}: expected {want}, got {m.group(1)!r}"


# --------------------------------------------------------------------------- #
# root:// — identity (DN) extraction from the verified proxy chain
# --------------------------------------------------------------------------- #
_reexport(globals(), "_test_gsi_handshake_extended")
