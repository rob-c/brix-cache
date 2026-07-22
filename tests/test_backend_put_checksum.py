"""
Outbound commit-leg origin-enforced integrity — brix_backend_put_checksum (#12).

THE GAP: when a brix node commits a staged object to an S3 origin, AWS SigV4
signs the body as the literal string UNSIGNED-PAYLOAD (the signature covers only
the headers), and the driver sent no Content-MD5.  So a byte flipped on the
node->origin hop by a hostile/flaky network sails past: the signature still
verifies, the origin stores the corrupted body and answers 200, and the node
commits the poison as a complete object.  Content-Length framing defends against
TRUNCATION on this leg, but nothing defended against CORRUPTION.

THE FIX (opt-in, fail-closed once enabled): "s3://host/bucket?put_checksum=1"
makes every commit PUT (and MPU UploadPart) carry a SIGNED x-amz-checksum-crc32
computed over the exact bytes the node intends to store.  A compliant origin
(here this repo's own brix_s3 server, protocols/s3/checksum.c) re-computes CRC-32
over the body it received and rejects a mismatch with 400 BadDigest — so an
in-flight bit flip fails the commit instead of publishing silent poison.  Off by
default (UNSIGNED-PAYLOAD parity) so origins that reject unknown checksum headers
keep working untouched.

TOPOLOGY (one nginx, three planes — nginx_root_s3_putck.conf):

    native pgwrite ->  brix_root node  ->  _BodyCorruptProxy  ->  brix_s3 origin
                       (:PORT knob ON /                            (validates
                        :PORT_OFF knob OFF)                         crc32)

The corruptor flips ONE body byte with the SigV4 headers left intact (a surgical
version of brix-fault-proxy's random `corrupt up`, made deterministic so the
knob-ON-rejects / knob-OFF-poisons contrast never flakes): the object carries a
unique marker and the flip lands on the byte right after it — always in the PUT
body, never in a signed header.

CONTRACT (driven over the native root:// wire via the test_pgwrite_cse helpers):
  * knob ON, clean link         -> commit succeeds, object byte-exact   [no FP]
  * knob ON, one body byte flip -> BadDigest, commit FAILS, no poison   [catch]
  * knob OFF, same body flip     -> commit "succeeds", corrupt object in
                                    the store (the silent poison #12 closes) [gap]

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_backend_put_checksum.py -v -p no:xdist
"""

import os
import socket
import threading
import time

import pytest

from settings import BIND_HOST, HOST, NGINX_BIN, SERVER_HOST
from fleet_lifecycle_ports import lifecycle_ports_for
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

# Reuse the battle-tested native pgwrite wire client verbatim (as the staged
# sync-gate test does): a staged s3:// backend commits the whole object as one
# PUT at close, which is the outbound leg under test.
from test_pgwrite_cse import (
    _handshake_login,
    _open,
    _close,
    send_pgwrite,
    build_payload,
    kXR_ok,
    kXR_error,
    kXR_status,
)

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-putck")]

S3_AK = "AKIDBACKENDPUTCK01"
S3_SK = "YmFja2VuZC1wdXQtY2hlY2tzdW0tc2VjcmV0LWZvci10ZXN0"

# A body-only marker: 28 bytes that cannot occur in a SigV4 header line, so the
# corruptor's flip always lands in the PUT body, never in a signed header.
MARKER = b"BRIX-PUTCK-MARKER-0123456789"


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


class _BodyCorruptProxy:
    """A deterministic TCP splice between the brix node and the S3 origin that,
    while armed, flips exactly ONE byte in the PUT body — the byte right after
    MARKER — leaving every SigV4 header untouched.  This is the surgical,
    non-flaky analogue of `brix-fault-proxy corrupt up`: an on-path bit flip the
    node's application layer must catch."""

    def __init__(self, target_host, target_port):
        self.target_host = target_host
        self.target_port = target_port
        self.listen = _free_port()
        self._lock = threading.Lock()
        self._flip_budget = 0
        self._srv = None
        self._stop = threading.Event()

    # arm/disarm are per-test: one armed flip is consumed by the single commit PUT.
    def arm(self):
        with self._lock:
            self._flip_budget = 1

    def disarm(self):
        with self._lock:
            self._flip_budget = 0

    def _has_budget(self):
        with self._lock:
            return self._flip_budget > 0

    def _consume_flip(self):
        with self._lock:
            if self._flip_budget > 0:
                self._flip_budget -= 1
                return True
            return False

    def _pump_up(self, src, dst):
        """node->origin: forward each chunk IMMEDIATELY (never withhold a tail, or
        a keepalive HEAD's trailing bytes would stall the origin), while flipping
        the single body byte right after MARKER when armed.  A one-past-the-end
        marker (ending exactly on a chunk boundary) flips the next chunk's first
        byte; a rolling `tail` catches a marker split across two recv() chunks."""
        M = len(MARKER)
        tail = b""            # last M-1 bytes already forwarded
        flip_next = False     # marker ended on the prior chunk boundary
        try:
            while not self._stop.is_set():
                data = src.recv(65536)
                if not data:
                    break
                data = bytearray(data)
                if flip_next:
                    if self._consume_flip():
                        data[0] ^= 0x01
                    flip_next = False
                elif self._has_budget():
                    hay = tail + bytes(data)
                    i = hay.find(MARKER)
                    if i != -1:
                        pos = i + M - len(tail)   # post-marker byte, indexed in data
                        if 0 <= pos < len(data):
                            if self._consume_flip():
                                data[pos] ^= 0x01
                        elif pos == len(data):
                            flip_next = True
                dst.sendall(bytes(data))
                tail = (tail + bytes(data))[-(M - 1):]
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _pump_down(self, src, dst):
        try:
            while not self._stop.is_set():
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _handle(self, client):
        try:
            upstream = socket.create_connection(
                (self.target_host, self.target_port), timeout=5)
        except OSError:
            client.close()
            return
        tu = threading.Thread(target=self._pump_up, args=(client, upstream),
                              daemon=True)
        td = threading.Thread(target=self._pump_down, args=(upstream, client),
                              daemon=True)
        tu.start(); td.start()
        tu.join(); td.join()
        client.close(); upstream.close()

    def _serve(self):
        while not self._stop.is_set():
            try:
                client, _ = self._srv.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,),
                             daemon=True).start()

    def start(self):
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((BIND_HOST, self.listen))
        self._srv.listen(16)
        threading.Thread(target=self._serve, daemon=True).start()

    def stop(self):
        self._stop.set()
        try:
            self._srv.close()
        except OSError:
            pass


@pytest.fixture(scope="module")
def node(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    # The S3 origin's posix root must exist (with the bucket dir) at parse;
    # committed objects land FLAT under it (the posix root IS the bucket root).
    s3_dir = tmp_path_factory.mktemp("s3store")
    (s3_dir / "testbucket").mkdir()
    # The knob-OFF server needs its OWN export root: the storage-backend registry
    # is keyed by canonical root, so sharing the knob-ON server's DATA_ROOT would
    # collide on one entry (last registration — put_checksum off — wins for both).
    off_root = tmp_path_factory.mktemp("offroot")
    # S3_PORT (S3 origin plane) and PORT_OFF (knob-off server) are embedded
    # listens owned by the lifecycle ledger (fleet_lifecycle_ports.root-s3-putck);
    # read them up-front because the body-corrupt proxy targets S3_PORT before the
    # server starts.  CORRUPT_PORT (the proxy's own bind) stays a dynamic mock port.
    _putck_extra = lifecycle_ports_for("root-s3-putck")[1]
    s3_port = _putck_extra["S3_PORT"]
    port_off = _putck_extra["PORT_OFF"]

    # The corruptor listens on CORRUPT_PORT (referenced in the node backend URIs
    # at parse) and forwards to the S3 origin plane on S3_PORT.
    proxy = _BodyCorruptProxy(BIND_HOST, s3_port)

    harness = LifecycleHarness()
    endpoint = harness.start(NginxInstanceSpec(
        name="root-s3-putck",
        template="nginx_root_s3_putck.conf",
        protocol="root",
        readiness="tcp",
        extra_ports={"S3_PORT": s3_port,
                     "CORRUPT_PORT": proxy.listen,
                     "PORT_OFF": port_off},
        template_values={"BIND_HOST": BIND_HOST,
                         "S3_DIR": str(s3_dir),
                         "OFF_ROOT": str(off_root),
                         "S3_ACCESS_KEY": S3_AK,
                         "S3_SECRET_KEY": S3_SK},
    ))
    proxy.start()

    # readiness waits on the knob-ON root {PORT}; poll the other two planes too.
    for _ in range(50):
        if _port_up(HOST, s3_port) and _port_up(HOST, port_off) \
                and _port_up(HOST, proxy.listen):
            break
        time.sleep(0.1)

    yield {"port_on": endpoint.port, "port_off": port_off,
           "store": s3_dir, "proxy": proxy}
    proxy.stop()
    harness.close()


def _store_objects(node):
    """Committed object files in the store (the pre-created testbucket dir is not
    an object)."""
    root = node["store"]
    return {n for n in os.listdir(root) if (root / n).is_file()}


def _obj_bytes(node, name):
    return (node["store"] / name).read_bytes()


def _write_object(port, key, data):
    """Native pgwrite the whole object then close -> the staged s3 backend commits
    it as one signed PUT.  Returns the close (status, errcode)."""
    sock = _handshake_login(host=SERVER_HOST, port=port)
    try:
        fh = _open(sock, key)
        st, off, cse = send_pgwrite(sock, fh, 0, build_payload(data, 0))
        assert st == kXR_status and cse == b"", \
            f"staged pgwrite append should succeed, got status={st} cse={cse!r}"
        return _close(sock, fh)
    finally:
        sock.close()


# --- tests --------------------------------------------------------------------

def test_clean_link_commit_is_byte_exact(node):
    """SUCCESS / no false positive: knob ON over a CLEAN link — the signed
    x-amz-checksum-crc32 is well-formed and ACCEPTED by the validating origin, the
    commit succeeds and the stored object is byte-exact.  (A wrong CRC, base64, or
    SigV4 fold would make the origin reject even this clean upload.)"""
    node["proxy"].disarm()
    before = _store_objects(node)

    good = MARKER + os.urandom(6000)
    st, err = _write_object(node["port_on"], b"/putck-clean.bin", good)
    assert st == kXR_ok, f"clean knob-ON commit must succeed, got status={st} err={err}"

    new = _store_objects(node) - before
    assert len(new) == 1, f"exactly one object should be published, got {new}"
    assert _obj_bytes(node, new.pop()) == good, "committed object must be byte-exact"


def test_knob_on_body_corruption_is_rejected(node):
    """ERROR / the guarantee: knob ON, one body byte flipped in flight — the origin
    re-computes CRC-32 over the received body, it disagrees with the signed
    x-amz-checksum-crc32, and it answers 400 BadDigest.  The node's commit FAILS
    (not kXR_ok) and NO poison object is left behind."""
    proxy = node["proxy"]
    before = _store_objects(node)

    good = MARKER + os.urandom(6000)
    proxy.arm()
    try:
        st, err = _write_object(node["port_on"], b"/putck-corrupt-on.bin", good)
    finally:
        proxy.disarm()

    assert st == kXR_error, \
        f"a body-corrupted knob-ON commit must fail (BadDigest), got status={st}"
    # The origin unlinks on BadDigest and the node commit failed: no new object,
    # and certainly no corrupt-but-blessed one.
    after = _store_objects(node)
    for name in (after - before):
        assert _obj_bytes(node, name) == good, \
            "knob ON must never leave a corrupt object in the store"


def test_knob_off_body_corruption_commits_silent_poison(node):
    """SECURITY-NEG / the gap the knob closes: knob OFF, the SAME one-byte body
    flip.  SigV4 signs UNSIGNED-PAYLOAD and no Content-MD5 is sent, so the origin
    has nothing to check — it stores the corrupted body, answers 200, and the node
    commits it.  The object in the store DIFFERS from what was written: silent
    poison.  This is exactly what put_checksum=1 (the test above) prevents."""
    proxy = node["proxy"]
    before = _store_objects(node)

    good = MARKER + os.urandom(6000)
    proxy.arm()
    try:
        st, err = _write_object(node["port_off"], b"/putck-corrupt-off.bin", good)
    finally:
        proxy.disarm()

    assert st == kXR_ok, \
        f"knob OFF accepts UNSIGNED-PAYLOAD, commit should 'succeed', got {st}/{err}"

    new = _store_objects(node) - before
    assert len(new) == 1, f"knob OFF should have committed one object, got {new}"
    committed = _obj_bytes(node, new.pop())
    assert committed != good, (
        "knob OFF should have committed SILENT POISON (corrupt body accepted as a "
        "good object) — the outbound-corruption gap #12 closes; if this is equal, "
        "the corruptor did not flip a body byte")
    assert len(committed) == len(good), \
        "the flip is a single-byte mutation, not a truncation"
