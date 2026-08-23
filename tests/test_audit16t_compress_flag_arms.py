"""
tests/test_audit16t_compress_flag_arms.py — audit tranche 16, file 20: the
inline-compression pair of ``root/stream/directives_security.h`` at (directive,
value) granularity.

THE GAP
-------
Re-running the audit's Method steps 1-2 over ``ngx_conf_set_flag_slot``
directives at VALUE granularity leaves ``brix_read_compress`` and
``brix_write_compress`` with the same shape as every other row this tranche has
closed: ``on`` is spelled in three configs, ``off`` in none.  Not "covered by a
placeholder that could render to off" — spelled nowhere, in any form, in
``tests/`` ``conf/`` ``client/`` or ``k8s-tests/``.

That is not for want of a compression suite.  There are nineteen
``test_compression_*.py`` files and they are thorough about what compression
DOES.  Every one of them runs against the harness anon server, whose
``nginx_shared.conf`` writes both flags ``on`` — so the entire suite shares a
single configuration of the subject, and not one of its tests can ask what
``off`` restores, whether absence behaves as ``off``, or whether the two
directives are actually two.  The closest anything comes is
``test_compression_root_adversarial.py::test_qconfig_cmpread_advertises_codecs``,
which reads ``query config cmpread`` on the ``on`` plane and explicitly skips
when it finds the disabled form — it names ``cmpread=0`` only to rule it out.
``cmpwrite`` has no capability-query coverage at all.

WHAT THE FLAGS ACTUALLY GATE
----------------------------
One expression, in ``open_negotiate_compress_codec``
(``src/protocols/root/read/open_request_opaque.c:71``)::

    enabled = is_write ? conf->write_compress : conf->read_compress;
    if (!enabled || ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0)
    { return BRIX_CODEC_IDENTITY; }

and two emitters in ``src/protocols/root/query/config.c:221-256``, which answer
``cmpread=<codec CSV>`` / ``cmpwrite=<codec CSV>`` when the flag is on and the
literal ``cmpread=0`` / ``cmpwrite=0`` when it is off.

The negotiation is deliberately fail-soft: a disabled direction, a missing
``?xrootd.compress=`` opaque, and an unknown or unbuilt codec all return
``BRIX_CODEC_IDENTITY`` alike, so the open SUCCEEDS and serves plaintext rather
than failing.  That is the right call for an opt-in extension that stock peers
must never notice, and this file does not argue with it — but it does measure
its consequence, which is that "compression was refused" and "compression was
never asked for" are the same reply, and the only channel that distinguishes a
disabled server is the capability query.

WHY FOUR PLANES
---------------
``on/on`` reproduces the one configuration the corpus already had.  ``off/off``
is the arm nobody wrote.  The plane with NEITHER directive written measures the
merge default instead of reading it off ``server_conf_merge_security.c:310-311``.
The fourth is the point of the file: ``read on, write off`` is the only plane on
which the two flags are distinguishable at all.  A single shared bit, or the two
slot offsets transposed in the header, satisfies every both-on and both-off case
and is visible ONLY where the directions disagree.

All four are acceptors in one worker over ONE export, because the gate is read
per ``kXR_open`` out of the per-server conf: the same bytes on disk reached
through four servers really are four arms, and a difference in negotiated codec
cannot be a difference in file.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
Nothing here says inline compression should be off, that fail-soft is wrong, or
that the defaults are wrong.  Both flags defaulting to 0 is what keeps the
extension invisible to stock clients, which is its whole design.  Measured here
is what each value does, what absence does, that the two directives are
independent, and what an operator can and cannot see of a refusal.

Run:
    PYTHONPATH=tests pytest tests/test_audit16t_compress_flag_arms.py -v
"""

import os
import re
import subprocess
import uuid
from pathlib import Path

import pytest

from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN, url_host

# The wire layer is imported, never rebuilt.  _handshake_login is the only
# port-parameterised session helper in the suite (every compression module binds
# NGINX_ANON_PORT at module scope and so cannot serve a file that runs its own
# planes); _open there returns just the fhandle, so the open BODY — which is
# where the negotiation result lives — comes from the compression module, whose
# _open/_read/_close take a socket and are therefore port-agnostic already.
from _test_pgwrite_cse_helpers import _handshake_login
from test_compression_root_invariant import (
    CODEC_GZIP,
    INLINE_CMP_MAGIC,
    _close,
    _gunzip,
    _looks_gzip,
    _open,
    _read,
    kXR_ok,
    kXR_open_read,
)

def _expression_1(verb, line, base):
    return (
        verb in line and base in line
    )

def _expression_2(seen, deadline):
    return (
        seen or time.monotonic() >= deadline
    )

def _expression_3(path):
    return (
        not path.is_file() or path.suffix not in CORPUS_SUFFIXES
    )


def _guard_corpus_writers_1(text, directive, value, found, path):
    if _writes(text, directive, value):
        found.append(path.name)


pytestmark = [pytest.mark.timeout(900),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16t-compress")]

NAME = "lc-audit16t-compress"
_EXTRA = LIFECYCLE_SHARED_PORTS[NAME]["extra"]
OFF_PORT = _EXTRA["OFF_PORT"]
ABSENT_PORT = _EXTRA["ABSENT_PORT"]
MIXED_PORT = _EXTRA["MIXED_PORT"]

ROOT = Path(__file__).resolve().parents[1]
OPAQUE_C = ROOT / "src/protocols/root/read/open_request_opaque.c"
QCONFIG_C = ROOT / "src/protocols/root/query/config.c"
MERGE_C = ROOT / "src/core/config/server_conf_merge_security.c"
DIRECTIVES_H = ROOT / "src/protocols/root/stream/directives_security.h"
CONFIGS = Path(__file__).resolve().parent / "configs"
TEMPLATE = CONFIGS / "nginx_audit16t_compress.conf"

READ_DIRECTIVE = "brix_read_compress"
WRITE_DIRECTIVE = "brix_write_compress"

XRDCP = ROOT / "client" / "bin" / "xrdcp"
XRDFS = ROOT / "client" / "bin" / "xrdfs"

# Compressible but content-rich: repeating text guarantees a gzip frame is
# dramatically smaller than the plaintext, so "did compression engage" is never
# a question about a few bytes of framing overhead.
_LINE = b"the quick brown fox jumps over the lazy dog 0123456789\n"   # 54 bytes
PAYLOAD = _LINE * 3700                                                # ~200 KiB

# The corpus roots the audit's Method step 2 scans, and the suffixes that can
# carry an nginx directive.
CORPUS_ROOTS = ["tests", "conf", "client", "k8s-tests"]
CORPUS_SUFFIXES = {".conf", ".py", ".sh", ".template", ".yaml", ".yml", ".j2",
                   ".tmpl"}


def _writes(text, directive, value):
    """Whether ``text`` spells one arm of ``directive`` as a whole line.

    Whole-line and whitespace-tolerant on purpose.  The templates in this repo
    align their values into a column, so a naive ``"%s %s;" % (d, v) in text``
    misses every one of them; and a substring test would count the directive
    named inside a comment, which is how a config's own header would otherwise
    "cover" an arm it never writes.

    A trailing ``#`` comment still counts — ``nginx_shared.conf`` writes both
    ``on`` arms that way ("brix_read_compress on;   # phase-42 W4: ...").  The
    line is spelled; what must not count is the directive appearing ONLY inside
    a comment, which the leading anchor already excludes.
    """
    return re.search(rf"^\s*{directive}\s+{value}\s*;\s*(#.*)?$", text,
                     re.MULTILINE) is not None


def _writers_in_root(base, directive, value):
    if not base.exists():
        return []
    found = []
    for path in base.rglob("*"):
        if _expression_3(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        _guard_corpus_writers_1(text, directive, value, found, path)
    return found


def _corpus_writers(directive, value):
    """Every corpus file that spells ``<directive> <value>;`` as a whole line."""
    found = []
    for rel in CORPUS_ROOTS:
        found.extend(_writers_in_root(ROOT / rel, directive, value))
    return sorted(found)


def _source(path):
    return path.read_text(encoding="utf-8", errors="replace")


def _gates():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    if not os.access(XRDCP, os.X_OK):
        pytest.skip(f"xrdcp not built: {XRDCP}")
    if not os.access(XRDFS, os.X_OK):
        pytest.skip(f"xrdfs not built: {XRDFS}")


class _Planes:
    """The four acceptors, the one export they share, and their four logs."""

    def __init__(self, endpoint):
        self.endpoint = endpoint
        # The rendered LOG_DIR, which is the instance prefix's logs/ — NOT the
        # directory holding the rendered config, which is its sibling conf/.
        self.log_dir = Path(endpoint.prefix) / "logs"
        self.ports = {"on": endpoint.port,
                      "off": OFF_PORT,
                      "absent": ABSENT_PORT,
                      "mixed": MIXED_PORT}

    def base(self, plane):
        return f"root://{url_host(HOST)}:{self.ports[plane]}"

    def session(self, plane):
        return _handshake_login(url_host(HOST), self.ports[plane])

    def query_config(self, plane, key):
        """`xrdfs <plane> query config <key>` — the capability channel.

        Shelling out to the stock-compatible client rather than framing
        kXR_query by hand is deliberate: it is exactly how
        test_compression_root_adversarial.py reads cmpread today, so a
        difference between the two files can only be the plane, never the
        question.
        """
        proc = subprocess.run(
            [str(XRDFS), f"{url_host(HOST)}:{self.ports[plane]}",
             "query", "config", key],
            capture_output=True, text=True, timeout=60)
        return proc

    def upload(self, plane, local, remote, codec=None):
        cmd = [str(XRDCP), "-f"]
        if codec is not None:
            cmd += ["--compress", codec]
        cmd += [str(local), f"{self.base(plane)}{remote}"]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    def download(self, plane, remote, out):
        return subprocess.run(
            [str(XRDCP), "-f", f"{self.base(plane)}{remote}", str(out)],
            capture_output=True, text=True, timeout=120)

    def rm(self, plane, remote):
        subprocess.run([str(XRDFS), self.base(plane), "rm", remote],
                       capture_output=True, timeout=60)

    def accesslog(self, plane):
        path = self.log_dir / f"access-{plane}.log"
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return ""

    def _matching_log(self, plane, basename, verb):
        seen = False
        for line in self.accesslog(plane).splitlines():
            if _expression_1(verb, line, basename):
                seen = True
                if "z=" in line:
                    return True, True
        return seen, False

    def logged(self, plane, remote, verb, timeout=15.0):
        """Whether this plane logged ``verb`` for ``remote``, and with the
        compression marker.  Returns (seen, compressed).

        The marker is the "z=<wirebytes>" field both directions emit
        (read/read_compress.c:232, write/write_compress.c:188) — the same one
        test_compression_write.py reads off the shared anon log.  Here each
        plane has its own file, so an ABSENCE is attributable without parsing
        out which server a shared line came from.  Polls because the client
        exits before the worker has finished logging, and returns as soon as a
        matching record exists so a negative is a complete slice rather than
        one that is merely empty so far.
        """
        import time
        base = os.path.basename(remote)
        deadline = time.monotonic() + timeout
        while True:
            seen, compressed = self._matching_log(plane, base, verb)
            if compressed:
                return True, True
            if _expression_2(seen, deadline):
                return seen, False
            time.sleep(0.1)

    def wrote_compressed(self, plane, remote, timeout=15.0):
        return self.logged(plane, remote, "WRITE", timeout)

    def read_compressed(self, plane, remote, timeout=15.0):
        return self.logged(plane, remote, "READ", timeout)


@pytest.fixture
def planes(lifecycle, tmp_path):
    """One export, four acceptors, one uploaded payload."""
    _gates()
    data = tmp_path / "data"
    data.mkdir()
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit16t_compress.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST},
        reason="audit-16t brix_read_compress/brix_write_compress at value "
               "granularity"))
    yield _Planes(endpoint)


@pytest.fixture
def uploaded(planes, tmp_path):
    """The one payload every plane reads, put there once through the on plane."""
    local = tmp_path / "payload.bin"
    local.write_bytes(PAYLOAD)
    remote = f"/audit16t_{uuid.uuid4().hex}.bin"
    proc = planes.upload("on", local, remote)
    if proc.returncode != 0:
        pytest.skip(f"upload failed: {proc.stderr[:300]}")
    yield remote
    planes.rm("on", remote)


def _open_body(sock, path, flags=kXR_open_read):
    """kXR_open returning the FULL ServerResponseBody_Open.

    ``_open`` from the compression module already frames this; the wrapper
    exists only to assert the status and hand back the body, because every case
    below reads cpsize/cptype out of it rather than the fhandle.
    """
    _sid, status, body = _open(sock, path, flags)
    return status, body


def _negotiated(body):
    """(cpsize, codec ordinal) out of an open reply, or (None, None).

    ServerResponseBody_Open is fhandle[4] cpsize(int32 BE) cptype[4]; a reply
    that carries no compression block at all is shorter, and that is itself one
    of the answers, so a short body is reported rather than raising.
    """
    import struct
    if len(body) < 12:
        return None, None
    return struct.unpack("!i", body[4:8])[0], body[8]


# --------------------------------------------------------------------------- #
# A — the arms at config time
# --------------------------------------------------------------------------- #
class TestTheArmsAtConfigTime:
    """The gap this file closes is a fact about the corpus, so it is asserted
    against the corpus rather than described in a docstring."""

    def test_this_file_is_the_only_writer_of_off(self):
        """Before this file, neither directive's `off` arm was spelled anywhere.

        The whole justification for a new instance is that no existing config
        can be asked the question.  If some other file starts writing `off`,
        this test is how that becomes visible instead of silently making the
        instance redundant.
        """
        for directive in (READ_DIRECTIVE, WRITE_DIRECTIVE):
            writers = _corpus_writers(directive, "off")
            assert writers == ["nginx_audit16t_compress.conf"], (
                f"{directive} off is written by {writers}")

    def test_the_on_arm_was_already_written(self):
        """`on` is the arm the corpus had — the asymmetry that IS the gap."""
        for directive in (READ_DIRECTIVE, WRITE_DIRECTIVE):
            writers = _corpus_writers(directive, "on")
            assert "nginx_shared.conf" in writers, (
                f"{directive} on expected in the shared harness config; "
                f"writers={writers}")
            assert len(writers) >= 2, writers

    def test_the_template_spells_both_arms_literally(self):
        """Not through a placeholder.

        The audit counts an arm as covered only when `<directive> <value>;` is
        greppable in the corpus.  A `{SLOT}` that renders to `off` at runtime
        exercises the code path but leaves the corpus still never saying so, and
        the next census would report the same gap.  This is the assertion that
        keeps the closing work honest.
        """
        text = _source(TEMPLATE)
        for directive in (READ_DIRECTIVE, WRITE_DIRECTIVE):
            for value in ("on", "off"):
                assert _writes(text, directive, value), (
                    f"{directive} {value}; is not spelled literally")

    def test_the_template_writes_each_arm_the_expected_number_of_times(self):
        """Four planes, and exactly the arms the header promises.

        A whole-line scan, not a substring count: the file's own header names
        both directives many times over, and counting those would let a config
        that writes nothing at all appear fully armed.
        """
        text = _source(TEMPLATE)
        read_arms = re.findall(rf"^\s*{READ_DIRECTIVE}\s+(on|off)\s*;\s*$",
                               text, re.MULTILINE)
        write_arms = re.findall(rf"^\s*{WRITE_DIRECTIVE}\s+(on|off)\s*;\s*$",
                                text, re.MULTILINE)
        # on/on, off/off, (absent), on/off
        assert read_arms == ["on", "off", "on"], read_arms
        assert write_arms == ["on", "off", "off"], write_arms

    def test_the_absent_plane_writes_neither_directive(self):
        """The plane that measures the default must not accidentally set one."""
        text = _source(TEMPLATE)
        block = text.split("neither written")[1].split("mixed:")[0]
        assert READ_DIRECTIVE not in block, block
        assert WRITE_DIRECTIVE not in block, block


# --------------------------------------------------------------------------- #
# B — the capability query, which is the only channel that distinguishes a
#     disabled server
# --------------------------------------------------------------------------- #
class TestWhatTheServerAdvertises:

    def test_the_on_plane_advertises_a_codec_list_for_both_directions(self, planes):
        for key in ("cmpread", "cmpwrite"):
            proc = planes.query_config("on", key)
            if proc.returncode != 0:
                pytest.skip(f"xrdfs query config {key} failed: "
                            f"{proc.stderr[:200]}")
            out = proc.stdout.lower()
            assert "gzip" in out, (
                f"{key} on the armed plane advertised no codec list: {out!r}")

    def test_the_off_plane_advertises_the_disabled_form(self, planes):
        """`cmpread=0` / `cmpwrite=0` — the literal the C emits when the flag is
        off (query/config.c:227-231, 248-252).  This is the arm that had never
        been read: the existing cmpread test skips when it sees this."""
        for key in ("cmpread", "cmpwrite"):
            proc = planes.query_config("off", key)
            if proc.returncode != 0:
                pytest.skip(f"xrdfs query config {key} failed: "
                            f"{proc.stderr[:200]}")
            out = proc.stdout.strip().lower()
            assert "gzip" not in out, (
                f"{key} advertised codecs on a disabled plane: {out!r}")
            assert "0" in out, (
                f"{key} did not advertise the disabled form: {out!r}")

    def test_the_absent_plane_advertises_exactly_what_off_does(self, planes):
        """The merge default, measured rather than read off the merge file."""
        for key in ("cmpread", "cmpwrite"):
            off = planes.query_config("off", key)
            absent = planes.query_config("absent", key)
            if off.returncode != 0 or absent.returncode != 0:
                pytest.skip("xrdfs query config unavailable")
            assert absent.stdout.strip() == off.stdout.strip(), (
                f"{key}: absent={absent.stdout!r} off={off.stdout!r}")

    def test_the_mixed_plane_advertises_the_two_directions_differently(self, planes):
        """The case that proves the capability emitters read two distinct slots.

        Both emitters build their list from the same brix_qconfig_codec_list, so
        a transposition or a shared bit would leave them agreeing here.
        """
        read = planes.query_config("mixed", "cmpread")
        write = planes.query_config("mixed", "cmpwrite")
        if read.returncode != 0 or write.returncode != 0:
            pytest.skip("xrdfs query config unavailable")
        assert "gzip" in read.stdout.lower(), (
            f"mixed plane has read_compress on but advertised {read.stdout!r}")
        assert "gzip" not in write.stdout.lower(), (
            f"mixed plane has write_compress off but advertised "
            f"{write.stdout!r}")


# --------------------------------------------------------------------------- #
# C — the read direction, negotiated at open
# --------------------------------------------------------------------------- #
class TestTheReadDirection:

    def test_the_armed_plane_negotiates_a_codec(self, planes, uploaded):
        sock = planes.session("on")
        try:
            status, body = _open_body(
                sock, f"{uploaded}?xrootd.compress=gzip")
            assert status == kXR_ok, status
            cpsize, codec = _negotiated(body)
            assert cpsize == INLINE_CMP_MAGIC, (
                f"compression not negotiated: cpsize={cpsize}")
            assert codec == CODEC_GZIP, codec
        finally:
            sock.close()

    def test_the_disabled_plane_negotiates_nothing(self, planes, uploaded):
        """The arm nobody wrote: the SAME request, on the SAME bytes, refused."""
        sock = planes.session("off")
        try:
            status, body = _open_body(
                sock, f"{uploaded}?xrootd.compress=gzip")
            assert status == kXR_ok, (
                "a disabled direction must not fail the open — the negotiation "
                f"is fail-soft by design (status={status})")
            cpsize, codec = _negotiated(body)
            assert cpsize != INLINE_CMP_MAGIC, (
                f"read_compress off still negotiated a codec: cpsize={cpsize}")
        finally:
            sock.close()

    def test_the_absent_plane_negotiates_nothing_either(self, planes, uploaded):
        sock = planes.session("absent")
        try:
            status, body = _open_body(
                sock, f"{uploaded}?xrootd.compress=gzip")
            assert status == kXR_ok, status
            cpsize, _codec = _negotiated(body)
            assert cpsize != INLINE_CMP_MAGIC, (
                f"the merge default negotiated a codec: cpsize={cpsize}")
        finally:
            sock.close()

    def test_a_refusal_is_indistinguishable_from_never_asking(self, planes,
                                                              uploaded):
        """The measured consequence of fail-soft.

        A client that asked for compression on a disabled server gets byte-for-
        byte the open reply of a client that asked for nothing.  This is not a
        bug report — it is the reason the capability query in §B exists, and the
        reason a client is expected to consult it first.
        """
        sock = planes.session("off")
        try:
            _s1, asked = _open_body(sock, f"{uploaded}?xrootd.compress=gzip")
            _s2, plain = _open_body(sock, uploaded)
            assert _negotiated(asked) == _negotiated(plain), (
                f"asked={_negotiated(asked)} plain={_negotiated(plain)}")
        finally:
            sock.close()


# --------------------------------------------------------------------------- #
# D — the read direction, in bytes
# --------------------------------------------------------------------------- #
class TestTheBytesOnTheWire:

    def test_the_armed_plane_returns_a_gzip_frame(self, planes, uploaded):
        """Negotiation is not cosmetic: the read body really is a codec frame
        that inflates to the plaintext."""
        sock = planes.session("on")
        try:
            _s, body = _open_body(sock, f"{uploaded}?xrootd.compress=gzip")
            fhandle = body[:4]
            _sid, status, data = _read(sock, fhandle, 0, len(PAYLOAD))
            assert status == kXR_ok, status
            assert _looks_gzip(data), (
                f"read body is not a gzip frame: {data[:8]!r}")
            assert _gunzip(data) == PAYLOAD
            assert len(data) < len(PAYLOAD), (
                f"frame {len(data)} not smaller than plaintext {len(PAYLOAD)}")
            _close(sock, fhandle)
        finally:
            sock.close()

    def test_the_disabled_plane_returns_plaintext(self, planes, uploaded):
        """What `off` RESTORES — the reading the corpus could not make."""
        sock = planes.session("off")
        try:
            _s, body = _open_body(sock, f"{uploaded}?xrootd.compress=gzip")
            fhandle = body[:4]
            _sid, status, data = _read(sock, fhandle, 0, len(PAYLOAD))
            assert status == kXR_ok, status
            assert not _looks_gzip(data), (
                "read_compress off still returned a gzip frame")
            assert data == PAYLOAD, (
                f"plaintext read returned {len(data)} of {len(PAYLOAD)} bytes")
            _close(sock, fhandle)
        finally:
            sock.close()

    def test_the_armed_plane_records_the_marker_on_the_read(self, planes,
                                                            uploaded):
        """The read direction has a log channel too, and it is the only
        aggregate-free evidence an operator gets: read_compress.c:232 appends
        "z=<wirebytes>" to the READ detail exactly when a codec engaged."""
        sock = planes.session("on")
        try:
            _s, body = _open_body(sock, f"{uploaded}?xrootd.compress=gzip")
            fhandle = body[:4]
            _sid, status, _data = _read(sock, fhandle, 0, len(PAYLOAD))
            assert status == kXR_ok, status
            _close(sock, fhandle)
        finally:
            sock.close()
        seen, compressed = planes.read_compressed("on", uploaded)
        assert seen, "no READ record for the compressed read"
        assert compressed, "armed plane recorded no z= marker on the read"

    def test_the_disabled_plane_records_no_marker_on_the_read(self, planes,
                                                              uploaded):
        """The same absence on the arm nobody wrote — the log says plaintext."""
        sock = planes.session("off")
        try:
            _s, body = _open_body(sock, f"{uploaded}?xrootd.compress=gzip")
            fhandle = body[:4]
            _sid, status, _data = _read(sock, fhandle, 0, len(PAYLOAD))
            assert status == kXR_ok, status
            _close(sock, fhandle)
        finally:
            sock.close()
        seen, compressed = planes.read_compressed("off", uploaded)
        assert seen, "no READ record at all"
        assert not compressed, (
            "read_compress off still recorded a compressed read")

    def test_the_mixed_plane_still_compresses_reads(self, planes, uploaded):
        """read on / write off: turning the WRITE direction off must not touch
        the read path.  Half of the independence claim."""
        sock = planes.session("mixed")
        try:
            _s, body = _open_body(sock, f"{uploaded}?xrootd.compress=gzip")
            cpsize, codec = _negotiated(body)
            assert cpsize == INLINE_CMP_MAGIC, (
                f"write_compress off disabled the READ direction: {cpsize}")
            assert codec == CODEC_GZIP, codec
            fhandle = body[:4]
            _sid, status, data = _read(sock, fhandle, 0, len(PAYLOAD))
            assert status == kXR_ok, status
            assert _looks_gzip(data)
            assert _gunzip(data) == PAYLOAD
            _close(sock, fhandle)
        finally:
            sock.close()


# --------------------------------------------------------------------------- #
# E — the write direction
# --------------------------------------------------------------------------- #
class TestTheWriteDirection:

    def test_the_armed_plane_decompresses_on_ingest(self, planes, tmp_path):
        """A compressed upload lands plaintext and is recorded with the marker."""
        local = tmp_path / "w_on.bin"
        local.write_bytes(PAYLOAD)
        remote = f"/audit16t_w_on_{uuid.uuid4().hex}.bin"
        try:
            proc = planes.upload("on", local, remote, codec="gzip")
            assert proc.returncode == 0, proc.stderr[:400]
            out = tmp_path / "w_on.out"
            assert planes.download("on", remote, out).returncode == 0
            assert out.read_bytes() == PAYLOAD, "stored bytes are not plaintext"
            seen, compressed = planes.wrote_compressed("on", remote)
            assert seen, "no WRITE record for the upload"
            assert compressed, "armed plane recorded no z= marker"
        finally:
            planes.rm("on", remote)

    def test_the_disabled_plane_stores_the_same_bytes_without_the_marker(
            self, planes, tmp_path):
        """The arm nobody wrote, on the write side.

        The upload still succeeds and the file is still byte-exact — the client
        simply never compressed, because the server did not advertise it.  What
        `off` costs is the wire saving, and nothing else.
        """
        local = tmp_path / "w_off.bin"
        local.write_bytes(PAYLOAD)
        remote = f"/audit16t_w_off_{uuid.uuid4().hex}.bin"
        try:
            proc = planes.upload("off", local, remote, codec="gzip")
            assert proc.returncode == 0, proc.stderr[:400]
            out = tmp_path / "w_off.out"
            assert planes.download("off", remote, out).returncode == 0
            assert out.read_bytes() == PAYLOAD
            seen, compressed = planes.wrote_compressed("off", remote)
            assert seen, "no WRITE record for the upload"
            assert not compressed, (
                "write_compress off still recorded a compressed write")
        finally:
            planes.rm("off", remote)

    def test_the_mixed_plane_refuses_the_write_direction_only(self, planes,
                                                              tmp_path):
        """The other half of the independence claim, and the case a shared bit
        or a transposed slot offset cannot pass: reads compress here, writes do
        not, on one server."""
        local = tmp_path / "w_mixed.bin"
        local.write_bytes(PAYLOAD)
        remote = f"/audit16t_w_mixed_{uuid.uuid4().hex}.bin"
        try:
            proc = planes.upload("mixed", local, remote, codec="gzip")
            assert proc.returncode == 0, proc.stderr[:400]
            out = tmp_path / "w_mixed.out"
            assert planes.download("mixed", remote, out).returncode == 0
            assert out.read_bytes() == PAYLOAD
            seen, compressed = planes.wrote_compressed("mixed", remote)
            assert seen, "no WRITE record for the upload"
            assert not compressed, (
                "write_compress off on the mixed plane still compressed")
        finally:
            planes.rm("mixed", remote)

    def test_the_absent_plane_behaves_as_off_on_writes_too(self, planes,
                                                           tmp_path):
        local = tmp_path / "w_absent.bin"
        local.write_bytes(PAYLOAD)
        remote = f"/audit16t_w_absent_{uuid.uuid4().hex}.bin"
        try:
            proc = planes.upload("absent", local, remote, codec="gzip")
            assert proc.returncode == 0, proc.stderr[:400]
            out = tmp_path / "w_absent.out"
            assert planes.download("absent", remote, out).returncode == 0
            assert out.read_bytes() == PAYLOAD
            seen, compressed = planes.wrote_compressed("absent", remote)
            assert seen, "no WRITE record for the upload"
            assert not compressed, "the merge default compressed a write"
        finally:
            planes.rm("absent", remote)


# --------------------------------------------------------------------------- #
# F — the negatives the fail-soft contract owes
# --------------------------------------------------------------------------- #
class TestTheFailSoftContract:

    def test_an_unknown_codec_degrades_rather_than_failing(self, planes,
                                                           uploaded):
        """On the ARMED plane, so the refusal is the codec lookup and not the
        flag — otherwise this case would pass for the wrong reason."""
        sock = planes.session("on")
        try:
            status, body = _open_body(
                sock, f"{uploaded}?xrootd.compress=notacodec")
            assert status == kXR_ok, (
                f"an unknown codec must not fail the open: {status}")
            cpsize, _codec = _negotiated(body)
            assert cpsize != INLINE_CMP_MAGIC, (
                f"an unknown codec negotiated compression: cpsize={cpsize}")
        finally:
            sock.close()

    def test_an_empty_codec_value_degrades(self, planes, uploaded):
        """`vlen == 0` is checked explicitly (open_request_opaque.c:83)."""
        sock = planes.session("on")
        try:
            status, body = _open_body(sock, f"{uploaded}?xrootd.compress=")
            assert status == kXR_ok, status
            cpsize, _codec = _negotiated(body)
            assert cpsize != INLINE_CMP_MAGIC, cpsize
        finally:
            sock.close()

    def test_no_opaque_at_all_negotiates_nothing_on_an_armed_plane(
            self, planes, uploaded):
        """Opt-in: an armed server must stay invisible to a client that never
        asks.  This is what keeps `on` safe to deploy."""
        sock = planes.session("on")
        try:
            status, body = _open_body(sock, uploaded)
            assert status == kXR_ok, status
            cpsize, _codec = _negotiated(body)
            assert cpsize != INLINE_CMP_MAGIC, (
                f"an armed plane compressed a read nobody asked for: {cpsize}")
        finally:
            sock.close()

    def test_an_armed_plane_serves_plaintext_to_a_stock_read(self, planes,
                                                             uploaded):
        """The bytes behind the previous case: no opaque, no gzip frame."""
        sock = planes.session("on")
        try:
            _s, body = _open_body(sock, uploaded)
            fhandle = body[:4]
            _sid, status, data = _read(sock, fhandle, 0, len(PAYLOAD))
            assert status == kXR_ok, status
            assert not _looks_gzip(data)
            assert data == PAYLOAD
            _close(sock, fhandle)
        finally:
            sock.close()


# --------------------------------------------------------------------------- #
# G — the mechanism is where this file says it is
# --------------------------------------------------------------------------- #
class TestTheMechanismIsWhereTheFileSaysItIs:
    """Source pins.

    Every runtime case above is an observation of behaviour; these say the
    behaviour comes from the lines the docstring names.  Without them a
    refactor could move the gate and leave the whole file passing while its
    explanation had become fiction.
    """

    def test_both_directives_are_flag_slots_on_the_stream_server(self):
        text = _source(DIRECTIVES_H)
        for directive in (READ_DIRECTIVE, WRITE_DIRECTIVE):
            idx = text.index(f'ngx_string("{directive}")')
            entry = text[idx:idx + 400]
            assert "NGX_STREAM_SRV_CONF" in entry, entry
            assert "NGX_CONF_FLAG" in entry, entry
            assert "ngx_conf_set_flag_slot" in entry, entry

    def test_both_default_to_zero_in_the_merge(self):
        text = _source(MERGE_C)
        for field in ("read_compress", "write_compress"):
            assert re.search(
                rf"ngx_conf_merge_value\(\s*conf->{field}\s*,\s*"
                rf"prev->{field}\s*,\s*0\s*\)", text), field

    def test_the_direction_gate_is_one_ternary(self):
        """The single expression the four planes exist to take apart."""
        text = _source(OPAQUE_C)
        assert ("enabled = is_write ? conf->write_compress : "
                "conf->read_compress;") in text, (
            "the direction gate is no longer the ternary this file assumes")

    def test_the_gate_returns_identity_rather_than_failing(self):
        text = _source(OPAQUE_C)
        idx = text.index("enabled = is_write ?")
        window = text[idx:idx + 300]
        assert "BRIX_CODEC_IDENTITY" in window, window
        assert "return" in window, window

    def test_the_disabled_capability_form_is_a_literal_zero(self):
        """`cmpread=0` / `cmpwrite=0` are spelled in the C, so §B is asserting
        the emitter's own string and not a client-side rendering."""
        text = _source(QCONFIG_C)
        assert '"cmpread=0\\n"' in text, "cmpread disabled form not found"
        assert '"cmpwrite=0\\n"' in text, "cmpwrite disabled form not found"

    def test_each_emitter_reads_its_own_flag(self):
        """The pin behind the mixed plane: two emitters, two fields."""
        text = _source(QCONFIG_C)
        read_fn = text.split("brix_qconfig_emit_cmpread(")[1].split("\n}\n")[0]
        write_fn = text.split("brix_qconfig_emit_cmpwrite(")[1].split("\n}\n")[0]
        assert "conf->read_compress" in read_fn, read_fn
        assert "conf->write_compress" not in read_fn, read_fn
        assert "conf->write_compress" in write_fn, write_fn
        assert "conf->read_compress" not in write_fn, write_fn

    def test_the_only_evidence_is_per_request(self):
        """Why the config binds no http face, and the shape of finding #97.

        Both directions append a "z=<wirebytes>" marker to their access record,
        so an operator can see that ONE request compressed.  What does not exist
        anywhere in src/ is an aggregate: no brix_metric call names a codec or a
        compression outcome, so "how often did compression engage, and how often
        was it refused" has no answer short of parsing logs.  If a counter is
        ever added this fails, and the instance should grow a METRICS_PORT and a
        metrics section — the absence is a measured property of this pair, not
        an oversight in the test.
        """
        assert 'z=%zu' in _source(ROOT / "src/protocols/root/read/read_compress.c")
        assert 'z=%zu' in _source(ROOT / "src/protocols/root/write/write_compress.c")

        hits = []
        for path in (ROOT / "src").rglob("*.c"):
            for line in _source(path).splitlines():
                if "brix_metric" in line and ("compress" in line.lower()
                                              or "codec" in line.lower()):
                    hits.append(f"{path.name}: {line.strip()}")
        assert hits == [], f"a compression metric now exists: {hits}"
