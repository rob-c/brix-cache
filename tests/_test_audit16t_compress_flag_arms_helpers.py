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
merge default instead of reading it off ``server_conf_merge_storage.c:310-311``.
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
import time
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
MERGE_C = ROOT / "src/core/config/server_conf_merge_storage.c"
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

