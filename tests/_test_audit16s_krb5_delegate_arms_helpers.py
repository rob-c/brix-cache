"""brix_krb5_delegate at VALUE granularity — audit §Method, 16th tranche.

WHY THIS FILE EXISTS
--------------------
The audit's Method (steps 1-2) counts directive NAMES.  Re-running the
measurement per (directive, VALUE) over the 128 ``ngx_conf_set_flag_slot``
directives in ``src/`` turned 256 pairs into 138 written literally, 12 reachable
only through a ``{PLACEHOLDER}``, and 106 written nowhere at all.
``brix_krb5_delegate`` is the last arm-gap left in
``src/protocols/root/stream/directives_auth.h``: ``on`` reaches two configs
(``nginx_lc_native_krb5_delegate.conf``, ``nginx_lc_krb5_cache_origin.conf``)
and ``off`` reaches none, in any form, anywhere in the corpus.

WHAT THE VALUE SELECTS
----------------------
One branch at the end of a verified krb5 login::

    src/auth/krb5/auth.c:560-563
        /* Round 1 with delegation on: request a forwarded TGT */
        if (brix_krb5_deleg_wanted(conf)) {
            return brix_krb5_begin_delegation(&rq, auth_ctx, ticket);
        }
        brix_krb5_finalize(&rq, auth_ctx, ticket, &out);

    src/auth/krb5/deleg_capture.c:23-26
        int brix_krb5_deleg_wanted(ngx_stream_brix_srv_conf_t *conf)
        { return conf != NULL && conf->krb5.delegate == 1; }

``on`` therefore does not merely switch a capture on.  The AP-REQ has already
been verified at that line: the login the client would otherwise have HAD is
withheld, the session subkey is parked, and a ``kXR_authmore`` "fwdtgt"
continuation goes back instead.  The arm adds a REQUIREMENT — a second round
and a *forwardable* ticket — and ``off``, the arm nobody wrote, is the only
spelling that takes the requirement away again.

WHAT THE TABLE ESTABLISHES
--------------------------
Three acceptors in ONE process, off one realm, one principal, one keytab and one
export, differing only in the directive.  The variable is the ticket: a stock
``kinit -k -t`` cache, and one taken with ``-f``.  Every row is the stock
``xrdfs`` — upstream's client, not this repo's — so nothing here depends on the
clean-room implementation:

    ticket        plane     login           kXR_authmore   captured
    forwardable   on        OK                    1        yes
    forwardable   off       OK                    0        no
    forwardable   absent    OK                    0        no      (merge is 0)
    stock         on        REFUSED (rc 52)       1        no
    stock         off       OK                    0        no
    stock         absent    OK                    0        no

Row 4 against rows 5 and 6 is the pair, and one worker answering all six is the
statement that this flag is per-server rather than per-process — the control
file 17's #92 failed.

FINDING — DEFECT CANDIDATE #95
------------------------------
A login refused for the reason this directive exists is invisible in every
operator-visible face.  Row 4 is a client that authenticated — a verified
AP-REQ, a mapped principal — and then got no session, and the server:

* logs no AUTH record at all.  ``brix_access_log`` on the armed plane carries
  the LOGIN and the DISCONNECT and nothing between them, where the same plane
  writes ``"AUTH - krb5" OK`` for a login that completes and ``"AUTH - krb5"
  ERR`` for a credential it cannot read (§F measures all three);
* moves no counter.  ``brix_auth_total{proto="stream",method="krb5"}`` is
  unchanged in BOTH ``status="ok"`` and ``status="fail"`` — the refusal is
  counted as neither, while a malformed credential on the same plane in the
  same run moves ``fail``;
* said nothing at start-up either.  ``brix: krb5 auth configured`` prints
  ``ip_check=`` and no delegation word at all (config.c:252-257), so the three
  planes emit three IDENTICAL notices.

The cause is structural rather than a missing call: ``brix_krb5_begin_delegation``
accounts for its failures (auth.c:436-437) but returns the challenge as a
SUCCESS, and nothing is left to account for the round that never comes back.
An operator who arms delegation and breaks every client whose tickets are not
forwardable — the default for ``kinit`` — sees a flat line.

FINDING — DEFECT CANDIDATE #96
------------------------------
The captured TGT lands in ``/tmp`` and the documented knob for moving it cannot
be set from a config file.  ``brix_krb5_deleg_mkccache`` (deleg_capture.c:209-216)
is commented "Honors $TMPDIR, defaulting to /tmp" — but nginx builds a worker's
environment from the ``env`` directives alone, so unless the operator writes a
main-scope ``env TMPDIR;``, ``getenv("TMPDIR")`` in the worker is NULL and every
capture is a ``mkstemp`` under ``/tmp``.  §G measures both renderings of the
same instance: without the directive the file is ``/tmp/brix-krb5-fwd-XXXXXX``,
with it the file moves to the handed-in directory.  The file is mode 0600 and is
unlinked at connection close, so this is a siting question and not an exposure —
but what sits there is a live, usable TGT (§G reads it back with ``klist``:
``alice@NGINX.TEST``, ``krbtgt/NGINX.TEST@NGINX.TEST``), the directive that
relocates it is nginx's rather than this module's, and no doc, README or config
in the corpus mentions it.

WHY THIS IS NOT test_krb5_delegation_e2e.py
-------------------------------------------
That file proves the delegation path runs end-to-end with the clean-room client:
one plane, ``on`` only, positive plus the non-forwardable security-negative.  It
cannot say anything about the arm, because it has only one — nothing there
measures what ``off`` restores, that absence is ``off``, that the flag is read
per server, what the round count on the wire is, what an operator can see of
any of it, or where the captured credential is written.  ``test_krb5_delegate_load.py``
is the parse tier for ``on`` alone.  Neither writes ``off``, which is the pair
this file closes.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
Nothing here says delegation should be off, or that the requirement is wrong: a
proxy that has to re-authenticate AS the user at an origin needs the user's TGT,
and asking for it is the only honest way to get one.  Measured here is what the
two values do, to whom, what it costs the client that meets neither, and what
the server records of it.
"""

import dataclasses
import os
import re
import shutil
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

import pytest
import requests

import kdc_helpers
from config_parse import nginx_t
from fleet_lifecycle_ports import (
    LIFECYCLE_SHARED_PORTS,
    PARSE_PLACEHOLDER_PORT,
    SHARED_PARSE_PLACEHOLDER_PORT,
)
from server_registry import NginxInstanceSpec
from settings import (
    HOST,
    KRB5_CCACHE,
    KRB5_CLIENT_KEYTAB,
    KRB5_CLIENT_PRINCIPAL,
    KRB5_CONF,
    KRB5_KEYTAB,
    KRB5_SERVICE_PRINCIPAL,
    NGINX_BIN,
    url_host,
)

def _expression_1(plane, mark, self):
    return (
        [line for line in self.accesslog(plane)[mark:].splitlines()
                               if line.strip()]
    )


def _guard_gates_1():
    if SYS_XRDFS is None:
        pytest.skip("stock xrdfs not on PATH")

def _guard_gates_2():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

def _guard_gates_3():
    if not kdc_helpers.krb5_tools_available():
        pytest.skip("MIT KDC tooling not installed (install krb5-server)")

def _guard_gates_4():
    if not kdc_helpers.up():
        pytest.skip("krb5 realm could not be provisioned")


pytestmark = [pytest.mark.timeout(900),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16s-krb5deleg")]

NAME = "lc-audit16s-krb5deleg"
_EXTRA = LIFECYCLE_SHARED_PORTS[NAME]["extra"]
OFF_PORT = _EXTRA["OFF_PORT"]
ABSENT_PORT = _EXTRA["ABSENT_PORT"]
RELAY_PORT = _EXTRA["RELAY_PORT"]
METRICS_PORT = _EXTRA["METRICS_PORT"]

ROOT = Path(__file__).resolve().parents[1]
AUTH_C = ROOT / "src/auth/krb5/auth.c"
CAPTURE_C = ROOT / "src/auth/krb5/deleg_capture.c"
MEMORY_C = ROOT / "src/auth/krb5/capture.c"
CONFIG_C = ROOT / "src/auth/krb5/config.c"
MERGE_C = ROOT / "src/core/config/server_conf_merge_security.c"
DIRECTIVES_H = ROOT / "src/protocols/root/stream/directives_auth.h"
CONFIGS = Path(__file__).resolve().parent / "configs"

DIRECTIVE = "brix_krb5_delegate"


def _writes(text, value):
    """Whether ``text`` spells one arm of the directive as a whole line.

    The audit's census is by literal spelling — ``<directive> <value>;`` — and
    the run of spaces between the two is a config file's own alignment, so it
    is the one thing the instrument must not be sensitive to.
    """
    return re.search(rf"^\s*{DIRECTIVE}\s+{value}\s*;\s*$", text,
                     re.MULTILINE) is not None

# The captured forwarded TGT: a mkstemp template the C spells out, and the
# directory it falls back to when the worker has no $TMPDIR — which is every
# worker that was not given one by an nginx `env` directive (#96).
CAPTURE_GLOB = "brix-krb5-fwd-*"
DEFAULT_CAPTURE_DIR = Path("/tmp")     # host-literal-allow: deleg_capture.c:218

MARKER = "krb5 delegation captured forwarded TGT"
NOTICE = "brix: krb5 auth configured"

kXR_auth = 3000
kXR_error = 4003
kXR_authmore = 4002
kXR_NotAuthorized = 3010

READ_FILE = "/probe.txt"
READ_BODY = b"krb5 delegate arms\n"

SYS_XRDFS = shutil.which("xrdfs")
SYS_KINIT = shutil.which("kinit") or "/usr/bin/kinit"
SYS_KLIST = shutil.which("klist") or "/usr/bin/klist"
BRIX_XRDFS = ROOT / "client" / "bin" / "xrdfs"


# --------------------------------------------------------------------------- #
# Tickets                                                                      #
# --------------------------------------------------------------------------- #

def _forwardable_ticket(tmp_path):
    """A cache holding a TGT the KDC issued with the FORWARDABLE flag.

    `kinit -f` is the whole difference from the cache `kdc_helpers.up()` already
    minted: same principal, same keytab, same realm.  Everything this file calls
    "the cost of the armed arm" is what that one flag buys.
    """
    ccache = tmp_path / "ccache-forwardable"
    subprocess.run([SYS_KINIT, "-f", "-k", "-t", KRB5_CLIENT_KEYTAB,
                    "-c", str(ccache), KRB5_CLIENT_PRINCIPAL],
                   env={**os.environ, "KRB5_CONFIG": KRB5_CONF},
                   check=True, capture_output=True, timeout=60)
    return str(ccache)


def _ticket_flags(ccache):
    """The flag letters of every ticket in a cache, joined.

    `klist -f` prints them as a "Flags: FIA" line under each entry; F is
    forwardable, and its presence is the instrument check for the whole file.
    """
    out = subprocess.run([SYS_KLIST, "-f", "-c", "FILE:" + str(ccache)],
                         env={**os.environ, "KRB5_CONFIG": KRB5_CONF},
                         capture_output=True, text=True, timeout=30).stdout
    return "".join(re.findall(r"Flags:\s*(\S+)", out))


# --------------------------------------------------------------------------- #
# The counting relay — the instrument                                          #
# --------------------------------------------------------------------------- #

class _Counter:
    """A TCP relay that records the status word of every server response.

    The extra round is the mechanism of this directive, and it has no other
    observable: the client reports a verdict, the server logs a marker, and
    neither says how many messages it took.  Nothing is rewritten or delayed —
    the relay parses the 8-byte response header (streamid, status, dlen) purely
    to know where the next one starts — so a relayed login is byte-for-byte the
    login the client would have made directly.

    ``target`` is read on every accept rather than fixed at construction, so one
    relay (one ledger port) serves whichever plane a case is asking about.
    """

    def __init__(self, port, target):
        self.target = target
        self.statuses = []
        self._stop = False
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((url_host(HOST), port))
        self._listener.listen(8)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def reset(self, target):
        self.target = target
        self.statuses = []

    def _serve(self):
        while not self._stop:
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            try:
                upstream = socket.create_connection((url_host(HOST),
                                                     self.target), timeout=10)
            except OSError:
                client.close()
                continue
            threading.Thread(target=self._pump, args=(client, upstream),
                             daemon=True).start()
            threading.Thread(target=self._count, args=(upstream, client),
                             daemon=True).start()

    @staticmethod
    def _pump(src, dst):
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            _shutdown(src, dst)

    def _count(self, src, dst):
        buf = b""
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                dst.sendall(chunk)
                buf += chunk
                while len(buf) >= 8:
                    _sid, status, dlen = struct.unpack("!2sHI", buf[:8])
                    if len(buf) < 8 + dlen:
                        break
                    self.statuses.append(status)
                    buf = buf[8 + dlen:]
        except OSError:
            pass
        finally:
            _shutdown(src, dst)

    def close(self):
        """Shut the listener down before closing it, and wait for the thread.

        close() alone does not free the port: the accept() this class parks a
        thread in holds a kernel reference to the socket, so the fd goes away
        while the binding stays and the NEXT test in the same process cannot
        take RELAY_PORT.  shutdown() is what wakes the blocked accept.
        """
        self._stop = True
        try:
            self._listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._listener.close()
        self._thread.join(timeout=10)

    def rounds(self):
        return self.statuses.count(kXR_authmore)


def _shutdown(*socks):
    # Both directions tear down the same pair; the second one through finds the
    # sockets already closed, which is why every call here is guarded.
    for sock in socks:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# The three planes                                                             #
# --------------------------------------------------------------------------- #

class _Planes:
    """The started instance plus what every case needs from it: which port
    carries which arm, where each plane wrote its audit trail, and the two
    tickets the whole table is a function of."""

    def __init__(self, endpoint, relay, tickets, tmp_path):
        self.endpoint = endpoint
        self.relay = relay
        self.forwardable, self.stock = tickets
        self.tmp_path = tmp_path
        self.on = endpoint.port
        self.off = OFF_PORT
        self.absent = ABSENT_PORT
        self.logs = os.path.join(endpoint.prefix, "logs")

    def errlog(self):
        """Instance logs are wiped at teardown, so failures quote them inline."""
        return _read(os.path.join(self.logs, "error.log"))

    def accesslog(self, plane):
        return _read(os.path.join(self.logs, f"access-{plane}.log"))

    def mark(self, plane):
        """Byte offset of the end of a plane's access log, for a slice."""
        try:
            return os.path.getsize(os.path.join(self.logs, f"access-{plane}.log"))
        except OSError:
            return 0

    def since(self, plane, mark, needle="DISCONNECT", timeout=10.0):
        """Every access record a plane wrote past ``mark``.

        A client's exit is not the sync point: xrdfs returns as soon as it has
        its reply, and the records for that connection are written by a worker
        that is still tearing it down.  So the read waits for ``needle`` — by
        default DISCONNECT, which is the last thing a connection ever logs and
        therefore the point past which nothing more is coming — and returns
        whatever is there when it arrives or when the wait runs out.  Cases
        that assert an ABSENCE need exactly that: a slice that is complete, not
        merely one that is empty so far.
        """
        deadline = time.monotonic() + timeout
        while True:
            records = _expression_1(plane, mark, self)
            if any(needle in line for line in records):
                return records
            if time.monotonic() >= deadline:
                return records
            time.sleep(0.05)

    def errmark(self):
        try:
            return os.path.getsize(os.path.join(self.logs, "error.log"))
        except OSError:
            return 0

    def errsince(self, mark):
        return self.errlog()[mark:]

    def auth_counts(self):
        """brix_auth_total{proto="stream",method="krb5"} by status.

        Read through the http face rather than out of a log, because a counter
        is what an operator actually watches, and because the family lives in
        shared memory the stream workers write and the http worker exports.
        """
        body = requests.get(f"http://{HOST}:{METRICS_PORT}/metrics",
                            timeout=15).text
        # proto="stream", not "root": the root:// plane's metric label comes
        # from core/types/proto_list.h, where the ROOT row's label is the nginx
        # module it lives in rather than the URL scheme it speaks.
        prefix = 'brix_auth_total{proto="stream",method="krb5"'
        counts = {}
        for line in body.splitlines():
            if line.startswith(prefix):
                counts[line.split('status="')[1].split('"')[0]] = int(
                    line.rsplit(" ", 1)[1])
        assert counts, f"the krb5 rows are missing from the exposition:\n{body}"
        return counts


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _gates():
    _guard_gates_1()
    _guard_gates_2()
    _guard_gates_3()
    _guard_gates_4()


def _spec(data, main_env):
    return NginxInstanceSpec(
        name=NAME,
        template="nginx_audit16s_krb5_delegate.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"PRINCIPAL": KRB5_SERVICE_PRINCIPAL,
                         "KEYTAB": KRB5_KEYTAB,
                         "MAIN_ENV": main_env},
        env={"KRB5_CONFIG": KRB5_CONF},
        reason="audit-16s brix_krb5_delegate at value granularity")


def _export(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / os.path.basename(READ_FILE)).write_bytes(READ_BODY)
    # The acceptor resolves default_realm and auth_to_local out of the generated
    # profile, and the launcher's `nginx -t` runs in this process — so the
    # ambient environment needs it too, not just the daemon's.
    os.environ["KRB5_CONFIG"] = KRB5_CONF
    return data


@pytest.fixture
def planes(lifecycle, tmp_path):
    """One realm, one keytab, one export, three acceptors, one relay."""
    _gates()
    data = _export(tmp_path)
    try:
        endpoint = lifecycle.start(_spec(data, ""))
        tickets = (_forwardable_ticket(tmp_path), KRB5_CCACHE)
    except Exception:
        kdc_helpers.down()
        raise

    relay = _Counter(RELAY_PORT, endpoint.port)
    try:
        yield _Planes(endpoint, relay, tickets, tmp_path)
    finally:
        relay.close()
        kdc_helpers.down()


@pytest.fixture
def relocated(lifecycle, tmp_path):
    """The same three planes, rendered with a main-scope ``env TMPDIR;``.

    Its own fixture rather than a parameter because it is the SECOND rendering
    of one instance name: a case takes this one or ``planes``, never both, and
    the pair is the whole of §G's comparison.
    """
    _gates()
    data = _export(tmp_path)
    ccdir = tmp_path / "deleg-ccaches"
    ccdir.mkdir()
    try:
        endpoint = lifecycle.start(dataclasses.replace(
            _spec(data, "env TMPDIR;"),
            env={"KRB5_CONFIG": KRB5_CONF, "TMPDIR": str(ccdir)}))
        ticket = _forwardable_ticket(tmp_path)
    except Exception:
        kdc_helpers.down()
        raise
    try:
        yield endpoint, ticket, ccdir
    finally:
        kdc_helpers.down()


# --------------------------------------------------------------------------- #
# Clients                                                                      #
# --------------------------------------------------------------------------- #

def _env(ccache):
    """The environment for one login, pinned to krb5 and to one cache.

    X509_* and BEARER_TOKEN are stripped so a stray proxy or token in the
    ambient environment can never make this a GSI or a token test by accident —
    the file would then measure a protocol with no delegation round at all.
    """
    env = os.environ.copy()
    env["XrdSecPROTOCOL"] = "krb5"
    env["KRB5_CONFIG"] = KRB5_CONF
    env["KRB5CCNAME"] = str(ccache)
    for stray in ("X509_USER_PROXY", "X509_USER_CERT", "X509_USER_KEY",
                  "BEARER_TOKEN", "BEARER_TOKEN_FILE"):
        env.pop(stray, None)
    return env


def _xrdfs(port, ccache, *args):
    """Upstream's client.  Every verdict in this file is measured with it."""
    return subprocess.run([SYS_XRDFS, f"root://{url_host(HOST)}:{port}", *args],
                          env=_env(ccache), capture_output=True, text=True,
                          timeout=60)


def _brix_xrdfs(port, ccache, *args):
    """This repo's client, used only where its diagnostics are the subject."""
    return subprocess.run([str(BRIX_XRDFS), "--auth", "krb5",
                           f"root://{url_host(HOST)}:{port}", *args],
                          env=_env(ccache), capture_output=True, text=True,
                          timeout=60)


def _counted(planes, port, ccache, *args):
    """The same login, through the relay, so its rounds can be counted."""
    planes.relay.reset(port)
    result = _xrdfs(RELAY_PORT, ccache, *args)
    time.sleep(0.3)     # the last response may still be in flight at exit
    return result, planes.relay.rounds()


def _text(result):
    return result.stdout + result.stderr


def _captures(directory=DEFAULT_CAPTURE_DIR):
    return sorted(Path(directory).glob(CAPTURE_GLOB))


# --------------------------------------------------------------------------- #
# A. What the value says at config time                                        #
# --------------------------------------------------------------------------- #

