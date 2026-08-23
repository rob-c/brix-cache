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

class TestTheValueAtConfigTime:
    """The three planes, and the one thing an operator is told about them."""

    def test_the_rendered_config_writes_both_arms_literally(self, planes):
        """success: the pair this file closes, in the form the audit's own
        census greps for.  `on` was already in two configs; `off` is written
        here for the first time anywhere in the corpus."""
        rendered = _read(planes.endpoint.config)
        for value in ("on", "off"):
            assert _writes(rendered, value), (
                f"`{DIRECTIVE} {value};` is not in the rendered config — the "
                f"arm is not closed\n{rendered}")

    def test_the_third_plane_writes_the_directive_nowhere(self, planes):
        """The absent plane has to be absence, not a third spelling: its whole
        job is to measure the merge default instead of reading it off
        server_conf_merge_security.c:241."""
        rendered = _read(planes.endpoint.config)
        written = re.findall(rf"^\s*{DIRECTIVE}\s+(\S+)\s*;\s*$", rendered,
                             re.MULTILINE)
        assert written == ["on", "off"], (
            f"expected exactly two {DIRECTIVE} lines, one per arm, in server "
            f"order; found {written}\n{rendered}")

    def test_the_planes_differ_in_nothing_else(self, planes):
        """One principal, one keytab, one export.  Any other difference would
        give a refusal a second explanation."""
        rendered = _read(planes.endpoint.config)
        for directive, expected in ((f"brix_krb5_principal {KRB5_SERVICE_PRINCIPAL};", 3),
                                    (f"brix_krb5_keytab    {KRB5_KEYTAB};", 3),
                                    (f"brix_storage_backend posix:{planes.endpoint.data_root};", 3)):
            assert rendered.count(directive) == expected, (
                f"{directive!r} appears {rendered.count(directive)} times, "
                f"expected {expected}\n{rendered}")

    def test_the_start_up_notice_never_names_the_directive(self, planes):
        """FINDING #95, the config-time half: the krb5 acceptor announces its
        principal, its keytab and its ip_check value — and says nothing at all
        about delegation, so the three planes emit identical notices and an
        operator cannot tell from the log which server is armed."""
        notices = [line for line in planes.errlog().splitlines()
                   if NOTICE in line]
        def _assert_test_the_start_up_notice_never_names_the_directive_2():
            assert notices, f"no krb5 configuration notice at all\n{planes.errlog()}"
            assert all("ip_check=" in line for line in notices), notices

        _assert_test_the_start_up_notice_never_names_the_directive_2()
        assert not any("delegate" in line for line in notices), (
            "the notice has learned to mention delegation — #95's config-time "
            "half is fixed and this case should become its regression pin\n"
            + "\n".join(notices))

    def test_the_notices_are_indistinguishable(self, planes):
        """The same statement from the other side: strip the position each
        notice carries and the three planes' lines are one string."""
        bodies = {line.split(NOTICE, 1)[1].split(" in ")[0].strip()
                  for line in planes.errlog().splitlines() if NOTICE in line}
        assert len(bodies) == 1, (
            f"the planes' notices already differ, so #95 is narrower than "
            f"recorded: {bodies}")


# --------------------------------------------------------------------------- #
# B. The instrument                                                            #
# --------------------------------------------------------------------------- #

class TestTheTickets:
    """The one flag the whole table is a function of."""

    def test_the_forwardable_ticket_carries_the_f_flag(self, planes):
        """success: `kinit -f` really did get a forwardable TGT.  Without this
        the refusals below would be measuring a KDC policy, not a directive."""
        assert "F" in _ticket_flags(planes.forwardable), (
            f"the -f ticket is not forwardable: "
            f"{_ticket_flags(planes.forwardable)!r}")

    def test_the_stock_ticket_does_not(self, planes):
        """And the cache every other krb5 test in the suite uses does not —
        which is what makes it the right stand-in for a real client."""
        assert "F" not in _ticket_flags(planes.stock), (
            f"the stock ticket is forwardable after all: "
            f"{_ticket_flags(planes.stock)!r}")

    def test_both_tickets_name_the_same_principal(self, planes):
        """Same user, same realm, same keytab: the only difference between the
        two caches is the flag above."""
        for ccache in (planes.forwardable, planes.stock):
            out = subprocess.run([SYS_KLIST, "-c", "FILE:" + str(ccache)],
                                 env={**os.environ, "KRB5_CONFIG": KRB5_CONF},
                                 capture_output=True, text=True,
                                 timeout=30).stdout
            assert KRB5_CLIENT_PRINCIPAL in out, out


# --------------------------------------------------------------------------- #
# C. The armed arm                                                             #
# --------------------------------------------------------------------------- #

class TestTheArmedPlane:
    """`brix_krb5_delegate on` — what the corpus already wrote, measured for
    the first time against the arms that did not."""

    def test_a_forwardable_ticket_logs_in(self, planes):
        """success: the arm is not a refusal machine — a client that can meet
        the requirement is served normally."""
        result = _xrdfs(planes.on, planes.forwardable, "stat", READ_FILE)
        assert result.returncode == 0, (
            f"a forwardable ticket was refused by the armed plane\n"
            f"{_text(result)}\n{planes.errlog()}")

    def test_the_session_can_read(self, planes):
        """And the session is a real one: the login yields file access, not a
        bare handshake."""
        result = _xrdfs(planes.on, planes.forwardable, "cat", READ_FILE)
        assert result.returncode == 0, _text(result)
        assert READ_BODY.decode() in result.stdout, (
            f"the delegated session read nothing\n{_text(result)}")

    def test_the_login_costs_exactly_one_extra_round(self, planes):
        """The mechanism, on the wire: one kXR_authmore, which is the
        continuation the acceptor sends INSTEAD of the session it had already
        earned the right to grant."""
        result, rounds = _counted(planes, planes.on, planes.forwardable,
                                  "stat", READ_FILE)
        assert result.returncode == 0, _text(result)
        assert rounds == 1, (
            f"expected exactly one kXR_authmore, saw {rounds}: "
            f"{planes.relay.statuses}")

    def test_the_capture_marker_names_the_user(self, planes):
        """The airtight proof the capture ran rather than the challenge merely
        being sent: the acceptor logs the marker only after it has decrypted
        and imported the forwarded KRB_CRED."""
        mark = planes.errmark()
        assert _xrdfs(planes.on, planes.forwardable, "stat",
                      READ_FILE).returncode == 0
        slice_ = planes.errsince(mark)
        assert MARKER in slice_, f"no capture marker\n{slice_}"
        assert 'for "alice"' in slice_, (
            f"the marker does not name the mapped principal\n{slice_}")

    def test_the_armed_plane_is_answered_by_the_stock_client(self, planes):
        """Every verdict in this file is upstream's client, which is worth
        saying once explicitly: the fwdtgt continuation is XrdSeckrb5's own
        forwarding exchange, so arming it does not require this repo's."""
        result = _xrdfs(planes.on, planes.forwardable, "stat", READ_FILE)
        assert result.returncode == 0, _text(result)
        assert SYS_XRDFS is not None and "client/bin" not in SYS_XRDFS


# --------------------------------------------------------------------------- #
# D. The arm nobody wrote                                                      #
# --------------------------------------------------------------------------- #

class TestTheArmNobodyWrote:
    """`brix_krb5_delegate off` — written here for the first time."""

    def test_a_forwardable_ticket_logs_in_with_no_extra_round(self, planes):
        """success: the same client and the same ticket as §C, one directive
        later — and the continuation is gone."""
        result, rounds = _counted(planes, planes.off, planes.forwardable,
                                  "stat", READ_FILE)
        assert result.returncode == 0, _text(result)
        assert rounds == 0, (
            f"the off arm still sent {rounds} kXR_authmore: "
            f"{planes.relay.statuses}")

    def test_the_ticket_the_armed_plane_refuses_is_accepted_here(self, planes):
        """The pair, in one sentence: the credential §E measures being turned
        away is served by the arm nobody had written."""
        result = _xrdfs(planes.off, planes.stock, "stat", READ_FILE)
        assert result.returncode == 0, (
            f"the off arm refused a stock ticket\n{_text(result)}\n"
            f"{planes.errlog()}")

    def test_nothing_is_captured(self, planes):
        """No marker, and no ccache: `off` does not merely skip the challenge,
        it never touches the client's credentials at all."""
        mark = planes.errmark()
        before = set(_captures())
        assert _xrdfs(planes.off, planes.forwardable, "stat",
                      READ_FILE).returncode == 0
        assert MARKER not in planes.errsince(mark), planes.errsince(mark)
        assert set(_captures()) - before == set(), (
            "the off arm wrote a forwarded-TGT ccache")

    def test_the_login_is_recorded_exactly_as_a_delegated_one(self, planes):
        """The off arm is not a downgrade in the log either: the access record
        carries the same method and the same mapped identity."""
        mark = planes.mark("off")
        assert _xrdfs(planes.off, planes.forwardable, "stat",
                      READ_FILE).returncode == 0
        records = planes.since("off", mark)
        assert any('"AUTH - krb5" OK' in line for line in records), records
        assert any('krb5 "alice"' in line for line in records), records

    def test_the_off_arm_still_refuses_a_credential_it_cannot_read(self, planes):
        """security-negative: removing the delegation requirement removes
        nothing else.  A blob that is not an AP-REQ is refused on this plane
        exactly as on the armed one — the arm governs what an authenticated
        client is additionally asked for, never whether it is authenticated."""
        status, errcode, message = _bad_credential(planes.off)
        assert status == kXR_error and errcode == kXR_NotAuthorized, (
            f"the off arm answered {status}/{errcode} to a malformed "
            f"credential")
        assert b"malformed krb5 credential" in message, message


# --------------------------------------------------------------------------- #
# E. The silent plane                                                          #
# --------------------------------------------------------------------------- #

class TestTheSilentPlane:
    """The directive unwritten — every krb5 server that never heard of it."""

    def test_absence_behaves_as_off(self, planes):
        """success: a stock ticket, which the armed plane refuses, is served."""
        result, rounds = _counted(planes, planes.absent, planes.stock,
                                  "stat", READ_FILE)
        assert result.returncode == 0, _text(result)
        assert rounds == 0, planes.relay.statuses

    def test_absence_captures_nothing_from_a_forwardable_ticket(self, planes):
        """And the other half: a client that COULD be asked is not."""
        mark = planes.errmark()
        before = set(_captures())
        assert _xrdfs(planes.absent, planes.forwardable, "stat",
                      READ_FILE).returncode == 0
        assert MARKER not in planes.errsince(mark)
        assert set(_captures()) - before == set()

    def test_the_merge_default_is_off(self):
        """Where the behaviour above comes from, pinned so a change to the
        default has to come past this file."""
        merge = _read(MERGE_C)
        assert "ngx_conf_merge_value(conf->krb5.delegate,       " \
               "prev->krb5.delegate,   0);" in merge, (
            "the delegate merge default is no longer 0")

    def test_all_three_planes_are_one_worker(self, planes):
        """The control file 17's #92 failed: three verdicts about one directive
        out of ONE process, which is what says the flag is per-server rather
        than a process global the last server in configuration order wins."""
        pid = int(_read(os.path.join(planes.logs, "nginx.pid")).strip())
        children = subprocess.run(["pgrep", "-P", str(pid)],
                                  capture_output=True, text=True).stdout.split()
        assert len(children) == 1, (
            f"expected one worker under {pid}, found {children}")
        refused = _xrdfs(planes.on, planes.stock, "stat", READ_FILE)
        assert refused.returncode != 0, _text(refused)
        for port, plane in ((planes.off, "off"), (planes.absent, "absent")):
            served = _xrdfs(port, planes.stock, "stat", READ_FILE)
            assert served.returncode == 0, (
                f"the {plane} plane in the same worker refused the ticket the "
                f"armed plane had just turned away\n{_text(served)}")


# --------------------------------------------------------------------------- #
# F. What the armed arm costs                                                  #
# --------------------------------------------------------------------------- #

class TestWhatTheArmCosts:
    """A client that authenticates and is refused anyway."""

    def test_a_stock_ticket_is_refused_on_the_armed_plane(self, planes):
        """security-negative: the client fails CLOSED.  It cannot answer the
        challenge and does not fall back to the single-round login it would
        have got from either other plane."""
        result = _xrdfs(planes.on, planes.stock, "stat", READ_FILE)
        assert result.returncode != 0, (
            f"a non-forwardable ticket was served by the armed plane\n"
            f"{_text(result)}")
        assert "Auth failed" in _text(result), _text(result)

    def test_the_refusal_is_the_forwarding_step_and_not_the_login(self, planes):
        """Which step failed, in the client's own words: the AP-REQ was fine
        and the KDC refused to issue a forwarded credential for it."""
        result = _xrdfs(planes.on, planes.stock, "stat", READ_FILE)
        assert "Unable to get forwarded credentials" in _text(result), (
            f"the stock client's diagnosis has changed\n{_text(result)}")

    def test_the_challenge_was_still_sent(self, planes):
        """The refusal is the client's, not the server's: the acceptor issued
        its one continuation and then never heard back."""
        result, rounds = _counted(planes, planes.on, planes.stock,
                                  "stat", READ_FILE)
        assert result.returncode != 0
        assert rounds == 1, (
            f"expected the challenge to go out anyway, saw {rounds}: "
            f"{planes.relay.statuses}")

    def test_the_refused_session_reads_nothing(self, planes):
        """security-negative: no partial grant.  The connection that failed the
        second round gets no file access at all."""
        result = _xrdfs(planes.on, planes.stock, "cat", READ_FILE)
        assert result.returncode != 0
        assert READ_BODY.decode() not in result.stdout, (
            f"a session that never completed authentication read the file\n"
            f"{_text(result)}")

    def test_this_repo_s_client_names_the_fix_and_upstream_s_does_not(self,
                                                                     planes):
        """The one place the clean-room client is the subject: both refuse, and
        only one tells the user which kinit flag they are missing.  Skipped
        rather than failed when the client has not been built — its absence
        says nothing about the directive."""
        if not BRIX_XRDFS.exists():
            pytest.skip("clean-room xrdfs not built")
        mine = _brix_xrdfs(planes.on, planes.stock, "stat", READ_FILE)
        assert mine.returncode != 0, _text(mine)
        assert "kinit -f" in _text(mine), (
            f"the clean-room client no longer names the fix\n{_text(mine)}")
        assert "kinit -f" not in _text(
            _xrdfs(planes.on, planes.stock, "stat", READ_FILE))


# --------------------------------------------------------------------------- #
# G. What an operator can see of it — DEFECT CANDIDATE #95                     #
# --------------------------------------------------------------------------- #

def _bad_credential(port):
    """One kXR_auth carrying a credtype the acceptor cannot read.

    The contrast case for #95, and the reason it is a wire client rather than
    xrdfs: no real client sends this, and the point is precisely that a refusal
    the SERVER makes is recorded while the refusal above is not.
    """
    from _test_pgwrite_cse_helpers import _handshake_login, _read_response

    sock = _handshake_login(url_host(HOST), port)
    try:
        cred = b"not-an-ap-req"
        sock.sendall(struct.pack("!2sH12s4sI", b"\x00\x03", kXR_auth,
                                 b"\x00" * 12, b"krb5", len(cred)) + cred)
        status, body = _read_response(sock)
    finally:
        _shutdown(sock)
    errcode = (struct.unpack("!I", body[:4])[0]
               if status == kXR_error and len(body) >= 4 else None)
    return status, errcode, body[4:]


class TestWhatAnOperatorCanSee:
    """FINDING #95 — the refusal that is neither logged nor counted."""

    def test_a_completed_delegation_is_logged(self, planes):
        """The baseline: the armed plane does write an AUTH record when the
        exchange finishes, so the silence below is about the failure and not
        about the plane."""
        mark = planes.mark("on")
        assert _xrdfs(planes.on, planes.forwardable, "stat",
                      READ_FILE).returncode == 0
        records = planes.since("on", mark)
        assert any('"AUTH - krb5" OK' in line for line in records), records

    def test_the_refusal_leaves_no_auth_record_at_all(self, planes):
        """FINDING #95: the same plane, one flag of the ticket different.  The
        client authenticated and got nothing, and the access log carries the
        LOGIN and the DISCONNECT with nothing between them."""
        mark = planes.mark("on")
        assert _xrdfs(planes.on, planes.stock, "stat",
                      READ_FILE).returncode != 0
        records = planes.since("on", mark)
        assert records, "the refused login is not in the access log at all"
        assert not any('"AUTH ' in line for line in records), (
            "the armed plane has learned to record a delegation refusal — #95 "
            "is fixed and this case should be inverted\n" + "\n".join(records))

    def test_the_refusal_moves_no_counter(self, planes):
        """The other face, and the one an operator watches: neither `ok` nor
        `fail` moves for a login that was refused."""
        mark = planes.mark("on")
        before = planes.auth_counts()
        assert _xrdfs(planes.on, planes.stock, "stat",
                      READ_FILE).returncode != 0
        # Read the counter only once the connection has finished logging, so a
        # counter that is merely LATE cannot pass for one that never moves.
        planes.since("on", mark)
        after = planes.auth_counts()
        assert after == before, (
            "brix_auth_total moved for a delegation refusal — #95 is fixed and "
            f"this case should be inverted: {before} -> {after}")

    def test_a_credential_the_server_rejects_is_both_logged_and_counted(
            self, planes):
        """The contrast that makes the two cases above a defect rather than a
        design: on the SAME plane in the same run, a refusal the acceptor
        itself makes writes an ERR record and moves `fail`."""
        mark = planes.mark("on")
        before = planes.auth_counts()
        status, errcode, _ = _bad_credential(planes.on)
        assert status == kXR_error and errcode == kXR_NotAuthorized
        records = planes.since("on", mark, needle="AUTH")
        assert any('"AUTH - krb5" ERR' in line for line in records), records
        after = planes.auth_counts()
        assert after.get("fail", 0) > before.get("fail", 0), (
            f"a malformed credential moved no fail counter: {before} -> "
            f"{after}")

    def test_a_delegated_login_is_counted_like_any_other(self, planes):
        """And the success side is no more informative: the armed plane's
        completed login moves `ok` by exactly what the off plane's does, so the
        counter cannot tell an operator whether delegation is happening."""
        before = planes.auth_counts()
        assert _xrdfs(planes.on, planes.forwardable, "stat",
                      READ_FILE).returncode == 0
        armed = planes.auth_counts()
        assert _xrdfs(planes.off, planes.forwardable, "stat",
                      READ_FILE).returncode == 0
        plain = planes.auth_counts()
        armed_delta = armed.get("ok", 0) - before.get("ok", 0)
        plain_delta = plain.get("ok", 0) - armed.get("ok", 0)
        assert armed_delta == plain_delta > 0, (
            f"armed +{armed_delta} vs plain +{plain_delta}: the counter has "
            f"learned to distinguish them, so #95 is narrower than recorded")

    def test_the_challenge_path_accounts_for_nothing(self):
        """Where #95 comes from, pinned in the C: every failure inside
        brix_krb5_begin_delegation is metered and logged, and the success
        return — the challenge itself — is not, because from the acceptor's
        point of view nothing has failed yet and nothing ever will."""
        source = _read(AUTH_C)
        body = source.split("brix_krb5_begin_delegation(brix_krb5_req_t *rq,",
                            1)[1].split("\n}\n", 1)[0]
        assert "brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_KRB5, 0);" in body
        tail = body.split("return brix_krb5_send_fwdtgt(ctx, c);", 1)[-1]
        assert "brix_metric_auth" not in tail and "brix_log_access" not in tail, (
            "the challenge path has learned to account for itself — #95 is "
            f"fixed and this case should be inverted\n{tail}")


# --------------------------------------------------------------------------- #
# H. Where the captured ticket lands — DEFECT CANDIDATE #96                    #
# --------------------------------------------------------------------------- #

class _Session:
    """A logged-in xrdfs held open, so the per-connection ccache can be looked
    at while it exists."""

    def __init__(self, port, ccache):
        self.proc = subprocess.Popen(
            [SYS_XRDFS, f"root://{url_host(HOST)}:{port}"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=_env(ccache))

    def stat(self):
        self.proc.stdin.write(f"stat {READ_FILE}\n")
        self.proc.stdin.flush()

    def close(self):
        try:
            self.proc.stdin.write("exit\n")
            self.proc.stdin.flush()
            self.proc.wait(timeout=30)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            self.proc.kill()


def _capture_while_open(port, ccache, directory=DEFAULT_CAPTURE_DIR):
    """Open a session, wait for its capture file, return (path, session)."""
    before = set(_captures(directory))
    session = _Session(port, ccache)
    session.stat()
    for _ in range(80):
        time.sleep(0.05)
        new = set(_captures(directory)) - before
        if new:
            return new.pop(), session
    return None, session


class TestWhereTheCapturedTicketLands:
    """FINDING #96 — /tmp, and a knob no config file can turn."""

    def test_the_capture_is_a_file_in_tmp_while_the_session_lives(self, planes):
        """The default rendering, which is every deployment that did not write
        an nginx `env` directive it was never told about."""
        path, session = _capture_while_open(planes.on, planes.forwardable)
        try:
            assert path is not None, (
                f"no capture file appeared under {DEFAULT_CAPTURE_DIR}\n"
                f"{planes.errlog()}")
        finally:
            session.close()

    def test_it_is_private_to_the_worker(self, planes):
        """security-negative: mkstemp's 0600 survives libkrb5 rewriting the
        file by name, and the file is owned by the worker's own uid.  This is
        what keeps #96 a siting question rather than an exposure."""
        path, session = _capture_while_open(planes.on, planes.forwardable)
        try:
            assert path is not None
            info = path.stat()
            assert oct(info.st_mode & 0o777) == "0o600", oct(info.st_mode)
            assert info.st_uid == os.getuid()
        finally:
            session.close()

    def test_what_sits_there_is_a_usable_tgt(self, planes):
        """Why the location is worth a finding at all: the file is not an
        opaque blob but a credential cache holding the user's ticket-granting
        ticket, readable as one by anything running as that uid."""
        path, session = _capture_while_open(planes.on, planes.forwardable)
        try:
            assert path is not None
            out = subprocess.run([SYS_KLIST, "-c", "FILE:" + str(path)],
                                 env={**os.environ, "KRB5_CONFIG": KRB5_CONF},
                                 capture_output=True, text=True, timeout=30)
            assert out.returncode == 0, _text(out)
            assert "alice@" in out.stdout, out.stdout
            assert "krbtgt/" in out.stdout, out.stdout
        finally:
            session.close()

    def test_it_is_unlinked_when_the_connection_closes(self, planes):
        """The pool cleanup at deleg_capture.c:163-172, measured: the ccache is
        per-connection and does not outlive it."""
        path, session = _capture_while_open(planes.on, planes.forwardable)
        assert path is not None
        session.close()
        for _ in range(40):
            time.sleep(0.05)
            if not path.exists():
                break
        assert not path.exists(), f"{path} outlived its connection"

    def test_the_off_plane_writes_nothing_anywhere(self, planes):
        """security-negative: the arm nobody wrote never puts a user's TGT on
        disk at all, which is the other half of what the pair buys."""
        before = set(_captures())
        session = _Session(planes.off, planes.forwardable)
        session.stat()
        time.sleep(1.0)
        try:
            assert set(_captures()) - before == set(), (
                "the off arm wrote a ccache under /tmp")
        finally:
            session.close()

    def test_only_an_nginx_env_directive_can_move_it(self, relocated):
        """FINDING #96: the same instance rendered with `env TMPDIR;` puts the
        capture in the handed-in directory, and without it the same $TMPDIR is
        invisible to the worker — nginx rebuilds the environment from the env
        list alone, so the C's documented fallback is the only reachable
        behaviour until an operator writes a directive belonging to nginx
        rather than to this module."""
        endpoint, ticket, ccdir = relocated
        assert "env TMPDIR;" in _read(endpoint.config)
        path, session = _capture_while_open(endpoint.port, ticket, ccdir)
        try:
            assert path is not None, (
                f"the capture did not follow $TMPDIR into {ccdir} — #96 has "
                f"changed shape\n{_read(os.path.join(endpoint.prefix, 'logs', 'error.log'))}")
            assert path.parent == ccdir
            assert oct(path.stat().st_mode & 0o777) == "0o600"
        finally:
            session.close()

    def test_the_directory_is_the_c_s_own_fallback(self):
        """Pinned at the source, so a change to either the template or the
        fallback has to come past this file."""
        source = _read(CAPTURE_C)
        assert 'const char *dir = getenv("TMPDIR");' in source
        assert 'dir = "/tmp";' in source
        assert '"%s/brix-krb5-fwd-XXXXXX"' in source
        assert "fd = mkstemp(path);" in source

    def test_no_config_in_the_corpus_writes_that_env_directive(self):
        """And the census half of #96: nothing in the coverage corpus except
        this file's own §G rendering asks nginx to pass TMPDIR to a worker, so
        no deployment modelled by the suite has ever moved a capture."""
        writers = sorted(path.name for path in CONFIGS.glob("*.conf")
                         if re.search(r"^\s*env\s+TMPDIR\s*;", _read(path),
                                      re.MULTILINE))
        assert writers == [], (
            f"a config now writes `env TMPDIR;`: {writers} — fold it into #96")


# --------------------------------------------------------------------------- #
# I. The parse tier                                                            #
# --------------------------------------------------------------------------- #

def _knobs(*lines):
    return "".join(f"        {line}\n" for line in lines)


def _second_server(*lines):
    """A whole second stream server for the parse scaffold.

    Its listen port is the OTHER placeholder: ngx_stream_core_listen refuses a
    repeated address/port pair, and that error would arrive before whatever the
    case is actually asking about.
    """
    body = "".join(f"        {line}\n" for line in lines)
    return (f"\n    server {{\n"
            f"        listen {SHARED_PARSE_PLACEHOLDER_PORT};\n"
            f"        brix_root on;\n"
            f"{body}    }}\n")


def _parse(tmp_path, knobs="", srv_extra="", stream_extra="", http_knobs="",
           outer=""):
    """`nginx -t` over file 5's scaffold, which writes no directive of its own.

    Shared rather than copied: the scaffold's shape — one stream server, a
    second one on the other placeholder, and the three placement slots — is
    exactly what a stream-srv flag needs, and a second copy of it would be a
    config whose only difference is the name in its header.
    """
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit16eparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT,
                     HTTP_PORT=PARSE_PLACEHOLDER_PORT,
                     LOG_DIR=str(tmp_path), DATA=str(data), KNOBS=knobs,
                     SRV_EXTRA=srv_extra, STREAM_EXTRA=stream_extra,
                     HTTP_KNOBS=http_knobs, OUTER=outer)
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


class TestTheParseTier:
    """What the flag accepts and refuses.  Nothing here starts a server, needs
    a realm or a KDC, or touches anything outside its own tmp_path."""

    @pytest.mark.parametrize("value", ["on", "off"])
    def test_both_values_parse(self, tmp_path, value):
        """success: the two arms at the tier that costs nothing — and the
        reason a value-granularity sweep exists, since `off` had never been
        written anywhere in the corpus in any form."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} {value};"))
        assert rc == 0, f"{DIRECTIVE} {value} was rejected\n{out}"

    @pytest.mark.parametrize("value", ["On", "OFF", "oFf"])
    def test_the_values_are_case_insensitive(self, tmp_path, value):
        """ngx_conf_set_flag_slot compares case-insensitively, which is worth a
        row because a config that spells it `Off` is the same config."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} {value};"))
        assert rc == 0, f"the flag slot rejected {value!r}\n{out}"

    @pytest.mark.parametrize("value", ["1", "0", "true", "yes", "disabled"])
    def test_a_plausible_synonym_is_refused(self, tmp_path, value):
        """security-negative: a spelling that looks like it disables delegation
        must not parse into the enabled arm.  `0` is the dangerous direction —
        it reads as off and is not."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} {value};"))
        assert rc != 0 and f'invalid value "{value}"' in out, out

    def test_an_empty_value_is_refused(self, tmp_path):
        """security-negative: an unset shell variable expanding to "" must not
        silently become an arm."""
        rc, out = _parse(tmp_path, _knobs(f'{DIRECTIVE} "";'))
        assert rc != 0 and 'invalid value ""' in out, out

    @pytest.mark.parametrize("line", [f"{DIRECTIVE};",
                                      f"{DIRECTIVE} on off;"])
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, line):
        rc, out = _parse(tmp_path, _knobs(line))
        assert rc != 0, f"{line!r} parsed\n{out}"
        assert "invalid number of arguments" in out, out

    def test_a_duplicate_directive_is_refused(self, tmp_path):
        """security-negative: two arms in one server must be an error rather
        than a last-one-wins, or a config could carry both and mean either."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} on;",
                                          f"{DIRECTIVE} off;"))
        assert rc != 0 and "is duplicate" in out, out

    def test_the_directive_is_refused_at_stream_level(self, tmp_path):
        """NGX_STREAM_SRV_CONF and nothing else: a site-wide default is exactly
        what an operator would try, and it must not parse."""
        rc, out = _parse(tmp_path, stream_extra=f"    {DIRECTIVE} on;\n")
        assert rc != 0 and "directive is not allowed here" in out, out

    def test_the_directive_is_refused_in_an_http_server(self, tmp_path):
        """The WebDAV face has its own auth and no delegation round at all."""
        rc, out = _parse(tmp_path, http_knobs=_knobs(f"{DIRECTIVE} on;"))
        assert rc != 0 and "directive is not allowed here" in out, out

    def test_the_directive_is_refused_at_main_context(self, tmp_path):
        rc, out = _parse(tmp_path, outer=f"{DIRECTIVE} on;\n")
        assert rc != 0 and "directive is not allowed here" in out, out

    def test_it_parses_on_a_server_that_has_no_krb5_auth(self, tmp_path):
        """A flag slot has no view of the auth method, so a server that can
        never reach the gate accepts the directive silently.  Recorded rather
        than filed: the same is true of every auth-specific flag in the table,
        and diagnosing it would need a merge-time check this module does not
        have for any of them."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} on;"))
        assert rc == 0, out
        assert "delegate" not in out, (
            f"the parse now says something about a delegation nobody can "
            f"reach\n{out}")

    def test_two_servers_may_disagree(self, tmp_path):
        """The parse-tier statement of §E's runtime measurement: a per-server
        flag with two values in one config is not a conflict."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} on;"),
                         srv_extra=_second_server(f"{DIRECTIVE} off;"))
        assert rc == 0, out


# --------------------------------------------------------------------------- #
# J. The mechanism is where this file says it is                               #
# --------------------------------------------------------------------------- #

class TestTheMechanismIsWhereTheFileSaysItIs:
    """Source pins for the claims above that no runtime case can make."""

    def test_the_declaration_is_a_stream_server_flag(self):
        declaration = _read(DIRECTIVES_H)
        block = declaration.split(f'ngx_string("{DIRECTIVE}")', 1)[1][:300]
        assert "NGX_STREAM_SRV_CONF | NGX_CONF_FLAG" in block, block
        assert "ngx_conf_set_flag_slot" in block, block
        assert "offsetof(ngx_stream_brix_srv_conf_t, krb5.delegate)" in block

    def test_the_flag_has_exactly_one_reader(self):
        """Everything else in the delegation path keys off ctx->krb5.round, so
        the gate is read once per connection and never again.  Two sites touch
        the field across src/: the merge that gives it its default, and the
        predicate §C-§E measure."""
        sites = {path.relative_to(ROOT).as_posix()
                 for path in (ROOT / "src").rglob("*.c")
                 if "conf->krb5.delegate" in _read(path)}
        assert sites == {"src/core/config/server_conf_merge_security.c",
                         "src/auth/krb5/deleg_capture.c"}, sites
        assert "return conf != NULL && conf->krb5.delegate == 1;" in _read(
            CAPTURE_C)

    def test_round_two_is_dispatched_on_the_parked_state(self):
        """Why the second message does not need the gate: a connection that has
        been challenged is already in round 1, and that is what routes it."""
        source = _read(AUTH_C)
        assert "if (ctx->krb5.round == 1) {" in source
        assert "return brix_krb5_finish_delegation(&rq);" in source

    def test_the_capture_lands_in_memory_before_it_reaches_a_file(self):
        """The order matters for #96: the forwarded credential is parked in a
        private MEMORY ccache (capture.c) and only then exported to the 0600
        temp file, so what lands in /tmp is a copy the acceptor makes for the
        origin leg rather than the working credential itself."""
        assert 'krb5_cc_new_unique(kctx, "MEMORY", NULL, &cc);' in _read(
            MEMORY_C)
        capture = _read(CAPTURE_C)
        assert capture.index("brix_krb5_deleg_mkccache(c, path, pathlen)") \
            < capture.index("brix_krb5_cred_to_ccache(*gss_cred, path,"), (
                "the export no longer follows the temp-file creation")

    def test_the_notice_carries_no_delegation_word(self):
        """#95's config-time half, pinned where it is emitted."""
        source = _read(CONFIG_C)
        notice = source.split(NOTICE, 1)[1][:400]
        assert "ip_check=" in notice
        assert "delegate" not in notice, notice

    def test_the_corpus_wrote_the_on_arm_twice_and_the_off_arm_here(self):
        """The census this file closes, re-measured so it cannot rot: `on` in
        the two configs the audit names, `off` only in this file's own."""
        on_writers = sorted(path.name for path in CONFIGS.glob("*.conf")
                            if _writes(_read(path), "on"))
        off_writers = sorted(path.name for path in CONFIGS.glob("*.conf")
                             if _writes(_read(path), "off"))
        def _assert_test_the_corpus_wrote_the_on_arm_twice_and_the_off_arm_here_1():
            assert on_writers == ["nginx_audit16s_krb5_delegate.conf",
                                  "nginx_lc_krb5_cache_origin.conf",
                                  "nginx_lc_native_krb5_delegate.conf"], on_writers
            assert off_writers == ["nginx_audit16s_krb5_delegate.conf"], off_writers

        _assert_test_the_corpus_wrote_the_on_arm_twice_and_the_off_arm_here_1()

    def test_the_two_existing_delegation_tests_write_only_the_on_arm(self):
        """Why this file is not a duplicate of either: neither writes `off`,
        and neither has a second plane to compare against."""
        here = Path(__file__).resolve().parent
        for name in ("test_krb5_delegation_e2e.py", "test_krb5_delegate_load.py"):
            text = _read(here / name)
            assert not _writes(text, "off"), (
                f"{name} now writes the off arm; the pair has a second closer")
