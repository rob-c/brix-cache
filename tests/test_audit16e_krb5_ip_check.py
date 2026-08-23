"""brix_krb5_ip_check at VALUE granularity — audit §Method, 16th tranche.

WHY THIS FILE EXISTS
--------------------
The audit's Method (steps 1-2) counts directive NAMES.  Re-running the
measurement per (directive, VALUE) over the 128 ``ngx_conf_set_flag_slot``
directives in ``src/`` turned 256 pairs into 138 written literally, 12 reachable
only through a ``{PLACEHOLDER}``, and 106 written nowhere at all.  Seven
directives have BOTH arms unwritten; ``brix_krb5_ip_check`` is the sixth of the
seven this tranche takes, and it is the only one of them whose subject is an
authentication decision.

WHAT THE VALUE SELECTS
----------------------
One optional stage of the krb5 acceptor::

    src/auth/krb5/auth.c:213-259
        brix_krb5_bind_peer(rq, auth_ctx, out)
            if (!conf->krb5.ip_check) {
                return NGX_OK;              /* off: the stage is skipped */
            }
            brix_krb5_peer_addr(c, &peer_addr)      -> INET / INET6 only
            krb5_auth_con_setaddrs(ctx, auth_ctx, NULL, &peer_addr)

Binding the peer address into the auth context is what makes the following
``krb5_rd_req()`` compare it against the ticket's own address list.  Nothing
else changes: same opcode, same round count, same reply on success.

WHAT THE TABLE ESTABLISHES
--------------------------
Three acceptors in ONE process, off one realm, one principal and one keytab,
differing only in the directive.  The client's SOURCE address is the variable —
an in-process TCP relay connects onward from a second loopback address, which is
the only way to make the address the server sees differ from the address the
ticket was issued for:

    ticket addresses      plane      source        login
    127.0.0.1 (+ host)    on         127.0.0.1     OK
    127.0.0.1 (+ host)    on         127.0.0.2     REFUSED (Incorrect net address)
    127.0.0.1 (+ host)    off        127.0.0.2     OK
    127.0.0.1 (+ host)    absent     127.0.0.2     OK      (merge default is off)
    (none)                on         127.0.0.1     OK
    (none)                on         127.0.0.2     OK      <- see #70

Row 2 against rows 3 and 4 is the pair, and the three planes reaching three
verdicts for one AP-REQ in one worker is also the statement that this flag —
unlike ``brix_cvmfs_origin_reuse_conn`` two files ago — really is per-server.

FINDING — DEFECT CANDIDATE #70
------------------------------
``brix_krb5_ip_check on`` is silently inert for the ticket a stock ``kinit``
produces.  ``krb5_rd_req()`` only compares addresses when the ticket carries
any, and MIT's ``noaddresses`` defaults to true, so an addressless ticket walks
past the enabled check from any address at all (rows 5-6).  Getting an addressed
ticket at all takes ``noaddresses = false`` in the CLIENT's profile — a decision
the server operator who enabled the check does not make and cannot see.

The behaviour matches upstream ``XrdSeckrb5 -ipchk``, so this is not a
divergence.  What is missing is any way to tell the two cases apart: the
acceptor logs nothing when it binds an address, nothing when the ticket has none
to check, and ``brix_auth_total`` counts an unchecked login exactly like a
checked one.  An operator who enables ``brix_krb5_ip_check`` gets no signal
whatsoever that it did nothing — the control is unverifiable from the server
side, which for a security control is the whole problem.  §C pins that, and
§A pins the one word of config-time feedback that does exist.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
Nothing here says the check is worth enabling.  Address-bound tickets do not
survive NAT, and the README (auth/krb5/README.md:159-162) is right that off is
the correct default; the address list in a ticket is also not an authentication
of anything, since an attacker who can present a stolen AP-REQ can usually
present it from the address it names.  Measured here is only what the two values
do, to whom, and what an operator can see of it.
"""

import os
import shutil
import socket
import subprocess
import threading
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

pytestmark = [pytest.mark.timeout(600),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16e-ipcheck")]

NAME = "lc-audit16e-ipcheck"
_EXTRA = LIFECYCLE_SHARED_PORTS[NAME]["extra"]
OFF_PORT = _EXTRA["OFF_PORT"]
ABSENT_PORT = _EXTRA["ABSENT_PORT"]
RELAY_PORT = _EXTRA["RELAY_PORT"]
METRICS_PORT = _EXTRA["METRICS_PORT"]

ROOT = Path(__file__).resolve().parents[1]
AUTH_C = ROOT / "src/auth/krb5/auth.c"
CONFIG_C = ROOT / "src/auth/krb5/config.c"
MERGE_C = ROOT / "src/core/config/server_conf_merge_security.c"

DIRECTIVE = "brix_krb5_ip_check"

# The second loopback address.  Linux gives `lo` the whole 127/8, so this is
# bindable without configuring anything, and it is NOT one of the addresses MIT
# puts in a ticket (krb5_os_localaddr drops 127/8), which is what makes it a
# mismatch rather than a coincidence.  The fixture asserts both.
FOREIGN = "127.0.0.2"  # net-literal-allow: the AP-REQ source address IS the subject

READ_FILE = "/hello.txt"
READ_BODY = b"krb5 ip check\n"

SYS_XRDFS = shutil.which("xrdfs")
SYS_KINIT = shutil.which("kinit") or "/usr/bin/kinit"
SYS_KLIST = shutil.which("klist") or "/usr/bin/klist"


# --------------------------------------------------------------------------- #
# Tickets                                                                      #
# --------------------------------------------------------------------------- #

class _Ticket:
    """A credential cache and the krb5 profile that has to be used with it.

    The two travel together because the profile is what decided whether the
    ticket carries addresses at all, and the TGS exchange that turns the TGT
    into a service ticket has to be made under the same policy.
    """

    def __init__(self, ccache, profile, addresses):
        self.ccache = str(ccache)
        self.profile = str(profile)
        self.addresses = addresses


def _klist_addresses(ticket_ccache, profile):
    """The address set the cached TGT names, empty for an addressless ticket."""
    out = subprocess.run(
        [SYS_KLIST, "-a", "-n", "-c", str(ticket_ccache)],
        env={**os.environ, "KRB5_CONFIG": str(profile)},
        capture_output=True, text=True, timeout=30).stdout
    addresses = set()
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("Addresses:"):
            continue
        value = line.split(":", 1)[1].strip()
        if value and value != "(none)":
            addresses.update(part.strip() for part in value.split(","))
    return addresses


def _kinit(profile, ccache):
    subprocess.run(
        [SYS_KINIT, "-k", "-t", KRB5_CLIENT_KEYTAB, "-c", str(ccache),
         KRB5_CLIENT_PRINCIPAL],
        env={**os.environ, "KRB5_CONFIG": str(profile)},
        check=True, capture_output=True, timeout=60)


def _addressed_ticket(base):
    """A TGT whose address list names the address the client connects FROM.

    ``noaddresses = false`` turns MIT's default off so the AS-REQ asks for an
    addressful ticket at all.  ``extra_addresses`` is then required rather than
    cosmetic: ``krb5_os_localaddr()`` skips 127/8, so without it the ticket
    would name only the host's routable addresses and the KDC would refuse the
    very next TGS-REQ — which arrives over loopback — as BADADDR, leaving the
    client with no service ticket to present and nothing for the server's check
    to have an opinion about.
    """
    profile = base / "krb5-addressed.conf"
    text = Path(KRB5_CONF).read_text()
    marker = "[libdefaults]\n"
    assert marker in text, f"the generated profile changed shape:\n{text}"
    profile.write_text(text.replace(
        marker,
        f"{marker}    noaddresses = false\n    extra_addresses = {HOST}\n", 1))
    ccache = base / "ccache-addressed"
    _kinit(profile, ccache)
    return _Ticket(ccache, profile, _klist_addresses(ccache, profile))


def _addressless_ticket():
    """The credential cache ``kdc_helpers.up()`` already minted.

    Nothing about it is special, and that is exactly why it is here: it is what
    a stock ``kinit`` against a stock profile produces, which is what every real
    client presents.
    """
    return _Ticket(KRB5_CCACHE, KRB5_CONF,
                   _klist_addresses(KRB5_CCACHE, KRB5_CONF))


# --------------------------------------------------------------------------- #
# The relay — the instrument                                                   #
# --------------------------------------------------------------------------- #

class _Relay:
    """A TCP relay whose only job is to change the client's SOURCE address.

    The AP-REQ address check compares the ticket's address list against the
    address the server accepted the connection from, and the stock XRootD client
    offers no way to choose that.  So the client connects here, and this
    connects onward from ``source`` — nothing is parsed, rewritten or delayed,
    which matters: the krb5 exchange has no channel binding, so a relayed
    AP-REQ is byte-for-byte the AP-REQ the client would have sent directly.

    ``target`` is read on every accept rather than fixed at construction, so one
    relay (one ledger port) can be pointed at whichever plane a case is asking
    about.
    """

    def __init__(self, port, source, target):
        self.source = source
        self.target = target
        self._stop = False
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((HOST, port))
        self._listener.listen(8)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            try:
                upstream = socket.socket()
                from ephemeral_port import free_port
                upstream.bind((self.source, free_port(self.source)))
                upstream.connect((HOST, self.target))
            except OSError:
                client.close()
                continue
            for src, dst in ((client, upstream), (upstream, client)):
                threading.Thread(target=self._pump, args=(src, dst),
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
            # Both directions tear down the same pair; the second one through
            # finds the sockets already closed, which is why every call here is
            # guarded rather than ordered.
            for sock in (src, dst):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()

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


def _foreign_address_usable():
    """Whether this host lets a socket bind the second loopback address."""
    probe = socket.socket()
    try:
        from ephemeral_port import free_port
        probe.bind((FOREIGN, free_port(FOREIGN)))
        return True
    except OSError:
        return False
    finally:
        probe.close()


# --------------------------------------------------------------------------- #
# The three planes                                                             #
# --------------------------------------------------------------------------- #

class _Planes:
    """The started instance plus the two things every case needs from it: which
    port carries which value, and where each plane wrote its audit trail."""

    def __init__(self, endpoint, relay, tmp_path):
        self.endpoint = endpoint
        self.relay = relay
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

    def auth_failures(self):
        """brix_auth_total{proto="root",method="krb5",status="fail"}.

        Read through the http face rather than out of the log, because a metric
        is what an operator actually watches, and because the counter lives in
        shared memory the stream workers write and the http worker reads — which
        is the only assertion here that the two faces agree.
        """
        body = requests.get(f"http://{HOST}:{METRICS_PORT}/metrics",
                            timeout=15).text
        # proto="stream", not "root": the root:// plane's metric label comes
        # from core/types/proto_list.h:59, where the ROOT row's label is the
        # nginx module it lives in rather than the URL scheme it speaks.
        needle = 'brix_auth_total{proto="stream",method="krb5",status="fail"}'
        for line in body.splitlines():
            if line.startswith(needle):
                return int(line.rsplit(" ", 1)[1])
        raise AssertionError(f"{needle} is missing from the exposition:\n{body}")


def _read(path):
    try:
        with open(path) as handle:
            return handle.read()
    except OSError:
        return ""


@pytest.fixture
def planes(lifecycle, tmp_path):
    """One realm, one keytab, three acceptors, one relay."""
    _require_plane_environment()
    data = tmp_path / "data"
    data.mkdir()
    (data / os.path.basename(READ_FILE)).write_bytes(READ_BODY)
    os.environ["KRB5_CONFIG"] = KRB5_CONF
    endpoint = _start_plane_endpoint(lifecycle, data)
    relay = _Relay(RELAY_PORT, FOREIGN, endpoint.port)
    try:
        yield _Planes(endpoint, relay, tmp_path)
    finally:
        relay.close()
        kdc_helpers.down()


def _require_plane_environment():
    checks = (
        (lambda: SYS_XRDFS is None, "stock xrdfs not on PATH"),
        (lambda: not os.access(NGINX_BIN, os.X_OK),
         f"nginx binary not executable: {NGINX_BIN}"),
        (lambda: not kdc_helpers.krb5_tools_available(),
         "MIT KDC tooling not installed (install krb5-server)"),
        (lambda: not _foreign_address_usable(),
         f"{FOREIGN} is not bindable on this host"),
        (lambda: not kdc_helpers.up(), "krb5 realm could not be provisioned"),
    )
    for unavailable, reason in checks:
        if unavailable():
            pytest.skip(reason)


def _start_plane_endpoint(lifecycle, data):
    spec = NginxInstanceSpec(
        name=NAME,
        template="nginx_audit16e_ipcheck.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"PRINCIPAL": KRB5_SERVICE_PRINCIPAL,
                         "KEYTAB": KRB5_KEYTAB},
        env={"KRB5_CONFIG": KRB5_CONF},
        reason="audit-16e the krb5 AP-REQ source-IP check at value granularity",
    )
    try:
        return lifecycle.start(spec)
    except Exception:
        kdc_helpers.down()
        raise


# --------------------------------------------------------------------------- #
# Client                                                                       #
# --------------------------------------------------------------------------- #

def _xrdfs(port, ticket, *args):
    """The stock client, pinned to krb5 and to one credential cache.

    X509_* is stripped so a stray proxy in the ambient environment can never
    make this a GSI test by accident — the whole file would then measure a
    protocol that has no address check at all.
    """
    env = os.environ.copy()
    env["XrdSecPROTOCOL"] = "krb5"
    env["KRB5_CONFIG"] = ticket.profile
    env["KRB5CCNAME"] = ticket.ccache
    for stray in ("X509_USER_PROXY", "X509_USER_CERT", "X509_USER_KEY"):
        env.pop(stray, None)
    return subprocess.run(["xrdfs", f"root://{url_host(HOST)}:{port}", *args],
                          env=env, capture_output=True, text=True, timeout=60)


def _relayed(planes, plane_port, ticket, *args):
    """The same login, arriving from FOREIGN instead of from HOST."""
    planes.relay.target = plane_port
    return _xrdfs(RELAY_PORT, ticket, *args)


def _refused(result):
    return result.returncode != 0 and "Auth failed" in (
        result.stdout + result.stderr)

from split_continuation import load as _load_continuations
_load_continuations(
    globals(), __file__,
    "_test_audit16e_krb5_ip_check_part2.py",
    "_test_audit16e_krb5_ip_check_part3.py",
)
