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
    if SYS_XRDFS is None:
        pytest.skip("stock xrdfs not on PATH")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    if not kdc_helpers.krb5_tools_available():
        pytest.skip("MIT KDC tooling not installed (install krb5-server)")
    if not _foreign_address_usable():
        pytest.skip(f"{FOREIGN} is not bindable on this host")
    if not kdc_helpers.up():
        pytest.skip("krb5 realm could not be provisioned")

    data = tmp_path / "data"
    data.mkdir()
    (data / os.path.basename(READ_FILE)).write_bytes(READ_BODY)

    # The acceptor resolves default_realm and auth_to_local out of the generated
    # profile, and the launcher's `nginx -t` runs in this process — so the
    # ambient environment needs it too, not just the daemon's.
    os.environ["KRB5_CONFIG"] = KRB5_CONF

    try:
        endpoint = lifecycle.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit16e_ipcheck.conf",
            protocol="root",
            readiness="tcp",
            data_root=str(data),
            template_values={"PRINCIPAL": KRB5_SERVICE_PRINCIPAL,
                             "KEYTAB": KRB5_KEYTAB},
            env={"KRB5_CONFIG": KRB5_CONF},
            reason="audit-16e the krb5 AP-REQ source-IP check at value "
                   "granularity"))
    except Exception:
        kdc_helpers.down()
        raise

    relay = _Relay(RELAY_PORT, FOREIGN, endpoint.port)
    try:
        yield _Planes(endpoint, relay, tmp_path)
    finally:
        relay.close()
        kdc_helpers.down()


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


# --------------------------------------------------------------------------- #
# A. What the value says at config time                                        #
# --------------------------------------------------------------------------- #

def _notice_values(text):
    """The ip_check word of every "krb5 auth configured" NOTICE, in order.

    The launcher's `nginx -t` and the daemon's own start both parse the same
    config into the same error log, so the sequence is the three planes'
    values repeated once per parse — which is why the assertions below check
    the shape of the whole run rather than a count.
    """
    values = []
    for line in text.splitlines():
        if "krb5 auth configured" not in line:
            continue
        for field in line.split():
            if field.startswith("ip_check="):
                values.append(field.split("=", 1)[1])
    return values


class TestTheValueAtConfigTime:
    """The one word of feedback an operator gets for this directive."""

    def test_each_plane_states_its_own_value(self, planes):
        """success: the NOTICE (auth/krb5/config.c:252-257) is the only place
        either arm is ever named, and it names all three — `on`, `off`, and the
        merge default that made the silent plane `off` too."""
        values = _notice_values(planes.errlog())
        assert values, (
            "no krb5 NOTICE was logged at all — the acceptor never got as far "
            f"as reading the flag\n{planes.errlog()}")
        assert len(values) % 3 == 0, (
            f"expected the three planes' values per parse, got {values}")
        for start in range(0, len(values), 3):
            assert values[start:start + 3] == ["on", "off", "off"], (
                f"the planes' values came out as {values[start:start + 3]}")

    def test_the_three_planes_share_one_principal_and_one_keytab(self, planes):
        """The attribution control, stated at the only moment it is checkable.

        Everything §B asserts is a difference between these three listeners; if
        they differed in the keytab or the principal as well, a refusal would
        have a second explanation and the pair would prove nothing."""
        principals, keytabs = set(), set()
        for line in planes.errlog().splitlines():
            if "krb5 auth configured" not in line:
                continue
            for field in line.split():
                if field.startswith("principal="):
                    principals.add(field.split("=", 1)[1])
                if field.startswith("keytab="):
                    keytabs.add(field.split("=", 1)[1])
        assert len(principals) == 1, f"the planes disagree on principal: {principals}"
        assert len(keytabs) == 1, f"the planes disagree on keytab: {keytabs}"


# --------------------------------------------------------------------------- #
# B. What the value does to an addressed ticket                                #
# --------------------------------------------------------------------------- #

class TestTheCheckWithAnAddressedTicket:
    """The pair.  One AP-REQ, one source address, three verdicts."""

    def test_the_ticket_names_the_direct_address_and_not_the_relayed_one(
            self, planes):
        """The instrument, asserted rather than assumed.

        Every case below reads as "refused because the address is wrong" only
        if the ticket really does name HOST and really does not name FOREIGN.
        Both are properties of MIT's address enumeration, and both are checked
        here so that a host where they stop holding fails with the reason."""
        ticket = _addressed_ticket(planes.tmp_path)
        assert HOST in ticket.addresses, (
            f"the addressed ticket does not name {HOST}: {ticket.addresses}")
        assert FOREIGN not in ticket.addresses, (
            f"{FOREIGN} is in the ticket's own address list ({ticket.addresses})"
            " — it can no longer serve as the mismatching source")

    def test_a_matching_address_authenticates_with_the_check_on(self, planes):
        """success: the enabled check passes an AP-REQ that arrives from an
        address the ticket names.  Without this row the refusal below would be
        indistinguishable from "the enabled check refuses everything"."""
        ticket = _addressed_ticket(planes.tmp_path)
        result = _xrdfs(planes.on, ticket, "stat", READ_FILE)
        assert result.returncode == 0, (
            f"a matching address was refused\n{result.stdout}{result.stderr}\n"
            f"{planes.errlog()}")
        assert "Size:   14" in result.stdout or "Size:" in result.stdout

    def test_a_foreign_source_address_is_refused_with_the_check_on(self, planes):
        """error: the same credential, the same server, one hop through a relay
        that connects onward from FOREIGN — and the AP-REQ no longer matches the
        address it arrives from."""
        ticket = _addressed_ticket(planes.tmp_path)
        result = _relayed(planes, planes.on, ticket, "stat", READ_FILE)
        assert _refused(result), (
            "a foreign source address authenticated against the enabled check\n"
            f"{result.stdout}{result.stderr}")
        assert "Incorrect net address" in planes.errlog(), (
            "the refusal did not come from the address check — a different "
            f"failure is wearing its clothes\n{planes.errlog()}")

    def test_the_same_request_is_accepted_with_the_check_off(self, planes):
        """success, and the other half of the pair: nothing about the credential
        or the route changed, only the directive."""
        ticket = _addressed_ticket(planes.tmp_path)
        result = _relayed(planes, planes.off, ticket, "stat", READ_FILE)
        assert result.returncode == 0, (
            "the disabled check refused a foreign source address\n"
            f"{result.stdout}{result.stderr}\n{planes.errlog()}")

    def test_the_silent_plane_accepts_it_too(self, planes):
        """The merge default (core/config/server_conf_merge_security.c:240) is
        0, so a server that never mentions the directive must behave exactly
        like one that wrote `off` — measured, not read off the C."""
        ticket = _addressed_ticket(planes.tmp_path)
        result = _relayed(planes, planes.absent, ticket, "stat", READ_FILE)
        assert result.returncode == 0, (
            "the merge default is not off\n"
            f"{result.stdout}{result.stderr}\n{planes.errlog()}")

    def test_the_refusal_reaches_the_enabled_plane_s_access_log(self, planes):
        """The audit trail.  A refusal that only exists as an error-log [warn]
        cannot be alerted on; the ERR record names the address that was turned
        away, which is the one fact an operator needs."""
        ticket = _addressed_ticket(planes.tmp_path)
        assert _refused(_relayed(planes, planes.on, ticket, "stat", READ_FILE))
        entries = [line for line in planes.accesslog("on").splitlines()
                   if " ERR " in line]
        assert entries, (
            "the enabled plane logged no refusal at all\n"
            f"{planes.accesslog('on')}\n{planes.errlog()}")
        assert any(line.startswith(FOREIGN) and "AUTH" in line
                   for line in entries), (
            f"no ERR record names {FOREIGN}\n" + "\n".join(entries))

    def test_the_refusal_is_counted_as_a_krb5_auth_failure(self, planes):
        """And the metric, because a counter is what gets watched.  Taken as a
        delta around the one refusal, since the family is process-wide shared
        memory that every plane writes."""
        ticket = _addressed_ticket(planes.tmp_path)
        before = planes.auth_failures()
        assert _refused(_relayed(planes, planes.on, ticket, "stat", READ_FILE))
        assert planes.auth_failures() > before, (
            "brix_auth_total{...,status=\"fail\"} did not move for a refused "
            "AP-REQ")

    def test_the_refusal_does_not_name_the_client_principal(self, planes):
        """security-negative: the address check runs INSIDE krb5_rd_req, so the
        ticket is never decrypted and the principal is never learned.  Nothing
        derived from an unverified AP-REQ may reach the log — and the accepted
        login on the off plane, which does name `alice`, is what shows the
        difference is the verdict rather than the log format."""
        ticket = _addressed_ticket(planes.tmp_path)
        assert _refused(_relayed(planes, planes.on, ticket, "stat", READ_FILE))
        refusals = [line for line in planes.errlog().splitlines()
                    if "credential verification failed" in line]
        assert refusals, planes.errlog()
        for line in refusals:
            assert "alice" not in line, (
                f"the refusal leaked the claimed principal: {line}")

        assert _relayed(planes, planes.off, ticket,
                        "stat", READ_FILE).returncode == 0
        assert 'principal="alice"' in planes.errlog(), (
            "the accepted login on the off plane did not name the principal — "
            "the contrast this test rests on is gone")


# --------------------------------------------------------------------------- #
# C. DEFECT CANDIDATE #70 — the check the ticket can opt out of                #
# --------------------------------------------------------------------------- #

class TestTheCheckIsInertForAnAddresslessTicket:
    """What ``on`` is worth against the credential every real client presents."""

    def test_a_stock_kinit_produces_an_addressless_ticket(self, planes):
        """The premise: ``kdc_helpers.up()`` kinits through the generated
        profile with no ``noaddresses`` line at all, and MIT's default for it is
        true.  Nothing in this suite, and nothing in a normal deployment, asks
        for anything else."""
        assert _addressless_ticket().addresses == set(), (
            "the stock credential cache now carries addresses — #70 needs "
            "re-deriving, and so does the profile in kdc_helpers")

    def test_the_enabled_check_accepts_it_from_a_foreign_address(self, planes):
        """security-negative, and the finding: the AP-REQ arrives from an
        address no ticket ever named, against a server whose operator switched
        the address check ON, and it authenticates.  ``krb5_rd_req`` compares
        nothing when there is nothing to compare."""
        ticket = _addressless_ticket()
        result = _relayed(planes, planes.on, ticket, "stat", READ_FILE)
        assert result.returncode == 0, (
            "an addressless ticket is now refused from a foreign address — the "
            "check gained teeth, so re-state #70\n"
            f"{result.stdout}{result.stderr}")

    def test_neither_arm_can_be_told_from_the_other(self, planes):
        """The observability half of #70.  Same credential, same source, both
        planes: same verdict, and no line anywhere names the check, says it was
        skipped, or distinguishes a checked login from an unchecked one."""
        ticket = _addressless_ticket()
        assert _relayed(planes, planes.on, ticket,
                        "stat", READ_FILE).returncode == 0
        assert _relayed(planes, planes.off, ticket,
                        "stat", READ_FILE).returncode == 0

        text = planes.errlog()
        for phrase in ("ip_check=on", "ip_check=off"):
            # The config-time NOTICE is allowed to say it once per parse; what
            # must not exist is a RUNTIME line, and those are the ones carrying
            # a connection number.
            for line in text.splitlines():
                if phrase in line:
                    assert "krb5 auth configured" in line, (
                        f"a runtime line now names the check: {line}")
        for phrase in ("address check", "ip check", "peer address"):
            assert phrase not in text.lower(), (
                f"the acceptor now says something about {phrase!r} at run time "
                "— close #70's observability half against the new line")

    def test_the_unchecked_login_is_counted_like_any_other(self, planes):
        """And the metric cannot tell them apart either: an addressless login
        through the enabled plane moves no failure counter and is recorded as an
        ordinary krb5 success."""
        ticket = _addressless_ticket()
        before = planes.auth_failures()
        assert _relayed(planes, planes.on, ticket,
                        "stat", READ_FILE).returncode == 0
        assert planes.auth_failures() == before, (
            "an accepted login moved the failure counter")


# --------------------------------------------------------------------------- #
# D. The shape of the denial                                                   #
# --------------------------------------------------------------------------- #

class TestTheDenial:
    """A refused login must refuse everything that follows it."""

    def test_the_refused_session_reads_nothing(self, planes):
        """security-negative: the denial happens before the session is marked
        authenticated (auth.c:296-310 returns before brix_krb5_session_grant),
        so a read attempted on the same connection must come back empty rather
        than partially served."""
        ticket = _addressed_ticket(planes.tmp_path)
        result = _relayed(planes, planes.on, ticket, "cat", READ_FILE)
        assert result.returncode != 0, (
            f"a refused session read the file\n{result.stdout}")
        assert READ_BODY.decode() not in result.stdout, (
            "file content reached a client whose AP-REQ was refused")

    def test_the_other_planes_are_unaffected_by_the_refusal(self, planes):
        """The flag is per-server, which is the contrast with the tranche's
        previous subject: a refusal on the enabled plane leaves the other two
        serving the same credential in the same worker."""
        ticket = _addressed_ticket(planes.tmp_path)
        assert _refused(_relayed(planes, planes.on, ticket, "stat", READ_FILE))
        for port, plane in ((planes.off, "off"), (planes.absent, "absent")):
            result = _relayed(planes, port, ticket, "stat", READ_FILE)
            assert result.returncode == 0, (
                f"the {plane} plane broke after a refusal on the on plane\n"
                f"{result.stdout}{result.stderr}")


# --------------------------------------------------------------------------- #
# E. The parse tier                                                            #
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


def _diagnostics(out):
    """The lines of an ``nginx -t`` transcript that would tell an operator
    something is wrong.  Matching on the transcript as a whole cannot work: the
    prefix is a tmp_path named after the test, and the tokens this file tests
    ("on", "off") appear inside directory names."""
    return [line for line in out.splitlines()
            if any(sev in line for sev in ("[warn]", "[error]", "[crit]",
                                           "[emerg]"))]


def _parse(tmp_path, knobs="", srv_extra="", stream_extra="", http_knobs="",
           outer=""):
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
    a realm, or touches anything outside its own tmp_path copy of the
    scaffold."""

    @pytest.mark.parametrize("value", ["on", "off"])
    def test_both_values_parse(self, tmp_path, value):
        """success: the two arms of the pair, at the tier that costs nothing —
        and the reason a value-granularity sweep exists, since neither had ever
        been written anywhere in the corpus."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} {value};"))
        assert rc == 0, f"{DIRECTIVE} {value} was rejected\n{out}"

    @pytest.mark.parametrize("value", ["On", "OFF", "oN"])
    def test_the_values_are_case_insensitive(self, tmp_path, value):
        """ngx_conf_set_flag_slot compares with ngx_strcasecmp after checking
        the length, so the config language is case-insensitive here while the
        audit's own grep for written values is not — which is why the sweep has
        to read the setter rather than the configs alone."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} {value};"))
        assert rc == 0, f"the flag slot rejected {value!r}\n{out}"

    @pytest.mark.parametrize("value", ["1", "0", "true", "yes", "enabled"])
    def test_a_plausible_synonym_is_refused(self, tmp_path, value):
        """error: every one of these is what an operator writes for a boolean
        in some other configuration language, and the flag slot takes exactly
        two spellings.  Refusing loudly is the whole protection: a silently
        ignored `brix_krb5_ip_check 1` would leave the check off on a server
        whose operator believes they turned it on."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} {value};"))
        assert rc != 0 and f'invalid value "{value}"' in out, out

    def test_an_empty_value_is_refused(self, tmp_path):
        """security-negative: an unset shell variable expanding to "" must not
        quietly become the default — and the default here is the permissive
        arm."""
        rc, out = _parse(tmp_path, _knobs(f'{DIRECTIVE} "";'))
        assert rc != 0 and 'invalid value ""' in out, out

    @pytest.mark.parametrize("line", [f"{DIRECTIVE};",
                                      f"{DIRECTIVE} on off;",
                                      f"{DIRECTIVE} off on;"])
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, line):
        """error: NGX_CONF_FLAG is TAKE1."""
        rc, out = _parse(tmp_path, _knobs(line))
        assert rc != 0, f"{line!r} parsed\n{out}"
        assert "invalid number of arguments" in out, out

    def test_a_duplicate_directive_is_refused(self, tmp_path):
        """security-negative: two values in ONE server would leave which one
        wins to the parser's ordering, on a directive whose whole subject is
        whether a credential is checked."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} on;",
                                          f"{DIRECTIVE} off;"))
        assert rc != 0 and f'"{DIRECTIVE}" directive is duplicate' in out, out

    def test_the_directive_is_refused_at_stream_level(self, tmp_path):
        """security-negative: NGX_STREAM_SRV_CONF alone.  Written once at the
        top of the stream block it reads like a site-wide default, and adopting
        it silently for every server — or ignoring it silently — would both be
        worse than refusing."""
        rc, out = _parse(tmp_path, stream_extra=f"    {DIRECTIVE} on;\n")
        assert rc != 0, f"a stream-level {DIRECTIVE} parsed\n{out}"
        assert f'"{DIRECTIVE}" directive is not allowed here' in out, out

    def test_the_directive_is_refused_in_an_http_server(self, tmp_path):
        """security-negative: the WebDAV face has its own auth directives, and
        this one has no meaning there.  An operator who writes it into http
        must be told, not quietly left with an unauthenticated face."""
        rc, out = _parse(tmp_path, http_knobs=f"        {DIRECTIVE} on;\n")
        assert rc != 0, f"an http-level {DIRECTIVE} parsed\n{out}"
        assert f'"{DIRECTIVE}" directive is not allowed here' in out, out

    def test_the_directive_is_refused_at_main_context(self, tmp_path):
        """security-negative: outside stream {} entirely."""
        rc, out = _parse(tmp_path, outer=f"{DIRECTIVE} on;\n")
        assert rc != 0, f"a main-context {DIRECTIVE} parsed\n{out}"
        assert f'"{DIRECTIVE}" directive is not allowed here' in out, out

    def test_it_parses_on_a_server_that_has_no_krb5_auth(self, tmp_path):
        """The scaffold configures no `brix_auth krb5` at all, so the flag lands
        on a server that can never read it — and nothing says so.  That is not
        a defect (a flag slot has no way to know), but it is why §A's NOTICE is
        the only feedback that exists: it is printed by the krb5 config stage,
        which a non-krb5 server never runs."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} on;"))
        assert rc == 0, out
        assert _diagnostics(out) == [], (
            f"the parse now diagnoses an unreadable {DIRECTIVE}\n{out}")

    def test_two_servers_may_disagree(self, tmp_path):
        """success, and the contrast with DEFECT #69 two files ago: this value
        is per-server, so two servers holding two values is a legitimate
        configuration rather than a silent clobber — §B measures both at once
        in one worker."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} on;"),
                         srv_extra=_second_server(f"{DIRECTIVE} off;"))
        assert rc == 0, f"two servers disagreeing stopped parsing\n{out}"
        assert _diagnostics(out) == [], out


# --------------------------------------------------------------------------- #
# F. Source pins for the mechanism                                             #
# --------------------------------------------------------------------------- #

def _source(path):
    return path.read_text()


def _code_lines(path, token):
    """Lines naming ``token`` that are code rather than prose.

    auth.c documents the flag three times in WHAT/WHY blocks before reading it
    once, and a pin that counted those would be a pin on the comments."""
    return [line for line in _source(path).splitlines()
            if token in line and not line.lstrip().startswith(("*", "/*", "//"))]


class TestTheMechanismIsWhereTheFileSaysItIs:
    """Everything above reads the flag through a socket.  These read it in the
    C, so that a refactor which moves the mechanism fails here — where the
    message names the new shape — instead of failing as an unexplained login."""

    def test_the_flag_has_exactly_one_reader(self):
        """One early return is the whole of the `off` arm.  A second reader
        would mean the value decides something else as well, and every claim in
        this file about "the only thing that changes" would need re-deriving."""
        readers = _code_lines(AUTH_C, "conf->krb5.ip_check")
        assert len(readers) == 1, (
            f"krb5.ip_check is read in more than one place: {readers}")
        assert "    if (!conf->krb5.ip_check) {\n        return NGX_OK;\n" in \
            _source(AUTH_C), "the off arm is no longer a plain early return"

    def test_the_merge_default_is_off(self):
        """§B measured it; this names the line, so a change to the default fails
        with the reason rather than as a login that stopped being refused."""
        lines = _code_lines(MERGE_C, "conf->krb5.ip_check")
        assert len(lines) == 1, f"expected one merge line, got {lines}"
        merge = " ".join(lines[0].split())          # the column alignment varies
        assert merge == ("ngx_conf_merge_value(conf->krb5.ip_check, "
                         "prev->krb5.ip_check, 0);"), (
            f"the merge default is no longer 0: {merge}")

    def test_the_notice_prints_the_value(self):
        """§A reads this line out of a log; this pins the line that writes it,
        because it is the only operator-visible statement of the value that
        exists anywhere."""
        text = _source(CONFIG_C)
        assert 'keytab=%s ip_check=%s' in text, (
            "the config NOTICE no longer states ip_check")
        assert 'xcf->krb5.ip_check ? "on" : "off"' in text, (
            "the NOTICE no longer renders the flag as on/off")

    def test_only_ipv4_and_ipv6_peers_can_be_bound(self):
        """The README calls the check best-effort because of exactly this:
        brix_krb5_peer_addr handles AF_INET and AF_INET6 and declines anything
        else, and an enabled check turns a decline into a denial (auth.c:228-
        239).  A unix-socket peer on an enabled server is therefore refused —
        which is a real consequence of the `on` arm and is pinned here rather
        than measured, since this listener has no AF_UNIX face."""
        text = _source(AUTH_C)
        for token in ("ADDRTYPE_INET;", "ADDRTYPE_INET6;"):
            assert token in text, f"{token} is gone from brix_krb5_peer_addr"
        assert "cannot bind krb5 peer address" in text, (
            "the unbindable-peer denial is gone — an enabled check now falls "
            "through to krb5_rd_req with no address bound")
