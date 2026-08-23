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


def _configured_fields(text):
    return [
        field
        for line in text.splitlines()
        if "krb5 auth configured" in line
        for field in line.split()
    ]


def _field_values(fields, prefix):
    return {field.split("=", 1)[1] for field in fields
            if field.startswith(prefix)}


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
        fields = _configured_fields(planes.errlog())
        principals = _field_values(fields, "principal=")
        keytabs = _field_values(fields, "keytab=")
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
        entries = _error_entries(planes.accesslog("on"))
        assert entries, (
            "the enabled plane logged no refusal at all\n"
            f"{planes.accesslog('on')}\n{planes.errlog()}")
        assert _has_foreign_auth_entry(entries), (
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
        refusals = _credential_refusals(planes.errlog())
        assert refusals, planes.errlog()
        _assert_no_claimed_principal(refusals)
        _assert_off_plane_names_principal(planes, ticket)


def _error_entries(text):
    return [line for line in text.splitlines() if " ERR " in line]


def _has_foreign_auth_entry(entries):
    return any(line.startswith(FOREIGN) and "AUTH" in line for line in entries)


def _credential_refusals(text):
    return [line for line in text.splitlines()
            if "credential verification failed" in line]


def _assert_no_claimed_principal(refusals):
    for line in refusals:
        assert "alice" not in line, (
            f"the refusal leaked the claimed principal: {line}")


def _assert_off_plane_names_principal(planes, ticket):
    result = _relayed(planes, planes.off, ticket, "stat", READ_FILE)
    assert result.returncode == 0
    assert 'principal="alice"' in planes.errlog(), (
        "the accepted login on the off plane did not name the principal — "
        "the contrast this test rests on is gone")
