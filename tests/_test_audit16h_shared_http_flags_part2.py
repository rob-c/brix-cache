# --------------------------------------------------------------------------- #
# §A — brix_read_only                                                          #
# --------------------------------------------------------------------------- #

class TestTheReadOnlySwitch:
    """``brix_shared_apply_read_only`` forces ``allow_write`` off when the flag
    is on (shared_conf.h:145-158), which is upstream of every protocol's own
    write gate — so the reading is the whole write-method table, not one verb."""

    def test_the_writable_control_accepts_every_write_method(self, flags):
        """The row every refusal below is measured against.  Without it a 403
        table proves only that something refused, not that the flag did."""
        assert flags.write_probe("rw", "control") == WRITABLE, flags.errlog()

    def test_on_refuses_every_write_method(self, flags):
        assert flags.write_probe("ro-on", "on") == REFUSED, flags.errlog()

    def test_on_leaves_reads_alone(self, flags):
        """Read-only is not closed: the export still serves and still enumerates.
        A flag that took the location off the air entirely would pass the
        refusal table above for the wrong reason."""
        assert flags.request("GET", "ro-on", COMPRESSIBLE).status_code == 200
        listing = flags.request("PROPFIND", "ro-on", headers={"Depth": "1"})
        assert listing.status_code == 207, listing.text[:400]

    def test_off_is_the_absent_value(self, flags):
        """The arm the corpus had never written.  ``off`` must land exactly
        where saying nothing lands — the control's table, verbatim."""
        assert flags.write_probe("ro-off", "off") == WRITABLE, flags.errlog()

    def test_off_is_not_a_write_grant(self, flags):
        """The security negative: ``brix_read_only off`` on a location that was
        never granted ``brix_allow_write`` must not open it.  ``off`` says "do
        not take writes away", never "give writes"."""
        assert flags.write_probe("ro-bare", "bare") == REFUSED, flags.errlog()

    def test_a_server_level_write_grant_reaches_a_child(self, flags):
        """The inheritance control.  Without this row, a 403 from the read-only
        vhost below would be indistinguishable from a location that simply
        never inherited its server's ``brix_allow_write``."""
        assert flags.write_probe("wi-inherit", "wi") == WRITABLE, flags.errlog()

    def test_a_server_level_lock_reaches_a_child(self, flags):
        assert flags.write_probe("ri-inherit", "ri") == REFUSED, flags.errlog()

    def test_a_child_can_take_the_inherited_lock_back(self, flags):
        """``brix_read_only off`` under a server that wrote ``on``: the child is
        writable again, because ``brix_shared_adopt_unified`` fills the child's
        unset ``allow_write`` from the server BEFORE
        ``brix_shared_apply_read_only`` runs for the child and finds
        ``read_only 0``.  Restating the grant explicitly changes nothing."""
        assert flags.write_probe("ri-off", "rioff") == WRITABLE, flags.errlog()
        assert flags.write_probe("ri-offaw", "riaw") == WRITABLE, flags.errlog()

    def test_the_notice_is_written_once_and_scoped_to_the_server(self, flags):
        """The observation in the header, half one: one sentence, absolute, and
        no per-location retraction anywhere in the log."""
        log = flags.errlog()
        notices = _lines_containing(log, "read_only on")
        assert notices, "a server-level read_only on logged nothing"
        bodies = {_notice_body(line) for line in notices}
        assert bodies == {READ_ONLY_NOTICE}, sorted(bodies)
        assert not _lines_containing(log, "ri-off"), \
            "a location that opted out of the lock is now named in the log — " \
            "the observation in this file's header needs rewriting"

    def test_the_readiness_line_is_where_the_opt_out_shows(self, flags):
        """The observation in the header, half two.  Every export announces its
        own writability at config time, so the truth IS available per location
        — 14 read-only, 5 read-write, plus the three origin-backed arms whose
        export is the origin's root."""
        census = _readiness_census(flags.errlog())
        assert census, flags.errlog()
        expected = {"posix/read-only": 14, "posix/read-write": 5,
                    "origin/read-write": 3}
        for pid, seen in census.items():
            assert seen == expected, f"pid {pid} announced {seen}"


def _lines_containing(text, needle):
    return [line for line in text.splitlines() if needle in line]


def _notice_body(line):
    return line.split("#", 1)[-1].split(":", 1)[-1].strip()


def _readiness_census(text):
    census = {}
    for line in text.splitlines():
        entry = _readiness_entry(line)
        if entry:
            _count_readiness(census, *entry)
    return census


def _readiness_entry(line):
    if "endpoint ready" not in line:
        return None
    pid = re.search(r"\]\s+(\d+)#", line)
    if pid is None:                              # pragma: no cover - diagnostic
        return None
    mode = "read-only" if "(read-only)" in line else "read-write"
    root = "origin" if 'export "/"' in line else "posix"
    return pid.group(1), f"{root}/{mode}"


def _count_readiness(census, pid, key):
    counts = census.setdefault(pid, {})
    counts[key] = counts.get(key, 0) + 1


# --------------------------------------------------------------------------- #
# §B — brix_strict_security (parse tier: it has no runtime face)               #
# --------------------------------------------------------------------------- #

def _block(text, indent):
    if not text:
        return ""
    return "".join(f"{indent}{line}\n" for line in text.splitlines())


def _parse(tmp_path, *, knobs="", srv="", http="", outer="", stream="",
           stream_main="", subject=""):
    """``nginx -t`` the scaffold with one slot filled.

    The scaffold writes none of the six itself: a second occurrence would be
    diagnosed as a duplicate, and that error arrives before the one a value or
    arity negative is reaching for.
    """
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    return nginx_t(
        "nginx_audit16hparse.conf", tmp_path,
        PORT=SHARED_PARSE_PLACEHOLDER_PORT,
        SUBJ_PORT=PARSE_PLACEHOLDER_PORT,
        STREAM_PORT=PARSE_PLACEHOLDER_PORT,
        LOG_DIR=str(tmp_path), DATA=str(data),
        KNOBS=_block(knobs, " " * 12),
        SRV_KNOBS=_block(srv, " " * 8),
        HTTP_KNOBS=_block(http, " " * 4),
        OUTER=_block(outer, ""),
        STREAM_KNOBS=_block(stream, " " * 8),
        STREAM_MAIN=_block(stream_main, " " * 4),
        SUBJECT=_block(subject, " " * 4))


def _subject_server(body, srv_flag=""):
    """An insecure export in a server of its own.

    Its own, and not a location beside the scaffold's probe, because
    ``brix_s3`` and ``brix_webdav`` may not share a listen port — the
    co-residency check would refuse the S3 subject before the security gate
    was ever consulted, and the refusal would look like the flag's.
    """
    lines = "".join(f"    {line}\n" for line in body.splitlines())
    return (f"server {{\n    listen {PARSE_PLACEHOLDER_PORT};\n"
            + (f"    {srv_flag}\n" if srv_flag else "") + lines + "}\n")


def _insecure_webdav(data, loc_flag="", srv_flag=""):
    return _subject_server(
        "location /insecure/ {\n"
        "    brix_webdav on;\n"
        f"    brix_storage_backend posix:{data};\n"
        "    brix_webdav_auth none;\n"
        "    brix_allow_write on;\n"
        + (f"    {loc_flag}\n" if loc_flag else "") + "}", srv_flag)


def _insecure_s3(data, loc_flag="", srv_flag=""):
    return _subject_server(
        "location /bucket/ {\n"
        "    brix_s3 on;\n"
        "    brix_s3_bucket b;\n"
        f"    brix_storage_backend posix:{data};\n"
        + (f"    {loc_flag}\n" if loc_flag else "") + "}", srv_flag)


def _insecure_dashboard(_data, loc_flag="", srv_flag=""):
    return _subject_server(
        "location /dash/ {\n"
        "    brix_dashboard on;\n"
        "    brix_dashboard_anonymous on;\n"
        + (f"    {loc_flag}\n" if loc_flag else "") + "}", srv_flag)


SUBJECTS = {"webdav": (_insecure_webdav, INSECURE_WEBDAV),
            "s3": (_insecure_s3, INSECURE_S3),
            "dashboard": (_insecure_dashboard, INSECURE_DASH)}


def _gate(tmp_path, subject, *, arm=None, where="loc"):
    """Run one cell of the §B matrix: a subject, a value, and a scope."""
    build, needle = SUBJECTS[subject]
    flag = "" if arm is None else f"brix_strict_security {arm};"
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    result = _parse(
        tmp_path,
        subject=build(str(data),
                      flag if where == "loc" else "",
                      flag if where == "srv" else ""),
        http=flag if where == "http" else "")
    return result, needle


@_needs_nginx
class TestTheStrictSecurityGate:
    """The flag has no runtime behaviour whatsoever: its entire effect is the
    severity ``brix_shared_security_gate`` uses (shared_conf.h:305-313), so it
    can only be measured against a configuration that is already insecure."""

    @pytest.mark.parametrize("subject", sorted(SUBJECTS))
    @pytest.mark.parametrize("where", ["loc", "srv", "http"])
    def test_on_refuses_the_insecure_export(self, tmp_path, subject, where):
        result, needle = _gate(tmp_path, subject, arm="on", where=where)
        assert result.returncode != 0, \
            f"{subject} accepted an insecure export with strict_security on " \
            f"in {where}:\n{result.stderr}"
        assert "[emerg]" in result.stderr and needle in result.stderr, \
            result.stderr

    @pytest.mark.parametrize("subject", sorted(SUBJECTS))
    @pytest.mark.parametrize("where", ["loc", "srv", "http"])
    @pytest.mark.parametrize("arm", ["off", None], ids=["off", "absent"])
    def test_the_open_arms_warn_and_start(self, tmp_path, subject, where, arm):
        """``off`` written out must land where saying nothing lands — and the
        advisory must still be issued, because the flag decides severity, not
        whether the configuration is examined."""
        result, needle = _gate(tmp_path, subject, arm=arm, where=where)
        assert result.returncode == 0, result.stderr
        assert "[warn]" in result.stderr and needle in result.stderr, \
            result.stderr

    @pytest.mark.parametrize("subject", sorted(SUBJECTS))
    def test_the_two_verdicts_carry_the_same_sentence(self, tmp_path, subject):
        """Only the severity changes.  An operator who turns the flag on gets
        the diagnosis they had been ignoring, not a new one."""
        refused, _ = _gate(tmp_path, subject, arm="on")
        warned, needle = _gate(tmp_path, subject, arm="off")
        assert needle in refused.stderr and needle in warned.stderr
        assert "(refused: brix_strict_security on)" in refused.stderr
        assert "(refused: brix_strict_security on)" not in warned.stderr

    @pytest.mark.parametrize("http,srv,loc,refused", [
        ("on", None, "off", False),
        ("on", "off", None, False),
        (None, "on", "off", False),
        ("off", None, "on", True),
    ], ids=["http-on-loc-off", "http-on-srv-off", "srv-on-loc-off",
            "http-off-loc-on"])
    def test_the_nearest_scope_decides(self, tmp_path, http, srv, loc, refused):
        """Inheritance, in the direction that matters: the export's own scope
        wins, so a site-wide ``on`` in http{} is retractable per location and a
        site-wide ``off`` does not protect a location that opts in."""
        as_flag = lambda v: f"brix_strict_security {v};" if v else ""
        data = tmp_path / "data"
        data.mkdir(exist_ok=True)
        result = _parse(
            tmp_path,
            subject=_insecure_webdav(str(data), as_flag(loc), as_flag(srv)),
            http=as_flag(http))
        assert (result.returncode != 0) is refused, result.stderr

    def test_the_scaffolds_own_probe_raises_nothing(self, tmp_path):
        """The control: every refusal above belongs to the subject, not to the
        anonymous read-only export the scaffold always carries."""
        result = _parse(tmp_path)
        assert result.returncode == 0, result.stderr
        assert "insecure configuration" not in result.stderr, result.stderr


# --------------------------------------------------------------------------- #
# §C — brix_verify_write                                                       #
# --------------------------------------------------------------------------- #

class TestTheWriteVerificationGate:
    """The only fault a read-back verify catches that a Content-Length check
    cannot: an origin that stores the object at the right length and hands back
    different bytes.  ``brix_stage off`` on these three arms is what makes the
    question reach the origin at all — a writable whole-object http:// backend
    with no stage tier is otherwise given a brix-managed local store
    (runtime_server_backend.c:256-267), and the read-back comes off local disk.
    """

    @pytest.mark.parametrize("arm", ORIGIN_ARMS)
    def test_the_honest_case_round_trips(self, flags, arm):
        """The control.  A write that never reached the origin would answer the
        corruption test below identically and for the wrong reason."""
        flags.origin.written.clear()
        flags.origin.corrupt.clear()
        stored = flags.request("PUT", arm, "honest.bin", data=BIG)
        assert stored.status_code == 204, stored.text[:400]
        served = flags.request("GET", arm, "honest.bin")
        assert served.status_code == 200 and served.content == BIG

    def test_no_arm_notices_a_corrupting_origin(self, flags):
        """The finding, on the wire: ``on``, ``off`` and absent are one
        behaviour.  The gate is unreachable from an http export because
        ``brix_shared_adopt_unified`` never adopts the value — DEFECT #34's
        family, owned by test_audit15j_zero_coverage_stragglers.py."""
        verdicts = {}
        for arm in ORIGIN_ARMS:
            flags.origin.written.clear()
            flags.origin.corrupt.clear()
            flags.origin.corrupt.add(f"/{arm}/lie.bin")
            stored = flags.request("PUT", arm, "lie.bin", data=BIG)
            served = flags.request("GET", arm, "lie.bin")
            verdicts[arm] = (stored.status_code, served.status_code,
                             served.content == BIG)
        assert verdicts == {arm: (204, 200, False) for arm in ORIGIN_ARMS}, \
            verdicts

    def test_the_origin_is_never_re_read_during_the_write(self, flags):
        """Verification would have to ask the origin for what it stored, and on
        the arm that asks for it the origin sees exactly the requests any
        unverified write makes."""
        flags.origin.written.clear()
        flags.origin.corrupt.clear()
        flags.origin.recorded.clear()
        assert flags.request("PUT", "vw-on", "probe.bin",
                             data=BIG).status_code == 204
        assert [entry["method"] for entry in flags.origin.recorded] \
            == ["HEAD", "PUT"], flags.origin.recorded

    def test_the_gap_is_in_the_adopt_list_and_already_has_an_owner(self):
        """Source, not wire: the five siblings are adopted and this one is not,
        which is why the value never reaches the location that wrote it.  The
        enumeration — and the defect number — belong to the 15j straggler
        test; asserting it here keeps the two from drifting apart."""
        adopt = SHARED_H.read_text()
        common = HTTP_COMMON_C.read_text()
        _assert_fields_declared(adopt)
        _assert_fields_adopted(common)
        assert "BRIX_ADOPT_VAL(verify_write" not in common, \
            "verify_write is adopted now — §C's finding and the 15j straggler " \
            "list both need revisiting"
        assert "verify_write" in OWNER_TEST.read_text(), \
            "the owning straggler test no longer names verify_write"


def _assert_fields_declared(source):
    for _, field in FLAGS:
        present = f"conf->{field}" in source or f"conf->{field}," in source
        assert present, field


def _assert_fields_adopted(source):
    fields = ("read_only", "compress", "strict_security", "session_log",
              "backend_krb5_forwardable")
    for field in fields:
        assert f"BRIX_ADOPT_VAL({field}," in source, field
