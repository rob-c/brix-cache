# --------------------------------------------------------------------------- #
# §D — brix_compress                                                           #
# --------------------------------------------------------------------------- #

class TestTheCompressSwitch:
    """``file_serve.c:325`` returns before the negotiator when the flag is off,
    so the value decides whether Accept-Encoding is read at all."""

    def test_on_compresses_and_the_body_survives_it(self, flags):
        response = flags.raw("cz-on", COMPRESSIBLE, "gzip")
        assert response.status == 200
        assert response.headers.get("Content-Encoding") == "gzip"
        assert len(response.data) < len(BIG)
        assert gzip.decompress(response.data) == BIG
        assert response.headers.get("Vary") == "Accept-Encoding", \
            "a compressed answer that does not vary poisons every shared cache"
        assert response.headers.get("Transfer-Encoding") == "chunked"
        assert response.headers.get("Content-Length") is None, \
            "a Content-Length alongside a chunked compressed body would be the " \
            "uncompressed length"

    @pytest.mark.parametrize("arm", ["cz-off", "cz-absent"],
                             ids=["off", "absent"])
    def test_the_closed_arms_serve_identity(self, flags, arm):
        """``off`` written out, against the arm that never mentions the flag."""
        response = flags.raw(arm, COMPRESSIBLE, "gzip")
        assert response.status == 200
        assert response.headers.get("Content-Encoding") is None
        assert response.headers.get("Content-Length") == str(len(BIG))
        assert response.data == BIG

    def test_a_body_below_the_floor_is_left_alone(self, flags):
        """Compression is refused under BRIX_COMPRESS_MIN_SIZE even with the
        flag on — otherwise the arm above would be measuring the body size."""
        floor = int(re.search(r"BRIX_COMPRESS_MIN_SIZE\s+(\d+)",
                              COMPRESS_H.read_text()).group(1))
        assert len(SMALL) < floor <= len(BIG)
        response = flags.raw("cz-on", TINY, "gzip")
        assert response.headers.get("Content-Encoding") is None
        assert response.headers.get("Content-Length") == str(len(SMALL))
        assert response.data == SMALL

    @pytest.mark.parametrize("accept", ["identity", "gzip;q=0", ""],
                             ids=["identity", "q-zero", "empty"])
    def test_the_client_can_still_refuse(self, flags, accept):
        """The flag enables negotiation; it does not impose an encoding."""
        response = flags.raw("cz-on", COMPRESSIBLE, accept)
        assert response.headers.get("Content-Encoding") is None
        assert response.data == BIG

    @pytest.mark.parametrize("accept,expected", [
        ("zstd", "zstd"), ("br", "br"), ("gzip, deflate, br, zstd", "zstd")],
        ids=["zstd", "brotli", "all-four"])
    def test_the_server_preference_order_decides_among_offers(
            self, flags, accept, expected):
        """``brix_codec_pref`` puts zstd first, so a client that offers
        everything gets zstd rather than the first name it listed."""
        response = flags.raw("cz-on", COMPRESSIBLE, accept)
        assert response.headers.get("Content-Encoding") == expected
        assert len(response.data) < len(BIG)

    def test_a_head_is_answered_uncompressed(self, flags):
        """``r->header_only`` short-circuits the negotiator (http_compress.c:144)
        so that the advertised length is the length a body would have."""
        response = flags.request("HEAD", "cz-on", COMPRESSIBLE,
                                 headers={"Accept-Encoding": "gzip"})
        assert response.headers.get("Content-Encoding") is None
        assert response.headers.get("Content-Length") == str(len(BIG))

    def test_a_range_request_is_answered_uncompressed(self, flags):
        """Ranges are offsets into the stored object; compressing one would
        make the range meaningless."""
        response = flags.request("GET", "cz-on", COMPRESSIBLE,
                                 headers={"Accept-Encoding": "gzip",
                                          "Range": "bytes=0-99"})
        assert response.status_code == 206
        assert response.headers.get("Content-Encoding") is None
        assert response.content == BIG[:100]

    def test_a_server_level_value_reaches_a_child_and_is_retractable(self, flags):
        inherited = flags.raw("zi-inherit", COMPRESSIBLE, "gzip")
        assert inherited.headers.get("Content-Encoding") == "gzip"
        assert gzip.decompress(inherited.data) == BIG
        retracted = flags.raw("zi-off", COMPRESSIBLE, "gzip")
        assert retracted.headers.get("Content-Encoding") is None
        assert retracted.data == BIG


# --------------------------------------------------------------------------- #
# §E — brix_session_log (and the brix_access_log sentinel it depends on)       #
# --------------------------------------------------------------------------- #

def _fetch(flags, arm, name, *, keep_alive=None):
    """One GET, on a connection of its own unless a session is handed in.

    Fresh by default because the connection is the instrument of the leak
    below: a request that reuses an earlier one's connection is answered by
    whatever that connection decided first.
    """
    flags.seed(arm, name)
    headers = {"Host": _vhost(arm)}
    if keep_alive is None:
        headers["Connection"] = "close"
        response = requests.get(flags.url(arm, name), headers=headers,
                                timeout=30)
    else:
        response = keep_alive.get(flags.url(arm, name), headers=headers,
                                  timeout=30)
    assert response.status_code == 200, response.text[:400]
    return response


def _record_parts(line):
    """(session id, event) out of one record, read by shape rather than by
    column: the line carries a timestamp prefix whose width is not this file's
    business (sesslog.c:328-450 writes ``SESS <id> <EVENT> ...``)."""
    matched = re.search(r"SESS ([0-9a-f]+) (\w+)", line)
    assert matched is not None, f"not a session record: {line!r}"
    return matched.group(1), matched.group(2)


def _events(records):
    return {_record_parts(line)[1] for line in records}


def _session_ids(records):
    return {_record_parts(line)[0] for line in records}


def _await_records(flags, arm, name, count=len(SESSION_EVENTS)):
    """Wait for one object's records to land.  The session log batches and
    flushes on a ~1 s timer, so the arrival of a record is the signal — never a
    line count, which every other arm's traffic also moves."""
    return wait_until(lambda: flags.records_for(arm, name)
                      if len(flags.records_for(arm, name)) >= count else None,
                      timeout=20,
                      what=f"session records for /{arm}/{name}")


def _await_silence(flags, arm, name, control_arm, control_name):
    """Drive the silent arm, then a logging one, and wait for the LOGGING
    object's records.  A negative that waited on a clock would pass on a slow
    flush; this one only passes once the log has demonstrably caught up past
    the request it is supposed to have ignored."""
    _fetch(flags, arm, name)
    _fetch(flags, control_arm, control_name)
    _await_records(flags, control_arm, control_name)
    return flags.records_for(arm, name)


class TestTheSessionLog:
    """``brix_sess_begin`` refuses unless the flag is on AND an access-log fd
    exists (sesslog_ngx.c:250), so the value is measured as records naming a
    per-test object in the one log every vhost inherits."""

    def test_on_records_the_transfer(self, flags):
        _fetch(flags, "sl-on", "sess-on.txt")
        records = _await_records(flags, "sl-on", "sess-on.txt")
        assert _events(records) == set(SESSION_EVENTS), records

    def test_off_is_silent_and_absent_is_not(self, flags):
        """The pair the corpus had never written together: ``off`` is the only
        silence, and a location that says nothing logs like ``on`` because the
        merge default is 1 (shared_conf.h:376)."""
        assert _await_silence(flags, "sl-off", "quiet.txt",
                              "sl-absent", "loud.txt") == []
        assert len(flags.records_for("sl-absent", "loud.txt")) \
            == len(SESSION_EVENTS)

    def test_the_access_log_sentinel_silences_a_logging_location(self, flags):
        """``brix_access_log off`` is a path that is never opened, so there is
        no fd for the session log to write to — ``brix_session_log on`` in the
        same location produces nothing, and no file called "off" is created."""
        assert _await_silence(flags, "al-off", "nofd.txt",
                              "sl-on", "witness.txt") == []
        created = {entry.name for entry in flags.logs.iterdir()} \
            | {entry.name for entry in Path(flags.endpoint.prefix).iterdir()}
        assert "off" not in created, sorted(created)

    def test_a_server_level_off_reaches_a_child_and_is_retractable(self, flags):
        assert _await_silence(flags, "qi-inherit", "hush.txt",
                              "qi-on", "speak.txt") == []
        assert len(flags.records_for("qi-on", "speak.txt")) \
            == len(SESSION_EVENTS)

    def test_a_kept_alive_connection_carries_the_first_decision(self, flags):
        """DEFECT #79.  ``brix_http_sess`` looks the record up per CONNECTION
        and returns it before reading the new location's conf
        (sesslog_conn.c:178-181), so a second request on the same connection is
        logged under the first location's value."""
        with requests.Session() as session:
            _fetch(flags, "sl-on", "ka-first.txt", keep_alive=session)
            _fetch(flags, "sl-off", "ka-second.txt", keep_alive=session)
        leaked = _await_records(flags, "sl-off", "ka-second.txt")
        assert _events(leaked) == set(SESSION_EVENTS), leaked
        opened = _await_records(flags, "sl-on", "ka-first.txt")
        assert _session_ids(leaked) == _session_ids(opened), \
            "the leaked records are a session of their own — the finding is " \
            "not per-connection caching"

    def test_the_reverse_order_leaks_nothing(self, flags):
        """The control that makes the row above a leak of the FIRST location's
        decision rather than a mis-merge: reached first, the silent location
        stays silent AND leaves nothing cached — the logging location that
        follows on the same connection opens a session of its own."""
        with requests.Session() as session:
            _fetch(flags, "sl-off", "ctl-first.txt", keep_alive=session)
            _fetch(flags, "sl-on", "ctl-second.txt", keep_alive=session)
        records = _await_records(flags, "sl-on", "ctl-second.txt")
        assert _events(records) == set(SESSION_EVENTS), records
        assert flags.records_for("sl-off", "ctl-first.txt") == []


# --------------------------------------------------------------------------- #
# §F — brix_backend_krb5_forwardable                                           #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheKrb5ForwardableFlag:
    """DEFECT CANDIDATE #77: an http-plane directive with no http reader."""

    @pytest.mark.parametrize("where", ["knobs", "srv", "http"])
    @pytest.mark.parametrize("value", ["on", "off"])
    def test_it_parses_in_every_http_scope(self, tmp_path, where, value):
        result = _parse(tmp_path,
                        **{where: f"brix_backend_krb5_forwardable {value};"})
        assert result.returncode == 0, result.stderr

    def test_its_only_reader_is_on_the_stream_plane(self):
        """Where the value is consumed, counted across the whole tree: one
        call site, inside the root:// stream protocol's path handler.  The
        http declaration is parse-only, and nothing says so at either config
        time or run time."""
        readers = _krb5_forwardable_readers()
        # The VFS context-builder split moved this one consumer out of
        # op_path.c; pin its new cohesive home as well as its uniqueness.
        assert readers == ["src/protocols/root/path/op_path_vfs.c:201"], readers
        assert "brix_krb5_deleg_origin_spn" in OP_PATH_C.read_text()


def _krb5_forwardable_readers():
    paths = sorted(SRC_DIR.rglob("*.c")) + sorted(SRC_DIR.rglob("*.h"))
    readers = []
    for path in paths:
        readers.extend(_forwardable_readers_in(path))
    return readers


def _forwardable_readers_in(path):
    readers = []
    try:
        text = path.read_text(errors="replace")
    except FileNotFoundError:
        return readers
    for number, line in enumerate(text.splitlines(), start=1):
        if _is_forwardable_reader(line):
            readers.append(f"{path.relative_to(ROOT)}:{number}")
    return readers


def test_forwardable_reader_scan_ignores_a_vanished_generated_file(tmp_path):
    assert _forwardable_readers_in(tmp_path / "vanished.c") == []


def _is_forwardable_reader(line):
    ignored = (
        "ngx_string(", "offsetof(", "NGX_CONF_UNSET", "ngx_conf_merge_value",
        "BRIX_ADOPT_VAL", "prev->backend_krb5_forwardable", "ngx_flag_t",
    )
    return all((
        "backend_krb5_forwardable" in line,
        not any(token in line for token in ignored),
        not line.lstrip().startswith(("*", "/*", "//", "#")),
    ))
