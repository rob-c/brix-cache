"""Test cases for audit16t_compress_flag_arms — preamble (fixtures/helpers/mocks) lives in
_test_audit16t_compress_flag_arms_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16t_compress_flag_arms_helpers")


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
        """The disabled compression form is the C emitter's own `=0` string, not
        a client-side rendering.

        cmpread and cmpwrite were consolidated onto one shared emitter
        (brix_qconfig_emit_cmp, 9ab5c3f5): when the direction is disabled it
        appends the literal `"%s=0\\n"` with the key name, so the on-wire bytes
        are still `cmpread=0\\n` / `cmpwrite=0\\n` — the source now carries the
        `=0` format once and the two keys as the arguments that fill the `%s`."""
        text = _source(QCONFIG_C)
        assert '"%s=0\\n"' in text, "disabled compression form (=0) not found"
        assert '"cmpread"' in text, "cmpread key not passed to the shared emitter"
        assert '"cmpwrite"' in text, \
            "cmpwrite key not passed to the shared emitter"

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
