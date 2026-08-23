"""Cold-cache and signing audit regression tests."""
# §4.2 — brix_cache_cold_max_age
# ===========================================================================
def _cold_layout(base):
    data = base / "data"
    cache = base / "cache"
    export = base / "export"
    for path in (data, cache, export, export / "cold", cache / "cold"):
        path.mkdir(parents=True, exist_ok=True)
    (data / "cold.bin").write_bytes(b"c" * (256 * 1024))
    return data, cache, export


def _cold_spec(data, cache, export):
    return NginxInstanceSpec(
        name="lc-audit-coldpurge",
        template="nginx_lc_audit_coldpurge.conf",
        protocol="root",
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_ROOT": str(data),
            "CACHE_ROOT": str(cache),
            "EXPORT_ROOT": str(export),
            "COLD_MAX_AGE": "60",
        },
        reason="audit §4.2 cold purge")


def _start_cold_harness(harness, spec):
    try:
        return harness.start(spec)
    except Exception as exc:  # noqa: BLE001 - unavailable live prerequisite
        harness.close()
        pytest.skip(f"cold-purge instance did not start: {exc}")


def _cold_fill(base, cache, endpoint):
    output = base / "pulled.bin"
    result = subprocess.run(
        [_XRDCP, "-f", "-s", f"root://{HOST}:{endpoint.port}//cold.bin",
         str(output)],
        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, f"fill copy failed: {result.stderr}"
    cached = [path for path in (cache / "cold").rglob("*")
              if path.is_file() and path.suffix not in (".cinfo", ".meta")]
    if not cached:
        pytest.skip("no cache object materialised for this tier shape")
    return cached


def _backdate_cold_files(paths):
    timestamp = time.time() - 3600
    for path in paths:
        os.utime(path, (timestamp, timestamp))


def _wait_for_cold_purge(harness, cached):
    for _ in range(4):
        harness.restart("lc-audit-coldpurge")
        round_end = time.time() + 20
        while time.time() < round_end:
            if not any(path.exists() for path in cached):
                return True
            time.sleep(1)
    return False


@pytest.mark.skipif(not os.path.exists(_XRDCP),
                    reason="brix-xrdcp not built (client/bin/xrdcp)")
class TestColdFilePurge:
    """A CLEAN read-through fill nobody touches must age out.

    The watermark reaper only runs when the filesystem crosses its high
    watermark, so on a roomy cache a cold object was previously kept forever.
    """

    def test_cold_clean_fill_is_purged_by_age(self, tmp_path_factory):
        base = tmp_path_factory.mktemp("audit-cold")
        data, cache, export = _cold_layout(base)
        harness = LifecycleHarness()
        endpoint = _start_cold_harness(
            harness, _cold_spec(data, cache, export))
        try:
            cached = _cold_fill(base, cache, endpoint)
            _backdate_cold_files(cached)
            purged = _wait_for_cold_purge(harness, cached)
            survivors = [str(path) for path in cached if path.exists()]
            assert all((purged, not survivors)), (
                f"cold cache files survived the age purge: {survivors}")
        finally:
            harness.close()


# ===========================================================================
# §5.2 — brix_security_level fail-closed on an unsignable session
# ===========================================================================
class TestSigningFailClosed:
    """brix_security_level was silently unenforced off-GSI.

    Only a GSI session establishes a signing key. On an anonymous/sss/ztn/krb5
    session `brix_security_level intense` used to return "continue" before any
    check ran — the tamper protection an operator configured was simply absent,
    with nothing in the log to say so.
    """

    @staticmethod
    def _open_probe(port, path="/probe.bin"):
        """Anonymous login + kXR_open; return the reply status code."""
        sock = socket.create_connection((HOST, port), timeout=20)
        try:
            sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
            _recv_exact(sock, 16)

            def req(reqid, body=b"", payload=b""):
                hdr = b"\x00\x01" + struct.pack(">H", reqid)
                hdr += body.ljust(16, b"\x00")
                hdr += struct.pack(">I", len(payload))
                sock.sendall(hdr + payload)
                rsp = _recv_exact(sock, 8)
                status = struct.unpack(">H", rsp[2:4])[0]
                dlen = struct.unpack(">I", rsp[4:8])[0]
                data = _recv_exact(sock, dlen) if dlen else b""
                return status, data

            status, _ = req(3006)                       # kXR_protocol
            assert status == kXR_ok, "protocol"
            status, _ = req(3007, payload=b"anonymous\x00")   # kXR_login
            assert status == kXR_ok, "login"

            body = struct.pack(">HH", 0o644, 0x0010) + b"\x00" * 12
            status, data = req(kXR_open, body=body,
                               payload=path.encode() + b"\x00")
            code = struct.unpack(">I", data[:4])[0] if (
                status == kXR_error and len(data) >= 4) else 0
            return status, code
        finally:
            sock.close()

    @pytest.fixture(scope="class")
    def subject(self, tmp_path_factory):
        """One instance, reconfigured between the required-on and -off cases.

        The pair then differ in exactly the directive under test and nothing
        else — and it costs one lifecycle ladder slot instead of two.
        """
        base = tmp_path_factory.mktemp("audit-sign")
        data = base / "data"
        data.mkdir(parents=True, exist_ok=True)
        (data / "probe.bin").write_bytes(b"p" * 128)

        harness = LifecycleHarness()
        spec = NginxInstanceSpec(
            name="lc-audit-signing",
            template="nginx_lc_audit_signing.conf",
            protocol="root",
            template_values={
                "BIND_HOST": BIND_HOST,
                "DATA_ROOT": str(data),
                "SIGNING_REQUIRED": "off",
            },
            reason="audit §5.2 signing fail-closed")
        try:
            endpoint = harness.start(spec)
        except Exception as exc:                                # noqa: BLE001
            harness.close()
            pytest.skip(f"signing instance did not start: {exc}")
        try:
            yield harness, endpoint
        finally:
            harness.close()

    def _set_required(self, harness, mode):
        harness.reconfigure("lc-audit-signing", SIGNING_REQUIRED=mode)
        harness.restart("lc-audit-signing")

    def test_required_off_still_serves_but_logs(self, subject):
        """Default-off keeps every existing non-GSI deployment working.

        Turning the refusal on rejects stock clients that never sign, so it is a
        deployment decision — but the gap must no longer be SILENT, which is
        what the WARN line asserts.
        """
        harness, endpoint = subject
        self._set_required(harness, "off")

        status, _code = self._open_probe(endpoint.port)
        assert status == kXR_ok, (
            f"default-off changed behaviour for an existing deployment "
            f"(status={status})")

        log = Path(endpoint.prefix) / "logs" / "error.log"
        deadline = time.time() + 15
        text = ""
        while time.time() < deadline:
            if log.exists():
                text = log.read_text(errors="replace")
                if "established no signing key" in text:
                    break
            time.sleep(0.5)
        assert "established no signing key" in text, (
            f"the unsignable-session gap is still silent — no WARN in {log}")
        assert "accepted UNSIGNED" in text, (
            "the log must state what actually happened to the request")

    def test_required_on_refuses_unsignable_session(self, subject):
        """SECURITY: with signing required, an unsignable session is REFUSED.

        This is the fix: `brix_security_level intense` now means what an
        operator reads it to mean instead of passing every request through.
        """
        harness, endpoint = subject
        self._set_required(harness, "on")

        status, code = self._open_probe(endpoint.port)
        assert status == kXR_error, (
            f"unsigned open accepted despite brix_signing_required on "
            f"(status={status})")
        assert code == 3010, f"expected kXR_NotAuthorized, got {code}"

    def test_handshake_opcodes_stay_exempt(self, subject):
        """Fail-closed must never lock out the session state machine.

        login/protocol/auth are exempt from signing at every level; if the
        refusal reached them, the connection could not even be established and
        the mode would be unusable rather than strict.
        """
        harness, endpoint = subject
        self._set_required(harness, "on")

        # _open_probe completes handshake+protocol+login before the open; a
        # refusal there would raise on its asserts instead of returning.
        status, code = self._open_probe(endpoint.port)
        assert status == kXR_error and code == 3010, (
            "expected the OPEN to be refused, with login/protocol having "
            f"succeeded first (status={status} code={code})")
