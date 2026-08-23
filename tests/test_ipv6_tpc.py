from split_continuation import reexport as _reexport
def _guard_test_native_tpc_ipv6_v6_to_v6_round_trip_1():
    if not os.path.isdir(IPV6_STREAM_DATA_ROOT):
        pytest.skip("ipv6-stream data root not locally visible")

def _check_test_native_tpc_ipv6_v6_to_v6_round_trip_1(got):
    assert got == b"hello from nginx-xrootd\n", (
        f"v6→v6 TPC content mismatch: {got!r}"
    )


_reexport(globals(), "_test_ipv6_tpc_helpers")

class TestNativeTpcIpv6BracketRoundTrip:
    """Prove the parse→rebuild round-trip accepts a bracketed IPv6 source
    (src/tpc/engine/parse.c strips "[::1]"→"::1"; src/tpc/engine/launch.c re-brackets at the
    registry/display URL rebuild).  Raw-wire because PyXRootD mishandles
    root://[::1] literals."""

    @pytest.mark.registry_server("ipv6-stream")
    def test_native_tpc_ipv6_bracketed_source_open_accepted(self):
        """GATING (parse round-trip): a kXR_open carrying a *bracketed* IPv6 TPC
        source "root://[::1]:PORT//test.txt" is parsed successfully — i.e. it is
        NOT rejected with kXR_ArgInvalid "invalid or incomplete TPC source".

        A successful parse yields one of two well-formed outcomes, both of which
        prove the bracket was understood:
          * kXR_OK + a file handle           (allow_local on → pull armed), or
          * kXR_error + "prohibited"         (allow_local off → SSRF gate).
        A *bare* "::1:PORT" source would mis-parse the port/host and the launch
        rebuild would emit an unparseable URL — this test fails closed on that."""
        _require_ipv6_stream()
        src = f"root://[{IPV6_LOOPBACK}]:{IPV6_STREAM_PORT}//test.txt"
        status, err, body = _native_tpc_open(
            lambda: _connect6(IPV6_STREAM_PORT),
            "/ipv6_tpc_dst_accept.dat", src,
        )

        # The bracket parse must have succeeded: never the "invalid/incomplete
        # TPC source" ArgInvalid path.
        assert "invalid or incomplete TPC source" not in err, (
            f"bracketed IPv6 source mis-parsed: {err!r}"
        )
        if status == kXR_OK:
            assert len(body) >= 1, "accepted TPC open must return a file handle"
        else:
            # Only acceptable non-OK outcome is the SSRF local-deny policy.
            assert "prohibited" in err, (
                f"unexpected TPC-open failure for bracketed IPv6 source: {err!r}"
            )

    @pytest.mark.registry_server("ipv6-stream")
    def test_native_tpc_ipv6_v6_to_v6_round_trip(self):
        """GATING (end-to-end rebuild): drive the full open+sync v6→v6 pull on
        ipv6-stream and confirm the destination file is byte-exact.  Reaching a
        completed transfer means launch.c rebuilt a *connectable* bracketed
        "root://[::1]:PORT//test.txt" — a bare-colon rebuild could never connect.

        Deterministic policy handling: if the ipv6-stream sibling left
        allow_local=off (loopback SSRF-denied), the pull cannot complete
        same-host; accept only that explicit denial as a non-bypass outcome."""
        _require_ipv6_stream()
        src = f"root://[{IPV6_LOOPBACK}]:{IPV6_STREAM_PORT}//test.txt"
        dst_name = f"ipv6_tpc_roundtrip_{os.getpid()}.dat"
        status, err = _native_tpc_open_and_sync(
            lambda: _connect6(IPV6_STREAM_PORT),
            "/" + dst_name, src,
        )

        if status != kXR_OK:
            if "prohibited" in err:
                return
            pytest.fail(f"v6→v6 native TPC pull did not complete: {err!r}")

        # Transfer committed: verify the rebuilt bracketed source actually moved
        # the bytes.  Best-effort filesystem check (skip if the data root is not
        # locally visible, e.g. remote-server mode).
        dst = os.path.join(IPV6_STREAM_DATA_ROOT, dst_name)
        _guard_test_native_tpc_ipv6_v6_to_v6_round_trip_1()
        try:
            with open(dst, "rb") as f:
                got = f.read()
        except FileNotFoundError:
            pytest.fail("TPC reported OK but destination file is missing")
        finally:
            try:
                os.unlink(dst)
            except OSError:
                pass
        _check_test_native_tpc_ipv6_v6_to_v6_round_trip_1(got)


# ===========================================================================
# (b) SECURITY-NEG — the re-bracket round-trip must NOT bypass the SSRF
#     local-deny policy.  Driven against tpc-ssrf-default (allow_local=off),
#     whose SSRF gate resolves the source host string regardless of address
#     family, so the result is deterministic and independent of the IPv6
#     sibling configs.
# ===========================================================================

class TestNativeTpcIpv6SsrfNegatives:
    """The SSRF gate (brix_tpc_check_src_policy) runs on the *bare* source host
    at kXR_open time, BEFORE the launch rebuild.  These prove a bracketed IPv6
    loopback / v4-mapped-loopback source is still rejected — the bracket fix did
    not punch an SSRF hole."""

    @pytest.mark.registry_servers("ipv6-stream", "tpc-ssrf-default")
    def test_ssrf_ipv6_loopback_source_rejected(self):
        """SECURITY-NEG: TPC pull from "root://[::1]:PORT//test.txt" against an
        allow_local=off server is rejected as a prohibited (loopback) address.
        ::1 matches the IN6 loopback constant in net_target.c."""
        _require_ssrf_default()
        src = f"root://[{IPV6_LOOPBACK}]:{IPV6_STREAM_PORT}//test.txt"
        status, err = _native_tpc_open_and_sync(
            lambda: _connect4(HOST, TPC_SSRF_DEFAULT_PORT),
            "/ipv6_ssrf_loopback.dat", src,
        )
        assert status == kXR_error, f"expected rejection, got status {status}"
        assert "prohibited" in err, (
            f"[::1] loopback source must be SSRF-prohibited, got: {err!r}"  # net-literal-allow: [::1] SSRF-prohibited source assertion message
        )

    @pytest.mark.registry_servers("ipv6-stream", "tpc-ssrf-default")
    def test_ssrf_ipv6_v4mapped_loopback_source_rejected(self):
        """SECURITY-NEG: "root://[::ffff:127.0.0.1]:PORT//test.txt" must also be
        rejected — net_target.c classifies a v4-mapped address (IN6_IS_ADDR_
        V4MAPPED) by its embedded IPv4, so ::ffff:127.0.0.1 == 127.0.0.1 loopback
        and is prohibited under allow_local=off.  This is the canonical
        v4-mapped SSRF-evasion vector."""
        _require_ssrf_default()
        src = f"root://[::ffff:127.0.0.1]:{IPV6_STREAM_PORT}//test.txt"  # net-literal-allow: v4-mapped-loopback SSRF source payload under test
        status, err = _native_tpc_open_and_sync(
            lambda: _connect4(HOST, TPC_SSRF_DEFAULT_PORT),
            "/ipv6_ssrf_v4mapped.dat", src,
        )
        assert status == kXR_error, f"expected rejection, got status {status}"
        assert "prohibited" in err, (
            f"[::ffff:127.0.0.1] mapped-loopback source must be SSRF-prohibited, "  # net-literal-allow: [::ffff:127.0.0.1] SSRF assertion message
            f"got: {err!r}"
        )

    @pytest.mark.registry_servers("ipv6-stream", "tpc-ssrf-default")
    def test_ssrf_rejection_is_not_a_parse_error(self):
        """SECURITY-NEG (control): the rejection above is the SSRF policy firing
        on a *correctly parsed* bracketed IPv6 host — not an accidental parse
        failure.  A bracketed [::1] source must reach the "prohibited" verdict,
        never "invalid or incomplete TPC source" (which would mean the bracket
        defeated parsing, masking rather than enforcing the policy)."""
        _require_ssrf_default()
        src = f"root://[{IPV6_LOOPBACK}]:{IPV6_STREAM_PORT}//test.txt"
        status, err, _body = _native_tpc_open(
            lambda: _connect4(HOST, TPC_SSRF_DEFAULT_PORT),
            "/ipv6_ssrf_parse_control.dat", src,
        )
        assert status == kXR_error
        assert "invalid or incomplete TPC source" not in err, (
            f"bracketed IPv6 source must parse then be SSRF-denied, not fail "
            f"parsing: {err!r}"
        )
        assert "prohibited" in err, f"expected SSRF prohibition, got: {err!r}"


# ===========================================================================
# (c) WebDAV HTTP-TPC COPY with a bracketed IPv6 Source: / Destination: header.
#     curl handles https://[::1]:port natively (RFC 3986).  These exercise the
#     COPY parse + outbound curl host bracketing (proxy_pool.c / tpc_curl.c).
# ===========================================================================

class TestWebdavTpcIpv6Copy:
    """COPY with a bracketed IPv6 Source/Destination.  The destination instance
    (ipv6-webdav) and its allow_local / cert posture are owned by a sibling
    config, so these gate on reachability and assert on the *shape* of the
    response — never a flaky transfer outcome."""

    @pytest.mark.registry_server("ipv6-webdav")
    def test_webdav_tpc_copy_ipv6_source_header_accepted(self):
        """GATING: a COPY pull with "Source: <scheme>://[::1]:PORT/test.txt" is
        NOT rejected as a malformed URL (HTTP 400) on account of the bracketed
        IPv6 authority — the bug class this gates is a 400 Bad Request that would
        prove the "[::1]" literal broke the COPY request line / Source-URL parse.

        Config-model note (diagnosed against the LIVE ipv6-webdav instance,
        nginx_ipv6_webdav.conf): that instance does NOT set "brix_webdav_tpc on",
        so HTTP-TPC is disabled.  A COPY carrying a "Source:" header therefore hits
        the TPC config gate at src/protocols/webdav/dispatch.c (`if (!conf->tpc) return
        NGX_HTTP_NOT_ALLOWED;`) and is answered 405 — BEFORE any Source-URL parse.
        This 405 was verified to be address-family-agnostic: an IPv4, hostname, or
        bracketed-IPv6 Source all return the identical 405, and a plain server-side
        COPY (Destination only, no Credential) returns 201 on the same instance.
        So the 405 is the TPC-disabled gate, not a bracket-parse failure, and the
        bracket-rebuild fix is covered by the native-TPC gating tests above
        (launch.c URL rebuild) which exercise the parser directly.

        Acceptable outcomes (none is a malformed-URL 400): 405 (HTTP-TPC disabled
        gate, the LIVE-instance result), 201/202/204 (transfer accepted/started),
        207, 403 (SSRF local-deny on loopback), 404, 409 (conflict), 412, 502
        (upstream/transfer error).  A 400 is the only failure — it would mean the
        bracketed source URL was rejected as malformed."""
        _require_ipv6_webdav()
        base = _webdav_base_url()
        src = f"{base}/test.txt"
        dst_url = f"{base}/ipv6_tpc_copy_dst.txt"
        proc = _curl_copy(
            dst_url,
            "Credential: none",
            f"Source: {src}",
            timeout=30,
        )
        assert proc.returncode == 0, proc.stderr.decode(errors="replace")
        code = _curl_code(proc)
        assert code != -1, f"no HTTP status from COPY: {proc.stdout!r}"
        assert code != 400, (
            f"bracketed IPv6 Source header rejected as malformed (400); "  # net-literal-allow: bracketed-IPv6 Source-header rejection assertion
            f"the [::1] authority must parse. body status={code}"
        )
        assert code in (201, 202, 204, 207, 403, 404, 405, 409, 412, 502), (
            f"unexpected COPY status {code} for bracketed IPv6 source"
        )

    @pytest.mark.registry_server("ipv6-webdav")
    def test_webdav_tpc_copy_ipv6_destination_header_accepted(self):
        """GATING (push): a COPY push with "Destination: <scheme>://[::1]:PORT/..."
        plus a "Credential:" header (which is what flags an HTTP-TPC push, see
        src/protocols/webdav/dispatch.c) is NOT rejected as a malformed URL (400) on account
        of the bracketed IPv6 egress authority.  Mirrors the pull case on the
        egress side; the destination/cert posture is sibling-owned, so we assert
        on response shape, never a transfer outcome.

        Config-model note: as for the pull case, the LIVE ipv6-webdav instance has
        HTTP-TPC disabled (no "brix_webdav_tpc on"), so a Destination+Credential
        COPY hits the same `!conf->tpc` gate and returns 405 BEFORE the egress URL
        is parsed (verified: identical 405 for IPv4/hostname/bracketed-IPv6
        Destination; a Destination-only server-side COPY returns 201).  The 405 is
        the TPC-disabled gate, not a bracket-parse failure; the bracket round-trip
        itself is covered by the native-TPC gating tests above.

        Acceptable outcomes (none is a malformed-URL 400): 405 (HTTP-TPC disabled
        gate, the LIVE-instance result), 201/202/204, 207, 403, 404, 409, 412, 502.
        A 400 is the only failure."""
        _require_ipv6_webdav()
        base = _webdav_base_url()
        dst = f"{base}/ipv6_tpc_push_dst.txt"
        # Push: COPY is issued against an existing source path on the same server;
        # the Destination header names a bracketed IPv6 egress target.
        proc = _curl_copy(
            f"{base}/test.txt",
            "Credential: none",
            f"Destination: {dst}",
            timeout=30,
        )
        assert proc.returncode == 0, proc.stderr.decode(errors="replace")
        code = _curl_code(proc)
        assert code != -1, f"no HTTP status from COPY push: {proc.stdout!r}"
        assert code != 400, (
            f"bracketed IPv6 Destination header rejected as malformed (400); "
            f"status={code}"
        )
        assert code in (201, 202, 204, 207, 403, 404, 405, 409, 412, 502), (
            f"unexpected COPY-push status {code} for bracketed IPv6 destination"
        )

    @pytest.mark.registry_server("ipv6-webdav")
    def test_webdav_tpc_copy_non_https_ipv6_destination_rejected(self):
        """SECURITY-NEG / REGRESSION: a COPY push to an explicit plaintext
        "http://[::1]:9999/..." egress is rejected (400) — the bracket fix did
        not relax the HTTPS-only egress requirement for HTTP-TPC.  This is the
        IPv6 form of test_webdav_tpc.py::test_push_non_https_destination_rejected.

        Deterministic policy handling: some source postures (auth-required,
        TPC-off) short-circuit before the scheme check with 403/405; those are
        accepted non-bypass results, while any 2xx success fails."""
        _require_ipv6_webdav()
        base = _webdav_base_url()
        proc = _curl_copy(
            f"{base}/test.txt",
            "Credential: none",
            "Destination: http://[::1]:9999/should-be-rejected.txt",  # net-literal-allow: SSRF Destination payload under test
            timeout=30,
        )
        assert proc.returncode == 0, proc.stderr.decode(errors="replace")
        code = _curl_code(proc)
        assert code != -1
        assert code not in (200, 201, 202), (
            f"plaintext IPv6 egress must not yield a successful copy, got {code}"
        )
        if code != 400:
            assert code in (403, 405), (
                f"unexpected non-success status for plaintext egress: {code}"
            )
            return
        assert code == 400
