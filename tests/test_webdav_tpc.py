from split_continuation import reexport as _reexport
_reexport(globals(), "_test_webdav_tpc_helpers")

class TestNginxPluginToPluginTPC:
    @pytest.mark.registry_server("webdav-tpc")
    def test_required_source_to_required_destination(self, tpc_nginx):
        content = b"nginx plugin source requiring x509 auth\n"
        _write(tpc_nginx.source_required_root / "required-source.txt", content)

        source = (
            f"https://{HOST}:{tpc_nginx.source_required_port}"
            "/required-source.txt"
        )
        code = _copy_code(
            tpc_nginx.dest_cafile_port,
            "/copied-from-required.txt",
            source,
            "TransferHeaderX-Test-Tpc: plugin-required",
        )

        assert code == 201
        assert (tpc_nginx.dest_cafile_root / "copied-from-required.txt").read_bytes() == content

    @pytest.mark.registry_server("webdav-tpc")
    def test_open_source_to_cadir_destination(self, tpc_nginx):
        content = b"nginx plugin open source, destination trusts a CA directory\n"
        _write(tpc_nginx.source_open_root / "open-source.txt", content)

        source = f"https://{HOST}:{tpc_nginx.source_open_port}/open-source.txt"
        code = _copy_code(tpc_nginx.dest_cadir_port, "/copied-via-cadir.txt", source)

        assert code == 201
        assert (tpc_nginx.dest_cadir_root / "copied-via-cadir.txt").read_bytes() == content

    @pytest.mark.registry_server("webdav-tpc")
    def test_overwrite_false_preserves_existing_destination(self, tpc_nginx):
        _write(tpc_nginx.source_open_root / "overwrite-source.txt", b"new content\n")
        existing = tpc_nginx.dest_cafile_root / "overwrite-target.txt"
        _write(existing, b"existing content\n")

        source = f"https://{HOST}:{tpc_nginx.source_open_port}/overwrite-source.txt"
        code = _copy_code(
            tpc_nginx.dest_cafile_port,
            "/overwrite-target.txt",
            source,
            "Overwrite: F",
        )

        assert code == 412
        assert existing.read_bytes() == b"existing content\n"

    @pytest.mark.registry_server("webdav-tpc")
    def test_tpc_disabled_destination_rejects_copy(self, tpc_nginx):
        _write(tpc_nginx.source_open_root / "disabled-source.txt", b"disabled dest\n")

        source = f"https://{HOST}:{tpc_nginx.source_open_port}/disabled-source.txt"
        code = _copy_code(tpc_nginx.dest_disabled_port, "/should-not-copy.txt", source)

        assert code == 405
        assert not (tpc_nginx.dest_disabled_root / "should-not-copy.txt").exists()

    @pytest.mark.registry_server("webdav-tpc")
    def test_readonly_destination_rejects_copy_before_pull(self, tpc_nginx):
        _write(tpc_nginx.source_open_root / "readonly-source.txt", b"readonly dest\n")

        source = f"https://{HOST}:{tpc_nginx.source_open_port}/readonly-source.txt"
        code = _copy_code(tpc_nginx.dest_readonly_port, "/should-not-copy.txt", source)

        assert code == 403
        assert not (tpc_nginx.dest_readonly_root / "should-not-copy.txt").exists()

    @pytest.mark.registry_server("webdav-tpc")
    def test_missing_service_credential_cannot_pull_required_source(self, tpc_nginx):
        content = b"requires outbound client cert\n"
        _write(tpc_nginx.source_required_root / "needs-cert.txt", content)

        source = f"https://{HOST}:{tpc_nginx.source_required_port}/needs-cert.txt"
        code = _copy_code(
            tpc_nginx.dest_no_service_cert_port,
            "/missing-service-cert.txt",
            source,
        )

        assert code == 502
        assert not (tpc_nginx.dest_no_service_cert_root / "missing-service-cert.txt").exists()


class TestXrootdHttpInteropTPC:
    @pytest.mark.registry_server("webdav-tpc")
    def test_brix_http_source_to_nginx_plugin_destination(self, tpc_nginx, reference_xrd_http):
        content = b"xrootd http source pulled into nginx plugin destination\n"
        _write(reference_xrd_http.data_root / "xrd-source.txt", content)

        source = f"https://{HOST}:{reference_xrd_http.http_port}/xrd-source.txt"
        code = _copy_code(tpc_nginx.dest_cafile_port, "/from-xrootd-http.txt", source)

        assert code == 201
        assert (tpc_nginx.dest_cafile_root / "from-xrootd-http.txt").read_bytes() == content

    @pytest.mark.registry_server("webdav-tpc")
    def test_nginx_plugin_source_to_brix_http_destination(self, tpc_nginx, reference_xrd_http):
        content = b"nginx plugin source pulled into xrootd http destination\n"
        _write(tpc_nginx.source_open_root / "nginx-source-for-xrd.txt", content)

        source = f"https://{HOST}:{tpc_nginx.source_open_port}/nginx-source-for-xrd.txt"
        result = _curl(
            "-X",
            "COPY",
            f"https://{HOST}:{reference_xrd_http.http_port}/from-nginx-plugin.txt",
            "-H",
            "Credential: none",
            "-H",
            f"Source: {source}",
            "-w",
            "%{http_code}",
            "-o",
            "/dev/null",
            timeout=30,
        )

        assert result.returncode == 0, result.stderr.decode(errors="replace")
        assert int(result.stdout.strip()) in (200, 201, 202)
        assert _wait_for_file(
            reference_xrd_http.data_root / "from-nginx-plugin.txt",
            content,
        )


class TestHTTPTPCPush:
    """HTTP-TPC push-mode tests: the source server reads a local file and PUTs
    it to a remote HTTPS destination (curl --upload-file)."""

    @pytest.mark.registry_server("webdav-tpc")
    def test_push_basic_creates_file_at_destination(self, tpc_nginx):
        content = b"pushed via HTTP-TPC push mode\n"
        _write(tpc_nginx.source_open_root / "push-source.txt", content)

        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-basic-dest.txt"
        )
        code = _copy_push_code(
            tpc_nginx.source_open_port, "/push-source.txt", dest_url
        )

        assert code == 201
        assert (tpc_nginx.dest_cafile_root / "push-basic-dest.txt").read_bytes() == content

    @pytest.mark.registry_server("webdav-tpc")
    def test_push_required_source_with_auth(self, tpc_nginx):
        content = b"push from auth-required source\n"
        _write(tpc_nginx.source_required_root / "push-required-source.txt", content)

        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-from-required.txt"
        )
        code = _copy_push_code(
            tpc_nginx.source_required_port,
            "/push-required-source.txt",
            dest_url,
        )

        assert code == 201
        assert (tpc_nginx.dest_cafile_root / "push-from-required.txt").read_bytes() == content

    @pytest.mark.registry_server("webdav-tpc")
    def test_push_to_cadir_destination(self, tpc_nginx):
        content = b"push to cadir destination\n"
        _write(tpc_nginx.source_open_root / "push-cadir-source.txt", content)

        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cadir_port}/push-via-cadir.txt"
        )
        code = _copy_push_code(
            tpc_nginx.source_open_port, "/push-cadir-source.txt", dest_url
        )

        assert code == 201
        assert (tpc_nginx.dest_cadir_root / "push-via-cadir.txt").read_bytes() == content

    @pytest.mark.registry_server("webdav-tpc")
    def test_push_nonexistent_source_returns_404(self, tpc_nginx):
        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-should-not-exist.txt"
        )
        code = _copy_push_code(
            tpc_nginx.source_open_port, "/no-such-file.txt", dest_url
        )

        assert code == 404
        assert not (tpc_nginx.dest_cafile_root / "push-should-not-exist.txt").exists()

    @pytest.mark.registry_server("webdav-tpc")
    def test_push_directory_source_returns_409(self, tpc_nginx):
        (tpc_nginx.source_open_root / "push-dir").mkdir(exist_ok=True)

        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-dir-dest.txt"
        )
        code = _copy_push_code(
            tpc_nginx.source_open_port, "/push-dir", dest_url
        )

        assert code == 409

    @pytest.mark.registry_server("webdav-tpc")
    def test_push_tpc_disabled_on_source_returns_405(self, tpc_nginx):
        """dest_disabled_port has brix_webdav_tpc off — COPY must be rejected."""
        _write(tpc_nginx.dest_disabled_root / "push-disabled-src.txt", b"x\n")

        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-disabled.txt"
        )
        code = _copy_push_code(
            tpc_nginx.dest_disabled_port, "/push-disabled-src.txt", dest_url
        )

        assert code == 405

    @pytest.mark.registry_server("webdav-tpc")
    def test_push_missing_service_cert_destination_fails_502(self, tpc_nginx):
        """Source has no outbound cert — destination (auth required) rejects curl PUT."""
        _write(tpc_nginx.dest_no_service_cert_root / "push-no-cert-src.txt", b"data\n")

        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-no-cert-dest.txt"
        )
        code = _copy_push_code(
            tpc_nginx.dest_no_service_cert_port,
            "/push-no-cert-src.txt",
            dest_url,
        )

        assert code == 502
        assert not (tpc_nginx.dest_cafile_root / "push-no-cert-dest.txt").exists()

    @pytest.mark.registry_server("webdav-tpc")
    def test_push_non_https_destination_rejected_400(self, tpc_nginx):
        _write(tpc_nginx.source_open_root / "push-http-dest-src.txt", b"data\n")

        code = _copy_push_code(
            tpc_nginx.source_open_port,
            "/push-http-dest-src.txt",
            f"http://{HOST}:9999/should-be-rejected",
        )

        assert code == 400

    @pytest.mark.registry_server("webdav-tpc")
    def test_push_with_transfer_header_forwarded(self, tpc_nginx):
        content = b"push with transfer header\n"
        _write(tpc_nginx.source_open_root / "push-xfer-hdr-src.txt", content)

        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-xfer-hdr-dest.txt"
        )
        code = _copy_push_code(
            tpc_nginx.source_open_port,
            "/push-xfer-hdr-src.txt",
            dest_url,
            "TransferHeaderX-Custom-Test: tpc-push-test",
        )

        assert code == 201
        assert (tpc_nginx.dest_cafile_root / "push-xfer-hdr-dest.txt").read_bytes() == content

    @pytest.mark.registry_server("webdav-tpc")
    def test_push_overwrite_false_forwarded(self, tpc_nginx):
        """Pushing with Overwrite: F should be forwarded to the destination.
        If the destination exists, it should return 412."""
        _write(tpc_nginx.source_open_root / "push-ovr-src.txt", b"new\n")
        dest_file = tpc_nginx.dest_cafile_root / "push-ovr-dest.txt"
        _write(dest_file, b"old\n")

        dest_url = f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-ovr-dest.txt"
        
        # When Overwrite: F is forwarded, the destination returns 412.
        # Since we use curl --fail, it exits with an error and we return 502.
        code = _copy_push_code(
            tpc_nginx.source_open_port,
            "/push-ovr-src.txt",
            dest_url,
            "Overwrite: F",
        )

        assert code == 502
        assert dest_file.read_bytes() == b"old\n"

    @pytest.mark.registry_server("webdav-tpc")
    def test_both_source_and_destination_headers_rejected_400(self, tpc_nginx):
        """Supplying both Source: and Destination: is ambiguous — must return 400."""
        _write(tpc_nginx.source_open_root / "push-both-hdrs.txt", b"data\n")

        source_url = (
            f"https://{HOST}:{tpc_nginx.source_open_port}/push-both-hdrs.txt"
        )
        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-both-hdrs-dest.txt"
        )
        result = _curl(
            "-X",
            "COPY",
            f"https://{HOST}:{tpc_nginx.source_open_port}/push-both-hdrs.txt",
            "-H",
            "Credential: none",
            "-H",
            f"Source: {source_url}",
            "-H",
            f"Destination: {dest_url}",
            "-w",
            "%{http_code}",
            "-o",
            "/dev/null",
        )
        assert result.returncode == 0
        assert int(result.stdout.strip()) == 400
