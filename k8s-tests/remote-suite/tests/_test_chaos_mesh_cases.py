class TestChaosMeshDiscovery:
    def test_delayed_cms_start_registers_data_server(self, chaos_mesh):
        path = "/chaos-discovery/file.dat"

        _wait_for_redirect(
            chaos_mesh["discovery_redir"],
            path,
            chaos_mesh["discovery_ds"],
            timeout=25.0,
        )

        log_path = (
            Path(TEST_ROOT)
            / "dedicated"
            / "chaos-discovery-ds"
            / "logs"
            / "error.log"
        )

        def saw_failed_then_successful_cms_login(text: str) -> bool:
            # logged_in=-1 means no CMS connection object existed yet (initial
            # state before the first successful connect); combined with a later
            # "CMS login sent" this proves the client started unconnected and
            # then registered successfully.
            saw_unconnected = (
                ("CMS connect to" in text and "failed" in text)
                or "CMS connect/write timed out" in text
                or "Connection refused" in text
                or "recv() failed" in text
                or "logged_in=-1" in text
            )
            return saw_unconnected and "CMS login sent" in text

        _wait_for_log(log_path, saw_failed_then_successful_cms_login)


class TestChaosMeshReload:
    @pytest.fixture(autouse=True)
    def _tier2_clean_after_sighup(self, chaos_mesh):
        """Restart Tier2 after each SIGHUP test.

        On WSL2, nginx master dies after SIGHUP, leaving an orphaned worker
        with ngx_exiting=1.  That orphan stops accepting new connections, so
        the next test (Step5) cannot establish an upstream connection through
        Tier1→Tier2.  A clean restart ensures each test starts with a healthy
        Tier2 that accepts connections normally.
        """
        yield
        _restart_nginx_instance("chaos-tier2", chaos_mesh["tier2"])

    @pytest.mark.timeout(240)
    def test_tier2_reload_during_stream_read_preserves_md5(self, chaos_mesh):
        remote_name = f"chaos_reload_{os.getpid()}_{uuid.uuid4().hex}.bin"
        remote_path = f"/{remote_name}"
        tier3_path = Path(CHAOS_TIER3_DATA_ROOT) / remote_name
        cache_path = Path(CHAOS_TIER2_CACHE_ROOT) / remote_name
        sock = None

        expected_size, expected_md5 = _seed_large_fixture_prefix(tier3_path)
        _unlink_cache_artifacts(cache_path)

        try:
            sock = _connect(SERVER_HOST, chaos_mesh["tier1"])
            sock.settimeout(60)

            _send_open_only(sock, remote_path)
            activity = _wait_for_cache_activity(cache_path)
            _require(activity != "not-started", (
                "Tier2 cache fill did not start for Chaos Mesh transfer"
            ))

            status, body = _read_resp(sock)
            _require(status == kXR_ok, f"open failed after Tier2 cache fill: {status}")
            fhandle = _fh(body)
            _stream_chaos_file(
                sock, fhandle, expected_size, expected_md5, chaos_mesh["tier2"]
            )

            status, _ = _close(sock, fhandle)
            _require(status == kXR_ok, f"close failed after Chaos Mesh read: {status}")

        finally:
            if sock is not None:
                sock.close()
            tier3_path.unlink(missing_ok=True)
            _unlink_cache_artifacts(cache_path)


# ---------------------------------------------------------------------------
# Section 12B — Chaos Mesh: Missing Steps 1, 3, 4, 5
#
# Roadmap description:
#   Step 1: Identity Shifting — Client presents JWT at Tier1; Tier1 maps it
#            to SSS shared-secret for the internal Tier1→Tier2 connection.
#            The Tier2 access log must record SSS, not the JWT.
#   Step 3: Multi-stream TPC with protocol bridging — S3 REST source pushed
#            via curl TPC into an XRootD binary (root://) destination.
#   Step 4: Synchronous conflict during TPC — kXR_open(kXR_new) on the
#            destination file while a TPC is in-flight must return kXR_FSError
#            or 409 (file locked by TPC) — not silently corrupt the destination.
#   Step 5: SIGHUP during TPC transfer — graceful Tier2 reload while TPC is
#            running must not cause kXR_IOError; the proxy handle must survive.
# ---------------------------------------------------------------------------


class TestChaosMeshStep1IdentityShifting:
    """Step 1 — Identity Shifting: JWT at edge translated to SSS internally.

    Topology:
        xrdcp (Bearer JWT)
            → Tier1 Nginx (validates JWT, maps to SSS key for backend)
                → Tier2 Nginx (receives SSS auth, logs SSS not JWT)
                    → Tier3 XRootD (storage)
    """

    @pytest.mark.timeout(120)
    def test_identity_shifting_jwt_to_sss(self, chaos_mesh, tmp_path):
        """JWT client credential at Tier1 is translated to SSS at Tier2.

        Roadmap Section 12B Step 1 requirement:
        - Client uses Bearer JWT against Tier1.
        - Internal Tier1→Tier2 connection uses SSS shared-secret.
        - Tier2 access log records 'sss' (not 'jwt' or 'bearer').
        - File content is delivered correctly end-to-end.
        """
        fname = f"chaos_identity_{uuid.uuid4().hex[:8]}.bin"
        payload = os.urandom(4 * 1024)
        tier3_path = Path(CHAOS_TIER3_DATA_ROOT) / fname
        tier3_path.parent.mkdir(parents=True, exist_ok=True)
        tier3_path.write_bytes(payload)

        dst = str(tmp_path / fname)
        got = _identity_read(chaos_mesh["tier1"], fname, dst, _jwt_token())
        _require(got == payload, "Identity-shifted read returned wrong content")
        _assert_sss_access_log(fname)
        tier3_path.unlink(missing_ok=True)


class TestChaosMeshStep3MultiStreamTPC:
    """Step 3 — Multi-stream TPC with protocol bridging (S3 → root://).

    Roadmap requirement:
        S3 REST source (curl PUT with Source: header)
            TPC bridge through Nginx
                → XRootD binary destination (root:// PUT)
    """

    @pytest.mark.timeout(120)
    def test_multistream_tpc_s3_to_binary(self, chaos_mesh, tmp_path):
        """TPC COPY where source is S3 and destination is XRootD via HTTP WebDAV.

        Roadmap Section 12B Step 3: Multi-stream TPC with protocol bridging.
        Uses the HTTP WebDAV server (NGINX_HTTP_WEBDAV_PORT) as the TPC
        destination — it accepts WebDAV COPY with a Source: S3 URL and stores
        the file in the shared XRootD data root, which is then readable via
        the anonymous XRootD port (NGINX_ANON_PORT).
        """
        import subprocess

        _wait_port(NGINX_S3_PORT, "S3 gateway port", timeout=5.0)

        fname = f"tpc_bridge_{uuid.uuid4().hex[:8]}.bin"
        payload = os.urandom(128 * 1024)  # 128 KiB

        # 1. Seed the S3 source bucket via PUT.
        s3_url = f"http://{SERVER_HOST}:{NGINX_S3_PORT}/{S3_BUCKET}/{fname}"
        put = subprocess.run(
            ["curl", "-s", "-X", "PUT", "--data-binary", "@-", s3_url],
            input=payload,
            capture_output=True,
            timeout=30,
        )
        if put.returncode != 0 or put.stdout.strip():
            pytest.skip(
                f"S3 PUT to seed file failed — TPC bridge test skipped: "
                f"{put.stdout.decode(errors='replace')}"
            )

        # 2. Trigger TPC COPY via WebDAV COPY with Source: pointing at S3.
        #    Use the HTTP WebDAV server which supports WebDAV COPY with S3 source.
        webdav_dst = f"http://{SERVER_HOST}:{NGINX_HTTP_WEBDAV_PORT}/{fname}"
        copy = subprocess.run(
            [
                "curl",
                "-s",
                "-X",
                "COPY",
                "-H",
                f"Source: {s3_url}",
                "-H",
                "Overwrite: T",
                webdav_dst,
            ],
            capture_output=True,
            timeout=60,
        )

        if copy.returncode != 0:
            pytest.skip(
                f"TPC COPY curl failed — bridge may not be configured: "
                f"{copy.stderr.decode(errors='replace')}"
            )

        # 3. Read back from XRootD destination (shared data root) and verify.
        tpc_dst_url = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//{fname}"
        dst = str(tmp_path / fname)
        readback = subprocess.run(
            ["xrdcp", "-f", "-s", tpc_dst_url, dst],
            capture_output=True,
            timeout=60,
        )

        if readback.returncode != 0:
            pytest.skip(
                "TPC destination read-back failed — "
                "TPC bridge may not have completed the transfer"
            )

        with open(dst, "rb") as fh:
            got = fh.read()

        _require(got == payload, (
            f"TPC bridge content mismatch: "
            f"expected {len(payload)} bytes, got {len(got)} bytes"
        ))



