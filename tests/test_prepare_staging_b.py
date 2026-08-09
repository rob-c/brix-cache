from split_continuation import reexport as _reexport
_reexport(globals(), "_test_prepare_staging_helpers")

class TestPrepareStageCommand:
    """Verify brix_prepare_command is invoked on kXR_stage requests.

    Uses pre-started dedicated servers (launched by manage_test_servers.sh):
      - prepare-command  (PREPARE_CMD_PORT):  brix_export=PREPARE_CMD_DATA_DIR,
        brix_prepare_command set to a hook that appends paths to PREPARE_CMD_LOG.
      - prepare-nocmd    (PREPARE_NOCMD_PORT): same xrootd config without
        brix_prepare_command.
    """

    @staticmethod
    def _truncate_log() -> None:
        """Reset the shared stage log before each test."""
        os.makedirs(os.path.dirname(PREPARE_CMD_LOG), exist_ok=True)
        open(PREPARE_CMD_LOG, "w").close()

    @staticmethod
    def _session_on(port: int):
        return _establish_session(port)

    @pytest.mark.requires_local_server
    @pytest.mark.registry_server("prepare-command")
    def test_stage_flag_invokes_command(self):
        """kXR_prepare with kXR_stage flag must invoke brix_prepare_command
        with the resolved absolute paths of all staged files.
        """
        self._truncate_log()
        os.makedirs(PREPARE_CMD_DATA_DIR, exist_ok=True)
        with open(os.path.join(PREPARE_CMD_DATA_DIR, "tape_file.dat"), "wb") as f:
            f.write(b"tape seed\n")

        sock, streamid = self._session_on(PREPARE_CMD_PORT)
        status, body = _send_prepare(sock, streamid, 0x08, 0, b"/tape_file.dat\n")
        sock.close()

        assert status == kXR_ok, \
            f"kXR_prepare kXR_stage failed: status={status} body={body!r}"

        for _ in range(30):
            if os.path.getsize(PREPARE_CMD_LOG) > 0:
                break
            time.sleep(0.1)

        assert os.path.getsize(PREPARE_CMD_LOG) > 0, \
            "brix_prepare_command was not invoked (log file empty after 3s)"

        content = open(PREPARE_CMD_LOG).read().strip()
        assert content.endswith("/tape_file.dat"), \
            f"unexpected staged path recorded: {content!r}"

    @pytest.mark.requires_local_server
    @pytest.mark.registry_server("prepare-command")
    def test_no_stage_flag_skips_command(self):
        """kXR_prepare WITHOUT kXR_stage must NOT invoke brix_prepare_command."""
        self._truncate_log()
        os.makedirs(PREPARE_CMD_DATA_DIR, exist_ok=True)
        with open(os.path.join(PREPARE_CMD_DATA_DIR, "local_file.dat"), "wb") as f:
            f.write(b"local seed\n")

        sock, streamid = self._session_on(PREPARE_CMD_PORT)
        # options=0 → no kXR_stage; server treats this as a stat-only prepare.
        status, body = _send_prepare(sock, streamid, 0x00, 0, b"/local_file.dat\n")
        sock.close()

        assert status == kXR_ok, \
            f"plain prepare returned error: status={status} body={body!r}"

        time.sleep(0.3)
        assert open(PREPARE_CMD_LOG).read() == "", \
            "brix_prepare_command was wrongly invoked (no kXR_stage flag)"

    @pytest.mark.requires_local_server
    @pytest.mark.registry_server("prepare-nocmd")
    def test_no_config_stage_silently_accepted(self):
        """kXR_stage with no brix_prepare_command configured must return
        kXR_ok — silently accepted with no error and no command invoked.
        """
        os.makedirs(PREPARE_NOCMD_DATA_DIR, exist_ok=True)
        with open(os.path.join(PREPARE_NOCMD_DATA_DIR, "noop_file.dat"), "wb") as f:
            f.write(b"noop seed\n")

        sock, streamid = self._session_on(PREPARE_NOCMD_PORT)
        status, body = _send_prepare(sock, streamid, 0x08, 0, b"/noop_file.dat\n")
        sock.close()

        assert status == kXR_ok, \
            f"kXR_stage without prepare_command must return ok: " \
            f"status={status} body={body!r}"

    @pytest.mark.requires_local_server
    @pytest.mark.registry_server("prepare-command")
    def test_stage_noerrs_missing_file_collected(self):
        """kXR_prepare with kXR_stage|kXR_noerrs and a missing file must still
        return kXR_ok and pass the resolved (pre-staging) path to the command.
        """
        self._truncate_log()
        missing = os.path.join(PREPARE_CMD_DATA_DIR, "on_tape_not_disk.dat")
        if os.path.exists(missing):
            os.remove(missing)

        sock, streamid = self._session_on(PREPARE_CMD_PORT)
        # kXR_stage (0x08) | kXR_noerrs (0x04) = 0x0c; file does not exist on disk
        status, body = _send_prepare(sock, streamid, 0x0c, 0,
                                     b"/on_tape_not_disk.dat\n")
        sock.close()

        assert status == kXR_ok, \
            f"kXR_stage|kXR_noerrs for missing file must return ok: " \
            f"status={status} body={body!r}"

        for _ in range(30):
            if os.path.getsize(PREPARE_CMD_LOG) > 0:
                break
            time.sleep(0.1)

        assert os.path.getsize(PREPARE_CMD_LOG) > 0, \
            "prepare_command not invoked for missing-file kXR_stage|kXR_noerrs"
        content = open(PREPARE_CMD_LOG).read().strip()
        assert content.endswith("/on_tape_not_disk.dat"), \
            f"unexpected path in command args: {content!r}"

    @pytest.mark.requires_local_server
    @pytest.mark.registry_server("prepare-command")
    def test_stage_cancel_skips_command(self):
        """kXR_prepare with kXR_cancel must return ok immediately (no-op) and
        must NOT invoke brix_prepare_command even if configured.
        """
        self._truncate_log()

        sock, streamid = self._session_on(PREPARE_CMD_PORT)
        # kXR_cancel = 0x01; cancel overrides stage in the dispatch path.
        status, body = _send_prepare(sock, streamid, 0x01, 0, b"/any_file.dat\n")
        sock.close()

        assert status == kXR_ok, \
            f"cancel prepare must return ok: status={status} body={body!r}"

        time.sleep(0.3)
        assert open(PREPARE_CMD_LOG).read() == "", \
            "prepare_command was wrongly invoked on kXR_cancel request"

    @pytest.mark.requires_local_server
    @pytest.mark.registry_server("prepare-command")
    def test_coloc_flag_passed_to_command(self):
        """kXR_prepare with kXR_coloc flag must set BRIX_PREPARE_COLOC=1 for the command."""
        self._truncate_log()
        os.makedirs(PREPARE_CMD_DATA_DIR, exist_ok=True)
        with open(os.path.join(PREPARE_CMD_DATA_DIR, "coloc_file.dat"), "wb") as f:
            f.write(b"coloc seed\n")

        sock, streamid = self._session_on(PREPARE_CMD_PORT)
        # kXR_stage (0x08) | kXR_coloc (0x20) = 0x28
        status, body = _send_prepare(sock, streamid, 0x28, 0, b"/coloc_file.dat\n")
        sock.close()

        assert status == kXR_ok

        for _ in range(30):
            if os.path.getsize(PREPARE_CMD_LOG) > 0:
                break
            time.sleep(0.1)

        assert os.path.getsize(PREPARE_CMD_LOG) > 0

        content = open(PREPARE_CMD_LOG).read()
        assert "COLOC=1" in content, f"COLOC=1 missing from log: {content!r}"
        assert "/coloc_file.dat" in content
