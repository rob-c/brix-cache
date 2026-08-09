from split_continuation import reexport as _reexport
_reexport(globals(), "_test_vo_acl_helpers")

class TestCmsProxy:
    """A VOMS proxy carrying the 'cms' VO is admitted to /cms/ and denied /atlas/."""

    @pytest.mark.registry_server("vo-acl")
    def test_stat_cms_dir(self, vo_nginx):
        """CMS proxy can stat the /cms/ directory."""
        assert _xrdfs_stat("/cms", PROXY_CMS) == 0

    @pytest.mark.registry_server("vo-acl")
    def test_dirlist_cms(self, vo_nginx):
        """CMS proxy can list the /cms/ directory."""
        assert _xrdfs_ls("/cms", PROXY_CMS) == 0

    @pytest.mark.registry_server("vo-acl")
    def test_read_cms_file(self, vo_nginx):
        """CMS proxy can read a file in /cms/."""
        assert _xrdcp_read("/cms/seed.txt", PROXY_CMS) == 0

    @pytest.mark.registry_server("vo-acl")
    def test_write_cms_file(self, vo_nginx):
        """CMS proxy can write a file into /cms/."""
        assert _xrdcp_write(b"cms write test\n", "/cms/cms_write.txt", PROXY_CMS) == 0

    @pytest.mark.registry_server("vo-acl")
    def test_stat_cms_file_python_client(self, vo_nginx):
        """Python XRootD client: CMS proxy stat returns ok for a /cms/ path."""
        status, _ = _python_stat("/cms/seed.txt", PROXY_CMS)
        assert status.ok, f"stat /cms/seed.txt with cms proxy failed: {status.message}"

    @pytest.mark.registry_server("vo-acl")
    def test_denied_atlas_stat(self, vo_nginx):
        """CMS proxy must NOT stat /atlas/."""
        assert _xrdfs_stat("/atlas", PROXY_CMS) != 0

    @pytest.mark.registry_server("vo-acl")
    def test_denied_atlas_read(self, vo_nginx):
        """CMS proxy must NOT read from /atlas/."""
        assert _xrdcp_read("/atlas/seed.txt", PROXY_CMS) != 0

    @pytest.mark.registry_server("vo-acl")
    def test_denied_atlas_write(self, vo_nginx):
        """CMS proxy must NOT write to /atlas/."""
        assert _xrdcp_write(b"should not land\n", "/atlas/cms_intruder.txt",
                            PROXY_CMS) != 0

    @pytest.mark.registry_server("vo-acl")
    def test_denied_atlas_python_client(self, vo_nginx):
        """Python XRootD client: CMS proxy stat of /atlas/ returns not-ok."""
        status, _ = _python_stat("/atlas/seed.txt", PROXY_CMS)
        assert not status.ok, "CMS proxy should be denied /atlas/ path"


# ---------------------------------------------------------------------------
# Tests: ATLAS proxy → /atlas/ (allowed) and /cms/ (denied)
# ---------------------------------------------------------------------------

class TestAtlasProxy:
    """A VOMS proxy carrying the 'atlas' VO is admitted to /atlas/ and denied /cms/."""

    @pytest.mark.registry_server("vo-acl")
    def test_stat_atlas_dir(self, vo_nginx):
        """ATLAS proxy can stat the /atlas/ directory."""
        assert _xrdfs_stat("/atlas", PROXY_ATLAS) == 0

    @pytest.mark.registry_server("vo-acl")
    def test_dirlist_atlas(self, vo_nginx):
        """ATLAS proxy can list the /atlas/ directory."""
        assert _xrdfs_ls("/atlas", PROXY_ATLAS) == 0

    @pytest.mark.registry_server("vo-acl")
    def test_read_atlas_file(self, vo_nginx):
        """ATLAS proxy can read a file in /atlas/."""
        assert _xrdcp_read("/atlas/seed.txt", PROXY_ATLAS) == 0

    @pytest.mark.registry_server("vo-acl")
    def test_write_atlas_file(self, vo_nginx):
        """ATLAS proxy can write a file into /atlas/."""
        assert _xrdcp_write(b"atlas write test\n", "/atlas/atlas_write.txt",
                            PROXY_ATLAS) == 0

    @pytest.mark.registry_server("vo-acl")
    def test_denied_cms_stat(self, vo_nginx):
        """ATLAS proxy must NOT stat /cms/."""
        assert _xrdfs_stat("/cms", PROXY_ATLAS) != 0

    @pytest.mark.registry_server("vo-acl")
    def test_denied_cms_read(self, vo_nginx):
        """ATLAS proxy must NOT read from /cms/."""
        assert _xrdcp_read("/cms/seed.txt", PROXY_ATLAS) != 0

    @pytest.mark.registry_server("vo-acl")
    def test_denied_cms_write(self, vo_nginx):
        """ATLAS proxy must NOT write to /cms/."""
        assert _xrdcp_write(b"should not land\n", "/cms/atlas_intruder.txt",
                            PROXY_ATLAS) != 0


# ---------------------------------------------------------------------------
# Tests: plain GSI proxy (no VOMS) → denied all restricted paths
# ---------------------------------------------------------------------------

class TestPlainProxy:
    """
    A plain GSI proxy (no VOMS extension) authenticates successfully but
    carries no VO membership, so it must be denied every VO-restricted path.
    """

    @pytest.mark.registry_server("vo-acl")
    def test_denied_cms_stat(self, vo_nginx):
        """Plain proxy denied stat on /cms/."""
        assert _xrdfs_stat("/cms", PROXY_STD) != 0

    @pytest.mark.registry_server("vo-acl")
    def test_denied_cms_read(self, vo_nginx):
        """Plain proxy denied read from /cms/."""
        assert _xrdcp_read("/cms/seed.txt", PROXY_STD) != 0

    @pytest.mark.registry_server("vo-acl")
    def test_denied_atlas_stat(self, vo_nginx):
        """Plain proxy denied stat on /atlas/."""
        assert _xrdfs_stat("/atlas", PROXY_STD) != 0

    @pytest.mark.registry_server("vo-acl")
    def test_denied_atlas_read(self, vo_nginx):
        """Plain proxy denied read from /atlas/."""
        assert _xrdcp_read("/atlas/seed.txt", PROXY_STD) != 0

    @pytest.mark.registry_server("vo-acl")
    def test_denied_cms_write(self, vo_nginx):
        """Plain proxy (no VO) must NOT write into /cms/ either."""
        assert _xrdcp_write(b"no-vo intruder\n", "/cms/novo_intruder.txt",
                            PROXY_STD) != 0

    @pytest.mark.registry_server("vo-acl")
    def test_denied_atlas_write(self, vo_nginx):
        """Plain proxy (no VO) must NOT write into /atlas/ either."""
        assert _xrdcp_write(b"no-vo intruder\n", "/atlas/novo_intruder.txt",
                            PROXY_STD) != 0

    @pytest.mark.registry_server("vo-acl")
    def test_allowed_public_stat(self, vo_nginx):
        """Plain proxy is allowed to stat the unrestricted /public/ directory."""
        assert _xrdfs_stat("/public", PROXY_STD) == 0

    @pytest.mark.registry_server("vo-acl")
    def test_allowed_public_read(self, vo_nginx):
        """Plain proxy can read a file in the unrestricted /public/ directory."""
        assert _xrdcp_read("/public/seed.txt", PROXY_STD) == 0

    @pytest.mark.registry_server("vo-acl")
    def test_allowed_public_write(self, vo_nginx):
        """Positive partner: plain proxy CAN write to the unrestricted /public/
        — proving the /cms and /atlas write denials above are VO-ACL, not a
        read-only endpoint."""
        assert _xrdcp_write(b"no-vo public write\n", "/public/novo_write.txt",
                            PROXY_STD) == 0


# ---------------------------------------------------------------------------
# Tests: unrestricted /public/ is accessible to all VOs
# ---------------------------------------------------------------------------

class TestPublicAccess:
    """Any authenticated client can access paths without a VO restriction."""

    @pytest.mark.registry_server("vo-acl")
    def test_cms_proxy_public_stat(self, vo_nginx):
        assert _xrdfs_stat("/public", PROXY_CMS) == 0

    @pytest.mark.registry_server("vo-acl")
    def test_atlas_proxy_public_stat(self, vo_nginx):
        assert _xrdfs_stat("/public", PROXY_ATLAS) == 0

    @pytest.mark.registry_server("vo-acl")
    def test_cms_proxy_public_read(self, vo_nginx):
        assert _xrdcp_read("/public/seed.txt", PROXY_CMS) == 0

    @pytest.mark.registry_server("vo-acl")
    def test_atlas_proxy_public_read(self, vo_nginx):
        assert _xrdcp_read("/public/seed.txt", PROXY_ATLAS) == 0

    @pytest.mark.registry_server("vo-acl")
    def test_cms_proxy_public_write(self, vo_nginx):
        assert _xrdcp_write(b"public write by cms\n",
                            "/public/cms_public.txt", PROXY_CMS) == 0

    @pytest.mark.registry_server("vo-acl")
    def test_atlas_proxy_public_write(self, vo_nginx):
        assert _xrdcp_write(b"public write by atlas\n",
                            "/public/atlas_public.txt", PROXY_ATLAS) == 0
