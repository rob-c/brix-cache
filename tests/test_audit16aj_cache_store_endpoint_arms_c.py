"""Test cases for audit16aj_cache_store_endpoint_arms — preamble (fixtures/helpers/mocks) lives in
_test_audit16aj_cache_store_endpoint_arms_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16aj_cache_store_endpoint_arms_helpers")


class TestUnlinkIsGuardedLikeTheReadingVerbs:
    """DEFECT CANDIDATE #141, fixed.  The flag was read at open, stat and statx
    and nowhere on the unlink path, so a client held to "this file does not
    exist" on every reading verb could still destroy it — while the WebDAV
    plane, over the same export and the same flag, refused the same DELETE.
    That made it a disagreement between two implementations of one rule rather
    than a deliberate asymmetry between reading and writing.

    The guard now sits in `brix_path_resolve_beneath` (root/path/op_path.c),
    which is the shared resolve core for rm, rmdir, mkdir, chmod, truncate,
    readlink, fattr and kXR_mv — so every mutating path verb inherits it at
    once, and it returns the gate's own NGX_DECLINED so the refusal leaves by
    the same door a genuine miss does.
    """

    def test_a_sidecar_the_client_cannot_stat_cannot_be_unlinked_either(self, srv):
        victim = "unlinked-by-f.cinfo"
        (srv / victim).write_bytes(SECRET)
        session = _session(ROOT_OFF)
        try:
            _, status, body = _stat_path(session, "/" + victim)
            assert status != kXR_ok and _err(body) == 3011

            open_status, open_body = _open(session, "/" + victim, kXR_open_read)
            assert open_status != kXR_ok and _err(open_body) == 3011

            rm_status, rm_body = _rm(session, "/" + victim)
            assert rm_status != kXR_ok and _err(rm_body) == 3011
        finally:
            session.close()
        assert (srv / victim).read_bytes() == SECRET

    def test_webdav_and_root_now_answer_the_same_delete_alike(self, srv):
        """The control that raised the defect, kept as the one that pins it
        closed: two planes, one flag, one export, one answer."""
        victim = "kept-by-webdav.cinfo"
        (srv / victim).write_bytes(SECRET)
        assert _dav(DAV_OFF, "DELETE", "/" + victim).status_code == 404
        assert (srv / victim).read_bytes() == SECRET
        session = _session(ROOT_OFF)
        try:
            status, body = _rm(session, "/" + victim)
            assert status != kXR_ok and _err(body) == 3011
        finally:
            session.close()
        assert (srv / victim).read_bytes() == SECRET

    def test_a_present_and_an_absent_reserved_name_are_not_told_apart(self, srv):
        """The refusal has to be the miss, not merely A refusal — otherwise the
        guard closes the destruction and re-opens the disclosure it was added
        to prevent."""
        victim = "present-for-f.cinfo"
        (srv / victim).write_bytes(SECRET)
        session = _session(ROOT_OFF)
        try:
            present = _rm(session, "/" + victim)
            absent = _rm(session, "/ghost-for-f.cinfo")
            plain_absent = _rm(session, "/ghost-for-f.dat")
            assert _err(present[1]) == _err(absent[1]) == _err(plain_absent[1]) == 3011
            assert _reason(present[1]) == _reason(absent[1]) == _reason(plain_absent[1])
        finally:
            session.close()
        assert (srv / victim).read_bytes() == SECRET

    def test_rmdir_took_the_guard_from_the_same_core(self, srv):
        """rm and rmdir reach `brix_path_resolve_beneath` by different opcodes;
        fixing one and not the other would leave a reserved DIRECTORY removable
        by a client that cannot see it."""
        victim = srv / "doomed.meta"
        victim.mkdir(exist_ok=True)
        session = _session(ROOT_OFF)
        try:
            status, body = _rmdir(session, "/doomed.meta")
            assert status != kXR_ok and _err(body) == 3011
        finally:
            session.close()
        assert victim.is_dir()

    def test_the_armed_arm_can_still_unlink_its_own_sidecars(self, srv):
        """A cache-store endpoint exists to write and rewrite these names; a
        guard that refused them there would break the feature the flag turns
        on."""
        victim = "unlinked-by-store.cinfo"
        (srv / victim).write_bytes(SECRET)
        session = _session(ROOT_ON)
        try:
            status, body = _rm(session, "/" + victim)
            assert status == kXR_ok, _err(body)
        finally:
            session.close()
        assert not (srv / victim).exists()

    def test_a_near_miss_name_is_still_removable_on_the_disarmed_arm(self, srv):
        """SECURITY-NEGATIVE.  The predicate now walks every path component, so
        the cell that matters is the one showing it did not start swallowing
        names it never matched: `keep.CINFO` differs by case, `x.cinfofoo` by a
        suffix, `sub/plain.dat` by nothing at all."""
        session = _session(ROOT_OFF)
        try:
            for name in ("near-miss.CINFO", "near-miss.cinfofoo", "near-miss.dat"):
                (srv / name).write_bytes(SECRET)
                status, body = _rm(session, "/" + name)
                assert status == kXR_ok, (name, _err(body))
                assert not (srv / name).exists()
        finally:
            session.close()


# --------------------------------------------------------------------------- #
# G. The duplicate both declarations now refuse — DEFECT CANDIDATE #142        #
# --------------------------------------------------------------------------- #

