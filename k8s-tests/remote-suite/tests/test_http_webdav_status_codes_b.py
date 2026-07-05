from _test_http_webdav_status_codes_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

class TestPropfind:
    def test_propfind_file_depth0_207(self):
        path, _, _ = _existing_file()
        r = _propfind(path, depth="0")
        assert r.status_code == 207

    def test_propfind_directory_depth1_207(self):
        path = f"/{_PFX}pfdir_{_uid()}"
        _mkcol(path)
        r = _propfind(path, depth="1")
        assert r.status_code == 207

    def test_propfind_directory_depth0_207(self):
        path = f"/{_PFX}pfd0_{_uid()}"
        _mkcol(path)
        r = _propfind(path, depth="0")
        assert r.status_code == 207

    def test_propfind_missing_resource_404(self):
        r = _propfind(f"/{_PFX}no_such_{_uid()}", depth="0")
        assert r.status_code == 404

    def test_propfind_response_is_valid_xml(self):
        path, _, _ = _existing_file()
        r = _propfind(path, depth="0")
        assert r.status_code == 207
        ET.fromstring(r.content)  # must not raise

    def test_propfind_depth1_lists_children(self):
        path = f"/{_PFX}lst_{_uid()}"
        _mkcol(path)
        fname = f"child_{_uid()}.txt"
        _put(f"{path}/{fname}", b"child content")
        r = _propfind(path, depth="1")
        assert r.status_code == 207
        assert fname in r.text

    def test_propfind_depth0_does_not_list_children(self):
        path = f"/{_PFX}d0_{_uid()}"
        _mkcol(path)
        fname = f"child_{_uid()}.txt"
        _put(f"{path}/{fname}", b"child")
        r = _propfind(path, depth="0")
        assert r.status_code == 207
        assert fname not in r.text

    def test_propfind_includes_content_length(self):
        path, content, _ = _existing_file()
        r = _propfind(path, depth="0")
        assert r.status_code == 207
        assert str(len(content)) in r.text

    def test_propfind_no_depth_header_does_not_crash(self):
        path, _, _ = _existing_file()
        headers = {"Content-Type": "application/xml"}
        body = '<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>'
        r = requests.request(
            "PROPFIND", _url(path), data=body, headers=headers, timeout=10
        )
        assert r.status_code == 207


# ---------------------------------------------------------------------------
# PROPPATCH / dead properties
# ---------------------------------------------------------------------------


class TestProppatch:
    def test_proppatch_dead_property_persists_in_propfind(self):
        path, _, _ = _existing_file()
        body = (
            '<?xml version="1.0"?>'
            '<D:propertyupdate xmlns:D="DAV:" xmlns:X="urn:nginx-xrootd:test">'
            '<D:set><D:prop><X:analysis>beam-spot</X:analysis></D:prop></D:set>'
            '</D:propertyupdate>'
        )
        r = _proppatch(path, body)
        assert r.status_code == 207
        assert "HTTP/1.1 200 OK" in r.text

        prop_body = (
            '<?xml version="1.0"?>'
            '<D:propfind xmlns:D="DAV:" xmlns:X="urn:nginx-xrootd:test">'
            '<D:prop><X:analysis/></D:prop>'
            '</D:propfind>'
        )
        r = _propfind(path, depth="0", body=prop_body)
        assert r.status_code == 207
        assert "beam-spot" in r.text
        ET.fromstring(r.text)

    def test_proppatch_invalid_xml_400(self):
        path, _, _ = _existing_file()
        r = _proppatch(path, "<D:propertyupdate>")
        assert r.status_code == 400

    def test_proppatch_protected_live_property_has_403_propstat(self):
        path, content, _ = _existing_file()
        body = (
            '<?xml version="1.0"?>'
            '<D:propertyupdate xmlns:D="DAV:">'
            '<D:set><D:prop><D:getcontentlength>1</D:getcontentlength></D:prop></D:set>'
            '</D:propertyupdate>'
        )
        r = _proppatch(path, body)
        assert r.status_code == 207
        assert "HTTP/1.1 403 Forbidden" in r.text

        r = _propfind(path, depth="0")
        assert r.status_code == 207
        assert f"<D:getcontentlength>{len(content)}</D:getcontentlength>" in r.text


# ---------------------------------------------------------------------------
# SEARCH / ACL
# ---------------------------------------------------------------------------


class TestSearchAndAcl:
    def test_options_advertises_search_and_acl_discovery(self):
        r = requests.options(_url("/"), timeout=10)
        assert r.status_code == 200
        assert "SEARCH" in r.headers.get("Allow", "")
        assert "ACL" in r.headers.get("Allow", "")
        assert "basicsearch" in r.headers.get("DASL", "")

    def test_search_basic_depth1_finds_child(self):
        parent = f"/{_PFX}search_{_uid()}"
        _mkcol(parent)
        _put(f"{parent}/needle.txt", b"needle")
        body = (
            '<?xml version="1.0"?>'
            '<D:searchrequest xmlns:D="DAV:">'
            '<D:basicsearch>'
            '<D:select><D:prop><D:displayname/></D:prop></D:select>'
            '<D:from><D:scope>'
            f'<D:href>{parent}</D:href><D:depth>1</D:depth>'
            '</D:scope></D:from>'
            '<D:where><D:contains><D:prop><D:displayname/></D:prop>'
            '<D:literal>needle</D:literal></D:contains></D:where>'
            '</D:basicsearch>'
            '</D:searchrequest>'
        )
        r = _search(parent, body)
        assert r.status_code == 207
        assert f"{parent}/needle.txt" in r.text
        ET.fromstring(r.text)

    def test_search_invalid_xml_400(self):
        r = _search("/", "<D:searchrequest>")
        assert r.status_code == 400

    def test_propfind_acl_privileges_are_discoverable(self):
        path, _, _ = _existing_file()
        body = (
            '<?xml version="1.0"?>'
            '<D:propfind xmlns:D="DAV:">'
            '<D:prop><D:current-user-privilege-set/><D:acl/></D:prop>'
            '</D:propfind>'
        )
        r = _propfind(path, depth="0", body=body)
        assert r.status_code == 207
        assert "<D:current-user-privilege-set>" in r.text
        assert "<D:acl>" in r.text
        ET.fromstring(r.text)

    def test_acl_method_is_protected_403(self):
        path, _, _ = _existing_file()
        body = (
            '<?xml version="1.0"?>'
            '<D:acl xmlns:D="DAV:"><D:ace><D:principal><D:all/></D:principal>'
            '<D:grant><D:privilege><D:write/></D:privilege></D:grant>'
            '</D:ace></D:acl>'
        )
        r = requests.request("ACL", _url(path), data=body, timeout=10)
        assert r.status_code == 403
        assert "cannot-modify-protected-property" in r.text


# ---------------------------------------------------------------------------
# MOVE
# ---------------------------------------------------------------------------


class TestMove:
    """RFC 4918 §9.9 — MOVE is implemented."""

    def test_move_new_destination_201(self):
        src, content, _ = _existing_file()
        dst = f"/{_PFX}moved_{_uid()}.txt"
        r = _move(src, dst)
        assert r.status_code == 201
        assert _get(dst).content == content

    def test_move_overwrite_existing_204(self):
        src, content, _ = _existing_file()
        dst, _, _ = _existing_file()
        r = _move(src, dst)
        assert r.status_code == 204
        assert _get(dst).content == content

    def test_move_source_gone_after_move(self):
        src, _, _ = _existing_file()
        dst = f"/{_PFX}moved_{_uid()}.txt"
        _move(src, dst)
        assert _get(src).status_code == 404

    def test_move_missing_source_404(self):
        r = _move(f"/{_PFX}no_{_uid()}.txt", f"/{_PFX}dst_{_uid()}.txt")
        assert r.status_code == 404

    def test_move_overwrite_false_destination_exists_412(self):
        src, _, _ = _existing_file()
        dst, _, _ = _existing_file()
        r = _move(src, dst, overwrite="F")
        assert r.status_code == 412

    def test_move_overwrite_false_new_destination_201(self):
        src, content, _ = _existing_file()
        dst = f"/{_PFX}moved_{_uid()}.txt"
        r = _move(src, dst, overwrite="F")
        assert r.status_code == 201

    def test_move_in_allow_header(self):
        r = requests.options(_url("/"), timeout=10)
        allow = r.headers.get("Allow", "")
        assert "MOVE" in allow

    def test_move_no_destination_header_400(self):
        src, _, _ = _existing_file()
        r = requests.request("MOVE", _url(src), timeout=10)
        assert r.status_code == 400

    def test_move_directory_overwrite_204(self):
        src = f"/{_PFX}dir_src_{_uid()}"
        _mkcol(src)
        _put(f"{src}/file.txt", b"content")

        dst = f"/{_PFX}dir_dst_{_uid()}"
        _mkcol(dst)
        _put(f"{dst}/old.txt", b"old")

        r = _move(src, dst)
        assert r.status_code == 204
        assert _get(f"{dst}/file.txt").content == b"content"
        assert _get(f"{dst}/old.txt").status_code == 404
        assert _propfind(src).status_code == 404

    def test_move_directory_offloads_to_thread_pool(self):
        src = f"/{_PFX}dir_src_async_{_uid()}"
        _mkcol(src)
        _put(f"{src}/file.txt", b"content")

        dst = f"/{_PFX}dir_dst_async_{_uid()}"
        start = _error_log_size()
        r = _move(src, dst)

        assert r.status_code == 201
        assert _get(f"{dst}/file.txt").content == b"content"
        assert _propfind(src).status_code == 404
        _assert_error_log_contains_since(
            start, "offloaded collection MOVE to thread pool"
        )


# ---------------------------------------------------------------------------
# COPY
# ---------------------------------------------------------------------------


class TestCopy:
    """RFC 4918 §9.8 — server-side COPY."""

    def test_copy_new_destination_201(self):
        src, content, _ = _existing_file()
        dst = f"/{_PFX}copied_{_uid()}.txt"
        r = _copy(src, dst)
        assert r.status_code == 201
        assert _get(dst).content == content

    def test_copy_source_preserved(self):
        src, content, _ = _existing_file()
        dst = f"/{_PFX}copied_{_uid()}.txt"
        _copy(src, dst)
        assert _get(src).content == content

    def test_copy_overwrite_existing_204(self):
        src, content, _ = _existing_file()
        dst, _, _ = _existing_file()
        r = _copy(src, dst)
        assert r.status_code == 204
        assert _get(dst).content == content

    def test_copy_overwrite_false_destination_exists_412(self):
        src, _, _ = _existing_file()
        dst, _, _ = _existing_file()
        r = _copy(src, dst, overwrite="F")
        assert r.status_code == 412

    def test_copy_overwrite_false_new_destination_201(self):
        src, content, _ = _existing_file()
        dst = f"/{_PFX}copied_{_uid()}.txt"
        r = _copy(src, dst, overwrite="F")
        assert r.status_code == 201
        assert _get(dst).content == content

    def test_copy_missing_source_404(self):
        r = _copy(f"/{_PFX}no_{_uid()}.txt", f"/{_PFX}dst_{_uid()}.txt")
        assert r.status_code == 404

    def test_copy_in_allow_header(self):
        r = requests.options(_url("/"), timeout=10)
        allow = r.headers.get("Allow", "")
        assert "COPY" in allow

    def test_copy_no_destination_header_400(self):
        src, _, _ = _existing_file()
        r = requests.request("COPY", _url(src), timeout=10)
        assert r.status_code == 400

    def test_copy_large_file_content_correct(self):
        path = f"/{_PFX}bigcopy_{_uid()}.bin"
        content = bytes(range(256)) * 1000  # 256 KB
        _put(path, content)
        dst = f"/{_PFX}bigcopy_dst_{_uid()}.bin"
        r = _copy(path, dst)
        assert r.status_code == 201
        assert _get(dst).content == content

    def test_copy_directory_recursive_201(self):
        parent = f"/{_PFX}dir_{_uid()}"
        _mkcol(parent)
        _put(f"{parent}/file1.txt", b"content1")
        _put(f"{parent}/file2.txt", b"content2")
        _mkcol(f"{parent}/subdir")
        _put(f"{parent}/subdir/file3.txt", b"content3")

        dst = f"/{_PFX}dir_dst_{_uid()}"
        r = _copy(parent, dst)
        assert r.status_code == 201
        assert _get(f"{dst}/file1.txt").content == b"content1"
        assert _get(f"{dst}/file2.txt").content == b"content2"
        assert _get(f"{dst}/subdir/file3.txt").content == b"content3"

    def test_copy_directory_recursive_offloads_to_thread_pool(self):
        parent = f"/{_PFX}dir_async_{_uid()}"
        _mkcol(parent)
        _put(f"{parent}/file1.txt", b"content1")
        _mkcol(f"{parent}/subdir")
        _put(f"{parent}/subdir/file2.txt", b"content2")

        dst = f"/{_PFX}dir_async_dst_{_uid()}"
        start = _error_log_size()
        r = _copy(parent, dst)

        assert r.status_code == 201
        assert _get(f"{dst}/file1.txt").content == b"content1"
        assert _get(f"{dst}/subdir/file2.txt").content == b"content2"
        _assert_error_log_contains_since(
            start, "offloaded collection COPY to thread pool"
        )

    def test_copy_directory_depth_0_201(self):
        parent = f"/{_PFX}dir_{_uid()}"
        _mkcol(parent)
        _put(f"{parent}/file1.txt", b"content1")
        dst = f"/{_PFX}dir_dst_{_uid()}"
        r = _copy(parent, dst, depth="0")
        assert r.status_code == 201
        # Check that the directory was created but its contents were not copied
        assert _propfind(dst).status_code == 207
        assert _get(f"{dst}/file1.txt").status_code == 404

    def test_copy_directory_overwrite_204(self):
        src = f"/{_PFX}dir_src_{_uid()}"
        _mkcol(src)
        _put(f"{src}/new.txt", b"new")

        dst = f"/{_PFX}dir_dst_{_uid()}"
        _mkcol(dst)
        _put(f"{dst}/old.txt", b"old")

        # COPY src to dst with Overwrite: T (default)
        r = _copy(src, dst)
        assert r.status_code == 204
        assert _get(f"{dst}/new.txt").content == b"new"
        # The old content should be gone (collection replaced)
        assert _get(f"{dst}/old.txt").status_code == 404

    def test_copy_directory_overwrite_false_412(self):
        src = f"/{_PFX}dir_src_{_uid()}"
        _mkcol(src)
        dst = f"/{_PFX}dir_dst_{_uid()}"
        _mkcol(dst)

        r = _copy(src, dst, overwrite="F")
        assert r.status_code == 412

# ---------------------------------------------------------------------------
# LOCK / UNLOCK
# ---------------------------------------------------------------------------


class TestLock:
    def test_lock_new_file_201(self):
        path = f"/{_PFX}lock_{_uid()}.txt"
        r = _lock(path)
        assert r.status_code == 201
        assert "Lock-Token" in r.headers
        token = r.headers["Lock-Token"].strip("<>")
        assert "opaquelocktoken:" in token

        # Verify it shows up in PROPFIND
        r = _propfind(path)
        assert r.status_code == 207
        assert token in r.text
        assert "<D:lockdiscovery>" in r.text
        assert "<D:supportedlock>" in r.text

    def test_lock_refresh_200(self):
        path = f"/{_PFX}refresh_{_uid()}.txt"
        r = _lock(path)
        token = r.headers["Lock-Token"]

        # Refresh using If header
        headers = {"If": f"({token})"}
        r = _lock(path, headers=headers, data="")
        assert r.status_code == 200

    def test_lock_enforcement_put_423(self):
        path = f"/{_PFX}locked_put_{_uid()}.txt"
        r = _lock(path)
        token = r.headers["Lock-Token"]

        # PUT without lock token should fail
        r = _put(path, b"failed content")
        assert r.status_code == 423

        # PUT with lock token (in If header) should succeed
        headers = {"If": f"({token})"}
        r = _put(path, b"success content", headers=headers)
        assert r.status_code in (201, 204)
        assert _get(path).content == b"success content"

    def test_lock_enforcement_delete_423(self):
        path = f"/{_PFX}locked_del_{_uid()}.txt"
        _put(path, b"content")
        r_lock = _lock(path)
        token = r_lock.headers["Lock-Token"]

        r = _delete(path)
        assert r.status_code == 423

        headers = {"If": f"({token})"}
        r = _delete(path, headers=headers)
        assert r.status_code == 204

    def test_unlock_204(self):
        path = f"/{_PFX}to_unlock_{_uid()}.txt"
        r = _lock(path)
        token = r.headers["Lock-Token"]

        r = _unlock(path, token)
        assert r.status_code == 204

        # Verify PUT now succeeds without token
        r = _put(path, b"after unlock")
        assert r.status_code in (201, 204)

    def test_lock_conflict_423(self):
        path = f"/{_PFX}conflict_{_uid()}.txt"
        _lock(path)

        # Second lock attempt from "someone else" (no If header)
        r = _lock(path)
        assert r.status_code == 423

    def test_lock_expiration(self):
        path = f"/{_PFX}expires_{_uid()}.txt"
        # 1 second timeout
        r = _lock(path, timeout=1)
        assert r.status_code == 201

        # Immediately should fail
        assert _put(path, b"too soon").status_code == 423

        # Wait for expiration
        time.sleep(2)

        # Should now succeed
        assert _put(path, b"expired").status_code in (201, 204)
