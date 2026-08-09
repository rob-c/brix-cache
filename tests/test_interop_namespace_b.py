from split_continuation import reexport as _reexport
_reexport(globals(), "_test_interop_namespace_helpers")

class TestFattrConformance:
    """
    kXR_fattr: Get / Set / List / Del suboperations.
    Both servers should agree on attribute presence after nginx-xrootd writes.
    """

    def _seed_file(self):
        name    = f"_fattr_{os.getpid()}_{id(self)}.bin"
        content = os.urandom(256)
        with open(os.path.join(DATA_DIR, name), "wb") as fh:
            fh.write(content)
        return f"/{name}", name

    def _open_file(self, url, path, flags=OpenFlags.READ):
        f = client.File()
        st, _ = f.open(_url(url, path), flags)
        return f, st

    def _set_attrs(self, path, attrs):
        st, _ = _fs(NGINX_URL).set_xattr(path, attrs)
        return st

    def _get_attrs(self, path, names):
        st, attrs = _fs(NGINX_URL).get_xattr(path, names)
        return st, self._attr_map(attrs)

    def _list_attrs(self, path):
        st, attrs = _fs(NGINX_URL).list_xattr(path)
        return st, self._attr_map(attrs)

    def _del_attrs(self, path, names):
        st, _ = _fs(NGINX_URL).del_xattr(path, names)
        return st

    def _attr_map(self, attrs):
        result = {}
        for attr in attrs or []:
            if hasattr(attr, "name"):
                result[attr.name] = getattr(attr, "value", None)
            elif isinstance(attr, tuple) and len(attr) >= 2:
                result[attr[0]] = attr[1]
        return result

    def test_fattr_set_and_get_roundtrip(self):
        xrd_path, name = self._seed_file()
        try:
            set_st = self._set_attrs(xrd_path, [("testkey", "testvalue")])
            assert set_st.ok, f"set_xattr failed: {set_st.message}"

            get_st, attrs = self._get_attrs(xrd_path, ["testkey"])
            assert get_st.ok, f"get_xattr failed: {get_st.message}"
            assert attrs.get("testkey") == "testvalue", \
                f"xattr value mismatch: got {attrs!r}"
        finally:
            _fs(NGINX_URL).rm(xrd_path)

    def test_fattr_list_includes_set_attr(self):
        xrd_path, name = self._seed_file()
        try:
            set_st = self._set_attrs(xrd_path, [("listkey", "listval")])
            assert set_st.ok, f"set_xattr failed: {set_st.message}"

            list_st, attrs = self._list_attrs(xrd_path)
            assert list_st.ok, f"list_xattr failed: {list_st.message}"
            names = set(attrs)
            assert "listkey" in names or "U.listkey" in names, \
                f"'listkey' not in fattr list: {names}"
        finally:
            _fs(NGINX_URL).rm(xrd_path)

    def test_fattr_delete_removes_attr(self):
        xrd_path, name = self._seed_file()
        try:
            set_st = self._set_attrs(xrd_path, [("delkey", "delval")])
            assert set_st.ok, f"set_xattr failed: {set_st.message}"

            del_st = self._del_attrs(xrd_path, ["delkey"])
            assert del_st.ok, f"del_xattr failed: {del_st.message}"

            get_st, attrs = self._get_attrs(xrd_path, ["delkey"])
            assert not get_st.ok or attrs.get("delkey") in (None, ""), \
                f"get_xattr after del should fail or return empty: {attrs!r}"
        finally:
            _fs(NGINX_URL).rm(xrd_path)

    def test_fattr_multiple_attrs_independent(self):
        xrd_path, name = self._seed_file()
        try:
            set_st = self._set_attrs(xrd_path, [("key1", "val1"),
                                                ("key2", "val2")])
            assert set_st.ok, f"set_xattr failed: {set_st.message}"

            get_st, attrs = self._get_attrs(xrd_path, ["key1", "key2"])
            assert get_st.ok, f"get_xattr failed: {get_st.message}"
            assert attrs.get("key1") == "val1"
            assert attrs.get("key2") == "val2"
        finally:
            _fs(NGINX_URL).rm(xrd_path)

    def test_fattr_visible_from_ref_filesystem(self):
        """xattr written via nginx-xrootd must be visible as a Linux xattr."""
        xrd_path, name = self._seed_file()
        fs_path = os.path.join(DATA_DIR, name)
        try:
            set_st = self._set_attrs(xrd_path, [("diskkey", "diskval")])
            assert set_st.ok, f"set_xattr failed: {set_st.message}"

            raw = os.getxattr(fs_path, "user.U.diskkey")
            assert raw == b"diskval", \
                f"xattr on disk: {raw!r}"
        finally:
            try:
                _fs(NGINX_URL).rm(xrd_path)
            except Exception:
                pass
