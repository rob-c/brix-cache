from split_continuation import reexport as _reexport
_reexport(globals(), "_test_webdav_helpers")

class TestPropfind:

    def _propfind(self, path: str, depth: str) -> ET.Element:
        """Run a PROPFIND and return the parsed XML root element."""
        rc, out, err = _curl(
            "-X", "PROPFIND",
            "-H", f"Depth: {depth}",
            f"{BASE_URL}{path}",
        )
        assert rc == 0, f"curl failed: {err.decode()}"
        try:
            return ET.fromstring(out)
        except ET.ParseError as exc:
            pytest.fail(
                f"PROPFIND response is not valid XML: {exc}\nBody:\n{out.decode()}"
            )

    def test_propfind_depth0_returns_207(self, scratch_file):
        url_path, _ = scratch_file
        code = _http_code(
            "-X", "PROPFIND", "-H", "Depth: 0",
            f"{BASE_URL}{url_path}",
        )
        assert code == 207

    def test_propfind_depth0_file_has_content_length(self, scratch_file):
        url_path, content = scratch_file
        root = self._propfind(url_path, "0")
        # Find D:getcontentlength anywhere in the multistatus tree
        ns = {"D": "DAV:"}
        cl_els = root.findall(".//D:getcontentlength", ns)
        assert cl_els, "D:getcontentlength missing from PROPFIND Depth:0 response"
        assert int(cl_els[0].text) == len(content), (
            f"getcontentlength {cl_els[0].text} != {len(content)}"
        )

    def test_propfind_depth0_directory(self):
        """PROPFIND Depth:0 on a directory should return a collection resourcetype."""
        name = f"{_PFX}propfind_dir"
        dst  = _data_path(name)
        os.makedirs(dst, exist_ok=True)
        try:
            root = self._propfind(f"/{name}", "0")
            ns = {"D": "DAV:"}
            coll = root.findall(".//D:collection", ns)
            assert coll, (
                "D:collection missing from PROPFIND Depth:0 response for a directory"
            )
        finally:
            shutil.rmtree(dst)

    def test_propfind_depth1_lists_children(self, scratch_file):
        url_path, _ = scratch_file
        filename = os.path.basename(url_path)
        # PROPFIND Depth:1 on root should include our scratch file
        root = self._propfind("/", "1")
        ns = {"D": "DAV:"}
        hrefs = [el.text for el in root.findall(".//D:href", ns)]
        assert any(filename in (h or "") for h in hrefs), (
            f"{filename!r} not found in PROPFIND Depth:1 href list:\n{hrefs}"
        )

    def test_propfind_depth1_returns_207(self):
        code = _http_code(
            "-X", "PROPFIND", "-H", "Depth: 1",
            f"{BASE_URL}/",
        )
        assert code == 207

    def test_propfind_missing_returns_404(self):
        code = _http_code(
            "-X", "PROPFIND", "-H", "Depth: 0",
            f"{BASE_URL}/{_PFX}no_such_propfind.txt",
        )
        assert code == 404

    def test_propfind_depth0_has_lastmodified(self, scratch_file):
        url_path, _ = scratch_file
        root = self._propfind(url_path, "0")
        ns = {"D": "DAV:"}
        lm = root.findall(".//D:getlastmodified", ns)
        assert lm, "D:getlastmodified missing from PROPFIND Depth:0 response"

    def test_propfind_depth1_escapes_xml_metacharacters_in_href(self):
        """Hostile filenames must not break PROPFIND XML output."""
        name = f"{_PFX}xml_&_<>.txt"
        dst = _data_path(name)
        with open(dst, "wb") as fh:
            fh.write(b"xml escape\n")

        try:
            root = self._propfind("/", "1")
            ns = {"D": "DAV:"}
            hrefs = [el.text for el in root.findall(".//D:href", ns)]
            assert f"/{name}" in hrefs, hrefs
        finally:
            if os.path.exists(dst):
                os.unlink(dst)


# ---------------------------------------------------------------------------
# PROPFIND body parsing (RFC 4918 §9.1): allprop / propname / prop
# ---------------------------------------------------------------------------

class TestPropfindBody:
    """Test PROPFIND request body parsing via libxml2."""

    DAV_NS = "DAV:"
    NS = {"D": "DAV:"}

    def _propfind_body(self, path: str, depth: str, body: bytes) -> ET.Element:
        """Run a PROPFIND with an explicit XML body; return parsed XML root."""
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as f:
            f.write(body)
            tmp = f.name
        try:
            rc, out, err = _curl(
                "-X", "PROPFIND",
                "-H", f"Depth: {depth}",
                "-H", "Content-Type: application/xml; charset=utf-8",
                "--data-binary", f"@{tmp}",
                f"{BASE_URL}{path}",
            )
            assert rc == 0, f"curl failed: {err.decode()}"
            try:
                return ET.fromstring(out)
            except ET.ParseError as exc:
                pytest.fail(
                    f"PROPFIND response is not valid XML: {exc}\nBody:\n{out.decode()}"
                )
        finally:
            os.unlink(tmp)

    def _propfind_body_code(self, path: str, depth: str, body: bytes) -> int:
        """Return HTTP status code for a PROPFIND with a body."""
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as f:
            f.write(body)
            tmp = f.name
        try:
            return _http_code(
                "-X", "PROPFIND",
                "-H", f"Depth: {depth}",
                "-H", "Content-Type: application/xml; charset=utf-8",
                "--data-binary", f"@{tmp}",
            )
        finally:
            os.unlink(tmp)

    # --- allprop body ---

    def test_propfind_allprop_body_returns_207(self, scratch_file):
        """Explicit <allprop/> body must produce the same 207 as a no-body request."""
        url_path, _ = scratch_file
        body = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b'<D:propfind xmlns:D="DAV:">'
            b'  <D:allprop/>'
            b'</D:propfind>'
        )
        root = self._propfind_body(url_path, "0", body)
        ns = self.NS
        assert root.findall(".//D:getcontentlength", ns), \
            "allprop body: expected D:getcontentlength in response"

    def test_propfind_allprop_includes_etag(self, scratch_file):
        """allprop response must include D:getetag."""
        url_path, _ = scratch_file
        body = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b'<D:propfind xmlns:D="DAV:">'
            b'  <D:allprop/>'
            b'</D:propfind>'
        )
        root = self._propfind_body(url_path, "0", body)
        assert root.findall(".//D:getetag", self.NS), \
            "allprop body: expected D:getetag in response"

    # --- propname body ---

    def test_propfind_propname_returns_207(self, scratch_file):
        """<propname/> body must return 207 Multi-Status."""
        url_path, _ = scratch_file
        body = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b'<D:propfind xmlns:D="DAV:">'
            b'  <D:propname/>'
            b'</D:propfind>'
        )
        root = self._propfind_body(url_path, "0", body)
        ns = self.NS
        props = root.findall(".//D:prop", ns)
        assert props, "propname: expected D:prop element in response"

    def test_propfind_propname_names_only_no_values(self, scratch_file):
        """propname response must have empty property elements (names, no values)."""
        url_path, _ = scratch_file
        body = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b'<D:propfind xmlns:D="DAV:">'
            b'  <D:propname/>'
            b'</D:propfind>'
        )
        root = self._propfind_body(url_path, "0", body)
        ns = self.NS
        # getcontentlength must appear as a name (empty tag)
        cl_els = root.findall(".//D:getcontentlength", ns)
        assert cl_els, "propname: expected D:getcontentlength name element"
        # but it must have no text value
        assert cl_els[0].text is None or cl_els[0].text.strip() == "", \
            f"propname: D:getcontentlength must be empty, got {cl_els[0].text!r}"

    def test_propfind_propname_contains_known_property_names(self, scratch_file):
        """propname must include all standard DAV: property names."""
        url_path, _ = scratch_file
        body = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b'<D:propfind xmlns:D="DAV:">'
            b'  <D:propname/>'
            b'</D:propfind>'
        )
        root = self._propfind_body(url_path, "0", body)
        ns = self.NS
        expected = [
            "D:resourcetype",
            "D:getcontentlength",
            "D:getlastmodified",
            "D:getetag",
        ]
        for tag in expected:
            assert root.findall(f".//{tag}", ns), \
                f"propname: missing {tag} in property names list"

    # --- prop body (specific properties) ---

    def test_propfind_prop_returns_requested_property(self, scratch_file):
        """<prop> body requesting getcontentlength must return that property."""
        url_path, content = scratch_file
        body = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b'<D:propfind xmlns:D="DAV:">'
            b'  <D:prop>'
            b'    <D:getcontentlength/>'
            b'  </D:prop>'
            b'</D:propfind>'
        )
        root = self._propfind_body(url_path, "0", body)
        ns = self.NS
        cl_els = root.findall(".//D:getcontentlength", ns)
        assert cl_els, "prop: expected D:getcontentlength in response"
        assert int(cl_els[0].text) == len(content), \
            f"prop: getcontentlength {cl_els[0].text!r} != {len(content)}"

    def test_propfind_prop_multiple_properties(self, scratch_file):
        """<prop> body requesting multiple properties must return all of them."""
        url_path, _ = scratch_file
        body = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b'<D:propfind xmlns:D="DAV:">'
            b'  <D:prop>'
            b'    <D:getcontentlength/>'
            b'    <D:getlastmodified/>'
            b'    <D:getetag/>'
            b'    <D:resourcetype/>'
            b'  </D:prop>'
            b'</D:propfind>'
        )
        root = self._propfind_body(url_path, "0", body)
        ns = self.NS
        for tag in ["D:getcontentlength", "D:getlastmodified", "D:getetag", "D:resourcetype"]:
            assert root.findall(f".//{tag}", ns), \
                f"prop: missing {tag} in response"

    def test_propfind_prop_unknown_property_in_404_propstat(self, scratch_file):
        """Unknown properties must appear in a 404 propstat, not be silently dropped."""
        url_path, _ = scratch_file
        body = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b'<D:propfind xmlns:D="DAV:">'
            b'  <D:prop>'
            b'    <D:getcontentlength/>'
            b'    <D:no-such-prop/>'
            b'  </D:prop>'
            b'</D:propfind>'
        )
        root = self._propfind_body(url_path, "0", body)
        ns = self.NS

        # Find propstat elements; one should have 200, one should have 404
        propstats = root.findall(".//D:propstat", ns)
        statuses = [ps.findtext("D:status", namespaces=ns) for ps in propstats]
        assert any("404" in (s or "") for s in statuses), \
            f"prop: unknown property not in 404 propstat; statuses={statuses}"

        # The 404 propstat should contain D:no-such-prop
        for ps in propstats:
            status = ps.findtext("D:status", namespaces=ns) or ""
            if "404" in status:
                props = ps.findall(".//D:prop/*", ns)
                names = [p.tag.split("}")[-1] if "}" in p.tag else p.tag for p in props]
                assert "no-such-prop" in names, \
                    f"prop: D:no-such-prop not found in 404 propstat; names={names}"

    def test_propfind_prop_only_unknown_gives_404_propstat(self, scratch_file):
        """Requesting only unknown properties must still produce a 207 with 404 propstat."""
        url_path, _ = scratch_file
        body = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b'<D:propfind xmlns:D="DAV:">'
            b'  <D:prop>'
            b'    <D:no-such-prop-a/>'
            b'    <D:no-such-prop-b/>'
            b'  </D:prop>'
            b'</D:propfind>'
        )
        root = self._propfind_body(url_path, "0", body)
        ns = self.NS
        propstats = root.findall(".//D:propstat", ns)
        statuses = [ps.findtext("D:status", namespaces=ns) for ps in propstats]
        assert any("404" in (s or "") for s in statuses), \
            f"prop: all-unknown should yield 404 propstat; statuses={statuses}"

    def test_propfind_prop_no_body_defaults_to_allprop(self, scratch_file):
        """No body must still return all known properties (backward compat)."""
        url_path, content = scratch_file
        rc, out, err = _curl(
            "-X", "PROPFIND",
            "-H", "Depth: 0",
            f"{BASE_URL}{url_path}",
        )
        assert rc == 0
        root = ET.fromstring(out)
        ns = self.NS
        cl_els = root.findall(".//D:getcontentlength", ns)
        assert cl_els, "no-body PROPFIND: expected D:getcontentlength"
        assert int(cl_els[0].text) == len(content)


# ---------------------------------------------------------------------------
# Authentication behaviour
# ---------------------------------------------------------------------------
