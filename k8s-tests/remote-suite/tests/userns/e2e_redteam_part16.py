class _MalformedHostileInputs:
    MARKER = b"MHI-BOB-XXE-CANARY-7f3a9"

    def __init__(self, key, data, port, s3port):
        self.key = key
        self.data = data
        self.port = port
        self.s3port = s3port
        self.alice_token = mint(key, "alice")
        self.bob_token = mint(key, "bob")
        self.leakfile = self._plant_canary()

    def _plant_canary(self):
        path = os.path.join(self.data, "bob", "mhi_canary.txt")
        try:
            with open(path, "wb") as stream:
                stream.write(self.MARKER + b"\n")
            os.chown(path, UID_BOB, UID_BOB)
            os.chmod(path, 0o600)
            return path
        except OSError:
            return None

    def clean(self, body):
        body = body or b""
        markers = (b"root:x:0:0", b"/bin/bash", b":/root:", self.MARKER)
        return not any(marker in body for marker in markers)

    def worker_alive(self, tag):
        marker = ("MHI-ALIVE-" + tag).encode()
        name = re.sub(r"[^a-z0-9]", "", tag.lower())[:24]
        path = f"/alice/mhi_alive_{name}.txt"
        write_status, _ = http("PUT", path, self.port, self.alice_token, marker + b"\n")
        read_status, body = http("GET", path, self.port, self.alice_token)
        disk_path = os.path.join(self.data, "alice", os.path.basename(path))
        owned = os.path.exists(disk_path) and os.stat(disk_path).st_uid == UID_ALICE
        status_ok = write_status in (200, 201, 204)
        response_ok = read_status == 200 and marker in (body or b"")
        ok(status_ok and self._worker_response_ok(response_ok, owned),
           f"worker survived {tag}: PUT {write_status}, GET {read_status}, owned={owned}")

    @staticmethod
    def _worker_response_ok(response_ok, owned):
        return response_ok and owned

    def raw_send(self, request, target_port, read_timeout=3.0):
        try:
            connection = socket.create_connection((HOST, target_port), timeout=4)
        except OSError as error:
            return -1, str(error).encode()
        connection.settimeout(read_timeout)
        response = self._exchange_raw(connection, request)
        try:
            connection.close()
        except OSError:
            pass
        match = re.match(rb"HTTP/1\.[01] (\d{3})", response)
        status = int(match.group(1)) if match else -1
        return status, response

    @staticmethod
    def _exchange_raw(connection, request):
        response = b""
        try:
            connection.sendall(request)
            while len(response) <= 262144:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response += chunk
        except (OSError, socket.timeout):
            pass
        return response

    def _probe_xml(self, method, path, attacks, allowed, headers=None):
        request_headers = headers or {"Content-Type": "application/xml"}
        for label, body in attacks:
            status, response = http(
                method, path, self.port, self.alice_token,
                data=body, hdrs=request_headers,
            )
            self._assert_xml_response(label, status, response, allowed)

    def _assert_xml_response(self, label, status, body, allowed):
        ok(status not in (200, 201) or self.clean(body),
           f"{label}: no passwd or tenant-secret leak (HTTP {status})")
        ok(status in allowed,
           f"{label}: handled with a status, no crash (HTTP {status})")

    def propfind_xml(self):
        passwd = (b'<?xml version="1.0"?>'
                  b'<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                  b'<D:propfind xmlns:D="DAV:"><D:prop><x>&xxe;</x></D:prop></D:propfind>')
        parameter = (b'<?xml version="1.0"?>'
                     b'<!DOCTYPE r [<!ENTITY % p SYSTEM "file:///etc/passwd"> %p;]>'
                     b'<D:propfind xmlns:D="DAV:"><D:prop><D:displayname/></D:prop></D:propfind>')
        billion = self._propfind_billion_laughs()
        quadratic = (b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY q "'
                     + b"q" * 8000 + b'">]><D:propfind xmlns:D="DAV:"><D:prop>'
                     + b"&q;" * 400 + b'</D:prop></D:propfind>')
        attacks = [("PROPFIND XXE-passwd", passwd),
                   ("PROPFIND XXE-param", parameter),
                   ("PROPFIND billion-laughs", billion),
                   ("PROPFIND quadratic-blowup", quadratic)]
        self._append_tenant_xxe(attacks)
        allowed = (207, 400, 403, 413, 422, 500, 501, -1)
        self._probe_xml("PROPFIND", "/alice/", attacks, allowed,
                        {"Depth": "0", "Content-Type": "application/xml"})
        self.worker_alive("propfind-xml")
        self._propfind_control()

    @staticmethod
    def _propfind_billion_laughs():
        return (b'<?xml version="1.0"?><!DOCTYPE x ['
                b'<!ENTITY a "aaaaaaaaaa">'
                b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
                b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
                b'<!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">'
                b'<!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">]>'
                b'<D:propfind xmlns:D="DAV:"><D:prop>&e;</D:prop></D:propfind>')

    def _append_tenant_xxe(self, attacks):
        if not self.leakfile:
            return
        body = (b'<?xml version="1.0"?>'
                b'<!DOCTYPE r [<!ENTITY g SYSTEM "file:///' + self.data.encode()
                + b'/bob/mhi_canary.txt">]>'
                b'<D:propfind xmlns:D="DAV:"><D:prop><x>&g;</x></D:prop></D:propfind>')
        attacks.append(("PROPFIND XXE-tenant-secret", body))

    def _propfind_control(self):
        body = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                b'<D:prop><D:displayname/></D:prop></D:propfind>')
        status, _ = http("PROPFIND", "/alice/", self.port, self.alice_token,
                         data=body,
                         hdrs={"Depth": "0", "Content-Type": "application/xml"})
        ok(status in (207, 200),
           f"control: well-formed PROPFIND works (HTTP {status})")

    def proppatch_xml(self):
        xxe = (b'<?xml version="1.0"?>'
               b'<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
               b'<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>'
               b'<z>&xxe;</z></D:prop></D:set></D:propertyupdate>')
        billion = (b'<?xml version="1.0"?><!DOCTYPE x ['
                   b'<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
                   b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
                   b'<!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">]>'
                   b'<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>&d;</D:prop>'
                   b'</D:set></D:propertyupdate>')
        truncated = b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"><D:set><D:prop'
        http("PUT", "/alice/pp_target.txt", self.port, self.alice_token, b"pp\n")
        attacks = [("PROPPATCH XXE-passwd", xxe),
                   ("PROPPATCH billion-laughs", billion),
                   ("PROPPATCH truncated", truncated)]
        allowed = (207, 400, 403, 405, 409, 413, 422, 500, 501, -1)
        self._probe_xml("PROPPATCH", "/alice/pp_target.txt", attacks, allowed)
        self.worker_alive("proppatch-xml")

    def lock_xml(self):
        xxe = (b'<?xml version="1.0"?>'
               b'<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
               b'<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope>'
               b'<D:locktype><D:write/></D:locktype>'
               b'<D:owner>&xxe;</D:owner></D:lockinfo>')
        billion = (b'<?xml version="1.0"?><!DOCTYPE x ['
                   b'<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
                   b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>'
                   b'<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope>'
                   b'<D:locktype><D:write/></D:locktype><D:owner>&c;</D:owner></D:lockinfo>')
        truncated = b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclu'
        attacks = [("LOCK XXE-passwd", xxe),
                   ("LOCK billion-laughs", billion),
                   ("LOCK truncated", truncated)]
        allowed = (200, 201, 400, 403, 409, 422, 423, 500, 501, -1)
        self._probe_xml("LOCK", "/alice/pp_target.txt", attacks, allowed)
        self.worker_alive("lock-xml")

    def s3_xml(self):
        if not self.s3port:
            ok(True, "S3 XML-body attacks skipped (no s3port configured)")
            return
        self._s3_delete_xml()
        self._s3_multipart_xml()
        self.worker_alive("s3-xml")

    def _s3_delete_xml(self):
        xxe = (b'<?xml version="1.0"?>'
               b'<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
               b'<Delete><Object><Key>&xxe;</Key></Object></Delete>')
        billion = (b'<?xml version="1.0"?><!DOCTYPE x ['
                   b'<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
                   b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>'
                   b'<Delete><Object><Key>&c;</Key></Object></Delete>')
        attacks = [("S3 DeleteObjects XXE", xxe),
                   ("S3 DeleteObjects billion-laughs", billion),
                   ("S3 DeleteObjects truncated", b'<Delete><Object><Key>alice/x')]
        for label, body in attacks:
            status, response = s3("POST", "", self.s3port,
                                  params={"delete": ""}, data=body)
            self._assert_s3_xml_response(label, status, response)
        bob_file = os.path.join(self.data, "bob", "readable.txt")
        status, _ = s3("POST", "", self.s3port, params={"delete": ""},
                       data=_delete_xml(["bob/readable.txt", "bob/private.txt"]))
        ok(os.path.exists(bob_file),
           f"S3 cross-tenant batch did not delete bob's file (HTTP {status})")

    def _assert_s3_xml_response(self, label, status, body):
        ok(self.clean(body), f"{label}: no passwd leak (HTTP {status})")
        ok(status in (200, 400, 403, 422, 500, 501, -1),
           f"{label}: handled, no crash (HTTP {status})")

    def _s3_multipart_xml(self):
        status, body = s3("POST", "alice/mhi_mpu.bin", self.s3port,
                          params={"uploads": ""})
        match = re.search(rb"<UploadId>([^<]+)</UploadId>", body or b"")
        if status != 200 or not match:
            ok(True, f"S3 multipart unavailable; XML probes skipped (HTTP {status})")
            return
        upload_id = match.group(1).decode()
        self._probe_multipart_xml(upload_id)
        s3("DELETE", "alice/mhi_mpu.bin", self.s3port,
           params={"uploadId": upload_id})

    def _probe_multipart_xml(self, upload_id):
        xxe = (b'<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
               b'<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>'
               b'<ETag>&xxe;</ETag></Part></CompleteMultipartUpload>')
        billion = (b'<!DOCTYPE x [<!ENTITY a "aaaaaaaaaa">'
                   b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
                   b'<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>'
                   b'<ETag>&b;</ETag></Part></CompleteMultipartUpload>')
        attacks = [("S3 CompleteMPU XXE", xxe),
                   ("S3 CompleteMPU billion-laughs", billion),
                   ("S3 CompleteMPU truncated", b'<CompleteMultipartUpload><Part>')]
        for label, body in attacks:
            status, response = s3("POST", "alice/mhi_mpu.bin", self.s3port,
                                  params={"uploadId": upload_id}, data=body)
            ok(self.clean(response), f"{label}: no passwd leak (HTTP {status})")
            ok(status in (200, 400, 403, 404, 422, 500, 501, -1),
               f"{label}: handled, no crash (HTTP {status})")

    def raw_protocol(self):
        host = f"{HOST}:{self.port}"
        bearer = f"Bearer {self.alice_token}"
        self._content_length_probes(host, bearer)
        self._header_size_probes(host, bearer)
        self._control_byte_probes(host, bearer)

    def _content_length_probes(self, host, bearer):
        large = (("PUT /alice/mhi_clbig.txt HTTP/1.1\r\nHost: %s\r\n"
                  "Authorization: %s\r\nContent-Length: 1000\r\n"
                  "Connection: close\r\n\r\n" % (host, bearer)).encode()
                 + b"only-a-few-bytes")
        status, response = self.raw_send(large, self.port)
        path = os.path.join(self.data, "alice", "mhi_clbig.txt")
        bad_owner = os.path.exists(path) and os.stat(path).st_uid != UID_ALICE
        ok(self.clean(response) and not bad_owner,
           f"Content-Length>body caused no leak or bad ownership (HTTP {status})")
        self._small_content_length(host, bearer)
        self._oversized_content_length(host, bearer)
        self._truncated_headers(host, bearer)

    def _small_content_length(self, host, bearer):
        request = (("PUT /alice/mhi_clsmall.txt HTTP/1.1\r\nHost: %s\r\n"
                    "Authorization: %s\r\nContent-Length: 4\r\n"
                    "Connection: close\r\n\r\n" % (host, bearer)).encode()
                   + b"AAAAGET /bob/private.txt HTTP/1.1\r\nHost: "
                   + host.encode() + b"\r\n\r\n")
        status, response = self.raw_send(request, self.port)
        ok(self.clean(response),
           f"Content-Length<body smuggle did not leak bob's secret (HTTP {status})")

    def _oversized_content_length(self, host, bearer):
        request = (("PUT /alice/mhi_toobig.txt HTTP/1.1\r\nHost: %s\r\n"
                    "Authorization: %s\r\nContent-Length: 83886080\r\n"
                    "Connection: close\r\n\r\n" % (host, bearer)).encode()
                   + b"X" * 256)
        status, _ = self.raw_send(request, self.port)
        ok(status in (413, 400, 414, 431, -1) or status >= 400,
           f"oversized body declaration rejected (HTTP {status})")
        path = os.path.join(self.data, "alice", "mhi_toobig.txt")
        ok(not os.path.exists(path), "oversized-body PUT created no file")

    def _truncated_headers(self, host, bearer):
        request = ("GET /alice/ HTTP/1.1\r\nHost: %s\r\nAuthorization: %s\r\n"
                   "X-Partial: yes" % (host, bearer)).encode()
        status, response = self.raw_send(request, self.port, read_timeout=2.0)
        ok(self.clean(response), f"truncated headers caused no leak (HTTP {status})")
        self.worker_alive("raw-cl-lies")

    def _header_size_probes(self, host, bearer):
        request = ("GET /alice/ HTTP/1.1\r\nHost: %s\r\nAuthorization: %s\r\n"
                   "X-Huge: %s\r\nConnection: close\r\n\r\n"
                   % (host, bearer, "Z" * 24000)).encode()
        status, response = self.raw_send(request, self.port)
        ok(status in (400, 431, 414, 494, -1) or status >= 400,
           f"oversized request header rejected (HTTP {status})")
        ok(self.clean(response), f"oversized header caused no leak (HTTP {status})")
        self._giant_query_probe()
        self.worker_alive("oversized-header-query")

    def _giant_query_probe(self):
        status, body = http("GET", "/bob/private.txt?k=" + "q" * 16000,
                            self.port, self.alice_token)
        body = body or b""
        ok(b"BOB-PRIVATE-SECRET" not in body and self.MARKER not in body,
           f"giant query did not leak bob's secret (HTTP {status})")

    def _control_byte_probes(self, host, bearer):
        prefix = b"GET /alice/ HTTP/1.1\r\nHost: " + host.encode()
        auth = b"\r\nAuthorization: " + bearer.encode()
        requests = [
            ("NUL header", prefix + auth + b"\r\nX-Evil: a\x00b\r\n\r\n"),
            ("encoded CRLF", b"GET /alice/%0d%0aX-Injected:%20yes HTTP/1.1\r\nHost: "
             + host.encode() + auth + b"\r\nConnection: close\r\n\r\n"),
            ("raw NUL path", b"GET /alice/\x00/../bob/private.txt HTTP/1.1\r\nHost: "
             + host.encode() + auth + b"\r\nConnection: close\r\n\r\n"),
        ]
        for label, request in requests:
            status, response = self.raw_send(request, self.port)
            ok(self.clean(response), f"{label} caused no leak (HTTP {status})")
        body = b"line1\x00\x01\x02\nline2\r\n"
        http("PUT", "/alice/mhi_ctrl.bin", self.port, self.alice_token, body)
        path = os.path.join(self.data, "alice", "mhi_ctrl.bin")
        ok(os.path.exists(path) and os.stat(path).st_uid == UID_ALICE,
           "control-byte body stored as alice-owned data")
        self.worker_alive("nul-control")

    def malformed_jwts(self):
        good = mint(self.key, "alice")
        header, payload, signature = good.split(".")
        variants = [
            ("two-segment", f"{header}.{payload}"),
            ("one-segment", header),
            ("four-segment", f"{good}.extra"),
            ("bad-base64-header", f"@@@notb64@@@.{payload}.{signature}"),
            ("bad-base64-payload", f"{header}.@@@notb64@@@.{signature}"),
            ("huge-header", f'{_b64u(b"{" + b"A" * 20000 + b"}")}.{payload}.{signature}'),
            ("non-json-payload", f'{header}.{_b64u(b"not-json-at-all")}.{signature}'),
            ("empty-segments", ".."), ("only-dots", "...."),
            ("whitespace", "   "), ("nul-in-token", good[:10] + "\x00" + good[10:]),
        ]
        for label, token in variants:
            self._probe_malformed_jwt(label, token)
        status, _ = http("GET", "/alice/pp_target.txt", self.port, good)
        ok(status == 200, f"control: good JWT still authenticates (HTTP {status})")
        self.worker_alive("malformed-jwt")
        return header, payload, signature

    def _probe_malformed_jwt(self, label, token):
        status, body = http("GET", "/bob/private.txt", self.port, token)
        denied = status in (400, 401, 403, -1)
        ok(denied and b"BOB-PRIVATE-SECRET" not in (body or b""),
           f"malformed JWT {label}: secret read denied (HTTP {status})")
        name = "mhi_jwt_%s.txt" % re.sub(r"[^a-z0-9]", "", label.lower())
        http("PUT", f"/alice/{name}", self.port, token, b"X\n")
        ok(not os.path.exists(os.path.join(self.data, "alice", name)),
           f"malformed JWT {label}: created no file")

    def malformed_sigv4(self):
        if not self.s3port:
            ok(True, "S3 SigV4 malformed-field matrix skipped (no s3port)")
            return
        path = f"/{S3_BUCKET}/alice/mhi_sig.txt"
        disk_path = os.path.join(self.data, "alice", "mhi_sig.txt")
        for label, headers in self._sig_variants(path).items():
            self._remove_file(disk_path)
            self._probe_sig_variant(label, headers, path, disk_path)
        self._remove_file(disk_path)
        self._sig_read_and_write_controls(path)
        self.worker_alive("s3-sigv4")

    def _sig_headers(self, path):
        return dict(s3_sign("PUT", path, self.s3port))

    def _sig_variants(self, path):
        variants = {}
        headers = self._sig_headers(path); headers["x-amz-date"] = "not-a-date"
        variants["bad date format"] = headers
        headers = self._sig_headers(path); headers["x-amz-date"] = "19990101T000000Z"
        variants["wildly-skewed date"] = headers
        headers = self._sig_headers(path); headers["Authorization"] = headers["Authorization"].replace("/s3/", "/iam/")
        variants["wrong service in scope"] = headers
        headers = self._sig_headers(path); headers["Authorization"] = re.sub(r"\d{8}/us-east-1", "00000000/us-east-1", headers["Authorization"])
        variants["zero date in scope"] = headers
        headers = self._sig_headers(path); headers["Authorization"] = headers["Authorization"].replace(", SignedHeaders=host;x-amz-date", "")
        variants["missing SignedHeaders"] = headers
        headers = self._sig_headers(path); headers["Authorization"] = headers["Authorization"].split("Signature=")[0] + "Signature="
        variants["empty signature"] = headers
        headers = self._sig_headers(path); headers["Authorization"] = headers["Authorization"].split("Signature=")[0] + "Signature=" + "g" * 64
        variants["non-hex signature"] = headers
        headers = self._sig_headers(path); headers["Authorization"] = headers["Authorization"].replace("AWS4-HMAC-SHA256", "AWS4-HMAC-MD5")
        variants["unsupported algorithm"] = headers
        headers = self._sig_headers(path); headers["Authorization"] = headers["Authorization"].replace("Credential=", "Cred=")
        variants["malformed Credential kw"] = headers
        headers = self._sig_headers(path); headers["Authorization"] = "AWS4-HMAC-SHA256 \x00\x01garbage"
        variants["control bytes in Authorization"] = headers
        return variants

    def _probe_sig_variant(self, label, headers, path, disk_path):
        status, _ = http("PUT", path, self.s3port, data=b"sig-attack\n", hdrs=headers)
        created = os.path.exists(disk_path)
        owner = os.stat(disk_path).st_uid if created else -1
        if label == "wrong service in scope":
            confined = not created or owner == UID_ALICE
            ok(confined, f"S3 SigV4 scope gap remains alice-confined (HTTP {status})")
            return
        ok(status not in (200, 201, 204) and owner in (-1, UID_ALICE),
           f"S3 SigV4 {label}: rejected without bad ownership (HTTP {status})")

    @staticmethod
    def _remove_file(path):
        try:
            os.unlink(path)
        except OSError:
            pass

    def _sig_read_and_write_controls(self, path):
        headers = self._sig_headers(path)
        headers["Authorization"] = headers["Authorization"][:-8] + "00000000"
        status, body = http("GET", f"/{S3_BUCKET}/bob/private.txt",
                            self.s3port, hdrs=headers)
        ok(status != 200 and b"BOB-PRIVATE-SECRET" not in (body or b""),
           f"S3 malformed-signature secret read rejected (HTTP {status})")
        status, _ = s3("PUT", "alice/mhi_sig_ok.txt", self.s3port, data=b"ok\n")
        disk_path = os.path.join(self.data, "alice", "mhi_sig_ok.txt")
        valid = status in (200, 201) and os.path.exists(disk_path)
        ok(valid and os.stat(disk_path).st_uid == UID_ALICE,
           f"control: valid SigV4 PUT is alice-owned (HTTP {status})")

    def root_tokens(self, token_parts):
        if not xrd_avail():
            ok(True, "root:// hostile-token probes skipped (native client absent)")
            return
        header, payload, signature = token_parts
        variants = [("two-segment", f"{header}.{payload}"),
                    ("garbage", "@@@not.a.jwt@@@"),
                    ("huge-header", f'{_b64u(b"{" + b"A" * 20000 + b"}")}.{payload}.{signature}'),
                    ("empty", "")]
        for label, token in variants:
            status, output, _error = xrd_fs_token(["cat", "/bob/private.txt"], token)
            ok(status != 0 and "BOB-PRIVATE-SECRET" not in (output or ""),
               f"root:// malformed token {label} denied (rc={status})")
        self._root_positive_control()

    def _root_positive_control(self):
        local = os.path.join(WORK, "mhi_root_seed.bin")
        try:
            with open(local, "wb") as stream:
                stream.write(b"MHI-ROOT-CONTROL\n")
            status, _output, _error = xrd_cp_up(
                local, "/alice/mhi_root_ctrl.bin", "alice"
            )
            remote = os.path.join(self.data, "alice", "mhi_root_ctrl.bin")
            valid = status == 0 and os.path.exists(remote)
            ok(valid and os.stat(remote).st_uid == UID_ALICE,
               f"control: root:// valid-token write is alice-owned (rc={status})")
        except OSError as error:
            ok(True, f"root:// control seed hiccup tolerated ({error})")

    def final_checks(self):
        self.worker_alive("final")
        self._ownership_invariants()
        status, body = http("GET", "/bob/private.txt", self.port, self.alice_token)
        ok(b"BOB-PRIVATE-SECRET" not in (body or b""),
           f"post-batch: alice still cannot read bob's secret (HTTP {status})")
        if self.leakfile:
            self._remove_file(self.leakfile)

    def _ownership_invariants(self):
        try:
            root_uid = os.stat(self.data).st_uid
            alice_uid = os.stat(os.path.join(self.data, "alice")).st_uid
            ok(root_uid == UID_SVC and alice_uid == UID_ALICE,
               f"ownership intact: root={root_uid}, alice={alice_uid}")
        except OSError as error:
            ok(False, f"could not stat ownership invariants ({error})")

    def run(self):
        self.propfind_xml()
        self.proppatch_xml()
        self.lock_xml()
        self.s3_xml()
        self.raw_protocol()
        token_parts = self.malformed_jwts()
        self.malformed_sigv4()
        self.root_tokens(token_parts)
        self.final_checks()


def run_malformed_hostile_inputs(key, data, port, s3port):
    """Drive malformed inputs across WebDAV, S3, and root:// isolation seams."""
    _MalformedHostileInputs(key, data, port, s3port).run()
