# mock_registry_part3.py — continuation shard split off from mock_registry.py for the 600
# logical-line cap; exec'd into its namespace by split_continuation.load so the
# module's import API is unchanged.

def _basic_pair(header):
    """(user, password) out of a Basic Authorization header — ("", "") for
    any other scheme or undecodable payload, which the account table then
    refuses like any unknown user."""
    if not header.startswith("Basic "):
        return "", ""
    try:
        pair = base64.b64decode(header[6:]).decode()
    except Exception:
        return "", ""
    user, _, pw = pair.partition(":")
    return user, pw


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/octet-stream", extra=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_body(self):
        # podman/skopeo PATCH layer chunks with Transfer-Encoding: chunked;
        # BaseHTTPRequestHandler leaves the decoding to us.
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            out = bytearray()
            while True:
                size = int(self.rfile.readline().split(b";")[0], 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass                    # skip trailers to the blank line
                    return bytes(out)
                out += self.rfile.read(size)
                self.rfile.readline()           # the chunk's trailing CRLF
        return self.rfile.read(int(self.headers.get("Content-Length", 0)))

    def _log(self):
        keep = {k: self.headers[k] for k in ("Accept", "Range")
                if self.headers.get(k)}
        auth = self.headers.get("Authorization")
        keep["has_authorization"] = auth is not None
        # The SCHEME, never the credential: a lane has to be able to prove that
        # Basic reached the token endpoint and nothing else, and logging the
        # secret itself would put it in every failure dump.
        keep["auth_scheme"] = auth.split(" ", 1)[0] if auth else None
        with STATE["lock"]:
            STATE["log"].append({"method": self.command, "path": self.path,
                                 "headers": keep, "ts": time.time()})
            if self.headers.get("Authorization"):
                STATE["saw_authorization"] += 1

    def _take_fault(self):
        with STATE["lock"]:
            f = STATE["fault"]
            if f["count"] != 0:
                pr = f.get("path_re")
                if pr is None or re.search(pr, self.path):
                    if f["count"] > 0:          # -1 = persist
                        f["count"] -= 1
                    return f["kind"]
        return "none"

    # ---- token plane -----------------------------------------------------
    def _token_ident(self):
        """Resolve the presented credential to a mint identity.

        (True, ident) — ident is None for an anonymous mint — or (False,
        None) after this method has already answered 401 for a credential
        the account table refuses.
        """
        if STATE["users"]:
            # Multi-user mode (D16 lanes): a presented Basic must name a known
            # account; anonymous mints succeed and carry no identity, exactly
            # like DockerHub, so denial happens on the DATA plane (403) where a
            # naive "the mint worked" client would wrongly declare victory.
            ah = self.headers.get("Authorization")
            if ah is None:
                return True, None
            user, pw = _basic_pair(ah)
            if not user or STATE["users"].get(user) != pw:
                self._send(401, b'{"error":"bad credentials"}',
                           "application/json")
                return False, None
            return True, user
        if STATE["basic"] is not None:
            want = "Basic " + base64.b64encode(
                STATE["basic"].encode()).decode()
            if self.headers.get("Authorization") != want:
                self._send(401, b'{"error":"bad credentials"}',
                           "application/json")
                return False, None
            return True, STATE["basic"].partition(":")[0]
        return True, None

    def _token_mint(self, ident):
        with STATE["lock"]:
            STATE["token_count"] += 1
            tok = "tok-%d" % STATE["token_count"]
            # A real registry bearer is a JWT: DockerHub's is ~2.7 KB, and a
            # client that carries a short one but clips a long one looks
            # perfectly healthy against a mock. --token-len is how a lane makes
            # the credential the size it is in production.
            if STATE["token_len"] > len(tok):
                tok += "." + "T" * (STATE["token_len"] - len(tok) - 1)
            STATE["tokens"][tok] = ident
        # Quay spells the field `access_token`, DockerHub `token`, and a
        # registry may omit `expires_in` entirely (the spec's default is 60 s).
        # All three shapes are one flag away so the client can be held to them.
        doc = {STATE["token_key"]: tok}
        if STATE["token_ttl"] > 0:
            doc["expires_in"] = STATE["token_ttl"]
        self._send(200, json.dumps(doc).encode(), "application/json")

    def _token(self):
        # Logged like any other request: "which credential reached WHICH plane"
        # is the whole subject of the auth-dance negatives, and a realm the
        # mirror was supposed to refuse can only be proven untouched if its
        # listener records what it did (not) receive.
        self._log()
        if STATE["token_redirect_loop"]:
            # A token endpoint that redirects to itself, forever. Same host, so
            # the realm allowlist has nothing to object to — the only thing that
            # can end this chain is the client's own hop budget.
            return self._send(302, b"", extra=[("Location", self.path)])
        ok, ident = self._token_ident()
        if not ok:
            return
        fault = self._take_fault()
        if fault == "corrupt":
            # A 200 the JSON parser cannot use — the failure mode a registry
            # behind a captive portal or a broken CDN actually presents.
            return self._send(200, b'{"tok', "application/json")
        if self._fault_body(fault, b""):
            return
        self._token_mint(ident)

    def _authorized(self, name, actions):
        if not STATE["auth"]:
            return True
        ah = self.headers.get("Authorization", "")
        if ah.startswith("Bearer ") and ah[7:] in STATE["tokens"]:
            allowed = STATE["private"].get(name)
            if allowed is None or STATE["tokens"][ah[7:]] in allowed:
                return True
            # A real token that does not cover THIS repository: DockerHub
            # answers 403, challenge-free — "the mint worked" is not
            # "authorized", which is exactly what the D16 verify leg probes.
            self._send(403, b'{"errors":[{"code":"DENIED"}]}',
                       "application/json")
            return False
        realm = STATE["realm"] or "http://%s:%d/token" % (
            self.server.server_address[0], self.server.server_address[1])
        scope = 'service="mock-registry",scope="repository:%s:%s"' % (
            name, actions)
        # "-" is the challenge RFC 7235 forbids: no realm at all. A client that
        # guesses one is a client that can be aimed at any host.
        ch = ("Bearer " + scope if realm == "-"
              else 'Bearer realm="%s",%s' % (realm, scope))
        self._send(401, b'{"errors":[{"code":"UNAUTHORIZED"}]}',
                   "application/json", [("WWW-Authenticate", ch)])
        return False

    # ---- data plane ------------------------------------------------------
    def _manifest_digest(self, name, ref):
        repo = STATE["repos"].get(name, {"tags": {}})
        if ":" in ref:
            return ref, repo
        return repo["tags"].get(ref), repo

    def _retagged_digest(self, digest, repo, fault):
        if fault != "retag":
            return digest
        alternatives = [value for value in repo["tags"].values()
                        if value != digest]
        return alternatives[0] if alternatives else digest

    def _manifest_header_digest(self, digest, fault):
        if fault == "wrong_digest_header":
            return "sha256:" + "0" * 64
        return digest

    def _corrupt_body(self, body, fault):
        if fault != "corrupt":
            return body
        middle = len(body) // 2
        return body[:middle] + bytes([body[middle] ^ 0xFF]) + body[middle + 1:]

    def _serve_manifest(self, name, ref):
        digest, repo = self._manifest_digest(name, ref)
        if digest is None or digest not in STATE["manifests"]:
            return self._send(404, b'{"errors":[{"code":"MANIFEST_UNKNOWN",'
                              b'"message":"manifest unknown"}]}',
                              "application/json")
        fault = self._take_fault()
        digest = self._retagged_digest(digest, repo, fault)
        body, media_type = STATE["manifests"][digest]
        if self._fault_body(fault, body):
            return
        body = self._corrupt_body(body, fault)
        header_digest = self._manifest_header_digest(digest, fault)
        self._send(200, body, media_type,
                   [("Docker-Content-Digest", header_digest)])

    def _redirect_location(self, digest):
        location = STATE["blob_redirect"] + self.path
        if STATE["blob_redirect_sign"]:
            location += "?Expires=%d&Signature=%s&Key-Pair-Id=BRIXTEST" % (
                int(time.time()) + 300, digest[7:39])
        return location

    def _serve_blob_redirect(self, digest):
        location = self._redirect_location(digest)
        self._send(302, b"", extra=[("Location", location)])

    def _serve_blob_content(self, digest):
        body = STATE["blobs"].get(digest)
        if body is None:
            return self._send(404, b'{"errors":[{"code":"BLOB_UNKNOWN"}]}',
                              "application/json")
        fault = self._take_fault()
        if self._fault_body(fault, body):
            return
        body = self._corrupt_body(body, fault)
        self._send(200, body, extra=[("Docker-Content-Digest", digest)])

    def _serve_blob(self, digest, query=""):
        redirect = STATE["blob_redirect"] is not None and self.command == "GET"
        if redirect:
            return self._serve_blob_redirect(digest)
        if STATE["require_signature"] and "Signature=" not in query:
            return self._send(403, b'{"errors":[{"code":"DENIED",'
                              b'"message":"unsigned request"}]}',
                              "application/json")
        self._serve_blob_content(digest)

    def _fault_http500(self, body):
        self._send(500, b"origin error")

    def _fault_toomanyrequests(self, body):
        self._send(429, b'{"errors":[{"code":"TOOMANYREQUESTS",'
                   b'"message":"pull rate limit exceeded"}]}',
                   "application/json", [("Retry-After", "7")])

    def _fault_reset(self, body):
        self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                   b"\x01\x00\x00\x00\x00\x00\x00\x00")
        self.connection.close()

    def _start_fault_response(self, length):
        self.send_response(200)
        self.send_header("Content-Length", str(length))
        self.end_headers()

    def _fault_stall(self, body):
        self._start_fault_response(len(body))
        self.wfile.write(body[:64])
        self.wfile.flush()
        time.sleep(30)

    def _fault_truncate(self, body):
        self._start_fault_response(len(body))
        self.wfile.write(body[:len(body) // 2])
        self.wfile.flush()
        self.connection.close()

    def _fault_wrong_length(self, body):
        self._start_fault_response(len(body) + 7)
        self.wfile.write(body)
        self.wfile.flush()
        self.connection.close()

    def _fault_slowdrip(self, body):
        self._start_fault_response(len(body))
        for index in range(0, len(body), 64):
            self.wfile.write(body[index:index + 64])
            self.wfile.flush()
            time.sleep(0.2)

    def _fault_body(self, fault, body):
        handlers = {
            "http500": self._fault_http500,
            "toomanyrequests": self._fault_toomanyrequests,
            "reset": self._fault_reset,
            "stall": self._fault_stall,
            "truncate": self._fault_truncate,
            "wrong_length": self._fault_wrong_length,
            "slowdrip": self._fault_slowdrip,
        }
        handler = handlers.get(fault)
        if handler is None:
            return False
        handler(body)
        return True

    def _query_params(self, query):
        pairs = (part.split("=", 1) for part in query.split("&") if "=" in part)
        return {key: unquote(value) for key, value in pairs}

    def _tags_after(self, tags, last):
        if last:
            return [tag for tag in tags if tag > last]
        return tags

    def _limit_tags(self, name, tags, limit):
        if not limit or len(tags) <= limit:
            return tags, []
        tags = tags[:limit]
        link = '</v2/%s/tags/list?n=%d&last=%s>; rel="next"' % (
            name, limit, tags[-1])
        return tags, [("Link", link)]

    def _paged_tags(self, name, tags, query):
        params = self._query_params(query)
        limit = int(params.get("n", 0)) or STATE["page_tags"]
        tags = self._tags_after(tags, params.get("last", ""))
        return self._limit_tags(name, tags, limit)

    def _serve_tags(self, name, query):
        repo = STATE["repos"].get(name)
        if repo is None:
            return self._send(404, b'{"errors":[{"code":"NAME_UNKNOWN"}]}',
                              "application/json")
        tags = sorted(repo["tags"])
        tags, extra = self._paged_tags(name, tags, query)
        body = json.dumps({"name": name, "tags": tags}).encode()
        self._send(200, body, "application/json", extra)

    def _referrer_descriptors(self, subject, query):
        return [{"mediaType": MT_MANIFEST, "digest": subject, "size": 7,
                 "artifactType": artifact_type,
                 "annotations": {"mock.query": query}}
                for artifact_type in ("application/vnd.example.sbom",
                                      "application/vnd.example.signature")]

    def _filter_referrers(self, descriptors, query):
        params = self._query_params(query)
        if "artifactType" not in params:
            return descriptors, []
        selected = [item for item in descriptors
                    if item["artifactType"] == params["artifactType"]]
        return selected, [("OCI-Filters-Applied", "artifactType")]

    def _serve_referrers(self, name, subject, query):
        """A deterministic referrers index for `subject` (D15.1).

        The mirror must forward this route verbatim and cache nothing, so the
        answer carries the QUERY back in an annotation: a lane can then prove
        the filter reached the upstream rather than being answered locally.
        """
        if STATE["repos"].get(name) is None:
            return self._send(404, b'{"errors":[{"code":"NAME_UNKNOWN"}]}',
                              "application/json")
        descs = self._referrer_descriptors(subject, query)
        descs, extra = self._filter_referrers(descs, query)
        body = json.dumps({"schemaVersion": 2, "mediaType": MT_INDEX,
                           "manifests": descs}).encode()
        self._send(200, body, MT_INDEX, extra)

    # ---- push plane ------------------------------------------------------
    def _record_upload_start(self, name, query):
        with STATE["lock"]:
            STATE["transcript"].append({"op": "start", "name": name,
                                        "query": query})

    def _try_blob_mount(self, name, params):
        digest = params.get("mount")
        if digest not in STATE["blobs"]:
            return False
        self._send(201, b"", extra=[
            ("Location", "/v2/%s/blobs/%s" % (name, digest))])
        return True

    def _open_upload(self, name, body):
        session_id = uuid.uuid4().hex
        with STATE["lock"]:
            STATE["uploads"][session_id] = {
                "name": name, "data": bytearray(body)}
        self._send(202, b"", extra=[
            ("Location", "/v2/%s/blobs/uploads/%s" % (name, session_id))])

    def _upload_start(self, name, query):
        params = self._query_params(query)
        self._record_upload_start(name, query)
        if self._try_blob_mount(name, params):
            return
        body = self._read_body()
        if "digest" in params:
            self._upload_seal(name, params["digest"], body)
            return
        self._open_upload(name, body)

    def _upload_seal(self, name, digest, body):
        if sha(body) != digest:
            return self._send(400, b'{"errors":[{"code":"DIGEST_INVALID"}]}',
                              "application/json")
        put_blob(bytes(body))
        with STATE["lock"]:
            STATE["transcript"].append({"op": "seal", "name": name,
                                        "digest": digest, "size": len(body)})
        self._send(201, b"", extra=[
            ("Location", "/v2/%s/blobs/%s" % (name, digest)),
            ("Docker-Content-Digest", digest)])

    def _upload_put(self, name, sid, query):
        q = {k: unquote(v) for k, v in
             (p.split("=", 1) for p in query.split("&") if "=" in p)}
        body = self._read_body()
        with STATE["lock"]:
            up = STATE["uploads"].pop(sid, None)
        if up is None or "digest" not in q:
            return self._send(404, b'{"errors":[{"code":"BLOB_UPLOAD_'
                              b'UNKNOWN"}]}', "application/json")
        up["data"].extend(body)
        self._upload_seal(name, q["digest"], up["data"])

    def _manifest_put(self, name, ref):
        body = self._read_body()
        mt = self.headers.get("Content-Type", MT_MANIFEST)
        d = put_manifest(name, None if ref.startswith("sha256:") else ref,
                         body, mt)
        with STATE["lock"]:
            STATE["transcript"].append({"op": "manifest", "name": name,
                                        "ref": ref, "digest": d})
        self._send(201, b"", extra=[("Docker-Content-Digest", d)])

    # ---- routing ---------------------------------------------------------
    def _ctl(self):
        with STATE["lock"]:
            if self.path == "/ctl/log":
                return self._send(200, json.dumps(STATE["log"]).encode(),
                                  "application/json")
            if self.path == "/ctl/token_count":
                body = json.dumps({"count": STATE["token_count"]})
                return self._send(200, body.encode(), "application/json")
            if self.path == "/ctl/saw_authorization":
                body = json.dumps({"count": STATE["saw_authorization"]})
                return self._send(200, body.encode(), "application/json")
            if self.path == "/ctl/uploads":
                return self._send(200,
                                  json.dumps(STATE["transcript"]).encode(),
                                  "application/json")
        self._send(404, b"")

    def _get_manifest(self, match, query):
        if self._authorized(match.group(1), "pull"):
            self._serve_manifest(match.group(1), match.group(2))

    def _get_blob(self, match, query):
        if self._authorized(match.group(1), "pull"):
            self._serve_blob(match.group(2), query)

    def _get_tags(self, match, query):
        if self._authorized(match.group(1), "pull"):
            self._serve_tags(match.group(1), query)

    def _get_referrers(self, match, query):
        if self._authorized(match.group(1), "pull"):
            self._serve_referrers(match.group(1), match.group(2), query)

    def _route_get(self, path, query):
        routes = (
            (r"/v2/(.+)/manifests/([^/]+)", self._get_manifest),
            (r"/v2/(.+)/blobs/(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})",
             self._get_blob),
            (r"/v2/(.+)/tags/list", self._get_tags),
            (r"/v2/(.+)/referrers/(sha256:[0-9a-f]{64})",
             self._get_referrers),
        )
        for pattern, handler in routes:
            match = re.fullmatch(pattern, path)
            if match:
                handler(match, query)
                return True
        return False

    def _get_api_version(self):
        if self._authorized("", "pull"):
            self._send(200, b"{}", "application/json")

    def do_GET(self):
        if self.path.startswith("/ctl/"):
            return self._ctl()
        if self.path.split("?")[0] == "/token":
            return self._token()
        self._log()
        path, _, query = self.path.partition("?")
        if self._route_get(path, query):
            return
        if path in ("/v2/", "/v2"):
            return self._get_api_version()
        self._send(404, b"not found")

    do_HEAD = do_GET

    def do_POST(self):
        if self.path == "/ctl/fault":
            req = json.loads(self.rfile.read(
                int(self.headers.get("Content-Length", 0))))
            with STATE["lock"]:
                STATE["fault"] = {
                    "kind": req["kind"],
                    "count": -1 if req.get("persist") else 1,
                    "path_re": req.get("path_re")}
            return self._send(200, b"ok")
        if self.path == "/ctl/reset":
            with STATE["lock"]:
                STATE["log"].clear()
                STATE["transcript"].clear()
                STATE["uploads"].clear()
                STATE["saw_authorization"] = 0
                STATE["fault"] = {"kind": "none", "count": 0,
                                  "path_re": None}
            return self._send(200, b"ok")
        if self.path == "/ctl/retag":
            req = json.loads(self.rfile.read(
                int(self.headers.get("Content-Length", 0))))
            with STATE["lock"]:
                STATE["repos"][req["name"]]["tags"][req["tag"]] = \
                    req["digest"]
            return self._send(200, b"ok")
        self._log()
        path, _, query = self.path.partition("?")
        m = re.fullmatch(r"/v2/(.+)/blobs/uploads/", path)
        if m and STATE["push"]:
            if self._authorized(m.group(1), "push,pull"):
                self._upload_start(m.group(1), query)
            return
        self._send(404, b"not found")

    def do_PUT(self):
        self._log()
        path, _, query = self.path.partition("?")
        m = re.fullmatch(r"/v2/(.+)/blobs/uploads/([0-9a-f]{32})", path)
        if m and STATE["push"]:
            if self._authorized(m.group(1), "push,pull"):
                self._upload_put(m.group(1), m.group(2), query)
            return
        m = re.fullmatch(r"/v2/(.+)/manifests/([^/]+)", path)
        if m and STATE["push"]:
            if self._authorized(m.group(1), "push,pull"):
                self._manifest_put(m.group(1), m.group(2))
            return
        self._send(404, b"not found")

    def do_PATCH(self):
        # chunked upload leg (podman/skopeo push): append to the open session,
        # ack with Location + Range; the closing PUT?digest= seals as usual.
        self._log()
        path, _, _query = self.path.partition("?")
        m = re.fullmatch(r"/v2/(.+)/blobs/uploads/([0-9a-f]{32})", path)
        if not (m and STATE["push"]):
            return self._send(404, b"not found")
        if not self._authorized(m.group(1), "push,pull"):
            return
        body = self._read_body()
        with STATE["lock"]:
            up = STATE["uploads"].get(m.group(2))
            if up is not None:
                up["data"].extend(body)
                size = len(up["data"])
        if up is None:
            return self._send(404, b'{"errors":[{"code":"BLOB_UPLOAD_'
                              b'UNKNOWN"}]}', "application/json")
        self._send(202, b"", extra=[
            ("Location", "/v2/%s/blobs/uploads/%s" % (m.group(1), m.group(2))),
            ("Range", "0-%d" % (size - 1))])

    def _remove_manifest(self, name, digest):
        with STATE["lock"]:
            removed = STATE["manifests"].pop(digest, None)
            repo = STATE["repos"].get(name, {"tags": {}})
            tags = [tag for tag, value in repo["tags"].items()
                    if value == digest]
            for tag in tags:
                del repo["tags"][tag]
        return removed

    def _delete_manifest(self, match):
        if not self._authorized(match.group(1), "push,pull"):
            return
        removed = self._remove_manifest(match.group(1), match.group(2))
        code = 202 if removed else 404
        self._send(code, b"")

    def do_DELETE(self):
        self._log()
        match = re.fullmatch(
            r"/v2/(.+)/manifests/"
            r"(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})", self.path)
        if match and STATE["push"]:
            self._delete_manifest(match)
            return
        self._send(404, b"not found")
