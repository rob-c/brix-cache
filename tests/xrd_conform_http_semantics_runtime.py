"""Runtime fixtures and command builders for HTTP semantic cases."""
from test_xrd_conform_http_semantics import *
from test_xrd_conform_http_semantics import _SemanticHandler

class SemanticOrigin:
    """Serve exact HTTP semantics selected by one named behavior."""

    def __init__(self, behaviour="ok", scratch=None):
        self.port, self.server = bind_port(
            lambda port: ThreadingHTTPServer((HOST, port), _SemanticHandler),
            HOST,
        )
        self.server.behaviour = behaviour
        self.server.scratch = {} if scratch is None else scratch
        self.server.token_hits = {}
        self.server.uploads = {}
        self.server.upload_sequence = 0
        self.server.head_hits = 0
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class SharedMutationRoot(PgOrigin):
    """Expose the HTTP fixture's mutable object through ROOT stat."""

    def __init__(self, scratch):
        self.scratch = scratch
        super().__init__(PAYLOAD, behaviour="ok")

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == kXR_stat:
            path = body.rstrip(b"\x00").decode("utf-8", "surrogateescape")
            payload = self.scratch.get(path)
            if payload is None:
                conn.sendall(error_frame(sid, 3011, b"not found"))
            else:
                stat = b"0 %d 0 0\x00" % len(payload)
                conn.sendall(ok_frame(sid, stat))
            return authenticated
        return super()._dispatch(conn, sid, reqid, hdr, body, authenticated)


class NamespaceRoot(PgOrigin):
    """Expose a controlled direct-child set through kXR_dirlist."""

    def __init__(self, names):
        self.names = names
        super().__init__(PAYLOAD, behaviour="ok")

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == kXR_dirlist:
            if self.names is None:
                conn.sendall(error_frame(sid, 3007, b"listing unavailable"))
            else:
                listing = ("\n".join(self.names) + "\n").encode()
                conn.sendall(ok_frame(sid, listing))
            return authenticated
        return super()._dispatch(
            conn, sid, reqid, hdr, body, authenticated,
        )


def _clean_environment(with_s3_credentials=False):
    environment = os.environ.copy()
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                 "AWS_SESSION_TOKEN", "BEARER_TOKEN", "BEARER_TOKEN_FILE"):
        environment.pop(name, None)
    if with_s3_credentials:
        environment.update({
            "AWS_ACCESS_KEY_ID": S3_ACCESS,
            "AWS_SECRET_ACCESS_KEY": S3_SECRET,
            "AWS_DEFAULT_REGION": S3_REGION,
            "BEARER_TOKEN": "eyJhbGciOiJub25lIn0.eyJzY29wZSI6"
                            "InN0b3JhZ2UucmVhZDovIn0.signature",
        })
    return environment


def _conform_byte_limit(scheme):
    return "33554432" if scheme == "s3" else "8388608"


def _conform_command(origin, output, scheme):
    profile = "s3" if scheme == "s3" else "http"
    families = "HTR,S3" if scheme == "s3" else "HTR"
    return [
        str(XRD), "conform", "accept",
        f"{scheme}://{HOST}:{origin.port}"
        f"{'/bucket/fixture' if scheme == 's3' else '/fixture'}",
        "--profile", profile,
        "--families", families, "--allow-mutate", "--scratch",
        "/bucket/scratch" if scheme == "s3" else "/scratch",
        "--fail-on", "divergent", "--wall-seconds", "10",
        "--request-limit", "96", "--byte-limit",
        _conform_byte_limit(scheme),
        "--out", str(output),
    ]


def _cross_plane_command(origin, output):
    command = _conform_command(origin, output, "http")
    family_index = command.index("HTR")
    command[family_index] = "HTR,S3,XPR"
    command.extend([
        "--also", f"s3://{HOST}:{origin.port}/bucket/fixture",
    ])
    return command


def _auth_cross_plane_command(origin, output):
    command = _cross_plane_command(origin, output)
    command[command.index("http")] = "full"
    command.extend(["--only", "S3-008"])
    return command


def _verification_args(clause_ids):
    if clause_ids is None:
        return []
    if isinstance(clause_ids, str):
        clause_ids = [clause_ids]
    return [item for clause_id in clause_ids
            for item in ("--verify-negative", clause_id)]


def _run(tmp_path, behaviour="ok", scheme="http", with_s3_credentials=False,
         verify_negative=None, only=None):
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")
    output = tmp_path / f"{scheme}-{behaviour}"
    with SemanticOrigin(behaviour) as origin:
        command = _conform_command(origin, output, scheme)
        if only is not None:
            command.extend(["--only", only])
        command.extend(_verification_args(verify_negative))
        result = subprocess.run(
            command,
            text=True, capture_output=True, timeout=15, check=False,
            env=_clean_environment(with_s3_credentials),
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}


def _run_cross_plane(tmp_path, behaviour="ok", with_s3_credentials=False,
                     only_auth=False, verify_negative=None):
    output = tmp_path / f"cross-plane-{behaviour}"
    with SemanticOrigin(behaviour) as origin:
        command = (_auth_cross_plane_command(origin, output) if only_auth
                   else _cross_plane_command(origin, output))
        command.extend(_verification_args(verify_negative))
        result = subprocess.run(
            command, text=True,
            capture_output=True, timeout=20, check=False,
            env=_clean_environment(with_s3_credentials),
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}
