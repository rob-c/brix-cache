"""Shared mutation and directory runners for HTTP semantic cases."""
import json
import subprocess

from settings import HOST
from test_xrd_conform_http_semantics import (
    NamespaceRoot,
    PAYLOAD,
    PgOrigin,
    SemanticOrigin,
    SharedMutationRoot,
    XRD,
    _clean_environment,
    _verification_args,
)

def _run_cross_plane_mutation(tmp_path, behaviour="ok", clause="XPR-009",
                              verify_negative=None):
    output = tmp_path / f"{clause}-mutation-{behaviour}"
    scratch = {}
    with PgOrigin(PAYLOAD, behaviour="ok") as primary:
        with SharedMutationRoot(scratch) as root:
            with SemanticOrigin(behaviour, scratch) as web:
                command = [
                    str(XRD), "conform", "accept",
                    f"root://{HOST}:{primary.port}//fixture",
                    "--profile", "full", "--only", clause,
                    "--allow-mutate", "--scratch", "/bucket/scratch",
                    "--mutation-fixture",
                    f"root=root://{HOST}:{root.port}//fixture",
                    "--mutation-fixture",
                    f"http=http://{HOST}:{web.port}/fixture",
                    "--fail-on", "divergent", "--wall-seconds", "20",
                    "--request-limit", "64", "--byte-limit", "1048576",
                    "--out", str(output),
                ]
                if clause == "XPR-009":
                    command.extend([
                        "--mutation-fixture",
                        f"s3=s3://{HOST}:{web.port}/bucket/fixture",
                    ])
                command.extend(_verification_args(verify_negative))
                result = subprocess.run(
                    command, text=True, capture_output=True, timeout=25,
                    check=False, env=_clean_environment(),
                )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}


def _run_dav_directory(tmp_path, root_names, web_behaviour="ok",
                       verify_negative=None):
    output = tmp_path / f"dav-directory-{web_behaviour}"
    with NamespaceRoot(root_names) as root:
        with SemanticOrigin(web_behaviour) as web:
            command = [
                str(XRD), "conform", "accept",
                f"root://{HOST}:{root.port}//fixture",
                "--profile", "full", "--only", "DAV-002",
                "--also", f"http://{HOST}:{web.port}/fixture",
                "--fail-on", "divergent", "--wall-seconds", "20",
                "--request-limit", "64", "--byte-limit", "1048576",
                "--out", str(output),
            ]
            command.extend(_verification_args(verify_negative))
            result = subprocess.run(command, text=True, capture_output=True,
                timeout=25, check=False,
                env=_clean_environment())
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}
