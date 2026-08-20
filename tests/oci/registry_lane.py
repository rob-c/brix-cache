# tests/oci/registry_lane.py — the shared driver for the D4 push lanes.
#
# The registry surface has no upstream and no mock: it IS the registry, so a
# lane needs exactly one thing brought up — a real brix nginx rendered from
# tests/configs/oci_registry.conf over an empty store directory. The nginx
# half must go through the lifecycle harness (a bare subprocess.Popen is what
# test_server_registry_lint.py's frozen LAUNCH_BACKLOG exists to stop), so
# this module wraps lifecycle.start(NginxInstanceSpec(...)) and the lanes
# carry pytest.mark.uses_lifecycle_harness.
#
# Ports: the `oci_registry` block claimed in docs/10-reference/test-fleet-ports.md.
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import NamedTuple

from brix_suite.registry import NginxInstanceSpec
from settings import HOST


class Registry(NamedTuple):
    """One running registry front and the handles every assertion needs."""

    base: str            #: http://host:port — what a client talks to
    endpoint: object     #: the registry ServerEndpoint (prefix, logs, ports)
    store: Path          #: this instance's store root, for on-disk assertions


def registry_spec(name, port, store_dir, *, anonymous=True, writable=True,
                  issuers=None, extra_lines="") -> NginxInstanceSpec:
    """The spec for one registry front — rendered by a start, or by nginx -t.

    `issuers` is a scitokens.cfg path; naming one is the authenticated leg,
    and `anonymous=False` with no issuer is the state oci_merge.c refuses at
    parse time (which is a lane assertion of its own, hence a spec builder
    separate from the start below).
    """
    return NginxInstanceSpec(
        name=name,
        template="oci_registry.conf",
        port=port,
        protocol="http",
        readiness="tcp",
        template_values={
            "BIND_HOST": HOST,
            "REGISTRY_ROOT": str(store_dir),
            "ALLOW_WRITE": "on" if writable else "off",
            "ANON_LINES": ("brix_oci_registry_allow_anonymous on;"
                           if anonymous else ""),
            "ISSUER_LINES": ("brix_oci_token_issuers %s;" % issuers
                             if issuers else ""),
            "EXTRA_LINES": extra_lines,
        },
        reason="phase-104 OCI local registry push lane",
    )


def start_registry(lifecycle, name, port, store_dir, **kwargs) -> Registry:
    """Bring up one brix nginx registry front over an empty store."""
    Path(store_dir).mkdir(parents=True, exist_ok=True)
    endpoint = lifecycle.start(registry_spec(name, port, store_dir, **kwargs))
    return Registry("http://%s:%d" % (endpoint.host, endpoint.port), endpoint,
                    Path(store_dir))


def req(url, *, method="GET", data=None, headers=None):
    """One request at the registry; returns (status, headers, body).

    urllib raises on >=400 and a registry lane reads those statuses as data,
    so the HTTPError is unwrapped back into the same triple.
    """
    request = urllib.request.Request(url, method=method, data=data,
                                     headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def digest_of(data: bytes, alg: str = "sha256") -> str:
    """The digest the registry grammar registers under `alg`.

    Both registered algorithms are reachable from here so a lane can push a
    sha512-addressed object without hand-rolling the string.
    """
    h = hashlib.sha512(data) if alg == "sha512" else hashlib.sha256(data)
    return "%s:%s" % (alg, h.hexdigest())


def err_code(body):
    """The OCI error code out of an error envelope ('' if unparsable)."""
    try:
        return json.loads(body)["errors"][0]["code"]
    except Exception:                              # noqa: BLE001 — shape IS the assertion
        return ""


def push_blob(reg: Registry, repo: str, payload: bytes, *, chunks=1,
              alg: str = "sha256") -> str:
    """POST → PATCH×n → PUT one blob, exactly as podman does. Returns digest."""
    digest = digest_of(payload, alg)

    status, headers, _ = req("%s/v2/%s/blobs/uploads/" % (reg.base, repo),
                             method="POST")
    assert status == 202, "upload start refused: %d" % status
    location = headers["Location"]

    size = max(1, len(payload) // chunks) if chunks > 1 else len(payload)
    offset = 0
    while offset < len(payload):
        piece = payload[offset:offset + size]
        status, headers, body = req(reg.base + location, method="PATCH",
                                    data=piece)
        assert status == 202, "PATCH at %d refused: %d %s" % (
            offset, status, body)
        location = headers["Location"]
        offset += len(piece)

    status, headers, body = req(
        "%s%s?digest=%s" % (reg.base, location,
                            urllib.parse.quote(digest, safe="")),
        method="PUT")
    assert status == 201, "seal refused: %d %s" % (status, body)
    return digest


def push_manifest(reg: Registry, repo: str, reference: str,
                  manifest: dict) -> tuple:
    """PUT one manifest; returns (status, headers, body)."""
    body = json.dumps(manifest).encode()
    return req("%s/v2/%s/manifests/%s" % (reg.base, repo, reference),
               method="PUT", data=body,
               headers={"Content-Type": manifest["mediaType"]})


def image_manifest(config_digest: str, layer_digests) -> dict:
    """The smallest well-formed OCI image manifest naming those objects."""
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": 0,
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": d,
                "size": 0,
            }
            for d in layer_digests
        ],
    }
