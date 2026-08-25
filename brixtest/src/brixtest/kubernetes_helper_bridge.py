"""Controller-side bridge for a bundled pytest helper in a Kubernetes Job."""

from __future__ import annotations

import argparse
import contextlib
import json
import shutil
import stat
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path
from typing import Mapping, Optional, Sequence, Tuple

from brixtest.helper_transport import FrameDecoder, apply_message

_EXTRACT_BUNDLE = r"""
import io,os,pathlib,stat,sys,zipfile
data=sys.stdin.buffer.read()
allowed=(pathlib.Path('/workspace'),pathlib.Path('/opt/brixtest'),pathlib.Path('/brixtest'))
with zipfile.ZipFile(io.BytesIO(data)) as archive:
    for info in archive.infolist():
        relative=pathlib.PurePosixPath(info.filename)
        if relative.is_absolute() or '..' in relative.parts:
            raise RuntimeError('unsafe helper bundle path')
        target=pathlib.Path('/') / pathlib.Path(*relative.parts)
        resolved=target.resolve()
        if not any(resolved == root or root in resolved.parents for root in allowed):
            raise RuntimeError('unconfined helper bundle path')
        mode=(info.external_attr >> 16) & 0o777
        if stat.S_ISLNK(info.external_attr >> 16):
            raise RuntimeError('helper bundle links are forbidden')
        if info.is_dir():
            target.mkdir(parents=True,exist_ok=True)
        else:
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(archive.read(info))
            target.chmod(mode or 0o600)
"""

_STREAM_TREE = r"""
import os,pathlib,stat,sys,tarfile
root=pathlib.Path(sys.argv[1])
missing=not root.is_dir()
with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as archive:
  if not missing:
    for current,dirs,files in os.walk(root,followlinks=False):
        base=pathlib.Path(current)
        dirs[:]=sorted(name for name in dirs if not (base/name).is_symlink())
        relative=base.relative_to(root)
        if relative.parts: archive.add(base,arcname=str(relative),recursive=False)
        for name in sorted(files):
            path=base/name
            if path.is_file() and not path.is_symlink():
                archive.add(path,arcname=str(path.relative_to(root)),recursive=False)
if missing: sys.exit(3)
"""

_READ_FILE = (
    "import pathlib,sys;"
    "p=pathlib.Path(sys.argv[1]);"
    "sys.stdout.buffer.write(p.read_bytes() if p.is_file() else b'')"
)


def _load_spec(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError("cannot load Kubernetes helper bridge spec: %s" % exc) from exc
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise RuntimeError("unsupported Kubernetes helper bridge spec")
    return value


def _strings(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuntimeError("Kubernetes helper bridge %s must be a string list" % field)
    return list(value)


def _path(value: object, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise RuntimeError("Kubernetes helper bridge %s must be a path" % field)
    return Path(value)


class _ProvisionHeartbeat:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.stop.set()
        self.thread.join(timeout=1.0)

    def _run(self) -> None:
        while not self.stop.wait(0.25):
            _write_json(self.path, {"schema": 1, "phase": "provisioning", "time": time.time()})


def _write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".bridge.tmp")
    temporary.write_text(json.dumps(value, sort_keys=True) + "\n")
    temporary.replace(path)


def _run(command: Sequence[str], *, input_data: Optional[bytes] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(command), input=input_data, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=120.0, check=False,
    )


def _checked(command: Sequence[str], action: str, *, input_data: Optional[bytes] = None) -> bytes:
    result = _run(command, input_data=input_data)
    if result.returncode:
        detail = result.stdout.decode("utf-8", errors="replace")
        raise RuntimeError("%s failed (%d): %s" % (action, result.returncode, detail))
    return result.stdout


def _pod_name(base: Sequence[str], job: str) -> str:
    output = _checked(
        [*base, "get", "pods", "-l", "job-name=%s" % job, "-o", "json"],
        "Kubernetes helper pod discovery",
    )
    try:
        items = json.loads(output.decode("utf-8"))["items"]
        names = [item["metadata"]["name"] for item in items]
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("Kubernetes helper pod discovery returned invalid JSON") from exc
    if len(names) != 1 or not isinstance(names[0], str):
        raise RuntimeError("Kubernetes helper Job must own exactly one pod")
    return names[0]


def _running_minikube(spec: Mapping[str, object]) -> bool:
    executable = spec.get("minikube")
    context = spec.get("context")
    if not isinstance(executable, str) or not executable or not context:
        return False
    result = _run([executable, "-p", str(context), "status", "--output=json"])
    if result.returncode:
        return False
    try:
        status = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, ValueError, TypeError):
        return False
    return status.get("Host") == "Running" and status.get("APIServer") == "Running"


def _local_image(spec: Mapping[str, object]) -> Optional[Tuple[str, str]]:
    docker = spec.get("docker")
    image = spec.get("image")
    if not isinstance(docker, str) or not docker or not isinstance(image, str):
        return None
    digest = image.rpartition("@sha256:")[2]
    if len(digest) != 64:
        return None
    result = _run([docker, "image", "inspect", image])
    expected = "sha256:%s" % digest
    if result.returncode or not _matching_image_identity(result.stdout, image, expected):
        return None
    return "brixtest.local/helper-runtime:sha256-%s" % digest, docker


def _matching_image_identity(payload: bytes, image: str, expected: str) -> bool:
    try:
        inspected = json.loads(payload.decode("utf-8"))[0]
        identities = {str(inspected.get("Id", "")), *map(str, inspected.get("RepoDigests", []))}
    except (IndexError, TypeError, UnicodeError, ValueError):
        return False
    return expected in identities or image in identities


def _use_minikube_image(spec: Mapping[str, object]) -> None:
    if not _running_minikube(spec):
        return
    selected = _local_image(spec)
    if selected is None:
        return
    tag, docker = selected
    minikube = str(spec["minikube"])
    context = str(spec["context"])
    _checked([docker, "tag", str(spec["image"]), tag], "Kubernetes helper image tag")
    _checked(
        [minikube, "-p", context, "image", "load", tag],
        "Kubernetes helper Minikube image load",
    )
    _replace_manifest_image(_path(spec.get("manifest"), "manifest"), tag)


def _replace_manifest_image(path: Path, image: str) -> None:
    try:
        resources = json.loads(path.read_text())
        job = next(item for item in resources["items"] if item["kind"] == "Job")
        container = job["spec"]["template"]["spec"]["containers"][0]
    except (KeyError, OSError, StopIteration, TypeError, ValueError) as exc:
        raise RuntimeError("cannot update Kubernetes helper image manifest") from exc
    container["image"] = image
    container["imagePullPolicy"] = "Never"
    _write_json(path, resources)


def _provision(spec: Mapping[str, object], base: Sequence[str]) -> str:
    manifest = _path(spec.get("manifest"), "manifest")
    bundle = _path(spec.get("bundle"), "bundle")
    job = str(spec.get("job", ""))
    _use_minikube_image(spec)
    _checked([*base, "apply", "-f", str(manifest)], "Kubernetes helper apply")
    _checked(
        [*base, "wait", "--for=condition=Ready", "pod", "-l", "job-name=%s" % job,
         "--timeout=60s"],
        "Kubernetes helper readiness",
    )
    pod = _pod_name(base, job)
    python = str(spec.get("python", "python3"))
    _checked(
        [*base, "exec", "-i", pod, "--", python, "-c", _EXTRACT_BUNDLE],
        "Kubernetes helper bundle upload", input_data=bundle.read_bytes(),
    )
    return pod


def _stream_test(
    command: Sequence[str], *, heartbeat: Path, result: Path, journal: Path,
) -> int:
    process = subprocess.Popen(
        list(command), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    assert process.stdout is not None
    decoder = FrameDecoder(
        lambda message: apply_message(
            message, heartbeat=heartbeat, result=result, journal=journal,
        )
    )
    read = getattr(process.stdout, "read1", process.stdout.read)
    while True:
        block = read(64 << 10)
        if not block:
            break
        ordinary = decoder.feed(block)
        if ordinary:
            sys.stdout.buffer.write(ordinary)
            sys.stdout.buffer.flush()
    trailing = decoder.close()
    if trailing:
        sys.stdout.buffer.write(trailing)
        sys.stdout.buffer.flush()
    return process.wait()


def _safe_destination(root: Path, name: str) -> Path:
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise RuntimeError("unsafe path in Kubernetes helper output")
    destination = (root / relative).resolve()
    if destination != root.resolve() and root.resolve() not in destination.parents:
        raise RuntimeError("unconfined path in Kubernetes helper output")
    return destination


def _extract_stream(process: subprocess.Popen, destination: Path) -> None:
    assert process.stdout is not None
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=process.stdout, mode="r|*") as archive:
        for member in archive:
            target = _safe_destination(destination, member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise RuntimeError("Kubernetes helper output may contain only files")
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError("cannot read Kubernetes helper output")
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as output:
                shutil.copyfileobj(source, output, length=1 << 20)
            target.chmod(stat.S_IMODE(member.mode) & 0o777)


def _download_tree(
    base: Sequence[str], pod: str, python: str, remote: str, destination: Path,
    diagnostics: Path,
) -> None:
    with diagnostics.open("ab") as errors:
        process = subprocess.Popen(
            [*base, "exec", pod, "--", python, "-c", _STREAM_TREE, remote],
            stdout=subprocess.PIPE, stderr=errors,
        )
        try:
            _extract_stream(process, destination)
        except (OSError, tarfile.TarError, RuntimeError):
            process.kill()
            process.wait()
            raise
        if process.wait() not in (0, 3):
            raise RuntimeError("cannot download Kubernetes helper output %s" % remote)


def _download_result(
    base: Sequence[str], pod: str, python: str, remote: str, destination: Path,
) -> None:
    output = _checked(
        [*base, "exec", pod, "--", python, "-c", _READ_FILE, remote],
        "Kubernetes helper result download",
    )
    if output:
        destination.write_bytes(output)


def _mark_done(base: Sequence[str], pod: str, python: str, path: str, code: int) -> None:
    script = "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text(sys.argv[2])"
    with contextlib.suppress(RuntimeError):
        _checked(
            [*base, "exec", pod, "--", python, "-c", script, path, str(code)],
            "Kubernetes helper completion",
        )


def _cleanup(base: Sequence[str], job: str, secret: str) -> None:
    _quiet_delete([
        *base, "delete", "pod", "-l", "job-name=%s" % job,
        "--ignore-not-found=true", "--grace-period=0", "--force", "--wait=false",
    ])
    _quiet_delete([
        *base, "delete", "job/%s" % job, "secret/%s" % secret,
        "--ignore-not-found=true", "--wait=false",
    ])


def _quiet_delete(argv: Sequence[str]) -> None:
    with contextlib.suppress(OSError, subprocess.TimeoutExpired):
        subprocess.run(
            list(argv),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=20.0, check=False,
        )


def run(spec_path: Path) -> int:
    """Run one bridge spec and return the remote pytest exit code."""
    spec = _load_spec(spec_path)
    base = _strings(spec.get("kubectl"), "kubectl")
    heartbeat = _path(spec.get("heartbeat"), "heartbeat")
    result = _path(spec.get("result"), "result")
    journal = _path(spec.get("journal"), "journal")
    python = str(spec.get("python", "python3"))
    job, secret = str(spec.get("job", "")), str(spec.get("secret", ""))
    pod = ""
    try:
        with _ProvisionHeartbeat(heartbeat):
            pod = _provision(spec, base)
            command = [
                *base, "exec", pod, "--", python,
                *_strings(spec.get("pytest"), "pytest"),
            ]
            code = _stream_test(
                command, heartbeat=heartbeat, result=result, journal=journal,
            )
            diagnostics = spec_path.parent / "download-errors.log"
            _download_result(base, pod, python, str(spec["remote_result"]), result)
            _download_tree(
                base, pod, python, str(spec["remote_run"]),
                _path(spec.get("run"), "run"), diagnostics,
            )
            _download_tree(
                base, pod, python, str(spec["remote_session"]),
                _path(spec.get("session"), "session"), diagnostics,
            )
            _mark_done(base, pod, python, str(spec["remote_done"]), code)
            return code
    except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        sys.stdout.write("BriXTest Kubernetes helper bridge: %s\n" % exc)
        sys.stdout.flush()
        return 125
    finally:
        _cleanup(base, job, secret)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry used only by the supervised controller launch."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("spec", type=Path)
    args = parser.parse_args(argv)
    return run(args.spec)


if __name__ == "__main__":
    raise SystemExit(main())
