"""Structured case logs and durable SQLite/search session archives."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sqlite3
import stat
import urllib.error
import urllib.request
import zlib
from pathlib import Path
from typing import Iterable, Mapping, Optional

from brixtest.errors import SpecError
from brixtest.evidence.search import SearchClient, bulk_lines
from brixtest.evidence.store import write_entities
from brixtest.evidence.redaction import text as redact_text

__all__ = [
    "archive_case_logs", "archive_server_log", "post_search_archive", "write_bulk_archive",
    "write_sqlite_archive",
]


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_file(path: Path, root: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root.resolve())
    except (OSError, ValueError, AttributeError):
        try:
            return path.is_file() and not path.is_symlink() and root.resolve() in path.resolve().parents
        except OSError:
            return False


def _copy(source: Path, target: Path) -> Optional[dict]:
    if not _safe_file(source, source.parent):
        return None
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(stat.S_IRUSR | stat.S_IWUSR)
    digest = hashlib.sha256()
    size = 0
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    return {
        "name": target.name, "path": str(target), "bytes": size,
        "sha256": digest.hexdigest(),
    }


def archive_case_logs(
    session_dir: Path, nodeid: str, run_root: Path, *, helper_log: Optional[Path] = None,
    attempt_id: str = "",
) -> list[dict]:
    """Copy every regular case log before ephemeral run cleanup can remove it."""
    root = Path(run_root)
    destination = Path(session_dir) / "logs" / _digest(nodeid)
    if attempt_id:
        destination = destination / attempt_id
    candidates = []
    if root.is_dir():
        for source in sorted(root.rglob("*")):
            if not _safe_file(source, root):
                continue
            relative = source.relative_to(root)
            if source.name == "summary.json" or any("log" in part.lower() for part in relative.parts) \
                    or source.suffix.lower() in (".log", ".out", ".err"):
                candidates.append((source, destination / "run" / relative))
    if helper_log is not None and helper_log.is_file() and not helper_log.is_symlink():
        candidates.append((helper_log, destination / "helper.log"))
    manifest = destination / "manifest.json"
    try:
        previous = json.loads(manifest.read_text()).get("logs", [])
        rows = [dict(item) for item in previous if isinstance(item, Mapping)]
    except (OSError, ValueError, TypeError, AttributeError):
        rows = []
    known = {str(row.get("relative", "")) for row in rows}
    for source, target in candidates:
        row = _copy(source, target)
        if row is not None:
            row["relative"] = str(target.relative_to(session_dir))
            try:
                row["source"] = str(source.relative_to(root))
            except ValueError:
                row["source"] = "helper.log"
            if row["relative"] not in known:
                rows.append(row)
                known.add(row["relative"])
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({"nodeid": nodeid, "logs": rows}, indent=2) + "\n")
    manifest.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return rows


def archive_server_log(
    session_dir: Path, source: Path, instance_id: str, *, server_name: str = "",
) -> dict:
    """Archive one physical server log under its stable instance identity."""
    destination = Path(session_dir) / "logs" / "instances" / instance_id
    target = destination / Path(source).name
    row = _copy(Path(source), target)
    if row is None:
        row = {
            "name": target.name, "path": str(target), "bytes": 0, "sha256": "",
            "missing": True,
        }
    row.update({
        "relative": str(target.relative_to(session_dir)),
        "artifact_id": "sha256:%s" % row["sha256"] if row["sha256"] else "",
        "kind": "server-log", "server_instance_id": instance_id,
        "server": server_name, "source": str(source),
    })
    manifest = destination / "manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({
        "server_instance_id": instance_id, "server": server_name, "logs": [row],
    }, indent=2, sort_keys=True) + "\n")
    manifest.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return row


def _tests(payload: Mapping[str, object]) -> Iterable[Mapping[str, object]]:
    rows = payload.get("tests", [])
    return (row for row in rows if isinstance(row, Mapping)) if isinstance(rows, list) else ()


def _log_data(session_dir: Path, row: Mapping[str, object]) -> Iterable[tuple[str, bytes, str]]:
    logs = row.get("logs", [])
    if not isinstance(logs, list):
        return ()
    result = []
    root = Path(session_dir).resolve()
    for item in logs:
        if not isinstance(item, Mapping):
            continue
        raw = item.get("relative")
        if not isinstance(raw, str):
            continue
        path = root / raw
        if not _safe_file(path, root):
            continue
        data = path.read_bytes()
        result.append((raw, data, hashlib.sha256(data).hexdigest()))
    return result


def _topology_log_data(
    payload: Mapping[str, object], session_dir: Path,
) -> Iterable[tuple[str, str, str, bytes, str]]:
    topology = payload.get("topology", {})
    pools = topology.get("pools", []) if isinstance(topology, Mapping) else []
    root = Path(session_dir).resolve()
    result = []
    for pool in pools if isinstance(pools, list) else []:
        if not isinstance(pool, Mapping):
            continue
        services = pool.get("services", {})
        if not isinstance(services, Mapping):
            continue
        for service in services.values():
            if not isinstance(service, Mapping):
                continue
            artifact = service.get("log_artifact", {})
            relative = artifact.get("relative") if isinstance(artifact, Mapping) else None
            if not isinstance(relative, str):
                continue
            path = root / relative
            if not _safe_file(path, root):
                continue
            data = path.read_bytes()
            result.append((
                str(pool.get("pool_id", "")), str(service.get("instance_id", "")),
                relative, data, hashlib.sha256(data).hexdigest(),
            ))
    return result


def write_sqlite_archive(payload: Mapping[str, object], session_dir: Path, path: Path) -> Path:
    """Write a portable archive; log contents are compressed and held in the DB."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(target))
    try:
        connection.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS sessions (
          session_id TEXT PRIMARY KEY, generated_at TEXT, exitstatus INTEGER, payload TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tests (
          session_id TEXT, nodeid TEXT, outcome TEXT, backend TEXT, isolation TEXT,
          wall_seconds REAL, error TEXT, payload TEXT NOT NULL,
          PRIMARY KEY(session_id, nodeid)
        );
        CREATE TABLE IF NOT EXISTS metrics (
          session_id TEXT, nodeid TEXT, name TEXT, value REAL, unit TEXT, kind TEXT,
          labels TEXT, at_seconds REAL
        );
        CREATE TABLE IF NOT EXISTS logs (
          session_id TEXT, nodeid TEXT, path TEXT, sha256 TEXT, encoding TEXT, content BLOB,
          PRIMARY KEY(session_id, nodeid, path)
        );
        """)
        session_id = str(payload.get("session_id", Path(session_dir).name))
        for table in ("metrics", "logs", "tests", "sessions"):
            connection.execute("DELETE FROM %s WHERE session_id = ?" % table, (session_id,))
        connection.execute(
            "INSERT OR REPLACE INTO sessions VALUES (?, ?, ?, ?)",
            (session_id, str(payload.get("generated_at", "")), payload.get("exitstatus"),
             json.dumps(payload, sort_keys=True)),
        )
        for row in _tests(payload):
            nodeid = str(row.get("nodeid", ""))
            connection.execute(
                "INSERT OR REPLACE INTO tests VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (session_id, nodeid, str(row.get("outcome", "")),
                 str(row.get("backend", "")), str(row.get("isolation", "process")),
                 float(str(row.get("wall_seconds", 0))), str(row.get("error", "")),
                 json.dumps(row, sort_keys=True)),
            )
            metrics = row.get("metrics", {})
            samples = metrics.get("samples", []) if isinstance(metrics, Mapping) else []
            if isinstance(samples, list):
                for sample in samples:
                    if isinstance(sample, Mapping):
                        connection.execute(
                            "INSERT INTO metrics VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (session_id, nodeid, str(sample.get("name", "")),
                             float(sample.get("value", 0)), str(sample.get("unit", "")),
                             str(sample.get("kind", "")),
                             json.dumps(sample.get("labels", {}), sort_keys=True),
                             float(sample.get("at_seconds", 0))),
                        )
            for relative, data, sha256 in _log_data(session_dir, row):
                connection.execute(
                    "INSERT OR REPLACE INTO logs VALUES (?, ?, ?, ?, 'zlib', ?)",
                    (session_id, nodeid, relative, sha256, sqlite3.Binary(zlib.compress(data))),
                )
        for pool_id, instance_id, relative, data, sha256 in _topology_log_data(
            payload, session_dir
        ):
            connection.execute(
                "INSERT OR REPLACE INTO logs VALUES (?, ?, ?, ?, 'zlib', ?)",
                (session_id, "@shared/%s/%s" % (pool_id, instance_id), relative,
                 sha256, sqlite3.Binary(zlib.compress(data))),
            )
        write_entities(connection, payload)
        connection.commit()
    finally:
        connection.close()
    target.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return target


def _search_docs(payload: Mapping[str, object], session_dir: Path, prefix: str) -> Iterable[str]:
    if not prefix or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for char in prefix):
        raise SpecError("search index", prefix, "must be lowercase [a-z0-9-_.]")
    session_id = str(payload.get("session_id", Path(session_dir).name))
    for row in _tests(payload):
        nodeid = str(row.get("nodeid", ""))
        safe = {key: value for key, value in row.items() if key not in ("replay", "run_root")}
        safe.update({"document_type": "test", "session_id": session_id})
        yield json.dumps({"index": {"_index": "%s-tests" % prefix,
                                    "_id": _digest(session_id + "\0" + nodeid)}})
        yield json.dumps(safe, sort_keys=True)
        for relative, data, sha256 in _log_data(session_dir, row):
            try:
                remote_data = redact_text(data.decode("utf-8")).encode("utf-8")
            except UnicodeDecodeError:
                remote_data = data
            document = {
                "document_type": "log", "session_id": session_id, "nodeid": nodeid,
                "path": relative, "sha256": sha256,
                "content_base64": base64.b64encode(zlib.compress(remote_data)).decode("ascii"),
                "encoding": "zlib+base64",
            }
            yield json.dumps({"index": {"_index": "%s-logs" % prefix,
                                        "_id": _digest(session_id + "\0" + nodeid + "\0" + relative)}})
            yield json.dumps(document, sort_keys=True)
    for pool_id, instance_id, relative, data, sha256 in _topology_log_data(
        payload, session_dir
    ):
        try:
            remote_data = redact_text(data.decode("utf-8")).encode("utf-8")
        except UnicodeDecodeError:
            remote_data = data
        document = {
            "document_type": "server-log", "session_id": session_id,
            "pool_id": pool_id, "server_instance_id": instance_id,
            "path": relative, "sha256": sha256,
            "content_base64": base64.b64encode(zlib.compress(remote_data)).decode("ascii"),
            "encoding": "zlib+base64",
        }
        yield json.dumps({"index": {"_index": "%s-logs" % prefix,
                                    "_id": _digest(session_id + "\0" + instance_id)}})
        yield json.dumps(document, sort_keys=True)
    yield from bulk_lines(payload, prefix=prefix)


def write_bulk_archive(
    payload: Mapping[str, object], session_dir: Path, path: Path, *, index: str = "brixtest",
) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(_search_docs(payload, session_dir, index)) + "\n")
    target.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return target


def post_search_archive(
    payload: Mapping[str, object], session_dir: Path, url: str, *, index: str = "brixtest",
    manage_schema: bool = False,
) -> None:
    base = url.rstrip("/")
    if base.endswith("/_bulk"):
        base = base[:-6]
    client = SearchClient(base, opener=urllib.request.urlopen, compress=False)
    if manage_schema:
        client.ensure_schema(index)
    client.post_lines(_search_docs(payload, session_dir, index))
