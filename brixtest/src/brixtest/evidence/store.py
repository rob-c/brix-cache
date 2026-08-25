"""Normalized SQLite persistence and read-only evidence queries."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Mapping, Sequence

from brixtest.errors import SpecError
from brixtest.evidence.model import SCHEMA_VERSION, iter_entities, normalize_session

_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_schema (
  name TEXT PRIMARY KEY, version INTEGER NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence_entities (
  session_id TEXT NOT NULL, entity TEXT NOT NULL, case_id TEXT NOT NULL DEFAULT '',
  attempt_id TEXT NOT NULL DEFAULT '', ordinal INTEGER NOT NULL DEFAULT 0,
  nodeid TEXT NOT NULL DEFAULT '', timestamp TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '', value REAL, unit TEXT NOT NULL DEFAULT '',
  payload TEXT NOT NULL,
  PRIMARY KEY(session_id, entity, case_id, attempt_id, ordinal, name)
);
CREATE INDEX IF NOT EXISTS evidence_entity_lookup
  ON evidence_entities(entity, session_id, nodeid, name);
CREATE INDEX IF NOT EXISTS evidence_attempt_lookup
  ON evidence_entities(session_id, attempt_id, entity);
CREATE TABLE IF NOT EXISTS evidence_attempts (
  session_id TEXT NOT NULL, case_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  nodeid TEXT NOT NULL, trial INTEGER NOT NULL, warmup INTEGER NOT NULL,
  outcome TEXT NOT NULL, started_at TEXT, wall_seconds REAL, run_root TEXT,
  error TEXT, payload TEXT NOT NULL,
  PRIMARY KEY(session_id, attempt_id)
);
CREATE INDEX IF NOT EXISTS evidence_attempt_outcome
  ON evidence_attempts(session_id, outcome, nodeid);
CREATE TABLE IF NOT EXISTS evidence_metrics (
  session_id TEXT NOT NULL, case_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  nodeid TEXT NOT NULL, ordinal INTEGER NOT NULL, name TEXT NOT NULL,
  value REAL NOT NULL, unit TEXT, kind TEXT, labels TEXT, at_seconds REAL,
  trial INTEGER, payload TEXT NOT NULL,
  PRIMARY KEY(session_id, attempt_id, ordinal)
);
CREATE INDEX IF NOT EXISTS evidence_metric_series
  ON evidence_metrics(name, session_id, nodeid);
CREATE TABLE IF NOT EXISTS evidence_server_pools (
  session_id TEXT NOT NULL, pool_id TEXT NOT NULL, outcome TEXT,
  started_at TEXT, stopped_at TEXT, payload TEXT NOT NULL,
  PRIMARY KEY(session_id, pool_id)
);
CREATE TABLE IF NOT EXISTS evidence_server_instances (
  session_id TEXT NOT NULL, instance_id TEXT NOT NULL, pool_id TEXT,
  name TEXT NOT NULL, scope TEXT NOT NULL, ports TEXT NOT NULL DEFAULT '{}',
  started_at TEXT, stopped_at TEXT,
  config_path TEXT, config_filename TEXT, config_source_sha256 TEXT, config_declared_sha256 TEXT,
  config_sha256 TEXT, log_path TEXT, log_sha256 TEXT, payload TEXT NOT NULL,
  PRIMARY KEY(session_id, instance_id)
);
CREATE INDEX IF NOT EXISTS evidence_server_instance_name
  ON evidence_server_instances(session_id, name, scope);
CREATE TABLE IF NOT EXISTS evidence_test_server_links (
  session_id TEXT NOT NULL, case_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  nodeid TEXT NOT NULL, instance_id TEXT NOT NULL,
  PRIMARY KEY(session_id, attempt_id, instance_id)
);
CREATE INDEX IF NOT EXISTS evidence_tests_by_server
  ON evidence_test_server_links(session_id, instance_id, nodeid);
CREATE TABLE IF NOT EXISTS evidence_resource_nodes (
  session_id TEXT NOT NULL, case_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  nodeid TEXT NOT NULL, resource_id TEXT NOT NULL, kind TEXT NOT NULL,
  name TEXT NOT NULL, backend TEXT NOT NULL, environment TEXT NOT NULL,
  execution_group TEXT NOT NULL, fingerprint TEXT NOT NULL,
  requirements TEXT NOT NULL, payload TEXT NOT NULL,
  PRIMARY KEY(session_id, attempt_id, resource_id)
);
CREATE INDEX IF NOT EXISTS evidence_resources_by_kind
  ON evidence_resource_nodes(session_id, kind, backend, name);
CREATE TABLE IF NOT EXISTS evidence_resource_links (
  session_id TEXT NOT NULL, case_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  nodeid TEXT NOT NULL, ordinal INTEGER NOT NULL, source TEXT NOT NULL,
  target TEXT NOT NULL, relation TEXT NOT NULL, graph_fingerprint TEXT NOT NULL,
  payload TEXT NOT NULL,
  PRIMARY KEY(session_id, attempt_id, ordinal)
);
CREATE INDEX IF NOT EXISTS evidence_resource_relationships
  ON evidence_resource_links(session_id, relation, source, target);
CREATE TABLE IF NOT EXISTS evidence_test_resource_links (
  session_id TEXT NOT NULL, case_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  nodeid TEXT NOT NULL, resource_id TEXT NOT NULL,
  PRIMARY KEY(session_id, attempt_id, resource_id)
);
CREATE INDEX IF NOT EXISTS evidence_tests_by_resource
  ON evidence_test_resource_links(session_id, resource_id, nodeid);
CREATE VIEW IF NOT EXISTS evidence_latest_metrics AS
  SELECT * FROM evidence_metrics WHERE session_id = (
    SELECT session_id FROM sessions ORDER BY generated_at DESC LIMIT 1
  );
"""


def _text(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def initialize(connection: sqlite3.Connection, generated_at: str = "") -> None:
    connection.executescript(_SCHEMA)
    columns = {
        str(row[1]) for row in connection.execute(
            "PRAGMA table_info(evidence_server_instances)"
        )
    }
    for name in (
        "ports", "config_filename", "config_source_sha256",
        "config_declared_sha256", "config_sha256",
    ):
        if name not in columns:
            connection.execute(
                "ALTER TABLE evidence_server_instances ADD COLUMN %s TEXT" % name
            )
    connection.execute(
        "INSERT OR REPLACE INTO evidence_schema(name, version, updated_at) VALUES(?, ?, ?)",
        ("brixtest.evidence", SCHEMA_VERSION, generated_at),
    )


def write_entities(connection: sqlite3.Connection, payload: Mapping[str, object]) -> None:
    session = normalize_session(payload)
    session_id = str(session["session_id"])
    initialize(connection, str(session.get("generated_at", "")))
    connection.execute("DELETE FROM evidence_entities WHERE session_id = ?", (session_id,))
    connection.execute("DELETE FROM evidence_attempts WHERE session_id = ?", (session_id,))
    connection.execute("DELETE FROM evidence_metrics WHERE session_id = ?", (session_id,))
    connection.execute("DELETE FROM evidence_server_pools WHERE session_id = ?", (session_id,))
    connection.execute("DELETE FROM evidence_server_instances WHERE session_id = ?", (session_id,))
    connection.execute("DELETE FROM evidence_test_server_links WHERE session_id = ?", (session_id,))
    connection.execute("DELETE FROM evidence_resource_nodes WHERE session_id = ?", (session_id,))
    connection.execute("DELETE FROM evidence_resource_links WHERE session_id = ?", (session_id,))
    connection.execute("DELETE FROM evidence_test_resource_links WHERE session_id = ?", (session_id,))
    for row in iter_entities(session):
        _write_entity(connection, session_id, row)


def _entity_fields(row: Mapping[str, object]) -> dict[str, object]:
    raw_value = row.get("value")
    return {
        "entity": str(row.get("entity", "")),
        "case_id": str(row.get("case_id", "")),
        "attempt_id": str(row.get("attempt_id", "")),
        "ordinal": int(row.get("ordinal", 0)),
        "nodeid": str(row.get("nodeid", "")),
        "timestamp": str(row.get("timestamp", row.get("started_at", ""))),
        "name": str(row.get("name", "")),
        "value": raw_value if isinstance(raw_value, (int, float)) else None,
        "unit": str(row.get("unit", "")),
    }


def _write_entity(
    connection: sqlite3.Connection, session_id: str, row: Mapping[str, object],
) -> None:
    fields = _entity_fields(row)
    connection.execute(
        "INSERT OR REPLACE INTO evidence_entities VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (session_id, fields["entity"], fields["case_id"], fields["attempt_id"],
         fields["ordinal"], fields["nodeid"], fields["timestamp"], fields["name"],
         fields["value"], fields["unit"], _text(row)),
    )
    handlers = {
        "attempt": _write_attempt,
        "metric": _write_metric,
        "server-pool": _write_server_pool,
        "server-instance": _write_server_instance,
        "resource-node": _write_resource_node,
        "resource-link": _write_resource_link,
    }
    handler = handlers.get(str(fields["entity"]))
    if handler is not None:
        handler(connection, session_id, row, fields)


def _write_attempt(connection, session_id, row, fields) -> None:
    connection.execute(
        "INSERT OR REPLACE INTO evidence_attempts VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (session_id, fields["case_id"], fields["attempt_id"], fields["nodeid"],
         int(row.get("trial", 0)), int(bool(row.get("warmup"))),
         str(row.get("outcome", "")), str(row.get("started_at", "")),
         float(row.get("wall_seconds", 0)), str(row.get("run_root", "")),
         str(row.get("error", "")), _text(row)),
    )


def _write_metric(connection, session_id, row, fields) -> None:
    connection.execute(
        "INSERT OR REPLACE INTO evidence_metrics VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (session_id, fields["case_id"], fields["attempt_id"], fields["nodeid"],
         fields["ordinal"], fields["name"], float(row.get("value", 0)), fields["unit"],
         str(row.get("kind", "")), _text(row.get("labels", {})),
         float(row.get("at_seconds", 0)), int(row.get("trial", 0)), _text(row)),
    )


def _write_server_pool(connection, session_id, row, fields) -> None:
    result = row.get("result", {})
    result = result if isinstance(result, Mapping) else {}
    connection.execute(
        "INSERT OR REPLACE INTO evidence_server_pools VALUES(?, ?, ?, ?, ?, ?)",
        (session_id, str(row.get("pool_id", "")), str(result.get("outcome", "")),
         str(result.get("started_at", "")), str(result.get("stopped_at", "")), _text(row)),
    )


def _write_server_instance(connection, session_id, row, fields) -> None:
    instance_id = str(row.get("instance_id", ""))
    if not instance_id:
        return
    artifact = row.get("log_artifact", {})
    artifact = artifact if isinstance(artifact, Mapping) else {}
    connection.execute(
        "INSERT OR REPLACE INTO evidence_server_instances "
        "(session_id, instance_id, pool_id, name, scope, ports, started_at, stopped_at, "
        "config_path, config_filename, config_source_sha256, config_declared_sha256, "
        "config_sha256, log_path, log_sha256, payload) "
        "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (session_id, instance_id, str(row.get("pool_id", "")), str(row.get("name", "")),
         str(row.get("scope", "case")), _text(row.get("ports", {})),
         str(row.get("started_at", "")), str(row.get("stopped_at", "")),
         str(row.get("config", "")), str(row.get("config_filename", "")),
         str(row.get("config_source_sha256", "")),
         str(row.get("config_declared_sha256", "")), str(row.get("config_sha256", "")),
         str(artifact.get("relative", row.get("log", ""))), str(artifact.get("sha256", "")),
         _text(row)),
    )
    if fields["case_id"] and not str(fields["nodeid"]).startswith("@shared/"):
        connection.execute(
            "INSERT OR REPLACE INTO evidence_test_server_links VALUES(?, ?, ?, ?, ?)",
            (session_id, fields["case_id"], fields["attempt_id"], fields["nodeid"], instance_id),
        )


def _write_resource_node(connection, session_id, row, fields) -> None:
    resource_id = str(row.get("resource_id", row.get("id", "")))
    if not resource_id:
        return
    connection.execute(
        "INSERT OR REPLACE INTO evidence_resource_nodes VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (session_id, fields["case_id"], fields["attempt_id"], fields["nodeid"],
         resource_id, str(row.get("kind", "")), str(row.get("name", "")),
         str(row.get("backend", "")), str(row.get("environment", "")),
         str(row.get("group", "")), str(row.get("fingerprint", "")),
         _text(row.get("requires", ())), _text(row)),
    )
    connection.execute(
        "INSERT OR REPLACE INTO evidence_test_resource_links VALUES(?, ?, ?, ?, ?)",
        (session_id, fields["case_id"], fields["attempt_id"], fields["nodeid"], resource_id),
    )


def _write_resource_link(connection, session_id, row, fields) -> None:
    connection.execute(
        "INSERT OR REPLACE INTO evidence_resource_links VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (session_id, fields["case_id"], fields["attempt_id"], fields["nodeid"],
         fields["ordinal"], str(row.get("source", "")), str(row.get("target", "")),
         str(row.get("relation", "")), str(row.get("graph_fingerprint", "")),
         _text(row)),
    )


def query(path: Path, sql: str, parameters: Sequence[object] = ()) -> dict:
    """Execute one read-only SELECT/CTE and return named rows."""
    statement = _query_statement(sql)
    return _execute_query(path, sql, statement, parameters)


def _query_statement(sql: str) -> str:
    statement = sql.strip()
    first = statement.split(None, 1)[0].lower() if statement else ""
    if first not in ("select", "with", "pragma", "explain") or ";" in statement.rstrip(";"):
        raise SpecError("evidence query", sql, "must be one read-only SQL statement")
    return statement


def _execute_query(
    path: Path, sql: str, statement: str, parameters: Sequence[object],
) -> dict:
    uri = "file:%s?mode=ro" % Path(path).resolve()
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    try:
        cursor = connection.execute(statement, tuple(parameters))
        columns = _column_names(cursor.description)
        rows = [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as exc:
        raise SpecError("evidence query", sql, str(exc)) from exc
    finally:
        connection.close()
    return {"columns": columns, "rows": rows}


def _column_names(description) -> list[str]:
    return [item[0] for item in (description or ())]


def integrity(path: Path) -> dict:
    connection = sqlite3.connect("file:%s?mode=ro" % Path(path).resolve(), uri=True)
    try:
        result = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        version = connection.execute(
            "SELECT version FROM evidence_schema WHERE name = ?", ("brixtest.evidence",)
        ).fetchone()
    finally:
        connection.close()
    return {"ok": result == "ok", "detail": result, "schema": version[0] if version else None}


def query_duckdb(path: Path, sql: str) -> dict:
    """Query a Parquet evidence export through optional embedded DuckDB."""
    statement = sql.strip()
    if not statement.lower().startswith(("select", "with", "explain")) \
            or ";" in statement.rstrip(";"):
        raise SpecError("DuckDB query", sql, "must be one read-only SQL statement")
    try:
        import duckdb
    except ImportError as exc:
        raise SpecError("DuckDB query", str(path), "install brixtest[analytics]") from exc
    connection = duckdb.connect(":memory:")
    try:
        connection.execute("CREATE VIEW evidence AS SELECT * FROM read_parquet(?)", [str(Path(path))])
        cursor = connection.execute(statement)
        columns = [item[0] for item in cursor.description]
        rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
    except Exception as exc:
        raise SpecError("DuckDB query", sql, str(exc)) from exc
    finally:
        connection.close()
    return {"columns": columns, "rows": rows}
