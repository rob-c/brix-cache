"""The run store (feature F22): every run catalogued, queryable, exportable.

SQLite because it is stdlib, transactional, and a single file inside
the lane (``<lane>/results/brixtest.db``) — the portal, the CLI, and
any ad-hoc ``sqlite3`` session all read the same catalogue.  OpenSearch
is an **export target**, not a dependency: ``export_opensearch`` emits
bulk-API JSONL (action line + document line) so an upload is one curl,
and the schema of the documents is the schema of the tables.

Writes are serialized behind one lock (the resource sampler writes
from its own thread); the schema carries a version stamp and refuses a
future schema rather than corrupting it.
"""

from __future__ import annotations

import dataclasses
import json
import sqlite3
import threading
from pathlib import Path
from typing import List, Optional, Sequence

from brixtest.errors import RunStoreError
from brixtest.results.model import Finding, PhaseResult, RunInfo, Sample, TestRecord

__all__ = ["ResultStore"]

_SCHEMA_VERSION = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_info (version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL DEFAULT '',
    lane_root TEXT NOT NULL,
    port_base INTEGER NOT NULL,
    hostname TEXT NOT NULL,
    wall_seconds REAL NOT NULL DEFAULT 0,
    counts_json TEXT NOT NULL DEFAULT '{}',
    meta_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS tests (
    run_id TEXT NOT NULL,
    nodeid TEXT NOT NULL,
    outcome TEXT NOT NULL,
    started_at TEXT NOT NULL,
    wall_seconds REAL NOT NULL,
    setup_seconds REAL NOT NULL DEFAULT 0,
    call_seconds REAL NOT NULL DEFAULT 0,
    teardown_seconds REAL NOT NULL DEFAULT 0,
    output_dir TEXT NOT NULL DEFAULT '',
    workspace TEXT NOT NULL DEFAULT '',
    servers_json TEXT NOT NULL DEFAULT '[]',
    dynamic_json TEXT NOT NULL DEFAULT '[]',
    artifacts_json TEXT NOT NULL DEFAULT '[]',
    markers_json TEXT NOT NULL DEFAULT '[]',
    params_json TEXT NOT NULL DEFAULT '{}',
    failure TEXT NOT NULL DEFAULT '',
    cpu_seconds REAL NOT NULL DEFAULT 0,
    rss_delta_kb INTEGER NOT NULL DEFAULT 0,
    maxrss_kb INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, nodeid)
);
CREATE TABLE IF NOT EXISTS samples (
    run_id TEXT NOT NULL,
    instance TEXT NOT NULL,
    ts REAL NOT NULL,
    pid INTEGER NOT NULL,
    rss_kb INTEGER NOT NULL,
    cpu_pct REAL NOT NULL,
    during_test TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS samples_by_instance ON samples (run_id, instance, ts);
CREATE TABLE IF NOT EXISTS findings (
    run_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    instance TEXT NOT NULL,
    detail TEXT NOT NULL,
    during_test TEXT NOT NULL DEFAULT '',
    at TEXT NOT NULL
);
"""


class ResultStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        row = self._conn.execute("SELECT version FROM schema_info").fetchone()
        if row is None:
            self._conn.execute("INSERT INTO schema_info VALUES (?)", (_SCHEMA_VERSION,))
            self._conn.commit()
        elif row[0] > _SCHEMA_VERSION:
            raise RunStoreError(
                str(self.db_path),
                "written by schema v%d, this brixtest speaks v%d — "
                "refusing to touch it" % (row[0], _SCHEMA_VERSION),
            )
        elif row[0] < _SCHEMA_VERSION:
            self._migrate()

    def _migrate(self) -> None:
        """v1 → v2: the per-test cost columns.  Guarded per column so a
        half-applied upgrade converges instead of failing on a rerun."""
        have = {r[1] for r in self._conn.execute("PRAGMA table_info(tests)")}
        for column, decl in (
            ("cpu_seconds", "REAL NOT NULL DEFAULT 0"),
            ("rss_delta_kb", "INTEGER NOT NULL DEFAULT 0"),
            ("maxrss_kb", "INTEGER NOT NULL DEFAULT 0"),
        ):
            if column not in have:
                self._conn.execute(
                    "ALTER TABLE tests ADD COLUMN %s %s" % (column, decl)
                )
        self._conn.execute("UPDATE schema_info SET version=?", (_SCHEMA_VERSION,))
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- writes ----------------------------------------------------------

    def begin_run(self, info: RunInfo) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO runs "
                "(run_id, started_at, lane_root, port_base, hostname, meta_json) "
                "VALUES (?,?,?,?,?,?)",
                (info.run_id, info.started_at, info.lane_root, info.port_base,
                 info.hostname, json.dumps(info.meta, sort_keys=True)),
            )
            self._conn.commit()

    def finish_run(self, info: RunInfo) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE runs SET finished_at=?, wall_seconds=?, counts_json=? "
                "WHERE run_id=?",
                (info.finished_at, info.wall_seconds,
                 json.dumps(info.counts, sort_keys=True), info.run_id),
            )
            self._conn.commit()

    def add_test(self, record: TestRecord) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO tests VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (record.run_id, record.nodeid, record.outcome, record.started_at,
                 record.wall_seconds,
                 record.phase_seconds("setup"), record.phase_seconds("call"),
                 record.phase_seconds("teardown"),
                 record.output_dir, record.workspace,
                 json.dumps(record.servers), json.dumps(record.dynamic_servers),
                 json.dumps(record.artifacts), json.dumps(record.markers),
                 json.dumps(record.params, sort_keys=True), record.failure,
                 record.cpu_seconds, record.rss_delta_kb, record.maxrss_kb),
            )
            self._conn.commit()

    def add_samples(self, run_id: str, samples: Sequence[Sample]) -> None:
        if not samples:
            return
        with self._lock:
            self._conn.executemany(
                "INSERT INTO samples VALUES (?,?,?,?,?,?,?)",
                [(run_id, s.instance, s.ts, s.pid, s.rss_kb, s.cpu_pct,
                  s.during_test) for s in samples],
            )
            self._conn.commit()

    def add_finding(self, run_id: str, finding: Finding) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO findings VALUES (?,?,?,?,?,?)",
                (run_id, finding.kind, finding.instance, finding.detail,
                 finding.during_test, finding.at),
            )
            self._conn.commit()

    # -- reads -----------------------------------------------------------

    def runs(self) -> List[RunInfo]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT run_id, started_at, finished_at, lane_root, port_base, "
                "hostname, wall_seconds, counts_json, meta_json "
                "FROM runs ORDER BY started_at DESC"
            ).fetchall()
        return [
            RunInfo(run_id=r[0], started_at=r[1], finished_at=r[2], lane_root=r[3],
                    port_base=r[4], hostname=r[5], wall_seconds=r[6],
                    counts=json.loads(r[7]), meta=json.loads(r[8]))
            for r in rows
        ]

    def latest_run_id(self) -> Optional[str]:
        all_runs = self.runs()
        return all_runs[0].run_id if all_runs else None

    def tests(self, run_id: str) -> List[TestRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM tests WHERE run_id=? ORDER BY started_at", (run_id,)
            ).fetchall()
        records = []
        for r in rows:
            record = TestRecord(
                run_id=r[0], nodeid=r[1], outcome=r[2], started_at=r[3],
                wall_seconds=r[4], output_dir=r[8], workspace=r[9],
                servers=json.loads(r[10]), dynamic_servers=json.loads(r[11]),
                artifacts=json.loads(r[12]), markers=json.loads(r[13]),
                params=json.loads(r[14]), failure=r[15],
                cpu_seconds=r[16], rss_delta_kb=r[17], maxrss_kb=r[18],
            )
            for phase, seconds in (("setup", r[5]), ("call", r[6]), ("teardown", r[7])):
                record.phases.append(PhaseResult(phase, "-", seconds))
            records.append(record)
        return records

    def findings(self, run_id: str) -> List[Finding]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT kind, instance, detail, during_test, at FROM findings "
                "WHERE run_id=? ORDER BY at", (run_id,)
            ).fetchall()
        return [Finding(*r) for r in rows]

    def sample_series(self, run_id: str, instance: str) -> List[tuple]:
        """(ts, rss_kb, cpu_pct) ascending — the portal's timelines."""
        with self._lock:
            return self._conn.execute(
                "SELECT ts, rss_kb, cpu_pct FROM samples "
                "WHERE run_id=? AND instance=? ORDER BY ts",
                (run_id, instance),
            ).fetchall()

    def instance_stats(self, run_id: str) -> List[tuple]:
        """(instance, samples, max_rss_kb, mean_cpu, max_cpu, first_rss, last_rss)."""
        with self._lock:
            return self._conn.execute(
                "SELECT instance, COUNT(*), MAX(rss_kb), AVG(cpu_pct), MAX(cpu_pct), "
                "(SELECT rss_kb FROM samples s2 WHERE s2.run_id=s.run_id AND "
                " s2.instance=s.instance ORDER BY ts LIMIT 1), "
                "(SELECT rss_kb FROM samples s3 WHERE s3.run_id=s.run_id AND "
                " s3.instance=s.instance ORDER BY ts DESC LIMIT 1) "
                "FROM samples s WHERE run_id=? GROUP BY instance ORDER BY instance",
                (run_id,),
            ).fetchall()

    # -- export ----------------------------------------------------------

    def export_opensearch(self, run_id: str, out_path: Path,
                          index_prefix: str = "brixtest") -> int:
        """Bulk-API JSONL: `{index:{...}}` action line + document line per
        record, across tests, findings, and instance stats.  Returns the
        number of documents written."""
        out_path = Path(out_path)
        count = 0
        with out_path.open("w") as out:
            def doc(index: str, _id: Optional[str], body: dict) -> None:
                nonlocal count
                action = {"index": {"_index": "%s-%s" % (index_prefix, index)}}
                if _id:
                    action["index"]["_id"] = _id
                out.write(json.dumps(action) + "\n")
                out.write(json.dumps(body, sort_keys=True) + "\n")
                count += 1

            for record in self.tests(run_id):
                body = dataclasses.asdict(record)
                body.pop("phases", None)
                for phase in ("setup", "call", "teardown"):
                    body["%s_seconds" % phase] = record.phase_seconds(phase)
                doc("tests", "%s:%s" % (run_id, record.nodeid), body)
            for finding in self.findings(run_id):
                doc("findings", None, dict(dataclasses.asdict(finding), run_id=run_id))
            for row in self.instance_stats(run_id):
                doc("instances", "%s:%s" % (run_id, row[0]), {
                    "run_id": run_id, "instance": row[0], "samples": row[1],
                    "max_rss_kb": row[2], "mean_cpu_pct": round(row[3] or 0, 2),
                    "max_cpu_pct": row[4], "first_rss_kb": row[5],
                    "last_rss_kb": row[6],
                })
        return count
