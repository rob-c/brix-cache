"""Self-contained correlated session report with no external assets."""

from __future__ import annotations

import html
import json
from typing import Mapping

from brixtest.evidence.model import normalize_session


def _escape(value: object) -> str:
    return html.escape(str(value))


def _number(value: object) -> str:
    try:
        return "%.6g" % float(value)
    except (TypeError, ValueError):
        return _escape(value)


def _rows(session: Mapping[str, object]) -> tuple[str, str, str]:
    cases, findings, artifacts = [], [], []
    for case in session["tests"]:
        attempts = case.get("attempts", [])
        measured = sum(not bool(row.get("warmup")) for row in attempts)
        resources = sum(len(row.get("resources", [])) for row in attempts)
        spans = sum(len(row.get("spans", [])) for row in attempts)
        cases.append(
            "<tr data-key='%s'><td>%s</td><td class='%s'>%s</td><td>%s</td>"
            "<td class=n>%s</td><td class=n>%s</td><td class=n>%s</td>"
            "<td class=n>%s</td></tr>" % (
                _escape(str(case.get("nodeid", "")).lower()), _escape(case.get("nodeid", "")),
                _escape(case.get("outcome", "")), _escape(case.get("outcome", "")),
                _escape(case.get("backend", "")), measured, _number(case.get("wall_seconds", 0)),
                resources, spans,
            )
        )
        for attempt in attempts:
            for finding in attempt.get("findings", []):
                findings.append("<tr><td>%s</td><td>%s</td><td class='%s'>%s</td><td>%s</td></tr>" % (
                    _escape(case.get("nodeid", "")), _escape(finding.get("kind", "")),
                    _escape(finding.get("severity", "warning")),
                    _escape(finding.get("severity", "warning")),
                    _escape(finding.get("detail", finding)),
                ))
            for item in attempt.get("artifacts", []):
                artifacts.append("<tr><td>%s</td><td>%s</td><td>%s</td><td class=n>%s</td>"
                                 "<td><code>%s</code></td></tr>" % (
                    _escape(case.get("nodeid", "")), _escape(item.get("name", "")),
                    _escape(item.get("media_type", "")), _number(item.get("size", 0)),
                    _escape(str(item.get("sha256", ""))[:16]),
                ))
    return "".join(cases), "".join(findings), "".join(artifacts)


def _metric_rows(session: Mapping[str, object]) -> str:
    rows = []
    for metric in session.get("aggregates", []):
        labels = dict(metric.get("labels", {}))
        suffix = "{%s}" % ",".join("%s=%s" % item for item in sorted(labels.items())) \
            if labels else ""
        rows.append("<tr><td>%s%s</td><td>%s</td><td class=n>%s</td>"
                    "<td class=n>%s</td><td class=n>%s</td><td class=n>%s</td></tr>" % (
            _escape(metric.get("name", "")), _escape(suffix), _escape(metric.get("unit", "")),
            _number(metric.get("samples", 0)), _number(metric.get("mean", 0)),
            _number(metric.get("p95", 0)), _number(metric.get("max", 0)),
        ))
    return "".join(rows)


def _timeline_rows(session: Mapping[str, object]) -> str:
    rows = []
    for case in session["tests"]:
        for attempt in case.get("attempts", []):
            wall = max(float(attempt.get("wall_seconds", 0)), 0.000001)
            bars = []
            for span in attempt.get("spans", []):
                left = min(100.0, 100.0 * float(span.get("start_seconds", 0)) / wall)
                width = max(0.4, min(100.0 - left,
                    100.0 * float(span.get("duration_seconds", 0)) / wall))
                bars.append("<span class=bar style='left:%.3f%%;width:%.3f%%' title='%s: %ss'></span>" % (
                    left, width, _escape(span.get("name", "span")),
                    _number(span.get("duration_seconds", 0)),
                ))
            rows.append("<tr><td>%s</td><td>%s%s</td><td class=n>%s</td><td><div class=track>%s</div></td></tr>" % (
                _escape(case.get("nodeid", "")), "warmup " if attempt.get("warmup") else "trial ",
                _escape(attempt.get("trial", 0)), _number(wall), "".join(bars),
            ))
    return "".join(rows)


def _provenance_rows(session: Mapping[str, object]) -> str:
    rows = []
    for case in session["tests"]:
        for attempt in case.get("attempts", []):
            provenance = dict(attempt.get("provenance", {}))
            source = dict(provenance.get("source", {}))
            runtime = dict(provenance.get("runtime", {}))
            rows.append("<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>" % (
                _escape(case.get("nodeid", "")), _escape(attempt.get("trial", 0)),
                _escape(str(source.get("git_commit", ""))[:12]),
                _escape(runtime.get("backend", case.get("backend", ""))),
                _escape(runtime.get("platform", "")),
            ))
    return "".join(rows)


def _server_rows(session: Mapping[str, object]) -> str:
    instances, links = {}, {}
    for case in session["tests"]:
        for attempt in case.get("attempts", []):
            for server in attempt.get("servers", []):
                instance_id = str(server.get("instance_id", ""))
                if not instance_id:
                    continue
                instances[instance_id] = dict(server)
                links.setdefault(instance_id, set()).add(str(case.get("nodeid", "")))
    topology = session.get("topology", {})
    pools = topology.get("pools", []) if isinstance(topology, Mapping) else []
    for pool in pools if isinstance(pools, list) else []:
        services = pool.get("services", {}) if isinstance(pool, Mapping) else {}
        for server in services.values() if isinstance(services, Mapping) else []:
            if isinstance(server, Mapping) and server.get("instance_id"):
                instances[str(server["instance_id"])] = dict(server)
    rows = []
    for instance_id, server in sorted(instances.items(), key=lambda item: (
        str(item[1].get("scope", "")), str(item[1].get("name", "")), item[0]
    )):
        artifact = server.get("log_artifact", {})
        artifact = artifact if isinstance(artifact, Mapping) else {}
        ports = server.get("ports", {})
        ports = ports if isinstance(ports, Mapping) else {}
        rows.append(
            "<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td>"
            "<td>%s</td><td><code>%s</code></td><td class=n>%s</td>"
            "<td>%s</td><td><code>%s</code></td></tr>" % (
                _escape(server.get("name", "")), _escape(server.get("scope", "")),
                _escape(instance_id[:16]),
                _escape(", ".join("%s=%s" % item for item in sorted(ports.items()))),
                _escape(server.get("config_filename", "")),
                _escape(str(server.get("config_sha256", ""))[:16]),
                len(links.get(instance_id, set())),
                _escape(", ".join(sorted(links.get(instance_id, set())))),
                _escape(str(artifact.get("sha256", ""))[:16]),
            )
        )
    return "".join(rows)


def _insight_rows(session: Mapping[str, object]) -> tuple[str, str, str]:
    raw = session.get("analysis", {})
    analysis = raw if isinstance(raw, Mapping) else {}
    correlations = []
    for row in analysis.get("correlations", []):
        if not isinstance(row, Mapping):
            continue
        correlations.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td class=n>%s</td>"
            "<td class=n>%s</td><td class=n>%s</td></tr>" % (
                _escape(row.get("nodeid", "")), _escape(row.get("left", "")),
                _escape(row.get("right", "")), _number(row.get("samples", 0)),
                _number(row.get("pearson", 0)), _number(row.get("spearman", 0)),
            )
        )
    outliers = []
    for row in analysis.get("outliers", []):
        if not isinstance(row, Mapping):
            continue
        outliers.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td class=n>%s</td>"
            "<td class=n>%s</td><td>%s</td></tr>" % (
                _escape(row.get("nodeid", "")), _escape(row.get("attempt_id", "")),
                _escape(row.get("series", "")), _number(row.get("value", 0)),
                _number(row.get("score", 0)), _escape(row.get("method", "")),
            )
        )
    evidence = analysis.get("evidence", {})
    coverage = []
    if isinstance(evidence, Mapping):
        for name, raw_row in sorted(evidence.items()):
            if not isinstance(raw_row, Mapping):
                continue
            coverage.append(
                "<tr><td>%s</td><td class=n>%s</td><td class=n>%s</td>"
                "<td class=n>%s</td></tr>" % (
                    _escape(name), _number(raw_row.get("count", 0)),
                    _number(raw_row.get("bytes", 0)),
                    _number(raw_row.get(
                        "checksum_coverage",
                        min(
                            float(raw_row.get("config_checksum_coverage", 1)),
                            float(raw_row.get("log_checksum_coverage", 1)),
                        ),
                    )),
                )
            )
    return "".join(correlations), "".join(outliers), "".join(coverage)


def render(payload: Mapping[str, object]) -> str:
    session = normalize_session(payload)
    case_rows, finding_rows, artifact_rows = _rows(session)
    metric_rows = _metric_rows(session)
    timeline_rows = _timeline_rows(session)
    provenance_rows = _provenance_rows(session)
    server_rows = _server_rows(session)
    correlation_rows, outlier_rows, coverage_rows = _insight_rows(session)
    counts = " · ".join("%s %s" % (value, key)
                        for key, value in sorted(session.get("counts", {}).items()))
    embedded = html.escape(json.dumps(session, separators=(",", ":"), default=str))
    return """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width"><title>BriXTest metrics and evidence</title><style>
:root{color-scheme:dark}body{margin:0;background:#0b1117;color:#dbe7f3;font:14px/1.5 system-ui,sans-serif}
main{max-width:96rem;margin:auto;padding:1.5rem}h1{margin:0;color:#f4f8fb}h2{margin-top:2rem;color:#a9c4dc}
.meta{color:#86a0b7}.cards{display:flex;gap:1rem;flex-wrap:wrap}.card{background:#121d27;padding:.8rem 1rem;border-radius:7px}
.scroller{overflow:auto}table{border-collapse:collapse;width:100%%}th,td{padding:.45rem .6rem;border-bottom:1px solid #263746;text-align:left}
th{color:#a9c4dc;position:sticky;top:0;background:#0b1117}.n{text-align:right;font-variant-numeric:tabular-nums}
.passed,.info{color:#63d391}.failed,.error{color:#ff7373}.warning{color:#ffc760}.skipped{color:#94a7bc}
.track{position:relative;min-width:18rem;height:1rem;background:#172531;border-radius:3px}.bar{position:absolute;height:100%%;background:#4e9bd1;border-radius:3px}
input{width:100%%;box-sizing:border-box;padding:.6rem;margin:.7rem 0;background:#121d27;color:inherit;border:1px solid #344b5f;border-radius:5px}
code{font-size:.85em}</style></head><body><main><h1>BriXTest evidence</h1>
<div class=meta>session %s · %s</div><div class=cards><div class=card>%d cases</div><div class=card>%s</div></div>
<h2>Metric aggregates</h2><div class=scroller><table><thead><tr><th>metric</th><th>unit</th><th>n</th><th>mean</th><th>p95</th><th>max</th></tr></thead><tbody>%s</tbody></table></div>
<h2>Cases</h2><input id=q placeholder="filter cases"><div class=scroller><table><thead><tr><th>test</th><th>outcome</th><th>backend</th><th>trials</th><th>wall s</th><th>resources</th><th>spans</th></tr></thead><tbody id=cases>%s</tbody></table></div>
<h2>Server instances</h2><div class=scroller><table><thead><tr><th>server</th><th>scope</th><th>instance</th><th>ports</th><th>config</th><th>config sha256</th><th>tests</th><th>consumers</th><th>log sha256</th></tr></thead><tbody>%s</tbody></table></div>
<h2>Correlated timeline</h2><div class=scroller><table><thead><tr><th>test</th><th>attempt</th><th>wall s</th><th>spans over attempt time</th></tr></thead><tbody>%s</tbody></table></div>
<h2>Cross-signal correlations</h2><div class=scroller><table><thead><tr><th>test</th><th>left</th><th>right</th><th>n</th><th>Pearson</th><th>Spearman</th></tr></thead><tbody>%s</tbody></table></div>
<h2>Robust outliers</h2><div class=scroller><table><thead><tr><th>test</th><th>attempt</th><th>series</th><th>value</th><th>score</th><th>method</th></tr></thead><tbody>%s</tbody></table></div>
<h2>Evidence integrity coverage</h2><div class=scroller><table><thead><tr><th>kind</th><th>items</th><th>bytes</th><th>checksum ratio</th></tr></thead><tbody>%s</tbody></table></div>
<h2>Findings</h2><div class=scroller><table><thead><tr><th>test</th><th>kind</th><th>severity</th><th>detail</th></tr></thead><tbody>%s</tbody></table></div>
<h2>Attachments</h2><div class=scroller><table><thead><tr><th>test</th><th>name</th><th>type</th><th>bytes</th><th>sha256</th></tr></thead><tbody>%s</tbody></table></div>
<h2>Provenance</h2><div class=scroller><table><thead><tr><th>test</th><th>trial</th><th>commit</th><th>backend</th><th>platform</th></tr></thead><tbody>%s</tbody></table></div>
<details><summary>machine-readable evidence</summary><pre id=data>%s</pre></details></main>
<script>q.oninput=e=>document.querySelectorAll('#cases tr').forEach(r=>r.hidden=!r.dataset.key.includes(e.target.value.toLowerCase()))</script></body></html>""" % (
        _escape(session.get("session_id", "")), _escape(session.get("generated_at", "")),
        len(session["tests"]), _escape(counts), metric_rows, case_rows, server_rows, timeline_rows,
        correlation_rows, outlier_rows, coverage_rows,
        finding_rows, artifact_rows, provenance_rows, embedded,
    )
