"""Render and serve self-contained HTML reports from stored test runs.

Reports use inline assets and contain only data already present in the result
store. The HTTP server exposes the result directory without modifying it.
"""

from __future__ import annotations

import functools
import html
import http.server
import json
from pathlib import Path
from typing import List

from brixtest.errors import RunStoreError
from brixtest.results.charts import resources_section
from brixtest.results.mapping import matrix_html, observed_rows
from brixtest.results.model import TestRecord
from brixtest.results.store import ResultStore

__all__ = ["serve", "write_index", "write_report"]

_OUTCOME_ORDER = ("failed", "error", "xpassed", "xfailed", "skipped", "passed")

_CSS = """
body { margin: 0; font: 14px/1.5 system-ui, sans-serif;
       background: #101418; color: #d8dee6; }
main { max-width: 72rem; margin: 0 auto; padding: 1.5rem; }
h1 { font-size: 1.3rem; margin: 0 0 .25rem; }
h2 { font-size: 1.05rem; margin: 2rem 0 .75rem; color: #9fb2c8; }
.meta { color: #7d8a99; font-size: .85rem; }
.tiles { display: flex; flex-wrap: wrap; gap: .75rem; margin: 1.25rem 0; }
.tile { background: #1a2129; border-radius: 8px; padding: .6rem 1.1rem;
        min-width: 5.5rem; text-align: center; }
.tile b { display: block; font-size: 1.4rem; }
.tile.passed b { color: #5fd38a; } .tile.failed b { color: #ff6b6b; }
.tile.error b { color: #ffab5e; } .tile.skipped b { color: #8fa3bb; }
.tile.xfailed b, .tile.xpassed b { color: #c792ea; }
.findings .card { background: #2a1a1a; border-left: 4px solid #ff6b6b;
                  border-radius: 6px; padding: .6rem .9rem; margin: .5rem 0; }
.findings .card.leak { border-color: #ffab5e; background: #2a2418; }
.findings .card.cpu-spike { border-color: #c792ea; background: #241a2a; }
input#filter { width: 100%; box-sizing: border-box; padding: .5rem .75rem;
               border-radius: 6px; border: 1px solid #2c3743;
               background: #1a2129; color: inherit; margin-bottom: .5rem; }
.scroller { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: .85rem; }
th, td { text-align: left; padding: .4rem .6rem;
         border-bottom: 1px solid #222b35; vertical-align: top; }
th { cursor: pointer; color: #9fb2c8; white-space: nowrap;
     user-select: none; position: sticky; top: 0; background: #101418; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
tr.t { cursor: pointer; }
tr.t:hover { background: #161d24; }
.o { font-weight: 600; }
.o.passed { color: #5fd38a; } .o.failed { color: #ff6b6b; }
.o.error { color: #ffab5e; } .o.skipped { color: #8fa3bb; }
.o.xfailed, .o.xpassed { color: #c792ea; }
tr.detail { display: none; } tr.detail.open { display: table-row; }
tr.detail td { background: #151b22; }
pre { margin: .5rem 0; padding: .6rem; background: #0c1014; border-radius: 6px;
      overflow-x: auto; white-space: pre-wrap; word-break: break-word;
      font-size: .8rem; }
.kv { color: #7d8a99; } .kv code { color: #d8dee6; }
a { color: #6cb2ff; }
table.map td.dot { text-align: center; }
table.map td.dot.on { color: #5fd38a; }
table.map td.dot.off { color: #2c3743; }
table.map td.dot.dyn { color: #c792ea; font-weight: 600; }
th.rot { white-space: nowrap; }
svg.spark { display: block; }
"""

_JS = """
const filter = document.getElementById('filter');
if (filter) filter.addEventListener('input', () => {
  const q = filter.value.toLowerCase();
  document.querySelectorAll('tr.t').forEach(row => {
    const hit = row.dataset.key.includes(q);
    row.style.display = hit ? '' : 'none';
    const detail = document.getElementById('d-' + row.dataset.i);
    if (detail && !hit) detail.classList.remove('open');
  });
});
document.querySelectorAll('tr.t').forEach(row =>
  row.addEventListener('click', () =>
    document.getElementById('d-' + row.dataset.i).classList.toggle('open')));
document.querySelectorAll('th[data-col]').forEach(th =>
  th.addEventListener('click', () => {
    const col = +th.dataset.col, numeric = th.dataset.num === '1';
    const dir = th.dataset.dir === 'a' ? -1 : 1;
    th.dataset.dir = dir === 1 ? 'a' : 'd';
    const body = th.closest('table').tBodies[0];
    const rows = [...body.querySelectorAll('tr.t')];
    rows.sort((x, y) => {
      const a = x.cells[col].textContent, b = y.cells[col].textContent;
      return dir * (numeric ? (+a || 0) - (+b || 0) : a.localeCompare(b));
    });
    rows.forEach(r => {
      body.appendChild(r);
      body.appendChild(document.getElementById('d-' + r.dataset.i));
    });
  }));
"""


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>%s</title><style>%s</style></head><body><main>%s</main>"
        "<script>%s</script></body></html>"
        % (html.escape(title), _CSS, body, _JS)
    )


def _tiles(counts: dict) -> str:
    cells = [
        "<div class='tile %s'><b>%d</b>%s</div>"
        % (outcome, counts[outcome], outcome)
        for outcome in _OUTCOME_ORDER
        if counts.get(outcome)
    ]
    cells.append("<div class='tile'><b>%d</b>total</div>" % sum(counts.values()))
    return "<div class='tiles'>%s</div>" % "".join(cells)


def _detail(record: TestRecord) -> str:
    parts = [
        _detail_value(label, value)
        for label, value in _detail_pairs(record)
        if value
    ]
    if record.failure:
        parts.append("<pre>%s</pre>" % html.escape(record.failure))
    return "".join(parts) or "<span class='kv'>no captured detail</span>"


def _detail_pairs(record: TestRecord):
    return (
        ("servers", ", ".join(record.servers)),
        ("dynamic", ", ".join(record.dynamic_servers)),
        ("test ΔRSS kB", "%+d" % record.rss_delta_kb if record.rss_delta_kb else ""),
        ("test max RSS kB", str(record.maxrss_kb) if record.maxrss_kb else ""),
        ("artifacts", ", ".join(record.artifacts)),
        ("markers", ", ".join(record.markers)),
        ("params", json.dumps(record.params) if record.params else ""),
        ("workspace", record.workspace),
        ("output dir", record.output_dir),
    )


def _detail_value(label: str, value: str) -> str:
    return "<div class='kv'>%s: <code>%s</code></div>" % (label, html.escape(value))


def _tests_table(records: List[TestRecord]) -> str:
    head = (
        "<tr><th data-col='0'>test</th><th data-col='1'>outcome</th>"
        "<th data-col='2' data-num='1'>wall s</th>"
        "<th data-col='3' data-num='1'>setup s</th>"
        "<th data-col='4' data-num='1'>call s</th>"
        "<th data-col='5' data-num='1'>teardown s</th>"
        "<th data-col='6' data-num='1'>cpu s</th></tr>"
    )
    rows = []
    for i, record in enumerate(records):
        key = html.escape(
            ("%s %s %s" % (record.nodeid, record.outcome,
                           " ".join(record.markers))).lower()
        )
        rows.append(
            "<tr class='t' data-i='%d' data-key=\"%s\">"
            "<td>%s</td><td class='o %s'>%s</td>"
            "<td class='num'>%.2f</td><td class='num'>%.2f</td>"
            "<td class='num'>%.2f</td><td class='num'>%.2f</td>"
            "<td class='num'>%.2f</td></tr>"
            "<tr class='detail' id='d-%d'><td colspan='7'>%s</td></tr>"
            % (i, key, html.escape(record.nodeid), record.outcome,
               record.outcome, record.wall_seconds,
               record.phase_seconds("setup"), record.phase_seconds("call"),
               record.phase_seconds("teardown"), record.cpu_seconds,
               i, _detail(record))
        )
    return (
        "<input id='filter' placeholder='filter tests (name, outcome, marker)…'>"
        "<div class='scroller'><table><thead>%s</thead><tbody>%s</tbody>"
        "</table></div>" % (head, "".join(rows))
    )


def _findings_block(store: ResultStore, run_id: str) -> str:
    cards = [
        "<div class='card %s'><b>%s</b> — %s: %s%s</div>"
        % (finding.kind, finding.kind, html.escape(finding.instance),
           html.escape(finding.detail),
           " <span class='meta'>(during %s)</span>"
           % html.escape(finding.during_test) if finding.during_test else "")
        for finding in store.findings(run_id)
    ]
    if not cards:
        return "<p class='meta'>no crash / leak / CPU-spike findings.</p>"
    return "<div class='findings'>%s</div>" % "".join(cards)


def write_report(store: ResultStore, run_id: str, out_path: Path) -> Path:
    infos = [info for info in store.runs() if info.run_id == run_id]
    if not infos:
        raise RunStoreError(
            str(store.db_path),
            "run %r is not catalogued — try: brixtest results list" % run_id,
        )
    info = infos[0]
    records = store.tests(run_id)
    body = (
        "<h1>BriXTest run %s</h1>"
        "<div class='meta'>%s → %s · lane %s · port base %d · %s · "
        "%.1f s wall</div>%s"
        "<h2>Findings</h2>%s"
        "<h2>Tests (%d)</h2>%s"
        "<h2>Test ↔ server map</h2>%s"
        "<h2>Server resources</h2>%s"
        % (html.escape(info.run_id), html.escape(info.started_at),
           html.escape(info.finished_at or "…"), html.escape(info.lane_root),
           info.port_base, html.escape(info.hostname), info.wall_seconds,
           _tiles(info.counts), _findings_block(store, run_id),
           len(records), _tests_table(records),
           matrix_html(*observed_rows(records)),
           resources_section(store, run_id))
    )
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(_page("BriXTest run %s" % info.run_id, body))
    return out_path


def write_index(store: ResultStore, out_path: Path) -> Path:
    rows = "".join(
        "<tr class='t' data-i='%d' data-key='%s'>"
        "<td><a href='%s/report.html'>%s</a></td><td>%s</td>"
        "<td class='num'>%d</td><td class='o failed'>%d</td>"
        "<td class='num'>%.1f</td></tr><tr class='detail' id='d-%d'><td></td></tr>"
        % (i, html.escape(info.run_id), html.escape(info.run_id),
           html.escape(info.run_id), html.escape(info.started_at),
           info.total, info.counts.get("failed", 0) + info.counts.get("error", 0),
           info.wall_seconds, i)
        for i, info in enumerate(store.runs())
    )
    body = (
        "<h1>BriXTest runs</h1><div class='scroller'><table><thead>"
        "<tr><th>run</th><th>started</th><th>tests</th><th>failed</th>"
        "<th>wall s</th></tr></thead><tbody>%s</tbody></table></div>" % rows
    )
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(_page("BriXTest runs", body))
    return out_path


def serve(results_dir: Path, port: int, host: str = "127.0.0.1") -> None:
    """Serve the results directory (blocking) — files only, no compute."""
    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=str(results_dir)
    )
    with http.server.ThreadingHTTPServer((host, port), handler) as httpd:
        print("brixtest portal: http://%s:%d/ (serving %s) — Ctrl-C to stop"
              % (host, port, results_dir))
        httpd.serve_forever()
