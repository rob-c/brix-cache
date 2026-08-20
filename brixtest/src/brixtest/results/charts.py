"""Inline-SVG resource timelines for the run report (feature F23).

Everything here renders from the run store's sample series into
self-contained SVG — no scripts, no external assets — so the report
stays one file that works anywhere.  Series longer than a sparkline's
point budget are downsampled by striding (the last point always
survives); the shape stays honest, the bytes stay bounded.
"""

from __future__ import annotations

import html
from typing import List, Optional, Sequence

__all__ = ["spark_svg", "resources_section"]

_W, _H, _PAD = 220, 40, 3
_POINT_BUDGET = 120


def _downsample(values: Sequence[float], budget: int) -> List[float]:
    if len(values) <= budget:
        return list(values)
    stride = (len(values) + budget - 1) // budget
    sampled = list(values[::stride])
    if sampled[-1] != values[-1]:
        sampled.append(values[-1])
    return sampled


def spark_svg(values: Sequence[float], color: str, title: str,
              floor: Optional[float] = None) -> str:
    """One polyline, normalized to the series range.  ``floor`` pins the
    scale's bottom (0 for CPU%) so a flat-but-busy line reads level."""
    if len(values) < 2:
        return "<span class='meta'>—</span>"
    points = _downsample(values, _POINT_BUDGET)
    low = min(points) if floor is None else floor
    high = max(points)
    span = (high - low) or 1.0
    step = (_W - 2 * _PAD) / (len(points) - 1)
    coords = " ".join(
        "%.1f,%.1f" % (
            _PAD + index * step,
            _H - _PAD - (value - low) / span * (_H - 2 * _PAD),
        )
        for index, value in enumerate(points)
    )
    return (
        "<svg class='spark' width='%d' height='%d' viewBox='0 0 %d %d'>"
        "<title>%s</title>"
        "<polyline fill='none' stroke='%s' stroke-width='1.5' points='%s'/>"
        "</svg>" % (_W, _H, _W, _H, html.escape(title), color, coords)
    )


def resources_section(store, run_id: str) -> str:
    """The report's server-resources block: the stats table with an RSS
    and a CPU timeline per instance, straight off the sample series."""
    rows = store.instance_stats(run_id)
    if not rows:
        return "<p class='meta'>no resource samples recorded.</p>"
    body = []
    for row in rows:
        instance = row[0]
        series = store.sample_series(run_id, instance)
        rss = [float(point[1]) for point in series]
        cpu = [float(point[2]) for point in series]
        body.append(
            "<tr><td>%s</td><td class='num'>%d</td><td class='num'>%d</td>"
            "<td class='num'>%.1f</td><td class='num'>%.1f</td>"
            "<td class='num'>%+d</td><td>%s</td><td>%s</td></tr>"
            % (html.escape(instance), row[1], row[2], row[3] or 0, row[4] or 0,
               (row[6] or 0) - (row[5] or 0),
               spark_svg(rss, "#6cb2ff",
                         "%s RSS kB (max %d)" % (instance, row[2])),
               spark_svg(cpu, "#c792ea",
                         "%s CPU %% (max %.1f)" % (instance, row[4] or 0),
                         floor=0.0))
        )
    return (
        "<div class='scroller'><table><thead><tr><th>instance</th>"
        "<th>samples</th><th>max RSS kB</th><th>mean CPU %%</th>"
        "<th>max CPU %%</th><th>RSS growth kB</th><th>RSS timeline</th>"
        "<th>CPU timeline</th></tr></thead><tbody>%s</tbody></table></div>"
        % "".join(body)
    )
