"""One-line structured diagnostics for standalone Python tools.

No root logger configuration or import-time output. Commands retain stdout for
their results. Every diagnostic supplies severity, source and event explicitly.
"""
import datetime
import json
import sys


_LEVELS = ("DEBUG", "INFO", "WARN", "ERROR", "CRIT", "FATAL")


def _message(values, sep, end):
    value = sep.join(str(item) for item in values)
    if end != "\n":
        value += end
    return value


def _timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


def _record(level, source, event, message, truncated):
    fields = {"source": source, "event": event, "message": message}
    quoted = " ".join(f"{key}={json.dumps(value, ensure_ascii=True)}"
                      for key, value in fields.items())
    return (f"timestamp={_timestamp()} level={level} service=brix role=tool "
            f"{quoted} truncated={int(truncated)}")


def diagnostic(level, source, event, *values, sep=" ", end="\n",
               file=None, flush=False):
    """Emit one bounded event, escaping controls, quotes and delimiter bytes."""
    if level not in _LEVELS:
        raise ValueError("unsupported diagnostic severity")
    stream = sys.stderr if file is None else file
    message = _message(values, sep, end)
    truncated = len(message) > 1024
    message = message[:1024]
    print(_record(level, source, event, message, truncated),
          file=stream, flush=flush)
