"""Finite transcripts exercise the real fault-proxy control and reset contracts."""

import json
from pathlib import Path
import re
import subprocess

import pytest

from brix_suite.client_build import client_make


def build_fault_unit(tmp_path_factory, kind):
    """Build the complete production link closure with its finite test driver."""
    client = Path(__file__).resolve().parents[1] / "client"
    output = tmp_path_factory.mktemp(f"fault-{kind}-unit")
    built = client_make(client, f"fault-proxy-{kind}-unit", f"BINDIR={output}",
                        capture_output=True, text=True, timeout=180)
    assert built.returncode == 0, built.stdout + built.stderr
    return output / f"fault_proxy_{kind}_unit"


@pytest.fixture(scope="module")
def control_unit(tmp_path_factory):
    """Provide the finite production control driver."""
    return build_fault_unit(tmp_path_factory, "control")


def transcript(binary, *commands, enable_exec=False):
    """Return each real dispatcher reply, preserving its text exactly."""
    options = ['--enable-exec'] if enable_exec else []
    result = subprocess.run([str(binary), *options, *commands], capture_output=True,
                            check=True, timeout=10)
    replies = result.stdout.decode().split("\0")
    assert replies.pop() == "", "unit reply frame was truncated"
    assert len(replies) == len(commands), result.stdout
    return replies


@pytest.mark.parametrize("verb,value,field", [
    ("latency", "17", "latency_ms"),
    ("corrupt", "2.5", "corrupt_pct"),
    ("lossy", "3.125", "lossy_pct"),
    ("dup", "4.5", "dup_pct"),
    ("rate", "123", "rate_kbps"),
    ("truncate-at", "4294967301", "trunc"),
])
@pytest.mark.parametrize("direction", ["up", "down", "both"])
def test_directional_lever_and_clear(control_unit, verb, value, field, direction):
    """A lever changes only the named direction and clear restores both sides."""
    replies = transcript(control_unit, f"{verb} {value} {direction}",
                         '{"cmd":"status"}', "clear", '{"cmd":"status"}')
    assert replies[0] == replies[2] == "ok\n"
    armed, cleared = json.loads(replies[1]), json.loads(replies[3])
    for side in ("up", "down"):
        expected = float(value) if direction in (side, "both") else 0
        assert armed[side][field] == expected
        assert cleared[side][field] == 0


@pytest.mark.parametrize("command", [
    "rate -1 up", "slow-close -1 down", "burst -1", "toxicity -1",
    "refuse -1", "connect-delay -1", "latency-dist unknown 10",
    "latency-dist normal -1", "latency-dist normal",
])
def test_invalid_fidelity_command_preserves_state(control_unit, command):
    """Rejected operands leave an already armed direction unchanged."""
    replies = transcript(control_unit, "latency 19 up", "status", command, "status")
    assert replies[2].startswith("err:"), replies[2]
    assert replies[1] == replies[3]


@pytest.mark.parametrize("verb", ["bisect", "recovery"])
def test_oracle_cannot_execute_without_opt_in(control_unit, tmp_path, verb):
    """Control input cannot execute a shell command without --enable-exec."""
    marker = tmp_path / "must-not-exist"
    replies = transcript(control_unit, f"{verb} touch {marker}", "status json")
    assert "needs --enable-exec" in replies[0]
    assert json.loads(replies[1])["exec"] == 0
    assert not marker.exists()


@pytest.mark.parametrize('probe,timeout_ms,expected', [
    ('true', 1000, 'done: no latency in [1,4] reproduced'),
    ('false', 1000, 'done: minimal latency=1 reproduces'),
    ('exit 9', 1000, 'done: minimal latency=1 reproduces'),
    ('sleep 1', 20, 'done: minimal latency=1 reproduces'),
])
def test_bisection_reports_real_probe_outcomes(control_unit, probe, timeout_ms, expected):
    """Real child exit/timeout results drive the boundary and clear the lever."""
    # Exit-status cases allow a loaded VM to schedule the shell; the sleep case
    # retains the short deadline and still proves real child timeout handling.
    replies = transcript(control_unit, f'bisect latency 1 4 {timeout_ms} {probe}',
                         'bisect-result', '{"cmd":"status"}', enable_exec=True)
    assert replies[0].startswith('ok (bisecting')
    assert replies[1].startswith(expected)
    assert json.loads(replies[2])['up']['latency_ms'] == 0


@pytest.mark.parametrize('probe,expected', [
    ('true', 'done: recovered in'), ('false', 'done: STUCK'),
])
def test_recovery_clears_fault_and_reports_probe(control_unit, probe, expected):
    """Successful and failed health probes both leave the fault disarmed."""
    replies = transcript(control_unit, f'recovery block | 1 | {probe} | 0',
                         'recovery-result', '{"cmd":"status"}', enable_exec=True)
    assert replies[0].startswith('ok (recovery')
    assert replies[1].startswith(expected)
    assert json.loads(replies[2])['flags']['blocked'] == 0


@pytest.mark.parametrize('command', ['bisect latency', 'recovery block'])
def test_incomplete_oracle_request_does_not_start_a_job(control_unit, command):
    """Enabling execution does not make incomplete requests executable."""
    replies = transcript(control_unit, command, '{"cmd":"status"}', enable_exec=True)
    assert replies[0].startswith('err:')
    assert json.loads(replies[1])['flags']['blocked'] == 0


@pytest.mark.parametrize("command", [
    '{"cmd":"latency\\nblock","ms":5}',
    '{"cmd":"latency","args":"7\\nblock"}',
    '{"cmd":"unknown"}',
    '{"args":"block"}',
    '{"cmd":',
])
def test_malformed_json_cannot_inject_block(control_unit, command):
    """Malformed or escaped command text never becomes a second control verb."""
    replies = transcript(control_unit, command, '{"cmd":"status"}')
    assert not json.loads(replies[1])["flags"]["blocked"]


@pytest.mark.parametrize("command,field,value", [
    ("block", "blocked", 1),
    ("hang", "hang", 1),
    ("fanout 3", "fanout", 3),
    ("global-rate 27", "global_rate_kbps", 27),
    ("accept-pause 13", "accept_pause_ms", 13),
])
def test_connection_controls_reset(control_unit, command, field, value):
    """Connection-wide controls are observable and clear releases them."""
    replies = transcript(control_unit, command, "status json", "clear", "status json")
    assert replies[0] == replies[2] == "ok\n"
    assert json.loads(replies[1])[field] == value
    assert json.loads(replies[3])[field] == 0


def direction_fields(report, side):
    """Read both the base and extended public status fields for one direction."""
    return " ".join(re.findall(rf"{side}\[([^]]*)\]", report)).split()


@pytest.mark.parametrize("command,armed,neutral", [
    ("jitter 7", "jit=7", "jit=0"),
    ("chunk 5", "chunk=5", "chunk=0"),
    ("drip 3 2", "drip=3/2ms", "drip=0/0ms"),
    ("reorder 20 4", "reorder=20.0000%/4ms", "reorder=0.0000%/50ms"),
    ("drop-bytes 2.5", "drop=2.5000%", "drop=0.0000%"),
    ("repeat-bytes 3", "rep=3.0000%", "rep=0.0000%"),
    ("delay-first 6", "dfirst=6", "dfirst=0"),
    ("slow-close 7", "sclose=7", "sclose=0"),
    ("burst 128", "burst=128", "burst=0"),
    ("latency-dist normal 10 2", "dist=1", "dist=0"),
])
@pytest.mark.parametrize("direction", ["up", "down", "both"])
def test_extended_directional_controls(control_unit, command, armed, neutral, direction):
    """Extended controls preserve the opposite direction and reset completely."""
    replies = transcript(control_unit, f"{command} {direction}", "status", "clear", "status")
    assert replies[0] == replies[2] == "ok\n"
    for side in ("up", "down"):
        expected = armed if direction in (side, "both") else neutral
        assert expected in direction_fields(replies[1], side)
        assert neutral in direction_fields(replies[3], side)


@pytest.mark.parametrize("command,armed,neutral", [
    ("mss 512", "mss=512", "mss=0"),
    ("rcvbuf 1024", "rcvbuf=1024", "rcvbuf=0"),
    ("sndbuf 2048", "sndbuf=2048", "sndbuf=0"),
    ("max-lifetime 1234", "maxlife=1234ms", "maxlife=0ms"),
    ("stall up", "stall=1/0", "stall=0/0"),
    ("stall down", "stall=0/1", "stall=0/0"),
    ("stall both", "stall=1/1", "stall=0/0"),
    ("proxy-header v1 192.0.2.1:1", "proxy=1", "proxy=0"),
    ("proxy-header v2 192.0.2.1:1 192.0.2.2:2", "proxy=2", "proxy=0"),
    ("trigger up str:needle block", "trig=1/0", "trig=0/0"),
    ("trigger-once down hex:4142 block", "trig=0/1", "trig=0/0"),
    ("trigger both str:needle block", "trig=1/1", "trig=0/0"),
    ("mangle-len up 0 set 12", "mangle=1/0", "mangle=0/0"),
    ("mangle-len down 0 add 12", "mangle=0/1", "mangle=0/0"),
    ("mangle-len both 0 sub 12", "mangle=1/1", "mangle=0/0"),
    ("idle-reap 50 rst", "idle-reap=50/rst", "idle-reap=0/black-hole"),
    ("eat-100-continue", "eat-100=1", "eat-100=0"),
    ("rst-after 50", "rst-after=0B/50ms", "rst-after=0B/0ms"),
    ("max-bytes 512 rst", "rst-after=512B/0ms", "rst-after=0B/0ms"),
    ("drop-fin up", "drop-fin=1/0", "drop-fin=0/0"),
    ("drop-fin down", "drop-fin=0/1", "drop-fin=0/0"),
    ("drop-fin both", "drop-fin=1/1", "drop-fin=0/0"),
    ("classify-throttle 128 8", "classify=128B/8kbps", "classify=0B/0kbps"),
    ("syn-drop 2000000", "syn-drop=1000000ppm", "syn-drop=0ppm"),
    ("hello-split-reset 32", "hello-reset=32", "hello-reset=0"),
    ("tls fragment 2 up", "tls=1/0", "tls=0/0"),
    ("http naked-lf down", "http=0/1", "http=0/0"),
    ("http header-hold 128 5 partial up", "hold=1/0", "hold=0/0"),
])
def test_wide_control_reset_contract(control_unit, command, armed, neutral):
    """Clear disarms each public wide-state control after a successful command."""
    replies = transcript(control_unit, command, "status", "clear", "status")
    assert replies[0] == replies[2] == "ok\n"
    assert armed in replies[1].split(), replies[1]
    assert neutral in replies[3].split(), replies[3]


@pytest.mark.parametrize("command", [
    "preset nonexistent", "trigger", "trigger up hex:ZZ block",
    "mangle-len", "mangle-len up 0 multiply 2", "ramp latency",
    "tls invalid", "http invalid", "http append hex:ZZ",
    "http header-hold 0 5", "http body-hold 1 -1",
    "http strip-header", "http inject-header", "proxy-header v3 source",
    "proxy-header v1", "inject hex:ZZ", "replace hex:ZZ str:x",
    "alg-rewrite", "alg-rewrite 256.1.1.1:1 192.0.2.1:2",
    "toxic unknown", "toxic add", "toxic add first invalid 1",
    "toxic remove nonexistent",
])
def test_malformed_extended_commands_are_rejected(control_unit, command):
    """Malformed commands produce a refusal and preserve the existing core state."""
    replies = transcript(control_unit, "latency 23 up", command, '{"cmd":"status"}')
    assert replies[1].startswith("err:"), replies[1]
    assert json.loads(replies[2])["up"]["latency_ms"] == 23


def test_named_toxics_keep_identity_and_remove_individually(control_unit):
    """Duplicate names cannot overwrite a toxic, and removal preserves its peer."""
    replies = transcript(control_unit,
        "toxic add first latency 7 up", "toxic add second rate 8 down",
        "toxic add first latency 999 up", "toxic list json",
        "toxic remove first", "toxic list json", "clear", "toxic list json")
    assert replies[2] == "err: exists\n"
    names = [item["name"] for item in json.loads(replies[3])["toxics"]]
    assert names == ["first", "second"]
    remaining = json.loads(replies[5])["toxics"]
    assert [item["name"] for item in remaining] == ["second"]
    assert json.loads(replies[7]) == {"toxics": []}
