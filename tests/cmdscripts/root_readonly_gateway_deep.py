"""The expansive half of the read-only root:// gateway proof — the production
gate.

``root_readonly_gateway`` proves that every opcode in the write-gated route
table is refused.  That is necessary but not sufficient before a gateway faces
the public internet: it says nothing about the opcodes NOT in that table, about
frames that reach the gate by another route (a bound secondary channel, a
signing envelope, a pre-login connection), about option words nobody wrote a
probe for, or about what survives a reload.  This module closes those:

  1. whole-opcode-space sweep   every request id defined in opcodes.h — standard
                                AND vendor — fired in a plausible mutating form.
                                The four dispatch tables are parsed out of the C,
                                so the sweep classifies each opcode by the table
                                that actually routes it, and an opcode routed by
                                NO table must still answer with an error.
  2. open option-word sweep     every single option bit, plus every combination
                                of the write-implying bits.  The write mask is
                                read from BRIX_OPEN_WRITE_BITS in the C, so the
                                expectation cannot drift from the server.
  3. pre-login / pre-handshake  mutations attempted before login, and before the
                                handshake, must never be accepted.
  4. bound secondary channel    a kXR_bind data channel is the one path allowed
                                to carry a bare kXR_write; it must still hit the
                                read-only gate, and it must not carry anything
                                else.
  5. signing envelope           a kXR_sigver-wrapped mutation must not bypass
                                the gate.
  6. path shapes                traversal, opaque suffixes, doubled separators,
                                NUL and trailing-slash forms of a mutating path.
  7. concurrency storm          the gate is not a race: N threads mutating at
                                once, then integrity.
  8. content-hash integrity     every family above is bracketed by a sha256
                                digest of the origin tree AND the gateway export,
                                so a same-size in-place rewrite cannot pass as
                                "unchanged" the way a path-set snapshot would.
  9. reload persistence         the posture survives SIGHUP.
 10. role conflict is fatal     brix_manager_mode + brix_read_only cannot even
                                parse: a manager redirects mutations before the
                                local gate runs, so the pair is refused by
                                nginx -t rather than silently half-honoured.
 11. brix_read_only_public      the public posture restricts the kXR_query
                                infotypes that describe the SERVER (QStats,
                                Qspace, QFSinfo, Qvisa), filters kXR_Qconfig per
                                key (deployment identity withheld, protocol
                                capability and readv geometry kept so transfer
                                tuning still works), and NOTHING else: the path-scoped queries, listing, stat and
                                streamed reads all still work, and the mutation
                                battery is refused without an explicit
                                brix_read_only.

Every expectation in this module is derived from the C (opcodes.h, the four
dispatch_*.c tables, open_flags.h), never hand-listed, so a new opcode or a new
write-implying option bit lands in the sweep on its own.
"""

from __future__ import annotations

import hashlib
import os
import re
import signal
import socket
import subprocess
import struct
import threading
import time
from pathlib import Path

from settings import HOST

import _test_a_robustness_helpers as H

from cmdscripts.root_readonly_gateway import (
    DOC_PAGE,
    PUBLIC_FILE,
    REPO,
    Probe,
    _errmsg,
    _errnum,
    _send,
    _session,
    _wait,
    kXR_NotAuthorized,
    kXR_Unsupported,
    kXR_bind,
    kXR_close,
    kXR_error,
    kXR_dirlist,
    kXR_fsReadOnly,
    kXR_mkdir,
    kXR_ok,
    kXR_open,
    kXR_open_read,
    kXR_query,
    kXR_read,
    kXR_readv,
    kXR_set,
    kXR_sigver,
    kXR_stat,
    kXR_write,
    mutating_opcodes,
    probes,
)

OPCODES_H = REPO / "src/protocols/root/protocol/opcodes.h"
FLAGS_H = REPO / "src/protocols/root/protocol/flags.h"
OPEN_FLAGS_H = REPO / "src/protocols/root/protocol/open_flags.h"
DISPATCH_DIR = REPO / "src/protocols/root/handshake"

#: files the SERVER creates in its own export as part of normal operation; they
#: are not client-visible mutations and must not fail the integrity assertion.
SERVER_OWNED = (".nginx-xrootd-ckp-recovery.lock",)


# --------------------------------------------------------------------------- #
# facts read out of the C                                                      #
# --------------------------------------------------------------------------- #


def wire_opcodes() -> dict[str, int]:
    """Every client request id in opcodes.h — standard 3000-3032 and vendor
    3500-3503 — as name -> number.

    Sliced between the "Request IDs" banner and the response-status section so
    the numerically overlapping error codes (kXR_ArgInvalid is also 3000) can
    never leak in.
    """
    text = OPCODES_H.read_text(encoding="utf-8")
    head = text.split("/* Request IDs (kXR_*)", 1)[1]
    body = head.split("Response status codes", 1)[0]
    return {
        name: int(value)
        for name, value in re.findall(r"#define\s+(kXR_[a-z]+)\s+(\d+)", body)
    }


def query_subcodes() -> dict[str, int]:
    """Every kXR_Q* infotype in opcodes.h — the second dimension of kXR_query,
    which the opcode sweep can only exercise one value of."""
    text = OPCODES_H.read_text(encoding="utf-8")
    return {
        name: int(value)
        for name, value in re.findall(r"#define\s+(kXR_Q\w+)\s+(\d+)", text)
    }


def routed_opcodes() -> dict[str, set[str]]:
    """Opcode names routed by each of the four dispatch tables.

    An opcode in none of them falls through brix_dispatch_opcode() to
    kXR_InvalidRequest — which is exactly the property the sweep asserts, so the
    tables have to be read rather than assumed.
    """
    out: dict[str, set[str]] = {}
    for label in ("session", "read", "write", "signing"):
        text = (DISPATCH_DIR / f"dispatch_{label}.c").read_text(encoding="utf-8")
        names = set(re.findall(r"case\s+(kXR_[a-z]+)\s*:", text))
        if label == "signing":
            names |= set(re.findall(r"cur_reqid\s*!=\s*(kXR_[a-z]+)", text))
        out[label] = names
    out["write"] = mutating_opcodes()
    return out


def open_flag_values() -> dict[str, int]:
    text = FLAGS_H.read_text(encoding="utf-8").split("Stat response flags", 1)[0]
    return {
        name: int(value, 0)
        for name, value in re.findall(r"#define\s+(kXR_\w+)\s+(0x[0-9a-fA-F]+)", text)
    }


def open_write_mask() -> int:
    """BRIX_OPEN_WRITE_BITS, evaluated from the C. This is the single definition
    of "this open is a write" that the server itself uses."""
    text = OPEN_FLAGS_H.read_text(encoding="utf-8")
    expr = text.split("#define BRIX_OPEN_WRITE_BITS", 1)[1].split(")", 1)[0]
    values = open_flag_values()
    mask = 0
    for name in re.findall(r"kXR_\w+", expr):
        mask |= values[name]
    return mask


# --------------------------------------------------------------------------- #
# integrity                                                                    #
# --------------------------------------------------------------------------- #


def tree_digest(root: Path) -> dict[str, str]:
    """Relative path -> content digest for every entry under ``root``.

    A path-set snapshot cannot see a same-size in-place rewrite; this can.
    """
    out: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        if path.is_symlink():
            out[rel] = "symlink:" + os.readlink(path)
        elif path.is_dir():
            out[rel] = "dir"
        else:
            try:
                out[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError as exc:  # unreadable == still a diff
                out[rel] = f"unreadable:{exc.errno}"
    return out


def _digest_diff(
    before: dict[str, str], after: dict[str, str]
) -> tuple[list[str], list[str], list[str]]:
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = sorted(k for k in set(before) & set(after) if before[k] != after[k])
    return added, removed, changed


def check_integrity(
    label: str,
    root: Path,
    before: dict[str, str],
    results: list[tuple[bool, str]],
    *,
    allow_server_owned: bool = False,
) -> None:
    added, removed, changed = _digest_diff(before, tree_digest(root))
    if allow_server_owned:
        added = [p for p in added if Path(p).name not in SERVER_OWNED]
    results.append(
        (
            not (added or removed or changed),
            f"{label}: content digest unchanged "
            f"(added={added} removed={removed} changed={changed})",
        )
    )


# --------------------------------------------------------------------------- #
# 1. whole-opcode-space sweep                                                  #
# --------------------------------------------------------------------------- #


def _sweep_frame(
    name: str, opcode: int, known: dict[int, Probe]
) -> tuple[bytes, bytes, bytes]:
    """The most mutation-shaped frame we can build for one opcode.

    Where the main probe table already has a considered frame for the opcode we
    reuse it verbatim; everything else gets a generic path-carrying request,
    which is the shape every path-based op on the wire takes.
    """
    probe = known.get(opcode)
    if probe is not None:
        return probe.body, probe.payload, probe.trailer
    if opcode == kXR_close:
        return b"\x00" * 16, b"", b""
    return b"\x00" * 16, f"/sweep_{name}.dat\x00".encode(), b""


def _try(
    port: int, opcode: int, body: bytes, payload: bytes, trailer: bytes
) -> tuple[int | None, bytes]:
    """One opcode on a fresh session. ``None`` status means the server answered
    nothing at all (timeout or close) — recorded, never silently passed."""
    try:
        s = _session(port)
    except (OSError, RuntimeError) as exc:
        return None, str(exc).encode()
    try:
        return _send(s, opcode, body, payload, trailer)
    except (OSError, ConnectionError):
        return None, b""
    finally:
        s.close()


def _record_opcode_inventory(
    ops: dict[str, int],
    routed: dict[str, set[str]],
    label: str,
    results: list[tuple[bool, str]],
) -> None:
    results.append(
        (
            len(ops) >= 37,
            f"{label}: opcodes.h defines {len(ops)} request ids (sweeping all of them)",
        )
    )
    stray = sorted(set().union(*routed.values()) - set(ops))
    results.append(
        (
            not stray,
            f"{label}: every dispatched opcode name exists in opcodes.h "
            f"(stray: {stray})",
        )
    )


def _record_write_opcode(
    name: str,
    opcode: int,
    status: int | None,
    err: int | None,
    label: str,
    missed: list[str],
    results: list[tuple[bool, str]],
) -> None:
    refused = status == kXR_error and err == kXR_fsReadOnly
    if not refused:
        missed.append(f"{name}({status}/{err})")
    results.append(
        (
            refused,
            f"{label}: sweep {name}({opcode}) is write-routed "
            f"-> kXR_fsReadOnly (got {status}/{err})",
        )
    )


def _record_unrouted_opcode(
    name: str,
    opcode: int,
    status: int | None,
    err: int | None,
    resp: bytes,
    label: str,
    accepted: list[str],
    results: list[tuple[bool, str]],
) -> None:
    refused = status is not None and status != kXR_ok
    if not refused:
        accepted.append(f"{name}({status})")
    results.append(
        (
            refused,
            f"{label}: sweep {name}({opcode}) is routed by no dispatch table "
            f"-> refused (got {status}/{err} "
            f"{_errmsg(resp)!r})",
        )
    )


def _record_read_opcode(
    name: str,
    opcode: int,
    status: int | None,
    err: int | None,
    routed: dict[str, set[str]],
    label: str,
    results: list[tuple[bool, str]],
) -> None:
    table = _table_of(name, routed)
    results.append(
        (
            True,
            f"{label}: sweep {name}({opcode}) is {table}-routed, "
            f"answered {status}/{err}",
        )
    )


def _record_opcode_result(
    name: str,
    opcode: int,
    status: int | None,
    err: int | None,
    resp: bytes,
    routed: dict[str, set[str]],
    unrouted: set[str],
    accepted: list[str],
    missed: list[str],
    label: str,
    results: list[tuple[bool, str]],
) -> None:
    if name in routed["write"]:
        _record_write_opcode(name, opcode, status, err, label, missed, results)
        return
    if name in unrouted:
        _record_unrouted_opcode(
            name, opcode, status, err, resp, label, accepted, results
        )
        return
    _record_read_opcode(name, opcode, status, err, routed, label, results)


def _sweep_opcodes(
    port: int,
    label: str,
    ops: dict[str, int],
    routed: dict[str, set[str]],
    known: dict[int, Probe],
    unrouted: set[str],
    results: list[tuple[bool, str]],
) -> tuple[list[str], list[str]]:
    accepted, missed = [], []
    for name, opcode in sorted(ops.items(), key=lambda item: item[1]):
        body, payload, trailer = _sweep_frame(name, opcode, known)
        status, resp = _try(port, opcode, body, payload, trailer)
        err = _errnum(resp) if status == kXR_error else None
        _record_opcode_result(
            name,
            opcode,
            status,
            err,
            resp,
            routed,
            unrouted,
            accepted,
            missed,
            label,
            results,
        )
    return accepted, missed


def _record_opcode_summary(
    label: str,
    unrouted: set[str],
    accepted: list[str],
    missed: list[str],
    results: list[tuple[bool, str]],
) -> None:
    results.append(
        (
            not missed,
            f"{label}: every write-routed opcode refused in the sweep "
            f"(missed: {missed})",
        )
    )
    results.append(
        (
            not accepted,
            f"{label}: no unrouted opcode was accepted (accepted: {accepted})",
        )
    )
    results.append(
        (bool(unrouted), f"{label}: unrouted opcodes exercised: {sorted(unrouted)}")
    )


def check_opcode_space(port: int, label: str, results: list[tuple[bool, str]]) -> None:
    """Fire every defined request id, classified by the C dispatch tables."""
    ops = wire_opcodes()
    routed = routed_opcodes()
    known = {probe.opcode: probe for probe in probes()}
    unrouted = set(ops) - set().union(*routed.values())
    _record_opcode_inventory(ops, routed, label, results)
    accepted, missed = _sweep_opcodes(
        port, label, ops, routed, known, unrouted, results
    )
    _record_opcode_summary(label, unrouted, accepted, missed, results)


def _table_of(name: str, routed: dict[str, set[str]]) -> str:
    return "+".join(sorted(k for k, v in routed.items() if name in v)) or "none"


# --------------------------------------------------------------------------- #
# 2. open option-word sweep                                                    #
# --------------------------------------------------------------------------- #


def _open_option_words(write_bits: list[int]) -> set[int]:
    words = {1 << n for n in range(16)}
    for combo in range(1, 1 << len(write_bits)):
        word = 0
        for index, bit in enumerate(write_bits):
            if combo & (1 << index):
                word |= bit
        words.add(word)
        words.add(word | kXR_open_read)
    return words


def _record_open_misses(
    word: int,
    status: int | None,
    err: int | None,
    expected: bool,
    refused: bool,
    bad_refusal: list[str],
    bad_pass: list[str],
) -> None:
    if expected and not refused:
        bad_pass.append(f"0x{word:04x}({status}/{err})")
    if not expected and refused:
        bad_refusal.append(f"0x{word:04x}")


def _open_decision(expected: bool) -> str:
    if expected:
        return "refused"
    return "allowed"


def _record_open_word(
    word: int,
    mask: int,
    names: dict[int, str],
    port: int,
    label: str,
    bad_refusal: list[str],
    bad_pass: list[str],
    results: list[tuple[bool, str]],
) -> None:
    status, resp = _try(
        port, kXR_open, struct.pack(">HH12x", 0o644, word), PUBLIC_FILE.encode(), b""
    )
    err = _errnum(resp) if status == kXR_error else None
    refused = status == kXR_error and err == kXR_fsReadOnly
    expected = bool(word & mask)
    _record_open_misses(word, status, err, expected, refused, bad_refusal, bad_pass)
    decision = _open_decision(expected)
    results.append(
        (
            refused == expected,
            f"{label}: open options 0x{word:04x} "
            f"[{names.get(word, 'combination')}] {decision} "
            f"(got {status}/{err})",
        )
    )


def _sweep_open_words(
    words: set[int],
    mask: int,
    names: dict[int, str],
    port: int,
    label: str,
    results: list[tuple[bool, str]],
) -> tuple[list[str], list[str]]:
    bad_refusal, bad_pass = [], []
    for word in sorted(words):
        _record_open_word(
            word, mask, names, port, label, bad_refusal, bad_pass, results
        )
    return bad_refusal, bad_pass


def _record_open_summary(
    label: str,
    bad_refusal: list[str],
    bad_pass: list[str],
    results: list[tuple[bool, str]],
) -> None:
    results.append(
        (
            not bad_pass,
            f"{label}: every write-implying option word refused (escaped: {bad_pass})",
        )
    )
    results.append(
        (
            not bad_refusal,
            f"{label}: no read-only option word was refused as "
            f"read-only (misrefused: {bad_refusal})",
        )
    )


def check_open_option_space(
    port: int, label: str, results: list[tuple[bool, str]]
) -> None:
    """Sweep every option bit and combination of C-defined write bits."""
    mask = open_write_mask()
    values = open_flag_values()
    write_bits = sorted(bit for bit in (1 << n for n in range(16)) if bit & mask)
    bit_count = bin(mask).count("1")
    results.append(
        (
            bit_count >= 5,
            f"{label}: BRIX_OPEN_WRITE_BITS parsed from the C = "
            f"0x{mask:04x} ({bit_count} bits)",
        )
    )
    words = _open_option_words(write_bits)
    names = {value: name for name, value in values.items()}
    bad_refusal, bad_pass = _sweep_open_words(words, mask, names, port, label, results)
    _record_open_summary(label, bad_refusal, bad_pass, results)


# --------------------------------------------------------------------------- #
# 3. pre-login and pre-handshake                                               #
# --------------------------------------------------------------------------- #


def check_unauthenticated_mutations(
    port: int, label: str, results: list[tuple[bool, str]]
) -> None:
    """A mutation must never be accepted from a connection that has not logged
    in — and must not even be parsed before the handshake."""
    accepted = []
    for probe in probes():
        try:
            s = socket.create_connection((HOST, port), timeout=8)
        except OSError as exc:
            results.append((False, f"{label}: pre-login connect failed: {exc}"))
            return
        s.settimeout(8)
        try:
            H._handshake_and_protocol(s)
            status, resp = _send(
                s, probe.opcode, probe.body, probe.payload, probe.trailer
            )
        except (OSError, ConnectionError):
            status, resp = None, b""
        finally:
            s.close()
        ok = status != kXR_ok
        if not ok:
            accepted.append(probe.name)
        results.append(
            (
                ok,
                f"{label}: pre-login {probe.name} not accepted "
                f"(status={status} err={_errnum(resp)})",
            )
        )
    results.append(
        (
            not accepted,
            f"{label}: no mutation accepted before login (accepted: {accepted})",
        )
    )

    # Before the handshake the server has no session at all: the frame must not
    # be executed, whatever it answers (error, or a dropped connection).
    try:
        s = socket.create_connection((HOST, port), timeout=8)
        s.settimeout(6)
        try:
            s.sendall(
                H.make_request(
                    b"\x00\x09",
                    kXR_mkdir,
                    struct.pack(">8xHH4x", 0, 0o755),
                    b"/pre_handshake_mkdir",
                )
            )
            status, resp = H._recv_response(s)
        finally:
            s.close()
    except (OSError, ConnectionError):
        status, resp = None, b""
    results.append(
        (
            status != kXR_ok,
            f"{label}: mkdir before the handshake is not accepted "
            f"(status={status} err={_errnum(resp)})",
        )
    )


# --------------------------------------------------------------------------- #
# 4. bound secondary data channel                                              #
# --------------------------------------------------------------------------- #


def _bind_secondary(port: int, sessid: bytes) -> tuple[socket.socket, int, bytes]:
    s = socket.create_connection((HOST, port), timeout=8)
    s.settimeout(8)
    s.sendall(H.HANDSHAKE + H.make_protocol_req())
    H._recv_response(s)
    H._recv_response(s)
    status, resp = _send(s, kXR_bind, sessid[:16])
    return s, status, resp


def _record_disabled_bind(
    status: int, resp: bytes, label: str, results: list[tuple[bool, str]]
) -> None:
    refused = status == kXR_error and _errnum(resp) == kXR_Unsupported
    results.append(
        (
            refused,
            f"{label}: kXR_bind refused when data substreams "
            f"are off ({status}/{_errnum(resp)} "
            f"{_errmsg(resp)!r})",
        )
    )


def _probe_bound_write(
    secondary: socket.socket, label: str, results: list[tuple[bool, str]]
) -> None:
    status, resp = _send(
        secondary, kXR_write, b"\x00" * 4 + struct.pack(">q4x", 0), b"X" * 8
    )
    refused = status == kXR_error and _errnum(resp) == kXR_fsReadOnly
    results.append(
        (
            refused,
            f"{label}: bound-stream kXR_write -> kXR_fsReadOnly "
            f"({status}/{_errnum(resp)} {_errmsg(resp)!r})",
        )
    )


def _probe_bound_mkdir(
    secondary: socket.socket, label: str, results: list[tuple[bool, str]]
) -> None:
    status, resp = _send(
        secondary, kXR_mkdir, struct.pack(">8xHH4x", 0, 0o755), b"/bound_mkdir"
    )
    refused = status == kXR_error and _errnum(resp) in (
        kXR_NotAuthorized,
        kXR_fsReadOnly,
    )
    results.append(
        (
            refused,
            f"{label}: bound-stream kXR_mkdir refused "
            f"({status}/{_errnum(resp)} {_errmsg(resp)!r})",
        )
    )


def _probe_bound_open(
    secondary: socket.socket, label: str, results: list[tuple[bool, str]]
) -> None:
    status, resp = _send(
        secondary, kXR_open, struct.pack(">HH12x", 0o644, 0x0028), b"/bound_open.dat"
    )
    refused = status == kXR_error and _errnum(resp) in (
        kXR_NotAuthorized,
        kXR_fsReadOnly,
    )
    results.append(
        (
            refused,
            f"{label}: bound-stream write-open refused "
            f"({status}/{_errnum(resp)} {_errmsg(resp)!r})",
        )
    )


def _probe_enabled_bound_stream(
    secondary: socket.socket,
    status: int,
    resp: bytes,
    label: str,
    results: list[tuple[bool, str]],
) -> None:
    results.append(
        (
            status == kXR_ok,
            f"{label}: kXR_bind accepted with substreams on "
            f"({status}/{_errnum(resp)} {_errmsg(resp)!r})",
        )
    )
    if status != kXR_ok:
        return
    _probe_bound_write(secondary, label, results)
    _probe_bound_mkdir(secondary, label, results)
    _probe_bound_open(secondary, label, results)


def _probe_bound_stream_mode(
    secondary: socket.socket,
    status: int,
    resp: bytes,
    substreams: bool,
    label: str,
    results: list[tuple[bool, str]],
) -> None:
    if not substreams:
        _record_disabled_bind(status, resp, label, results)
        return
    _probe_enabled_bound_stream(secondary, status, resp, label, results)


def check_bound_stream(
    port: int, label: str, *, substreams: bool, results: list[tuple[bool, str]]
) -> None:
    """kXR_bind is the one path a bare kXR_write may travel without an open on
    the same connection (policy.c lets a bound secondary carry kXR_write, and
    only kXR_write).  It must still hit the read-only gate.

    With brix_data_substreams off the bind itself is refused — a narrower
    surface, asserted separately so a posture flip cannot pass unnoticed.
    """
    primary = socket.create_connection((HOST, port), timeout=8)
    primary.settimeout(8)
    try:
        hs, proto, login, body = H._full_anon_login_body(primary)
        if login != kXR_ok or len(body) < 16:
            results.append(
                (
                    False,
                    f"{label}: primary login for bind failed ({hs}/{proto}/{login})",
                )
            )
            return
        sessid = body[:16]
        secondary, status, resp = _bind_secondary(port, sessid)
        try:
            _probe_bound_stream_mode(
                secondary, status, resp, substreams, label, results
            )
        finally:
            secondary.close()
    except (OSError, ConnectionError) as exc:
        results.append((False, f"{label}: bound-stream probe failed: {exc}"))
    finally:
        primary.close()


# --------------------------------------------------------------------------- #
# 5. signing envelope                                                          #
# --------------------------------------------------------------------------- #


def check_signed_mutation(
    port: int, label: str, results: list[tuple[bool, str]]
) -> None:
    """A kXR_sigver envelope announces "the next request is signed". It must not
    become a way to carry a mutation past the read-only gate."""
    s = _session(port)
    try:
        # sigver body: expectrid[2] version[1] flags[1] seqno[8] crypto[1] rsvd[3].
        # A well-formed envelope draws NO response — it is a request PREFIX, and
        # the single response belongs to the signed request that follows
        # (session/signing.c) — so the envelope is sent without reading.
        body = struct.pack(">HBBqB3x", kXR_mkdir, 0, 0, 1, 0)
        s.sendall(H.make_request(b"\x00\x07", kXR_sigver, body, b"\x00" * 32))
        st, resp = _send(
            s, kXR_mkdir, struct.pack(">8xHH4x", 0, 0o755), b"/signed_mkdir"
        )
        results.append(
            (
                st == kXR_error and _errnum(resp) == kXR_fsReadOnly,
                f"{label}: a mutation inside a kXR_sigver envelope is "
                f"still refused ({st}/{_errnum(resp)} {_errmsg(resp)!r})",
            )
        )
    except (OSError, ConnectionError) as exc:
        results.append((False, f"{label}: signed-mutation probe failed: {exc}"))
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# 6. path shapes                                                               #
# --------------------------------------------------------------------------- #

PATH_SHAPES = (
    ("traversal", b"/../escape_mkdir"),
    ("deep traversal", b"/a/../../../../tmp/escape_mkdir"),
    ("doubled separators", b"//ro_shape//dir"),
    ("trailing slash", b"/ro_shape_slash/"),
    ("dot segment", b"/./ro_shape_dot"),
    ("opaque suffix", b"/ro_shape_opq?oss.asize=1"),
    ("embedded NUL", b"/ro_shape_nul\x00/extra"),
    ("relative", b"ro_shape_rel"),
    ("root", b"/"),
    ("empty", b""),
)


def check_path_shapes(port: int, label: str, results: list[tuple[bool, str]]) -> None:
    """No spelling of a mutating path may be accepted — and none may escape the
    export either, which the integrity bracket around this family proves."""
    accepted = []
    for name, path in PATH_SHAPES:
        status, resp = _try(
            port, kXR_mkdir, struct.pack(">8xHH4x", 0, 0o755), path, b""
        )
        err = _errnum(resp) if status == kXR_error else None
        ok = status != kXR_ok
        if not ok:
            accepted.append(name)
        results.append(
            (
                ok,
                f"{label}: mkdir with a {name} path is not accepted "
                f"({status}/{err} {_errmsg(resp)!r})",
            )
        )
    results.append(
        (not accepted, f"{label}: no path shape was accepted (accepted: {accepted})")
    )


# --------------------------------------------------------------------------- #
# 6b. kXR_query subcodes                                                       #
# --------------------------------------------------------------------------- #


def check_query_subcodes(
    port: int, label: str, results: list[tuple[bool, str]]
) -> None:
    """kXR_query is read-routed, but it is really thirteen operations behind one
    opcode — including the two "implementation-defined" escape hatches
    (kXR_Qopaquf / kXR_Qopaqug) that stock XRootD uses to pass commands to the
    filesystem, and kXR_Qckscan, which walks a tree.  The opcode sweep can only
    fire one infotype; this fires them all.

    The mutation assertion is the digest bracket around the family — including
    the gateway's OWN export, so a query that materialises a cache artefact
    where a public read-only gateway should have none is caught too.
    """
    answered = []
    for name, infotype in sorted(query_subcodes().items(), key=lambda kv: kv[1]):
        body = struct.pack(">HH4s8x", infotype, 0, b"\x00" * 4)
        status, resp = _try(port, kXR_query, body, PUBLIC_FILE.encode() + b"\x00", b"")
        err = _errnum(resp) if status == kXR_error else None
        answered.append(status is not None)
        results.append(
            (
                status is not None,
                f"{label}: query {name}({infotype}) answered "
                f"{status}/{err} {_errmsg(resp)!r}",
            )
        )
    results.append(
        (
            all(answered) and len(answered) >= 13,
            f"{label}: every kXR_query infotype in opcodes.h was "
            f"exercised ({len(answered)})",
        )
    )


# --------------------------------------------------------------------------- #
# 6c. session opcodes cannot lift the gate                                     #
# --------------------------------------------------------------------------- #


def check_session_ops_cannot_lift_the_gate(
    port: int, label: str, results: list[tuple[bool, str]]
) -> None:
    """kXR_set is login-gated but NOT write-gated (dispatch_session.c), so it is
    the one server-configuration opcode a public client can reach.  Prove it
    cannot move the posture: run the session opcodes on a connection, then
    mutate on that same connection and require the same refusal.
    """
    try:
        s = _session(port)
    except (OSError, RuntimeError) as exc:
        results.append((False, f"{label}: session for the set probe failed: {exc}"))
        return
    try:
        # kXR_set body: modifier(1) reserved(15) — appid and clttl are the two
        # modifiers the server names (query/set.c).
        for modifier, what in ((0x00, "appid"), (0x01, "clttl")):
            st, resp = _send(
                s, kXR_set, struct.pack(">B15x", modifier), b"brix-readonly-probe\n"
            )
            results.append(
                (
                    st in (kXR_ok, kXR_error),
                    f"{label}: kXR_set {what} answered {st}/{_errnum(resp)}",
                )
            )
        st, resp = _send(
            s, kXR_set, struct.pack(">B15x", 0x00), b"cms.space 1000000 999999\n"
        )
        results.append(
            (
                st in (kXR_ok, kXR_error),
                f"{label}: kXR_set cms.space answered {st}/{_errnum(resp)}",
            )
        )
        st, resp = _send(
            s, kXR_mkdir, struct.pack(">8xHH4x", 0, 0o755), b"/after_set_mkdir"
        )
        results.append(
            (
                st == kXR_error and _errnum(resp) == kXR_fsReadOnly,
                f"{label}: a mutation after kXR_set is still refused "
                f"({st}/{_errnum(resp)} {_errmsg(resp)!r})",
            )
        )
        # A second login on a live session must not re-negotiate the posture.
        s.sendall(H.make_login_req())
        st, resp = H._recv_response(s)
        results.append(
            (True, f"{label}: re-login on a live session answered {st}/{_errnum(resp)}")
        )
        st, resp = _send(
            s, kXR_mkdir, struct.pack(">8xHH4x", 0, 0o755), b"/after_relogin_mkdir"
        )
        results.append(
            (
                st == kXR_error and _errnum(resp) == kXR_fsReadOnly,
                f"{label}: a mutation after a re-login is still refused "
                f"({st}/{_errnum(resp)} {_errmsg(resp)!r})",
            )
        )
    except (OSError, ConnectionError) as exc:
        results.append((False, f"{label}: session-opcode probe failed: {exc}"))
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# 7. concurrency storm                                                         #
# --------------------------------------------------------------------------- #


def _mutation_worker(
    port: int,
    table: list[Probe],
    stride: int,
    index: int,
    outcomes: list[tuple[str, int | None, int | None]],
    lock: threading.Lock,
) -> None:
    local = []
    for probe in table[index::stride]:
        status, resp = _try(
            port, probe.opcode, probe.body, probe.payload, probe.trailer
        )
        err = _errnum(resp) if status == kXR_error else None
        local.append((probe.name, status, err))
    with lock:
        outcomes.extend(local)


def _run_mutation_workers(
    port: int, table: list[Probe], thread_count: int
) -> list[tuple[str, int | None, int | None]]:
    outcomes: list[tuple[str, int | None, int | None]] = []
    lock = threading.Lock()
    workers = [
        threading.Thread(
            target=_mutation_worker,
            args=(port, table, thread_count, index, outcomes, lock),
            daemon=True,
        )
        for index in range(thread_count)
    ]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join(timeout=120)
    return outcomes


def check_mutation_storm(
    port: int, label: str, results: list[tuple[bool, str]], *, threads: int = 8
) -> None:
    """Prove the per-request gate holds under concurrent mutation attempts."""
    table = probes()
    outcomes = _run_mutation_workers(port, table, threads)

    escaped = [f"{n}({s}/{e})" for n, s, e in outcomes if e != kXR_fsReadOnly]
    results.append(
        (
            len(outcomes) == len(table),
            f"{label}: storm ran every probe concurrently "
            f"({len(outcomes)}/{len(table)} across {threads} threads)",
        )
    )
    results.append(
        (
            not escaped,
            f"{label}: every concurrent mutation refused as read-only "
            f"(escaped: {escaped})",
        )
    )


# --------------------------------------------------------------------------- #
# 8. reload persistence                                                        #
# --------------------------------------------------------------------------- #


def check_reload_persistence(
    prefix: Path, port: int, label: str, results: list[tuple[bool, str]]
) -> None:
    """SIGHUP re-runs the config merge in a new worker. brix_read_only must come
    back on: an operator reloading for an unrelated reason must not silently
    open the gateway for writes."""
    try:
        pid = int((prefix / "nginx.pid").read_text(encoding="utf-8").strip())
        os.kill(pid, signal.SIGHUP)
    except (OSError, ValueError) as exc:
        results.append((False, f"{label}: could not SIGHUP the gateway: {exc}"))
        return
    time.sleep(1.0)
    results.append((_wait(port), f"{label}: gateway accepts connections after SIGHUP"))
    survived = []
    for probe in probes():
        status, resp = _try(
            port, probe.opcode, probe.body, probe.payload, probe.trailer
        )
        err = _errnum(resp) if status == kXR_error else None
        if err != kXR_fsReadOnly:
            survived.append(f"{probe.name}({status}/{err})")
    results.append(
        (
            not survived,
            f"{label}: every mutation still refused after a reload "
            f"(escaped: {survived})",
        )
    )


# --------------------------------------------------------------------------- #
# 9. reads keep working under every posture                                    #
# --------------------------------------------------------------------------- #


def check_read_surface_intact(
    port: int, label: str, results: list[tuple[bool, str]]
) -> None:
    """After the whole expansive run, the gateway must still be a gateway."""
    try:
        s = _session(port)
    except (OSError, RuntimeError) as exc:
        results.append((False, f"{label}: session after the sweep failed: {exc}"))
        return
    try:
        st, resp = _send(
            s, kXR_open, struct.pack(">HH12x", 0, kXR_open_read), PUBLIC_FILE.encode()
        )
        results.append(
            (
                st == kXR_ok,
                f"{label}: read-open still succeeds after the full sweep "
                f"({st}/{_errnum(resp)} {_errmsg(resp)!r})",
            )
        )
        if st == kXR_ok:
            handle = resp[:4]
            st, data = _send(s, kXR_read, handle + struct.pack(">qi", 0, 64))
            results.append(
                (
                    st == kXR_ok and data,
                    f"{label}: read still returns bytes after the sweep",
                )
            )
            _send(s, kXR_close, handle + b"\x00" * 12)
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# 10. the manager/read-only role conflict is fatal                             #
# --------------------------------------------------------------------------- #


def _try_manager_conf(
    work: Path, nginx_bin: str, name: str, knobs: str
) -> tuple[int, str]:
    conf = work / f"{name}.conf"
    conf.write_text(
        "daemon off;\n"
        f"error_log {work / 'logs' / (name + '.log')} info;\n"
        "events { worker_connections 64; }\n"
        "stream {\n"
        "  server {\n"
        f"    listen unix:{work / (name + '.sock')};\n"
        "    brix_root on;\n"
        f"    brix_export {work / 'export'};\n"
        "    brix_auth none;\n"
        f"{knobs}"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    process = subprocess.run(
        [nginx_bin, "-p", str(work), "-c", str(conf), "-t"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    output = (process.stderr or "") + (process.stdout or "")
    return process.returncode, output


def _record_manager_conflict(
    name: str, rc: int, output: str, results: list[tuple[bool, str]]
) -> None:
    named = all(
        fragment in output
        for fragment in ("brix_manager_mode", "brix_read_only", "mutually exclusive")
    )
    results.append(
        (
            rc != 0 and named,
            f"config: manager + brix_{name} is refused by nginx -t, "
            f"naming both directives "
            f"(rc={rc} {output.strip()[-240:]!r})",
        )
    )
    results.append(
        ("[emerg]" in output, f"config: manager + brix_{name} refusal is EMERG")
    )


def check_manager_mode_is_refused_at_config_time(
    base: Path, nginx_bin: str, results: list[tuple[bool, str]]
) -> None:
    """Reject manager/read-only role conflicts while accepting plain managers."""
    work = base / "rolecheck"
    (work / "export").mkdir(parents=True, exist_ok=True)
    (work / "logs").mkdir(parents=True, exist_ok=True)

    for name, knobs in (
        ("read_only", "    brix_read_only on;\n    brix_manager_mode on;\n"),
        (
            "read_only_public",
            "    brix_read_only_public on;\n    brix_manager_mode on;\n",
        ),
    ):
        rc, output = _try_manager_conf(work, nginx_bin, f"manager_{name}", knobs)
        _record_manager_conflict(name, rc, output, results)

    rc, output = _try_manager_conf(
        work, nginx_bin, "manager_alone", "    brix_manager_mode on;\n"
    )
    results.append(
        (
            rc == 0,
            f"config: brix_manager_mode WITHOUT read_only still parses — "
            f"plain manager nodes are unaffected "
            f"(rc={rc} {output.strip()[-160:]!r})",
        )
    )


# --------------------------------------------------------------------------- #
# 11. brix_read_only_public — the introspection surface                        #
# --------------------------------------------------------------------------- #

#: kXR_query infotypes that describe the SERVER rather than a path.  Mirrors
#: brix_query_is_server_introspection() in src/protocols/root/query/dispatch.c;
#: the check below parses that function so the two cannot drift apart.
QUERY_DISPATCH_C = REPO / "src/protocols/root/query/dispatch.c"


def public_restricted_infotypes() -> set[str]:
    """The server-introspection set, read out of the C gate function."""
    text = QUERY_DISPATCH_C.read_text(encoding="utf-8")
    body = text.split("brix_query_is_server_introspection(uint16_t infotype)", 1)[1]
    body = body.split("}", 1)[0]
    return set(re.findall(r"infotype\s*==\s*(kXR_Q\w+)", body))


def _is_not_authorized(status: int | None, response: bytes) -> bool:
    return status == kXR_error and _errnum(response) == kXR_NotAuthorized


def _append_failed_case(failures: list[str], passed: bool, detail: str) -> None:
    if not passed:
        failures.append(detail)


def _record_restricted_query(
    name: str,
    infotype: int,
    ro_status: int | None,
    ro_response: bytes,
    pub_status: int | None,
    pub_response: bytes,
    leaked: list[str],
    unchanged: list[str],
    results: list[tuple[bool, str]],
) -> None:
    refused = _is_not_authorized(pub_status, pub_response)
    pub_error = _errnum(pub_response) if pub_status == kXR_error else None
    _append_failed_case(leaked, refused, f"{name}({pub_status}/{pub_error})")
    results.append(
        (
            refused,
            f"read_only_public: query {name}({infotype}) is refused "
            f"kXR_NotAuthorized ({pub_status}/{pub_error} "
            f"{_errmsg(pub_response)[:60]!r})",
        )
    )
    changed = not _is_not_authorized(ro_status, ro_response)
    _append_failed_case(unchanged, changed, name)
    ro_error = _errnum(ro_response) if ro_status == kXR_error else None
    results.append(
        (
            changed,
            f"read_only_public: query {name}({infotype}) was not "
            f"already refused on plain read-only (ro={ro_status}/"
            f"{ro_error})",
        )
    )


def _response_outcome(
    status: int | None, response: bytes
) -> tuple[int | None, int | None]:
    error = _errnum(response) if status == kXR_error else None
    return status, error


def _record_path_query(
    name: str,
    infotype: int,
    ro_status: int | None,
    ro_response: bytes,
    pub_status: int | None,
    pub_response: bytes,
    over_refused: list[str],
    results: list[tuple[bool, str]],
) -> None:
    same = _response_outcome(pub_status, pub_response) == _response_outcome(
        ro_status, ro_response
    )
    refused = _is_not_authorized(pub_status, pub_response)
    _append_failed_case(over_refused, not refused, name)
    pub_error = _errnum(pub_response) if pub_status == kXR_error else None
    results.append(
        (
            same,
            f"read_only_public: query {name}({infotype}) is unchanged "
            f"from the plain read-only gateway (ro={ro_status} "
            f"public={pub_status}/"
            f"{pub_error})",
        )
    )


def _check_public_query(
    name: str,
    infotype: int,
    restricted: set[str],
    pub_port: int,
    ro_port: int,
    leaked: list[str],
    over_refused: list[str],
    unchanged: list[str],
    results: list[tuple[bool, str]],
) -> None:
    body = struct.pack(">HH4s8x", infotype, 0, b"\x00" * 4)
    payload = PUBLIC_FILE.encode() + b"\x00"
    ro_status, ro_response = _try(ro_port, kXR_query, body, payload, b"")
    pub_status, pub_response = _try(pub_port, kXR_query, body, payload, b"")
    if name in restricted:
        _record_restricted_query(
            name,
            infotype,
            ro_status,
            ro_response,
            pub_status,
            pub_response,
            leaked,
            unchanged,
            results,
        )
        return
    _record_path_query(
        name,
        infotype,
        ro_status,
        ro_response,
        pub_status,
        pub_response,
        over_refused,
        results,
    )


def check_public_mode_restricts_introspection(
    pub_port: int, ro_port: int, results: list[tuple[bool, str]]
) -> None:
    """Every kXR_query infotype, fired at BOTH postures and compared.

    The claim has two halves and one test has to carry both, because either half
    alone is satisfiable by a broken build: a server that refused every query
    would pass "introspection is restricted", and a server that refused none
    would pass "reads still work".  So each infotype is fired at the plain
    read-only gateway AND at the public one, and the ONLY permitted difference
    is that the restricted set flips from answered to kXR_NotAuthorized.
    """
    restricted = public_restricted_infotypes()
    results.append(
        (
            len(restricted) >= 4 and "kXR_Qconfig" not in restricted,
            f"read_only_public: the C names {len(restricted)} "
            f"server-introspection infotypes {sorted(restricted)}, and "
            f"kXR_Qconfig is filtered per key rather than refused",
        )
    )

    leaked, over_refused, unchanged = [], [], []
    ordered = sorted(query_subcodes().items(), key=lambda item: item[1])
    for name, infotype in ordered:
        _check_public_query(
            name,
            infotype,
            restricted,
            pub_port,
            ro_port,
            leaked,
            over_refused,
            unchanged,
            results,
        )

    results.append(
        (
            not leaked,
            f"read_only_public: no server-introspection query answered "
            f"(leaked: {leaked})",
        )
    )
    results.append(
        (
            not over_refused,
            f"read_only_public: no path-scoped query was collaterally "
            f"refused (over-refused: {over_refused})",
        )
    )
    results.append(
        (
            not unchanged,
            f"read_only_public: every restricted infotype was answerable "
            f"only because of the directive (already-refused: {unchanged})",
        )
    )


#: The kXR_Qconfig descriptor table, with its public_safe column.  Parsed out of
#: the C so a key added there — safe or withheld — lands in this check on its own.
QUERY_CONFIG_C = REPO / "src/protocols/root/query/config.c"


def qconfig_keys() -> dict[str, bool]:
    """{key: public_safe} straight from brix_qconfig_table[].

    Each row is now 4-column — ``{ "key", <fixed-response-line|NULL>,
    <emitter|NULL>, <public_safe> }`` — after the qconfig table was reshaped
    (9ab5c3f5) so a key that emits a constant line carries the string as data
    with a NULL emitter, instead of every key needing its own emitter function.
    The key is the first quoted token and public_safe is the trailing 0/1; the
    two middle columns (a possibly multi-line string literal, NULL, or an
    ``brix_qconfig_emit_*`` name) are skipped non-greedily so both fixed-line and
    emitter rows are read.  The old regex pinned an emitter immediately after the
    key and so matched zero rows against the reshaped table."""
    text = QUERY_CONFIG_C.read_text(encoding="utf-8")
    body = text.split("brix_qconfig_table[] = {", 1)[1].split("\n};", 1)[0]
    return {
        key: value == "1"
        for key, value in re.findall(
            r'\{\s*"([^"]+)"\s*,.*?,\s*([01])\s*\}', body, re.DOTALL
        )
    }


def _qconfig(port: int, key: str) -> tuple[int | None, bytes]:
    return _try(
        port, kXR_query, struct.pack(">HH4s8x", 7, 0, b"\x00" * 4), key.encode(), b""
    )


def _record_safe_qconfig(
    key: str,
    ro_status: int | None,
    ro_response: bytes,
    pub_status: int | None,
    pub_response: bytes,
    differed: list[str],
    results: list[tuple[bool, str]],
) -> None:
    same = pub_status == ro_status and pub_response == ro_response
    _append_failed_case(differed, same, key)
    results.append(
        (
            same and pub_status == kXR_ok,
            f"read_only_public: qconfig capability key {key!r} answers "
            f"identically to the plain read-only gateway "
            f"({pub_status} {pub_response[:48]!r})",
        )
    )


def _record_withheld_qconfig(
    key: str,
    ro_status: int | None,
    ro_response: bytes,
    pub_status: int | None,
    pub_response: bytes,
    leaked: list[str],
    results: list[tuple[bool, str]],
) -> None:
    encoded_key = key.encode()
    plain_value = ro_response.rstrip(b"\x00").strip()
    plain_served = ro_status == kXR_ok and plain_value != encoded_key
    results.append(
        (
            plain_served,
            f"read_only_public: qconfig key {key!r} IS served on the plain "
            f"read-only gateway ({ro_response[:48]!r})",
        )
    )
    echoed = pub_response.rstrip(b"\x00").strip() == encoded_key
    _append_failed_case(leaked, echoed, f"{key}={pub_response[:32]!r}")
    results.append(
        (
            pub_status == kXR_ok and echoed,
            f"read_only_public: qconfig deployment key {key!r} is withheld — "
            f"echoed like an unknown key "
            f"({pub_status} {pub_response[:48]!r})",
        )
    )
    value_hidden = plain_value not in pub_response or plain_value == encoded_key
    results.append(
        (
            value_hidden,
            f"read_only_public: withheld {key!r} value "
            f"{plain_value[:32]!r} appears nowhere in the public answer",
        )
    )


def _check_qconfig_key(
    key: str,
    public_safe: bool,
    pub_port: int,
    ro_port: int,
    leaked: list[str],
    differed: list[str],
    results: list[tuple[bool, str]],
) -> None:
    ro_status, ro_response = _qconfig(ro_port, key)
    pub_status, pub_response = _qconfig(pub_port, key)
    if public_safe:
        _record_safe_qconfig(
            key, ro_status, ro_response, pub_status, pub_response, differed, results
        )
        return
    _record_withheld_qconfig(
        key, ro_status, ro_response, pub_status, pub_response, leaked, results
    )


def check_public_mode_qconfig_is_filtered_per_key(
    pub_port: int, ro_port: int, results: list[tuple[bool, str]]
) -> None:
    """kXR_Qconfig answers PROTOCOL capability and withholds DEPLOYMENT identity.

    Refusing the whole infotype would hide nothing an anonymous client cannot
    establish by trying, and would cost it the vector-read geometry — XrdCl that
    cannot read readv_ior_max/readv_iov_max falls back to conservative defaults
    and issues many more, much smaller readv elements against the very endpoint
    that exists to stream bulk data.  So each key is fired at BOTH postures:

      * public_safe keys must answer byte-identically to the plain read-only
        gateway (a capability that silently changed value under the directive
        would be its own bug),
      * withheld keys must answer exactly like an UNKNOWN key — the reference
        do_Qconf default branch echoes the key name — so a restricted key is
        indistinguishable from one this build never supported,
      * and the withheld VALUE must not appear anywhere in the response.
    """
    keys = qconfig_keys()
    withheld = sorted(key for key, safe in keys.items() if not safe)
    results.append(
        (
            len(keys) >= 15 and bool(withheld),
            f"read_only_public: the C table names {len(keys)} kXR_Qconfig keys, "
            f"withheld: {withheld}",
        )
    )

    leaked, differed = [], []
    for key, public_safe in sorted(keys.items()):
        _check_qconfig_key(
            key, public_safe, pub_port, ro_port, leaked, differed, results
        )

    results.append(
        (
            not leaked,
            f"read_only_public: no deployment-identity qconfig key was "
            f"served (leaked: {leaked})",
        )
    )
    results.append(
        (
            not differed,
            f"read_only_public: no capability qconfig key changed value "
            f"under the directive (differed: {differed})",
        )
    )


def _collect_readv_limits(
    pub_port: int, results: list[tuple[bool, str]]
) -> dict[str, int]:
    limits = {}
    for key in ("readv_ior_max", "readv_iov_max", "pio_max", "bind_max"):
        status, response = _qconfig(pub_port, key)
        text = response.rstrip(b"\x00").strip().decode("latin-1")
        valid = status == kXR_ok and text.isdigit() and int(text) > 0
        if valid:
            limits[key] = int(text)
        results.append(
            (
                valid,
                f"read_only_public: qconfig {key} answers a bare "
                f"positive integer for atoi() ({status} {text!r})",
            )
        )
    return limits


def _record_readv_capabilities(pub_port: int, results: list[tuple[bool, str]]) -> None:
    status, response = _qconfig(pub_port, "readv")
    results.append(
        (
            status == kXR_ok and b"readv=1" in response,
            f"read_only_public: qconfig advertises readv support "
            f"({status} {response[:32]!r})",
        )
    )
    status, response = _qconfig(pub_port, "chksum")
    results.append(
        (
            status == kXR_ok and b"adler32" in response,
            f"read_only_public: qconfig advertises the checksum list "
            f"xrdcp negotiates with "
            f"({status} {response[:48]!r})",
        )
    )


def _run_readv_probe(
    session: socket.socket, segment_limit: int, results: list[tuple[bool, str]]
) -> None:
    status, response = _send(
        session, kXR_open, struct.pack(">HH12x", 0, kXR_open_read), PUBLIC_FILE.encode()
    )
    if status != kXR_ok:
        results.append((False, f"read_only_public: readv open failed ({status})"))
        return
    handle = response[:4]
    segments = min(4, segment_limit)
    body = b"".join(
        handle + struct.pack(">qi", index * 4, 4) for index in range(segments)
    )
    status, data = _send(session, kXR_readv, b"\x00" * 16, body)
    results.append(
        (
            status == kXR_ok and len(data) > 0,
            f"read_only_public: a kXR_readv of {segments} elements "
            f"sized from the advertised limits is served "
            f"({status}, {len(data)} B)",
        )
    )
    _send(session, kXR_close, handle + b"\x00" * 12)


def _probe_readv_geometry(
    pub_port: int, segment_limit: int, results: list[tuple[bool, str]]
) -> None:
    try:
        session = _session(pub_port)
    except (OSError, RuntimeError) as exc:
        results.append((False, f"read_only_public: readv session failed: {exc}"))
        return
    try:
        _run_readv_probe(session, segment_limit, results)
    except (OSError, ConnectionError) as exc:
        results.append((False, f"read_only_public: readv probe failed: {exc}"))
    finally:
        session.close()


def check_public_mode_readv_tuning_survives(
    pub_port: int, results: list[tuple[bool, str]]
) -> None:
    """Verify public qconfig tuning values drive a real vector read."""
    limits = _collect_readv_limits(pub_port, results)
    _record_readv_capabilities(pub_port, results)
    if "readv_iov_max" not in limits:
        results.append((False, "read_only_public: no readv geometry to exercise"))
        return
    _probe_readv_geometry(pub_port, limits["readv_iov_max"], results)


def _record_public_namespace_reads(
    session: socket.socket, results: list[tuple[bool, str]]
) -> None:
    status, response = _send(session, kXR_dirlist, b"\x00" * 16, b"/\x00")
    listed = PUBLIC_FILE.strip("/").encode() in response
    results.append(
        (
            status == kXR_ok and listed,
            f"read_only_public: dirlist still lists the namespace "
            f"({status} {response[:60]!r})",
        )
    )
    status, _response = _send(
        session, kXR_stat, b"\x00" * 16, PUBLIC_FILE.encode() + b"\x00"
    )
    results.append(
        (status == kXR_ok, f"read_only_public: stat still answers ({status})")
    )


def _read_public_chunks(session: socket.socket, handle: bytes) -> tuple[int, bytes]:
    streamed = b""
    status = kXR_ok
    for offset in (0, 8, 16):
        status, data = _send(session, kXR_read, handle + struct.pack(">qi", offset, 8))
        if status != kXR_ok:
            break
        streamed += data
    return status, streamed


def _record_public_stream(
    session: socket.socket, results: list[tuple[bool, str]]
) -> None:
    status, response = _send(
        session, kXR_open, struct.pack(">HH12x", 0, kXR_open_read), PUBLIC_FILE.encode()
    )
    results.append(
        (status == kXR_ok, f"read_only_public: read-open still succeeds ({status})")
    )
    if status != kXR_ok:
        return
    handle = response[:4]
    status, streamed = _read_public_chunks(session, handle)
    results.append(
        (
            status == kXR_ok and len(streamed) > 8,
            f"read_only_public: a multi-chunk streamed read returns bytes "
            f"({status}, {len(streamed)} B)",
        )
    )
    _send(session, kXR_close, handle + b"\x00" * 12)


def _record_public_checksum(
    session: socket.socket, results: list[tuple[bool, str]]
) -> None:
    status, response = _send(
        session,
        kXR_query,
        struct.pack(">HH4s8x", 3, 0, b"\x00" * 4),
        PUBLIC_FILE.encode() + b"\x00",
    )
    results.append(
        (
            status == kXR_ok,
            f"read_only_public: per-path checksum still answers "
            f"({status} {_errmsg(response)[:40]!r})",
        )
    )


def _run_public_read_surface(
    session: socket.socket, results: list[tuple[bool, str]]
) -> None:
    _record_public_namespace_reads(session, results)
    _record_public_stream(session, results)
    _record_public_checksum(session, results)


def check_public_mode_still_serves_data(
    port: int, results: list[tuple[bool, str]]
) -> None:
    """The directive must not cost the gateway its job.

    "Restricts introspection while still allowing data to be listed and
    read/streamed" is the requirement, so the read surface is exercised end to
    end on the public instance: dirlist, stat, open, a multi-chunk streamed
    read, and the per-path checksum xrdcp uses to verify a transfer.
    """
    try:
        s = _session(port)
    except (OSError, RuntimeError) as exc:
        results.append((False, f"read_only_public: session failed: {exc}"))
        return
    try:
        _run_public_read_surface(s, results)
    except (OSError, ConnectionError) as exc:
        results.append((False, f"read_only_public: read-surface probe failed: {exc}"))
    finally:
        s.close()


def check_public_mode_is_still_read_only(
    pub_port: int, results: list[tuple[bool, str]]
) -> None:
    """brix_read_only_public IMPLIES brix_read_only — assert it on the wire.

    The implication is applied in brix_shared_apply_read_only(), i.e. in the
    config finaliser rather than in any handler, so the only way to know it
    reached the write gates is to fire the mutation battery at a server that
    was configured with the public directive ALONE.
    """
    escaped = []
    for probe in probes():
        status, resp = _try(
            pub_port, probe.opcode, probe.body, probe.payload, probe.trailer
        )
        err = _errnum(resp) if status == kXR_error else None
        if err != kXR_fsReadOnly:
            escaped.append(f"{probe.name}({status}/{err})")
    results.append(
        (
            not escaped,
            f"read_only_public: every mutation refused as read-only "
            f"WITHOUT an explicit brix_read_only (escaped: {escaped})",
        )
    )


def _read_log_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _collect_startup_output(result, prefix: Path) -> str:
    output = (result.stderr or "") + (result.stdout or "")
    logs = sorted((prefix / "logs").glob("*.log"))
    return output + "".join(_read_log_text(path) for path in logs)


def check_override_is_logged(
    nginx_bin: str, prefix: Path, conf: Path, results: list[tuple[bool, str]], run
) -> None:
    """brix_read_only silently overriding brix_allow_write would be a nasty
    surprise in the other direction too: the server must SAY so.

    The NOTICE is emitted during the config merge, so it lands in the error log
    the config itself names (not on the -t stderr); both are inspected.
    """
    result = run([nginx_bin, "-p", str(prefix), "-c", str(conf), "-t"])
    output = _collect_startup_output(result, prefix)
    hit = [line for line in output.splitlines() if "overrides allow_write" in line]
    results.append(
        (
            bool(hit),
            f"read_only+allow_write: startup announces that read_only "
            f"overrides allow_write ({hit[:1]})",
        )
    )


# --------------------------------------------------------------------------- #
# entry point used by the main rig                                             #
# --------------------------------------------------------------------------- #


def run_deep_checks(
    *,
    ro_port: int,
    ro_prefix: Path,
    sub_port: int,
    pub_port: int,
    pub_prefix: Path,
    pub_export: Path,
    nginx_bin: str,
    base: Path,
    origin_root: Path,
    export_root: Path,
    results: list[tuple[bool, str]],
) -> None:
    """Every expansive family, each bracketed by a content-hash integrity check
    of both the origin tree and the gateway's own export."""
    families = (
        ("opcode space", lambda: check_opcode_space(ro_port, "read_only", results)),
        (
            "open options",
            lambda: check_open_option_space(ro_port, "read_only", results),
        ),
        (
            "unauthenticated",
            lambda: check_unauthenticated_mutations(ro_port, "read_only", results),
        ),
        # brix_data_substreams merges to ON, so the DOCUMENTED gateway is the
        # one that accepts a secondary channel; the extra posture is the
        # explicit off.
        (
            "bound stream (default)",
            lambda: check_bound_stream(
                ro_port, "read_only", substreams=True, results=results
            ),
        ),
        (
            "bound stream (substreams off)",
            lambda: check_bound_stream(
                sub_port, "read_only+substreams off", substreams=False, results=results
            ),
        ),
        (
            "signed mutation",
            lambda: check_signed_mutation(ro_port, "read_only", results),
        ),
        ("query subcodes", lambda: check_query_subcodes(ro_port, "read_only", results)),
        (
            "session opcodes",
            lambda: check_session_ops_cannot_lift_the_gate(
                ro_port, "read_only", results
            ),
        ),
        ("path shapes", lambda: check_path_shapes(ro_port, "read_only", results)),
        ("mutation storm", lambda: check_mutation_storm(ro_port, "read_only", results)),
        (
            "reload",
            lambda: check_reload_persistence(ro_prefix, ro_port, "read_only", results),
        ),
    )
    for name, family in families:
        origin_before = tree_digest(origin_root)
        export_before = tree_digest(export_root)
        family()
        check_integrity(
            f"read_only: origin after {name}", origin_root, origin_before, results
        )
        check_integrity(
            f"read_only: gateway export after {name}",
            export_root,
            export_before,
            results,
            allow_server_owned=True,
        )

    # The public posture gets the mutation battery too, bracketed against ITS
    # own export: brix_read_only_public reaches the write gates only through the
    # implication applied in the config finaliser, so it has to be proven on the
    # wire and not assumed from the plain read-only instance's result rows.
    for name, family in (
        (
            "public introspection",
            lambda: check_public_mode_restricts_introspection(
                pub_port, ro_port, results
            ),
        ),
        (
            "public read surface",
            lambda: check_public_mode_still_serves_data(pub_port, results),
        ),
        (
            "public qconfig filtering",
            lambda: check_public_mode_qconfig_is_filtered_per_key(
                pub_port, ro_port, results
            ),
        ),
        (
            "public readv tuning",
            lambda: check_public_mode_readv_tuning_survives(pub_port, results),
        ),
        (
            "public mutations",
            lambda: check_public_mode_is_still_read_only(pub_port, results),
        ),
    ):
        origin_before = tree_digest(origin_root)
        export_before = tree_digest(pub_export)
        family()
        check_integrity(
            f"read_only_public: origin after {name}",
            origin_root,
            origin_before,
            results,
        )
        check_integrity(
            f"read_only_public: gateway export after {name}",
            pub_export,
            export_before,
            results,
            allow_server_owned=True,
        )

    check_manager_mode_is_refused_at_config_time(base, nginx_bin, results)
    check_read_surface_intact(ro_port, "read_only", results)
    check_read_surface_intact(pub_port, "read_only_public", results)
