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

from split_continuation import load as _load_shard_root_readonly_gateway_deep_ext2
_load_shard_root_readonly_gateway_deep_ext2(globals(), __file__, "root_readonly_gateway_deep_ext2.py")

from split_continuation import load as _load_shard_root_readonly_gateway_deep_ext
_load_shard_root_readonly_gateway_deep_ext(globals(), __file__, "root_readonly_gateway_deep_ext.py")
