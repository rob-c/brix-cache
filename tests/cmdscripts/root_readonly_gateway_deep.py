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
    DOC_PAGE, PUBLIC_FILE, REPO, Probe,
    _errmsg, _errnum, _send, _session, _wait,
    kXR_NotAuthorized, kXR_Unsupported, kXR_bind, kXR_close, kXR_error,
    kXR_dirlist, kXR_fsReadOnly, kXR_mkdir, kXR_ok, kXR_open, kXR_open_read,
    kXR_query, kXR_read, kXR_readv, kXR_set, kXR_sigver, kXR_stat, kXR_write,
    mutating_opcodes, probes,
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
    return {name: int(value)
            for name, value in re.findall(r"#define\s+(kXR_[a-z]+)\s+(\d+)", body)}


def query_subcodes() -> dict[str, int]:
    """Every kXR_Q* infotype in opcodes.h — the second dimension of kXR_query,
    which the opcode sweep can only exercise one value of."""
    text = OPCODES_H.read_text(encoding="utf-8")
    return {name: int(value)
            for name, value in re.findall(r"#define\s+(kXR_Q\w+)\s+(\d+)", text)}


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
    return {name: int(value, 0)
            for name, value in re.findall(r"#define\s+(kXR_\w+)\s+(0x[0-9a-fA-F]+)",
                                          text)}


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
            except OSError as exc:                    # unreadable == still a diff
                out[rel] = f"unreadable:{exc.errno}"
    return out


def _digest_diff(before: dict[str, str],
                 after: dict[str, str]) -> tuple[list[str], list[str], list[str]]:
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = sorted(k for k in set(before) & set(after) if before[k] != after[k])
    return added, removed, changed


def check_integrity(label: str, root: Path, before: dict[str, str],
                    results: list[tuple[bool, str]], *,
                    allow_server_owned: bool = False) -> None:
    added, removed, changed = _digest_diff(before, tree_digest(root))
    if allow_server_owned:
        added = [p for p in added if Path(p).name not in SERVER_OWNED]
    results.append((not (added or removed or changed),
                    f"{label}: content digest unchanged "
                    f"(added={added} removed={removed} changed={changed})"))


# --------------------------------------------------------------------------- #
# 1. whole-opcode-space sweep                                                  #
# --------------------------------------------------------------------------- #

def _sweep_frame(name: str, opcode: int,
                 known: dict[int, Probe]) -> tuple[bytes, bytes, bytes]:
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


def _try(port: int, opcode: int, body: bytes, payload: bytes,
         trailer: bytes) -> tuple[int | None, bytes]:
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


def check_opcode_space(port: int, label: str,
                       results: list[tuple[bool, str]]) -> None:
    """Fire EVERY defined request id, classified by the C dispatch tables."""
    ops = wire_opcodes()
    routed = routed_opcodes()
    known = {p.opcode: p for p in probes()}
    unrouted = sorted(set(ops) - set().union(*routed.values()))

    results.append((len(ops) >= 37,
                    f"{label}: opcodes.h defines {len(ops)} request ids "
                    f"(sweeping all of them)"))
    stray = sorted(set().union(*routed.values()) - set(ops))
    results.append((not stray,
                    f"{label}: every dispatched opcode name exists in opcodes.h "
                    f"(stray: {stray})"))

    accepted_unrouted, unrefused_write = [], []
    for name, opcode in sorted(ops.items(), key=lambda kv: kv[1]):
        body, payload, trailer = _sweep_frame(name, opcode, known)
        status, resp = _try(port, opcode, body, payload, trailer)
        err = _errnum(resp) if status == kXR_error else None
        if name in routed["write"]:
            ok = status == kXR_error and err == kXR_fsReadOnly
            if not ok:
                unrefused_write.append(f"{name}({status}/{err})")
            results.append((ok, f"{label}: sweep {name}({opcode}) is write-routed "
                                f"-> kXR_fsReadOnly (got {status}/{err})"))
        elif name in unrouted:
            ok = status is not None and status != kXR_ok
            if not ok:
                accepted_unrouted.append(f"{name}({status})")
            results.append((ok, f"{label}: sweep {name}({opcode}) is routed by no "
                                f"dispatch table -> refused (got {status}/{err} "
                                f"{_errmsg(resp)!r})"))
        else:
            # read/session/signing surface: the sweep's job here is to prove the
            # frame changes nothing — asserted by the digest bracket around the
            # whole sweep — so only the outcome is recorded.
            results.append((True, f"{label}: sweep {name}({opcode}) is "
                                  f"{_table_of(name, routed)}-routed, answered "
                                  f"{status}/{err}"))
    results.append((not unrefused_write,
                    f"{label}: every write-routed opcode refused in the sweep "
                    f"(missed: {unrefused_write})"))
    results.append((not accepted_unrouted,
                    f"{label}: no unrouted opcode was accepted "
                    f"(accepted: {accepted_unrouted})"))
    results.append((bool(unrouted),
                    f"{label}: unrouted opcodes exercised: {unrouted}"))


def _table_of(name: str, routed: dict[str, set[str]]) -> str:
    return "+".join(sorted(k for k, v in routed.items() if name in v)) or "none"


# --------------------------------------------------------------------------- #
# 2. open option-word sweep                                                    #
# --------------------------------------------------------------------------- #

def check_open_option_space(port: int, label: str,
                            results: list[tuple[bool, str]]) -> None:
    """Every single option bit, and every combination of the write bits.

    The expectation comes from BRIX_OPEN_WRITE_BITS in the C: any option word
    intersecting it is a write open and MUST draw kXR_fsReadOnly; any word that
    does not must NOT.  A new write-implying bit added to the macro is swept
    here the moment it is defined.
    """
    mask = open_write_mask()
    values = open_flag_values()
    write_bits = sorted(b for b in (1 << n for n in range(16)) if b & mask)
    results.append((bin(mask).count("1") >= 5,
                    f"{label}: BRIX_OPEN_WRITE_BITS parsed from the C = "
                    f"0x{mask:04x} ({bin(mask).count('1')} bits)"))

    words = {1 << n for n in range(16)}
    for combo in range(1, 1 << len(write_bits)):
        word = 0
        for index, bit in enumerate(write_bits):
            if combo & (1 << index):
                word |= bit
        words.add(word)
        words.add(word | kXR_open_read)

    names = {value: name for name, value in values.items()}
    bad_refusal, bad_pass = [], []
    for word in sorted(words):
        status, resp = _try(port, kXR_open,
                            struct.pack(">HH12x", 0o644, word),
                            PUBLIC_FILE.encode(), b"")
        err = _errnum(resp) if status == kXR_error else None
        refused = status == kXR_error and err == kXR_fsReadOnly
        expect = bool(word & mask)
        if expect and not refused:
            bad_pass.append(f"0x{word:04x}({status}/{err})")
        if not expect and refused:
            bad_refusal.append(f"0x{word:04x}")
        results.append((refused == expect,
                        f"{label}: open options 0x{word:04x} "
                        f"[{names.get(word, 'combination')}] "
                        f"{'refused' if expect else 'allowed'} "
                        f"(got {status}/{err})"))
    results.append((not bad_pass,
                    f"{label}: every write-implying option word refused "
                    f"(escaped: {bad_pass})"))
    results.append((not bad_refusal,
                    f"{label}: no read-only option word was refused as "
                    f"read-only (misrefused: {bad_refusal})"))


# --------------------------------------------------------------------------- #
# 3. pre-login and pre-handshake                                               #
# --------------------------------------------------------------------------- #

def check_unauthenticated_mutations(port: int, label: str,
                                    results: list[tuple[bool, str]]) -> None:
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
            status, resp = _send(s, probe.opcode, probe.body, probe.payload,
                                 probe.trailer)
        except (OSError, ConnectionError):
            status, resp = None, b""
        finally:
            s.close()
        ok = status != kXR_ok
        if not ok:
            accepted.append(probe.name)
        results.append((ok, f"{label}: pre-login {probe.name} not accepted "
                            f"(status={status} err={_errnum(resp)})"))
    results.append((not accepted,
                    f"{label}: no mutation accepted before login "
                    f"(accepted: {accepted})"))

    # Before the handshake the server has no session at all: the frame must not
    # be executed, whatever it answers (error, or a dropped connection).
    try:
        s = socket.create_connection((HOST, port), timeout=8)
        s.settimeout(6)
        try:
            s.sendall(H.make_request(b"\x00\x09", kXR_mkdir,
                                     struct.pack(">8xHH4x", 0, 0o755),
                                     b"/pre_handshake_mkdir"))
            status, resp = H._recv_response(s)
        finally:
            s.close()
    except (OSError, ConnectionError):
        status, resp = None, b""
    results.append((status != kXR_ok,
                    f"{label}: mkdir before the handshake is not accepted "
                    f"(status={status} err={_errnum(resp)})"))


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


def check_bound_stream(port: int, label: str, *, substreams: bool,
                       results: list[tuple[bool, str]]) -> None:
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
            results.append((False, f"{label}: primary login for bind failed "
                                   f"({hs}/{proto}/{login})"))
            return
        sessid = body[:16]
        secondary, status, resp = _bind_secondary(port, sessid)
        try:
            if not substreams:
                results.append((status == kXR_error
                                and _errnum(resp) == kXR_Unsupported,
                                f"{label}: kXR_bind refused when "
                                f"brix_data_substreams is off "
                                f"({status}/{_errnum(resp)} {_errmsg(resp)!r})"))
                return
            results.append((status == kXR_ok,
                            f"{label}: kXR_bind accepted with substreams on "
                            f"({status}/{_errnum(resp)} {_errmsg(resp)!r})"))
            if status != kXR_ok:
                return
            # The one opcode a bound stream may carry.
            st, rb = _send(secondary, kXR_write,
                           b"\x00" * 4 + struct.pack(">q4x", 0), b"X" * 8)
            results.append((st == kXR_error and _errnum(rb) == kXR_fsReadOnly,
                            f"{label}: bound-stream kXR_write -> kXR_fsReadOnly "
                            f"({st}/{_errnum(rb)} {_errmsg(rb)!r})"))
            # Everything else must be refused before the write gate is reached.
            st, rb = _send(secondary, kXR_mkdir,
                           struct.pack(">8xHH4x", 0, 0o755), b"/bound_mkdir")
            results.append((st == kXR_error
                            and _errnum(rb) in (kXR_NotAuthorized, kXR_fsReadOnly),
                            f"{label}: bound-stream kXR_mkdir refused "
                            f"({st}/{_errnum(rb)} {_errmsg(rb)!r})"))
            st, rb = _send(secondary, kXR_open,
                           struct.pack(">HH12x", 0o644, 0x0028), b"/bound_open.dat")
            results.append((st == kXR_error
                            and _errnum(rb) in (kXR_NotAuthorized, kXR_fsReadOnly),
                            f"{label}: bound-stream write-open refused "
                            f"({st}/{_errnum(rb)} {_errmsg(rb)!r})"))
        finally:
            secondary.close()
    except (OSError, ConnectionError) as exc:
        results.append((False, f"{label}: bound-stream probe failed: {exc}"))
    finally:
        primary.close()


# --------------------------------------------------------------------------- #
# 5. signing envelope                                                          #
# --------------------------------------------------------------------------- #

def check_signed_mutation(port: int, label: str,
                          results: list[tuple[bool, str]]) -> None:
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
        st, resp = _send(s, kXR_mkdir, struct.pack(">8xHH4x", 0, 0o755),
                         b"/signed_mkdir")
        results.append((st == kXR_error and _errnum(resp) == kXR_fsReadOnly,
                        f"{label}: a mutation inside a kXR_sigver envelope is "
                        f"still refused ({st}/{_errnum(resp)} {_errmsg(resp)!r})"))
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


def check_path_shapes(port: int, label: str,
                      results: list[tuple[bool, str]]) -> None:
    """No spelling of a mutating path may be accepted — and none may escape the
    export either, which the integrity bracket around this family proves."""
    accepted = []
    for name, path in PATH_SHAPES:
        status, resp = _try(port, kXR_mkdir, struct.pack(">8xHH4x", 0, 0o755),
                            path, b"")
        err = _errnum(resp) if status == kXR_error else None
        ok = status != kXR_ok
        if not ok:
            accepted.append(name)
        results.append((ok, f"{label}: mkdir with a {name} path is not accepted "
                            f"({status}/{err} {_errmsg(resp)!r})"))
    results.append((not accepted,
                    f"{label}: no path shape was accepted (accepted: {accepted})"))


# --------------------------------------------------------------------------- #
# 6b. kXR_query subcodes                                                       #
# --------------------------------------------------------------------------- #

def check_query_subcodes(port: int, label: str,
                         results: list[tuple[bool, str]]) -> None:
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
        status, resp = _try(port, kXR_query, body,
                            PUBLIC_FILE.encode() + b"\x00", b"")
        err = _errnum(resp) if status == kXR_error else None
        answered.append(status is not None)
        results.append((status is not None,
                        f"{label}: query {name}({infotype}) answered "
                        f"{status}/{err} {_errmsg(resp)!r}"))
    results.append((all(answered) and len(answered) >= 13,
                    f"{label}: every kXR_query infotype in opcodes.h was "
                    f"exercised ({len(answered)})"))


# --------------------------------------------------------------------------- #
# 6c. session opcodes cannot lift the gate                                     #
# --------------------------------------------------------------------------- #

def check_session_ops_cannot_lift_the_gate(port: int, label: str,
                                           results: list[tuple[bool, str]]) -> None:
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
            st, resp = _send(s, kXR_set, struct.pack(">B15x", modifier),
                             b"brix-readonly-probe\n")
            results.append((st in (kXR_ok, kXR_error),
                            f"{label}: kXR_set {what} answered {st}/"
                            f"{_errnum(resp)}"))
        st, resp = _send(s, kXR_set, struct.pack(">B15x", 0x00),
                         b"cms.space 1000000 999999\n")
        results.append((st in (kXR_ok, kXR_error),
                        f"{label}: kXR_set cms.space answered {st}/"
                        f"{_errnum(resp)}"))
        st, resp = _send(s, kXR_mkdir, struct.pack(">8xHH4x", 0, 0o755),
                         b"/after_set_mkdir")
        results.append((st == kXR_error and _errnum(resp) == kXR_fsReadOnly,
                        f"{label}: a mutation after kXR_set is still refused "
                        f"({st}/{_errnum(resp)} {_errmsg(resp)!r})"))
        # A second login on a live session must not re-negotiate the posture.
        s.sendall(H.make_login_req())
        st, resp = H._recv_response(s)
        results.append((True, f"{label}: re-login on a live session answered "
                              f"{st}/{_errnum(resp)}"))
        st, resp = _send(s, kXR_mkdir, struct.pack(">8xHH4x", 0, 0o755),
                         b"/after_relogin_mkdir")
        results.append((st == kXR_error and _errnum(resp) == kXR_fsReadOnly,
                        f"{label}: a mutation after a re-login is still refused "
                        f"({st}/{_errnum(resp)} {_errmsg(resp)!r})"))
    except (OSError, ConnectionError) as exc:
        results.append((False, f"{label}: session-opcode probe failed: {exc}"))
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# 7. concurrency storm                                                         #
# --------------------------------------------------------------------------- #

def check_mutation_storm(port: int, label: str,
                         results: list[tuple[bool, str]], *,
                         threads: int = 8) -> None:
    """The gate is a per-request check, not a startup latch: prove it holds when
    many connections mutate at once (a config-merge value could in principle be
    read racily; a per-connection cache could be primed by a read first)."""
    table = probes()
    outcomes: list[tuple[str, int | None, int | None]] = []
    lock = threading.Lock()

    def worker(index: int) -> None:
        local = []
        for probe in table[index::threads]:
            status, resp = _try(port, probe.opcode, probe.body, probe.payload,
                                probe.trailer)
            local.append((probe.name, status,
                          _errnum(resp) if status == kXR_error else None))
        with lock:
            outcomes.extend(local)

    workers = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(threads)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join(timeout=120)

    escaped = [f"{n}({s}/{e})" for n, s, e in outcomes if e != kXR_fsReadOnly]
    results.append((len(outcomes) == len(table),
                    f"{label}: storm ran every probe concurrently "
                    f"({len(outcomes)}/{len(table)} across {threads} threads)"))
    results.append((not escaped,
                    f"{label}: every concurrent mutation refused as read-only "
                    f"(escaped: {escaped})"))


# --------------------------------------------------------------------------- #
# 8. reload persistence                                                        #
# --------------------------------------------------------------------------- #

def check_reload_persistence(prefix: Path, port: int, label: str,
                             results: list[tuple[bool, str]]) -> None:
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
    results.append((_wait(port), f"{label}: gateway accepts connections after "
                                 f"SIGHUP"))
    survived = []
    for probe in probes():
        status, resp = _try(port, probe.opcode, probe.body, probe.payload,
                            probe.trailer)
        err = _errnum(resp) if status == kXR_error else None
        if err != kXR_fsReadOnly:
            survived.append(f"{probe.name}({status}/{err})")
    results.append((not survived,
                    f"{label}: every mutation still refused after a reload "
                    f"(escaped: {survived})"))


# --------------------------------------------------------------------------- #
# 9. reads keep working under every posture                                    #
# --------------------------------------------------------------------------- #

def check_read_surface_intact(port: int, label: str,
                              results: list[tuple[bool, str]]) -> None:
    """After the whole expansive run, the gateway must still be a gateway."""
    try:
        s = _session(port)
    except (OSError, RuntimeError) as exc:
        results.append((False, f"{label}: session after the sweep failed: {exc}"))
        return
    try:
        st, resp = _send(s, kXR_open, struct.pack(">HH12x", 0, kXR_open_read),
                         PUBLIC_FILE.encode())
        results.append((st == kXR_ok,
                        f"{label}: read-open still succeeds after the full sweep "
                        f"({st}/{_errnum(resp)} {_errmsg(resp)!r})"))
        if st == kXR_ok:
            handle = resp[:4]
            st, data = _send(s, kXR_read, handle + struct.pack(">qi", 0, 64))
            results.append((st == kXR_ok and data,
                            f"{label}: read still returns bytes after the sweep"))
            _send(s, kXR_close, handle + b"\x00" * 12)
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# 10. the manager/read-only role conflict is fatal                             #
# --------------------------------------------------------------------------- #

def check_manager_mode_is_refused_at_config_time(
        base: Path, nginx_bin: str, results: list[tuple[bool, str]]) -> None:
    """`brix_manager_mode on` + `brix_read_only on` must not start AT ALL.

    manager_redirect_mutation() runs BEFORE the local write gate and answers a
    path mutation with a redirect to a data node, so on a manager the read-only
    switch does not make the namespace read-only — it hands the client the
    address of a node that will accept the write.  An operator who writes both
    directives believes they have a read-only endpoint and does not, so the pair
    is refused by brix_merge_srv_readonly_role_check() at config time: nginx -t
    fails, the master never starts, and the error names both directives.

    Three arms, because "it failed" is not the assertion — WHY it failed is:
      1. read_only + manager_mode      -> EMERG naming both directives
      2. read_only_public + manager_mode -> the same, since public implies
                                            read_only (and the message says so)
      3. manager_mode alone            -> still perfectly valid; the check must
                                          not have broken plain manager nodes
    """
    work = base / "rolecheck"
    (work / "export").mkdir(parents=True, exist_ok=True)
    (work / "logs").mkdir(parents=True, exist_ok=True)

    def _try_conf(name: str, knobs: str) -> tuple[int, str]:
        conf = work / f"{name}.conf"
        conf.write_text(
            "daemon off;\n"
            f"error_log {work / 'logs' / (name + '.log')} info;\n"
            "events { worker_connections 64; }\n"
            "stream {\n"
            "  server {\n"
            # A unix socket, not a TCP port: `nginx -t` OPENS the listening
            # sockets before it reports success, so a port here would either
            # collide with the lane or need a ladder slot of its own.
            f"    listen unix:{work / (name + '.sock')};\n"
            "    brix_root on;\n"
            f"    brix_export {work / 'export'};\n"
            "    brix_auth none;\n"
            f"{knobs}"
            "  }\n"
            "}\n", encoding="utf-8")
        proc = subprocess.run([nginx_bin, "-p", str(work), "-c", str(conf), "-t"],
                              capture_output=True, text=True, timeout=60)
        return proc.returncode, (proc.stderr or "") + (proc.stdout or "")

    for name, knobs in (
            ("read_only", "    brix_read_only on;\n    brix_manager_mode on;\n"),
            ("read_only_public",
             "    brix_read_only_public on;\n    brix_manager_mode on;\n")):
        rc, out = _try_conf(f"manager_{name}", knobs)
        named = ("brix_manager_mode" in out and "brix_read_only" in out
                 and "mutually exclusive" in out)
        results.append((rc != 0 and named,
                        f"config: brix_manager_mode + brix_{name} is refused by "
                        f"nginx -t, naming both directives "
                        f"(rc={rc} {out.strip()[-240:]!r})"))
        results.append(("[emerg]" in out,
                        f"config: the brix_manager_mode + brix_{name} refusal is "
                        f"EMERG (the master does not start)"))

    rc, out = _try_conf("manager_alone", "    brix_manager_mode on;\n")
    results.append((rc == 0,
                    f"config: brix_manager_mode WITHOUT read_only still parses — "
                    f"plain manager nodes are unaffected "
                    f"(rc={rc} {out.strip()[-160:]!r})"))


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


def check_public_mode_restricts_introspection(
        pub_port: int, ro_port: int, results: list[tuple[bool, str]]) -> None:
    """Every kXR_query infotype, fired at BOTH postures and compared.

    The claim has two halves and one test has to carry both, because either half
    alone is satisfiable by a broken build: a server that refused every query
    would pass "introspection is restricted", and a server that refused none
    would pass "reads still work".  So each infotype is fired at the plain
    read-only gateway AND at the public one, and the ONLY permitted difference
    is that the restricted set flips from answered to kXR_NotAuthorized.
    """
    restricted = public_restricted_infotypes()
    results.append((len(restricted) >= 4 and "kXR_Qconfig" not in restricted,
                    f"read_only_public: the C names {len(restricted)} "
                    f"server-introspection infotypes {sorted(restricted)}, and "
                    f"kXR_Qconfig is filtered per key rather than refused"))

    leaked, over_refused, unchanged = [], [], []
    for name, infotype in sorted(query_subcodes().items(), key=lambda kv: kv[1]):
        body = struct.pack(">HH4s8x", infotype, 0, b"\x00" * 4)
        payload = PUBLIC_FILE.encode() + b"\x00"
        ro_st, ro_resp = _try(ro_port, kXR_query, body, payload, b"")
        pub_st, pub_resp = _try(pub_port, kXR_query, body, payload, b"")
        pub_err = _errnum(pub_resp) if pub_st == kXR_error else None
        refused = pub_st == kXR_error and pub_err == kXR_NotAuthorized

        if name in restricted:
            if not refused:
                leaked.append(f"{name}({pub_st}/{pub_err})")
            results.append((refused,
                            f"read_only_public: query {name}({infotype}) is "
                            f"refused kXR_NotAuthorized "
                            f"({pub_st}/{pub_err} {_errmsg(pub_resp)[:60]!r})"))
            # The restriction has to be a REAL change: an infotype that was
            # already answering kXR_NotAuthorized on the plain gateway would
            # make the refusal above pass without the directive doing anything.
            # (kXR_ok is too strong an expectation — some infotypes answer with
            # their own error for reasons that have nothing to do with this
            # posture; what must not already be true is the refusal itself.)
            ro_err = _errnum(ro_resp) if ro_st == kXR_error else None
            changed = not (ro_st == kXR_error and ro_err == kXR_NotAuthorized)
            if not changed:
                unchanged.append(name)
            results.append((changed,
                            f"read_only_public: query {name}({infotype}) was "
                            f"NOT already refused on the plain read-only "
                            f"gateway, so the directive is what refused it "
                            f"(ro={ro_st}/{ro_err})"))
        else:
            same = (pub_st == ro_st
                    and (_errnum(pub_resp) if pub_st == kXR_error else None)
                        == (_errnum(ro_resp) if ro_st == kXR_error else None))
            if refused:
                over_refused.append(name)
            results.append((same,
                            f"read_only_public: query {name}({infotype}) is "
                            f"unchanged from the plain read-only gateway "
                            f"(ro={ro_st} public={pub_st}/{pub_err})"))

    results.append((not leaked,
                    f"read_only_public: no server-introspection query answered "
                    f"(leaked: {leaked})"))
    results.append((not over_refused,
                    f"read_only_public: no path-scoped query was collaterally "
                    f"refused (over-refused: {over_refused})"))
    results.append((not unchanged,
                    f"read_only_public: every restricted infotype was answerable "
                    f"only because of the directive (already-refused: {unchanged})"))


#: The kXR_Qconfig descriptor table, with its public_safe column.  Parsed out of
#: the C so a key added there — safe or withheld — lands in this check on its own.
QUERY_CONFIG_C = REPO / "src/protocols/root/query/config.c"


def qconfig_keys() -> dict[str, bool]:
    """{key: public_safe} straight from brix_qconfig_table[]."""
    text = QUERY_CONFIG_C.read_text(encoding="utf-8")
    body = text.split("brix_qconfig_table[] = {", 1)[1].split("\n};", 1)[0]
    return {key: value == "1"
            for key, value in re.findall(
                r'\{\s*"([^"]+)"\s*,\s*brix_qconfig_emit_\w+\s*,\s*(\d)\s*\}', body)}


def _qconfig(port: int, key: str) -> tuple[int | None, bytes]:
    return _try(port, kXR_query, struct.pack(">HH4s8x", 7, 0, b"\x00" * 4),
                key.encode(), b"")


def check_public_mode_qconfig_is_filtered_per_key(
        pub_port: int, ro_port: int, results: list[tuple[bool, str]]) -> None:
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
    results.append((len(keys) >= 15 and any(not safe for safe in keys.values()),
                    f"read_only_public: the C table names {len(keys)} kXR_Qconfig "
                    f"keys, withheld: {sorted(k for k, v in keys.items() if not v)}"))

    leaked, differed = [], []
    for key, public_safe in sorted(keys.items()):
        ro_st, ro_resp = _qconfig(ro_port, key)
        pub_st, pub_resp = _qconfig(pub_port, key)
        echo = pub_resp.rstrip(b"\x00").strip() == key.encode()

        if public_safe:
            same = pub_st == ro_st and pub_resp == ro_resp
            if not same:
                differed.append(key)
            results.append((same and pub_st == kXR_ok,
                            f"read_only_public: qconfig capability key {key!r} "
                            f"answers identically to the plain read-only gateway "
                            f"({pub_st} {pub_resp[:48]!r})"))
        else:
            # The plain gateway must still serve it, or "withheld" is vacuous.
            results.append((ro_st == kXR_ok and not
                            ro_resp.rstrip(b"\x00").strip() == key.encode(),
                            f"read_only_public: qconfig key {key!r} IS served on "
                            f"the plain read-only gateway ({ro_resp[:48]!r})"))
            if not echo:
                leaked.append(f"{key}={pub_resp[:32]!r}")
            results.append((pub_st == kXR_ok and echo,
                            f"read_only_public: qconfig deployment key {key!r} is "
                            f"withheld — echoed like an unknown key "
                            f"({pub_st} {pub_resp[:48]!r})"))
            # Belt and braces: the real value must not appear at all.
            real = ro_resp.rstrip(b"\x00").strip()
            results.append((real not in pub_resp or real == key.encode(),
                            f"read_only_public: the withheld {key!r} value "
                            f"{real[:32]!r} appears nowhere in the public answer"))

    results.append((not leaked,
                    f"read_only_public: no deployment-identity qconfig key was "
                    f"served (leaked: {leaked})"))
    results.append((not differed,
                    f"read_only_public: no capability qconfig key changed value "
                    f"under the directive (differed: {differed})"))


def check_public_mode_readv_tuning_survives(
        pub_port: int, results: list[tuple[bool, str]]) -> None:
    """The specific regression this filtering exists to prevent.

    XrdCl sizes a VectorRead from readv_ior_max (bytes per element) and
    readv_iov_max (elements per request), both parsed with atoi() from a BARE
    integer line — a missing or non-numeric answer silently drops the client to
    its built-in defaults.  So it is not enough that the query "succeeds": the
    answer has to be a positive integer, and a real kXR_readv sized from it has
    to be accepted.
    """
    limits = {}
    for key in ("readv_ior_max", "readv_iov_max", "pio_max", "bind_max"):
        st, resp = _qconfig(pub_port, key)
        text = resp.rstrip(b"\x00").strip().decode("latin-1")
        ok = st == kXR_ok and text.isdigit() and int(text) > 0
        if ok:
            limits[key] = int(text)
        results.append((ok, f"read_only_public: qconfig {key} answers a bare "
                            f"positive integer for atoi() ({st} {text!r})"))

    st, resp = _qconfig(pub_port, "readv")
    results.append((st == kXR_ok and b"readv=1" in resp,
                    f"read_only_public: qconfig advertises readv support "
                    f"({st} {resp[:32]!r})"))
    st, resp = _qconfig(pub_port, "chksum")
    results.append((st == kXR_ok and b"adler32" in resp,
                    f"read_only_public: qconfig advertises the checksum list "
                    f"xrdcp negotiates with ({st} {resp[:48]!r})"))

    # And the advertised geometry is honoured on the wire, not just quoted.
    if "readv_iov_max" not in limits:
        results.append((False, "read_only_public: no readv geometry to exercise"))
        return
    try:
        s = _session(pub_port)
    except (OSError, RuntimeError) as exc:
        results.append((False, f"read_only_public: readv session failed: {exc}"))
        return
    try:
        st, resp = _send(s, kXR_open, struct.pack(">HH12x", 0, kXR_open_read),
                         PUBLIC_FILE.encode())
        if st != kXR_ok:
            results.append((False, f"read_only_public: readv open failed ({st})"))
            return
        handle = resp[:4]
        segments = min(4, limits["readv_iov_max"])
        body = b"".join(handle + struct.pack(">qi", i * 4, 4)
                        for i in range(segments))
        st, data = _send(s, kXR_readv, b"\x00" * 16, body)
        results.append((st == kXR_ok and len(data) > 0,
                        f"read_only_public: a kXR_readv of {segments} elements "
                        f"sized from the advertised limits is served "
                        f"({st}, {len(data)} B)"))
        _send(s, kXR_close, handle + b"\x00" * 12)
    except (OSError, ConnectionError) as exc:
        results.append((False, f"read_only_public: readv probe failed: {exc}"))
    finally:
        s.close()


def check_public_mode_still_serves_data(
        port: int, results: list[tuple[bool, str]]) -> None:
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
        st, resp = _send(s, kXR_dirlist, b"\x00" * 16, b"/\x00")
        results.append((st == kXR_ok and PUBLIC_FILE.strip("/").encode() in resp,
                        f"read_only_public: dirlist still lists the namespace "
                        f"({st} {resp[:60]!r})"))
        st, resp = _send(s, kXR_stat, b"\x00" * 16, PUBLIC_FILE.encode() + b"\x00")
        results.append((st == kXR_ok,
                        f"read_only_public: stat still answers ({st})"))
        st, resp = _send(s, kXR_open, struct.pack(">HH12x", 0, kXR_open_read),
                         PUBLIC_FILE.encode())
        results.append((st == kXR_ok,
                        f"read_only_public: read-open still succeeds ({st})"))
        if st == kXR_ok:
            handle = resp[:4]
            streamed = b""
            for offset in (0, 8, 16):
                st, data = _send(s, kXR_read,
                                 handle + struct.pack(">qi", offset, 8))
                if st != kXR_ok:
                    break
                streamed += data
            results.append((st == kXR_ok and len(streamed) > 8,
                            f"read_only_public: a multi-chunk streamed read "
                            f"returns bytes ({st}, {len(streamed)} B)"))
            _send(s, kXR_close, handle + b"\x00" * 12)
        # xrdcp verifies transfers with Qcksum; restricting it would break the
        # very clients this posture exists to serve.
        st, resp = _send(s, kXR_query,
                         struct.pack(">HH4s8x", 3, 0, b"\x00" * 4),
                         PUBLIC_FILE.encode() + b"\x00")
        results.append((st == kXR_ok,
                        f"read_only_public: per-path checksum still answers "
                        f"({st} {_errmsg(resp)[:40]!r})"))
    except (OSError, ConnectionError) as exc:
        results.append((False, f"read_only_public: read-surface probe failed: {exc}"))
    finally:
        s.close()


def check_public_mode_is_still_read_only(
        pub_port: int, results: list[tuple[bool, str]]) -> None:
    """brix_read_only_public IMPLIES brix_read_only — assert it on the wire.

    The implication is applied in brix_shared_apply_read_only(), i.e. in the
    config finaliser rather than in any handler, so the only way to know it
    reached the write gates is to fire the mutation battery at a server that
    was configured with the public directive ALONE.
    """
    escaped = []
    for probe in probes():
        status, resp = _try(pub_port, probe.opcode, probe.body, probe.payload,
                            probe.trailer)
        err = _errnum(resp) if status == kXR_error else None
        if err != kXR_fsReadOnly:
            escaped.append(f"{probe.name}({status}/{err})")
    results.append((not escaped,
                    f"read_only_public: every mutation refused as read-only "
                    f"WITHOUT an explicit brix_read_only (escaped: {escaped})"))


def check_override_is_logged(nginx_bin: str, prefix: Path, conf: Path,
                             results: list[tuple[bool, str]],
                             run) -> None:
    """brix_read_only silently overriding brix_allow_write would be a nasty
    surprise in the other direction too: the server must SAY so.

    The NOTICE is emitted during the config merge, so it lands in the error log
    the config itself names (not on the -t stderr); both are inspected.
    """
    result = run([nginx_bin, "-p", str(prefix), "-c", str(conf), "-t"])
    output = (result.stderr or "") + (result.stdout or "")
    for log in sorted((prefix / "logs").glob("*.log")):
        try:
            output += log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    hit = [line for line in output.splitlines()
           if "overrides allow_write" in line]
    results.append((bool(hit),
                    f"read_only+allow_write: startup announces that read_only "
                    f"overrides allow_write ({hit[:1]})"))


# --------------------------------------------------------------------------- #
# entry point used by the main rig                                             #
# --------------------------------------------------------------------------- #

def run_deep_checks(*, ro_port: int, ro_prefix: Path, sub_port: int,
                    pub_port: int, pub_prefix: Path, pub_export: Path,
                    nginx_bin: str, base: Path,
                    origin_root: Path, export_root: Path,
                    results: list[tuple[bool, str]]) -> None:
    """Every expansive family, each bracketed by a content-hash integrity check
    of both the origin tree and the gateway's own export."""
    families = (
        ("opcode space", lambda: check_opcode_space(ro_port, "read_only", results)),
        ("open options",
         lambda: check_open_option_space(ro_port, "read_only", results)),
        ("unauthenticated",
         lambda: check_unauthenticated_mutations(ro_port, "read_only", results)),
        # brix_data_substreams merges to ON, so the DOCUMENTED gateway is the
        # one that accepts a secondary channel; the extra posture is the
        # explicit off.
        ("bound stream (default)",
         lambda: check_bound_stream(ro_port, "read_only", substreams=True,
                                    results=results)),
        ("bound stream (substreams off)",
         lambda: check_bound_stream(sub_port, "read_only+substreams off",
                                    substreams=False, results=results)),
        ("signed mutation",
         lambda: check_signed_mutation(ro_port, "read_only", results)),
        ("query subcodes",
         lambda: check_query_subcodes(ro_port, "read_only", results)),
        ("session opcodes",
         lambda: check_session_ops_cannot_lift_the_gate(ro_port, "read_only",
                                                        results)),
        ("path shapes", lambda: check_path_shapes(ro_port, "read_only", results)),
        ("mutation storm",
         lambda: check_mutation_storm(ro_port, "read_only", results)),
        ("reload",
         lambda: check_reload_persistence(ro_prefix, ro_port, "read_only",
                                          results)),
    )
    for name, family in families:
        origin_before = tree_digest(origin_root)
        export_before = tree_digest(export_root)
        family()
        check_integrity(f"read_only: origin after {name}", origin_root,
                        origin_before, results)
        check_integrity(f"read_only: gateway export after {name}", export_root,
                        export_before, results, allow_server_owned=True)

    # The public posture gets the mutation battery too, bracketed against ITS
    # own export: brix_read_only_public reaches the write gates only through the
    # implication applied in the config finaliser, so it has to be proven on the
    # wire and not assumed from the plain read-only instance's result rows.
    for name, family in (
            ("public introspection",
             lambda: check_public_mode_restricts_introspection(
                 pub_port, ro_port, results)),
            ("public read surface",
             lambda: check_public_mode_still_serves_data(pub_port, results)),
            ("public qconfig filtering",
             lambda: check_public_mode_qconfig_is_filtered_per_key(
                 pub_port, ro_port, results)),
            ("public readv tuning",
             lambda: check_public_mode_readv_tuning_survives(pub_port, results)),
            ("public mutations",
             lambda: check_public_mode_is_still_read_only(pub_port, results))):
        origin_before = tree_digest(origin_root)
        export_before = tree_digest(pub_export)
        family()
        check_integrity(f"read_only_public: origin after {name}", origin_root,
                        origin_before, results)
        check_integrity(f"read_only_public: gateway export after {name}",
                        pub_export, export_before, results,
                        allow_server_owned=True)

    check_manager_mode_is_refused_at_config_time(base, nginx_bin, results)
    check_read_surface_intact(ro_port, "read_only", results)
    check_read_surface_intact(pub_port, "read_only_public", results)
