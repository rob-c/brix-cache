"""A public anonymous ``root://`` gateway with ``brix_read_only on`` is
read-only across its WHOLE protocol surface.

The rig, the probe table and the opcode-coverage check live in
cmdscripts/root_readonly_gateway.py; the expansive families (whole-opcode-space
sweep, option-word sweep, bound secondary channels, pre-login mutations, signing
envelopes, path shapes, concurrency, reload) live in the sibling
cmdscripts/root_readonly_gateway_deep.py; the deployment they mirror is
documented in docs/03-configuration/read-only-root-gateway.md.

One rig serves every test (module-scoped fixture): six instances are started
once — the XRootD origin, the documented read-only gateway, a
read_only+allow_write gateway, a writable control, a substreams-off gateway and
a ``brix_read_only_public`` gateway — the whole battery runs against them, and
each test asserts its own slice of the result rows.  The one posture with no
instance is brix_manager_mode + brix_read_only: it is refused by ``nginx -t``,
so it is asserted at config time.
"""

import os

import pytest

from cmdscripts.root_readonly_gateway import run_checks
from settings import NGINX_BIN

pytestmark = pytest.mark.xdist_group("cmd-root_readonly_gateway")


@pytest.fixture(scope="module")
def probe_results(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    results = run_checks(tmp_path_factory.mktemp("rogw"), nginx_bin=NGINX_BIN)
    assert results, "run_checks produced no rows"
    return results


def _rows(results, *needles):
    """Rows whose message contains every needle (at least one must match)."""
    hits = [(ok, msg) for ok, msg in results
            if all(needle in msg for needle in needles)]
    assert hits, f"no result row matched {needles!r}"
    return hits


def _assert_all_green(rows):
    failed = [msg for ok, msg in rows if not ok]
    assert not failed, "\n".join(failed)


def test_read_only_gateway_still_serves_reads(probe_results):
    """Success path: the gateway is a fully functional READ gateway — open,
    read, stat, dirlist and the fattr read side all work through to the XRootD
    origin, and still do after the entire battery has been fired at it."""
    _assert_all_green(_rows(probe_results, "origin is "))
    # The published example configs must still survive `nginx -t`.
    _assert_all_green(_rows(probe_results, "documentation page publishes"))
    _assert_all_green(_rows(probe_results, "passes nginx -t"))
    for label in ("read_only:", "read_only+allow_write:"):
        _assert_all_green(_rows(probe_results, label, "read-open succeeds"))
        _assert_all_green(_rows(probe_results, label, "read returns the origin"))
        _assert_all_green(_rows(probe_results, label, "dirlist succeeds"))
        _assert_all_green(_rows(probe_results, label, "fattr list"))
        _assert_all_green(_rows(probe_results, label, "stat succeeds"))
    _assert_all_green(_rows(probe_results, "read-open still succeeds after"))
    _assert_all_green(_rows(probe_results, "read still returns bytes after"))


def test_read_only_gateway_refuses_every_mutating_opcode(probe_results):
    """Error path: every opcode in the write-gated route table of
    dispatch_write.c, plus the four read-table opcodes that can still mutate
    (open in write mode, fattr set/del, prepare kXR_wmode, clone), is refused —
    kXR_fsReadOnly for the gated set, kXR_NotAuthorized for clone (no writable
    handle can exist to clone onto)."""
    _assert_all_green(_rows(probe_results, "route table is parseable"))
    _assert_all_green(_rows(probe_results, "every write-gated opcode is probed"))
    _assert_all_green(_rows(probe_results, "numeric mapping here"))
    _assert_all_green(_rows(probe_results, "read_only:", "(got status="))
    _assert_all_green(_rows(probe_results, "read_only:", "mutating probes refused"))
    _assert_all_green(_rows(probe_results, "read_only:", "clone onto an open READ"))
    _assert_all_green(_rows(probe_results, "read_only:",
                            "prepare stage is refused"))


def test_read_only_overrides_allow_write_and_leaves_the_origin_intact(
        probe_results):
    """Security-negative: an operator (or a merge accident) that also sets
    ``brix_allow_write on`` must not open the surface — brix_shared_apply_read_only()
    forces allow_write off before token scope, so the refusal set is identical.
    The same frames against a WRITABLE control server are never refused as
    read-only and do land their mutations, so the refusals above are the gate
    and not a malformed probe; and the origin tree is unchanged afterwards."""
    _assert_all_green(
        _rows(probe_results, "read_only+allow_write:", "(got status="))
    _assert_all_green(
        _rows(probe_results, "read_only+allow_write:", "mutating probes refused"))
    _assert_all_green(
        _rows(probe_results, "read_only+allow_write:", "clone onto an open READ"))
    _assert_all_green(
        _rows(probe_results, "read_only+allow_write:",
              "prepare stage is refused"))
    _assert_all_green(_rows(probe_results, "control: no probe draws"))
    _assert_all_green(_rows(probe_results, "control: every well-formed"))
    _assert_all_green(_rows(probe_results, "origin tree is byte-for-byte"))
    _assert_all_green(_rows(probe_results, "origin public file content"))
    # The override must be announced, not silent.
    _assert_all_green(_rows(probe_results, "startup announces that read_only"))

    # The two read-only postures must refuse the SAME probes ("(got status=" is
    # the probe-table row shape; the sweep rows have their own).
    ro = len(_rows(probe_results, "read_only:", "(got status="))
    ov = len(_rows(probe_results, "read_only+allow_write:", "(got status="))
    assert ro == ov > 0, f"refusal sets differ: read_only={ro} override={ov}"


# --------------------------------------------------------------------------- #
# the expansive families                                                       #
# --------------------------------------------------------------------------- #

def test_whole_opcode_space_holds_no_accepted_mutation(probe_results):
    """Every request id defined in opcodes.h — standard AND vendor — is fired.
    Opcodes the C routes through the write table answer kXR_fsReadOnly, and an
    opcode routed by no dispatch table at all is refused rather than reaching a
    handler.  The classification comes from parsing the four dispatch_*.c
    tables, so a new opcode cannot enter the surface unswept."""
    _assert_all_green(_rows(probe_results, "opcodes.h defines"))
    _assert_all_green(_rows(probe_results, "exists in opcodes.h"))
    _assert_all_green(_rows(probe_results, "is write-routed -> kXR_fsReadOnly"))
    _assert_all_green(_rows(probe_results, "routed by no dispatch table"))
    _assert_all_green(_rows(probe_results, "every write-routed opcode refused"))
    _assert_all_green(_rows(probe_results, "no unrouted opcode was accepted"))
    _assert_all_green(_rows(probe_results, "unrouted opcodes exercised"))
    # kXR_query is one opcode carrying thirteen operations; all are exercised.
    _assert_all_green(_rows(probe_results, "every kXR_query infotype"))


def test_every_write_implying_open_option_word_is_refused(probe_results):
    """kXR_open is the widest single door in the protocol: one 16-bit option
    word decides read from write.  Every single bit, and every combination of
    the write-implying bits, is fired — with the expectation taken from
    BRIX_OPEN_WRITE_BITS in the C, so it cannot drift from the server."""
    _assert_all_green(_rows(probe_results, "BRIX_OPEN_WRITE_BITS parsed"))
    _assert_all_green(_rows(probe_results, "open options 0x"))
    _assert_all_green(_rows(probe_results, "every write-implying option word"))
    _assert_all_green(_rows(probe_results, "no read-only option word was refused"))


def test_no_mutation_is_accepted_without_a_session(probe_results):
    """Security-negative: mutations attempted before login — and before the
    handshake — are never accepted, so the read-only gate is not the only thing
    standing between an anonymous client and the namespace."""
    _assert_all_green(_rows(probe_results, "pre-login "))
    _assert_all_green(_rows(probe_results, "no mutation accepted before login"))
    _assert_all_green(_rows(probe_results, "before the handshake"))


def test_bound_secondary_channel_cannot_write(probe_results):
    """kXR_bind is the one route by which a bare kXR_write reaches the dispatcher
    without an open on the same connection (policy.c admits kXR_write, and only
    kXR_write, from a bound stream).  It must still hit the read-only gate; every
    other opcode from a bound stream is refused before the gate; and with
    brix_data_substreams off the bind itself is refused."""
    _assert_all_green(_rows(probe_results, "kXR_bind accepted with substreams on"))
    _assert_all_green(_rows(probe_results, "bound-stream kXR_write"))
    _assert_all_green(_rows(probe_results, "bound-stream kXR_mkdir"))
    _assert_all_green(_rows(probe_results, "bound-stream write-open"))
    _assert_all_green(_rows(probe_results, "kXR_bind refused when"))


def test_envelopes_and_session_opcodes_do_not_lift_the_gate(probe_results):
    """A kXR_sigver signing envelope does not smuggle a mutation past the gate,
    and kXR_set — the one server-configuration opcode reachable by a public
    client, login-gated but not write-gated — cannot move the posture either."""
    _assert_all_green(_rows(probe_results, "kXR_sigver envelope is still refused"))
    _assert_all_green(_rows(probe_results, "kXR_set "))
    _assert_all_green(_rows(probe_results, "after kXR_set is still refused"))
    _assert_all_green(_rows(probe_results, "after a re-login is still refused"))


def test_no_path_spelling_reaches_the_namespace(probe_results):
    """Traversal, doubled separators, dot segments, opaque suffixes, an embedded
    NUL, a relative path, the root itself and the empty path: no spelling of a
    mutating request is accepted."""
    _assert_all_green(_rows(probe_results, "path is not accepted"))
    _assert_all_green(_rows(probe_results, "no path shape was accepted"))


def test_the_posture_survives_concurrency_and_reload(probe_results):
    """The gate is a per-request check, not a startup latch: it holds under a
    concurrent storm, and it comes back after SIGHUP re-runs the config merge —
    an operator reloading for an unrelated reason must not open the gateway."""
    _assert_all_green(_rows(probe_results, "storm ran every probe"))
    _assert_all_green(_rows(probe_results, "every concurrent mutation refused"))
    _assert_all_green(_rows(probe_results, "accepts connections after SIGHUP"))
    _assert_all_green(_rows(probe_results, "still refused after a reload"))


def test_nothing_on_disk_changed_under_any_family(probe_results):
    """The claim is about bytes, not about error codes: every family above is
    bracketed by a sha256 digest of the origin tree AND of the gateway's own
    export, so an in-place rewrite that preserves the path set cannot pass."""
    digests = _rows(probe_results, "content digest unchanged")
    _assert_all_green(digests)
    # One origin bracket and one export bracket per family — a family that
    # stopped being bracketed would silently lose its integrity proof.
    assert len(digests) >= 20, f"only {len(digests)} integrity brackets ran"


def test_manager_mode_with_read_only_refuses_to_start(probe_results):
    """Security-negative: a manager redirects mkdir/rm/mv/chmod/truncate to a
    data node BEFORE the local write gate runs, so ``brix_manager_mode on`` plus
    ``brix_read_only on`` is an endpoint that looks read-only in the config and
    is not one on the wire.  The pair must therefore be impossible to deploy:
    nginx -t fails at EMERG naming both directives, so the master never starts —
    and the same holds for brix_read_only_public, which implies read_only.  A
    manager WITHOUT read_only must still be perfectly valid."""
    _assert_all_green(_rows(probe_results, "is refused by nginx -t"))
    _assert_all_green(_rows(probe_results, "refusal is EMERG"))
    _assert_all_green(_rows(probe_results, "WITHOUT read_only still parses"))


# --------------------------------------------------------------------------- #
# brix_read_only_public                                                        #
# --------------------------------------------------------------------------- #

def test_public_mode_still_lists_reads_and_streams(probe_results):
    """Success path: the restriction must not cost the gateway its job.  On an
    instance configured with ``brix_read_only_public on`` and nothing else,
    dirlist, stat, read-open, a multi-chunk streamed read and the per-path
    checksum xrdcp verifies transfers with all still work."""
    _assert_all_green(_rows(probe_results, "read_only_public: dirlist still"))
    _assert_all_green(_rows(probe_results, "read_only_public: stat still"))
    _assert_all_green(_rows(probe_results, "read_only_public: read-open still"))
    _assert_all_green(_rows(probe_results, "multi-chunk streamed read"))
    _assert_all_green(_rows(probe_results, "per-path checksum still answers"))
    _assert_all_green(
        _rows(probe_results, "read_only_public:", "read-open still succeeds "
                                                  "after the full sweep"))


def test_public_mode_refuses_server_introspection(probe_results):
    """Error path: the kXR_query infotypes that describe the SERVER rather than
    a path — kXR_QStats, kXR_Qspace, kXR_QFSinfo, kXR_Qvisa — answer
    kXR_NotAuthorized, so no capacity, statistics or visa-issuing surface is
    served to a public client.  The restricted set is read out of
    brix_query_is_server_introspection() in the C, so a new infotype added to
    that function lands in the sweep on its own."""
    _assert_all_green(_rows(probe_results, "server-introspection infotypes"))
    _assert_all_green(
        _rows(probe_results, "is refused kXR_NotAuthorized"))
    _assert_all_green(_rows(probe_results, "no server-introspection query answered"))


def test_public_mode_withholds_config_but_keeps_capability(probe_results):
    """kXR_Qconfig is filtered per KEY, not refused wholesale.

    Refusing the infotype outright hid nothing an anonymous client could not
    establish by trying, and cost it the vector-read geometry — so the C table
    carries a public_safe column: `version` and `role` (which describe the
    deployment) are withheld and echoed exactly like an unknown key, every
    protocol capability and limit still answers, and the column defaults to
    WITHHELD so a key added later fails closed.  Both halves are asserted, plus
    the belt-and-braces check that a withheld value appears nowhere in the
    public answer."""
    _assert_all_green(_rows(probe_results, "kXR_Qconfig is filtered per key"))
    _assert_all_green(_rows(probe_results, "kXR_Qconfig keys, withheld:"))
    _assert_all_green(_rows(probe_results, "is withheld — echoed like an unknown"))
    _assert_all_green(_rows(probe_results, "appears nowhere in the public answer"))
    _assert_all_green(_rows(probe_results, "IS served on the plain read-only"))
    _assert_all_green(_rows(probe_results, "no deployment-identity qconfig key"))
    _assert_all_green(_rows(probe_results, "answers identically to the plain"))
    _assert_all_green(_rows(probe_results, "no capability qconfig key changed"))


def test_public_mode_keeps_vector_read_tuning(probe_results):
    """The regression the per-key filter exists to prevent.

    XrdCl sizes a VectorRead from readv_ior_max (bytes per element) and
    readv_iov_max (elements per request), both parsed with atoi() from a bare
    integer line; a missing or non-numeric answer silently drops the client to
    conservative built-in defaults — many more, much smaller readv elements
    against the endpoint that exists to stream bulk data.  So the values must be
    bare positive integers, the checksum list xrdcp negotiates with must still
    be advertised, and a real kXR_readv sized from those limits must be served
    by the public gateway."""
    _assert_all_green(_rows(probe_results, "bare positive integer for atoi()"))
    _assert_all_green(_rows(probe_results, "advertises readv support"))
    _assert_all_green(_rows(probe_results, "advertises the checksum list"))
    _assert_all_green(
        _rows(probe_results, "sized from the advertised limits is served"))


def test_public_mode_restricts_nothing_else(probe_results):
    """Security-negative, in the other direction: a posture that refused
    everything would satisfy the test above while being useless, and a posture
    that quietly dropped the read-only guarantee would satisfy the one before
    it.  So every non-restricted infotype must answer EXACTLY as it does on the
    plain read-only gateway, every restricted one must not have been refused
    there already, and the whole mutation battery must still be refused as
    read-only on a server that was never given an explicit brix_read_only."""
    _assert_all_green(_rows(probe_results, "unchanged from the plain read-only"))
    _assert_all_green(_rows(probe_results, "no path-scoped query was collaterally"))
    _assert_all_green(_rows(probe_results, "only because of the directive"))
    _assert_all_green(
        _rows(probe_results, "every mutation refused as read-only WITHOUT"))
    # And it changed no bytes doing it.
    _assert_all_green(_rows(probe_results, "read_only_public:", "digest unchanged"))
