"""Conformance artifacts and the manifest the C and pytest layers both read.

Moved verbatim out of `tests/tokenforge_part3.py` by TS-5.  That module was
`exec`-ed into `tokenforge.py`'s globals, which is how it reached `TokenForge`
and `write_jwks` without importing either.  Both are real imports now.

`TokenForge` is imported from the package facade, which composes *this* module
last precisely so the cycle closes: by the time `__init__` reaches its final
import the class is already bound.
"""
import json
import os

from brix_suite.security.tokens import TokenForge
from brix_suite.security.tokens.issuer_cfg import write_scitokens_cfg
from brix_suite.security.tokens.jose import write_jwks


def fleet_artifacts(token_dir):
    """Ensure multi-key JWKS and scitokens.cfg for the managed test fleet.

    WHAT: Materialises the secondary RSA and EC keys, then writes:
          - jwks_multi.json  — three-key JWKS (main RSA + key-2 RSA + EC).
          - scitokens.cfg    — two-issuer registry (atlas + cms), each using
                              the MAIN jwks.json so forge-minted tokens verify.
    WHY:  Called once per start-all so the multikey and registry dedicated nginx
          instances have fresh artifacts that survive key rotation (main key
          re-created by TokenIssuer.init_keys on a clean tree).
    HOW:  TokenForge lazy-creates the secondary keys on first access; write_jwks
          and write_scitokens_cfg handle serialisation.
    """
    os.makedirs(token_dir, exist_ok=True)
    f = TokenForge(token_dir)
    if not os.path.exists(f.key_path):
        f.init_keys()
    # Materialise the secondary keys (side-effect: persists them to disk).
    second_pub = f.second_rsa_key.public_key()
    ec_pub = f.ec_key.public_key()
    main_pub = f.private_key.public_key()

    write_jwks(os.path.join(token_dir, "jwks_multi.json"), [
        (main_pub,   "test-key-1"),
        (second_pub, "test-key-2"),
        (ec_pub,     "ec-key-1"),
    ])

    main_jwks = os.path.join(token_dir, "jwks.json")
    write_scitokens_cfg(os.path.join(token_dir, "scitokens.cfg"), [
        {
            "name":       "atlas",
            "issuer":     "https://atlas.example.com",
            "base_paths": ["/atlas"],
            "jwks_path":  main_jwks,
            "strategy":   "capability",
        },
        {
            "name":       "cms",
            "issuer":     "https://cms.example.com",
            "base_paths": ["/cms"],
            "jwks_path":  main_jwks,
            "strategy":   "capability",
        },
    ])


def alg_jwks(token_dir):
    """Write {token_dir}/jwks_alg.json for the ALG-family's ACCEPT cases.

    WHAT: Materialises ec_p384_key and ec_p521_key (side-effect: persists them to
          disk), then writes a JWKS containing the three keys that the ALG-family
          ACCEPT tests verify against: main RSA (test-key-1), P-384 (ec-p384),
          P-521 (ec-p521).
    WHY:  The ALG-family nginx port serves this JWKS so rs384/rs512/ps*/es384/es512
          ACCEPT cases validate correctly, while weak_rsa_signed and es256_wrong_curve
          REJECT because their kids (weak-rsa, ec-p384 signed as ES256) are either
          absent or curve-mismatched.
    HOW:  Creates a TokenForge, initialises the main key if needed, accesses the
          three ACCEPT-case keys, delegates to write_jwks.
    """
    os.makedirs(token_dir, exist_ok=True)
    f = TokenForge(token_dir)
    if not os.path.exists(f.key_path):
        f.init_keys()
    write_jwks(os.path.join(token_dir, "jwks_alg.json"), [
        (f.private_key.public_key(),   "test-key-1"),
        (f.ec_p384_key.public_key(),   "ec-p384"),
        (f.ec_p521_key.public_key(),   "ec-p521"),
    ])


class Manifest:
    def __init__(self):
        self.rows = []

    def add(self, case_id, mint_recipe, protocol, expected,
            expected_reason, spec_ref, path=None, write=False):
        """Append a manifest row.

        Args:
            case_id:         Unique case identifier string (e.g. "SCP-W01").
            mint_recipe:     Dict describing how to mint the token (keys: "m",
                             optionally "args" / "kwargs").
            protocol:        One of "root", "webdav", "s3".
            expected:        "accept" or "reject".
            expected_reason: Human-readable rationale for the verdict.
            spec_ref:        Spec section or RFC reference.
            path:            XRootD/WebDAV path to probe; defaults to
                             "/test.txt" at assertion time when None.
            write:           If True, probe via a write operation rather than
                             read.  Stored in the row for assert_verdict().
        """
        assert expected in ("accept", "reject")
        row = {
            "case_id": case_id, "mint_recipe": mint_recipe,
            "protocol": protocol, "expected": expected,
            "expected_reason": expected_reason, "spec_ref": spec_ref,
        }
        if path is not None:
            row["path"] = path
        if write:
            row["write"] = write
        self.rows.append(row)

    def write(self, path):
        # Collection runs under pytest-xdist, so several workers can build the
        # first manifest concurrently. Publish only a complete JSON document;
        # readers must never observe the truncate/write window. The spill is a
        # dot-file so manifest consumers globbing the directory never see it,
        # and a failed dump removes it — only the rename publishes.
        head, tail = os.path.split(path)
        tmp = os.path.join(head, f".{tail}.{os.getpid()}.tmp")
        try:
            with open(tmp, "w") as fh:
                json.dump({"cases": self.rows}, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.replace(tmp, path)


def build_manifest(out_dir):
    """Mint the core representative manifest cases and write token_manifest.json.

    WHAT: Creates out_dir, initialises a TokenForge (generating keys on first
          run), and appends the SIG-family seed rows so the manifest file is
          always valid.  Later family tasks append their own rows by calling
          build_manifest() and extending the result, or by inserting m.add()
          calls between the seed rows and the write() call.
    WHY:  Provides a self-contained entrypoint so CI and the pytest harness can
          confirm the manifest round-trips without needing the full test suite.
    HOW:  Constructs TokenForge → Manifest → writes JSON; returns the manifest
          path so callers can open it directly.
    """
    os.makedirs(out_dir, exist_ok=True)
    f = TokenForge(out_dir)
    if not os.path.exists(f.key_path):
        f.init_keys()
    m = Manifest()

    # SIG family — root:// only.
    # WebDAV port 8443 is optional-auth (cannot enforce reject), and S3 port
    # 9001 has no token path, so these cases run on root:// exclusively.
    #
    # DEFERRED (need a JWKS-varied port — added with the multi-key-JWKS port task):
    #   SIG-10..14: kid selection (hit/miss), no_kid multi-key fallback,
    #   wrong-kid multi-key reject, ES256 accept.
    m.add("SIG-01", {"m": "alg_none"}, "root", "reject",
          "alg=none blocked before verify (RFC8725)", "spec §2, RFC8725")
    m.add("SIG-02", {"m": "alg_hs256_confusion"}, "root", "reject",
          "HS256-signed-with-RSA-pubkey confusion", "spec §2, RFC8725")
    m.add("SIG-03", {"m": "alg_lowercase"}, "root", "reject",
          "alg is case-sensitive; rs256 != RS256", "RFC7515 §4.1.1")
    m.add("SIG-04", {"m": "alg_unsupported", "args": ["RS384"]}, "root", "reject",
          "RS384 not in {RS256,ES256}", "spec §2")
    m.add("SIG-05", {"m": "alg_unsupported", "args": ["PS256"]}, "root", "reject",
          "PS256 not accepted", "spec §2")
    m.add("SIG-06", {"m": "generate"}, "root", "accept",
          "valid RS256 token", "spec §2")
    m.add("SIG-07",
          {"m": "for_issuer", "args": ["https://evil.example.com"]},
          "root", "reject",
          "wrong issuer, validly signed", "spec §3.1")
    m.add("SIG-08", {"m": "truncated_sig"}, "root", "reject",
          "truncated signature fails verify", "RFC7515 §5.2")
    m.add("SIG-09", {"m": "generate_bad_signature"}, "root", "reject",
          "tampered signature fails verify", "RFC7515 §5.2")

    # CLM family — temporal, structural, and size checks; root:// only.
    # Ground truth: src/auth/token/validate.c
    #   - token_len > 8192       → reject (line 220)
    #   - now > exp + BRIX_TOKEN_CLOCK_SKEW_SECS (30)  → reject (line 389)
    #   - now < nbf (no skew on nbf)                   → reject (line 398)
    #   - missing/string exp: json_get_int64 leaves exp=0 → treated as expired
    m.add("CLM-01", {"m": "temporal", "args": [-3600]}, "root", "reject",
          "expired 1h beyond 30s skew", "RFC7519 §4.1.4, tunables.h skew=30")
    m.add("CLM-02", {"m": "temporal", "args": [-20]}, "root", "accept",
          "expired 20s but within current 30s skew (locks pre-Task-6 behavior)",
          "RFC7519 §4.1.4, tunables.h skew=30")
    m.add("CLM-03", {"m": "missing_exp"}, "root", "reject",
          "missing exp → json_get_int64 leaves exp=0 → treated as expired",
          "RFC7519 §4.1.4")
    m.add("CLM-04", {"m": "exp_string"}, "root", "reject",
          "string-typed exp is not an integer → parse fail → exp=0 → expired",
          "RFC7519 §4.1.4")
    m.add("CLM-05", {"m": "oversized", "args": [9000]}, "root", "reject",
          "token_len>8192 rejected at size check before any parsing",
          "validate.c line 220")
    m.add("CLM-06", {"m": "malformed_json"}, "root", "reject",
          "malformed JSON payload fails jansson parse", "RFC7515 §7.2")
    m.add("CLM-07", {"m": "not_a_jwt"}, "root", "reject",
          "not a compact JWS (no dots) → structural reject", "RFC7515 §3.1")
    m.add("CLM-08", {"m": "temporal", "args": [3600, 120]}, "root", "reject",
          "nbf 120s in future; nbf has no skew tolerance (validate.c line 398)",
          "RFC7519 §4.1.5")
    m.add("CLM-09", {"m": "generate"}, "root", "accept",
          "valid token baseline — all temporal checks pass",
          "RFC7519 §4.1.4-5")

    # AUD family — audience claim: scalar vs array membership; root:// only.
    # Ground truth: json_string_or_array_contains (src/auth/token/json.c line 165)
    #   iterates ALL array elements → position-independent membership test.
    m.add("AUD-01", {"m": "aud_value", "args": ["nginx-xrootd"]},
          "root", "accept",
          "scalar aud match against expected nginx-xrootd",
          "RFC7519 §4.1.3")
    m.add("AUD-02", {"m": "aud_value", "args": ["wrong-aud"]},
          "root", "reject",
          "scalar aud mismatch — nginx-xrootd not present",
          "RFC7519 §4.1.3")
    m.add("AUD-03", {"m": "aud_value", "args": [["nginx-xrootd", "other"]]},
          "root", "accept",
          "array aud — expected nginx-xrootd is first element",
          "RFC7519 §4.1.3, json_string_or_array_contains")
    m.add("AUD-04", {"m": "aud_value", "args": [["other", "nginx-xrootd"]]},
          "root", "accept",
          "array aud — expected nginx-xrootd is last element (position-independent)",
          "RFC7519 §4.1.3, json_string_or_array_contains")
    m.add("AUD-05", {"m": "aud_value", "args": [["a", "b"]]},
          "root", "reject",
          "array aud without expected nginx-xrootd — membership fails",
          "RFC7519 §4.1.3")
    m.add("AUD-06", {"m": "aud_value", "args": [[]]},
          "root", "reject",
          "empty array aud — membership check finds nothing",
          "RFC7519 §4.1.3")

    # VER family — wlcg.ver claim: advisory, not enforced; root:// only.
    # Ground truth: wlcg.ver is NOT read anywhere in src/auth/token/validate.c;
    #   the claim is emitted by pelican_register.c but never validated — advisory.
    m.add("VER-01", {"m": "generate"}, "root", "accept",
          "wlcg.ver=1.0 present — standard valid token baseline",
          "WLCG Token Profile §2.1")
    m.add("VER-02", {"m": "wlcg_ver", "args": [None]}, "root", "accept",
          "wlcg.ver absent is advisory, not fatal (not read by validate.c)",
          "WLCG Token Profile §2.1 advisory")
    m.add("VER-03", {"m": "wlcg_ver", "args": ["2.0"]}, "root", "accept",
          "unknown wlcg.ver advisory, not fatal — validate.c ignores the claim",
          "WLCG Token Profile §2.1 advisory")

    # ... further families appended by their respective test tasks ...

    # SCP family — scope-enforcement and path-traversal defense; root:// only.
    # Ground truth: src/auth/token/scopes.c (brix_token_check_scope),
    #   src/protocols/root/path/op_path.c (brix_op_path_forbidden_component),
    #   src/protocols/root/read/stat.c (brix_reject_dotdot_path called BEFORE scope).
    # Rules:
    #   - storage.stage maps to read permission.
    #   - scope path prefix /data does NOT cover /database (no boundary crossing).
    #   - scope path "" (empty after the colon) defaults to root "/".
    #   - paths with ".." components → kXR_ArgInvalid BEFORE scope check (§3.5).
    #   - a token that auth-passes but has no scope covering the path → kXR_NotAuthorized.
    m.add("SCP-W01",
          {"m": "scope", "args": ["storage.read:/atlas"]},
          "root", "accept",
          "in-scope read: storage.read:/atlas covers /atlas/ok.txt",
          "WLCG Token Profile §4, scopes.c",
          path="/atlas/ok.txt")
    m.add("SCP-W02",
          {"m": "scope", "args": ["storage.read:/atlas"]},
          "root", "reject",
          "out-of-scope read: storage.read:/atlas does not cover /cms/ok.txt",
          "WLCG Token Profile §4, scopes.c",
          path="/cms/ok.txt")
    m.add("SCP-W03",
          {"m": "scope", "args": ["storage.read:/data"]},
          "root", "reject",
          "/data prefix must not cover /database (boundary: /data != /database)",
          "WLCG Token Profile §4 path-prefix rules",
          path="/database/ok.txt")
    m.add("SCP-W04",
          {"m": "scope", "args": ["storage.read:/atlas"]},
          "root", "reject",
          "TRAVERSAL: dot-dot escape must not reach /cms (§3.5 — "
          "brix_reject_dotdot_path fires before scope check)",
          "spec §3.5, op_path.c brix_reject_dotdot_path",
          path="/atlas/../cms/ok.txt")
    m.add("SCP-W05",
          {"m": "scope", "args": ["storage.read:/"]},
          "root", "accept",
          "root scope storage.read:/ covers all paths including /test.txt",
          "WLCG Token Profile §4",
          path="/test.txt")
    m.add("SCP-W06",
          {"m": "no_scope"},
          "root", "reject",
          "authenticated but scope claim absent — no grant covers any path",
          "WLCG Token Profile §4, scopes.c",
          path="/test.txt")
    m.add("SCP-W07",
          {"m": "scope", "args": ["storage.stage:/atlas"]},
          "root", "accept",
          "storage.stage grants read permission per WLCG token profile",
          "WLCG Token Profile §4, scopes.c storage.stage→read alias",
          path="/atlas/ok.txt")
    m.add("SCP-W08",
          {"m": "scope", "args": ["storage.write:/atlas"]},
          "root", "reject",
          "write-only scope storage.write:/atlas does not grant read",
          "WLCG Token Profile §4, scopes.c",
          path="/atlas/ok.txt")
    m.add("SCP-W09",
          {"m": "scope", "args": ["storage.read:"]},
          "root", "accept",
          "empty path after colon defaults to root scope / — covers /test.txt",
          "WLCG Token Profile §4, scopes.c empty-path-defaults-to-root",
          path="/test.txt")

    manifest_path = os.path.join(out_dir, "token_manifest.json")
    m.write(manifest_path)
    return manifest_path


def main(argv=None):
    """Entry point for ``python -m brix_suite.security.tokens`` and the shim.

    The flat stack carried this as a bare ``if __name__ == "__main__":`` block
    at the foot of ``tokenforge_part3.py``.  That only ever ran because
    ``tokenforge.py`` ``exec``-ed part 3 into its own globals, so part 3 saw the
    parent's ``__name__``.  Under real imports the guard belongs to *this*
    module and never fires for a caller running ``tokenforge.py``, which is how
    ``FleetArtifactsStep`` (``brix_suite/prep_steps.py``) came to exit 0 while
    writing nothing -- it invokes the helper with ``tolerate=True``, so a silent
    no-op looked like success.  A named function has one home and both
    spellings call it.
    """
    import argparse

    ap = argparse.ArgumentParser(
        description="WLCG token conformance fixture forge CLI")
    sub = ap.add_subparsers(dest="cmd")
    manifest_p = sub.add_parser("manifest",
                                help="Build token_manifest.json in out_dir")
    manifest_p.add_argument("out_dir",
                            help="Directory to write fixtures into")
    fleet_p = sub.add_parser(
        "fleet-artifacts",
        help="Write jwks_multi.json and scitokens.cfg into token_dir")
    fleet_p.add_argument("token_dir",
                         help="Directory to write fleet artifacts into")
    args = ap.parse_args(argv)

    if args.cmd == "manifest":
        print(build_manifest(args.out_dir))
    elif args.cmd == "fleet-artifacts":
        fleet_artifacts(args.token_dir)
    else:
        ap.print_help()
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
