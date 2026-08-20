# `tests/lib/` — the stub servers, and where their bodies now live

Every file here is a **§10.2 self-replacement shim**. The bodies moved to
`tests/brix_suite/servers/` in TS-5; these eight files stay because the
spelling `from lib.tokenconf import …` appears in twenty-five suites, and
`tests/lib/<stub>.py` appears as a spawn path in two suites and one
`cmdscripts` driver. A shim imports the canonical module, runs its `main()`
under `__main__`, and then replaces itself in `sys.modules` — so `lib.X` and
`brix_suite.servers.X` are one object, not two.

That last part is the whole reason for the pattern rather than a re-export.
`tokenconf.ensure_conformance_data()` memoises the provisioned tree in module
state; two module objects would mean two memos and a second provision nobody
asked for.

| Module | What it is | How it is started |
|---|---|---|
| `tokenconf.py` | WLCG conformance data + token minting. Not a server. | imported |
| `guard_stub_server.py` | Hit-counting HTTP upstream for the phase-65 guard suites; control API at `/__introspect`, `/__reset`, `/__status/<n>`. | spec `guard-stub` |
| `static_origin_server.py` | Fixed-body origin behind the cache. | spec `static-origin` |
| `mirror_shadow_server.py` | Shadow-write mirror target; records what it was sent. | spec `mirror-shadow` |
| `introspect_idp_server.py` | RFC 7662 token-introspection endpoint. | spec `introspect-idp` |
| `ocsp_responder.py` | Signing OCSP responder; refuses to start without `--signer-cert`. | spawned by path from `test_audit16a_ocsp_flags.py`, `test_audit16u_ocsp_nonce.py` |
| `fwd_mint_proxy.py` | Credential-forwarding token minter. | spawned by path from `cmdscripts/_fwd_matrix_live_part2_mixina.py` |
| `fwd_oidc_server.py` | OIDC discovery + JWKS for the forwarding matrix. | spawned by path from the same driver |

The four spec-started stubs are launched as `python -m brix_suite.servers.X`
and carry a `PYTHONPATH` naming `tests/` — `-m` puts the *current* directory
on `sys.path`, not the script's, and these modules import
`brix_suite.settings`. See `_module_env()` in
`brix_suite/catalogue/_shared.py`.

**Writing a new stub?** Do not copy one of these. They are grown code, pinned
byte-for-byte by suites that read their exact wire responses, which is why the
TS-5 move changed nothing but their `settings` import. The base for anything
new is `brixtest.stubs.StubServer` (`brixtest/src/brixtest/stubs/__init__.py`),
which handles the lane contract, readiness, access logging, and refuses to bind
a port outside its lane or a non-loopback address.

Frozen pre-move bodies: `tests/brix_suite/_legacy/*_flat.py`. Parity and the
start paths above are pinned by `tests/test_ci_ts5_servers_move.py`.
Prior history: [phase-38](../../docs/refactor/phase-38-file-size-unix-modularity.md)
split a bash monolith into `.sh` libs here; those were dissolved when the fleet
became pure Python, and this file described them until TS-5.
