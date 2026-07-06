# WLCG Token Differential — Findings (generated golden)

Layer-3 differential tier output. Our verdict is asserted against the
spec (a mismatch fails the tier). Stock XRootD is a comparison target
only; `xrootd != spec` rows are recorded as findings, not failures.
Regenerate with `TEST_TOKEN_DIFF=1 tests/run_token_differential.sh`.

**Stock-XRootD column not populated.** A SciTokens-configured
stock `xrootd` was not available/configured on this run, so only
the ours-vs-spec assertion executed. The `libXrdSecztn` and
`libXrdAccSciTokens` plugins may be present but a server-side
issuer config (SciTokens `[Issuer]` block mapping our test issuer
to our JWKS) is site-specific; supply it via the harness to
populate the `xrootd` column.

| Case | Scenario | Ours | XRootD | Spec |
|---|---|---|---|---|
| DIFF-01 | generate | accept | n/a | accept |
| DIFF-02 | alg_none | reject | n/a | reject |
| DIFF-03 | temporal | reject | n/a | reject |
| DIFF-04 | for_issuer | reject | n/a | reject |
| DIFF-05 | scope | reject | n/a | reject |
| DIFF-06 | aud_value | accept | n/a | accept |
| DIFF-07 | alg_hs256_confusion | reject | n/a | reject |

_No stock-XRootD divergences recorded on this run._
