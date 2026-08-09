from split_continuation import reexport as _reexport
_reexport(globals(), "_test_wlcg_token_conformance_edge_helpers")

@pytest.mark.tokenconf
def test_g03_nbf_30s_future_default_port_reject():
    """nbf=now+30 (30s in future) on default port → reject.

    WHY:  nbf is enforced strictly (no skew window).  nbf=now+30 means the
          token is not yet valid; now < nbf → reject.  Confirms the skew
          window is applied ONLY to exp, not to nbf.
    """
    assert root_ztn(_f().temporal(3600, 30), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_g04_nbf_31s_future_default_port_reject():
    """nbf=now+31 (31s in future) on default port → reject.

    WHY:  Confirms nbf enforcement holds even 1s beyond the exp skew window.
          Paired with G03 to show consistent strict nbf behaviour.
    """
    assert root_ztn(_f().temporal(3600, 31), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_g05_exp_ok_nbf_future_reject():
    """exp=now+3600 (valid), nbf=now+1 (1s future) → reject.

    WHY:  Both exp and nbf are checked independently.  A valid exp does not
          compensate for a future nbf; the token is still not-yet-valid.
          Confirms that nbf enforcement is not bypassed by a good exp value.
    """
    assert root_ztn(_f().temporal(3600, 1), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_g06_iat_1d_old_valid_exp_accept():
    """iat=now-86400 (1 day old iat) with normal exp and nbf → accept.

    WHY:  iat is informational only.  A very old iat with still-valid exp/nbf
          must be accepted.  Confirms no upper-bound on iat age is enforced.
    """
    assert root_ztn(_f().temporal(3600, 0, -86400), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_g07_exp_minus_29s_strict_port_reject():
    """exp=now-29 (29s expired) on strict port (skew=0) → reject.

    WHY:  Strict port: any past expiry is rejected.  exp=now-29 is fine on
          11097 (within 30s grace) but must be rejected on 11119 (skew=0).
          Provides a clear cross-port contrast: the SAME token rejects on 11119
          but would accept on 11097.
    """
    assert root_ztn(_f().temporal(-29), "/test.txt", port=STRICT) == "reject"


@pytest.mark.tokenconf
def test_g08_exp_exactly_now_strict_port_accept():
    """exp=now (exp_delta=0) on strict port (skew=0) → accept.

    WHY:  Both mint and validate use int(time.time()); within the same integer
          second, exp == now, so now > exp is false → token is still valid.
          With skew=0, "not yet expired" means now <= exp (not now < exp+30).
          This shows strict=0 means strict-expiry, not sub-second pessimism.
          Contrast: exp=now-1 on strict port → reject (A04) because now > exp-1+0.
    """
    assert root_ztn(_f().temporal(0), "/test.txt", port=STRICT) == "accept"


@pytest.mark.tokenconf
def test_g09_nbf_5s_future_strict_port_reject():
    """nbf=now+5 (5s future) on strict port → reject.

    WHY:  Confirms that the strict port also enforces nbf (not just exp).
          nbf=now+5 is in the future on any port; skew=0 does not change nbf
          handling (which has always been strict).  This is a belt-and-braces
          check that the strict port's tighter exp-skew did not accidentally
          relax nbf enforcement.
    """
    assert root_ztn(_f().temporal(3600, 5), "/test.txt", port=STRICT) == "reject"
