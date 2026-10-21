"""Unit tests for the BWVS risk engine."""

import pytest

from app.risk_engine.bwvs import BWVSCalculator, BWVSWeights


def test_default_weights_sum_to_one():
    assert BWVSWeights().validate()


def test_maximum_inputs_score_100():
    r = BWVSCalculator().calculate(10, 10, 10, 10, 10, 100)
    assert r["final_bwvs"] == 100.0


def test_minimum_inputs_score_low():
    r = BWVSCalculator().calculate(0, 0, 0, 0, 0, 0)
    # AI relevance floors at 2/10 with weight 0.10
    assert r["final_bwvs"] == pytest.approx(2.0)


def test_business_context_changes_priority():
    calc = BWVSCalculator()
    technical = dict(cvss_score=8.0, exploit_activity_score=8, ai_relevance_percentage=60)
    payroll = calc.calculate(**technical, exposure_score=10, criticality_score=10, business_impact_score=10)
    sandbox = calc.calculate(**technical, exposure_score=1, criticality_score=3, business_impact_score=3)
    assert payroll["final_bwvs"] > sandbox["final_bwvs"] + 20


def test_inputs_are_clamped():
    r = BWVSCalculator().calculate(99, 99, 99, 99, 99, 500)
    assert r["final_bwvs"] == 100.0


@pytest.mark.parametrize("info,expected", [
    ({"cisa_kev": True}, 10),
    ({"sources": ["metasploit"]}, 10),
    ({"sources": ["github"]}, 8),
    ({"has_exploit": True}, 6),
    ({}, 2),
])
def test_exploit_score(info, expected):
    assert BWVSCalculator.get_exploit_score(info) == expected


@pytest.mark.parametrize("lakhs,expected", [(25, 10), (7, 8), (2, 6), (0.2, 3)])
def test_business_impact_score(lakhs, expected):
    assert BWVSCalculator.get_business_impact_score(lakhs) == expected


def test_exposure_and_criticality_lookup():
    assert BWVSCalculator.get_exposure_score("internet_facing") == 10
    assert BWVSCalculator.get_exposure_score("isolated") == 1
    assert BWVSCalculator.get_criticality_score("payment_payroll") == 10
    assert BWVSCalculator.get_criticality_score("unknown") == 3
