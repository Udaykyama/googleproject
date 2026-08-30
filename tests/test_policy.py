"""Tests for policy configuration and its safety guards."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_review_detector.errors import PolicyError  # noqa: E402
from fake_review_detector.models import Action, RiskLevel  # noqa: E402
from fake_review_detector.policy import SIGNAL_CODES, Policy  # noqa: E402


def test_default_policy_is_valid():
    policy = Policy()
    assert policy.version
    assert set(policy.weights) == set(SIGNAL_CODES)


def test_default_weights_match_the_original_heuristics():
    policy = Policy()
    assert policy.weight("GENERIC_PHRASE") == 25
    assert policy.weight("NEAR_DUPLICATE_TEXT") == 25
    assert policy.weight("UNVERIFIED_PURCHASE") == 20
    assert policy.weight("SHOUTY_TEXT") == 15


def test_risk_thresholds():
    policy = Policy()
    assert policy.risk_level(0) is RiskLevel.LOW
    assert policy.risk_level(29) is RiskLevel.LOW
    assert policy.risk_level(30) is RiskLevel.MEDIUM
    assert policy.risk_level(59) is RiskLevel.MEDIUM
    assert policy.risk_level(60) is RiskLevel.HIGH


def test_risk_level_compares_equal_to_its_string():
    # The original API exposed plain strings; that comparison must still hold.
    assert RiskLevel.HIGH == "high"
    assert Policy().risk_level(90) == "high"


def test_partial_weight_override_keeps_other_defaults():
    policy = Policy(weights={"GENERIC_PHRASE": 40})
    assert policy.weight("GENERIC_PHRASE") == 40
    assert policy.weight("NEW_ACCOUNT") == 20


def test_weights_are_immutable():
    with pytest.raises(TypeError):
        Policy().weights["GENERIC_PHRASE"] = 99


def test_unknown_signal_code_rejected():
    with pytest.raises(PolicyError) as exc:
        Policy(weights={"TYPO_CODE": 10})
    assert "TYPO_CODE" in str(exc.value)


def test_out_of_range_weight_rejected():
    with pytest.raises(PolicyError):
        Policy(weights={"GENERIC_PHRASE": -1})
    with pytest.raises(PolicyError):
        Policy(weights={"GENERIC_PHRASE": 101})


def test_thresholds_must_be_ordered():
    with pytest.raises(PolicyError):
        Policy(medium_threshold=80, high_threshold=40)


def test_actions_must_cover_every_risk_level():
    with pytest.raises(PolicyError):
        Policy(actions={"low": "allow"})


def test_unknown_action_rejected():
    with pytest.raises(PolicyError):
        Policy(actions={"low": "allow", "medium": "enqueue", "high": "vaporise"})


def test_auto_removal_is_off_by_default():
    policy = Policy()
    assert policy.allow_auto_removal is False
    assert policy.action_for(RiskLevel.HIGH, 100) is Action.ENQUEUE


def test_removal_action_requires_explicit_opt_in():
    # Configuring removal without enabling it is a mistake, not a default.
    with pytest.raises(PolicyError):
        Policy(actions={"low": "allow", "medium": "enqueue", "high": "remove"})


def test_removal_still_requires_clearing_its_own_threshold():
    policy = Policy(
        allow_auto_removal=True,
        actions={"low": "allow", "medium": "enqueue", "high": "remove"},
        auto_removal_threshold=90,
    )
    assert policy.action_for(RiskLevel.HIGH, 95) is Action.REMOVE
    # High risk but below the removal bar falls back to human review.
    assert policy.action_for(RiskLevel.HIGH, 70) is Action.ENQUEUE


def test_digest_is_stable_and_content_sensitive():
    assert Policy().digest() == Policy().digest()
    assert Policy().digest() != Policy(medium_threshold=31).digest()
    # Same settings under a different version string are still different.
    assert Policy().digest() != Policy(version="other").digest()


def test_round_trip_through_dict_preserves_digest():
    policy = Policy(medium_threshold=25, weights={"SHOUTY_TEXT": 5})
    assert Policy.from_dict(policy.to_dict()).digest() == policy.digest()


def test_from_file_reads_json(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"version": "test.1", "medium_threshold": 40}))
    policy = Policy.from_file(path)
    assert policy.version == "test.1"
    assert policy.medium_threshold == 40


def test_from_file_reports_bad_json(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text("{not json")
    with pytest.raises(PolicyError):
        Policy.from_file(path)


def test_from_file_reports_missing_file(tmp_path):
    with pytest.raises(PolicyError):
        Policy.from_file(tmp_path / "absent.json")


def test_unknown_policy_field_rejected():
    with pytest.raises(PolicyError):
        Policy.from_dict({"unexpected": 1})


def test_burst_threshold_must_be_meaningful():
    with pytest.raises(PolicyError):
        Policy(burst_review_count=1)


def test_similarity_threshold_bounds():
    with pytest.raises(PolicyError):
        Policy(duplicate_similarity_threshold=0)
    with pytest.raises(PolicyError):
        Policy(duplicate_similarity_threshold=1.5)


def test_zero_weight_disables_a_signal():
    assert Policy(weights={"SHOUTY_TEXT": 0}).weight("SHOUTY_TEXT") == 0
