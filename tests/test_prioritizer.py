"""Tests for the prioritizer module."""
from app.engine.prioritizer import compute_risk_scores
from app.engine.classifier import classify_teams


class TestComputeRiskScores:
    def test_adds_risk_columns(self, sample_defender_df):
        df = classify_teams(sample_defender_df)
        result = compute_risk_scores(df)
        assert "riskScore" in result.columns
        assert "riskRating" in result.columns
        assert "slaDays" in result.columns
        assert "slaDeadline" in result.columns
        assert "slaBreached" in result.columns

    def test_scores_in_valid_range(self, sample_defender_df):
        df = classify_teams(sample_defender_df)
        result = compute_risk_scores(df)
        assert (result["riskScore"] >= 0).all()
        assert (result["riskScore"] <= 100).all()

    def test_critical_cvss_scores_higher(self, sample_defender_df):
        df = classify_teams(sample_defender_df)
        result = compute_risk_scores(df)
        critical = result[result["vulnerabilitySeverityLevel"] == "Critical"]["riskScore"].mean()
        medium = result[result["vulnerabilitySeverityLevel"] == "Medium"]["riskScore"].mean()
        assert critical > medium

    def test_sorted_by_risk_descending(self, sample_defender_df):
        df = classify_teams(sample_defender_df)
        result = compute_risk_scores(df)
        scores = result["riskScore"].tolist()
        assert scores == sorted(scores, reverse=True)
