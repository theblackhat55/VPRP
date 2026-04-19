"""Tests for the deduplicator module."""
from app.engine.deduplicator import deduplicate_by_patch
from app.engine.classifier import classify_teams
from app.engine.prioritizer import compute_risk_scores


class TestDeduplicateByPatch:
    def test_groups_by_patch(self, sample_defender_df):
        df = classify_teams(sample_defender_df)
        df = compute_risk_scores(df)
        result = deduplicate_by_patch(df)
        # Should have entries for KB5034441 and KB5034442
        assert len(result) >= 1
        assert "cveCount" in result.columns
        assert "affectedDevices" in result.columns

    def test_returns_empty_when_no_patches(self, sample_defender_df):
        df = classify_teams(sample_defender_df)
        df = compute_risk_scores(df)
        df["recommendedSecurityUpdate"] = None
        result = deduplicate_by_patch(df)
        assert result.empty
