"""Tests for the classifier module."""
from app.engine.classifier import classify_teams


class TestClassifyTeams:
    def test_classifies_os_team(self, sample_defender_df):
        result = classify_teams(sample_defender_df)
        os_row = result[result["cveId"] == "CVE-2024-0001"].iloc[0]
        assert os_row["assignedTeam"] == "OS Team"

    def test_classifies_cisco_team(self, sample_defender_df):
        result = classify_teams(sample_defender_df)
        cisco_row = result[result["cveId"] == "CVE-2024-0002"].iloc[0]
        assert cisco_row["assignedTeam"] == "Network / Cisco Team"

    def test_classifies_third_party(self, sample_defender_df):
        result = classify_teams(sample_defender_df)
        chrome_row = result[result["cveId"] == "CVE-2024-0003"].iloc[0]
        assert chrome_row["assignedTeam"] == "Third-Party Apps Team"

    def test_classifies_dotnet(self, sample_defender_df):
        result = classify_teams(sample_defender_df)
        dotnet_row = result[result["cveId"] == "CVE-2024-0004"].iloc[0]
        assert dotnet_row["assignedTeam"] == ".NET / IIS Team"

    def test_classifies_manageengine(self, sample_defender_df):
        result = classify_teams(sample_defender_df)
        me_row = result[result["cveId"] == "CVE-2024-0005"].iloc[0]
        assert me_row["assignedTeam"] == "Endpoint / ManageEngine Team"

    def test_all_rows_classified(self, sample_defender_df):
        result = classify_teams(sample_defender_df)
        assert "assignedTeam" in result.columns
        assert (result["assignedTeam"] != "Unassigned / Triage Required").all()
