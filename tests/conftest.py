"""Shared test fixtures."""
import pytest
import pandas as pd
import os

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "sample_data")


@pytest.fixture
def sample_defender_df():
    """Minimal DataFrame mimicking parsed Defender output."""
    return pd.DataFrame({
        "cveId": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003",
                   "CVE-2024-0004", "CVE-2024-0005"],
        "cvssScore": [9.8, 7.5, 5.0, 8.1, 6.5],
        "deviceName": ["server01", "server02", "workstation01", "server01", "server03"],
        "softwareVendor": ["microsoft", "cisco", "google", "microsoft", "manageengine"],
        "softwareName": ["windows_10", "anyconnect", "chrome", ".net_framework", "manageengine_agent"],
        "softwareVersion": ["10.0.19041", "4.10.0", "120.0.0", "4.8.0", "14.0.0"],
        "vulnerabilitySeverityLevel": ["Critical", "High", "Medium", "High", "Medium"],
        "exploitabilityLevel": ["ExploitIsPublic", "NoExploit", "NoExploit",
                                 "ExploitIsVerified", "NoExploit"],
        "recommendationReference": ["va-_-microsoft-_-windows_10", "", "", "va-_-microsoft-_-.net_framework", ""],
        "recommendedSecurityUpdate": ["KB5034441", None, None, "KB5034442", None],
        "firstSeenTimestamp": pd.to_datetime([
            "2024-01-15", "2024-02-01", "2024-03-10", "2024-01-20", "2024-04-01"
        ]),
        "lastSeenTimestamp": pd.to_datetime([
            "2024-06-01", "2024-06-01", "2024-06-01", "2024-06-01", "2024-06-01"
        ]),
    })
