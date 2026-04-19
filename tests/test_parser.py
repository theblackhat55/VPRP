"""Tests for the parser module."""
import pytest
import pandas as pd
import io
from unittest.mock import MagicMock
from app.engine.parser import parse_uploaded_file, merge_multi_upload, _normalize


def _make_upload(content: str, filename: str = "test.csv"):
    """Create a mock Streamlit UploadedFile."""
    mock = MagicMock()
    mock.name = filename
    mock.read.return_value = content.encode("utf-8")
    mock.seek = MagicMock()
    return mock


class TestNormalize:
    def test_renames_columns(self):
        df = pd.DataFrame({
            "CVE ID": ["CVE-2024-0001"],
            "Device Name": ["server01"],
            "Software Vendor": ["microsoft"],
            "Software Name": ["windows_10"],
            "Software Version": ["10.0"],
            "Severity": ["High"],
        })
        result = _normalize(df, [])
        assert "cveId" in result.columns
        assert "deviceName" in result.columns
        assert "vulnerabilitySeverityLevel" in result.columns

    def test_drops_rows_without_cve(self):
        df = pd.DataFrame({
            "cveId": ["CVE-2024-0001", None, "", "nan"],
            "deviceName": ["s1", "s2", "s3", "s4"],
            "softwareVendor": ["ms", "ms", "ms", "ms"],
            "softwareName": ["win", "win", "win", "win"],
            "softwareVersion": ["1", "1", "1", "1"],
            "vulnerabilitySeverityLevel": ["High", "High", "High", "High"],
        })
        result = _normalize(df, [])
        assert len(result) == 1
        assert result.iloc[0]["cveId"] == "CVE-2024-0001"

    def test_lowercases_text_fields(self):
        df = pd.DataFrame({
            "cveId": ["CVE-2024-0001"],
            "deviceName": ["SERVER01.CORP.LOCAL"],
            "softwareVendor": ["Microsoft"],
            "softwareName": ["Windows_10"],
            "softwareVersion": ["10.0"],
            "vulnerabilitySeverityLevel": ["High"],
        })
        result = _normalize(df, [])
        assert result.iloc[0]["deviceName"] == "server01.corp.local"
        assert result.iloc[0]["softwareVendor"] == "microsoft"


class TestParseUploadedFile:
    def test_parses_csv(self):
        csv = (
            "CVE ID,Device Name,Software Vendor,Software Name,Software Version,Severity,Exploitability Level\n"
            "CVE-2024-0001,server01,microsoft,windows_10,10.0,High,NoExploit\n"
            "CVE-2024-0002,server02,cisco,anyconnect,4.10,Medium,NoExploit\n"
        )
        result = parse_uploaded_file(_make_upload(csv))
        assert result.row_count == 2
        assert result.source_type == "Defender TVM (CSV)"
        assert "cveId" in result.df.columns

    def test_rejects_missing_columns(self):
        csv = "col1,col2\nval1,val2\n"
        with pytest.raises(ValueError, match="Missing required columns"):
            parse_uploaded_file(_make_upload(csv))


class TestMergeMultiUpload:
    def test_deduplicates_across_files(self):
        csv1 = (
            "CVE ID,Device Name,Software Vendor,Software Name,Software Version,Severity\n"
            "CVE-2024-0001,server01,microsoft,windows_10,10.0,High\n"
        )
        csv2 = (
            "CVE ID,Device Name,Software Vendor,Software Name,Software Version,Severity\n"
            "CVE-2024-0001,server01,microsoft,windows_10,10.0,High\n"
            "CVE-2024-0002,server02,cisco,anyconnect,4.10,Medium\n"
        )
        r1 = parse_uploaded_file(_make_upload(csv1, "file1.csv"))
        r2 = parse_uploaded_file(_make_upload(csv2, "file2.csv"))
        combined, stats = merge_multi_upload([r1, r2])

        assert stats["duplicates_removed"] == 1
        assert stats["total_rows_after_dedup"] == 2
        assert len(combined) == 2
