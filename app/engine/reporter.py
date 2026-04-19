"""
Generate downloadable Excel and CSV reports.
"""
import io
import pandas as pd
from datetime import datetime, timezone


def generate_excel_report(
    full_df: pd.DataFrame,
    dedup_df: pd.DataFrame,
    executive_summary: str,
    team_summaries: dict,
) -> bytes:
    """Create multi-sheet Excel workbook."""
    output = io.BytesIO()

    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        workbook = writer.book

        # Formats
        header_fmt = workbook.add_format({
            "bold": True, "bg_color": "#1F4E79", "font_color": "white",
            "border": 1, "text_wrap": True,
        })
        critical_fmt = workbook.add_format({"bg_color": "#FF4444", "font_color": "white"})
        high_fmt = workbook.add_format({"bg_color": "#FF8C00"})
        medium_fmt = workbook.add_format({"bg_color": "#FFD700"})
        wrap_fmt = workbook.add_format({"text_wrap": True, "valign": "top"})

        # Sheet 1: Executive Summary
        ws_exec = workbook.add_worksheet("Executive Summary")
        ws_exec.set_column("A:A", 120)
        ws_exec.write(0, 0, "Vulnerability Remediation Report", workbook.add_format({
            "bold": True, "font_size": 16,
        }))
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        ws_exec.write(1, 0, f"Generated: {now_str}")
        ws_exec.write(3, 0, executive_summary, wrap_fmt)

        row = 6
        for team, summary in team_summaries.items():
            ws_exec.write(row, 0, f"--- {team} ---", workbook.add_format({
                "bold": True, "font_size": 12,
            }))
            row += 1
            ws_exec.write(row, 0, summary, wrap_fmt)
            row += 3

        # Sheet 2: All Vulnerabilities
        export_cols = [
            "cveId", "cvssScore", "riskScore", "riskRating",
            "vulnerabilitySeverityLevel", "exploitabilityLevel",
            "assignedTeam", "softwareVendor", "softwareName",
            "softwareVersion", "deviceName", "osPlatform",
            "recommendedSecurityUpdate", "recommendedSecurityUpdateId",
            "securityUpdateAvailable", "firstSeenTimestamp",
            "lastSeenTimestamp", "slaDeadline", "slaBreached",
        ]
        export_cols = [c for c in export_cols if c in full_df.columns]
        for extra in ("cisaKev", "epssScore"):
            if extra in full_df.columns:
                export_cols.append(extra)

        all_vuln = full_df[export_cols].copy()
        all_vuln.to_excel(writer, sheet_name="All Vulnerabilities", index=False, startrow=1)

        ws_all = writer.sheets["All Vulnerabilities"]
        for col_num, col_name in enumerate(export_cols):
            ws_all.write(0, col_num, col_name, header_fmt)
        ws_all.autofilter(0, 0, len(all_vuln), len(export_cols) - 1)
        ws_all.freeze_panes(1, 0)

        # Severity color coding
        if "vulnerabilitySeverityLevel" in export_cols:
            sev_idx = export_cols.index("vulnerabilitySeverityLevel")
            sev_fmts = {"Critical": critical_fmt, "High": high_fmt, "Medium": medium_fmt}
            for row_idx in range(len(all_vuln)):
                sev = str(all_vuln.iloc[row_idx]["vulnerabilitySeverityLevel"])
                fmt = sev_fmts.get(sev)
                if fmt:
                    ws_all.write(row_idx + 1, sev_idx, sev, fmt)

        # Sheet 3: Patch Actions
        if not dedup_df.empty:
            dedup_df.to_excel(writer, sheet_name="Patch Actions", index=False, startrow=1)
            ws_patch = writer.sheets["Patch Actions"]
            for col_num, col_name in enumerate(dedup_df.columns):
                ws_patch.write(0, col_num, col_name, header_fmt)
            ws_patch.autofilter(0, 0, len(dedup_df), len(dedup_df.columns) - 1)
            ws_patch.freeze_panes(1, 0)

        # Per-Team Sheets
        teams = sorted(full_df["assignedTeam"].unique())
        for team in teams:
            team_df = full_df[full_df["assignedTeam"] == team][export_cols]
            sheet_name = team[:31]  # Excel 31 char limit
            team_df.to_excel(writer, sheet_name=sheet_name, index=False, startrow=1)
            ws_team = writer.sheets[sheet_name]
            for col_num, col_name in enumerate(export_cols):
                ws_team.write(0, col_num, col_name, header_fmt)
            ws_team.autofilter(0, 0, len(team_df), len(export_cols) - 1)
            ws_team.freeze_panes(1, 0)

    return output.getvalue()


def generate_team_csv(df: pd.DataFrame, team: str) -> bytes:
    """Generate CSV for a single team."""
    team_df = df[df["assignedTeam"] == team]
    return team_df.to_csv(index=False).encode("utf-8")
