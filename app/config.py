"""
VPRP Platform Configuration
Team mapping rules, SLA definitions, and risk scoring weights.
Edit TEAM_RULES to match your organization's ownership model.
"""

# ── Priority SLA (calendar days) ─────────────────────────
SEVERITY_SLA = {
    "Critical": 15,
    "High": 30,
    "Medium": 60,
    "Low": 90,
}

# ── Risk Score Weights ────────────────────────────────────
WEIGHT_CVSS = 0.30
WEIGHT_EXPLOITABILITY = 0.25
WEIGHT_AGE = 0.15
WEIGHT_ASSET_EXPOSURE = 0.15
WEIGHT_THREAT_INTEL = 0.10
WEIGHT_EXPOSURE_COUNT = 0.05

EXPLOITABILITY_SCORES = {
    "ExploitIsInKit": 1.0,
    "ExploitIsVerified": 0.8,
    "ExploitIsPublic": 0.6,
    "NoExploit": 0.1,
}

# ── Team Classification Rules ────────────────────────────
# Each rule: (match_field, match_type, match_value, team_name)
#   match_field:  "softwareVendor", "softwareName", "recommendationReference"
#   match_type:   "contains", "equals", "startswith"
#   match_value:  string to match (case-insensitive)
#   team_name:    team that owns remediation
#
# Rules evaluated top-down; first match wins.

TEAM_RULES = [
    # ── OS / Platform Team ────────────────────────────────
    ("softwareName", "contains", "windows_10", "OS Team"),
    ("softwareName", "contains", "windows_11", "OS Team"),
    ("softwareName", "contains", "windows_server", "OS Team"),
    ("softwareName", "contains", "linux_kernel", "OS Team"),
    ("softwareName", "contains", "ubuntu", "OS Team"),
    ("softwareName", "contains", "red_hat", "OS Team"),
    ("softwareName", "contains", "centos", "OS Team"),
    ("recommendationReference", "startswith", "va-_-microsoft-_-windows", "OS Team"),

    # ── .NET / IIS Team ───────────────────────────────────
    ("softwareName", "contains", ".net_framework", ".NET / IIS Team"),
    ("softwareName", "contains", ".net_core", ".NET / IIS Team"),
    ("softwareName", "contains", "asp.net", ".NET / IIS Team"),
    ("softwareName", "contains", "iis", ".NET / IIS Team"),
    ("softwareName", "contains", "internet_information_services", ".NET / IIS Team"),
    ("softwareName", "contains", "dotnet", ".NET / IIS Team"),

    # ── Cisco / Network Team ──────────────────────────────
    ("softwareVendor", "contains", "cisco", "Network / Cisco Team"),
    ("softwareName", "contains", "appdynamics", "Network / Cisco Team"),
    ("softwareName", "contains", "anyconnect", "Network / Cisco Team"),
    ("softwareName", "contains", "webex", "Network / Cisco Team"),
    ("softwareName", "contains", "jabber", "Network / Cisco Team"),

    # ── ManageEngine / Endpoint Team ──────────────────────
    ("softwareVendor", "contains", "manageengine", "Endpoint / ManageEngine Team"),
    ("softwareName", "contains", "manageengine", "Endpoint / ManageEngine Team"),
    ("softwareVendor", "contains", "zoho", "Endpoint / ManageEngine Team"),

    # ── Microsoft Apps Team ───────────────────────────────
    ("softwareName", "contains", "edge", "Microsoft Apps Team"),
    ("softwareName", "contains", "office", "Microsoft Apps Team"),
    ("softwareName", "contains", "outlook", "Microsoft Apps Team"),
    ("softwareName", "contains", "excel", "Microsoft Apps Team"),
    ("softwareName", "contains", "word", "Microsoft Apps Team"),
    ("softwareName", "contains", "onedrive", "Microsoft Apps Team"),
    ("softwareName", "contains", "teams", "Microsoft Apps Team"),
    ("softwareName", "contains", "project", "Microsoft Apps Team"),
    ("softwareName", "contains", "visio", "Microsoft Apps Team"),
    ("softwareName", "contains", "sharepoint", "Microsoft Apps Team"),

    # ── SQL / Database Team ───────────────────────────────
    ("softwareName", "contains", "sql_server", "Database Team"),
    ("softwareName", "contains", "mysql", "Database Team"),
    ("softwareName", "contains", "postgresql", "Database Team"),
    ("softwareName", "contains", "mariadb", "Database Team"),
    ("softwareVendor", "contains", "oracle", "Database Team"),

    # ── Third-Party Apps ──────────────────────────────────
    ("softwareVendor", "contains", "google", "Third-Party Apps Team"),
    ("softwareVendor", "contains", "mozilla", "Third-Party Apps Team"),
    ("softwareVendor", "contains", "adobe", "Third-Party Apps Team"),
    ("softwareVendor", "contains", "java", "Third-Party Apps Team"),
    ("softwareName", "contains", "chrome", "Third-Party Apps Team"),
    ("softwareName", "contains", "firefox", "Third-Party Apps Team"),
    ("softwareName", "contains", "7-zip", "Third-Party Apps Team"),
    ("softwareName", "contains", "vlc", "Third-Party Apps Team"),
    ("softwareName", "contains", "notepad++", "Third-Party Apps Team"),
    ("softwareName", "contains", "putty", "Third-Party Apps Team"),

    # ── Security Tools Team ───────────────────────────────
    ("softwareName", "contains", "defender", "Security Team"),
    ("softwareName", "contains", "endpoint_protection", "Security Team"),
    ("softwareName", "contains", "antivirus", "Security Team"),
    ("softwareName", "contains", "crowdstrike", "Security Team"),
    ("softwareName", "contains", "sentinel", "Security Team"),
]

# Default team if no rule matches
DEFAULT_TEAM = "Unassigned / Triage Required"
