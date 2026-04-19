"""
VPRP Platform Configuration
Team mapping rules, SLA definitions, and risk scoring weights.
"""
import json
import os

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

# ── Team Definitions ─────────────────────────────────────
# Canonical team names used across the platform.
TEAM_DEFINITIONS = {
    "OS Team": "Operating system patches: Windows, Linux, macOS kernels and core OS components",
    "NET / IIS Team": ".NET runtime, ASP.NET, IIS web server, and related middleware",
    "Network / Cisco Team": "Network infrastructure: Cisco, Juniper, Palo Alto, Fortinet, F5 and related agents",
    "Endpoint / ManageEngine Team": "Endpoint management agents: ManageEngine, Zoho, SCCM, Intune, BigFix",
    "Microsoft Apps Team": "Microsoft desktop & productivity apps: Office, Edge, Teams, OneDrive, Visual Studio",
    "Database Team": "Database engines: SQL Server, MySQL, PostgreSQL, MariaDB, Oracle DB, MongoDB",
    "Third-Party Apps Team": "Non-Microsoft desktop apps: browsers, utilities, media players, dev tools",
    "Security Team": "Security tools: EDR, AV, SIEM agents, vulnerability scanners",
    "Virtualization Team": "Hypervisors and VM tools: VMware, Hyper-V, VirtualBox, Citrix",
    "Web / App Server Team": "Web servers and app runtimes: Apache, Nginx, Tomcat, Node.js, PHP",
    "Cloud / DevOps Team": "Cloud agents and DevOps tools: AWS, Azure, GCP SDKs, Docker, Kubernetes, Terraform",
    "Backup / Storage Team": "Backup and storage software: Veeam, Commvault, Veritas, NetApp",
    "Collaboration Team": "Collaboration and communication: Zoom, Slack, Webex (non-Cisco infra), Mattermost",
    "Java / Middleware Team": "Java runtimes and middleware: JDK, JRE, Tomcat, WildFly, WebLogic, WebSphere",
}

# ── Team Classification Rules ────────────────────────────
# (match_field, match_type, match_value, team_name)
# Evaluated top-down; first match wins.

TEAM_RULES = [
    # ── OS / Platform Team ────────────────────────────────
    ("softwareName", "contains", "windows_10", "OS Team"),
    ("softwareName", "contains", "windows_11", "OS Team"),
    ("softwareName", "contains", "windows_server", "OS Team"),
    ("softwareName", "contains", "windows_7", "OS Team"),
    ("softwareName", "contains", "windows_8", "OS Team"),
    ("softwareName", "contains", "windows_rt", "OS Team"),
    ("softwareName", "contains", "windows_xp", "OS Team"),
    ("softwareName", "contains", "windows_vista", "OS Team"),
    ("softwareName", "contains", "linux_kernel", "OS Team"),
    ("softwareName", "contains", "ubuntu", "OS Team"),
    ("softwareName", "contains", "red_hat", "OS Team"),
    ("softwareName", "contains", "redhat", "OS Team"),
    ("softwareName", "contains", "centos", "OS Team"),
    ("softwareName", "contains", "debian", "OS Team"),
    ("softwareName", "contains", "suse", "OS Team"),
    ("softwareName", "contains", "fedora", "OS Team"),
    ("softwareName", "contains", "oracle_linux", "OS Team"),
    ("softwareName", "contains", "alma_linux", "OS Team"),
    ("softwareName", "contains", "rocky_linux", "OS Team"),
    ("softwareName", "contains", "macos", "OS Team"),
    ("softwareName", "contains", "mac_os", "OS Team"),
    ("recommendationReference", "startswith", "va-_-microsoft-_-windows", "OS Team"),
    ("recommendationReference", "contains", "kernel", "OS Team"),

    # ── .NET / IIS Team ───────────────────────────────────
    ("softwareName", "contains", ".net_framework", "NET / IIS Team"),
    ("softwareName", "contains", ".net_core", "NET / IIS Team"),
    ("softwareName", "contains", ".net_runtime", "NET / IIS Team"),
    ("softwareName", "contains", "asp.net", "NET / IIS Team"),
    ("softwareName", "contains", "aspnet", "NET / IIS Team"),
    ("softwareName", "contains", "dotnet", "NET / IIS Team"),
    ("softwareName", "contains", "iis", "NET / IIS Team"),
    ("softwareName", "contains", "internet_information_services", "NET / IIS Team"),
    ("softwareName", "contains", "nuget", "NET / IIS Team"),
    ("softwareName", "contains", "powershell", "NET / IIS Team"),
    ("recommendationReference", "contains", "asp.net", "NET / IIS Team"),
    ("recommendationReference", "contains", ".net_framework", "NET / IIS Team"),
    ("softwareVendor", "contains", "microsoft", "OS Team"),

    # ── Cisco / Network Team ──────────────────────────────
    ("softwareVendor", "contains", "cisco", "Network / Cisco Team"),
    ("softwareName", "contains", "appdynamics", "Network / Cisco Team"),
    ("softwareName", "contains", "anyconnect", "Network / Cisco Team"),
    ("softwareName", "contains", "webex", "Network / Cisco Team"),
    ("softwareName", "contains", "jabber", "Network / Cisco Team"),
    ("softwareName", "contains", "cisco_secure", "Network / Cisco Team"),
    ("softwareVendor", "contains", "juniper", "Network / Cisco Team"),
    ("softwareVendor", "contains", "palo_alto", "Network / Cisco Team"),
    ("softwareVendor", "contains", "paloalto", "Network / Cisco Team"),
    ("softwareVendor", "contains", "fortinet", "Network / Cisco Team"),
    ("softwareName", "contains", "forticlient", "Network / Cisco Team"),
    ("softwareName", "contains", "fortigate", "Network / Cisco Team"),
    ("softwareVendor", "contains", "f5", "Network / Cisco Team"),
    ("softwareName", "contains", "big-ip", "Network / Cisco Team"),
    ("softwareVendor", "contains", "aruba", "Network / Cisco Team"),
    ("softwareName", "contains", "checkpoint", "Network / Cisco Team"),
    ("softwareVendor", "contains", "sonicwall", "Network / Cisco Team"),
    ("softwareName", "contains", "wireguard", "Network / Cisco Team"),
    ("softwareName", "contains", "openvpn", "Network / Cisco Team"),
    ("softwareName", "contains", "pulse_secure", "Network / Cisco Team"),
    ("softwareName", "contains", "globalprotect", "Network / Cisco Team"),

    # ── ManageEngine / Endpoint Team ──────────────────────
    ("softwareVendor", "contains", "manageengine", "Endpoint / ManageEngine Team"),
    ("softwareName", "contains", "manageengine", "Endpoint / ManageEngine Team"),
    ("softwareVendor", "contains", "zoho", "Endpoint / ManageEngine Team"),
    ("softwareName", "contains", "desktop_central", "Endpoint / ManageEngine Team"),
    ("softwareName", "contains", "sccm", "Endpoint / ManageEngine Team"),
    ("softwareName", "contains", "intune", "Endpoint / ManageEngine Team"),
    ("softwareName", "contains", "bigfix", "Endpoint / ManageEngine Team"),
    ("softwareVendor", "contains", "hcl_software", "Endpoint / ManageEngine Team"),
    ("softwareName", "contains", "tanium", "Endpoint / ManageEngine Team"),
    ("softwareName", "contains", "ivanti", "Endpoint / ManageEngine Team"),
    ("softwareVendor", "contains", "ivanti", "Endpoint / ManageEngine Team"),
    ("softwareName", "contains", "landesk", "Endpoint / ManageEngine Team"),
    ("softwareName", "contains", "connectwise", "Endpoint / ManageEngine Team"),
    ("softwareName", "contains", "kaseya", "Endpoint / ManageEngine Team"),

    # ── Microsoft Apps Team ───────────────────────────────
    ("softwareName", "contains", "microsoft_edge", "Microsoft Apps Team"),
    ("softwareName", "contains", "office", "Microsoft Apps Team"),
    ("softwareName", "contains", "outlook", "Microsoft Apps Team"),
    ("softwareName", "contains", "excel", "Microsoft Apps Team"),
    ("softwareName", "contains", "word", "Microsoft Apps Team"),
    ("softwareName", "contains", "onedrive", "Microsoft Apps Team"),
    ("softwareName", "contains", "teams", "Microsoft Apps Team"),
    ("softwareName", "contains", "project", "Microsoft Apps Team"),
    ("softwareName", "contains", "visio", "Microsoft Apps Team"),
    ("softwareName", "contains", "sharepoint", "Microsoft Apps Team"),
    ("softwareName", "contains", "access", "Microsoft Apps Team"),
    ("softwareName", "contains", "publisher", "Microsoft Apps Team"),
    ("softwareName", "contains", "onenote", "Microsoft Apps Team"),
    ("softwareName", "contains", "skype", "Microsoft Apps Team"),
    ("softwareName", "contains", "visual_studio", "Microsoft Apps Team"),
    ("softwareName", "contains", "vs_code", "Microsoft Apps Team"),
    ("softwareName", "contains", "vscode", "Microsoft Apps Team"),
    ("softwareName", "contains", "microsoft_365", "Microsoft Apps Team"),
    ("softwareName", "contains", "m365", "Microsoft Apps Team"),
    ("softwareName", "contains", "msxml", "Microsoft Apps Team"),
    ("softwareName", "contains", "silverlight", "Microsoft Apps Team"),

    # ── Database Team ─────────────────────────────────────
    ("softwareName", "contains", "sql_server", "Database Team"),
    ("softwareName", "contains", "mysql", "Database Team"),
    ("softwareName", "contains", "postgresql", "Database Team"),
    ("softwareName", "contains", "postgres", "Database Team"),
    ("softwareName", "contains", "mariadb", "Database Team"),
    ("softwareVendor", "contains", "oracle", "Database Team"),
    ("softwareName", "contains", "oracle_database", "Database Team"),
    ("softwareName", "contains", "mongodb", "Database Team"),
    ("softwareName", "contains", "redis", "Database Team"),
    ("softwareName", "contains", "elasticsearch", "Database Team"),
    ("softwareName", "contains", "couchdb", "Database Team"),
    ("softwareName", "contains", "cassandra", "Database Team"),
    ("softwareName", "contains", "sqlite", "Database Team"),
    ("softwareName", "contains", "db2", "Database Team"),
    ("softwareVendor", "contains", "sap_se", "Database Team"),
    ("softwareName", "contains", "ssms", "Database Team"),

    # ── Virtualization Team ───────────────────────────────
    ("softwareVendor", "contains", "vmware", "Virtualization Team"),
    ("softwareName", "contains", "vmware", "Virtualization Team"),
    ("softwareName", "contains", "esxi", "Virtualization Team"),
    ("softwareName", "contains", "vcenter", "Virtualization Team"),
    ("softwareName", "contains", "vsphere", "Virtualization Team"),
    ("softwareName", "contains", "hyper-v", "Virtualization Team"),
    ("softwareName", "contains", "virtualbox", "Virtualization Team"),
    ("softwareVendor", "contains", "citrix", "Virtualization Team"),
    ("softwareName", "contains", "citrix", "Virtualization Team"),
    ("softwareName", "contains", "xen", "Virtualization Team"),
    ("softwareName", "contains", "proxmox", "Virtualization Team"),
    ("softwareName", "contains", "qemu", "Virtualization Team"),

    # ── Web / App Server Team ─────────────────────────────
    ("softwareName", "contains", "apache_http", "Web / App Server Team"),
    ("softwareName", "contains", "httpd", "Web / App Server Team"),
    ("softwareName", "contains", "nginx", "Web / App Server Team"),
    ("softwareName", "contains", "tomcat", "Web / App Server Team"),
    ("softwareName", "contains", "node.js", "Web / App Server Team"),
    ("softwareName", "contains", "nodejs", "Web / App Server Team"),
    ("softwareName", "contains", "php", "Web / App Server Team"),
    ("softwareName", "contains", "lighttpd", "Web / App Server Team"),
    ("softwareName", "contains", "caddy", "Web / App Server Team"),
    ("softwareName", "contains", "haproxy", "Web / App Server Team"),
    ("softwareName", "contains", "openssl", "Web / App Server Team"),
    ("softwareName", "contains", "curl", "Web / App Server Team"),

    # ── Java / Middleware Team ────────────────────────────
    ("softwareName", "contains", "java", "Java / Middleware Team"),
    ("softwareName", "contains", "jdk", "Java / Middleware Team"),
    ("softwareName", "contains", "jre", "Java / Middleware Team"),
    ("softwareName", "contains", "openjdk", "Java / Middleware Team"),
    ("softwareName", "contains", "wildfly", "Java / Middleware Team"),
    ("softwareName", "contains", "jboss", "Java / Middleware Team"),
    ("softwareName", "contains", "weblogic", "Java / Middleware Team"),
    ("softwareName", "contains", "websphere", "Java / Middleware Team"),
    ("softwareName", "contains", "glassfish", "Java / Middleware Team"),
    ("softwareName", "contains", "spring", "Java / Middleware Team"),
    ("softwareName", "contains", "log4j", "Java / Middleware Team"),
    ("softwareName", "contains", "maven", "Java / Middleware Team"),
    ("softwareName", "contains", "gradle", "Java / Middleware Team"),

    # ── Cloud / DevOps Team ───────────────────────────────
    ("softwareName", "contains", "docker", "Cloud / DevOps Team"),
    ("softwareName", "contains", "kubernetes", "Cloud / DevOps Team"),
    ("softwareName", "contains", "terraform", "Cloud / DevOps Team"),
    ("softwareName", "contains", "ansible", "Cloud / DevOps Team"),
    ("softwareName", "contains", "puppet", "Cloud / DevOps Team"),
    ("softwareName", "contains", "chef_infra", "Cloud / DevOps Team"),
    ("softwareName", "contains", "jenkins", "Cloud / DevOps Team"),
    ("softwareName", "contains", "gitlab", "Cloud / DevOps Team"),
    ("softwareName", "contains", "aws_cli", "Cloud / DevOps Team"),
    ("softwareName", "contains", "azure_cli", "Cloud / DevOps Team"),
    ("softwareName", "contains", "gcloud", "Cloud / DevOps Team"),
    ("softwareName", "contains", "helm", "Cloud / DevOps Team"),
    ("softwareName", "contains", "vault", "Cloud / DevOps Team"),
    ("softwareVendor", "contains", "hashicorp", "Cloud / DevOps Team"),

    # ── Backup / Storage Team ─────────────────────────────
    ("softwareName", "contains", "veeam", "Backup / Storage Team"),
    ("softwareVendor", "contains", "veeam", "Backup / Storage Team"),
    ("softwareName", "contains", "commvault", "Backup / Storage Team"),
    ("softwareVendor", "contains", "veritas", "Backup / Storage Team"),
    ("softwareName", "contains", "netbackup", "Backup / Storage Team"),
    ("softwareName", "contains", "backup_exec", "Backup / Storage Team"),
    ("softwareName", "contains", "acronis", "Backup / Storage Team"),
    ("softwareVendor", "contains", "netapp", "Backup / Storage Team"),
    ("softwareName", "contains", "synology", "Backup / Storage Team"),

    # ── Collaboration Team ────────────────────────────────
    ("softwareName", "contains", "zoom", "Collaboration Team"),
    ("softwareVendor", "contains", "zoom", "Collaboration Team"),
    ("softwareName", "contains", "slack", "Collaboration Team"),
    ("softwareName", "contains", "mattermost", "Collaboration Team"),
    ("softwareName", "contains", "telegram", "Collaboration Team"),
    ("softwareName", "contains", "signal", "Collaboration Team"),

    # ── Third-Party Apps (broad catch) ────────────────────
    ("softwareVendor", "contains", "google", "Third-Party Apps Team"),
    ("softwareVendor", "contains", "mozilla", "Third-Party Apps Team"),
    ("softwareVendor", "contains", "adobe", "Third-Party Apps Team"),
    ("softwareName", "contains", "chrome", "Third-Party Apps Team"),
    ("softwareName", "contains", "firefox", "Third-Party Apps Team"),
    ("softwareName", "contains", "acrobat", "Third-Party Apps Team"),
    ("softwareName", "contains", "reader", "Third-Party Apps Team"),
    ("softwareName", "contains", "flash", "Third-Party Apps Team"),
    ("softwareName", "contains", "7-zip", "Third-Party Apps Team"),
    ("softwareName", "contains", "7zip", "Third-Party Apps Team"),
    ("softwareName", "contains", "vlc", "Third-Party Apps Team"),
    ("softwareName", "contains", "notepad++", "Third-Party Apps Team"),
    ("softwareName", "contains", "notepadplusplus", "Third-Party Apps Team"),
    ("softwareName", "contains", "putty", "Third-Party Apps Team"),
    ("softwareName", "contains", "winscp", "Third-Party Apps Team"),
    ("softwareName", "contains", "filezilla", "Third-Party Apps Team"),
    ("softwareName", "contains", "gimp", "Third-Party Apps Team"),
    ("softwareName", "contains", "paint.net", "Third-Party Apps Team"),
    ("softwareName", "contains", "irfanview", "Third-Party Apps Team"),
    ("softwareName", "contains", "winrar", "Third-Party Apps Team"),
    ("softwareName", "contains", "peazip", "Third-Party Apps Team"),
    ("softwareName", "contains", "ccleaner", "Third-Party Apps Team"),
    ("softwareName", "contains", "teamviewer", "Third-Party Apps Team"),
    ("softwareName", "contains", "anydesk", "Third-Party Apps Team"),
    ("softwareName", "contains", "git", "Third-Party Apps Team"),
    ("softwareName", "contains", "python", "Third-Party Apps Team"),
    ("softwareName", "contains", "perl", "Third-Party Apps Team"),
    ("softwareName", "contains", "ruby", "Third-Party Apps Team"),
    ("softwareName", "contains", "rust", "Third-Party Apps Team"),
    ("softwareName", "contains", "golang", "Third-Party Apps Team"),
    ("softwareName", "contains", "r_for_windows", "Third-Party Apps Team"),
    ("softwareName", "contains", "wireshark", "Third-Party Apps Team"),
    ("softwareName", "contains", "nmap", "Third-Party Apps Team"),

    # ── Security Tools Team ───────────────────────────────
    ("softwareName", "contains", "defender", "Security Team"),
    ("softwareName", "contains", "endpoint_protection", "Security Team"),
    ("softwareName", "contains", "antivirus", "Security Team"),
    ("softwareName", "contains", "crowdstrike", "Security Team"),
    ("softwareVendor", "contains", "crowdstrike", "Security Team"),
    ("softwareName", "contains", "falcon", "Security Team"),
    ("softwareName", "contains", "sentinelone", "Security Team"),
    ("softwareName", "contains", "sophos", "Security Team"),
    ("softwareVendor", "contains", "sophos", "Security Team"),
    ("softwareName", "contains", "mcafee", "Security Team"),
    ("softwareName", "contains", "trellix", "Security Team"),
    ("softwareVendor", "contains", "trellix", "Security Team"),
    ("softwareName", "contains", "symantec", "Security Team"),
    ("softwareVendor", "contains", "symantec", "Security Team"),
    ("softwareName", "contains", "kaspersky", "Security Team"),
    ("softwareName", "contains", "eset", "Security Team"),
    ("softwareName", "contains", "bitdefender", "Security Team"),
    ("softwareName", "contains", "malwarebytes", "Security Team"),
    ("softwareName", "contains", "carbon_black", "Security Team"),
    ("softwareName", "contains", "qualys", "Security Team"),
    ("softwareName", "contains", "tenable", "Security Team"),
    ("softwareName", "contains", "nessus", "Security Team"),
    ("softwareName", "contains", "rapid7", "Security Team"),
    ("softwareName", "contains", "splunk", "Security Team"),
    ("softwareVendor", "contains", "splunk", "Security Team"),
]

# Default team if no rule matches
DEFAULT_TEAM = "Unassigned / Triage Required"


# ── Custom Rules (user-created via UI, persisted to JSON) ─
CUSTOM_RULES_FILE = os.environ.get(
    "VPRP_CUSTOM_RULES",
    "/data/custom_rules.json",
)


def load_custom_rules() -> list:
    """Load admin-created rules from JSON file."""
    path = CUSTOM_RULES_FILE
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r") as f:
            rules = json.load(f)
        # Validate structure
        validated = []
        for r in rules:
            if (isinstance(r, (list, tuple)) and len(r) == 4
                    and r[1] in ("contains", "equals", "startswith")):
                validated.append(tuple(r))
        return validated
    except (json.JSONDecodeError, IOError):
        return []


def save_custom_rules(rules: list) -> None:
    """Persist admin-created rules to JSON file."""
    path = CUSTOM_RULES_FILE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump([list(r) for r in rules], f, indent=2)


def get_all_team_names() -> list:
    """Return sorted list of all known team names."""
    teams = set(TEAM_DEFINITIONS.keys())
    teams.update(r[3] for r in TEAM_RULES)
    teams.update(r[3] for r in load_custom_rules())
    teams.discard(DEFAULT_TEAM)
    return sorted(teams)
