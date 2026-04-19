"""
Optional enrichment: CISA KEV, EPSS, and Azure AI Foundry.
All enrichments are graceful — failures log warnings but never break the pipeline.
"""
import os
import logging
import pandas as pd
import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

ENABLE_AI = os.getenv("ENABLE_AI_ENRICHMENT", "false").lower() == "true"

# ── CISA KEV ─────────────────────────────────────────────
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known-exploited-vulnerabilities.json"
_kev_cache = None


def load_kev_catalog() -> set:
    """Download and cache the CISA KEV catalog."""
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache
    try:
        resp = requests.get(_KEV_URL, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        _kev_cache = {v["cveID"] for v in data.get("vulnerabilities", [])}
        logger.info("Loaded %d CVEs from CISA KEV catalog", len(_kev_cache))
    except Exception as e:
        logger.warning("Failed to load CISA KEV catalog: %s", e)
        _kev_cache = set()
    return _kev_cache


def enrich_with_kev(df: pd.DataFrame) -> pd.DataFrame:
    """Flag CVEs in CISA KEV and boost their risk score."""
    df = df.copy()
    kev = load_kev_catalog()
    df["cisaKev"] = df["cveId"].isin(kev)
    kev_count = df["cisaKev"].sum()
    if kev_count > 0:
        df.loc[df["cisaKev"], "riskScore"] = (
            df.loc[df["cisaKev"], "riskScore"] * 1.25
        ).clip(upper=100)
        logger.info("Flagged %d findings matching CISA KEV", kev_count)
    return df


# ── EPSS ──────────────────────────────────────────────────
def enrich_with_epss(df: pd.DataFrame) -> pd.DataFrame:
    """Fetch EPSS scores for unique CVEs."""
    df = df.copy()
    unique_cves = df["cveId"].dropna().unique().tolist()
    epss_map = {}

    for i in range(0, len(unique_cves), 100):
        batch = unique_cves[i : i + 100]
        try:
            resp = requests.get(
                "https://api.first.org/data/v1/epss",
                params={"cve": ",".join(batch)},
                timeout=15,
            )
            if resp.ok:
                for entry in resp.json().get("data", []):
                    epss_map[entry["cve"]] = float(entry.get("epss", 0))
        except Exception as e:
            logger.warning("EPSS API batch %d failed: %s", i, e)

    df["epssScore"] = df["cveId"].map(epss_map).fillna(0.0)
    logger.info("Fetched EPSS scores for %d CVEs", len(epss_map))
    return df


# ── Azure AI Foundry ──────────────────────────────────────
def _get_ai_client():
    """Initialize Azure AI Inference client."""
    if not ENABLE_AI:
        return None
    try:
        from azure.ai.inference import ChatCompletionsClient
        from azure.core.credentials import AzureKeyCredential

        endpoint = os.getenv("AZURE_AI_ENDPOINT")
        key = os.getenv("AZURE_AI_KEY")
        if not endpoint or not key:
            return None
        return ChatCompletionsClient(
            endpoint=endpoint, credential=AzureKeyCredential(key)
        )
    except ImportError:
        logger.warning("azure-ai-inference not installed; AI enrichment unavailable")
        return None


def ai_generate_executive_summary(df: pd.DataFrame) -> str:
    """Generate executive summary using AI or fallback template."""
    client = _get_ai_client()
    if client is None:
        return _fallback_executive_summary(df)

    try:
        from azure.ai.inference.models import SystemMessage, UserMessage

        model = os.getenv("AZURE_AI_MODEL", "gpt-4o")
        stats = _build_stats_block(df)

        response = client.complete(
            model=model,
            messages=[
                SystemMessage(
                    content=(
                        "You are a cybersecurity vulnerability analyst. Produce a concise "
                        "executive summary (max 300 words) of the organisation's vulnerability "
                        "posture. Highlight top risks, SLA breaches, and recommended actions. "
                        "Professional tone for CISO reporting."
                    )
                ),
                UserMessage(content=stats),
            ],
            max_tokens=600,
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.warning("AI executive summary failed: %s", e)
        return _fallback_executive_summary(df)


def ai_generate_team_summary(team_name: str, team_df: pd.DataFrame) -> str:
    """Generate team-specific remediation brief using AI or fallback."""
    client = _get_ai_client()
    if client is None:
        return _fallback_team_summary(team_name, team_df)

    try:
        from azure.ai.inference.models import SystemMessage, UserMessage

        model = os.getenv("AZURE_AI_MODEL", "gpt-4o")
        stats = _build_team_stats(team_name, team_df)

        response = client.complete(
            model=model,
            messages=[
                SystemMessage(
                    content=(
                        "You are a cybersecurity remediation advisor. Write a concise "
                        "actionable remediation brief (max 200 words) for this team. "
                        "Focus on: what to patch first, most dangerous CVEs, and "
                        "recommended updates. Use bullet points for top 5 actions."
                    )
                ),
                UserMessage(content=stats),
            ],
            max_tokens=400,
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.warning("AI team summary failed for %s: %s", team_name, e)
        return _fallback_team_summary(team_name, team_df)


def _build_stats_block(df: pd.DataFrame) -> str:
    total = len(df)
    unique_cves = df["cveId"].nunique()
    devices = df["deviceName"].nunique()
    by_sev = df["vulnerabilitySeverityLevel"].value_counts().to_dict()
    by_team = df["assignedTeam"].value_counts().head(10).to_dict()
    kev_count = int(df["cisaKev"].sum()) if "cisaKev" in df.columns else "N/A"
    breached = int(df["slaBreached"].sum()) if "slaBreached" in df.columns else "N/A"

    return (
        f"Total vulnerability findings: {total}\n"
        f"Unique CVEs: {unique_cves}\n"
        f"Affected devices: {devices}\n"
        f"By severity: {by_sev}\n"
        f"By team: {by_team}\n"
        f"CISA KEV matches: {kev_count}\n"
        f"SLA breaches: {breached}\n"
    )


def _build_team_stats(team: str, tdf: pd.DataFrame) -> str:
    cols = ["cveId", "cvssScore", "riskScore", "softwareName",
            "recommendedSecurityUpdate"]
    cols = [c for c in cols if c in tdf.columns]
    top = tdf.nlargest(10, "riskScore")[cols]
    return f"Team: {team}\nTotal findings: {len(tdf)}\nTop CVEs:\n{top.to_string(index=False)}"


def _fallback_executive_summary(df: pd.DataFrame) -> str:
    stats = _build_stats_block(df)
    return (
        "Executive Summary (auto-generated — enable Azure AI for richer analysis)\n"
        "=" * 70 + "\n\n" + stats
    )


def _fallback_team_summary(team: str, tdf: pd.DataFrame) -> str:
    cols = ["cveId", "cvssScore", "riskScore", "softwareName",
            "recommendedSecurityUpdate"]
    cols = [c for c in cols if c in tdf.columns]
    top5 = tdf.nlargest(5, "riskScore")[cols].to_string(index=False)
    return (
        f"{team} — Remediation Brief (enable Azure AI for detailed guidance)\n"
        f"{'=' * 60}\n"
        f"Total findings: {len(tdf)} | Unique CVEs: {tdf['cveId'].nunique()} | "
        f"Devices: {tdf['deviceName'].nunique()}\n\n"
        f"Top 5 by risk:\n{top5}"
    )
