"""
Three-tier vulnerability classifier:
  Tier 1 — Rule engine (built-in + custom rules, fast, free)
  Tier 2 — LLM fallback for unmatched rows (optional, costs API calls)
  Tier 3 — Flagged for admin review
"""
import os
import logging
import pandas as pd
from app.config import (
    TEAM_RULES, DEFAULT_TEAM, TEAM_DEFINITIONS,
    load_custom_rules, save_custom_rules, get_all_team_names,
)

logger = logging.getLogger(__name__)


# ───────────────────────────────────────────────────────────
# Tier 1: Rule-Based Classification
# ───────────────────────────────────────────────────────────

def _apply_rules(df: pd.DataFrame, rules: list) -> pd.DataFrame:
    """Apply a list of rules to unassigned rows. First match wins."""
    for field, match_type, match_value, team in rules:
        if field not in df.columns:
            continue

        col = df[field].astype(str).str.lower()
        val = match_value.lower()

        if match_type == "contains":
            mask = col.str.contains(val, na=False, regex=False)
        elif match_type == "equals":
            mask = col == val
        elif match_type == "startswith":
            mask = col.str.startswith(val, na=False)
        else:
            continue

        unassigned = df["assignedTeam"] == DEFAULT_TEAM
        df.loc[mask & unassigned, "assignedTeam"] = team

    return df


def classify_teams(df: pd.DataFrame) -> pd.DataFrame:
    """Tier 1: Assign teams using built-in rules then custom rules."""
    df = df.copy()
    df["assignedTeam"] = DEFAULT_TEAM
    df["classificationTier"] = ""

    # Built-in rules
    df = _apply_rules(df, TEAM_RULES)
    df.loc[df["assignedTeam"] != DEFAULT_TEAM, "classificationTier"] = "rule"

    # Custom rules (admin-created)
    custom_rules = load_custom_rules()
    if custom_rules:
        before_count = (df["assignedTeam"] == DEFAULT_TEAM).sum()
        df = _apply_rules(df, custom_rules)
        after_count = (df["assignedTeam"] == DEFAULT_TEAM).sum()
        newly_classified = before_count - after_count
        if newly_classified > 0:
            logger.info(f"Custom rules classified {newly_classified} additional rows")
        # Mark custom-rule matches
        df.loc[
            (df["assignedTeam"] != DEFAULT_TEAM) & (df["classificationTier"] == ""),
            "classificationTier"
        ] = "custom_rule"

    # Mark remaining as needing review
    df.loc[df["assignedTeam"] == DEFAULT_TEAM, "classificationTier"] = "unmatched"

    return df


# ───────────────────────────────────────────────────────────
# Tier 2: LLM-Based Classification (optional)
# ───────────────────────────────────────────────────────────

def classify_with_llm(df: pd.DataFrame) -> pd.DataFrame:
    """Use Azure AI Foundry to classify unmatched rows.

    Only processes rows where assignedTeam == DEFAULT_TEAM.
    Groups by (softwareVendor, softwareName) to minimize API calls.
    """
    enabled = os.getenv("ENABLE_AI_ENRICHMENT", "false").lower() == "true"
    if not enabled:
        logger.info("AI classification disabled, skipping LLM tier")
        return df

    endpoint = os.getenv("AZURE_AI_ENDPOINT", "")
    api_key = os.getenv("AZURE_AI_KEY", "")
    model = os.getenv("AZURE_AI_MODEL", "gpt-4o")

    if not endpoint or not api_key:
        logger.warning("Azure AI credentials not configured, skipping LLM tier")
        return df

    try:
        from azure.ai.inference import ChatCompletionsClient
        from azure.core.credentials import AzureKeyCredential
    except ImportError:
        logger.warning("azure-ai-inference not installed, skipping LLM tier")
        return df

    unmatched = df[df["assignedTeam"] == DEFAULT_TEAM].copy()
    if unmatched.empty:
        return df

    # Group unique vendor+software combos to minimize calls
    combos = (
        unmatched.groupby(["softwareVendor", "softwareName"], dropna=False)
        .size()
        .reset_index(name="count")
    )

    team_names = get_all_team_names()
    team_descriptions = "\n".join(
        f"  - {name}: {desc}" for name, desc in TEAM_DEFINITIONS.items()
    )

    system_prompt = f"""You are a vulnerability management classifier. Given a software vendor
and software name, assign it to the most appropriate team from this list:

{team_descriptions}

If none fit well, respond with exactly: {DEFAULT_TEAM}

Respond with ONLY the team name, nothing else. No explanations."""

    client = ChatCompletionsClient(endpoint=endpoint, credential=AzureKeyCredential(api_key))
    llm_map = {}
    classified_count = 0

    for _, row in combos.iterrows():
        vendor = str(row["softwareVendor"])
        software = str(row["softwareName"])
        user_msg = f"Vendor: {vendor}\nSoftware: {software}"

        try:
            response = client.complete(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.0,
                max_tokens=50,
            )
            team = response.choices[0].message.content.strip()

            # Validate the response is a known team
            if team in team_names or team == DEFAULT_TEAM:
                llm_map[(vendor.lower(), software.lower())] = team
                if team != DEFAULT_TEAM:
                    classified_count += 1
            else:
                # Fuzzy match: check if response contains a known team name
                matched = False
                for known_team in team_names:
                    if known_team.lower() in team.lower():
                        llm_map[(vendor.lower(), software.lower())] = known_team
                        classified_count += 1
                        matched = True
                        break
                if not matched:
                    logger.warning(f"LLM returned unknown team '{team}' for {vendor}/{software}")
                    llm_map[(vendor.lower(), software.lower())] = DEFAULT_TEAM

        except Exception as e:
            logger.error(f"LLM classification failed for {vendor}/{software}: {e}")
            continue

    # Apply LLM results
    if llm_map:
        for idx, row in df.iterrows():
            if row["assignedTeam"] == DEFAULT_TEAM:
                key = (
                    str(row.get("softwareVendor", "")).lower(),
                    str(row.get("softwareName", "")).lower(),
                )
                if key in llm_map and llm_map[key] != DEFAULT_TEAM:
                    df.at[idx, "assignedTeam"] = llm_map[key]
                    df.at[idx, "classificationTier"] = "llm"

    logger.info(f"LLM classified {classified_count} unique vendor/software combos")
    return df


# ───────────────────────────────────────────────────────────
# Tier 3: Admin Review Helpers
# ───────────────────────────────────────────────────────────

def get_unmatched_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Return summary of unmatched rows grouped by vendor + software for admin review."""
    unmatched = df[df["assignedTeam"] == DEFAULT_TEAM]
    if unmatched.empty:
        return pd.DataFrame()

    summary = (
        unmatched.groupby(["softwareVendor", "softwareName"], dropna=False)
        .agg(
            cveCount=("cveId", "nunique"),
            deviceCount=("deviceName", "nunique"),
            maxCvss=("cvssScore", "max"),
            maxRisk=("riskScore", "max") if "riskScore" in unmatched.columns else ("cvssScore", "max"),
            sampleCves=("cveId", lambda x: ", ".join(x.unique()[:3])),
        )
        .reset_index()
        .sort_values("cveCount", ascending=False)
    )
    return summary


def add_custom_rule(field: str, match_type: str, value: str, team: str) -> bool:
    """Add a new custom rule created by admin via the UI."""
    if not all([field, match_type, value, team]):
        return False
    if match_type not in ("contains", "equals", "startswith"):
        return False

    rules = load_custom_rules()
    new_rule = (field, match_type, value, team)

    # Avoid duplicates
    if new_rule in [tuple(r) for r in rules]:
        return False

    rules.append(new_rule)
    save_custom_rules(rules)
    logger.info(f"Custom rule added: {new_rule}")
    return True


def remove_custom_rule(index: int) -> bool:
    """Remove a custom rule by index."""
    rules = load_custom_rules()
    if 0 <= index < len(rules):
        removed = rules.pop(index)
        save_custom_rules(rules)
        logger.info(f"Custom rule removed: {removed}")
        return True
    return False
