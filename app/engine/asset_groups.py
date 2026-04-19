"""
VPRP — Asset Grouping Engine
Groups assets into applications, services, or teams.
All related vulnerabilities inherit the group context.
"""
import logging
import json
import os
from typing import Optional, List, Dict

import pandas as pd
from sqlalchemy import Column, String, Integer, Text, DateTime, Boolean, JSON
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid

from app.models.database import get_session, Base
from app.models.schemas import Asset, Finding

logger = logging.getLogger(__name__)

ASSET_GROUPS_FILE = os.environ.get("VPRP_ASSET_GROUPS", "/data/asset_groups.json")


# ── In-memory + file-based asset group definitions ───────

def load_asset_groups() -> list:
    """Load asset group definitions from persistent storage."""
    if os.path.exists(ASSET_GROUPS_FILE):
        try:
            with open(ASSET_GROUPS_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load asset groups: {e}")
    return []


def save_asset_groups(groups: list):
    """Save asset group definitions."""
    try:
        os.makedirs(os.path.dirname(ASSET_GROUPS_FILE), exist_ok=True)
        with open(ASSET_GROUPS_FILE, "w") as f:
            json.dump(groups, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save asset groups: {e}")


def create_asset_group(
    name: str,
    group_type: str,  # application, service, team, business_unit, environment
    description: str = "",
    owner: str = "",
    criticality: int = 3,
    match_rules: list = None,
    device_names: list = None,
) -> dict:
    """Create a new asset group definition."""
    groups = load_asset_groups()

    # Check uniqueness
    if any(g["name"] == name for g in groups):
        logger.error(f"Asset group '{name}' already exists")
        return None

    group = {
        "id": str(uuid.uuid4()),
        "name": name,
        "type": group_type,
        "description": description,
        "owner": owner,
        "criticality": criticality,
        "match_rules": match_rules or [],
        "device_names": device_names or [],
        "created_at": datetime.utcnow().isoformat(),
    }
    groups.append(group)
    save_asset_groups(groups)
    logger.info(f"Asset group created: {name} ({group_type})")
    return group


def update_asset_group(group_id: str, **kwargs) -> bool:
    """Update an existing asset group."""
    groups = load_asset_groups()
    for g in groups:
        if g["id"] == group_id:
            allowed = ["name", "type", "description", "owner", "criticality",
                       "match_rules", "device_names"]
            for key, val in kwargs.items():
                if key in allowed:
                    g[key] = val
            g["updated_at"] = datetime.utcnow().isoformat()
            save_asset_groups(groups)
            return True
    return False


def delete_asset_group(group_id: str) -> bool:
    """Delete an asset group."""
    groups = load_asset_groups()
    new_groups = [g for g in groups if g["id"] != group_id]
    if len(new_groups) < len(groups):
        save_asset_groups(new_groups)
        return True
    return False


def match_device_to_groups(device_name: str, groups: list = None) -> list:
    """Find all groups a device belongs to based on rules and explicit membership."""
    if groups is None:
        groups = load_asset_groups()

    matched = []
    device_lower = device_name.lower()

    for group in groups:
        # Explicit device list
        if device_name in group.get("device_names", []):
            matched.append(group)
            continue

        # Rule-based matching
        for rule in group.get("match_rules", []):
            field = rule.get("field", "device_name")
            match_type = rule.get("type", "contains")
            value = rule.get("value", "").lower()

            if field == "device_name":
                target = device_lower
            elif field == "os_platform":
                target = ""  # would need asset lookup
            else:
                target = device_lower

            if match_type == "contains" and value in target:
                matched.append(group)
                break
            elif match_type == "startswith" and target.startswith(value):
                matched.append(group)
                break
            elif match_type == "endswith" and target.endswith(value):
                matched.append(group)
                break
            elif match_type == "exact" and target == value:
                matched.append(group)
                break
            elif match_type == "regex":
                import re
                if re.search(value, target):
                    matched.append(group)
                    break

    return matched


def apply_asset_groups(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply asset group context to findings DataFrame.
    Adds columns: assetGroups, assetGroupNames, assetGroupTypes, maxGroupCriticality
    """
    if df.empty or "deviceName" not in df.columns:
        return df

    groups = load_asset_groups()
    if not groups:
        df["assetGroups"] = ""
        df["assetGroupNames"] = ""
        df["assetGroupTypes"] = ""
        df["maxGroupCriticality"] = 3
        return df

    group_names = []
    group_types = []
    group_ids = []
    max_criticalities = []

    for _, row in df.iterrows():
        device = row.get("deviceName", "")
        matched = match_device_to_groups(device, groups)

        if matched:
            group_names.append(", ".join(g["name"] for g in matched))
            group_types.append(", ".join(set(g["type"] for g in matched)))
            group_ids.append(", ".join(g["id"] for g in matched))
            max_criticalities.append(max(g.get("criticality", 3) for g in matched))
        else:
            group_names.append("")
            group_types.append("")
            group_ids.append("")
            max_criticalities.append(3)

    df = df.copy()
    df["assetGroups"] = group_ids
    df["assetGroupNames"] = group_names
    df["assetGroupTypes"] = group_types
    df["maxGroupCriticality"] = max_criticalities

    assigned = sum(1 for n in group_names if n)
    logger.info(f"Asset grouping: {assigned}/{len(df)} findings matched to groups")
    return df


def get_group_vulnerability_summary(df: pd.DataFrame) -> pd.DataFrame:
    """
    Summarize vulnerabilities per asset group.
    Returns a DataFrame with group-level risk metrics.
    """
    groups = load_asset_groups()
    if not groups or df.empty:
        return pd.DataFrame()

    summaries = []
    for group in groups:
        # Find all devices in this group
        devices = set(group.get("device_names", []))
        for _, row in df.iterrows():
            device = row.get("deviceName", "")
            matched = match_device_to_groups(device, [group])
            if matched:
                devices.add(device)

        # Filter findings for these devices
        if "deviceName" in df.columns:
            group_findings = df[df["deviceName"].isin(devices)]
        else:
            group_findings = pd.DataFrame()

        if group_findings.empty:
            summaries.append({
                "group_name": group["name"],
                "group_type": group["type"],
                "owner": group.get("owner", ""),
                "criticality": group.get("criticality", 3),
                "device_count": 0,
                "finding_count": 0,
                "critical_count": 0,
                "high_count": 0,
                "avg_risk": 0,
                "max_risk": 0,
                "sla_breached": 0,
            })
            continue

        summaries.append({
            "group_name": group["name"],
            "group_type": group["type"],
            "owner": group.get("owner", ""),
            "criticality": group.get("criticality", 3),
            "device_count": group_findings["deviceName"].nunique() if "deviceName" in group_findings.columns else 0,
            "finding_count": len(group_findings),
            "critical_count": (group_findings["vulnerabilitySeverity"] == "critical").sum() if "vulnerabilitySeverity" in group_findings.columns else 0,
            "high_count": (group_findings["vulnerabilitySeverity"] == "high").sum() if "vulnerabilitySeverity" in group_findings.columns else 0,
            "avg_risk": round(group_findings["riskScore"].mean(), 1) if "riskScore" in group_findings.columns else 0,
            "max_risk": round(group_findings["riskScore"].max(), 1) if "riskScore" in group_findings.columns else 0,
            "sla_breached": (group_findings["slaBreached"] == True).sum() if "slaBreached" in group_findings.columns else 0,
        })

    return pd.DataFrame(summaries).sort_values("max_risk", ascending=False)
