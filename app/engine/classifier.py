"""
Classify each vulnerability row to a responsible team using config rules.
Vectorized implementation for performance on large datasets.
"""
import pandas as pd
from app.config import TEAM_RULES, DEFAULT_TEAM


def classify_teams(df: pd.DataFrame) -> pd.DataFrame:
    """Add 'assignedTeam' column based on TEAM_RULES. Vectorized for speed."""
    df = df.copy()
    df["assignedTeam"] = DEFAULT_TEAM

    for field, match_type, match_value, team in TEAM_RULES:
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

        # Only assign to rows not yet classified (first match wins)
        unassigned = df["assignedTeam"] == DEFAULT_TEAM
        df.loc[mask & unassigned, "assignedTeam"] = team

    return df
