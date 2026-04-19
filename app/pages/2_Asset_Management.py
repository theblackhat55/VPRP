"""
VPRP — Asset Management Page
Manage asset criticality, business context, and ownership.
"""
import streamlit as st
import pandas as pd
from app.models.database import get_session
from app.models.schemas import Asset
from app.utils.constants import APP_ICON
from sqlalchemy import func

st.set_page_config(page_title="VPRP — Assets", page_icon=APP_ICON, layout="wide")
st.title(f"{APP_ICON} Asset Management")
st.caption("Manage asset criticality, business units, environments, and ownership")

CRITICALITY_LABELS = {
    1: "1 — Low",
    2: "2 — Medium",
    3: "3 — High",
    4: "4 — Critical",
    5: "5 — Mission-Critical",
}

ENVIRONMENT_OPTIONS = ["production", "staging", "development", "test", "dr", "dmz"]


def load_assets() -> pd.DataFrame:
    """Load all assets from the database."""
    session = get_session()
    try:
        assets = session.query(Asset).order_by(Asset.device_name).all()
        if not assets:
            return pd.DataFrame()
        return pd.DataFrame([
            {
                "id": str(a.id),
                "device_name": a.device_name,
                "os_platform": a.os_platform or "",
                "asset_criticality": a.asset_criticality or 3,
                "business_unit": a.business_unit or "",
                "environment": a.environment or "production",
                "owner": a.owner or "",
                "location": a.location or "",
                "first_seen": a.first_seen,
                "last_seen": a.last_seen,
            }
            for a in assets
        ])
    finally:
        session.close()


def update_asset(asset_id: str, **kwargs) -> bool:
    """Update asset fields in the database."""
    session = get_session()
    try:
        asset = session.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            return False
        for key, value in kwargs.items():
            if hasattr(asset, key):
                setattr(asset, key, value)
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        st.error(f"Update failed: {e}")
        return False
    finally:
        session.close()


def bulk_update_assets(asset_ids: list, **kwargs) -> int:
    """Bulk update multiple assets."""
    session = get_session()
    try:
        count = 0
        for aid in asset_ids:
            asset = session.query(Asset).filter(Asset.id == aid).first()
            if asset:
                for key, value in kwargs.items():
                    if hasattr(asset, key):
                        setattr(asset, key, value)
                count += 1
        session.commit()
        return count
    except Exception as e:
        session.rollback()
        st.error(f"Bulk update failed: {e}")
        return 0
    finally:
        session.close()


# ── Load Data ────────────────────────────────────────────
assets_df = load_assets()

if assets_df.empty:
    st.info("No assets discovered yet. Upload vulnerability data to auto-populate the asset registry.")
    st.stop()

# ── Summary Metrics ──────────────────────────────────────
st.header("Asset Overview")
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Assets", len(assets_df))
col2.metric("Mission-Critical (5)", len(assets_df[assets_df["asset_criticality"] == 5]))
col3.metric("Critical (4)", len(assets_df[assets_df["asset_criticality"] == 4]))
col4.metric("High (3)", len(assets_df[assets_df["asset_criticality"] == 3]))
col5.metric("Low-Medium (1-2)", len(assets_df[assets_df["asset_criticality"] <= 2]))

# Criticality distribution chart
crit_counts = assets_df["asset_criticality"].value_counts().sort_index()
crit_labels = [CRITICALITY_LABELS.get(k, str(k)) for k in crit_counts.index]

import plotly.express as px
fig_crit = px.bar(
    x=crit_labels, y=crit_counts.values,
    title="Asset Criticality Distribution",
    labels={"x": "Criticality", "y": "Count"},
    color=crit_counts.values,
    color_continuous_scale="YlOrRd",
)
st.plotly_chart(fig_crit, use_container_width=True)

# ── Filters ──────────────────────────────────────────────
st.header("Asset Registry")

fcol1, fcol2, fcol3 = st.columns(3)
with fcol1:
    filter_crit = st.multiselect(
        "Filter by criticality",
        options=list(CRITICALITY_LABELS.keys()),
        format_func=lambda x: CRITICALITY_LABELS[x],
        default=list(CRITICALITY_LABELS.keys()),
    )
with fcol2:
    filter_env = st.multiselect(
        "Filter by environment",
        options=sorted(assets_df["environment"].unique()),
        default=sorted(assets_df["environment"].unique()),
    )
with fcol3:
    filter_search = st.text_input("Search device name", "")

filtered = assets_df[
    (assets_df["asset_criticality"].isin(filter_crit))
    & (assets_df["environment"].isin(filter_env))
]
if filter_search:
    filtered = filtered[filtered["device_name"].str.contains(filter_search, case=False, na=False)]

st.caption(f"Showing {len(filtered)} of {len(assets_df)} assets")

# Display table
display_df = filtered[[
    "device_name", "os_platform", "asset_criticality",
    "business_unit", "environment", "owner", "location", "last_seen",
]].copy()
display_df["asset_criticality"] = display_df["asset_criticality"].map(CRITICALITY_LABELS)
display_df.columns = [
    "Device Name", "OS", "Criticality",
    "Business Unit", "Environment", "Owner", "Location", "Last Seen",
]
st.dataframe(display_df, use_container_width=True, hide_index=True, height=400)

# ── Bulk Update ──────────────────────────────────────────
st.divider()
st.header("Bulk Update Assets")
st.caption("Apply changes to all assets matching the current filter")

bcol1, bcol2 = st.columns(2)
with bcol1:
    bulk_criticality = st.selectbox(
        "Set criticality",
        options=[None] + list(CRITICALITY_LABELS.keys()),
        format_func=lambda x: "— No change —" if x is None else CRITICALITY_LABELS[x],
        key="bulk_crit",
    )
    bulk_environment = st.selectbox(
        "Set environment",
        options=[None] + ENVIRONMENT_OPTIONS,
        format_func=lambda x: "— No change —" if x is None else x,
        key="bulk_env",
    )
with bcol2:
    bulk_business_unit = st.text_input("Set business unit (blank = no change)", "", key="bulk_bu")
    bulk_owner = st.text_input("Set owner (blank = no change)", "", key="bulk_owner")

if st.button(f"Apply to {len(filtered)} assets", type="primary", key="bulk_apply"):
    updates = {}
    if bulk_criticality is not None:
        updates["asset_criticality"] = bulk_criticality
    if bulk_environment is not None:
        updates["environment"] = bulk_environment
    if bulk_business_unit.strip():
        updates["business_unit"] = bulk_business_unit.strip()
    if bulk_owner.strip():
        updates["owner"] = bulk_owner.strip()

    if updates:
        asset_ids = filtered["id"].tolist()
        count = bulk_update_assets(asset_ids, **updates)
        st.success(f"Updated {count} assets")
        st.rerun()
    else:
        st.warning("No changes selected")

# ── Single Asset Editor ──────────────────────────────────
st.divider()
st.header("Edit Single Asset")

asset_names = sorted(assets_df["device_name"].tolist())
selected_asset_name = st.selectbox("Select asset", asset_names, key="single_asset")

if selected_asset_name:
    asset_row = assets_df[assets_df["device_name"] == selected_asset_name].iloc[0]

    ecol1, ecol2 = st.columns(2)
    with ecol1:
        edit_crit = st.selectbox(
            "Criticality",
            options=list(CRITICALITY_LABELS.keys()),
            format_func=lambda x: CRITICALITY_LABELS[x],
            index=list(CRITICALITY_LABELS.keys()).index(asset_row["asset_criticality"]),
            key="edit_crit",
        )
        edit_env = st.selectbox(
            "Environment",
            options=ENVIRONMENT_OPTIONS,
            index=ENVIRONMENT_OPTIONS.index(asset_row["environment"]) if asset_row["environment"] in ENVIRONMENT_OPTIONS else 0,
            key="edit_env",
        )
        edit_location = st.text_input("Location", value=asset_row["location"], key="edit_loc")
    with ecol2:
        edit_bu = st.text_input("Business Unit", value=asset_row["business_unit"], key="edit_bu")
        edit_owner = st.text_input("Owner", value=asset_row["owner"], key="edit_owner")
        st.markdown(f"**OS:** {asset_row['os_platform']}")
        st.markdown(f"**First seen:** {asset_row['first_seen']}")
        st.markdown(f"**Last seen:** {asset_row['last_seen']}")

    if st.button("Save Changes", key="save_single"):
        success = update_asset(
            asset_row["id"],
            asset_criticality=edit_crit,
            environment=edit_env,
            business_unit=edit_bu,
            owner=edit_owner,
            location=edit_location,
        )
        if success:
            st.success(f"Asset '{selected_asset_name}' updated")
            st.rerun()

# ── CSV Import for Bulk Asset Context ────────────────────
st.divider()
st.header("Import Asset Context (CSV)")
st.caption("Upload a CSV with columns: device_name, asset_criticality, business_unit, environment, owner, location")

asset_csv = st.file_uploader("Upload asset CSV", type=["csv"], key="asset_csv")
if asset_csv:
    try:
        import_df = pd.read_csv(asset_csv)
        st.dataframe(import_df.head(10), use_container_width=True)

        if "device_name" not in import_df.columns:
            st.error("CSV must contain a 'device_name' column")
        elif st.button("Import Asset Context", type="primary", key="import_assets"):
            session = get_session()
            try:
                updated = 0
                created = 0
                for _, row in import_df.iterrows():
                    device = str(row["device_name"]).strip()
                    if not device:
                        continue
                    asset = session.query(Asset).filter(Asset.device_name == device).first()
                    if asset:
                        if "asset_criticality" in row and pd.notna(row["asset_criticality"]):
                            asset.asset_criticality = int(row["asset_criticality"])
                        if "business_unit" in row and pd.notna(row["business_unit"]):
                            asset.business_unit = str(row["business_unit"])
                        if "environment" in row and pd.notna(row["environment"]):
                            asset.environment = str(row["environment"])
                        if "owner" in row and pd.notna(row["owner"]):
                            asset.owner = str(row["owner"])
                        if "location" in row and pd.notna(row["location"]):
                            asset.location = str(row["location"])
                        updated += 1
                    else:
                        new_asset = Asset(
                            device_name=device,
                            asset_criticality=int(row.get("asset_criticality", 3)) if pd.notna(row.get("asset_criticality")) else 3,
                            business_unit=str(row.get("business_unit", "")) if pd.notna(row.get("business_unit")) else None,
                            environment=str(row.get("environment", "production")) if pd.notna(row.get("environment")) else "production",
                            owner=str(row.get("owner", "")) if pd.notna(row.get("owner")) else None,
                            location=str(row.get("location", "")) if pd.notna(row.get("location")) else None,
                        )
                        session.add(new_asset)
                        created += 1
                session.commit()
                st.success(f"Import complete: {updated} updated, {created} created")
                st.rerun()
            except Exception as e:
                session.rollback()
                st.error(f"Import failed: {e}")
            finally:
                session.close()
    except Exception as e:
        st.error(f"Failed to read CSV: {e}")
