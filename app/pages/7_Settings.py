"""
VPRP — Platform Settings
Logo upload, branding, system configuration.
"""
import streamlit as st
import os
import shutil
from pathlib import Path

from app.utils.auth_guard import require_role, show_user_sidebar
st.session_state["_page_id"] = "settings"

st.set_page_config(page_title="VPRP — Settings", page_icon="⚙️", layout="wide")
st.title("⚙️ Platform Settings")

current_user = require_role("admin")
st.session_state["_page_id"] = "settings"
show_user_sidebar()

BRANDING_DIR = "/data/branding"
LOGO_PATH = os.path.join(BRANDING_DIR, "logo.png")
FAVICON_PATH = os.path.join(BRANDING_DIR, "favicon.png")

# Ensure branding directory exists
os.makedirs(BRANDING_DIR, exist_ok=True)

# ── Branding ────────────────────────────────────────────
st.header("Branding & Logo")

br1, br2 = st.columns(2)

with br1:
    st.subheader("Company Logo")
    st.caption("Displayed on the login page and sidebar. Recommended: PNG, max 500x200px.")

    if os.path.exists(LOGO_PATH):
        st.image(LOGO_PATH, width=250)
        st.success("Logo is set.")
        if st.button("Remove Logo"):
            os.remove(LOGO_PATH)
            st.success("Logo removed.")
            st.rerun()
    else:
        st.info("No logo uploaded yet.")

    uploaded_logo = st.file_uploader(
        "Upload Logo (PNG/JPG)", type=["png", "jpg", "jpeg"],
        key="logo_upload",
    )
    if uploaded_logo:
        # Save uploaded file
        with open(LOGO_PATH, "wb") as f:
            f.write(uploaded_logo.getbuffer())
        st.success(f"Logo uploaded: {uploaded_logo.name} ({uploaded_logo.size} bytes)")
        st.rerun()

with br2:
    st.subheader("Favicon")
    st.caption("Browser tab icon. Recommended: PNG, 32x32 or 64x64px.")

    if os.path.exists(FAVICON_PATH):
        st.image(FAVICON_PATH, width=64)
        st.success("Favicon is set.")
        if st.button("Remove Favicon"):
            os.remove(FAVICON_PATH)
            st.success("Favicon removed.")
            st.rerun()
    else:
        st.info("No favicon uploaded yet.")

    uploaded_favicon = st.file_uploader(
        "Upload Favicon (PNG)", type=["png"],
        key="favicon_upload",
    )
    if uploaded_favicon:
        with open(FAVICON_PATH, "wb") as f:
            f.write(uploaded_favicon.getbuffer())
        st.success(f"Favicon uploaded: {uploaded_favicon.name}")
        st.rerun()

# ── Platform Info ───────────────────────────────────────
st.divider()
st.header("Platform Information")

from app.utils.constants import APP_NAME, APP_VERSION

pi1, pi2, pi3 = st.columns(3)
pi1.metric("Platform", APP_NAME)
pi2.metric("Version", APP_VERSION)
pi3.metric("Environment", os.environ.get("VPRP_ENV", "production"))

# ── Database Stats ──────────────────────────────────────
st.divider()
st.header("Database Statistics")

from app.models.database import get_session
from app.models.schemas import Finding, Asset, ScanUpload, User
from sqlalchemy import func

session = get_session()
try:
    stats = {
        "Findings": session.query(func.count(Finding.id)).scalar() or 0,
        "Assets": session.query(func.count(Asset.id)).scalar() or 0,
        "Scan Uploads": session.query(func.count(ScanUpload.id)).scalar() or 0,
        "Users": session.query(func.count(User.id)).scalar() or 0,
    }
finally:
    session.close()

ds1, ds2, ds3, ds4 = st.columns(4)
ds1.metric("Findings", f"{stats['Findings']:,}")
ds2.metric("Assets", f"{stats['Assets']:,}")
ds3.metric("Scan Uploads", f"{stats['Scan Uploads']:,}")
ds4.metric("Users", f"{stats['Users']:,}")

# ── Notification Settings (display current) ─────────────
st.divider()
st.header("Notification Configuration")

nc1, nc2 = st.columns(2)
with nc1:
    st.subheader("Microsoft Teams")
    teams_url = os.environ.get("TEAMS_WEBHOOK_URL", "")
    if teams_url:
        st.success(f"Configured: ...{teams_url[-30:]}")
    else:
        st.warning("Not configured. Set `TEAMS_WEBHOOK_URL` in .env")

with nc2:
    st.subheader("Email (SMTP)")
    smtp_host = os.environ.get("SMTP_HOST", "")
    if smtp_host:
        st.success(f"Configured: {smtp_host}:{os.environ.get('SMTP_PORT', '587')}")
    else:
        st.warning("Not configured. Set `SMTP_HOST` in .env")

st.caption("To change notification settings, update the `.env` file and restart the app container.")

# ── Data Management ─────────────────────────────────────
st.divider()
st.header("Data Management")

with st.expander("Clear Cache"):
    st.caption("Clear Streamlit's internal cache. Useful if data appears stale.")
    if st.button("Clear All Caches"):
        st.cache_data.clear()
        st.success("All caches cleared.")

with st.expander("Storage Usage"):
    dirs_to_check = {
        "Uploads": "/data/uploads",
        "Reports": "/data/reports",
        "Archives": "/data/archives",
        "Logs": "/data/logs",
        "Branding": BRANDING_DIR,
    }
    for name, path in dirs_to_check.items():
        if os.path.exists(path):
            total_size = sum(
                os.path.getsize(os.path.join(dirpath, filename))
                for dirpath, dirnames, filenames in os.walk(path)
                for filename in filenames
            )
            size_mb = total_size / (1024 * 1024)
            st.text(f"{name}: {size_mb:.2f} MB ({path})")
        else:
            st.text(f"{name}: directory not found ({path})")
