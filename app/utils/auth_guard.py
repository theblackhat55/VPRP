"""
VPRP — Authentication Guard
Central session-based auth. Hides sidebar when not logged in.
"""
import os
import streamlit as st
from app.models.auth_service import authenticate, check_permission, ROLES

HIDE_SIDEBAR_CSS = """
<style>
    [data-testid="stSidebar"] { display: none !important; }
    [data-testid="stSidebarNav"] { display: none !important; }
    header[data-testid="stHeader"] { display: none !important; }
    .stDeployButton { display: none !important; }
</style>
"""


def is_authenticated() -> bool:
    return "user" in st.session_state and st.session_state["user"] is not None


def get_current_user() -> dict:
    return st.session_state.get("user", None)


def logout_user():
    for key in list(st.session_state.keys()):
        if key in ["user", "authenticated"]:
            del st.session_state[key]


def require_auth():
    """Gate any page — hides sidebar and shows redirect message if not authenticated."""
    if not is_authenticated():
        st.markdown(HIDE_SIDEBAR_CSS, unsafe_allow_html=True)
        st.markdown("""
        <div style="text-align:center; padding-top:100px;">
            <span style="font-size:3em;">🔐</span>
            <h2>Authentication Required</h2>
            <p style="color:#64748b;">Please sign in from the main page.</p>
        </div>
        """, unsafe_allow_html=True)

        # Provide a mini login form on sub-pages too
        c1, c2, c3 = st.columns([1, 1.5, 1])
        with c2:
            with st.form("page_login", clear_on_submit=False):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                if st.form_submit_button("Sign In", type="primary", use_container_width=True):
                    if username and password:
                        user = authenticate(username, password)
                        if user:
                            st.session_state["user"] = user
                            st.rerun()
                        else:
                            st.error("Invalid credentials.")
        st.stop()
    return st.session_state["user"]


def require_role(required_role: str):
    """Require minimum role level."""
    user = require_auth()
    if not check_permission(user, required_role):
        st.error(f"Access denied. Required role: **{required_role}** or higher.")
        st.stop()
    return user


def show_user_sidebar():
    """Display user info and logout in sidebar."""
    if is_authenticated():
        user = st.session_state["user"]
        with st.sidebar:
            logo_path = "/data/branding/logo.png"
            if os.path.exists(logo_path):
                st.image(logo_path, width=180)
            st.divider()
            st.caption(f"👤 **{user.get('full_name') or user['username']}**")
            st.caption(f"Role: {user['role']} | Team: {user.get('team') or 'N/A'}")
            if st.button("🚪 Logout", key="_logout_btn_" + st.session_state.get("_page_id", "main")):
                logout_user()
                st.rerun()
