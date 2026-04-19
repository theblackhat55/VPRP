"""
VPRP — Authentication Guard
Reusable login gate for Streamlit pages.
"""
import streamlit as st
from app.models.auth_service import authenticate, check_permission, ROLES


def login_form():
    """Show login form and return True if authenticated."""
    if "user" in st.session_state and st.session_state["user"]:
        return True

    st.markdown("### 🔐 Login Required")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign In", type="primary")

    if submitted:
        if username and password:
            user = authenticate(username, password)
            if user:
                st.session_state["user"] = user
                st.rerun()
            else:
                st.error("Invalid username or password.")
        else:
            st.warning("Enter both username and password.")

    return False


def require_login():
    """Block page access unless logged in. Returns user dict."""
    if not login_form():
        st.stop()
    return st.session_state["user"]


def require_role(required_role: str):
    """Block page unless user has sufficient role. Returns user dict."""
    user = require_login()
    if not check_permission(user, required_role):
        st.error(f"Access denied. Required role: **{required_role}** or higher.")
        st.stop()
    return user


def show_user_sidebar():
    """Display logged-in user info in sidebar with logout."""
    if "user" in st.session_state and st.session_state["user"]:
        user = st.session_state["user"]
        with st.sidebar:
            st.divider()
            st.caption(f"👤 **{user['full_name'] or user['username']}**")
            st.caption(f"Role: {user['role']} | Team: {user.get('team') or 'N/A'}")
            if st.button("Logout", key="logout_btn"):
                del st.session_state["user"]
                st.rerun()
