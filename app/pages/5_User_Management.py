"""
VPRP — User Management (Admin Only)
Create, edit, deactivate user accounts.
"""
import streamlit as st
import pandas as pd

from app.utils.auth_guard import require_role, show_user_sidebar
from app.models.auth_service import (
    list_users, create_user, update_user, change_password,
    delete_user, ROLES,
)

st.set_page_config(page_title="VPRP — Users", page_icon="👥", layout="wide")
st.title("👥 User Management")
show_user_sidebar()

# Admin-only access
current_user = require_role("admin")

# ── User List ───────────────────────────────────────────
st.header("User Accounts")
show_inactive = st.checkbox("Show inactive users", value=False)
users = list_users(include_inactive=show_inactive)

if users:
    users_df = pd.DataFrame(users)
    display_cols = ["username", "email", "full_name", "role", "team", "is_active",
                    "last_login", "login_count"]
    available = [c for c in display_cols if c in users_df.columns]
    st.dataframe(users_df[available], use_container_width=True, hide_index=True)
    st.caption(f"Total: {len(users)} user(s)")
else:
    st.info("No users found.")

# ── Create User ─────────────────────────────────────────
st.divider()
st.header("Create New User")

with st.form("create_user_form"):
    cu1, cu2 = st.columns(2)
    with cu1:
        new_username = st.text_input("Username")
        new_email = st.text_input("Email")
        new_password = st.text_input("Password", type="password")
    with cu2:
        new_fullname = st.text_input("Full Name")
        new_role = st.selectbox("Role", list(ROLES.keys()))
        new_team = st.text_input("Team (optional)")

    st.caption(f"**{new_role}**: {ROLES[new_role]['description']}")

    if st.form_submit_button("Create User", type="primary"):
        if new_username and new_email and new_password:
            result = create_user(
                new_username, new_email, new_password,
                full_name=new_fullname or None,
                role=new_role,
                team=new_team or None,
                created_by=current_user["username"],
            )
            if result:
                st.success(f"User **{new_username}** created with role **{new_role}**.")
                st.rerun()
            else:
                st.error("Failed — username or email may already exist.")
        else:
            st.warning("Username, email, and password are required.")

# ── Edit User ───────────────────────────────────────────
st.divider()
st.header("Edit User")

if users:
    user_options = {f"{u['username']} ({u['role']})": u for u in users}
    selected_label = st.selectbox("Select user", list(user_options.keys()))
    selected_user = user_options[selected_label]

    with st.form("edit_user_form"):
        eu1, eu2 = st.columns(2)
        with eu1:
            edit_fullname = st.text_input("Full Name", value=selected_user.get("full_name") or "")
            edit_email = st.text_input("Email", value=selected_user["email"])
            edit_role = st.selectbox("Role", list(ROLES.keys()),
                                    index=list(ROLES.keys()).index(selected_user["role"]))
        with eu2:
            edit_team = st.text_input("Team", value=selected_user.get("team") or "")
            edit_active = st.checkbox("Active", value=selected_user["is_active"])

        if st.form_submit_button("Save Changes"):
            ok = update_user(
                selected_user["id"],
                updated_by=current_user["username"],
                full_name=edit_fullname or None,
                email=edit_email,
                role=edit_role,
                team=edit_team or None,
                is_active=edit_active,
            )
            if ok:
                st.success(f"User **{selected_user['username']}** updated.")
                st.rerun()
            else:
                st.error("Update failed.")

    # ── Password Reset ──
    with st.expander("Reset Password"):
        with st.form("reset_pw_form"):
            new_pw = st.text_input("New Password", type="password", key="reset_pw")
            confirm_pw = st.text_input("Confirm Password", type="password", key="confirm_pw")
            if st.form_submit_button("Reset Password"):
                if new_pw and new_pw == confirm_pw:
                    ok = change_password(selected_user["id"], new_pw,
                                        changed_by=current_user["username"])
                    if ok:
                        st.success(f"Password reset for **{selected_user['username']}**.")
                    else:
                        st.error("Password reset failed.")
                else:
                    st.warning("Passwords must match and not be empty.")

    # ── Deactivate ──
    with st.expander("Deactivate User"):
        if selected_user["username"] != current_user["username"]:
            if st.button(f"Deactivate {selected_user['username']}", type="secondary"):
                delete_user(selected_user["id"], deleted_by=current_user["username"])
                st.warning(f"User **{selected_user['username']}** deactivated.")
                st.rerun()
        else:
            st.info("You cannot deactivate your own account.")

# ── Role Reference ──────────────────────────────────────
st.divider()
with st.expander("Role Permissions Reference"):
    for role, info in ROLES.items():
        st.markdown(f"**{role}** (level {info['level']}): {info['description']}")
