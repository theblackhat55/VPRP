"""
VPRP — Authentication & User Management Service
Local login with bcrypt-hashed passwords stored in PostgreSQL.
"""
import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

import bcrypt
from sqlalchemy import func

from app.models.database import get_session
from app.models.schemas import User

logger = logging.getLogger(__name__)

ROLES = {
    "admin": {"level": 100, "description": "Full access — manage users, settings, all data"},
    "analyst": {"level": 70, "description": "Upload scans, classify, update remediation status"},
    "team_lead": {"level": 50, "description": "View team findings, update status, request exceptions"},
    "viewer": {"level": 10, "description": "Read-only access to dashboards and reports"},
}


def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify plaintext against bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def authenticate(username: str, password: str, session=None) -> Optional[dict]:
    """Authenticate user and return user info dict or None."""
    _session = session or get_session()
    try:
        user = _session.query(User).filter(
            User.username == username,
            User.is_active == True,
        ).first()

        if not user:
            logger.warning(f"Login failed: user '{username}' not found or inactive")
            return None

        if not verify_password(password, user.password_hash):
            logger.warning(f"Login failed: wrong password for '{username}'")
            return None

        # Update login stats
        user.last_login = datetime.utcnow()
        user.login_count = (user.login_count or 0) + 1
        _session.commit()

        logger.info(f"User '{username}' authenticated (role={user.role})")
        return {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "team": user.team,
            "is_active": user.is_active,
        }
    except Exception as e:
        logger.error(f"Auth error: {e}")
        return None
    finally:
        if not session:
            _session.close()


def create_user(username: str, email: str, password: str, full_name: str = None,
                role: str = "viewer", team: str = None, created_by: str = "admin",
                session=None) -> Optional[dict]:
    """Create a new user account."""
    if role not in ROLES:
        logger.error(f"Invalid role: {role}")
        return None

    _session = session or get_session()
    try:
        # Check uniqueness
        existing = _session.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing:
            logger.error(f"User already exists: {username} / {email}")
            return None

        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            full_name=full_name,
            role=role,
            team=team,
            created_by=created_by,
        )
        _session.add(user)
        _session.commit()
        logger.info(f"User created: {username} (role={role}) by {created_by}")
        return {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "role": user.role,
        }
    except Exception as e:
        _session.rollback()
        logger.error(f"Create user failed: {e}")
        return None
    finally:
        if not session:
            _session.close()


def update_user(user_id: str, updated_by: str = "admin", session=None, **kwargs) -> bool:
    """Update user fields (full_name, email, role, team, is_active)."""
    _session = session or get_session()
    try:
        user = _session.query(User).filter(User.id == user_id).first()
        if not user:
            return False

        allowed_fields = ["full_name", "email", "role", "team", "is_active"]
        for key, value in kwargs.items():
            if key in allowed_fields and value is not None:
                setattr(user, key, value)

        user.updated_at = datetime.utcnow()
        _session.commit()
        logger.info(f"User {user.username} updated by {updated_by}: {list(kwargs.keys())}")
        return True
    except Exception as e:
        _session.rollback()
        logger.error(f"Update user failed: {e}")
        return False
    finally:
        if not session:
            _session.close()


def change_password(user_id: str, new_password: str, changed_by: str = "self",
                    session=None) -> bool:
    """Change a user's password."""
    _session = session or get_session()
    try:
        user = _session.query(User).filter(User.id == user_id).first()
        if not user:
            return False
        user.password_hash = hash_password(new_password)
        user.updated_at = datetime.utcnow()
        _session.commit()
        logger.info(f"Password changed for {user.username} by {changed_by}")
        return True
    except Exception as e:
        _session.rollback()
        logger.error(f"Password change failed: {e}")
        return False
    finally:
        if not session:
            _session.close()


def delete_user(user_id: str, deleted_by: str = "admin", session=None) -> bool:
    """Deactivate (soft-delete) a user."""
    return update_user(user_id, updated_by=deleted_by, is_active=False)


def list_users(include_inactive: bool = False, session=None) -> list:
    """List all user accounts."""
    _session = session or get_session()
    try:
        q = _session.query(User)
        if not include_inactive:
            q = q.filter(User.is_active == True)
        q = q.order_by(User.username)

        return [{
            "id": str(u.id),
            "username": u.username,
            "email": u.email,
            "full_name": u.full_name,
            "role": u.role,
            "team": u.team,
            "is_active": u.is_active,
            "last_login": str(u.last_login) if u.last_login else "Never",
            "login_count": u.login_count or 0,
            "created_at": str(u.created_at),
        } for u in q.all()]
    finally:
        if not session:
            _session.close()


def get_user_by_id(user_id: str, session=None) -> Optional[dict]:
    """Get user details by ID."""
    _session = session or get_session()
    try:
        u = _session.query(User).filter(User.id == user_id).first()
        if not u:
            return None
        return {
            "id": str(u.id),
            "username": u.username,
            "email": u.email,
            "full_name": u.full_name,
            "role": u.role,
            "team": u.team,
            "is_active": u.is_active,
            "last_login": str(u.last_login) if u.last_login else "Never",
            "login_count": u.login_count or 0,
        }
    finally:
        if not session:
            _session.close()


def check_permission(user_info: dict, required_role: str) -> bool:
    """Check if user has sufficient role level."""
    if not user_info:
        return False
    user_level = ROLES.get(user_info.get("role", ""), {}).get("level", 0)
    required_level = ROLES.get(required_role, {}).get("level", 100)
    return user_level >= required_level
