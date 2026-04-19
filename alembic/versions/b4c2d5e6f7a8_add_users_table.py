"""add users table

Revision ID: b4c2d5e6f7a8
Revises: a3b1c2d4e5f6
Create Date: 2026-04-19
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'b4c2d5e6f7a8'
down_revision = 'a3b1c2d4e5f6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text('gen_random_uuid()')),
        sa.Column('username', sa.String(100), nullable=False, unique=True),
        sa.Column('email', sa.String(300), nullable=False, unique=True),
        sa.Column('password_hash', sa.String(500), nullable=False),
        sa.Column('full_name', sa.String(200)),
        sa.Column('role', sa.String(30), nullable=False, server_default='viewer'),
        sa.Column('team', sa.String(200)),
        sa.Column('is_active', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('last_login', sa.DateTime),
        sa.Column('login_count', sa.Integer, server_default='0'),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.text('NOW()')),
        sa.Column('created_by', sa.String(100), server_default='system'),
    )
    op.create_index('ix_users_username', 'users', ['username'], unique=True)
    op.create_index('ix_users_email', 'users', ['email'], unique=True)
    op.create_index('ix_users_role', 'users', ['role'])

    # Seed default admin user (password: admin — CHANGE IMMEDIATELY)
    # bcrypt hash for 'admin'
    op.execute("""
        INSERT INTO users (id, username, email, password_hash, full_name, role, is_active)
        VALUES (
            gen_random_uuid(),
            'admin',
            'admin@vprp.local',
            '$2b$12$oie5X4QUDNgSbykh2aRdHugh1yJUCWD/wWQLpM0S9XFGW9H5YxVrW',
            'VPRP Administrator',
            'admin',
            true
        )
    """)


def downgrade() -> None:
    op.drop_index('ix_users_role', table_name='users')
    op.drop_index('ix_users_email', table_name='users')
    op.drop_index('ix_users_username', table_name='users')
    op.drop_table('users')
