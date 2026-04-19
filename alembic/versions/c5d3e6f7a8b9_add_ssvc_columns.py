"""Add SSVC decision columns to findings

Revision ID: c5d3e6f7a8b9
Revises: b4c2d5e6f7a8
Create Date: 2026-04-19
"""
from alembic import op
import sqlalchemy as sa

revision = "c5d3e6f7a8b9"
down_revision = "b4c2d5e6f7a8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── SSVC decision-point columns ──
    op.add_column("findings", sa.Column("ssvc_exploitation", sa.String(30), nullable=True))
    op.add_column("findings", sa.Column("ssvc_system_exposure", sa.String(30), nullable=True))
    op.add_column("findings", sa.Column("ssvc_automatable", sa.String(10), nullable=True))
    op.add_column("findings", sa.Column("ssvc_human_impact", sa.String(20), nullable=True))
    op.add_column("findings", sa.Column("ssvc_priority", sa.String(30), nullable=True))
    op.add_column("findings", sa.Column("ssvc_evaluated_at", sa.DateTime(), nullable=True))

    # ── Correlation / grouping columns ──
    op.add_column("findings", sa.Column("patch_group", sa.String(500), nullable=True))
    op.add_column("findings", sa.Column("software_group", sa.String(500), nullable=True))
    op.add_column("findings", sa.Column("correlation_cluster", sa.String(200), nullable=True))

    # ── Asset-group columns ──
    op.add_column("findings", sa.Column("asset_group_id", sa.String(100), nullable=True))
    op.add_column("findings", sa.Column("asset_group_name", sa.String(200), nullable=True))
    op.add_column("findings", sa.Column("asset_group_criticality", sa.String(30), nullable=True))

    # Indexes for common query patterns
    op.create_index("ix_findings_ssvc_priority", "findings", ["ssvc_priority"])
    op.create_index("ix_findings_patch_group", "findings", ["patch_group"])
    op.create_index("ix_findings_software_group", "findings", ["software_group"])
    op.create_index("ix_findings_asset_group_id", "findings", ["asset_group_id"])
    op.create_index("ix_findings_ssvc_exploitation", "findings", ["ssvc_exploitation"])

    # ── Create asset_groups table for persistent group definitions ──
    op.create_table(
        "asset_groups",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("group_type", sa.String(50), nullable=False, server_default="custom"),
        sa.Column("match_patterns", sa.Text()),       # JSON array of patterns
        sa.Column("criticality", sa.String(30), server_default="medium"),
        sa.Column("owner", sa.String(200)),
        sa.Column("team", sa.String(200)),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("created_by", sa.String(200), server_default="system"),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true")),
    )
    op.create_index("ix_asset_groups_group_type", "asset_groups", ["group_type"])
    op.create_index("ix_asset_groups_criticality", "asset_groups", ["criticality"])
    op.create_index("ix_asset_groups_team", "asset_groups", ["team"])


def downgrade() -> None:
    op.drop_index("ix_asset_groups_team", table_name="asset_groups")
    op.drop_index("ix_asset_groups_criticality", table_name="asset_groups")
    op.drop_index("ix_asset_groups_group_type", table_name="asset_groups")
    op.drop_table("asset_groups")

    op.drop_index("ix_findings_ssvc_exploitation", table_name="findings")
    op.drop_index("ix_findings_asset_group_id", table_name="findings")
    op.drop_index("ix_findings_software_group", table_name="findings")
    op.drop_index("ix_findings_patch_group", table_name="findings")
    op.drop_index("ix_findings_ssvc_priority", table_name="findings")

    for col in [
        "ssvc_exploitation", "ssvc_system_exposure", "ssvc_automatable",
        "ssvc_human_impact", "ssvc_priority", "ssvc_evaluated_at",
        "patch_group", "software_group", "correlation_cluster",
        "asset_group_id", "asset_group_name", "asset_group_criticality",
    ]:
        op.drop_column("findings", col)
