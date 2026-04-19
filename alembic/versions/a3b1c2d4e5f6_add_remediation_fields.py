"""add remediation tracking fields

Revision ID: a3b1c2d4e5f6
Revises: 2f63606c464d
Create Date: 2026-04-19
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'a3b1c2d4e5f6'
down_revision = '2f63606c464d'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Remediation status columns on findings ──
    op.add_column('findings', sa.Column('remediation_status', sa.String(30),
                  nullable=False, server_default='open'))
    op.add_column('findings', sa.Column('remediation_substatus', sa.String(50),
                  nullable=True))
    op.add_column('findings', sa.Column('remediation_notes', sa.Text(),
                  nullable=True))
    op.add_column('findings', sa.Column('remediation_updated_at', sa.DateTime(),
                  nullable=True))
    op.add_column('findings', sa.Column('remediation_updated_by', sa.String(200),
                  nullable=True))
    op.add_column('findings', sa.Column('assigned_to', sa.String(200),
                  nullable=True))
    op.add_column('findings', sa.Column('ticket_id', sa.String(100),
                  nullable=True))
    op.add_column('findings', sa.Column('ticket_url', sa.String(500),
                  nullable=True))

    # ── Exception / risk-acceptance fields ──
    op.add_column('findings', sa.Column('exception_status', sa.String(30),
                  nullable=True))
    op.add_column('findings', sa.Column('exception_reason', sa.Text(),
                  nullable=True))
    op.add_column('findings', sa.Column('exception_requested_by', sa.String(200),
                  nullable=True))
    op.add_column('findings', sa.Column('exception_requested_at', sa.DateTime(),
                  nullable=True))
    op.add_column('findings', sa.Column('exception_approved_by', sa.String(200),
                  nullable=True))
    op.add_column('findings', sa.Column('exception_approved_at', sa.DateTime(),
                  nullable=True))
    op.add_column('findings', sa.Column('exception_expiry', sa.DateTime(),
                  nullable=True))

    # ── Remediation audit log table ──
    op.create_table(
        'remediation_audit_log',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text('gen_random_uuid()')),
        sa.Column('finding_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('action', sa.String(50), nullable=False),
        sa.Column('old_status', sa.String(30), nullable=True),
        sa.Column('new_status', sa.String(30), nullable=True),
        sa.Column('old_substatus', sa.String(50), nullable=True),
        sa.Column('new_substatus', sa.String(50), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('performed_by', sa.String(200), nullable=False,
                  server_default='system'),
        sa.Column('performed_at', sa.DateTime(), nullable=False,
                  server_default=sa.text('NOW()')),
    )
    op.create_index('ix_audit_finding', 'remediation_audit_log', ['finding_id'])
    op.create_index('ix_audit_performed_at', 'remediation_audit_log', ['performed_at'])

    # ── Indexes for remediation queries ──
    op.create_index('ix_findings_status', 'findings', ['remediation_status'])
    op.create_index('ix_findings_exception', 'findings', ['exception_status'])
    op.create_index('ix_findings_assigned_to', 'findings', ['assigned_to'])

    # ── Backfill existing rows ──
    op.execute("UPDATE findings SET remediation_status = 'open' WHERE remediation_status IS NULL")


def downgrade() -> None:
    op.drop_index('ix_findings_assigned_to', table_name='findings')
    op.drop_index('ix_findings_exception', table_name='findings')
    op.drop_index('ix_findings_status', table_name='findings')
    op.drop_index('ix_audit_performed_at', table_name='remediation_audit_log')
    op.drop_index('ix_audit_finding', table_name='remediation_audit_log')
    op.drop_table('remediation_audit_log')
    for col in ['exception_expiry', 'exception_approved_at', 'exception_approved_by',
                'exception_requested_at', 'exception_requested_by', 'exception_reason',
                'exception_status', 'ticket_url', 'ticket_id', 'assigned_to',
                'remediation_updated_by', 'remediation_updated_at',
                'remediation_notes', 'remediation_substatus', 'remediation_status']:
        op.drop_column('findings', col)
