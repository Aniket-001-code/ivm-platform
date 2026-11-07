"""Audit hash chain + immutability triggers, ingestion error capture, workflow columns.

Revision 0001 builds tables from the current models, so on a fresh database these columns
already exist; each column is only added when missing so existing databases upgrade cleanly.
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_audit_chain_and_workflow"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None

NEW_COLUMNS = {
    "audit_logs": [
        sa.Column("sequence", sa.Integer(), nullable=True),
        sa.Column("prev_hash", sa.String(64), nullable=True),
        sa.Column("row_hash", sa.String(64), nullable=True),
    ],
    "raw_findings": [sa.Column("error_message", sa.Text(), nullable=True)],
    "findings": [
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reopened_count", sa.Integer(), nullable=False, server_default="0"),
    ],
    "remediation_tasks": [sa.Column("assigned_group", sa.String(120), nullable=True)],
    "escalations": [
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.Uuid(), nullable=True),
    ],
}

SQLITE_TRIGGERS = [
    """CREATE TRIGGER IF NOT EXISTS audit_logs_no_update BEFORE UPDATE ON audit_logs
       BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END""",
    """CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete BEFORE DELETE ON audit_logs
       BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END""",
]

POSTGRES_TRIGGERS = [
    """CREATE OR REPLACE FUNCTION audit_logs_append_only() RETURNS trigger AS $$
       BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END; $$ LANGUAGE plpgsql""",
    "DROP TRIGGER IF EXISTS audit_logs_no_update_delete ON audit_logs",
    """CREATE TRIGGER audit_logs_no_update_delete BEFORE UPDATE OR DELETE ON audit_logs
       FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only()""",
]


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    for table, columns in NEW_COLUMNS.items():
        existing = {c["name"] for c in inspector.get_columns(table)}
        for column in columns:
            if column.name not in existing:
                op.add_column(table, column)
    existing_indexes = {i["name"] for i in inspector.get_indexes("audit_logs")}
    if "ix_audit_logs_sequence" not in existing_indexes:
        op.create_index("ix_audit_logs_sequence", "audit_logs", ["sequence"], unique=True)
    statements = POSTGRES_TRIGGERS if bind.dialect.name == "postgresql" else SQLITE_TRIGGERS
    for statement in statements:
        op.execute(statement)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_logs_no_update_delete ON audit_logs")
        op.execute("DROP FUNCTION IF EXISTS audit_logs_append_only()")
    else:
        op.execute("DROP TRIGGER IF EXISTS audit_logs_no_update")
        op.execute("DROP TRIGGER IF EXISTS audit_logs_no_delete")
