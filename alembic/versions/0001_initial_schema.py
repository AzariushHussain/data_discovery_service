"""initial_schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-19 11:30:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sources",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("dsn", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(op.f("ix_sources_id"), "sources", ["id"], unique=False)

    op.create_table(
        "column_inventory",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "source_id",
            sa.Integer(),
            sa.ForeignKey("sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("schema_name", sa.String(length=128), nullable=False),
        sa.Column("table_name", sa.String(length=128), nullable=False),
        sa.Column("column_name", sa.String(length=128), nullable=False),
        sa.Column("data_type", sa.String(length=64), nullable=False),
        sa.Column("inferred_pii_type", sa.String(length=32), nullable=False),
        sa.Column(
            "embedded_pii_types",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("risk_level", sa.String(length=16), nullable=False),
        sa.Column("sample_size", sa.Integer(), nullable=False),
        sa.Column("null_count", sa.Integer(), nullable=False),
        sa.Column(
            "masked_evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "source_id",
            "schema_name",
            "table_name",
            "column_name",
            name="uq_source_schema_table_column",
        ),
    )
    op.create_index(
        op.f("ix_column_inventory_id"), "column_inventory", ["id"], unique=False
    )
    op.create_index(
        op.f("ix_column_inventory_source_id"),
        "column_inventory",
        ["source_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_column_inventory_source_id"), table_name="column_inventory"
    )
    op.drop_index(op.f("ix_column_inventory_id"), table_name="column_inventory")
    op.drop_table("column_inventory")
    op.drop_index(op.f("ix_sources_id"), table_name="sources")
    op.drop_table("sources")
