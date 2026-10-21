"""Separate observed match ratios from sample-weighted confidence scores."""
from alembic import op
import sqlalchemy as sa

revision = "b8c4e13a9d20"
down_revision = "8ca35beef7a7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Previous scans did not retain the counts needed to reconstruct these values.
    op.add_column("column_inventory", sa.Column("match_ratio", sa.Float(), nullable=True))
    op.add_column("column_inventory", sa.Column("embedded_match_ratio", sa.Float(), nullable=True))
    op.add_column("column_inventory", sa.Column("embedded_confidence", sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column("column_inventory", "embedded_confidence")
    op.drop_column("column_inventory", "embedded_match_ratio")
    op.drop_column("column_inventory", "match_ratio")
