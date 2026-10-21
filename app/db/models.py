from datetime import datetime
from typing import Any
from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from app.db.base import Base


class Source(Base):
    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    secret_path: Mapped[str] = mapped_column(
    String(255), nullable=False
)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_scanned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    columns: Mapped[list["ColumnInventory"]] = relationship(
        "ColumnInventory",
        back_populates="source",
        cascade="all, delete-orphan",
    )

class ColumnInventory(Base):
    __tablename__ = "column_inventory"
    __table_args__ = (
        UniqueConstraint(
            "source_id",
            "schema_name",
            "table_name",
            "column_name",
            name="uq_source_schema_table_column",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    source_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("sources.id", ondelete="CASCADE"), nullable=False, index=True
    )
    schema_name: Mapped[str] = mapped_column(String(128), nullable=False)
    table_name: Mapped[str] = mapped_column(String(128), nullable=False)
    column_name: Mapped[str] = mapped_column(String(128), nullable=False)
    data_type: Mapped[str] = mapped_column(String(64), nullable=False)

    # Classification & Risk outputs
    inferred_pii_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="NONE"
    )
    embedded_pii_types: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    match_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)
    embedded_match_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)
    embedded_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="NONE")

    # Sampling stats & masked evidence
    sample_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    null_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    masked_evidence: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    justification: Mapped[str] = mapped_column(Text, nullable=False, default="")

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    source: Mapped["Source"] = relationship("Source", back_populates="columns")
