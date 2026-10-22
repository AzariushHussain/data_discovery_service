from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class SourceCreateRequest(BaseModel):
    name: str = Field(
        ...,
        min_length=1,
        max_length=120,
        examples=["Customer E-Commerce Prod"],
    )
    dsn: str = Field(
        ...,
        min_length=10,
        description="PostgreSQL connection string (e.g. postgresql+psycopg://user:pass@host:5432/dbname)",
        examples=[
            "postgresql+psycopg://customer_ro:customer_password@sample_source_db:5432/ecommerce_prod"
        ],
    )


class SourceResponse(BaseModel):
    id: int
    name: str
    created_at: datetime
    last_scanned_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class ColumnInventoryResponse(BaseModel):
    id: int
    source_id: int
    schema_name: str
    table_name: str
    column_name: str
    data_type: str
    inferred_pii_type: str
    embedded_pii_types: list[str]
    confidence: float = Field(
        description="Primary match ratio weighted by sample size; zero when primary is NONE. A heuristic, not a probability of correctness or absence of PII."
    )
    match_ratio: float | None = Field(
        description="Fraction matching the selected primary type; zero if no type reaches 25%. Subthreshold candidates are explained in justification; null until rescanned."
    )
    embedded_match_ratio: float | None = Field(
        description="Fraction of sampled values with PII inside surrounding text; null until rescanned."
    )
    embedded_confidence: float | None = Field(
        description="Embedded match ratio weighted by sample size; null until rescanned."
    )
    risk_level: str
    sample_size: int = Field(description="Nonblank values among the sampled table rows.")
    null_count: int = Field(description="Null or blank values among sampled table rows, not the whole table.")
    masked_evidence: list[str]
    justification: str
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanSummaryResponse(BaseModel):
    source_id: int
    scanned_at: datetime
    total_columns_scanned: int
    pii_columns_detected: int
    embedded_pii_columns_detected: int
    risk_breakdown: dict[str, int]


class InventoryReportResponse(BaseModel):
    source_id: int
    source_name: str
    last_scanned_at: datetime | None
    total_columns: int
    columns: list[ColumnInventoryResponse]
