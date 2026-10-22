from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from uuid import uuid4
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from app.services.secret_store import SecretStore, SecretStoreError

from app.api.schemas import (
    ColumnInventoryResponse,
    InventoryReportResponse,
    ScanSummaryResponse,
    SourceCreateRequest,
    SourceResponse,
)
from app.config import settings
from app.db.models import ColumnInventory, Source
from app.db.session import get_db
from app.services.classifier import PIIClassifier
from app.services.connector import SourceScanError, TargetDBConnector

router = APIRouter()


def _normalize_dsn(raw_dsn: str) -> str:
    dsn = raw_dsn.strip()

    if dsn.startswith("postgres://"):
        dsn = dsn.replace("postgres://", "postgresql+psycopg://", 1)
    elif dsn.startswith("postgresql://"):
        dsn = dsn.replace("postgresql://", "postgresql+psycopg://", 1)

    try:
        url = make_url(dsn)
        if url.drivername != "postgresql+psycopg":
            raise ValueError("Unsupported database driver")
        return dsn
    except (SQLAlchemyError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="Invalid PostgreSQL connection string.",
        ) from None


def _to_source_response(source: Source) -> SourceResponse:
    return SourceResponse(
        id=source.id,
        name=source.name,
        created_at=source.created_at,
        last_scanned_at=source.last_scanned_at,
    )

def _get_source_dsn(source: Source) -> str:
    try:
        return SecretStore().get_dsn(source.secret_path)
    except SecretStoreError:
        raise HTTPException(
            status_code=503,
            detail="Could not retrieve source credentials.",
        ) from None


@router.post(
    "/sources",
    response_model=SourceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register and verify a PostgreSQL data source",
)
def register_source(
    payload: SourceCreateRequest,
    db: Session = Depends(get_db),
) -> SourceResponse:
    normalized_dsn = _normalize_dsn(payload.dsn)
    connector = None
    try:
        connector = TargetDBConnector(normalized_dsn)
        connector.verify_connection()
    except (ConnectionError, SQLAlchemyError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="Could not connect to the target database.",
        ) from None
    finally:
        if connector is not None:
            connector.engine.dispose()

    secret_path = f"sources/{uuid4().hex}"

    try:
        SecretStore().store_dsn(secret_path, normalized_dsn)
    except SecretStoreError:
        raise HTTPException(
            status_code=503,
            detail="Credential storage is unavailable.",
        ) from None

    new_source = Source(
    name=payload.name,
    secret_path=secret_path,
    )

    try:
        db.add(new_source)
        db.commit()
        db.refresh(new_source)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not save the source registration.",
        ) from None

    return _to_source_response(new_source)


@router.get(
    "/sources",
    response_model=list[SourceResponse],
    summary="List all registered data sources",
)
def list_sources(db: Session = Depends(get_db)) -> list[SourceResponse]:
    sources = db.scalars(select(Source).order_by(Source.id.asc())).all()
    return [_to_source_response(src) for src in sources]


@router.post(
    "/sources/{source_id}/scan",
    response_model=ScanSummaryResponse,
    summary="Run schema discovery and PII classification on a registered source",
)
def scan_source(source_id: int, db: Session = Depends(get_db)) -> ScanSummaryResponse:
    connector = None
    try:
        # Hold one source row until commit/rollback so overlapping scans cannot reconcile stale data.
        source = db.scalar(select(Source).where(Source.id == source_id).with_for_update(nowait=True))
        if source is None:
            raise HTTPException(status_code=404, detail=f"Source {source_id} not found.")
        dsn = _get_source_dsn(source)
        connector = TargetDBConnector(dsn)
        connector.verify_connection()
        discovered_columns = connector.discover_schema()

        risk_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
        pii_columns_detected = 0
        embedded_pii_columns_detected = 0
        now_utc = datetime.now(timezone.utc)
        current_ids = []

        tables = {}
        for col_meta in discovered_columns:
            key = (col_meta["schema_name"], col_meta["table_name"])
            tables.setdefault(key, []).append(col_meta)

        for (schema_name, table_name), table_columns in tables.items():
            table_samples = connector.sample_table_values(
                schema_name=schema_name,
                table_name=table_name,
                column_names=[col["column_name"] for col in table_columns],
                limit=settings.SAMPLE_LIMIT,
            )
            for col_meta in table_columns:
                column_name = col_meta["column_name"]
                data_type = col_meta["data_type"]
                sample_result = table_samples[column_name]

                classification = PIIClassifier.classify_column(
                    column_name=column_name,
                    data_type=data_type,
                    samples=sample_result["samples"],
                )

                inferred_type = classification["inferred_pii_type"]
                embedded_types = classification["embedded_pii_types"]
                risk_level = classification["risk_level"]

                if inferred_type != "NONE":
                    pii_columns_detected += 1
                if embedded_types:
                    embedded_pii_columns_detected += 1
                risk_breakdown[risk_level] = risk_breakdown.get(risk_level, 0) + 1

                # Idempotent Upsert (updates existing findings on re-scan)
                stmt = pg_insert(ColumnInventory).values(
                    source_id=source.id,
                    schema_name=schema_name,
                    table_name=table_name,
                    column_name=column_name,
                    data_type=data_type,
                    inferred_pii_type=inferred_type,
                    embedded_pii_types=embedded_types,
                    confidence=classification["confidence"],
                    match_ratio=classification["match_ratio"],
                    embedded_match_ratio=classification["embedded_match_ratio"],
                    embedded_confidence=classification["embedded_confidence"],
                    risk_level=risk_level,
                    sample_size=sample_result["sample_size"],
                    null_count=sample_result["null_count"],
                    masked_evidence=classification["masked_evidence"],
                    justification=classification["justification"],
                    updated_at=now_utc,
                )
                stmt = stmt.on_conflict_do_update(
                    constraint="uq_source_schema_table_column",
                    set_={
                        "data_type": stmt.excluded.data_type,
                        "inferred_pii_type": stmt.excluded.inferred_pii_type,
                        "embedded_pii_types": stmt.excluded.embedded_pii_types,
                        "confidence": stmt.excluded.confidence,
                        "match_ratio": stmt.excluded.match_ratio,
                        "embedded_match_ratio": stmt.excluded.embedded_match_ratio,
                        "embedded_confidence": stmt.excluded.embedded_confidence,
                        "risk_level": stmt.excluded.risk_level,
                        "sample_size": stmt.excluded.sample_size,
                        "null_count": stmt.excluded.null_count,
                        "masked_evidence": stmt.excluded.masked_evidence,
                        "justification": stmt.excluded.justification,
                        "updated_at": stmt.excluded.updated_at,
                    },
                )
                current_ids.append(db.execute(stmt.returning(ColumnInventory.id)).scalar_one())

        cleanup = delete(ColumnInventory).where(ColumnInventory.source_id == source.id)
        if current_ids:
            cleanup = cleanup.where(ColumnInventory.id.not_in(current_ids))
        db.execute(cleanup)
        source.last_scanned_at = now_utc
        db.commit()

        return ScanSummaryResponse(
            source_id=source.id,
            scanned_at=now_utc,
            total_columns_scanned=len(discovered_columns),
            pii_columns_detected=pii_columns_detected,
            embedded_pii_columns_detected=embedded_pii_columns_detected,
            risk_breakdown=risk_breakdown,
        )
    except HTTPException:
        db.rollback()
        raise
    except OperationalError as exc:
        db.rollback()
        if getattr(exc.orig, "sqlstate", None) == "55P03":
            raise HTTPException(
                status_code=409, detail=f"Source {source_id} is already being scanned. Retry after it finishes."
            ) from None
        raise HTTPException(
            status_code=500, detail=f"Scan failed for source {source_id}. Scan results were not saved."
        ) from None
    except SourceScanError as exc:
        db.rollback()
        raise HTTPException(
            status_code=502,
            detail=f"Source {source_id}: {exc} Scan results were not saved.",
        ) from None
    except ConnectionError:
        db.rollback()
        raise HTTPException(
            status_code=502,
            detail=f"Could not connect to target source {source_id}. Scan results were not saved.",
        ) from None
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed for source {source_id}. Scan results were not saved.",
        ) from None
    finally:
        if connector is not None:
            connector.engine.dispose()


@router.get(
    "/sources/{source_id}/inventory",
    response_model=InventoryReportResponse,
    summary="Get classified column inventory for a source",
)
def get_source_inventory(
    source_id: int,
    risk_level: str | None = Query(
        default=None, description="Filter by risk level (CRITICAL, HIGH, MEDIUM, LOW, NONE)"
    ),
    pii_type: str | None = Query(
        default=None, description="Filter by inferred PII type (e.g. PAN, PHONE_IN, EMAIL)"
    ),
    db: Session = Depends(get_db),
) -> InventoryReportResponse:
    source = db.get(Source, source_id)
    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source {source_id} not found.",
        )

    query = select(ColumnInventory).where(ColumnInventory.source_id == source_id)
    if risk_level:
        query = query.where(ColumnInventory.risk_level == risk_level.upper())
    if pii_type:
        query = query.where(ColumnInventory.inferred_pii_type == pii_type.upper())

    query = query.order_by(
        ColumnInventory.table_name.asc(), ColumnInventory.id.asc()
    )
    cols = db.scalars(query).all()

    return InventoryReportResponse(
        source_id=source.id,
        source_name=source.name,
        last_scanned_at=source.last_scanned_at,
        total_columns=len(cols),
        columns=[ColumnInventoryResponse.model_validate(c) for c in cols],
    )


@router.get(
    "/columns/{column_id}",
    response_model=ColumnInventoryResponse,
    summary="Inspect a single column finding in detail",
)
def get_column_detail(
    column_id: int, db: Session = Depends(get_db)
) -> ColumnInventoryResponse:
    col = db.get(ColumnInventory, column_id)
    if not col:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Column inventory record {column_id} not found.",
        )
    return ColumnInventoryResponse.model_validate(col)
