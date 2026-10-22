"""PostgreSQL rollback tests; enable with TEST_DATABASE_URL."""
from datetime import datetime, timezone
import os
from uuid import uuid4
from unittest.mock import Mock

from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.schema import CreateSchema, CreateTable, DropSchema

from app.api import routes
from app.db.models import ColumnInventory, Source
from app.db.session import get_db
from app.main import app
from app.services.connector import SourceScanError
from app.services.connector import TargetDBConnector


PREVIOUS_SCAN = datetime(2020, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def scan_database():
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set TEST_DATABASE_URL to run PostgreSQL transaction tests")
    base_engine = create_engine(url)
    schema = f"test_scan_{uuid4().hex}"
    try:
        with base_engine.begin() as conn:
            conn.execute(CreateSchema(schema))
        engine = base_engine.execution_options(schema_translate_map={None: schema})
        with engine.begin() as conn:
            conn.execute(CreateTable(Source.__table__))
            conn.execute(CreateTable(ColumnInventory.__table__))
        sessions = sessionmaker(bind=engine)
        with sessions.begin() as db:
            source = Source(id=1, name="Test source", secret_path="sources/test", last_scanned_at=PREVIOUS_SCAN)
            db.add(source)
            db.flush()
            db.add(ColumnInventory(
                source_id=1, schema_name="public", table_name="customers",
                column_name="email_address", data_type="TEXT", inferred_pii_type="NONE",
                risk_level="NONE", justification="Previous completed scan", updated_at=PREVIOUS_SCAN,
            ))
        yield sessions
    finally:
        with base_engine.begin() as conn:
            conn.execute(DropSchema(schema, cascade=True, if_exists=True))
        base_engine.dispose()


def configure_scan(monkeypatch, sessions, failure):
    target = Mock()
    columns = ["email_address", "new_phone"]
    if failure in {"sample", "classify"}:
        columns.append("blocked")
    target.discover_schema.return_value = [
        {"schema_name": "public", "table_name": "blocked_table" if name == "blocked" else "customers", "column_name": name, "data_type": "TEXT"}
        for name in columns
    ]
    if failure == "connect":
        target.verify_connection.side_effect = ConnectionError("private-password-and-PII")
    if failure == "discover":
        target.discover_schema.side_effect = SourceScanError("Target schema discovery failed.")

    def sample(**kwargs):
        if failure == "sample" and "blocked" in kwargs["column_names"]:
            raise SourceScanError("Target table sampling failed.")
        return {
            name: {"samples": ["a@example.com"], "sample_size": 1, "null_count": 0}
            for name in kwargs["column_names"]
        }
    target.sample_table_values.side_effect = sample
    monkeypatch.setattr(routes, "TargetDBConnector", Mock(return_value=target))

    def source_dsn(source):
        if failure == "secret":
            raise HTTPException(status_code=503, detail="Could not retrieve source credentials.")
        return "postgresql+psycopg://dummy:dummy@unused/test"
    monkeypatch.setattr(routes, "_get_source_dsn", source_dsn)
    original_classify = routes.PIIClassifier.classify_column
    if failure == "classify":
        def classify(**kwargs):
            if kwargs["column_name"] == "blocked":
                raise ValueError("private-password-and-PII")
            return original_classify(**kwargs)
        monkeypatch.setattr(routes.PIIClassifier, "classify_column", classify)

    def database():
        with sessions() as db:
            if failure == "commit":
                monkeypatch.setattr(db, "commit", Mock(side_effect=SQLAlchemyError("private-password-and-PII")))
            yield db
    return target, database


@pytest.mark.parametrize(
    "failure,status",
    [("connect", 502), ("discover", 502), ("sample", 502),
     ("classify", 500), ("commit", 500), ("secret", 503)],
)
def test_failed_scan_preserves_previous_inventory_and_timestamp(monkeypatch, scan_database, failure, status):
    target, database = configure_scan(monkeypatch, scan_database, failure)
    app.dependency_overrides[get_db] = database
    try:
        with TestClient(app) as client:
            response = client.post("/sources/1/scan")
        assert response.status_code == status
        assert "private-password-and-PII" not in response.text
        with scan_database() as db:
            rows = db.scalars(select(ColumnInventory)).all()
            assert len(rows) == 1
            assert rows[0].inferred_pii_type == "NONE"
            assert rows[0].justification == "Previous completed scan"
            assert rows[0].updated_at == PREVIOUS_SCAN
            assert db.get(Source, 1).last_scanned_at == PREVIOUS_SCAN
        if failure != "secret":
            target.engine.dispose.assert_called_once()
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_successful_scan_commits_all_findings_and_timestamp(monkeypatch, scan_database):
    target, database = configure_scan(monkeypatch, scan_database, None)
    app.dependency_overrides[get_db] = database
    try:
        with TestClient(app) as client:
            response = client.post("/sources/1/scan")
        assert response.status_code == 200
        assert response.json()["total_columns_scanned"] == 2
        target.sample_table_values.assert_called_once_with(
            schema_name="public", table_name="customers",
            column_names=["email_address", "new_phone"], limit=routes.settings.SAMPLE_LIMIT,
        )
        with scan_database() as db:
            rows = db.scalars(select(ColumnInventory)).all()
            assert len(rows) == 2
            assert all(row.inferred_pii_type == "EMAIL" for row in rows)
            assert all(row.updated_at > PREVIOUS_SCAN for row in rows)
            assert db.get(Source, 1).last_scanned_at > PREVIOUS_SCAN
        target.engine.dispose.assert_called_once()
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_real_table_sampling_bounds_rows_and_counts_only_sampled_nulls(scan_database):
    with scan_database() as db:
        engine = db.get_bind()
    schema = engine.get_execution_options()["schema_translate_map"][None]
    safe_schema = engine.dialect.identifier_preparer.quote_identifier(schema)
    with engine.begin() as connection:
        connection.execute(text(f'CREATE TABLE {safe_schema}.sample_values (empty_col TEXT, phone TEXT)'))
        connection.execute(text(
            f"INSERT INTO {safe_schema}.sample_values "
            "SELECT NULL, '9876543210' FROM generate_series(1, 50)"
        ))
    statements = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        target = TargetDBConnector.__new__(TargetDBConnector)
        target.engine = engine
        result = target.sample_table_values(schema, "sample_values", ["empty_col", "phone"], limit=3)
    finally:
        event.remove(engine, "before_cursor_execute", record)
    assert len(statements) == 1
    assert "COUNT" not in statements[0]
    assert result == {
        "empty_col": {"samples": [], "sample_size": 0, "null_count": 3},
        "phone": {"samples": ["9876543210"] * 3, "sample_size": 3, "null_count": 0},
    }


def add_stale_and_other_source(sessions):
    with sessions.begin() as db:
        db.add(Source(id=2, name="Other source", secret_path="sources/other"))
        db.flush()
        db.add_all([
            ColumnInventory(source_id=1, schema_name="public", table_name="retired_table",
                            column_name="old_phone", data_type="TEXT", updated_at=PREVIOUS_SCAN),
            ColumnInventory(source_id=2, schema_name="public", table_name="retired_table",
                            column_name="old_phone", data_type="TEXT", updated_at=PREVIOUS_SCAN),
        ])


def test_successful_rescan_removes_stale_rows_only_for_scanned_source(monkeypatch, scan_database):
    add_stale_and_other_source(scan_database)
    target, database = configure_scan(monkeypatch, scan_database, None)
    app.dependency_overrides[get_db] = database
    try:
        with TestClient(app) as client:
            response = client.post("/sources/1/scan")
        assert response.status_code == 200
        with scan_database() as db:
            current = db.scalars(select(ColumnInventory).where(ColumnInventory.source_id == 1)).all()
            assert {row.column_name for row in current} == {"email_address", "new_phone"}
            assert next(row.id for row in current if row.column_name == "email_address") == 1
            other = db.scalars(select(ColumnInventory).where(ColumnInventory.source_id == 2)).all()
            assert len(other) == 1 and other[0].column_name == "old_phone"
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_renamed_column_is_new_finding_and_old_id_is_removed(monkeypatch, scan_database):
    target, database = configure_scan(monkeypatch, scan_database, None)
    target.discover_schema.return_value = [
        {"schema_name": "public", "table_name": "customers", "column_name": "contact_email", "data_type": "TEXT"},
    ]
    app.dependency_overrides[get_db] = database
    try:
        with TestClient(app) as client:
            assert client.post("/sources/1/scan").status_code == 200
            assert client.get("/columns/1").status_code == 404
        with scan_database() as db:
            rows = db.scalars(select(ColumnInventory)).all()
            assert len(rows) == 1
            assert rows[0].column_name == "contact_email" and rows[0].id != 1
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_successful_empty_discovery_clears_only_that_source_inventory(monkeypatch, scan_database):
    add_stale_and_other_source(scan_database)
    target, database = configure_scan(monkeypatch, scan_database, None)
    target.discover_schema.return_value = []
    app.dependency_overrides[get_db] = database
    try:
        with TestClient(app) as client:
            response = client.post("/sources/1/scan")
        assert response.status_code == 200
        assert response.json()["total_columns_scanned"] == 0
        target.sample_table_values.assert_not_called()
        with scan_database() as db:
            assert db.scalars(select(ColumnInventory).where(ColumnInventory.source_id == 1)).all() == []
            assert len(db.scalars(select(ColumnInventory).where(ColumnInventory.source_id == 2)).all()) == 1
            assert db.get(Source, 1).last_scanned_at > PREVIOUS_SCAN
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_commit_failure_restores_stale_rows_deleted_in_pending_scan(monkeypatch, scan_database):
    add_stale_and_other_source(scan_database)
    target, database = configure_scan(monkeypatch, scan_database, "commit")
    app.dependency_overrides[get_db] = database
    try:
        with TestClient(app) as client:
            response = client.post("/sources/1/scan")
        assert response.status_code == 500
        with scan_database() as db:
            rows = db.scalars(select(ColumnInventory).where(ColumnInventory.source_id == 1)).all()
            assert {row.column_name for row in rows} == {"email_address", "old_phone"}
            assert all(row.updated_at == PREVIOUS_SCAN for row in rows)
            assert db.get(Source, 1).last_scanned_at == PREVIOUS_SCAN
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_overlapping_scan_is_rejected_but_different_source_can_scan(monkeypatch, scan_database):
    add_stale_and_other_source(scan_database)
    target, database = configure_scan(monkeypatch, scan_database, None)
    app.dependency_overrides[get_db] = database
    try:
        with scan_database() as active:
            active.scalar(select(Source).where(Source.id == 1).with_for_update())
            with TestClient(app) as client:
                response = client.post("/sources/1/scan")
                assert response.status_code == 409
                target.verify_connection.assert_not_called()
                assert client.post("/sources/2/scan").status_code == 200
        with scan_database() as db:
            assert db.get(Source, 1).last_scanned_at == PREVIOUS_SCAN
            assert db.get(Source, 2).last_scanned_at > PREVIOUS_SCAN
    finally:
        app.dependency_overrides.pop(get_db, None)
