"""Use TEST_SOURCE_DATABASE_URL pointing to the disposable seeded demo reader."""
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from app.services.classifier import PIIClassifier
from app.services.connector import TargetDBConnector


@pytest.fixture
def reader_url():
    url = os.getenv("TEST_SOURCE_DATABASE_URL")
    if not url:
        pytest.skip("Set TEST_SOURCE_DATABASE_URL for demo-reader permission tests")
    return url


def test_reader_has_no_administrative_or_source_write_privileges(reader_url):
    engine = create_engine(reader_url)
    try:
        with engine.connect() as connection:
            row = connection.execute(text(
                "SELECT current_user, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolinherit "
                "FROM pg_roles WHERE rolname = current_user"
            )).one()
            assert row[0] == "discovery_reader"
            assert not any(row[1:])
            for privilege in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
                assert not connection.execute(text(
                    "SELECT has_table_privilege(current_user, 'public.customers', :privilege)"
                ), {"privilege": privilege}).scalar_one()
            for privilege in ("CREATE", "TEMP"):
                assert not connection.execute(text(
                    "SELECT has_database_privilege(current_user, current_database(), :privilege)"
                ), {"privilege": privilege}).scalar_one()
    finally:
        engine.dispose()


@pytest.mark.parametrize("statement", [
    "UPDATE public.customers SET full_name = full_name WHERE false",
    "DELETE FROM public.customers WHERE false",
    "INSERT INTO public.customers SELECT * FROM public.customers WHERE false",
    "CREATE TABLE public.reader_probe_{suffix} (id integer)",
])
def test_reader_cannot_write_even_with_readonly_default_disabled(reader_url, statement):
    engine = create_engine(reader_url)
    try:
        with engine.connect() as connection:
            connection.execute(text("SET default_transaction_read_only = off"))
            connection.commit()
            with pytest.raises(DBAPIError) as error:
                connection.execute(text(statement.format(suffix=uuid4().hex)))
            assert error.value.orig.sqlstate == "42501"
            connection.rollback()
    finally:
        engine.dispose()


def test_real_reader_can_discover_sample_and_classify_seed(reader_url):
    target = TargetDBConnector(reader_url)
    try:
        assert target.verify_connection()
        columns = target.discover_schema()
        assert len(columns) == 26
        tables = {}
        for column in columns:
            tables.setdefault((column["schema_name"], column["table_name"]), []).append(column)
        results = {}
        for (schema, table), table_columns in tables.items():
            samples = target.sample_table_values(schema, table, [c["column_name"] for c in table_columns])
            for column in table_columns:
                name = column["column_name"]
                results[(table, name)] = PIIClassifier.classify_column(name, column["data_type"], samples[name]["samples"])
        assert results[("customers", "email_address")]["inferred_pii_type"] == "EMAIL"
        assert results[("customers", "date_of_birth")]["inferred_pii_type"] == "DOB"
        assert results[("customers", "pincode")]["inferred_pii_type"] == "PINCODE"
        assert results[("support_tickets", "ticket_body")]["embedded_pii_types"] == ["AADHAAR", "EMAIL", "PAN", "PHONE_IN"]
    finally:
        target.engine.dispose()
