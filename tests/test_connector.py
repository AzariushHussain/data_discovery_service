import traceback
from unittest.mock import MagicMock, Mock

import pytest
from psycopg.errors import InsufficientPrivilege, QueryCanceled
from sqlalchemy.dialects.postgresql import dialect
from sqlalchemy.exc import DBAPIError

from app.services import connector as connector_module
from app.services.connector import SourceScanError, TargetDBConnector


@pytest.fixture
def target():
    target = TargetDBConnector.__new__(TargetDBConnector)
    target.engine = MagicMock()
    target.engine.dialect = dialect()
    return target


@pytest.fixture(params=[InsufficientPrivilege, QueryCanceled], ids=["permission", "timeout"])
def database_error(request):
    return DBAPIError("SELECT private_value", {}, request.param("private-password-and-PII"))


def assert_sanitized(error, message):
    assert str(error.value) == message
    rendered = "".join(traceback.format_exception(error.type, error.value, error.tb))
    assert "private-password-and-PII" not in rendered
    assert "SELECT private_value" not in rendered


def test_connection_failure_is_sanitized(target, database_error):
    target.engine.connect.side_effect = database_error
    with pytest.raises(ConnectionError) as error:
        target.verify_connection()
    assert_sanitized(error, "Target database connection failed.")


@pytest.mark.parametrize("stage", ["inspect", "schemas", "tables", "columns"])
def test_schema_failures_are_not_silently_skipped(monkeypatch, target, database_error, stage):
    inspector = Mock()
    inspector.get_schema_names.return_value = ["public"]
    inspector.get_table_names.return_value = ["customers", "orders"]
    inspector.get_columns.return_value = [{"name": "email", "type": "TEXT"}]
    inspect_mock = Mock(return_value=inspector)
    monkeypatch.setattr(connector_module, "inspect", inspect_mock)
    if stage == "inspect":
        inspect_mock.side_effect = database_error
    elif stage == "schemas":
        inspector.get_schema_names.side_effect = database_error
    elif stage == "tables":
        inspector.get_table_names.side_effect = database_error
    else:
        # Discovery must fail even after metadata from one table was collected.
        inspector.get_columns.side_effect = [inspector.get_columns.return_value, database_error]
    with pytest.raises(SourceScanError) as error:
        target.discover_schema()
    assert_sanitized(error, "Target schema discovery failed.")


@pytest.mark.parametrize("stage", ["connect", "null_count", "samples", "iteration"])
def test_sampling_failures_are_not_empty_successes(target, database_error, stage):
    connection = target.engine.connect.return_value.__enter__.return_value
    count_result = Mock()
    count_result.scalar.return_value = 0
    if stage == "connect":
        target.engine.connect.side_effect = database_error
    elif stage == "null_count":
        connection.execute.side_effect = database_error
    elif stage == "samples":
        connection.execute.side_effect = [count_result, database_error]
    else:
        def interrupted_rows():
            yield ("private-value",)
            raise database_error
        connection.execute.side_effect = [count_result, interrupted_rows()]

    with pytest.raises(SourceScanError) as error:
        target.sample_column_values("public", "customers", "email")
    assert_sanitized(error, "Target column sampling failed.")


def test_successful_empty_column_is_still_a_valid_result(target):
    connection = target.engine.connect.return_value.__enter__.return_value
    count_result = Mock()
    count_result.scalar.return_value = 3
    connection.execute.side_effect = [count_result, []]
    assert target.sample_column_values("public", "customers", "email") == {
        "samples": [], "sample_size": 0, "null_count": 3,
    }


def test_sampling_quotes_identifiers_and_binds_limit(target):
    connection = target.engine.connect.return_value.__enter__.return_value
    count_result = Mock()
    count_result.scalar.return_value = 0
    connection.execute.side_effect = [count_result, [("a@example.com",)]]
    result = target.sample_column_values('odd"schema', 'odd"table', 'odd"column', limit=7)
    statement, params = connection.execute.call_args.args
    assert '"odd""schema"."odd""table"' in str(statement)
    assert '"odd""column"' in str(statement)
    assert params == {"limit": 7}
    assert result["samples"] == ["a@example.com"]
