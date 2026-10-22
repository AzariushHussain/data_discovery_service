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


@pytest.mark.parametrize("stage", ["connect", "samples", "iteration"])
def test_sampling_failures_are_not_empty_successes(target, database_error, stage):
    connection = target.engine.connect.return_value.__enter__.return_value
    if stage == "connect":
        target.engine.connect.side_effect = database_error
    elif stage == "samples":
        connection.execute.side_effect = database_error
    else:
        def interrupted_rows():
            yield ("private-value",)
            raise database_error
        connection.execute.return_value = interrupted_rows()

    with pytest.raises(SourceScanError) as error:
        target.sample_table_values("public", "customers", ["email"])
    assert_sanitized(error, "Target table sampling failed.")


def test_successful_empty_column_is_still_a_valid_result(target):
    connection = target.engine.connect.return_value.__enter__.return_value
    connection.execute.return_value = [(None,), ("",), ("  ",)]
    assert target.sample_table_values("public", "customers", ["email"]) == {
        "email": {"samples": [], "sample_size": 0, "null_count": 3},
    }
    connection.execute.assert_called_once()


def test_sampling_quotes_identifiers_and_binds_limit(target):
    connection = target.engine.connect.return_value.__enter__.return_value
    connection.execute.return_value = [("a@example.com",)]
    result = target.sample_table_values('odd"schema', 'odd"table', ['odd"column'], limit=7)
    statement, params = connection.execute.call_args.args
    assert '"odd""schema"."odd""table"' in str(statement)
    assert '"odd""column"' in str(statement)
    assert params == {"limit": 7}
    assert result['odd"column']["samples"] == ["a@example.com"]
    connection.execute.assert_called_once()


def test_table_sampling_uses_one_row_set_without_full_counts_or_nonblank_search(target):
    connection = target.engine.connect.return_value.__enter__.return_value
    connection.execute.return_value = [
        ("a@example.com", None, 123),
        (None, "9876543210", 456),
        (" ", "", None),
    ]
    result = target.sample_table_values("public", "customers", ["email", "phone", "number"], limit=3)
    connection.execute.assert_called_once()
    statement, params = connection.execute.call_args.args
    assert 'SELECT "email", "phone", "number"' in str(statement)
    assert "COUNT" not in str(statement)
    assert "WHERE" not in str(statement)
    assert "LIMIT :limit" in str(statement)
    assert params == {"limit": 3}
    assert result == {
        "email": {"samples": ["a@example.com"], "sample_size": 1, "null_count": 2},
        "phone": {"samples": ["9876543210"], "sample_size": 1, "null_count": 2},
        "number": {"samples": ["123", "456"], "sample_size": 2, "null_count": 1},
    }


def test_empty_table_has_zero_sampled_nulls(target):
    connection = target.engine.connect.return_value.__enter__.return_value
    connection.execute.return_value = []
    assert target.sample_table_values("public", "empty", ["email"]) == {
        "email": {"samples": [], "sample_size": 0, "null_count": 0},
    }


@pytest.mark.parametrize("limit,columns", [(0, ["email"]), (-1, ["email"]), (10, [])])
def test_invalid_sampling_bounds_do_not_query_source(target, limit, columns):
    with pytest.raises(ValueError):
        target.sample_table_values("public", "customers", columns, limit=limit)
    target.engine.connect.assert_not_called()
