from typing import Any
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from app.config import settings


class SourceScanError(RuntimeError):
    """A sanitized target discovery or sampling failure."""


class TargetDBConnector:
    """Safely connects to external target databases to inspect schemas and sample column data."""

    def __init__(self, dsn: str):
        # Enforce read-only and strict timeouts on the external target connection
        self.dsn = dsn
        self.engine: Engine = create_engine(
            dsn,
            pool_pre_ping=True,
            connect_args={
                "options": f"-c default_transaction_read_only=on -c statement_timeout={settings.STATEMENT_TIMEOUT_MS}",
                "connect_timeout": settings.CONNECT_TIMEOUT_SEC,
            },
        )

    def verify_connection(self) -> bool:
        """Verify that the DSN is valid and the target database is reachable."""
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except SQLAlchemyError:
            raise ConnectionError("Target database connection failed.") from None

    def discover_schema(self) -> list[dict[str, Any]]:
        """Inspects all tables and columns across non-system schemas."""
        column_inventory_metadata = []

        # Exclude system schemas
        excluded_schemas = {"pg_catalog", "information_schema", "pg_toast"}
        try:
            inspector = inspect(self.engine)
            schemas = [
                s for s in inspector.get_schema_names() if s not in excluded_schemas
            ]
            for schema in schemas:
                for table_name in inspector.get_table_names(schema=schema):
                    columns = inspector.get_columns(table_name, schema=schema)
                    for col in columns:
                        column_inventory_metadata.append(
                            {
                                "schema_name": schema,
                                "table_name": table_name,
                                "column_name": col["name"],
                                "data_type": str(col["type"]),
                            }
                        )
        except SQLAlchemyError:
            raise SourceScanError("Target schema discovery failed.") from None

        return column_inventory_metadata

    def sample_table_values(
        self, schema_name: str, table_name: str, column_names: list[str], limit: int = 200
    ) -> dict[str, dict[str, Any]]:
        """Read one bounded row sample; count nulls/blanks only within those rows."""
        if limit <= 0 or not column_names:
            raise ValueError("Sampling requires a positive limit and at least one column.")
        quote = self.engine.dialect.identifier_preparer.quote_identifier
        safe_schema = quote(schema_name)
        safe_table = quote(table_name)
        safe_columns = ", ".join(quote(name) for name in column_names)
        query = text(
            f"SELECT {safe_columns} FROM {safe_schema}.{safe_table} LIMIT :limit"
        )
        sampled = {
            name: {"samples": [], "sample_size": 0, "null_count": 0}
            for name in column_names
        }
        try:
            with self.engine.connect() as conn:
                result = conn.execute(query, {"limit": limit})
                for row in result:
                    for name, val in zip(column_names, row):
                        if val is None or not str(val).strip():
                            sampled[name]["null_count"] += 1
                        else:
                            sampled[name]["samples"].append(str(val))
        except SQLAlchemyError:
            raise SourceScanError("Target table sampling failed.") from None
        for column in sampled.values():
            column["sample_size"] = len(column["samples"])
        return sampled
