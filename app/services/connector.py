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

    def sample_column_values(
        self, schema_name: str, table_name: str, column_name: str, limit: int = 200
    ) -> dict[str, Any]:
        """Samples up to `limit` non-null values from a specific table column securely."""
        # Quote identifiers safely to prevent SQL injection vulnerabilities
        quote = self.engine.dialect.identifier_preparer.quote_identifier
        safe_schema = quote(schema_name)
        safe_table = quote(table_name)
        safe_column = quote(column_name)

        query = text(
            f"SELECT {safe_column} FROM {safe_schema}.{safe_table} "
            f"WHERE {safe_column} IS NOT NULL AND TRIM(CAST({safe_column} AS TEXT)) != '' "
            f"LIMIT :limit"
        )

        samples: list[str] = []
        null_count = 0

        try:
            with self.engine.connect() as conn:
                # Count total nulls first
                null_query = text(
                    f"SELECT COUNT(*) FROM {safe_schema}.{safe_table} "
                    f"WHERE {safe_column} IS NULL OR TRIM(CAST({safe_column} AS TEXT)) = ''"
                )
                null_count = conn.execute(null_query).scalar() or 0

                # Fetch bounded non-null samples
                result = conn.execute(query, {"limit": limit})
                for row in result:
                    val = row[0]
                    if val is not None:
                        samples.append(str(val))
        except SQLAlchemyError:
            raise SourceScanError("Target column sampling failed.") from None

        return {
            "samples": samples,
            "sample_size": len(samples),
            "null_count": null_count,
        }
