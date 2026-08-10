import json
from collections.abc import Mapping
from datetime import datetime, timezone

import sqlalchemy
from sqlalchemy.exc import IntegrityError


class SQLAlchemyCacheBackend:
    """SQLAlchemy Core implementation of the report-cache backend: same
    contract as SQLiteCacheBackend, but works against any SQL database
    SQLAlchemy supports via a connection URL. No report-shaping logic here -
    that's VirusTotalService's job alone, same as SQLiteCacheBackend."""

    def __init__(self, db_url: str):
        self.engine = sqlalchemy.create_engine(db_url)
        self.metadata = sqlalchemy.MetaData()
        self.table = sqlalchemy.Table(
            "cached_reports",
            self.metadata,
            sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
            sqlalchemy.Column("value_type", sqlalchemy.String, nullable=False),
            sqlalchemy.Column("value", sqlalchemy.String, nullable=False),
            sqlalchemy.Column("report_json", sqlalchemy.Text, nullable=False),
            sqlalchemy.Column("cached_at", sqlalchemy.String, nullable=False),
            sqlalchemy.UniqueConstraint("value_type", "value", name="uq_value_type_value"),
        )
        self.metadata.create_all(self.engine)

    def get(self, value_type: str, value: str) -> tuple[dict, str] | None:
        stmt = sqlalchemy.select(self.table.c.report_json, self.table.c.cached_at).where(
            self.table.c.value_type == value_type,
            self.table.c.value == value,
        )
        with self.engine.connect() as conn:
            row = conn.execute(stmt).fetchone()
        if row is None:
            return None
        report_json, cached_at = row
        return json.loads(report_json), cached_at

    def set(self, value_type: str, value: str, report: dict) -> None:
        cached_at = datetime.now(timezone.utc).isoformat()
        report_json = json.dumps(
            report,
            default=lambda o: dict(o) if isinstance(o, Mapping) else str(o),
        )
        try:
            with self.engine.begin() as conn:
                conn.execute(
                    self.table.insert().values(
                        value_type=value_type,
                        value=value,
                        report_json=report_json,
                        cached_at=cached_at,
                    )
                )
        except IntegrityError:
            # engine.begin()'s context manager already rolled back and closed
            # the failed connection when the exception propagated out of the
            # `with` block above, so this starts a fresh connection/transaction
            # rather than reusing one that may be in an aborted state.
            with self.engine.begin() as conn:
                conn.execute(
                    self.table.update()
                    .where(
                        self.table.c.value_type == value_type,
                        self.table.c.value == value,
                    )
                    .values(report_json=report_json, cached_at=cached_at)
                )

    def close(self) -> None:
        self.engine.dispose()
