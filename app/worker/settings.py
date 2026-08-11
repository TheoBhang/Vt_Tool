import os
from datetime import timedelta

from arq.connections import RedisSettings

from app.DataHandler.validator import DataValidator
from app.cache_backends.sqlalchemy_backend import SQLAlchemyCacheBackend
from app.cache_backends.sqlite_backend import SQLiteCacheBackend
from app.services.cache_service import DEFAULT_TTL_HOURS, ReportCacheService
from app.services.validation_service import ValidationService
from app.worker.tasks import analyze_value

DATABASE_FILE = "vttools.sqlite"


async def startup(ctx: dict) -> None:
    """Builds the shared ValidationService/ReportCacheService once per worker
    process - reads VT_CACHE_DB_URL/VT_CACHE_TTL_HOURS the same way init.py
    does for the CLI, so the worker's cache configuration always matches."""
    db_url = os.getenv("VT_CACHE_DB_URL")
    cache_backend = SQLAlchemyCacheBackend(db_url) if db_url else SQLiteCacheBackend(DATABASE_FILE)
    cache_ttl = timedelta(hours=float(os.getenv("VT_CACHE_TTL_HOURS", str(DEFAULT_TTL_HOURS))))
    ctx["validation"] = ValidationService(DataValidator())
    ctx["cache"] = ReportCacheService(cache_backend, ttl=cache_ttl)


async def shutdown(ctx: dict) -> None:
    ctx["cache"].backend.close()


class WorkerSettings:
    functions = [analyze_value]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(os.getenv("REDIS_URL", "redis://localhost:6379"))
