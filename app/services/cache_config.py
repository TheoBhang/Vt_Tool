import os
from datetime import timedelta

from app.cache_backends.sqlalchemy_backend import SQLAlchemyCacheBackend
from app.cache_backends.sqlite_backend import SQLiteCacheBackend
from app.services.cache_service import DEFAULT_TTL_HOURS, ReportCacheService

DEFAULT_DATABASE_FILE = "vttools.sqlite"


def build_cache_service() -> ReportCacheService:
    """Builds a ReportCacheService from VT_CACHE_DB_URL/VT_CACHE_TTL_HOURS -
    the same environment-driven cache configuration every entrypoint (CLI,
    API, worker) needs. Single source of truth for this wiring, read fresh
    on every call rather than cached at import time, so callers that need
    per-instantiation env reads (tests using mock.patch.dict) see overrides
    take effect."""
    db_url = os.getenv("VT_CACHE_DB_URL")
    backend = SQLAlchemyCacheBackend(db_url) if db_url else SQLiteCacheBackend(DEFAULT_DATABASE_FILE)
    ttl_hours_env = os.getenv("VT_CACHE_TTL_HOURS")
    ttl = timedelta(hours=float(ttl_hours_env) if ttl_hours_env else DEFAULT_TTL_HOURS)
    return ReportCacheService(backend, ttl=ttl)
