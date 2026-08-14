from arq.connections import RedisSettings

from app.DataHandler.utils import get_env
from app.DataHandler.validator import DataValidator
from app.services.cache_config import build_cache_service
from app.services.validation_service import ValidationService
from app.worker.tasks import analyze_value


async def startup(ctx: dict) -> None:
    """Builds the shared ValidationService/ReportCacheService once per worker
    process - reads VT_CACHE_DB_URL/VT_CACHE_TTL_HOURS the same way init.py
    does for the CLI, so the worker's cache configuration always matches."""
    ctx["validation"] = ValidationService(DataValidator())
    ctx["cache"] = build_cache_service()


async def shutdown(ctx: dict) -> None:
    ctx["cache"].backend.close()


class WorkerSettings:
    functions = [analyze_value]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(get_env("REDIS_URL", "redis://localhost:6379"))
