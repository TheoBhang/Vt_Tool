import os
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Literal

from arq import create_pool
from arq.connections import RedisSettings
from arq.jobs import Job, JobStatus
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from app.DataHandler.validator import DataValidator
from app.cache_backends.sqlalchemy_backend import SQLAlchemyCacheBackend
from app.cache_backends.sqlite_backend import SQLiteCacheBackend
from app.services.analysis_service import UNSUPPORTED_VALUE_TYPES
from app.services.cache_service import DEFAULT_TTL_HOURS, ReportCacheService
from app.services.validation_service import ValidationService

DATABASE_FILE = "vttools.sqlite"


def _build_cache() -> ReportCacheService:
    db_url = os.getenv("VT_CACHE_DB_URL")
    cache_backend = SQLAlchemyCacheBackend(db_url) if db_url else SQLiteCacheBackend(DATABASE_FILE)
    cache_ttl = timedelta(hours=float(os.getenv("VT_CACHE_TTL_HOURS", str(DEFAULT_TTL_HOURS))))
    return ReportCacheService(cache_backend, ttl=cache_ttl)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.validation = ValidationService(DataValidator())
    app.state.cache = _build_cache()
    app.state.redis = await create_pool(
        RedisSettings.from_dsn(os.getenv("REDIS_URL", "redis://localhost:6379"))
    )
    yield
    app.state.cache.backend.close()
    await app.state.redis.aclose()


app = FastAPI(lifespan=lifespan)


class AnalyzeItem(BaseModel):
    value: str
    value_type: Literal["ips", "domains", "urls", "hashes"]


class AnalyzeRequest(BaseModel):
    values: list[AnalyzeItem]
    api_key: str
    proxy: str | None = None


@app.post("/analyze")
async def analyze(payload: AnalyzeRequest, request: Request):
    validation: ValidationService = request.app.state.validation
    cache: ReportCacheService = request.app.state.cache
    redis = request.app.state.redis

    results = []
    for item in payload.values:
        cached = cache.get(item.value_type, item.value)
        if cached is not None:
            results.append({"status": "hit", "report": cached})
            continue

        classification = validation.classify(item.value, item.value_type)
        if not classification or classification in UNSUPPORTED_VALUE_TYPES:
            results.append({
                "status": "invalid",
                "error": f"Unsupported or invalid {item.value_type[:-1]}: {item.value}",
            })
            continue

        job = await redis.enqueue_job(
            "analyze_value", item.value, item.value_type, payload.api_key, payload.proxy
        )
        results.append({"status": "queued", "job_id": job.job_id})

    return results


@app.get("/jobs/{job_id}")
async def get_job(job_id: str, request: Request):
    redis = request.app.state.redis
    job = Job(job_id, redis=redis)
    status = await job.status()

    if status == JobStatus.not_found:
        raise HTTPException(status_code=404, detail="Job not found")
    if status in (JobStatus.deferred, JobStatus.queued):
        return {"status": "queued", "report": None, "error": None}
    if status == JobStatus.in_progress:
        return {"status": "in_progress", "report": None, "error": None}

    info = await job.result_info()
    if info.success:
        return {"status": "complete", "report": info.result, "error": None}
    return {"status": "failed", "report": None, "error": str(info.result)}
