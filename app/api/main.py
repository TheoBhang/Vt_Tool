import os
from contextlib import asynccontextmanager
from typing import Literal

from arq import create_pool
from arq.connections import RedisSettings
from arq.jobs import Job, JobStatus
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from app.DataHandler.validator import DataValidator
from app.errors import ValidationError
from app.services.analysis_service import AnalysisService
from app.services.cache_config import build_cache_service
from app.services.validation_service import ValidationService


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.analysis = AnalysisService(
        validation=ValidationService(DataValidator()),
        virustotal=None,
        cache=build_cache_service(),
    )
    app.state.redis = await create_pool(
        RedisSettings.from_dsn(os.getenv("REDIS_URL", "redis://localhost:6379"))
    )
    yield
    app.state.analysis.cache.backend.close()
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
    analysis: AnalysisService = request.app.state.analysis
    redis = request.app.state.redis

    results = []
    for item in payload.values:
        cached = analysis.check_cache(item.value, item.value_type)
        if cached is not None:
            results.append({"status": "hit", "report": cached})
            continue

        try:
            analysis.classify_or_raise(item.value, item.value_type)
        except ValidationError as e:
            results.append({"status": "invalid", "error": str(e)})
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
