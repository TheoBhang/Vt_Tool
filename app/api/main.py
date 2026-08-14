import os
from contextlib import asynccontextmanager
from typing import Literal

from arq import create_pool
from arq.connections import RedisSettings
from arq.jobs import Job, JobStatus
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.DataHandler.validator import DataValidator
from app.errors import ValidationError
from app.services.analysis_service import AnalysisService
from app.services.cache_config import build_cache_service
from app.services.history_service import HistoryService
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
    app.state.history = HistoryService("vttools.sqlite")
    yield
    app.state.analysis.cache.backend.close()
    app.state.history.close()
    await app.state.redis.aclose()


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.getenv("CORS_ALLOWED_ORIGINS", "*").split(",") if o.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health(request: Request):
    analysis: AnalysisService = request.app.state.analysis
    redis = request.app.state.redis
    try:
        analysis.check_cache("healthcheck", "domains")
        await redis.ping()
    except Exception:
        raise HTTPException(status_code=503, detail="not ready")
    return {"status": "ok"}


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


class AnalysisItem(BaseModel):
    value: str
    value_type: Literal["ips", "domains", "urls", "hashes"]
    report: dict | None = None
    error: str | None = None


class SaveAnalysisRequest(BaseModel):
    case_label: str | None = None
    items: list[AnalysisItem]


@app.post("/analyses")
async def save_analysis(payload: SaveAnalysisRequest, request: Request):
    history: HistoryService = request.app.state.history
    items = [item.model_dump() for item in payload.items]
    return history.save(items, case_label=payload.case_label)


@app.get("/analyses")
async def list_analyses(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    history: HistoryService = request.app.state.history
    return history.list(limit=limit, offset=offset)


@app.get("/analyses/{analysis_id}")
async def get_analysis(analysis_id: str, request: Request):
    history: HistoryService = request.app.state.history
    result = history.get(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return result
