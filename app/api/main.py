import os
from contextlib import asynccontextmanager
from typing import Literal

from arq import create_pool
from arq.connections import RedisSettings
from arq.jobs import Job, JobStatus
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymisp import ExpandedPyMISP

from app.DataHandler.utils import get_env
from app.DataHandler.validator import DataValidator
from app.errors import ValidationError
from app.MISP.vt_tools2misp import get_misp_event, submit_misp_objects
from app.services.analysis_service import AnalysisService
from app.services.cache_config import build_cache_service
from app.services.history_service import HistoryService
from app.services.misp_service import ATTRIBUTE_TYPE_MAPPING, MispService, OBJECT_NAME_BY_VALUE_TYPE
from app.services.validation_service import ValidationService


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.analysis = AnalysisService(
        validation=ValidationService(DataValidator()),
        virustotal=None,
        cache=build_cache_service(),
    )
    app.state.redis = await create_pool(
        RedisSettings.from_dsn(get_env("REDIS_URL", "redis://localhost:6379"))
    )
    app.state.history = HistoryService(get_env("VT_HISTORY_DB_PATH", "vttools.sqlite"))
    yield
    app.state.analysis.cache.backend.close()
    app.state.history.close()
    await app.state.redis.aclose()


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in get_env("CORS_ALLOWED_ORIGINS", "*").split(",") if o.strip()],
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


def _flatten_report_for_misp(report: dict) -> dict:
    """ATTRIBUTE_TYPE_MAPPING's keys are flat CSV column names, but
    VirusTotalService's report dicts nest some fields under sub-dicts
    (IP reports: info-ip.regional_internet_registry / info-ip.asn) that would
    otherwise never match any mapping entry and get silently dropped. Other
    dict-valued fields (info, https_certificate) have no per-subfield mapping
    at all, so they're excluded rather than passed through as a stringified
    dict. Builds a new dict - never mutates the report stored in history.
    """
    flattened = {k: v for k, v in report.items() if not isinstance(v, dict)}
    flattened.update(report.get("info-ip", {}))
    return flattened


class MispPushRequest(BaseModel):
    case_id: str | None = None


@app.post("/analyses/{analysis_id}/misp-push")
async def push_analysis_to_misp(analysis_id: str, payload: MispPushRequest, request: Request):
    history: HistoryService = request.app.state.history
    analysis = history.get(analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    misp_url = os.getenv("MISPURL")
    misp_key = os.getenv("MISPKEY")
    if not misp_url or not misp_key:
        raise HTTPException(status_code=503, detail="MISP is not configured (MISPURL/MISPKEY unset)")

    try:
        misp = ExpandedPyMISP(misp_url, misp_key, False)
        misp_event = get_misp_event(misp, payload.case_id or analysis_id)

        misp_service = MispService()
        misp_objects = []
        skipped_count = 0
        skip_reasons = []
        for item in analysis["items"]:
            report = item.get("report")
            object_name = OBJECT_NAME_BY_VALUE_TYPE.get(item["value_type"])
            if not report:
                skipped_count += 1
                skip_reasons.append(f"{item['value']}: no report data")
                continue
            if object_name is None:
                skipped_count += 1
                skip_reasons.append(f"{item['value']}: unsupported value_type '{item['value_type']}'")
                continue
            attribute_mapping = {**ATTRIBUTE_TYPE_MAPPING[object_name], **ATTRIBUTE_TYPE_MAPPING["general"]}
            object_errors: list[str] = []
            misp_object = misp_service.create_object(
                _flatten_report_for_misp(report), object_name, attribute_mapping, errors=object_errors
            )
            if misp_object is None:
                skipped_count += 1
                reason = object_errors[0] if object_errors else "could not build MISP object"
                skip_reasons.append(f"{item['value']}: {reason}")
                continue
            misp_objects.append(misp_object)

        pushed_count = submit_misp_objects(misp, misp_event, misp_objects)
        # Recording the event id is part of the same MISP-push operation as
        # far as the caller is concerned - if this write fails (e.g. a
        # sqlite lock under concurrent history writes), the objects were
        # still genuinely submitted to MISP, so a raw unhandled 500 here
        # would make the client believe the push failed and potentially
        # retry, re-submitting the same objects with no idempotency check.
        # Folding it into the same try/except at least surfaces it as the
        # same clean 502 every other MISP-interaction failure gets.
        history.set_misp_event_id(analysis_id, str(misp_event.id), payload.case_id)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"MISP push failed: {e}")

    rejected_by_misp = len(misp_objects) - pushed_count
    if rejected_by_misp:
        skip_reasons.append(f"{rejected_by_misp} object(s) built successfully but MISP rejected them (see server logs)")
    skipped_count += rejected_by_misp
    return {
        "event_id": str(misp_event.id),
        "pushed_count": pushed_count,
        "skipped_count": skipped_count,
        "skip_reasons": skip_reasons,
    }
