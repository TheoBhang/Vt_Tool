import asyncio

from app.VirusTotal.vt_client import VirusTotalClient
from app.services.analysis_service import AnalysisService
from app.services.virustotal_service import VirusTotalService


async def analyze_value(ctx, value, value_type: str, api_key: str, proxy: str | None) -> dict:
    """arq job: analyze one value using the calling request's own VT API key.

    vt-py's Client methods (get_object, close) are synchronous wrappers that
    internally drive their own event loop via asyncio.get_event_loop()
    .run_until_complete() (vt-py's make_sync() helper). Calling them directly
    from this coroutine - which arq already runs inside a live event loop -
    raises "RuntimeError: This event loop is already running" (verified
    directly during planning). Running the whole synchronous
    AnalysisService.analyze() call chain inside a thread pool executor
    sidesteps this: a fresh executor thread has no event loop of its own
    running, so make_sync() can safely create one there.

    ctx["validation"]/ctx["cache"] are shared across every job in this worker
    process (populated once at worker startup, see settings.py) - only the
    VirusTotalService/vt.Client differ per job, scoped to this job's api_key.
    """

    def _run_analysis() -> dict:
        client = VirusTotalClient(api_key, proxy).init_client()
        try:
            analysis = AnalysisService(
                validation=ctx["validation"],
                virustotal=VirusTotalService(client),
                cache=ctx["cache"],
            )
            report, _ = analysis.analyze(value, value_type)
            return report
        finally:
            client.close()

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _run_analysis)
