from datetime import datetime, timedelta, timezone


class ReportCacheService:
    """A pure cache in front of a CacheBackend: no report-shaping logic lives
    here, only the policy of when a cached entry counts as a real hit - a TTL
    comparison against the backend's cached_at timestamp."""

    def __init__(self, backend, ttl: timedelta = timedelta(hours=24)):
        self.backend = backend
        self.ttl = ttl

    def get(self, value_type: str, value: str) -> dict | None:
        result = self.backend.get(value_type, value)
        if result is None:
            return None
        report, cached_at = result
        age = datetime.now(timezone.utc) - datetime.fromisoformat(cached_at)
        if age > self.ttl:
            return None
        return report

    def set(self, value_type: str, value: str, report: dict) -> None:
        self.backend.set(value_type, value, report)
