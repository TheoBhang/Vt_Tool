NOT_FOUND_ERROR = "Not found"


class ReportCacheService:
    """A pure cache in front of a CacheBackend: no report-shaping logic lives
    here, only the policy of when a cached entry counts as a real hit."""

    def __init__(self, backend, threshold: float = 0.8):
        self.backend = backend
        self.threshold = threshold

    def get(self, value_type: str, value: str) -> dict | None:
        report = self.backend.get(value_type, value)
        if report is None:
            return None
        if not report:
            return None
        not_found_count = sum(1 for v in report.values() if v == NOT_FOUND_ERROR)
        if (not_found_count / len(report)) >= self.threshold:
            return None
        return report

    def set(self, value_type: str, value: str, report: dict) -> None:
        self.backend.set(value_type, value, report)
