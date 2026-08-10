from typing import Protocol


class CacheBackend(Protocol):
    """Contract a report-cache storage backend must implement. ReportCacheService
    depends on this, not on any concrete backend - SQLiteCacheBackend is the only
    implementation today, but a future backend just needs to match this shape.
    No report-shaping or freshness-policy logic belongs in an implementation of
    this Protocol; that's ReportCacheService's job."""

    def get(self, value_type: str, value: str) -> tuple[dict, str] | None:
        """Return (report, cached_at_iso_string) for an existing entry, or
        None if nothing has ever been cached for this (value_type, value)."""
        ...

    def set(self, value_type: str, value: str, report: dict) -> None:
        """Store report, stamping/refreshing its cached_at to now."""
        ...
