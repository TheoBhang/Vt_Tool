class AnalysisError(Exception):
    """Base class for all core-service errors."""


class ValidationError(AnalysisError):
    """Raised when a value cannot be classified as a supported, queryable IOC type."""


class VirusTotalAPIError(AnalysisError):
    """Raised when a VirusTotal API call fails for a reason other than 'not found'."""


class CacheError(AnalysisError):
    """Raised when the report cache fails to read or write."""
