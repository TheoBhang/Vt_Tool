from app.errors import ValidationError

UNSUPPORTED_VALUE_TYPES = {
    "Private IPv4",
    "Loopback IPv4",
    "Unspecified IPv4",
    "Link-local IPv4",
    "Reserved IPv4",
    "SHA-224",
    "SHA-384",
    "SHA-512",
    "SSDEEP",
}


class AnalysisService:
    """The orchestrator: check cache, on miss validate + fetch from VirusTotal +
    cache the result. This is the single 'analyze one value' entry point both
    the CLI and an API job worker call.

    check_cache()/classify_or_raise() are also exposed as their own public
    methods, not just internal steps of analyze() - the API's sync-hit path
    calls check_cache() directly (it never fetches, so it's constructed with
    virustotal=None and never calls analyze()), and calls classify_or_raise()
    before enqueueing a job, so an invalid value is rejected the same way
    whether analyze() or the API classifies it - one place owns that logic,
    not two independently-maintained copies.

    The cache is namespaced by the CLI-plural value_type ("domains", "ips", ...)
    rather than VirusTotalService's canonical uppercase type, specifically so a
    cache hit never has to call ValidationService.classify() at all - that type
    conversion is only needed on the miss path, right before the VT API call."""

    def __init__(self, validation, virustotal, cache):
        self.validation = validation
        self.virustotal = virustotal
        self.cache = cache

    def analyze(self, value, value_type: str) -> tuple[dict, bool]:
        cached = self.check_cache(value, value_type)
        if cached is not None:
            return cached, True

        canonical_type = self.classify_or_raise(value, value_type)
        report = self.virustotal.get_report(canonical_type, value)
        self.cache.set(value_type, self._cache_key(value), report)
        return report, False

    def check_cache(self, value, value_type: str) -> dict | None:
        """Cache-only lookup, no classification or VT fetch."""
        return self.cache.get(value_type, self._cache_key(value))

    def classify_or_raise(self, value, value_type: str) -> str:
        """Validates value against value_type, raising ValidationError if
        unsupported/invalid. Returns the canonical uppercase type
        VirusTotalService expects."""
        classification = self.validation.classify(value, value_type)
        if not classification or classification in UNSUPPORTED_VALUE_TYPES:
            raise ValidationError(f"Unsupported or invalid {value_type[:-1]}: {value}")
        return classification.upper()

    def _cache_key(self, value) -> str:
        return value[0] if isinstance(value, tuple) else value
