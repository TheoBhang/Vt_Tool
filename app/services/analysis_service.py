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
    the CLI and (later) an API job worker call.

    The cache is namespaced by the CLI-plural value_type ("domains", "ips", ...)
    rather than VirusTotalService's canonical uppercase type, specifically so a
    cache hit never has to call ValidationService.classify() at all - that type
    conversion is only needed on the miss path, right before the VT API call."""

    def __init__(self, validation, virustotal, cache):
        self.validation = validation
        self.virustotal = virustotal
        self.cache = cache

    def analyze(self, value, value_type: str) -> tuple[dict, bool]:
        cache_key = self._cache_key(value)

        cached = self.cache.get(value_type, cache_key)
        if cached is not None:
            return cached, True

        classification = self.validation.classify(value, value_type)
        if not classification or classification in UNSUPPORTED_VALUE_TYPES:
            raise ValidationError(f"Unsupported or invalid {value_type[:-1]}: {value}")

        canonical_type = classification.upper()
        report = self.virustotal.get_report(canonical_type, value)
        self.cache.set(value_type, cache_key, report)
        return report, False

    def _cache_key(self, value) -> str:
        return value[0] if isinstance(value, tuple) else value
