import unittest

from app.errors import AnalysisError, ValidationError, VirusTotalAPIError, CacheError


class ErrorHierarchyTests(unittest.TestCase):
    def test_validation_error_is_analysis_error(self):
        self.assertTrue(issubclass(ValidationError, AnalysisError))

    def test_virustotal_api_error_is_analysis_error(self):
        self.assertTrue(issubclass(VirusTotalAPIError, AnalysisError))

    def test_cache_error_is_analysis_error(self):
        self.assertTrue(issubclass(CacheError, AnalysisError))

    def test_analysis_error_is_exception(self):
        self.assertTrue(issubclass(AnalysisError, Exception))


if __name__ == "__main__":
    unittest.main()
