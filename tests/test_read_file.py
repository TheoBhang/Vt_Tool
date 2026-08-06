import io
import os
import sys
import tempfile
import unittest
from unittest import mock

from app.FileHandler.read_file import Pattern, ValueExtractor, ValueReader


class PatternMatchTests(unittest.TestCase):
    def setUp(self):
        self.pattern = Pattern()

    def test_ip_with_and_without_port(self):
        matches = self.pattern.match_pattern(
            "check 8.8.8.8 and 1.1.1.1:8080 please", "ip"
        )
        self.assertEqual(matches, [("8.8.8.8", ""), ("1.1.1.1", "8080")])

    def test_hash(self):
        matches = self.pattern.match_pattern(
            "44d88612fea8a8f36de82e1278abb02f end", "hash"
        )
        self.assertEqual(matches, ["44d88612fea8a8f36de82e1278abb02f"])

    def test_url(self):
        matches = self.pattern.match_pattern(
            "visit https://example.com/path?x=1 now", "url"
        )
        self.assertEqual(matches, ["https://example.com/path?x=1"])

    def test_domain(self):
        matches = self.pattern.match_pattern(
            "go to example.com or www.test.org", "domain"
        )
        self.assertEqual(matches, ["example.com", "www.test.org"])

    def test_unknown_pattern_type_raises(self):
        with self.assertRaises(ValueError):
            self.pattern.match_pattern("text", "bogus")


class ValueExtractorTests(unittest.TestCase):
    def test_filters_filenames_out_of_domains(self):
        extractor = ValueExtractor()
        result = extractor.sort_values("download malware.exe now", is_file=False)
        self.assertNotIn("malware.exe", result["domains"])

    def test_strips_www_prefix_from_domains(self):
        extractor = ValueExtractor()
        result = extractor.sort_values("see www.example.com", is_file=False)
        self.assertIn("example.com", result["domains"])


class ValueReaderTests(unittest.TestCase):
    def _reader(self, fname=None, values=None):
        reader = ValueReader(fname, values or [])
        return reader

    def test_read_from_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("8.8.8.8\nexample.com\n44d88612fea8a8f36de82e1278abb02f\n")
            path = f.name
        try:
            reader = self._reader(fname=path)
            result = reader.read_from_file()
            self.assertIn("8.8.8.8", [ip for ip, _ in result["ips"]])
            self.assertIn("example.com", result["domains"])
            self.assertIn(
                "44d88612fea8a8f36de82e1278abb02f", result["hashes"]
            )
        finally:
            os.remove(path)

    def test_read_from_file_missing_file_returns_empty(self):
        reader = self._reader(fname="/nonexistent/file.txt")
        result = reader.read_from_file()
        self.assertEqual(result, {"ips": [], "urls": [], "hashes": [], "keys": [], "domains": []})

    def test_read_from_stdin_returns_empty_when_stdin_is_a_tty(self):
        reader = self._reader()
        with mock.patch.object(sys.stdin, "isatty", return_value=True):
            result = reader.read_from_stdin()
        self.assertEqual(result, {"ips": [], "urls": [], "hashes": [], "keys": [], "domains": []})

    def test_read_from_stdin_parses_piped_lines(self):
        reader = ValueReader(None, [])
        piped_input = io.StringIO("8.8.8.8\nexample.com\n")
        with mock.patch.object(sys, "stdin", piped_input):
            with mock.patch.object(piped_input, "isatty", return_value=False):
                result = reader.read_from_stdin()
        # ValueReader defines _accumulate_values twice (once for stdin,
        # once for file read); the second definition wins and both paths
        # share it, so the parsed lines land in self.dict_values_file
        # instead of self.dict_values / the returned dict. This documents
        # current behavior, not a claim that it's correct.
        self.assertEqual(result, {})
        self.assertIn("example.com", reader.dict_values_file["domains"])

    def test_read_values_narrows_keys_and_reads_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("example.com\n")
            path = f.name
        try:
            reader = ValueReader(path, [])
            with mock.patch.object(sys.stdin, "isatty", return_value=True):
                result = reader.read_values()
            self.assertEqual(set(result.keys()), {"ips", "urls", "hashes", "domains"})
            self.assertIn("example.com", result["domains"])
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
