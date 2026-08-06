# VT_Tool Unit Test Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a characterization unit-test suite covering every module under `app/`, plus `vt_tools.py` and `init.py`, without modifying any existing application code, so the team has a safety net before the planned refactor/audit pass.

**Architecture:** One `unittest.TestCase`-based test file per module (`tests/test_<module>.py`), using `unittest.mock` for all external boundaries (VirusTotal SDK, `requests`, MISP, stdin, filesystem cwd). `sqlite3`'s built-in `:memory:` mode is used directly (no mocking) for `DBHandler` tests since that *is* the thing under test. No test framework is added — Python's stdlib `unittest` already covers everything needed (mocking, assertions, discovery), so `pytest` is deliberately not introduced as a dependency.

**Adaptation from standard TDD:** This is a *characterization* test suite for existing, working code — not new-feature development. There is no RED step (write a failing test, watch it fail) because there is no missing implementation to build. Each task's steps are: write the test file (full code), run it and confirm it **passes**, commit. If a test fails unexpectedly, that means either the test is wrong (fix the test) or it has caught a real bug in the app — in the latter case **do not touch application code**; instead keep the test but assert the actual (buggy) behavior with a comment explaining the discrepancy, and flag it in the task's commit message / final report for the upcoming audit. Two such bugs were already found during planning and are called out explicitly in Task 7 and Task 11 below — write those tests to assert the current (buggy) behavior, not the "correct" behavior.

**Tech Stack:** Python 3 stdlib `unittest` + `unittest.mock`. No new third-party dependencies.

## Global Constraints

- Do not modify any file under `app/`, `vt_tools.py`, or `init.py` — this phase is test-writing only.
- No new entries in `requirements.txt` — use stdlib `unittest`/`unittest.mock` only.
- Tests must not perform real network I/O (mock `vt.Client`, `requests.Session`, `ExpandedPyMISP`) and must not write to the real `vttools.sqlite` file or the real `Results/` directory (use `:memory:` SQLite and `tempfile`/`chdir` isolation).
- Virtualenv lives at `.venv/` (already created against `requirements.txt`); activate it for every command: `source .venv/bin/activate`.
- Run the whole suite with: `python -m unittest discover -s tests -t . -v`
- Run a single file with: `python -m unittest tests.test_<module> -v`
- `tests/__init__.py` must exist (already created) so `discover -t .` can import `tests` as a package and resolve `from app... import ...` against the repo root.

---

### Task 1: Test harness bootstrap

**Files:**
- Create: `tests/__init__.py` (empty)
- Create: `.venv/` (via `python3 -m venv .venv`, deps from `requirements.txt`)

**Interfaces:**
- Produces: a working `python -m unittest discover -s tests -t .` command that every later task's tests run under.

- [ ] **Step 1: Create the venv and install dependencies**

```bash
cd /home/forensics/vt_tool
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip -q
pip install -q -r requirements.txt
```

- [ ] **Step 2: Create the tests package**

```bash
mkdir -p tests
touch tests/__init__.py
```

- [ ] **Step 3: Verify discovery works with zero tests**

Run: `source .venv/bin/activate && python -m unittest discover -s tests -t . -v`
Expected: `Ran 0 tests in 0.000s` / `OK` (no errors, no import failures).

- [ ] **Step 4: Commit**

```bash
git add tests/__init__.py
git commit -m "test: bootstrap unittest harness"
```

(`.venv/` stays untracked — it is already covered by nothing in `.gitignore` today; if `git status` shows it, add `.venv/` to `.gitignore` in this same commit.)

---

### Task 2: `app/DataHandler/validator.py`

**Files:**
- Create: `tests/test_validator.py`

**Interfaces:**
- Consumes: `DataValidator` (methods `validate_ip`, `validate_domain`, `validate_hash`, `validate_url`), and module-level functions `get_url_details`, `get_service_name`, `get_port_from_service_name`, `extract_ip_address` from `app.DataHandler.validator`.

- [ ] **Step 1: Write the test file**

```python
import unittest
from unittest import mock

import tldextract

import app.DataHandler.validator as validator_mod
from app.DataHandler.validator import (
    DataValidator,
    get_url_details,
    get_service_name,
    get_port_from_service_name,
    extract_ip_address,
)


def setUpModule():
    # get_url_details() calls the module-level tldextract.extract(), which
    # uses tldextract's global default instance and can hit the network on
    # a cold cache. Patch just the `extract` attribute (not the whole
    # module, which would also shadow tldextract.TLDExtract used by
    # DataValidator.__init__) to a local, network-free instance so tests
    # never perform real I/O regardless of cache state.
    global _tldextract_patcher
    offline_extract = tldextract.TLDExtract(
        cache_dir=None, suffix_list_urls=(), fallback_to_snapshot=True
    )
    _tldextract_patcher = mock.patch.object(
        validator_mod.tldextract, "extract", offline_extract
    )
    _tldextract_patcher.start()


def tearDownModule():
    _tldextract_patcher.stop()


class ValidateIpTests(unittest.TestCase):
    def setUp(self):
        self.validator = DataValidator()

    def test_public_ipv4(self):
        self.assertEqual(self.validator.validate_ip(("8.8.8.8",)), "Public IPv4")

    def test_private_ipv4(self):
        self.assertEqual(self.validator.validate_ip(("192.168.1.1",)), "Private IPv4")

    def test_loopback_ipv4_is_classified_as_private(self):
        # ipaddress.IPv4Address("127.0.0.1").is_private is True, and validate_ip
        # checks is_private before is_loopback, so the "Private" branch wins.
        # The "Loopback IPv4" branch is effectively unreachable for IPv4.
        # Documents current behavior; not a claim that it's correct.
        self.assertEqual(self.validator.validate_ip(("127.0.0.1",)), "Private IPv4")

    def test_public_ipv6(self):
        self.assertEqual(
            self.validator.validate_ip(("2606:4700:4700::1111",)), "Public IPv6"
        )

    def test_invalid_ip_returns_none(self):
        self.assertIsNone(self.validator.validate_ip(("999.999.999.999",)))


class ValidateDomainTests(unittest.TestCase):
    def setUp(self):
        self.validator = DataValidator()

    def test_valid_domain(self):
        self.assertEqual(self.validator.validate_domain("example.com"), "DOMAIN")

    def test_localhost_is_not_a_domain(self):
        self.assertIsNone(self.validator.validate_domain("localhost"))

    def test_plain_text_is_not_a_domain(self):
        self.assertIsNone(self.validator.validate_domain("just some text"))


class ValidateHashTests(unittest.TestCase):
    def setUp(self):
        self.validator = DataValidator()

    def test_md5_by_length(self):
        self.assertEqual(self.validator.validate_hash("a" * 32), "MD5")

    def test_sha1_by_length(self):
        self.assertEqual(self.validator.validate_hash("a" * 40), "SHA-1")

    def test_sha256_by_length(self):
        self.assertEqual(self.validator.validate_hash("a" * 64), "SHA-256")

    def test_ssdeep_by_pattern(self):
        self.assertEqual(
            self.validator.validate_hash("3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr"),
            "SSDEEP",
        )

    def test_invalid_hash_returns_none(self):
        self.assertIsNone(self.validator.validate_hash("abc123"))


class ValidateUrlTests(unittest.TestCase):
    def setUp(self):
        self.validator = DataValidator()

    def test_valid_url(self):
        self.assertEqual(self.validator.validate_url("https://example.com"), "URL")

    def test_invalid_url_returns_none(self):
        self.assertIsNone(self.validator.validate_url("not a url"))


class GetUrlDetailsTests(unittest.TestCase):
    def test_parses_all_components(self):
        details = get_url_details(
            "https://sub.example.com:8443/path/to/res?a=1&b=2#frag"
        )
        self.assertEqual(details["scheme"], "https")
        self.assertEqual(details["subdomain"], "sub")
        self.assertEqual(details["domain"], "example.com")
        self.assertEqual(details["tld"], "com")
        self.assertEqual(details["port"], 8443)
        self.assertEqual(details["resource_path"], "/path/to/res")
        self.assertEqual(details["query_strings"], "a=1&b=2")
        self.assertEqual(details["query_params"], {"a": ["1"], "b": ["2"]})
        self.assertEqual(details["fragment"], "frag")


class ServiceNameLookupTests(unittest.TestCase):
    def test_get_service_name_known_port(self):
        self.assertEqual(get_service_name(80), "http")

    def test_get_service_name_invalid_port(self):
        self.assertIsNone(get_service_name("not-a-port"))

    def test_get_port_from_service_name_known_service(self):
        self.assertEqual(get_port_from_service_name("http"), 80)

    def test_get_port_from_service_name_unknown_service(self):
        self.assertIsNone(get_port_from_service_name("not-a-real-service"))


class ExtractIpAddressTests(unittest.TestCase):
    def test_extracts_ip_from_whois_style_text(self):
        text = "Name: foo\nIP Address: 10.20.30.40\nOther: x"
        self.assertEqual(extract_ip_address(text), "10.20.30.40")

    def test_returns_none_when_no_match(self):
        self.assertIsNone(extract_ip_address("no ip here"))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run and verify pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_validator -v`
Expected: all tests `ok`, final line `OK`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_validator.py
git commit -m "test: characterize DataValidator and validator helper functions"
```

---

### Task 3: `app/DataHandler/utils.py`

**Files:**
- Create: `tests/test_utils.py`

**Interfaces:**
- Consumes: `utc2local`, `get_api_key`, `get_proxy`, `display_menu`, `get_initial_choice`, `get_analysis_type`, `get_user_choice`, `ANALYSIS_OPTIONS`, `ALL_ANALYSIS_TYPES` from `app.DataHandler.utils`. Interactive functions are driven via `rich.prompt.Prompt.ask`, mocked at `app.DataHandler.utils.Prompt.ask`.

- [ ] **Step 1: Write the test file**

```python
import os
import tempfile
import unittest
from datetime import datetime
from unittest import mock

import app.DataHandler.utils as utils


class Utc2LocalTests(unittest.TestCase):
    def test_accepts_iso_string(self):
        result = utils.utc2local("2024-01-01T12:00:00")
        self.assertIsInstance(result, datetime)
        self.assertIsNotNone(result.tzinfo)

    def test_accepts_datetime(self):
        result = utils.utc2local(datetime(2024, 1, 1, 12, 0, 0))
        self.assertIsInstance(result, datetime)
        self.assertIsNotNone(result.tzinfo)

    def test_rejects_non_datetime_input(self):
        with self.assertRaises(ValueError):
            utils.utc2local(123)


class GetApiKeyTests(unittest.TestCase):
    def test_direct_argument_wins(self):
        self.assertEqual(utils.get_api_key(api_key="direct"), "direct")

    def test_reads_from_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("  filekey123  \n")
            path = f.name
        try:
            self.assertEqual(utils.get_api_key(api_key_file=path), "filekey123")
        finally:
            os.remove(path)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            utils.get_api_key(api_key_file="/nonexistent/path/key.txt")

    def test_falls_back_to_env_var(self):
        with mock.patch.dict(os.environ, {"VTAPIKEY": "envkey"}, clear=True):
            self.assertEqual(utils.get_api_key(), "envkey")

    def test_raises_when_nothing_provided(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                utils.get_api_key()


class GetProxyTests(unittest.TestCase):
    def test_direct_argument_wins(self):
        self.assertEqual(utils.get_proxy(proxy="http://direct:8080"), "http://direct:8080")

    def test_falls_back_to_env_var(self):
        with mock.patch.dict(os.environ, {"PROXY": "http://env:8080"}, clear=True):
            self.assertEqual(utils.get_proxy(), "http://env:8080")

    def test_returns_none_when_nothing_provided(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(utils.get_proxy())


class InteractivePromptTests(unittest.TestCase):
    def test_display_menu_returns_choice(self):
        with mock.patch("app.DataHandler.utils.Prompt.ask", return_value="2"):
            self.assertEqual(utils.display_menu(), "2")

    def test_get_initial_choice_normalizes_yes(self):
        with mock.patch("app.DataHandler.utils.Prompt.ask", return_value="yes"):
            self.assertEqual(utils.get_initial_choice(), "y")

    def test_get_initial_choice_normalizes_no(self):
        with mock.patch("app.DataHandler.utils.Prompt.ask", return_value="no"):
            self.assertEqual(utils.get_initial_choice(), "n")

    def test_get_analysis_type_maps_key_to_lowercase_name(self):
        with mock.patch("app.DataHandler.utils.Prompt.ask", return_value="3"):
            self.assertEqual(utils.get_analysis_type(), "urls")

    def test_get_user_choice_single_type(self):
        with mock.patch(
            "app.DataHandler.utils.Prompt.ask", side_effect=["y", "3"]
        ):
            self.assertEqual(utils.get_user_choice(), ["urls"])

    def test_get_user_choice_all_types(self):
        with mock.patch("app.DataHandler.utils.Prompt.ask", side_effect=["n"]):
            self.assertEqual(utils.get_user_choice(), utils.ALL_ANALYSIS_TYPES)

    def test_get_user_choice_invalid_response_defaults_to_all(self):
        with mock.patch(
            "app.DataHandler.utils.Prompt.ask",
            side_effect=utils.InvalidResponse("bad"),
        ):
            self.assertEqual(utils.get_user_choice(), utils.ALL_ANALYSIS_TYPES)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run and verify pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_utils -v`
Expected: all tests `ok`, final line `OK`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_utils.py
git commit -m "test: characterize DataHandler utils (api key/proxy resolution, prompts)"
```

---

### Task 4: `app/FileHandler/create_table.py`

**Files:**
- Create: `tests/test_create_table.py`

**Interfaces:**
- Consumes: `CustomPrettyTable` from `app.FileHandler.create_table`.

- [ ] **Step 1: Write the test file**

```python
import unittest

from app.FileHandler.create_table import CustomPrettyTable as cpt


class CleanDataTests(unittest.TestCase):
    def test_drops_unwanted_headers_and_columns(self):
        headers = ["ip", "malicious_score", "info", "whois", "https_certificate"]
        data = [["8.8.8.8", "0", "x", "y", "z"]]
        table = cpt(headers, data)
        self.assertEqual(table.headers, ["ip", "malicious_score"])
        self.assertEqual(table.data, [["8.8.8.8", "0"]])

    def test_drops_rows_with_mismatched_column_count(self):
        headers = ["ip", "info", "malicious_score"]
        data = [["8.8.8.8", "x", "0"], ["1.1.1.1", "5"]]  # second row malformed
        table = cpt(headers, data)
        self.assertEqual(table.headers, ["ip", "malicious_score"])
        self.assertEqual(table.data, [["8.8.8.8", "0"]])


class SortDataTests(unittest.TestCase):
    def test_sorts_by_column(self):
        table = cpt(["ip"], [["9.9.9.9"], ["1.1.1.1"], ["5.5.5.5"]])
        table.sort_data(sort_by="ip")
        self.assertEqual(table.data, [["1.1.1.1"], ["5.5.5.5"], ["9.9.9.9"]])

    def test_invalid_sort_column_raises(self):
        table = cpt(["ip"], [["9.9.9.9"]])
        with self.assertRaises(ValueError):
            table.sort_data(sort_by="does_not_exist")


class CreateTableTests(unittest.TestCase):
    def test_renders_headers_and_rows(self):
        table = cpt(["ip", "malicious_score"], [["8.8.8.8", "0"], ["1.1.1.1", "5"]])
        rendered = table.create_table()
        self.assertIn("ip", rendered)
        self.assertIn("malicious_score", rendered)
        self.assertIn("8.8.8.8", rendered)
        self.assertIn("1.1.1.1", rendered)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run and verify pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_create_table -v`
Expected: all tests `ok`, final line `OK`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_create_table.py
git commit -m "test: characterize CustomPrettyTable"
```

---

### Task 5: `app/FileHandler/output_to_file.py`

**Files:**
- Create: `tests/test_output_to_file.py`

**Interfaces:**
- Consumes: `OutputHandler` from `app.FileHandler.output_to_file`.
- Isolation: each test runs inside a `tempfile.TemporaryDirectory()` with `os.chdir()`, since `OutputHandler` hardcodes the relative path `Results/`. `setUp`/`tearDown` restore the original cwd so this suite never touches the real repo's `Results/` directory.

- [ ] **Step 1: Write the test file**

```python
import csv
import os
import tempfile
import unittest

from app.FileHandler.output_to_file import OutputHandler


class OutputHandlerTestCase(unittest.TestCase):
    def setUp(self):
        self._orig_cwd = os.getcwd()
        self._tmpdir = tempfile.TemporaryDirectory()
        os.chdir(self._tmpdir.name)

    def tearDown(self):
        os.chdir(self._orig_cwd)
        self._tmpdir.cleanup()


class GetFilePathTests(OutputHandlerTestCase):
    def test_builds_path_with_zero_padded_case_and_suffix(self):
        handler = OutputHandler("42")
        path = handler._get_file_path("IP", extension="csv")
        self.assertTrue(path.startswith("Results/000042_IP_Analysis_"))
        self.assertTrue(path.endswith(".csv"))

    def test_csv_extension_is_tracked_in_csvfilescreated(self):
        handler = OutputHandler("1")
        path = handler._get_file_path("HASH", extension="csv")
        self.assertEqual(handler.csvfilescreated, [path])

    def test_txt_extension_is_not_tracked(self):
        handler = OutputHandler("1")
        handler._get_file_path("HASH", extension="txt")
        self.assertEqual(handler.csvfilescreated, [])

    def test_unknown_value_type_raises(self):
        handler = OutputHandler("1")
        with self.assertRaises(ValueError):
            handler._get_file_path("BOGUS", extension="csv")


class OutputToCsvTests(OutputHandlerTestCase):
    def test_writes_csv_with_header_and_rows(self):
        handler = OutputHandler("7")
        data = [[{"ip": "8.8.8.8", "malicious_score": "0"}]]
        handler.output_to_csv(data, "IP")

        [written_path] = handler.csvfilescreated
        with open(written_path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(rows, [{"ip": "8.8.8.8", "malicious_score": "0"}])


class OutputToTxtTests(OutputHandlerTestCase):
    def test_writes_txt_content(self):
        handler = OutputHandler("7")
        handler.output_to_txt("+---+\n| x |\n+---+", "HASH")

        [name] = [f for f in os.listdir("Results") if f.endswith(".txt")]
        with open(os.path.join("Results", name), encoding="utf-8") as f:
            content = f.read()
        self.assertIn("+---+", content)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run and verify pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_output_to_file -v`
Expected: all tests `ok`, final line `OK`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_output_to_file.py
git commit -m "test: characterize OutputHandler CSV/TXT file writing"
```

---

### Task 6: `app/FileHandler/read_file.py`

**Files:**
- Create: `tests/test_read_file.py`

**Interfaces:**
- Consumes: `Pattern`, `ValueExtractor`, `ValueReader` from `app.FileHandler.read_file`.
- Isolation: `ValueReader` tests use `tempfile` for file input and mock `sys.stdin.isatty()` so no test blocks on real stdin.

- [ ] **Step 1: Write the test file**

```python
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
```

- [ ] **Step 2: Run and verify pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_read_file -v`
Expected: all tests `ok`, final line `OK`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_read_file.py
git commit -m "test: characterize Pattern/ValueExtractor/ValueReader input parsing"
```

---

### Task 7: `app/DBHandler/db_handler.py`

**Files:**
- Create: `tests/test_db_handler.py`

**Interfaces:**
- Consumes: `DBHandler` from `app.DBHandler.db_handler`.
- Isolation: every test uses `DBHandler().create_connection(":memory:")` — never the real `vttools.sqlite` file.

**Known bugs to characterize (do not fix, per Global Constraints):**
1. `DBHandler.exists()` compares stored values against the literal `"Not Found"` (capital F), but `NOT_FOUND_ERROR` (what's actually stored) is `"Not found"` (lowercase f). The ratio-based "treat mostly-empty cached rows as cache misses" logic therefore never fires — case mismatch means the count is always 0.
2. `DBHandler.populate_scores()` reads `report[2]`/`report[3]` and `DBHandler.populate_tags()` reads `report[4]` — these are the fixed offsets for the `hashes` table (where `malicious_score`/`total_scans`/`tags` happen to sit at those positions) but are wrong for `ips` and `domains` (where `port`/`protocol` occupy those slots, so unrelated column values leak into `malicious_score`/`total_scans`/`tags`). It is coincidentally masked for `urls` because `populate_url_data()` overwrites those three keys afterward with the correct indices.

- [ ] **Step 1: Write the test file**

```python
import unittest

from app.DBHandler.db_handler import DBHandler


IP_ROW = {
    "ip": "8.8.8.8",
    "port": "Not found",
    "protocol": "Not found",
    "malicious_score": "0",
    "total_scans": "10",
    "tags": "Not found",
    "link": "l",
    "owner": "Google",
    "location": "US",
    "network": "8.8.8.0/24",
    "https_certificate": "Not found",
    "info-ip": {"regional_internet_registry": "ARIN", "asn": "15169"},
}


class SchemaAndConnectionTests(unittest.TestCase):
    def test_create_schema_creates_all_tables(self):
        db = DBHandler()
        conn = db.create_connection(":memory:")
        db.create_schema(conn)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}
        # sqlite_sequence is an internal bookkeeping table SQLite creates
        # automatically because the schema uses AUTOINCREMENT columns.
        tables.discard("sqlite_sequence")
        self.assertEqual(tables, {"urls", "hashes", "ips", "domains"})


class InsertAndUpsertTests(unittest.TestCase):
    def setUp(self):
        self.db = DBHandler()
        self.conn = self.db.create_connection(":memory:")
        self.db.create_schema(self.conn)

    def test_insert_ip_data_creates_one_row(self):
        self.db.insert_ip_data(self.conn, IP_ROW)
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM ips")
        self.assertEqual(cur.fetchone()[0], 1)

    def test_reinsert_same_key_updates_instead_of_duplicating(self):
        self.db.insert_ip_data(self.conn, IP_ROW)
        updated = dict(IP_ROW, malicious_score="5")
        self.db.insert_ip_data(self.conn, updated)

        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM ips")
        self.assertEqual(cur.fetchone()[0], 1)
        cur.execute("SELECT malicious_score FROM ips WHERE ip = ?", ("8.8.8.8",))
        self.assertEqual(cur.fetchone()[0], "5")


class ExistsTests(unittest.TestCase):
    def setUp(self):
        self.db = DBHandler()
        self.conn = self.db.create_connection(":memory:")
        self.db.create_schema(self.conn)

    def test_false_when_absent(self):
        self.assertFalse(self.db.exists(self.conn, "ips", "8.8.8.8", "ip"))

    def test_true_when_present(self):
        self.db.insert_ip_data(self.conn, IP_ROW)
        self.assertTrue(self.db.exists(self.conn, "ips", "8.8.8.8", "ip"))

    def test_mostly_not_found_row_still_reads_as_existing(self):
        # BUG (see task header, item 1): exists() checks for the literal
        # "Not Found" but NOT_FOUND_ERROR is "Not found", so the ratio
        # check that's supposed to treat heavily-empty cached rows as
        # cache misses never triggers. This documents the current
        # (buggy) behavior: even an almost-entirely-empty row reads as
        # "exists" and will never be retried.
        empty_row = dict(IP_ROW)
        for key in ("port", "protocol", "malicious_score", "total_scans",
                    "tags", "link", "owner", "location", "network",
                    "https_certificate"):
            empty_row[key] = "Not found"
        empty_row["info-ip"] = {"regional_internet_registry": "Not found", "asn": "Not found"}
        self.db.insert_ip_data(self.conn, empty_row)
        self.assertTrue(self.db.exists(self.conn, "ips", "8.8.8.8", "ip"))


class GetReportRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.db = DBHandler()
        self.conn = self.db.create_connection(":memory:")
        self.db.create_schema(self.conn)

    def test_hash_report_fields_are_correctly_positioned(self):
        # The hashes table schema happens to put malicious_score/total_scans/
        # tags exactly where populate_scores/populate_tags read them, so this
        # path is correct.
        hash_row = {
            "hash": "a" * 64, "malicious_score": "7", "total_scans": "70",
            "tags": "trojan", "threat_category": "tc", "threat_labels": "tl",
            "link": "l", "extension": "exe", "size": "123", "md5": "m",
            "sha1": "s1", "sha256": "s2", "ssdeep": "sd", "tlsh": "t",
            "meaningful_name": "n", "names": "names", "type": "PE",
            "type_probability": "0.9",
        }
        self.db.insert_hash_data(self.conn, hash_row)
        report = self.db.get_report(hash_row["hash"], "SHA-256", self.conn)
        csv_row = report["csv_report"][0]
        self.assertEqual(csv_row["malicious_score"], "7")
        self.assertEqual(csv_row["tags"], "trojan")

    def test_domain_report_score_and_tag_fields_are_misaligned(self):
        # BUG (see task header, item 2): for the domains table, populate_scores
        # reads report[2]/report[3] (= ip/port columns) instead of the actual
        # malicious_score/total_scans columns, and populate_tags reads
        # report[4] (= protocol) instead of the tags column. This test pins
        # down the current (incorrect) behavior rather than the intended one.
        domain_row = {
            "domain": "example.com", "ip": "1.2.3.4", "port": "443",
            "protocol": "https", "malicious_score": "9", "total_scans": "90",
            "tags": "phishing", "link": "l", "creation_date": "2020",
            "reputation": "0", "whois": "w",
            "info": {
                "last_analysis_results": "x", "last_analysis_stats": "y",
                "last_dns_records": "z", "last_https_certificate": "c",
                "registrar": "r",
            },
        }
        self.db.insert_domain_data(self.conn, domain_row)
        report = self.db.get_report("example.com", "DOMAIN", self.conn)
        csv_row = report["csv_report"][0]
        # Actual (buggy) values: malicious_score reads the "ip" column,
        # tags reads the "protocol" column.
        self.assertEqual(csv_row["malicious_score"], "1.2.3.4")
        self.assertEqual(csv_row["tags"], "https")

    def test_url_report_score_and_tag_fields_are_correct(self):
        # populate_url_data() overwrites malicious_score/total_scans/tags
        # afterward with the correct indices, masking the same underlying
        # bug that affects domains/ips.
        url_row = {
            "url": "http://x.com/a", "domain": "x.com", "ip": "1.1.1.1",
            "port": "80", "protocol": "http", "fragment": "",
            "resource_path": "/a", "query_params": "", "query_strings": "",
            "tld": "com", "subdomain": "", "scheme": "http",
            "malicious_score": "3", "total_scans": "30", "tags": "malware",
            "link": "l", "title": "t", "final_url": "f", "first_scan": "fs",
            "metadatas": "m", "targeted": "tg", "links": "lk",
            "redirection_chain": "rc", "trackers": "tr",
        }
        self.db.insert_url_data(self.conn, url_row)
        report = self.db.get_report("http://x.com/a", "URL", self.conn)
        csv_row = report["csv_report"][0]
        self.assertEqual(csv_row["malicious_score"], "3")
        self.assertEqual(csv_row["tags"], "malware")

    def test_get_report_returns_none_for_missing_value(self):
        self.assertIsNone(self.db.get_report("nope.example", "DOMAIN", self.conn))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run and verify pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_db_handler -v`
Expected: all tests `ok`, final line `OK`. (These tests assert the *current* behavior including the two documented bugs — they should pass as written, not fail.)

- [ ] **Step 3: Commit**

```bash
git add tests/test_db_handler.py
git commit -m "test: characterize DBHandler CRUD/exists/get_report, document two indexing bugs"
```

---

### Task 8: `app/VirusTotal/vt_client.py`

**Files:**
- Create: `tests/test_vt_client.py`

**Interfaces:**
- Consumes: `VirusTotalClient` from `app.VirusTotal.vt_client`.

- [ ] **Step 1: Write the test file**

```python
import unittest
from unittest import mock

import vt

from app.VirusTotal.vt_client import VirusTotalClient


class VirusTotalClientTests(unittest.TestCase):
    def test_init_client_returns_vt_client_instance(self):
        client_wrapper = VirusTotalClient("fake-key")
        client = client_wrapper.init_client()
        try:
            self.assertIsInstance(client, vt.Client)
        finally:
            client.close()

    def test_stores_api_key_and_proxy(self):
        client_wrapper = VirusTotalClient("fake-key", proxy="http://proxy:8080")
        self.assertEqual(client_wrapper.api_key, "fake-key")
        self.assertEqual(client_wrapper.proxy, "http://proxy:8080")

    def test_init_client_returns_false_on_api_error(self):
        with mock.patch(
            "app.VirusTotal.vt_client.vt.Client",
            side_effect=vt.APIError("AuthenticationRequiredError", "bad key"),
        ):
            client_wrapper = VirusTotalClient("bad-key")
            self.assertFalse(client_wrapper.init_client())

    def test_init_client_returns_false_on_unexpected_error(self):
        with mock.patch(
            "app.VirusTotal.vt_client.vt.Client", side_effect=RuntimeError("boom")
        ):
            client_wrapper = VirusTotalClient("key")
            self.assertFalse(client_wrapper.init_client())


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run and verify pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_vt_client -v`
Expected: all tests `ok`, final line `OK`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_vt_client.py
git commit -m "test: characterize VirusTotalClient init success/failure paths"
```

---

### Task 9: `app/VirusTotal/vt_reporter.py`

**Files:**
- Create: `tests/test_vt_reporter.py`

**Interfaces:**
- Consumes: `VTReporter`, `NOT_FOUND_ERROR` from `app.VirusTotal.vt_reporter`.
- Isolation: `app.VirusTotal.vt_reporter.DBHandler` is patched in every test so `insert_into_db()` never touches the real `vttools.sqlite` file. The VT SDK object returned by `vt_client.get_object()` is replaced with a small local `FakeReport` stand-in exposing both attribute access (`getattr`) and `.get()`, matching what `vt-py`'s `Object` supports and what `vt_reporter.py` actually calls.

- [ ] **Step 1: Write the test file**

```python
import unittest
from unittest import mock

from app.VirusTotal.vt_reporter import VTReporter, NOT_FOUND_ERROR


class FakeReport:
    """Minimal stand-in for vt.Object: supports getattr() and .get()."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def get(self, key, default=None):
        return self.__dict__.get(key, default)


class CreateReportTests(unittest.TestCase):
    def test_unknown_value_type_returns_none(self):
        reporter = VTReporter(mock.Mock())
        self.assertIsNone(reporter.create_report("BOGUS", "x"))

    def test_not_found_error_returns_sentinel(self):
        vt_client = mock.Mock()
        vt_client.get_object.side_effect = Exception("NotFoundError raised by vt-py")
        reporter = VTReporter(vt_client)
        self.assertEqual(reporter.create_report("DOMAIN", "nosuch.example"), NOT_FOUND_ERROR)

    def test_other_errors_propagate(self):
        vt_client = mock.Mock()
        vt_client.get_object.side_effect = RuntimeError("network down")
        reporter = VTReporter(vt_client)
        with self.assertRaises(RuntimeError):
            reporter.create_report("DOMAIN", "example.com")


class GetReportIpTests(unittest.TestCase):
    def test_populates_ip_fields_from_report(self):
        with mock.patch("app.VirusTotal.vt_reporter.DBHandler") as MockDB:
            vt_client = mock.Mock()
            report = FakeReport(
                last_analysis_stats={"malicious": 2, "harmless": 60},
                tags=["t1", "t2"],
                as_owner="Google LLC",
                continent="NA",
                country="US",
                network="8.8.8.0/24",
                last_https_certificate="cert",
                regional_internet_registry="ARIN",
                asn=15169,
            )
            vt_client.get_object.return_value = report
            reporter = VTReporter(vt_client)

            result = reporter.get_report("PUBLIC IPV4", "8.8.8.8")

            csv_row = result["csv_report"][0]
            self.assertEqual(csv_row["malicious_score"], 2)
            self.assertEqual(csv_row["total_scans"], 62)
            self.assertEqual(csv_row["tags"], "t1, t2")
            self.assertEqual(csv_row["location"], "NA / US")
            self.assertEqual(csv_row["owner"], "Google LLC")
            self.assertTrue(MockDB.return_value.insert_ip_data.called)


class GetReportNotFoundTests(unittest.TestCase):
    def test_not_found_still_caches_an_empty_row(self):
        with mock.patch("app.VirusTotal.vt_reporter.DBHandler") as MockDB:
            vt_client = mock.Mock()
            vt_client.get_object.side_effect = Exception("NotFoundError")
            reporter = VTReporter(vt_client)

            result = reporter.get_report("DOMAIN", "nosuch.example")

            csv_row = result["csv_report"][0]
            self.assertEqual(csv_row["malicious_score"], 0)
            self.assertEqual(csv_row["tags"], "Not found")
            self.assertTrue(MockDB.return_value.insert_domain_data.called)


class GetReportHashThreatClassificationTests(unittest.TestCase):
    def test_populates_threat_category_and_labels_when_present(self):
        with mock.patch("app.VirusTotal.vt_reporter.DBHandler"):
            vt_client = mock.Mock()
            report = FakeReport(
                last_analysis_stats={"malicious": 40, "harmless": 20},
                tags=[],
                type_extension="exe", size=1024, md5="m", sha1="s1", sha256="s2",
                ssdeep="sd", tlsh="t", meaningful_name="n", names=["n1", "n2"],
                trid=[{"file_type": "Win32 EXE", "probability": "80.0%"}],
                popular_threat_classification={
                    "suggested_threat_label": "trojan.generic",
                    "popular_threat_category": [{"value": "trojan"}],
                },
            )
            vt_client.get_object.return_value = report
            reporter = VTReporter(vt_client)

            result = reporter.get_report("SHA-256", "a" * 64)

            csv_row = result["csv_report"][0]
            self.assertEqual(csv_row["threat_category"], "trojan")
            self.assertEqual(csv_row["threat_labels"], "trojan.generic")
            self.assertEqual(csv_row["type"], "Win32 EXE")

    def test_missing_classification_falls_back_to_not_found(self):
        with mock.patch("app.VirusTotal.vt_reporter.DBHandler"):
            vt_client = mock.Mock()
            report = FakeReport(
                last_analysis_stats={"malicious": 0, "harmless": 20},
                tags=[],
                type_extension="exe", size=1024, md5="m", sha1="s1", sha256="s2",
                ssdeep="sd", tlsh="t", meaningful_name="n", names=["n1"],
                # no `trid`, no `popular_threat_classification` attribute at all
            )
            vt_client.get_object.return_value = report
            reporter = VTReporter(vt_client)

            result = reporter.get_report("SHA-256", "b" * 64)

            csv_row = result["csv_report"][0]
            self.assertEqual(csv_row["threat_category"], "Not found")
            self.assertEqual(csv_row["threat_labels"], "Not found")
            self.assertEqual(csv_row["type"], "Not found")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run and verify pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_vt_reporter -v`
Expected: all tests `ok`, final line `OK`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_vt_reporter.py
git commit -m "test: characterize VTReporter report creation and field population"
```

---

### Task 10: `app/MISP/vt_tools2misp.py` (pure/local functions only)

**Files:**
- Create: `tests/test_misp.py`

**Interfaces:**
- Consumes: `process_csv_file`, `get_attribute_mapping`, `load_template`, `apply_template_data`, `create_misp_object`, `identify_object_type` from `app.MISP.vt_tools2misp`.
- Out of scope: `get_misp_event`, `submit_misp_objects`, `misp_event`, `misp_choice`, `misp_choice_template` require a live/mocked `ExpandedPyMISP` server round trip and interactive prompts — not covered here to keep this task's tests fast and deterministic. Flag as a follow-up if the team wants that coverage later.

- [ ] **Step 1: Write the test file**

```python
import csv
import os
import tempfile
import unittest

from app.MISP.vt_tools2misp import (
    process_csv_file,
    get_attribute_mapping,
    load_template,
    apply_template_data,
    create_misp_object,
    identify_object_type,
)


class ProcessCsvFileTests(unittest.TestCase):
    def test_reads_rows_as_dicts(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "test.csv")
            with open(path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["ip", "malicious_score", "link"])
                writer.writeheader()
                writer.writerow({"ip": "8.8.8.8", "malicious_score": "0", "link": "http://x"})
            rows = process_csv_file(path)
        self.assertEqual(rows, [{"ip": "8.8.8.8", "malicious_score": "0", "link": "http://x"}])

    def test_missing_file_returns_empty_list(self):
        self.assertEqual(process_csv_file("/nonexistent/file.csv"), [])


class GetAttributeMappingTests(unittest.TestCase):
    def test_maps_known_headers(self):
        mapping = {"ip": ("ip", "ip-dst", "Network activity", False)}
        result = get_attribute_mapping(["ip", "unrelated"], mapping)
        self.assertEqual(result, {"ip": ("ip", "ip-dst", "Network activity", False)})

    def test_raises_when_no_headers_match(self):
        mapping = {"ip": ("ip", "ip-dst", "Network activity", False)}
        with self.assertRaises(ValueError):
            get_attribute_mapping(["nope"], mapping)


class LoadTemplateTests(unittest.TestCase):
    def test_parses_template_rows_keyed_by_value(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "template.csv")
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["value", "comment", "tag1"])
                writer.writerow(["8.8.8.8", "test comment", "tlp:green"])
            template = load_template(path)
        self.assertEqual(
            template, {"8.8.8.8": {"comment": ["test comment"], "tag1": ["tlp:green"]}}
        )

    def test_missing_value_column_returns_empty_dict(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "template.csv")
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["not_value", "comment"])
                writer.writerow(["x", "y"])
            self.assertEqual(load_template(path), {})

    def test_missing_file_returns_empty_dict(self):
        self.assertEqual(load_template("/nonexistent/template.csv"), {})


class ApplyTemplateDataTests(unittest.TestCase):
    def test_merges_matching_template_row_into_data(self):
        data = [{"ip": "8.8.8.8", "malicious_score": "0"}]
        template = {"8.8.8.8": {"comment": ["hi"], "tag1": ["tlp:green"]}}
        apply_template_data(data, template, "ip")
        self.assertEqual(
            data, [{"ip": "8.8.8.8", "malicious_score": "0", "comment": "hi", "tag1": "tlp:green"}]
        )

    def test_no_match_leaves_row_unchanged(self):
        data = [{"ip": "1.1.1.1", "malicious_score": "0"}]
        apply_template_data(data, {"8.8.8.8": {"comment": ["hi"]}}, "ip")
        self.assertEqual(data, [{"ip": "1.1.1.1", "malicious_score": "0"}])


class CreateMispObjectTests(unittest.TestCase):
    def test_builds_object_with_mapped_attributes(self):
        row = {"ip": "8.8.8.8", "malicious_score": "Not found", "comment": "hi"}
        attribute_mapping = {
            "ip": ("ip", "ip-dst", "Network activity", False),
            "malicious_score": ("malicious_score", "text", "Antivirus detection", False),
        }
        obj = create_misp_object(row, "ip-port", attribute_mapping)
        self.assertEqual(obj.name, "ip-port")
        self.assertEqual(obj.comment, "hi")
        # "Not found" sentinel values are skipped, so only "ip" is added.
        self.assertEqual(len(obj.attributes), 1)
        self.assertEqual(obj.attributes[0].type, "ip-dst")
        self.assertEqual(obj.attributes[0].value, "8.8.8.8")
        self.assertTrue(obj.attributes[0].to_ids)

    def test_incomplete_mapping_returns_none(self):
        row = {"ip": "8.8.8.8"}
        attribute_mapping = {"ip": ("ip", "ip-dst", "Network activity")}  # missing 4th element
        self.assertIsNone(create_misp_object(row, "ip-port", attribute_mapping))


class IdentifyObjectTypeTests(unittest.TestCase):
    def test_matches_known_patterns_case_insensitively(self):
        self.assertEqual(identify_object_type("000001_Hashes_Analysis_x.csv"), "file")
        self.assertEqual(identify_object_type("000001_URL_Analysis_x.csv"), "url")
        self.assertEqual(identify_object_type("000001_IP_Analysis_x.csv"), "ip-port")
        self.assertEqual(identify_object_type("000001_Domains_Analysis_x.csv"), "domain-ip")
        # Lowercase "hashes" only matches r"Hash" via re.IGNORECASE, so this
        # assertion is the one that actually exercises case-insensitivity.
        self.assertEqual(identify_object_type("000001_hashes_analysis_x.csv"), "file")

    def test_unknown_filename_raises(self):
        with self.assertRaises(ValueError):
            identify_object_type("unrelated_file.csv")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run and verify pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_misp -v`
Expected: all tests `ok`, final line `OK`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_misp.py
git commit -m "test: characterize MISP CSV/template parsing and object construction"
```

---

### Task 11: `vt_tools.py` helper functions

**Files:**
- Create: `tests/test_vt_tools.py`

**Interfaces:**
- Consumes: `count_iocs`, `extract_table_data`, `get_remaining_quota`, `value_exists`, `validate_value` from `vt_tools` (repo root module).
- `get_remaining_quota` is tested by patching `vt_tools.requests.Session` with a fake session/response — no real HTTP call.
- `value_exists`/`validate_value` take an `Initializator`-shaped object; tests pass a `unittest.mock.Mock()` standing in for it.

**Known latent bug to characterize (do not fix):** `extract_table_data()` accumulates `headers` as a `set` across all `results`, but builds each row using `headers` **as it stood after processing that single result** — not the final combined header set. If two results in the same batch have different key sets, earlier rows end up shorter than later rows and shorter than the returned `headers` list, which is what `CustomPrettyTable.clean_data()`'s "Skipping malformed row" path exists to paper over. In today's usage every result of a given `value_type` has the same key set (populated with `NOT_FOUND_ERROR` fallbacks), so this rarely manifests — but it's fragile. Write the test to pin the current per-result-snapshot behavior.

- [ ] **Step 1: Write the test file**

```python
import unittest
from unittest import mock

import vt_tools


class CountIocsTests(unittest.TestCase):
    def test_sums_list_lengths(self):
        self.assertEqual(
            vt_tools.count_iocs({"ips": ["a", "b"], "domains": ["c"]}), 3
        )

    def test_rejects_non_dict(self):
        with self.assertRaises(TypeError):
            vt_tools.count_iocs(["not", "a", "dict"])


class ExtractTableDataTests(unittest.TestCase):
    def test_headers_are_the_union_of_all_results(self):
        results = [
            {"csv_report": [{"ip": "8.8.8.8", "malicious_score": 0}]},
            {"csv_report": [{"ip": "1.1.1.1", "malicious_score": 5, "extra": "x"}]},
        ]
        headers, rows = vt_tools.extract_table_data(results)
        self.assertEqual(set(headers), {"ip", "malicious_score", "extra"})

    def test_row_length_matches_header_set_snapshot_at_that_point_not_final(self):
        # Documents current behavior (see task header): row 1 is built before
        # "extra" is added to `headers`, so it has 2 entries while row 2 (and
        # the final `headers` list) has 3. This is why CustomPrettyTable has
        # to silently drop rows whose length doesn't match the header count.
        results = [
            {"csv_report": [{"ip": "8.8.8.8", "malicious_score": 0}]},
            {"csv_report": [{"ip": "1.1.1.1", "malicious_score": 5, "extra": "x"}]},
        ]
        _, rows = vt_tools.extract_table_data(results)
        self.assertEqual(len(rows[0]), 2)
        self.assertEqual(len(rows[1]), 3)


class GetRemainingQuotaTests(unittest.TestCase):
    def test_computes_remaining_from_allowed_and_used(self):
        class FakeResponse:
            status_code = 200

            def raise_for_status(self):
                pass

            def json(self):
                return {"data": {"api_requests_hourly": {"user": {"allowed": 500, "used": 120}}}}

        class FakeSession:
            def __enter__(self):
                return self

            def __exit__(self, *exc_info):
                return False

            def __init__(self):
                self.proxies = {}

            def get(self, url, headers=None):
                return FakeResponse()

        with mock.patch("vt_tools.requests.Session", return_value=FakeSession()):
            self.assertEqual(vt_tools.get_remaining_quota("key", None, None), 380)

    def test_returns_zero_on_request_exception(self):
        import requests

        class FailingSession:
            def __enter__(self):
                return self

            def __exit__(self, *exc_info):
                return False

            def __init__(self):
                self.proxies = {}

            def get(self, url, headers=None):
                raise requests.exceptions.RequestException("network down")

        with mock.patch("vt_tools.requests.Session", return_value=FailingSession()):
            self.assertEqual(vt_tools.get_remaining_quota("key", None, None), 0)


class ValueExistsTests(unittest.TestCase):
    def test_hashes_uses_singular_hash_column(self):
        init = mock.Mock()
        vt_tools.value_exists(init, "somehash", "hashes", conn=None)
        init.db_handler.exists.assert_called_once_with(None, "hashes", "somehash", "hash")

    def test_ips_unwraps_tuple_and_uses_ip_column(self):
        init = mock.Mock()
        vt_tools.value_exists(init, ("8.8.8.8", "443"), "ips", conn=None)
        init.db_handler.exists.assert_called_once_with(None, "ips", "8.8.8.8", "ip")

    def test_domains_uses_singular_domain_column(self):
        init = mock.Mock()
        vt_tools.value_exists(init, "example.com", "domains", conn=None)
        init.db_handler.exists.assert_called_once_with(None, "domains", "example.com", "domain")


class ValidateValueTests(unittest.TestCase):
    def test_hashes_calls_validate_hash(self):
        init = mock.Mock()
        init.validator.validate_hash.return_value = "MD5"
        result = vt_tools.validate_value(init, "a" * 32, "hashes")
        init.validator.validate_hash.assert_called_once_with("a" * 32)
        self.assertEqual(result, "MD5")

    def test_other_types_call_matching_validate_method(self):
        init = mock.Mock()
        init.validator.validate_domain.return_value = "DOMAIN"
        result = vt_tools.validate_value(init, "example.com", "domains")
        init.validator.validate_domain.assert_called_once_with("example.com")
        self.assertEqual(result, "DOMAIN")

    def test_missing_validator_method_returns_empty_string(self):
        init = mock.Mock(spec=["validator"])
        init.validator = mock.Mock(spec=[])  # no validate_domain attribute at all
        result = vt_tools.validate_value(init, "example.com", "domains")
        self.assertEqual(result, "")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run and verify pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_vt_tools -v`
Expected: all tests `ok`, final line `OK`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_vt_tools.py
git commit -m "test: characterize vt_tools helper functions, document extract_table_data fragility"
```

---

### Task 12: `init.py` (`Initializator`)

**Files:**
- Create: `tests/test_init.py`

**Interfaces:**
- Consumes: `Initializator` from `init`.
- No mocking needed for `vt.Client` construction itself (verified during planning that `vt.Client(api_key, proxy=proxy)` does not perform any network I/O at construction time) — only `.close()` is called in teardown to avoid leaking the underlying `aiohttp` session.

- [ ] **Step 1: Write the test file**

```python
import unittest

from init import Initializator
from app.VirusTotal.vt_reporter import VTReporter
from app.DataHandler.validator import DataValidator
from app.FileHandler.output_to_file import OutputHandler
from app.DBHandler.db_handler import DBHandler


class InitializatorTests(unittest.TestCase):
    def setUp(self):
        self.init = Initializator("fake-api-key", proxy=None, case_num="000001")

    def tearDown(self):
        self.init.client.close()

    def test_wires_up_all_components(self):
        self.assertTrue(self.init.client)
        self.assertIsInstance(self.init.reporter, VTReporter)
        self.assertIsInstance(self.init.validator, DataValidator)
        self.assertIsInstance(self.init.output, OutputHandler)
        self.assertIsInstance(self.init.db_handler, DBHandler)

    def test_stores_constructor_args(self):
        self.assertEqual(self.init.api_key, "fake-api-key")
        self.assertIsNone(self.init.proxy)
        self.assertEqual(self.init.case_num, "000001")
        self.assertEqual(self.init.output.case_num, "000001")

    def test_reporter_is_bound_to_the_same_client(self):
        self.assertIs(self.init.reporter.vt, self.init.client)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run and verify pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_init -v`
Expected: all tests `ok`, final line `OK`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_init.py
git commit -m "test: characterize Initializator component wiring"
```

---

### Task 13: Full-suite verification

**Files:** none (verification only)

- [ ] **Step 1: Run the entire suite from a clean shell**

```bash
cd /home/forensics/vt_tool
source .venv/bin/activate
python -m unittest discover -s tests -t . -v
```

Expected: every test from Tasks 2–12 listed, all `ok`, final line `OK`, no `ERROR`/`FAIL` entries.

- [ ] **Step 2: Confirm no test touched the real DB or Results directory**

```bash
git status --short
```

Expected: only `tests/*.py` (and `.venv/` if untracked) show as changes — `vttools.sqlite` and `Results/` must not appear as modified/created (Task 5/7/9 isolate these with `:memory:` SQLite, `tempfile`, and mocked `DBHandler`/`vt.Client`).

- [ ] **Step 3: Report the documented bugs to the user**

No code change — just make sure the findings below are called out clearly as candidates for the upcoming audit/fix pass, since that's the whole reason this suite was built first:

1. **DBHandler cache-hit case-sensitivity bug** (Task 7, `tests/test_db_handler.py`): `exists()` compares against `"Not Found"` but the app stores `"Not found"`, so the ratio-based cache-miss check never fires.
2. **DBHandler malicious_score/total_scans/tags column misalignment** for `ips`/`domains` (Task 7, `tests/test_db_handler.py`): `populate_scores`/`populate_tags` use fixed tuple offsets correct only for the `hashes` table.
3. **extract_table_data's per-result header snapshot** (Task 11, `tests/test_vt_tools.py`): `vt_tools.py` builds each row from a `headers` set mid-accumulation, not the final set, so rows can end up shorter than the final header list when results have heterogeneous keys.
4. **`ValueReader._accumulate_values` is defined twice** (found during the final-review fix cycle, `tests/test_read_file.py`): `app/FileHandler/read_file.py`'s `ValueReader` class defines `_accumulate_values` once for the stdin path (~line 252) and again for the file path (~line 334) — Python keeps only the second definition, so `read_from_stdin()` silently writes into `self.dict_values_file` instead of `self.dict_values` and always returns an empty dict, even though it prints "Successfully read values from user input". **This means the CLI's stdin-piping input mode is completely broken today** — the most user-visible of the four findings, since it fails silently with no error.

---

## Self-Review

**Spec coverage:** every module under `app/` (`DataHandler/validator.py`, `DataHandler/utils.py`, `FileHandler/create_table.py`, `FileHandler/output_to_file.py`, `FileHandler/read_file.py`, `DBHandler/db_handler.py`, `VirusTotal/vt_client.py`, `VirusTotal/vt_reporter.py`, `MISP/vt_tools2misp.py`) plus `vt_tools.py` and `init.py` each have a task and test file. `app/DataHandler/public/*` is static data (public suffix list), not code — no task needed.

**Placeholder scan:** no TBD/TODO markers; every step shows complete, runnable code verified against the actual installed dependencies during planning (Python 3.12 venv, `requirements.txt` installed).

**Type/behavior consistency:** function names and call signatures used in tests (`validate_ip(("8.8.8.8",))`, `get_remaining_quota(api_key, proxy, args)`, `value_exists(init, value, value_type, conn)`, etc.) were checked against the actual source in `app/` and `vt_tools.py`, and every non-obvious assertion (IP tuple wrapping, `exists()` case bug, DB column misalignment, `extract_table_data` header snapshot) was executed against the real code during planning to confirm the expected value before being written into this plan.
