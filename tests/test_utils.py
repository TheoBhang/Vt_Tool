import os
import tempfile
import unittest
from datetime import datetime
from unittest import mock

from vt import url_id

import app.DataHandler.utils as utils


class BuildVirustotalLinkTests(unittest.TestCase):
    def test_url_type_uses_url_id_encoding(self):
        result = utils.build_virustotal_link("https://example.com/a", "URL")
        self.assertEqual(
            result, f"https://www.virustotal.com/gui/url/{url_id('https://example.com/a')}"
        )

    def test_non_url_type_uses_search_path(self):
        result = utils.build_virustotal_link("8.8.8.8", "PUBLIC IPV4")
        self.assertEqual(result, "https://www.virustotal.com/gui/search/8.8.8.8")

    def test_non_url_type_unwraps_tuple_value(self):
        result = utils.build_virustotal_link(("8.8.8.8", "443"), "PUBLIC IPV4")
        self.assertEqual(result, "https://www.virustotal.com/gui/search/8.8.8.8")


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


class GetSslVerifyTests(unittest.TestCase):
    def test_defaults_to_true_when_unset(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(utils.get_ssl_verify())

    def test_reads_false_from_env_var(self):
        with mock.patch.dict(os.environ, {"VTSSLVERIFY": "false"}, clear=True):
            self.assertFalse(utils.get_ssl_verify())

    def test_reads_true_from_env_var(self):
        with mock.patch.dict(os.environ, {"VTSSLVERIFY": "true"}, clear=True):
            self.assertTrue(utils.get_ssl_verify())

    def test_is_case_insensitive(self):
        with mock.patch.dict(os.environ, {"VTSSLVERIFY": "FALSE"}, clear=True):
            self.assertFalse(utils.get_ssl_verify())

    def test_unrecognized_value_is_treated_as_false(self):
        with mock.patch.dict(os.environ, {"VTSSLVERIFY": "nope"}, clear=True):
            self.assertFalse(utils.get_ssl_verify())


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
