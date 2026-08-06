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
