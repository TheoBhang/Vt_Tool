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
