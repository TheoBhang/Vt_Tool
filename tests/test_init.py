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
