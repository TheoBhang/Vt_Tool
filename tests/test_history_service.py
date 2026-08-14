import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from app.services.history_service import HistoryService


class HistoryServiceTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.db_path)  # service creates it fresh
        self.service = HistoryService(self.db_path)

    def tearDown(self):
        self.service.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_save_returns_an_id_and_created_at(self):
        result = self.service.save([{"value": "8.8.8.8", "value_type": "ips", "report": {"malicious_score": 0}, "error": None}])
        self.assertIn("id", result)
        self.assertIn("created_at", result)
        self.assertIsNone(result["case_label"])

    def test_save_with_a_case_label(self):
        result = self.service.save([], case_label="incident-42")
        self.assertEqual(result["case_label"], "incident-42")

    def test_get_returns_none_when_absent(self):
        self.assertIsNone(self.service.get("nonexistent-id"))

    def test_save_then_get_round_trips_items(self):
        items = [{"value": "example.com", "value_type": "domains", "report": {"domain": "example.com"}, "error": None}]
        saved = self.service.save(items)
        result = self.service.get(saved["id"])
        self.assertEqual(result["items"], items)
        self.assertEqual(result["case_label"], None)
        self.assertIsNone(result["misp_event_id"])

    def test_list_returns_summaries_newest_first(self):
        first = self.service.save([{"value": "a", "value_type": "domains", "report": None, "error": "x"}])
        second = self.service.save([{"value": "b", "value_type": "ips", "report": None, "error": "x"}, {"value": "c", "value_type": "ips", "report": None, "error": "x"}])
        results = self.service.list(limit=10, offset=0)
        self.assertEqual([r["id"] for r in results], [second["id"], first["id"]])
        self.assertEqual(results[0]["item_count"], 2)
        self.assertEqual(results[1]["item_count"], 1)

    def test_list_respects_limit_and_offset(self):
        for i in range(5):
            self.service.save([{"value": str(i), "value_type": "domains", "report": None, "error": None}])
        page = self.service.list(limit=2, offset=1)
        self.assertEqual(len(page), 2)

    def test_set_misp_event_id_updates_event_id_and_label(self):
        saved = self.service.save([{"value": "a", "value_type": "domains", "report": None, "error": None}])
        self.service.set_misp_event_id(saved["id"], "123", "incident-42")
        result = self.service.get(saved["id"])
        self.assertEqual(result["misp_event_id"], "123")
        self.assertEqual(result["case_label"], "incident-42")

    def test_set_misp_event_id_without_a_case_label_leaves_label_unchanged(self):
        saved = self.service.save([{"value": "a", "value_type": "domains", "report": None, "error": None}], case_label="already-set")
        self.service.set_misp_event_id(saved["id"], "456", None)
        result = self.service.get(saved["id"])
        self.assertEqual(result["misp_event_id"], "456")
        self.assertEqual(result["case_label"], "already-set")


class ThreadSafetyTests(unittest.TestCase):
    """save()/list()/get() must be safe to call concurrently - the API calls
    this from concurrent request handlers, same reasoning as
    SQLiteCacheBackend's own thread-safety tests."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.db_path)
        self.service = HistoryService(self.db_path)

    def tearDown(self):
        self.service.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_concurrent_save_and_list_does_not_raise(self):
        errors = []

        def save_and_list(i):
            try:
                self.service.save([{"value": f"v{i}", "value_type": "domains", "report": None, "error": None}])
                self.service.list(limit=5, offset=0)
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=10) as executor:
            list(executor.map(save_and_list, range(50)))

        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
