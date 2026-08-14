import csv
import os
import tempfile
import unittest
from unittest import mock

from app.MISP.vt_tools2misp import (
    process_csv_file,
    load_template,
    apply_template_data,
    misp_choice,
    get_misp_event,
    submit_misp_objects,
)


class _FakeAttribute:
    def __init__(self):
        self.uuid = "attr-uuid"


class _FakeMispObject:
    def __init__(self, name, attributes):
        self.name = name
        self.attributes = attributes
        self.uuid = "obj-uuid"


class SubmitMispObjectsTests(unittest.TestCase):
    """pushed_count must reflect what MISP actually accepted (add_object not
    raising), not the number of objects handed to it - a push where MISP
    rejects everything used to still report a full pushed_count."""

    def test_returns_the_count_of_objects_misp_actually_accepted(self):
        fake_misp = mock.Mock()
        fake_event = mock.Mock(id="42")
        objects = [_FakeMispObject("ip-port", [_FakeAttribute()]) for _ in range(3)]

        count = submit_misp_objects(fake_misp, fake_event, objects)

        self.assertEqual(count, 3)
        self.assertEqual(fake_misp.add_object.call_count, 3)

    def test_a_failed_add_object_is_not_counted(self):
        fake_misp = mock.Mock()
        fake_misp.add_object.side_effect = [None, Exception("MISP rejected it"), None]
        fake_event = mock.Mock(id="42")
        objects = [_FakeMispObject("ip-port", [_FakeAttribute()]) for _ in range(3)]

        count = submit_misp_objects(fake_misp, fake_event, objects)

        self.assertEqual(count, 2)

    def test_an_object_with_no_attributes_is_skipped_and_not_counted(self):
        fake_misp = mock.Mock()
        fake_event = mock.Mock(id="42")
        objects = [_FakeMispObject("ip-port", [])]

        count = submit_misp_objects(fake_misp, fake_event, objects)

        self.assertEqual(count, 0)
        fake_misp.add_object.assert_not_called()

    def test_empty_object_list_returns_zero(self):
        fake_misp = mock.Mock()
        fake_event = mock.Mock(id="42")

        self.assertEqual(submit_misp_objects(fake_misp, fake_event, []), 0)


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




class GetMispEventTests(unittest.TestCase):
    def test_creates_a_new_event_when_get_event_returns_a_pymisp_error_dict(self):
        # pymisp's ExpandedPyMISP.get_event() does NOT raise on a 404 - it
        # returns {'errors': (404, ...)}. This is the exact shape that let
        # the create-if-missing branch go unreachable: an except-based check
        # never fires because get_event() never raises.
        fake_misp = mock.Mock()
        fake_misp.get_event.return_value = {'errors': (404, 'Event not found')}
        fake_misp.new_event.return_value = {"Event": {"id": "7", "info": "VirusTotal Report - no-such-case"}}

        get_misp_event(fake_misp, "no-such-case")

        fake_misp.new_event.assert_called_once_with(info="VirusTotal Report - no-such-case")


class MispChoiceTests(unittest.TestCase):
    def test_yes_calls_misp_event_with_case_and_files(self):
        with mock.patch("app.MISP.vt_tools2misp.misp_event") as mock_event:
            with mock.patch("app.MISP.vt_tools2misp.Prompt.ask", return_value="y"):
                misp_choice("123456", ["a.csv"])
        mock_event.assert_called_once_with("123456", ["a.csv"], None, None)

    def test_yes_passes_through_template_file_and_template(self):
        with mock.patch("app.MISP.vt_tools2misp.misp_event") as mock_event:
            with mock.patch("app.MISP.vt_tools2misp.Prompt.ask", return_value="1"):
                misp_choice("123456", ["a.csv"], "template.csv", "value,comment")
        mock_event.assert_called_once_with("123456", ["a.csv"], "template.csv", "value,comment")

    def test_case_000000_prompts_for_event_id(self):
        with mock.patch("app.MISP.vt_tools2misp.misp_event") as mock_event:
            with mock.patch(
                "app.MISP.vt_tools2misp.Prompt.ask", side_effect=["yes", "999999"]
            ):
                misp_choice("000000", ["a.csv"])
        mock_event.assert_called_once_with("999999", ["a.csv"], None, None)

    def test_no_choice_skips_misp_event(self):
        with mock.patch("app.MISP.vt_tools2misp.misp_event") as mock_event:
            with mock.patch("app.MISP.vt_tools2misp.Prompt.ask", return_value="no"):
                misp_choice("123456", ["a.csv"])
        mock_event.assert_not_called()

    def test_invalid_choice_retries_until_valid(self):
        with mock.patch("app.MISP.vt_tools2misp.misp_event") as mock_event:
            with mock.patch(
                "app.MISP.vt_tools2misp.Prompt.ask", side_effect=["bogus", "n"]
            ):
                misp_choice("123456", ["a.csv"])
        mock_event.assert_not_called()


if __name__ == "__main__":
    unittest.main()
