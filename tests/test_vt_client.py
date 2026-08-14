import unittest
from unittest import mock

import vt

from app.errors import VirusTotalAPIError
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

    def test_verify_ssl_defaults_to_true(self):
        client_wrapper = VirusTotalClient("fake-key")
        self.assertTrue(client_wrapper.verify_ssl)

    def test_verify_ssl_is_passed_through_to_vt_client(self):
        with mock.patch("app.VirusTotal.vt_client.vt.Client") as mock_vt_client:
            VirusTotalClient("fake-key", verify_ssl=False).init_client()
        mock_vt_client.assert_called_once_with("fake-key", proxy=None, verify_ssl=False)

    def test_init_client_raises_virustotal_api_error_on_api_error(self):
        # Regression test: this used to return False, which callers used as
        # if it were a real client (calling .get_object()/.close() on it),
        # producing a confusing "'bool' object has no attribute 'close'"
        # instead of the actual cause - e.g. the web UI submitting with no
        # API key set, which makes vt.Client("") raise ValueError.
        with mock.patch(
            "app.VirusTotal.vt_client.vt.Client",
            side_effect=vt.APIError("AuthenticationRequiredError", "bad key"),
        ):
            client_wrapper = VirusTotalClient("bad-key")
            with self.assertRaises(VirusTotalAPIError):
                client_wrapper.init_client()

    def test_init_client_raises_virustotal_api_error_on_unexpected_error(self):
        with mock.patch(
            "app.VirusTotal.vt_client.vt.Client", side_effect=RuntimeError("boom")
        ):
            client_wrapper = VirusTotalClient("key")
            with self.assertRaises(VirusTotalAPIError):
                client_wrapper.init_client()

    def test_init_client_raises_virustotal_api_error_on_empty_api_key(self):
        # The real scenario that surfaced this bug: an empty API key (e.g.
        # the web UI submitting with none configured) makes the real vt.Client
        # constructor raise ValueError, not vt.APIError - both must be caught.
        client_wrapper = VirusTotalClient("")
        with self.assertRaises(VirusTotalAPIError):
            client_wrapper.init_client()


if __name__ == "__main__":
    unittest.main()
