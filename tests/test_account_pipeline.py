import sys
import unittest
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from account_pipeline import probe_account


class ProbeFallbackTests(unittest.TestCase):
    def test_timeout_falls_back_to_models(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/responses"):
                raise httpx.ReadTimeout("model busy", request=request)
            return httpx.Response(
                200,
                json={"object": "list", "data": [{"id": "grok-4.5"}]},
                request=request,
            )

        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            result = probe_account(
                {"access_token": "test", "base_url": "https://example.test/v1"},
                client=client,
            )

        self.assertTrue(result["available"])
        self.assertEqual(result["fallback"], "models")
        self.assertEqual(result["classification"], "model_busy")
        self.assertFalse(result["chat_ready"])

    def test_double_timeout_is_retryable_not_dead(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("busy", request=request)

        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            result = probe_account(
                {"access_token": "test", "base_url": "https://example.test/v1"},
                client=client,
            )

        self.assertIsNone(result["available"])
        self.assertTrue(result["retryable"])
        self.assertEqual(result["classification"], "uncertain")

    def test_unauthorized_is_hard_failure(self):
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            return httpx.Response(401, json={"error": "invalid token"}, request=request)

        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            result = probe_account(
                {"access_token": "test", "base_url": "https://example.test/v1"},
                client=client,
            )

        self.assertFalse(result["available"])
        self.assertFalse(result["retryable"])
        self.assertEqual(result["classification"], "invalid_credential")
        self.assertEqual(calls, ["/v1/responses"])


if __name__ == "__main__":
    unittest.main()
