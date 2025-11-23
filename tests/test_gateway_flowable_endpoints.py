"""Tests for Flowable proxy endpoints."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from gateway.flowable import FlowableError

ROOT_DIR = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT_DIR / "config"
_TEST_TMPDIR = tempfile.TemporaryDirectory()
_TEST_DB_PATH = Path(_TEST_TMPDIR.name) / "gateway.db"

_ENV = {
    "FLOWABLE_REST_BASE_URL": "http://flowable.test/flowable-rest",
    "FLOWABLE_REST_APP_ADMIN_USER_ID": "rest-admin",
    "FLOWABLE_REST_APP_ADMIN_PASSWORD": "rest-admin",
    "RDM_KEYSET_PATH": str(CONFIG_DIR / "keyset.example.json"),
    "GATEWAY_INTERNAL_URL": "http://gateway.test",
    "DATABASE_URL": f"sqlite:///{_TEST_DB_PATH}",
    "GATEWAY_SIGNING_KEY_ID": "gateway-dev-v1",
    "GATEWAY_SIGNING_PRIVATE_KEY_PATH": str(CONFIG_DIR / "gateway-dev-v1.key.example"),
    "ENCRYPTION_KEY": "AuYz-pnPer1D-0b3bmaaKjZYBdQEfLTRZJlqaX0Xw40=",
    "RDM_ALLOWED_DOMAINS": "http://rdm.local",
    "RDM_ALLOWED_API_DOMAINS": "http://api.local",
    "RDM_ALLOWED_WATERBUTLER_URLS": "http://wb.local",
}
for key, value in _ENV.items():
    os.environ.setdefault(key, value)

from gateway import auth as auth_module  # noqa: E402
from gateway import main as main_module  # noqa: E402


class _FakeClient:
    def __init__(self, *, payload: dict | None = None, error: FlowableError | None = None):
        self.payload = payload or {"data": []}
        self.error = error

    async def list_process_definitions(self, params=None):  # pragma: no cover - helper
        if self.error:
            raise self.error
        return self.payload


class FlowableEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = main_module.app
        self.original_get_flowable_client = main_module.get_flowable_client
        self.app.dependency_overrides[auth_module.require_token] = self._token_context

    def tearDown(self) -> None:
        self.app.dependency_overrides.clear()
        main_module.get_flowable_client = self.original_get_flowable_client

    def _token_context(self):
        return auth_module.TokenContext(
            subject="tester",
            scopes=["workflow::delegate"],
            claims={},
            engine_id=None,
            key_id="rdm-service-v1",
        )

    def test_process_definitions_success(self):
        payload = {"data": [{"id": "proc"}]}
        main_module.get_flowable_client = lambda: _FakeClient(payload=payload)
        with TestClient(self.app) as client:
            response = client.get("/flowable/process-definitions")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), payload)

    def test_process_definitions_error_translation(self):
        error = FlowableError(502, {"message": "boom"})
        main_module.get_flowable_client = lambda: _FakeClient(error=error)
        with TestClient(self.app) as client:
            response = client.get("/flowable/process-definitions")
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json(), {"detail": {"message": "boom"}})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
