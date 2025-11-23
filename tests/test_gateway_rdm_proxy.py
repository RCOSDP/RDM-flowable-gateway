"""Tests for RDM proxy endpoints."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

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

from gateway import database as database_module  # noqa: E402
from gateway import main as main_module  # noqa: E402
from gateway import models as models_module  # noqa: E402


def _reset_database() -> None:
    models_module.Base.metadata.drop_all(bind=database_module.engine)
    models_module.Base.metadata.create_all(bind=database_module.engine)


class _DummyResponse:
    def __init__(self, *, status_code: int = 200, body: bytes = b"ok") -> None:
        self.status_code = status_code
        self.content = body
        self.headers = {"content-type": "text/plain"}


class _DummyAsyncClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def request(self, *args, **kwargs):
        return _DummyResponse()


class RDMProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        _reset_database()
        self.app = main_module.app
        self.session = database_module.SessionLocal()

    def tearDown(self) -> None:
        self.session.close()

    def _create_delegation(self) -> models_module.DelegationToken:
        token = models_module.DelegationToken(
            gateway_request_id="req-123",
            process_instance_id="proc-123",
            rdm_domain="http://rdm.local",
            rdm_api_domain="http://api.local",
            rdm_waterbutler_url="http://wb.local",
        )
        token.creator_token = "token"
        token.creator_owner = "owner"
        self.session.add(token)
        self.session.commit()
        return token

    def test_missing_request_returns_404(self):
        self._create_delegation()
        with TestClient(self.app) as client:
            response = client.get("/rdm/unknown/creator/web/path")
        self.assertEqual(response.status_code, 404)

    def test_missing_role_token_returns_403(self):
        self._create_delegation()
        with TestClient(self.app) as client:
            response = client.get("/rdm/req-123/manager/web/path")
        self.assertEqual(response.status_code, 403)

    def test_web_proxy_returns_stub_response(self):
        self._create_delegation()
        with mock.patch("gateway.rdm_proxy.httpx.AsyncClient", _DummyAsyncClient):
            with TestClient(self.app) as client:
                response = client.get("/rdm/req-123/creator/web/path")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"ok")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
