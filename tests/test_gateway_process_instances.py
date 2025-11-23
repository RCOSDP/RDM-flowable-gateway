"""Integration tests for gateway process instance handling."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

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

from gateway import auth as auth_module  # noqa: E402
from gateway import database as database_module  # noqa: E402
from gateway import main as main_module  # noqa: E402
from gateway import models as models_module  # noqa: E402
from gateway.flowable import FlowableError  # noqa: E402


def _reset_database() -> None:
    models_module.Base.metadata.drop_all(bind=database_module.engine)
    models_module.Base.metadata.create_all(bind=database_module.engine)


_reset_database()


class _SuccessfulFlowableClient:
    async def start_process(self, payload):  # pragma: no cover - helper
        return {"id": "process-123"}


class _FailingFlowableClient:
    def __init__(self, error: FlowableError) -> None:  # pragma: no cover - helper
        self._error = error

    async def start_process(self, payload):  # pragma: no cover - helper
        raise self._error


class ProcessInstanceTests(unittest.TestCase):
    def setUp(self) -> None:
        _reset_database()
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

    def test_missing_rdm_variables_returns_400(self):
        main_module.get_flowable_client = lambda: _SuccessfulFlowableClient()
        payload = {
            "processDefinitionId": "publication:1",
            "variables": [],
            "delegationTokens": {
                "creator": {
                    "tokenValue": "token",
                    "tokenOwner": "owner",
                    "mode": "read",
                }
            },
        }

        with TestClient(self.app) as client:
            response = client.post("/flowable/process-instances", json=payload)

        self.assertEqual(response.status_code, 400)

    def test_delegation_token_is_not_persisted_when_flowable_fails(self):
        error = FlowableError(502, {"message": "boom"})
        main_module.get_flowable_client = lambda: _FailingFlowableClient(error)
        payload = {
            "processDefinitionId": "publication:1",
            "variables": [
                {"name": "RDM_DOMAIN", "value": "http://rdm.local"},
                {"name": "RDM_API_DOMAIN", "value": "http://api.local"},
                {"name": "RDM_WATERBUTLER_URL", "value": "http://wb.local"},
            ],
            "delegationTokens": {
                "creator": {
                    "tokenValue": "token",
                    "tokenOwner": "owner",
                    "mode": "read",
                }
            },
        }

        with TestClient(self.app) as client:
            response = client.post("/flowable/process-instances", json=payload)

        self.assertEqual(response.status_code, 502)

        session = database_module.SessionLocal()
        try:
            tokens = session.query(models_module.DelegationToken).all()
        finally:
            session.close()
        self.assertEqual(tokens, [], "delegation tokens must not persist after Flowable failure")

    def test_rejects_rdm_domain_not_in_allowlist(self):
        main_module.get_flowable_client = lambda: _SuccessfulFlowableClient()
        payload = {
            "processDefinitionId": "publication:1",
            "variables": [
                {"name": "RDM_DOMAIN", "value": "http://evil.local"},
                {"name": "RDM_API_DOMAIN", "value": "http://api.local"},
                {"name": "RDM_WATERBUTLER_URL", "value": "http://wb.local"},
            ],
            "delegationTokens": {
                "creator": {
                    "tokenValue": "token",
                    "tokenOwner": "owner",
                    "mode": "read",
                }
            },
        }

        with TestClient(self.app) as client:
            response = client.post("/flowable/process-instances", json=payload)

        self.assertEqual(response.status_code, 400)
        detail = response.json().get("detail") or {}
        self.assertIn("allowlisted", detail.get("message", ""))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
