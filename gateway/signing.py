from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

import jwt
from cryptography.hazmat.primitives import serialization

from .settings import get_settings


class SigningConfigurationError(RuntimeError):
    """Raised when signing configuration is incomplete."""


def _read_private_key(path: Path) -> str:
    if not path.exists():
        raise SigningConfigurationError(f"Gateway signing key not found: {path}")
    try:
        return path.read_text()
    except OSError as error:
        raise SigningConfigurationError(f"Failed to read signing key: {path}") from error


@lru_cache(maxsize=1)
def _get_private_key() -> str:
    settings = get_settings()
    if settings.signing_private_key_path is None:
        raise SigningConfigurationError("GATEWAY_SIGNING_PRIVATE_KEY_PATH must be set to sign tokens")
    return _read_private_key(settings.signing_private_key_path)


def issue_gateway_token(claims: Dict[str, Any], headers: Dict[str, Any] | None = None) -> str:
    """Sign a JWT that the gateway can present to RDM.

    Raises :class:`SigningConfigurationError` if the signing key is not configured.
    """

    settings = get_settings()
    if settings.signing_key_id is None:
        raise SigningConfigurationError("GATEWAY_SIGNING_KEY_ID must be set to sign tokens")

    token_headers = dict(headers or {})
    token_headers.setdefault("kid", settings.signing_key_id)

    private_key = _get_private_key()

    return jwt.encode(
        claims,
        private_key,
        algorithm=settings.jwt_algorithm,
        headers=token_headers,
    )


def get_public_key_pem() -> str:
    """Derive the PEM-encoded public key corresponding to the configured signing key."""

    try:
        private_key = serialization.load_pem_private_key(
            _get_private_key().encode('utf-8'),
            password=None,
        )
    except ValueError as error:
        raise SigningConfigurationError("Configured signing key is not a valid PEM private key") from error

    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8').strip()
