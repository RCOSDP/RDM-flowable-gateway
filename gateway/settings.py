from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .keyset import KeySet, load_keyset_from_path, load_keyset_from_url


@dataclass(frozen=True)
class Settings:
    flowable_rest_base_url: str
    flowable_rest_username: str
    flowable_rest_password: str
    keyset_path: Path
    keyset_url: str | None
    jwt_algorithm: str
    jwt_audience: str | None
    jwt_issuer: str | None
    engine_claim: str | None
    signing_key_id: str | None
    signing_private_key_path: Path | None
    gateway_internal_url: str
    debug_localhost_override: str | None


def _load_env(name: str) -> str:
    try:
        return os.environ[name]
    except KeyError as error:
        raise RuntimeError(f"Environment variable {name} must be set") from error


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    flowable_rest_base_url = _load_env("FLOWABLE_REST_BASE_URL")
    flowable_rest_username = _load_env("FLOWABLE_REST_APP_ADMIN_USER_ID")
    flowable_rest_password = _load_env("FLOWABLE_REST_APP_ADMIN_PASSWORD")
    keyset_path = Path(os.environ.get("RDM_KEYSET_PATH", "/app/config/keyset.example.json"))
    keyset_url = os.environ.get("RDM_KEYSET_URL")
    jwt_algorithm = os.environ.get("GATEWAY_DEFAULT_ALGORITHM", "RS256")
    jwt_audience = os.environ.get("GATEWAY_JWT_AUDIENCE")
    jwt_issuer = os.environ.get("GATEWAY_JWT_ISSUER")
    engine_claim = os.environ.get("GATEWAY_ENGINE_CLAIM")
    signing_key_id = os.environ.get("GATEWAY_SIGNING_KEY_ID")
    signing_private_key = os.environ.get("GATEWAY_SIGNING_PRIVATE_KEY_PATH")
    signing_private_key_path = Path(signing_private_key) if signing_private_key else None

    gateway_internal_url = _load_env("GATEWAY_INTERNAL_URL")
    debug_localhost_override = os.environ.get("DEBUG_LOCALHOST_OVERRIDE")

    return Settings(
        flowable_rest_base_url=flowable_rest_base_url,
        flowable_rest_username=flowable_rest_username,
        flowable_rest_password=flowable_rest_password,
        keyset_path=keyset_path,
        keyset_url=keyset_url,
        jwt_algorithm=jwt_algorithm,
        jwt_audience=jwt_audience,
        jwt_issuer=jwt_issuer,
        engine_claim=engine_claim,
        signing_key_id=signing_key_id,
        signing_private_key_path=signing_private_key_path,
        gateway_internal_url=gateway_internal_url,
        debug_localhost_override=debug_localhost_override,
    )


@lru_cache(maxsize=1)
def get_keyset() -> KeySet:
    settings = get_settings()
    if settings.keyset_url:
        return load_keyset_from_url(settings.keyset_url)
    return load_keyset_from_path(settings.keyset_path)
