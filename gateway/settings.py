from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

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
    asice_private_key_path: Path | None
    asice_certificate_path: Path | None
    asice_tsa_url: str | None
    asice_tsa_certificate_path: Path | None
    http_timeout_seconds: float
    allowed_rdm_domains: tuple[str, ...]
    allowed_rdm_api_domains: tuple[str, ...]
    allowed_rdm_waterbutler_urls: tuple[str, ...]


def normalize_base_url(value: str) -> str:
    """Normalize a base URL to scheme://host[:port]."""

    candidate = value.strip()
    if not candidate:
        raise ValueError("URL must not be empty")

    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL must use http or https")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")
    if parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("URL must not include a path, query, or fragment")

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower()
    port = parsed.port
    default_port = 80 if scheme == "http" else 443

    if port is None or port == default_port:
        return f"{scheme}://{hostname}"
    return f"{scheme}://{hostname}:{port}"


def _load_allowed_urls(env_name: str) -> tuple[str, ...]:
    raw = os.environ.get(env_name)
    if not raw:
        raise RuntimeError(f"Environment variable {env_name} must list allowed URLs")

    entries = []
    for part in raw.split(','):
        candidate = part.strip()
        if not candidate:
            continue
        try:
            entries.append(normalize_base_url(candidate))
        except ValueError as error:
            raise RuntimeError(f"{env_name} entry '{candidate}' is invalid: {error}") from error

    if not entries:
        raise RuntimeError(f"Environment variable {env_name} must list at least one allowed URL")

    return tuple(entries)


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

    asice_private_key = os.environ.get("ASICE_PRIVATE_KEY_PATH")
    asice_certificate = os.environ.get("ASICE_CERTIFICATE_PATH")
    asice_tsa_url = os.environ.get("ASICE_TSA_URL")
    asice_tsa_certificate = os.environ.get("ASICE_TSA_CERTIFICATE_PATH")

    asice_private_key_path = Path(asice_private_key) if asice_private_key else None
    asice_certificate_path = Path(asice_certificate) if asice_certificate else None
    asice_tsa_certificate_path = Path(asice_tsa_certificate) if asice_tsa_certificate else None
    http_timeout_seconds = float(os.environ.get("GATEWAY_HTTP_TIMEOUT", "30"))
    allowed_rdm_domains = _load_allowed_urls("RDM_ALLOWED_DOMAINS")
    allowed_rdm_api_domains = _load_allowed_urls("RDM_ALLOWED_API_DOMAINS")
    allowed_rdm_waterbutler_urls = _load_allowed_urls("RDM_ALLOWED_WATERBUTLER_URLS")

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
        asice_private_key_path=asice_private_key_path,
        asice_certificate_path=asice_certificate_path,
        asice_tsa_url=asice_tsa_url,
        asice_tsa_certificate_path=asice_tsa_certificate_path,
        http_timeout_seconds=http_timeout_seconds,
        allowed_rdm_domains=allowed_rdm_domains,
        allowed_rdm_api_domains=allowed_rdm_api_domains,
        allowed_rdm_waterbutler_urls=allowed_rdm_waterbutler_urls,
    )


@lru_cache(maxsize=1)
def get_keyset() -> KeySet:
    settings = get_settings()
    if settings.keyset_url:
        return load_keyset_from_url(settings.keyset_url)
    return load_keyset_from_path(settings.keyset_path)
