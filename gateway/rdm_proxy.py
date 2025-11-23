"""RDM proxy endpoint for Flowable workflows."""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import MethodType
from typing import Optional
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from osfclient import OSF, exceptions as osf_exceptions
from osfclient.utils import find_by_path, norm_remote_path
from sqlalchemy.orm import Session
from weakref import WeakSet

from .database import get_db
from .models import DelegationToken
from .schemas import WaterButlerPathResponse
from .settings import get_settings

logger = logging.getLogger(__name__)
router = APIRouter()
settings = get_settings()
_patched_sessions: WeakSet = WeakSet()


@dataclass(frozen=True)
class AsiceConfig:
    key_path: Path
    certificate_path: Path
    tsa_url: str
    tsa_certificate_path: Path


def _apply_localhost_override(url: Optional[str]) -> Optional[str]:
    if not url:
        return url
    if settings.debug_localhost_override:
        return (
            url.replace("localhost", settings.debug_localhost_override)
               .replace("127.0.0.1", settings.debug_localhost_override)
        )
    return url


def _patch_osf_session_for_localhost(osf_client: OSF) -> None:
    """Ensure OSF session follows DEBUG_LOCALHOST_OVERRIDE for all requests."""
    if not settings.debug_localhost_override:
        return

    session = osf_client.session
    # Avoid wrapping twice if the same session is reused.
    if session in _patched_sessions:
        return

    def _rewrite_url(url):
        if url is None:
            return None
        url_str = str(url)
        rewritten = _apply_localhost_override(url_str)
        if isinstance(url, httpx.URL) and rewritten == url_str:
            return url
        return rewritten

    original_request = session.request

    async def patched_request(self, method, url, *args, **kwargs):
        return await original_request(method, _rewrite_url(url), *args, **kwargs)

    session.request = MethodType(patched_request, session)

    original_stream = session.stream

    def patched_stream(self, method, url, *args, **kwargs):
        return original_stream(method, _rewrite_url(url), *args, **kwargs)

    session.stream = MethodType(patched_stream, session)
    _patched_sessions.add(session)


_ROLE_NAMES = {"creator", "manager", "executor"}


def _get_asice_config() -> AsiceConfig:
    if not settings.asice_private_key_path or not settings.asice_private_key_path.is_file():
        logger.error("ASiC private key path is missing or unreadable", extra={"path": settings.asice_private_key_path})
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ASiC private key is not configured",
        )
    if not settings.asice_certificate_path or not settings.asice_certificate_path.is_file():
        logger.error("ASiC certificate path is missing or unreadable", extra={"path": settings.asice_certificate_path})
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ASiC certificate is not configured",
        )
    if not settings.asice_tsa_url:
        logger.error("ASiC TSA URL is not configured")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ASiC TSA URL is not configured",
        )
    if not settings.asice_tsa_certificate_path or not settings.asice_tsa_certificate_path.is_file():
        logger.error(
            "ASiC TSA certificate path is missing or unreadable",
            extra={"path": settings.asice_tsa_certificate_path},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ASiC TSA certificate is not configured",
        )

    return AsiceConfig(
        key_path=settings.asice_private_key_path,
        certificate_path=settings.asice_certificate_path,
        tsa_url=settings.asice_tsa_url,
        tsa_certificate_path=settings.asice_tsa_certificate_path,
    )


def _sanitize_filename(value: Optional[str], label: str) -> str:
    if not value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing {label}",
        )
    name = value.strip()
    if not name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing {label}",
        )
    if os.path.basename(name) != name or any(sep in name for sep in ("/", "\\")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {label}",
        )
    return name


async def _build_asice_archive(payload: bytes, filename: str, config: AsiceConfig) -> bytes:
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request payload is empty",
        )

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        payload_path = tmp_path / filename
        payload_path.write_bytes(payload)
        archive_path = tmp_path / "payload.asice"

        cmd = [
            sys.executable,
            "-m",
            "asice_cli.cli",
            "package",
            "--key",
            str(config.key_path),
            "--cert",
            str(config.certificate_path),
            "--tsa-url",
            config.tsa_url,
            "--tsa-cert",
            str(config.tsa_certificate_path),
            "--output",
            str(archive_path),
            str(payload_path),
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            logger.error(
                "ASiC packaging failed",
                extra={
                    "payload": filename,
                    "return_code": process.returncode,
                    "stdout": stdout.decode(errors="ignore"),
                    "stderr": stderr.decode(errors="ignore"),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to package ASiC payload",
            )

        return archive_path.read_bytes()


def _get_delegation_or_404(db: Session, request_id: str) -> DelegationToken:
    delegation = db.query(DelegationToken).filter(
        (DelegationToken.gateway_request_id == request_id) | (DelegationToken.process_instance_id == request_id)
    ).first()
    if not delegation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Request not found: {request_id}",
        )
    return delegation


def _get_role_token(delegation: DelegationToken, role: str) -> str:
    if role not in _ROLE_NAMES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role: {role}",
        )
    token_value = getattr(delegation, f"{role}_token")
    if not token_value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"No token available for role: {role}",
        )
    return token_value


def _normalize_materialized_path(materialized_path: Optional[str]) -> tuple[Optional[str], str]:
    if materialized_path is None:
        return None, '/'
    candidate = materialized_path.strip()
    if not candidate or candidate == '/':
        return None, '/'
    candidate = candidate.lstrip('/')
    candidate = f'/{candidate}'
    normalized = norm_remote_path(candidate)
    if not normalized:
        return None, '/'
    return normalized, candidate


async def _lookup_materialized_object(storage, normalized_path: Optional[str], display_path: str) -> tuple[str, str, bool, Optional[str]]:
    if normalized_path is None:
        wb_path = storage.path or '/'
        return wb_path, '/', True, storage.name

    target = await find_by_path(storage, normalized_path)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Path not found: {display_path}",
        )

    wb_path = target.osf_path

    materialized = target.path
    is_folder = hasattr(target, 'files')
    name = target.name
    return wb_path, materialized, is_folder, name


async def _proxy_asice_upload(
    *,
    request: Request,
    delegation: DelegationToken,
    token_value: str,
    path: str,
    request_id: str,
    role: str,
) -> Response:
    if request.method != "PUT":
        raise HTTPException(
            status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
            detail="ASiC service only supports PUT",
        )

    parts = path.split('/', 2)
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ASiC path must include node id and provider",
        )
    node_id, provider = parts[0], parts[1]
    wb_path = parts[2] if len(parts) == 3 else ''
    if not wb_path:
        wb_path = '/'
    elif not wb_path.startswith('/'):
        wb_path = f'/{wb_path}'

    config = _get_asice_config()
    payload_filename = _sanitize_filename(request.query_params.get("payload_filename"), "payload_filename")
    archive_name = _sanitize_filename(request.query_params.get("name"), "name")
    payload_bytes = await request.body()
    archive_bytes = await _build_asice_archive(payload_bytes, payload_filename, config)

    upload_params = dict(request.query_params)
    upload_params.pop("payload_filename", None)
    upload_params["name"] = archive_name
    upload_params.setdefault("kind", "file")

    base_url = _apply_localhost_override(delegation.rdm_waterbutler_url)
    if not base_url:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Delegation is missing RDM_WATERBUTLER_URL",
        )
    target_url = f"{base_url.rstrip('/')}/v1/resources/{node_id}/providers/{provider}{wb_path}"

    headers = {
        "Authorization": f"Bearer {token_value}",
        "Content-Type": "application/octet-stream",
    }

    timeout_seconds = settings.http_timeout_seconds
    timeout = httpx.Timeout(timeout_seconds)

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.put(
                target_url,
                params=upload_params,
                headers=headers,
                content=archive_bytes,
                follow_redirects=False,
            )
        except httpx.RequestError as error:
            logger.error(
                "ASiC upload failed",
                extra={
                    "request_id": request_id,
                    "role": role,
                    "node_id": node_id,
                    "provider": provider,
                    "path": wb_path,
                },
                exc_info=True,
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to contact WaterButler: {str(error)}",
            ) from error

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=dict(response.headers),
    )


async def _resolve_waterbutler_path(
    *,
    request_id: str,
    role: str,
    node_id: str,
    provider: str,
    materialized_path: Optional[str],
    db: Session,
) -> WaterButlerPathResponse:
    delegation = _get_delegation_or_404(db, request_id)
    token_value = _get_role_token(delegation, role)

    raw_api_url = _apply_localhost_override(delegation.rdm_api_domain)
    if not raw_api_url:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Delegation is missing RDM_API_DOMAIN",
        )
    api_base_url = f"{raw_api_url.rstrip('/')}/v2/"

    normalized_path, display_path = _normalize_materialized_path(materialized_path)
    provider_name = provider.lower()

    osf = OSF(token=token_value, base_url=api_base_url)
    _patch_osf_session_for_localhost(osf)
    base_proxy_url = f"{settings.gateway_internal_url.rstrip('/')}/rdm/{request_id}/{role}/waterbutler"

    try:
        project = await osf.project(node_id)
        storage = await project.storage(provider_name)
        wb_path, resolved_materialized, is_folder, name = await _lookup_materialized_object(
            storage,
            normalized_path,
            display_path,
        )
    except osf_exceptions.OSFException as error:
        logger.error(
            "OSF client error",
            extra={
                "node_id": node_id,
                "provider": provider_name,
                "api_base_url": api_base_url,
            },
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"RDM API rejected the request: {error}",
        ) from error
    except httpx.HTTPError as error:
        logger.error(
            "HTTP error while contacting RDM API",
            extra={
                "node_id": node_id,
                "provider": provider_name,
                "api_base_url": api_base_url,
            },
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to contact RDM API: {error}",
        ) from error
    except RuntimeError as error:
        logger.error(
            "Unexpected response from RDM API",
            extra={
                "node_id": node_id,
                "provider": provider_name,
                "api_base_url": api_base_url,
            },
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(error),
        ) from error
    finally:
        await osf.aclose()

    quoted_path = quote(wb_path, safe='/')
    waterbutler_url = f"{base_proxy_url}/v1/resources/{node_id}/providers/{provider_name}{quoted_path}"
    asice_base_url = f"{settings.gateway_internal_url.rstrip('/')}/rdm/{request_id}/{role}/asice"
    asice_url = f"{asice_base_url}/{node_id}/{provider_name}{quoted_path}"

    return WaterButlerPathResponse(
        provider=provider_name,
        node_id=node_id,
        materialized_path=resolved_materialized,
        path=wb_path,
        is_folder=is_folder,
        name=name,
        waterbutler_url=waterbutler_url,
        asice_url=asice_url,
    )


@router.api_route(
    "/rdm/{request_id}/{role}/{service}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def rdm_proxy(
    request_id: str,
    role: str,
    service: str,
    path: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Proxy requests from Flowable to RDM services with token authentication.

    Flowable workflows call this endpoint instead of RDM directly.
    Gateway retrieves stored token and forwards request with authentication.
    """
    delegation = _get_delegation_or_404(db, request_id)
    token_value = _get_role_token(delegation, role)

    if service == "waterbutler-path":
        parts = path.split('/', 2)
        if len(parts) < 2:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="WaterButler path resolution requires node id and provider",
            )
        node_id, provider = parts[0], parts[1]
        materialized = parts[2] if len(parts) == 3 else None
        if materialized == "":
            materialized = None
        result = await _resolve_waterbutler_path(
            request_id=request_id,
            role=role,
            node_id=node_id,
            provider=provider,
            materialized_path=materialized,
            db=db,
        )
        return JSONResponse(content=result.dict(by_alias=True))

    if service == "asice":
        return await _proxy_asice_upload(
            request=request,
            delegation=delegation,
            token_value=token_value,
            path=path,
            request_id=request_id,
            role=role,
        )

    logger.info(
        "RDM proxy request | request_id=%s role=%s service=%s method=%s path=%s content_type=%s",
        request_id,
        role,
        service,
        request.method,
        path,
        request.headers.get("content-type"),
    )

    service_url_map = {
        "web": _apply_localhost_override(delegation.rdm_domain),
        "api": _apply_localhost_override(delegation.rdm_api_domain),
        "waterbutler": _apply_localhost_override(delegation.rdm_waterbutler_url),
    }

    target_base_url = service_url_map.get(service)
    if not target_base_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No URL configured for service: {service}",
        )

    target_url = f"{target_base_url.rstrip('/')}/{path}"

    headers = {k: v for k, v in request.headers.items()}
    content_type = headers.get("content-type")
    headers["Authorization"] = f"Bearer {token_value}"
    headers.pop("host", None)

    body = await request.body() if request.method not in {"GET", "HEAD", "OPTIONS"} else None

    if request.method not in {"GET", "HEAD", "OPTIONS"} and (content_type or "").startswith("application/json"):
        logger.info(
            "RDM proxy request body | request_id=%s role=%s service=%s method=%s path=%s content_type=%s body=%s",
            request_id,
            role,
            service,
            request.method,
            path,
            content_type,
            body.decode("utf-8", errors="replace") if isinstance(body, (bytes, bytearray)) else body,
        )

    timeout_seconds = settings.http_timeout_seconds
    timeout = httpx.Timeout(timeout_seconds)

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                params=request.query_params,
                content=body,
                follow_redirects=False,
            )
        except httpx.RequestError as error:
            logger.error(f"Proxy request failed: {error}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to connect to RDM service: {str(error)}",
            ) from error

    upstream_content_type = response.headers.get("content-type")
    actual_length = len(response.content)
    response_headers = dict(response.headers)
    response_headers["content-length"] = str(actual_length)
    logger.info(
        "RDM proxy response | request_id=%s role=%s service=%s method=%s path=%s status=%s target_url=%s content_length=%s actual_length=%s content_type=%s",
        request_id,
        role,
        service,
        request.method,
        path,
        response.status_code,
        target_url,
        response_headers.get("content-length"),
        actual_length,
        upstream_content_type,
    )

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=response_headers,
    )
