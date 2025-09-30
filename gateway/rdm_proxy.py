"""RDM proxy endpoint for Flowable workflows."""
import logging
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

    return WaterButlerPathResponse(
        provider=provider_name,
        node_id=node_id,
        materialized_path=resolved_materialized,
        path=wb_path,
        is_folder=is_folder,
        name=name,
        waterbutler_url=waterbutler_url,
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

    headers = dict(request.headers)
    headers["Authorization"] = f"Bearer {token_value}"
    headers.pop("host", None)

    body = await request.body() if request.method not in {"GET", "HEAD", "OPTIONS"} else None

    async with httpx.AsyncClient() as client:
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

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=dict(response.headers),
    )
