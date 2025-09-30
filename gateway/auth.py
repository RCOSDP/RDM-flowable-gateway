from __future__ import annotations

from typing import Any, Dict, List

import logging

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from .keyset import KeyRecord
from .settings import get_keyset, get_settings

_bearer_scheme = HTTPBearer(auto_error=False)

logger = logging.getLogger(__name__)


class TokenContext(BaseModel):
    subject: str
    scopes: List[str]
    claims: Dict[str, Any]
    engine_id: str | None
    key_id: str


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _forbidden(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=detail,
    )


def _extract_scopes(scope_claim: Any) -> List[str]:
    if scope_claim is None:
        return []
    if isinstance(scope_claim, str):
        return [entry for entry in scope_claim.split() if entry]
    if isinstance(scope_claim, list):
        return [str(entry) for entry in scope_claim if entry]
    logger.warning("Invalid scope claim", extra={"scope": scope_claim})
    raise _unauthorized("Invalid scope claim")


def require_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> TokenContext:
    if credentials is None:
        raise _unauthorized("Missing bearer token")

    raw_header = f'{credentials.scheme} {credentials.credentials}' if credentials.scheme else credentials.credentials
    # Authorization header is intentionally not logged for security reasons.
    token = credentials.credentials
    settings = get_settings()

    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as error:
        logger.warning("Token header decode failed", exc_info=error)
        raise _unauthorized("Malformed token header") from error

    kid = header.get("kid")
    if not kid:
        logger.warning("Token missing kid header")
        raise _unauthorized("Token header missing kid")

    try:
        key_record: KeyRecord = get_keyset().get(kid)
    except KeyError as error:
        logger.warning("Unknown key id", extra={"kid": kid})
        raise _unauthorized("Unknown key id") from error

    decode_kwargs: Dict[str, Any] = {
        "algorithms": [key_record.algorithm],
        "issuer": settings.jwt_issuer,
    }
    if settings.jwt_audience:
        decode_kwargs["audience"] = settings.jwt_audience
    else:
        decode_kwargs.setdefault("options", {})["verify_aud"] = False

    verify_key = key_record.public_key

    try:
        payload = jwt.decode(token, verify_key, **decode_kwargs)
    except jwt.ExpiredSignatureError as error:
        logger.warning("Token expired", extra={"kid": kid})
        raise _unauthorized("Token expired") from error
    except jwt.InvalidTokenError as error:
        logger.warning("Token signature invalid", extra={"kid": kid})
        raise _unauthorized("Invalid token") from error

    subject = payload.get("sub")
    if not subject:
        logger.warning("Token missing subject", extra={"kid": kid})
        raise _unauthorized("Token missing subject")

    engine_claim_value = None
    if settings.engine_claim:
        engine_claim_value = payload.get(settings.engine_claim)
        if engine_claim_value is None:
            logger.warning("Token missing engine claim", extra={"kid": kid, "claim": settings.engine_claim})
            raise _unauthorized("Token missing required engine claim")

    scopes = _extract_scopes(payload.get("scope"))

    return TokenContext(
        subject=str(subject),
        scopes=scopes,
        claims=payload,
        engine_id=str(engine_claim_value) if engine_claim_value is not None else None,
        key_id=key_record.kid,
    )


def ensure_scope(context: TokenContext, required_scope: str) -> None:
    if required_scope not in context.scopes:
        raise _forbidden(f"Missing required scope: {required_scope}")
