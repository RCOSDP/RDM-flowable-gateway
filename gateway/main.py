import io
import json
import logging
import mimetypes
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import Any, Dict, List

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from .auth import TokenContext, ensure_scope, require_token
from .database import get_db
from .flowable import FlowableError, get_flowable_client, translate_flowable_error
from .models import DelegationToken
from .rdm_proxy import router as rdm_proxy_router
from .schemas import DelegationTokenData, RestVariable, StartProcessRequest, TaskActionRequest
from .settings import get_settings
from .signing import SigningConfigurationError, get_public_key_pem

logger = logging.getLogger(__name__)
settings = get_settings()
app = FastAPI(title="RDM Flowable Gateway")
app.include_router(rdm_proxy_router)


def _build_proxy_variables(
    process_instance_id: str,
    delegation_tokens: Dict[str, DelegationTokenData],
) -> List[RestVariable]:
    """Build proxy URL variables for Flowable.

    For each role with a token, creates:
    - RDM_<ROLE>_MODE: token mode (read/readwrite)
    - RDM_<ROLE>_TOKEN_OWNER: user ID who owns the token
    - RDM_<ROLE>_WEB_URL: proxy URL for RDM web interface
    - RDM_<ROLE>_API_URL: proxy URL for RDM API
    - RDM_<ROLE>_WATERBUTLER_URL: proxy URL for WaterButler
    """
    variables: List[RestVariable] = []
    roles = ["creator", "manager", "executor"]

    service_map = {
        "WEB": "web",
        "API": "api",
        "WATERBUTLER": "waterbutler",
        "WATERBUTLER_PATH": "waterbutler-path",
    }

    for role in roles:
        token_data = delegation_tokens.get(role)
        if token_data:
            variables.append(RestVariable(
                name=f"RDM_{role.upper()}_MODE",
                type="string",
                value=token_data.mode,
            ))
            variables.append(RestVariable(
                name=f"RDM_{role.upper()}_TOKEN_OWNER",
                type="string",
                value=token_data.token_owner,
            ))

            for suffix, service_path in service_map.items():
                variables.append(RestVariable(
                    name=f"RDM_{role.upper()}_{suffix}_URL",
                    type="string",
                    value=f"{settings.gateway_internal_url}/rdm/{process_instance_id}/{role}/{service_path}",
                ))

    return variables


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.error(f"Validation error: {exc.errors()}", exc_info=True)
    return JSONResponse(
        status_code=400,
        content={"detail": exc.errors()}
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)}
    )


@app.get("/healthz", response_model=Dict[str, Any])
def healthcheck() -> Dict[str, Any]:
    """Expose a simple health endpoint for container orchestration."""
    return {"status": "ok"}


@app.get("/config", response_model=Dict[str, Any])
def config(context: TokenContext = Depends(require_token)) -> Dict[str, Any]:
    """Surface gateway configuration for quick inspection during bootstrapping."""
    return {
        "flowableRestBaseUrl": settings.flowable_rest_base_url,
        "subject": context.subject,
        "scopes": context.scopes,
        "engineId": context.engine_id,
        "keyId": context.key_id,
    }


@app.get("/keyset", response_model=Dict[str, Any])
def gateway_keyset() -> Dict[str, Any]:
    """Expose the gateway's public keyset for RDM registration."""

    if not settings.signing_key_id:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GATEWAY_SIGNING_KEY_ID must be set to publish the gateway keyset",
        )

    try:
        public_key = get_public_key_pem()
    except SigningConfigurationError as error:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(error)) from error

    return {
        "keys": [
            {
                "kid": settings.signing_key_id,
                "alg": settings.jwt_algorithm,
                "public_key": public_key,
            }
        ]
    }


def _get_query_params(request: Request) -> Dict[str, Any]:
    return dict(request.query_params.multi_items())


@app.get("/flowable/process-definitions", response_model=Dict[str, Any])
async def list_process_definitions(
    request: Request,
    context: TokenContext = Depends(require_token),
) -> Dict[str, Any]:
    ensure_scope(context, "workflow::delegate")
    client = get_flowable_client()
    try:
        return await client.list_process_definitions(_get_query_params(request) or None)
    except FlowableError as error:
        raise translate_flowable_error(error)


@app.get("/flowable/process-definitions/{definition_id}", response_model=Dict[str, Any])
async def get_process_definition(
    definition_id: str,
    context: TokenContext = Depends(require_token),
) -> Dict[str, Any]:
    ensure_scope(context, "workflow::delegate")
    client = get_flowable_client()
    try:
        payload = await client.get_process_definition(definition_id)
    except FlowableError as error:
        raise translate_flowable_error(error)
    if not isinstance(payload, dict):
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            detail={"message": "Flowable returned unexpected payload for definition lookup."},
        )
    return payload


@app.get("/flowable/process-definitions/{definition_id}/start-form", response_model=Dict[str, Any])
async def get_process_definition_start_form(
    definition_id: str,
    context: TokenContext = Depends(require_token),
) -> Dict[str, Any]:
    ensure_scope(context, "workflow::delegate")
    client = get_flowable_client()
    try:
        payload = await client.get_process_definition_start_form(definition_id)
    except FlowableError as error:
        raise translate_flowable_error(error)
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            detail={"message": "Flowable returned unexpected payload for definition start form."},
        )

    # Form resolution proxy: resolve formKey if formProperties is empty
    form_key = payload.get('formKey')
    form_properties = payload.get('formProperties', [])
    deployment_id = payload.get('deploymentId')

    if form_key and not form_properties and deployment_id:
        form_json = await _resolve_form_from_deployment(client, deployment_id, form_key)
        payload['fields'] = form_json['editorJson']['fields']

    return payload


@app.get("/flowable/process-instances", response_model=Dict[str, Any])
async def list_process_instances(
    request: Request,
    context: TokenContext = Depends(require_token),
) -> Dict[str, Any]:
    ensure_scope(context, "workflow::delegate")
    client = get_flowable_client()
    try:
        return await client.list_process_instances(_get_query_params(request) or None)
    except FlowableError as error:
        raise translate_flowable_error(error)


@app.get("/flowable/process-instances/{instance_id}", response_model=Dict[str, Any])
async def get_process_instance(
    instance_id: str,
    request: Request,
    context: TokenContext = Depends(require_token),
) -> Dict[str, Any]:
    ensure_scope(context, "workflow::delegate")
    client = get_flowable_client()
    try:
        return await client.get_process_instance(instance_id, _get_query_params(request) or None)
    except FlowableError as error:
        raise translate_flowable_error(error)


@app.get("/flowable/history/historic-process-instances", response_model=Dict[str, Any])
async def list_historic_process_instances(
    request: Request,
    context: TokenContext = Depends(require_token),
) -> Dict[str, Any]:
    ensure_scope(context, "workflow::delegate")
    client = get_flowable_client()
    try:
        return await client.list_historic_process_instances(_get_query_params(request) or None)
    except FlowableError as error:
        raise translate_flowable_error(error)


@app.get("/flowable/history/historic-task-instances", response_model=Dict[str, Any])
async def list_historic_tasks(
    request: Request,
    context: TokenContext = Depends(require_token),
) -> Dict[str, Any]:
    ensure_scope(context, "workflow::delegate")
    client = get_flowable_client()
    try:
        return await client.list_historic_tasks(_get_query_params(request) or None)
    except FlowableError as error:
        raise translate_flowable_error(error)


@app.post("/flowable/process-instances", response_model=Dict[str, Any])
async def create_process_instance(
    payload: StartProcessRequest,
    context: TokenContext = Depends(require_token),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    ensure_scope(context, "workflow::delegate")
    client = get_flowable_client()

    gateway_request_id = None
    if payload.delegation_tokens:
        gateway_request_id = str(uuid.uuid4())

        rdm_domain = None
        rdm_api_domain = None
        rdm_waterbutler_url = None

        for var in payload.variables:
            if var.name == "RDM_DOMAIN":
                rdm_domain = var.value
            elif var.name == "RDM_API_DOMAIN":
                rdm_api_domain = var.value
            elif var.name == "RDM_WATERBUTLER_URL":
                rdm_waterbutler_url = var.value

        proxy_variables = _build_proxy_variables(gateway_request_id, payload.delegation_tokens)
        payload.variables.extend(proxy_variables)

        delegation = DelegationToken(
            gateway_request_id=gateway_request_id,
            process_instance_id=None,
            rdm_domain=rdm_domain,
            rdm_api_domain=rdm_api_domain,
            rdm_waterbutler_url=rdm_waterbutler_url,
        )

        for role, token_data in payload.delegation_tokens.items():
            setattr(delegation, f"{role}_token", token_data.token_value)
            setattr(delegation, f"{role}_owner", token_data.token_owner)

        db.add(delegation)
        db.commit()

    try:
        response = await client.start_process(payload.to_flowable_payload())
    except FlowableError as error:
        raise translate_flowable_error(error)

    process_instance_id = response["id"]

    if gateway_request_id:
        delegation = db.query(DelegationToken).filter(DelegationToken.gateway_request_id == gateway_request_id).first()
        delegation.process_instance_id = process_instance_id
        db.commit()

    return response


@app.delete("/flowable/process-instances/{instance_id}")
async def terminate_process_instance(
    instance_id: str,
    request: Request,
    context: TokenContext = Depends(require_token),
) -> None:
    ensure_scope(context, "workflow::delegate")
    client = get_flowable_client()
    try:
        params = _get_query_params(request) or {}
        reason = params.get('deleteReason')
        cascade = params.get('cascade') == 'true'
        await client.terminate_process(instance_id, reason=reason, cascade=cascade)
    except FlowableError as error:
        raise translate_flowable_error(error)


@app.get("/flowable/tasks", response_model=Dict[str, Any])
async def list_tasks(
    request: Request,
    context: TokenContext = Depends(require_token),
) -> Dict[str, Any]:
    ensure_scope(context, "workflow::delegate")
    client = get_flowable_client()
    params = _get_query_params(request)
    business_key = params.pop("businessKey", None)

    try:
        if business_key:
            instances = await client.list_process_instances({"businessKey": business_key})
            data = instances.get("data", []) if isinstance(instances, dict) else []
            instance_ids = [item.get("id") for item in data if item.get("id")]
            aggregated: Dict[str, Any] = {"data": [], "total": 0, "start": 0, "size": 0}
            for instance_id in instance_ids:
                per_params = dict(params)
                per_params["processInstanceId"] = instance_id
                task_response = await client.list_tasks(per_params)
                if isinstance(task_response, dict):
                    aggregated["data"].extend(task_response.get("data", []))
            aggregated["total"] = len(aggregated["data"])
            aggregated["size"] = aggregated["total"]
            return aggregated
        return await client.list_tasks(params or None)
    except FlowableError as error:
        raise translate_flowable_error(error)


@app.get("/flowable/tasks/{task_id}", response_model=Dict[str, Any])
async def get_task(
    task_id: str,
    context: TokenContext = Depends(require_token),
) -> Dict[str, Any]:
    ensure_scope(context, "workflow::delegate")
    client = get_flowable_client()
    try:
        response = await client.get_task(task_id)
    except FlowableError as error:
        raise translate_flowable_error(error)
    if isinstance(response, dict):
        return response
    return {"data": response}


@app.get("/flowable/history/historic-process-instances/{instance_id}", response_model=Dict[str, Any])
async def get_historic_process_instance(
    instance_id: str,
    context: TokenContext = Depends(require_token),
) -> Dict[str, Any]:
    ensure_scope(context, "workflow::delegate")
    client = get_flowable_client()
    try:
        payload = await client.get_historic_process_instance(instance_id)
    except FlowableError as error:
        raise translate_flowable_error(error)
    if isinstance(payload, dict):
        return payload
    return {"data": payload}


@app.post("/flowable/tasks/{task_id}", response_model=Dict[str, Any])
async def update_task(
    task_id: str,
    payload: TaskActionRequest,
    context: TokenContext = Depends(require_token),
) -> Dict[str, Any]:
    ensure_scope(context, "workflow::delegate")
    client = get_flowable_client()
    try:
        await client.update_task(task_id, payload.to_flowable_payload())
    except FlowableError as error:
        raise translate_flowable_error(error)
    return {"status": "accepted"}


@app.get("/flowable/tasks/{task_id}/form", response_model=Dict[str, Any])
async def get_task_form(
    task_id: str,
    context: TokenContext = Depends(require_token),
) -> Dict[str, Any]:
    ensure_scope(context, "workflow::delegate")
    client = get_flowable_client()
    try:
        response = await client.get_task_form(task_id)
    except FlowableError as error:
        raise translate_flowable_error(error)

    # Form resolution proxy: resolve formKey if formProperties is empty
    form_key = response.get('formKey')
    form_properties = response.get('formProperties', [])
    deployment_id = response.get('deploymentId')

    if form_key and not form_properties and deployment_id:
        form_json = await _resolve_form_from_deployment(client, deployment_id, form_key)
        response['fields'] = form_json['editorJson']['fields']

    return response


async def _resolve_form_from_deployment(client, deployment_id: str, form_key: str) -> Dict[str, Any]:
    """Resolve form definition from Flowable deployment resources."""
    resource_name = f'form-models-{form_key}.json'
    form_json = await client.get_deployment_resource_data(deployment_id, resource_name)
    return form_json


def _detect_content_type(path: Path) -> str:
    """Detect content type for a file based on extension."""
    content_type, _ = mimetypes.guess_type(path.name)
    if content_type:
        return content_type
    if path.suffix in {'.xml', '.bpmn', '.bpmn20', '.bpmn20.xml'}:
        return 'application/xml'
    if path.suffix in {'.json', '.form'}:
        return 'application/json'
    return 'application/octet-stream'


@app.post("/flowable/deployments", response_model=Dict[str, Any])
async def deploy_workflow(
    file: UploadFile = File(...),
    deploymentName: str = Form(...),
    category: str = Form('rdm'),
    enableDuplicateFiltering: str = Form('true'),
    context: TokenContext = Depends(require_token),
) -> Dict[str, Any]:
    """Deploy workflow ZIP to Flowable."""
    ensure_scope(context, "workflow::delegate")

    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='No file provided'
        )

    if not file.filename.endswith('.zip'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Only ZIP files are supported'
        )

    content = await file.read()

    try:
        with zipfile.ZipFile(io.BytesIO(content), 'r') as zf:
            zf.testzip()
    except zipfile.BadZipFile as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Invalid ZIP file'
        ) from error

    files = [('file', (file.filename, content, 'application/zip'))]

    client = get_flowable_client()
    try:
        response = await client.deploy_workflow(
            files=files,
            deployment_name=deploymentName,
            category=category,
            enable_duplicate_filtering=(enableDuplicateFiltering.lower() in {'true', '1', 'yes'}),
        )
    except FlowableError as error:
        raise translate_flowable_error(error)

    return response
