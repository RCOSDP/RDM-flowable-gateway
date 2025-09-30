from __future__ import annotations

import json
from functools import lru_cache
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import httpx

from fastapi import HTTPException, status

from .settings import get_settings


class FlowableError(Exception):
    """Represents an error returned from the Flowable REST API."""

    def __init__(self, status_code: int, detail: str | Dict[str, Any]):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class FlowableClient:
    """Thin async wrapper around the Flowable REST API."""

    def __init__(
        self,
        *,
        base_url: str,
        username: str,
        password: str,
        timeout: float = 10.0,
    ) -> None:
        if not base_url:
            raise ValueError("Flowable base URL must be configured")
        if not username or not password:
            raise ValueError("Flowable credentials must be configured")

        self._base_url = base_url if base_url.endswith('/') else f"{base_url}/"
        self._username = username
        self._password = password
        self._timeout = timeout

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = urljoin(self._base_url, path)
        try:
            async with httpx.AsyncClient(
                auth=(self._username, self._password),
                timeout=self._timeout,
            ) as client:
                response = await client.request(method, url, params=params, json=json)
                response.raise_for_status()
        except httpx.HTTPStatusError as error:
            detail: Any
            try:
                detail = error.response.json()
            except ValueError:
                detail = error.response.text
            raise FlowableError(error.response.status_code, detail) from error
        except httpx.RequestError as error:
            raise FlowableError(
                status.HTTP_502_BAD_GATEWAY,
                f"Failed to contact Flowable: {error}"
            ) from error

        if response.status_code == status.HTTP_204_NO_CONTENT:
            return None
        if not response.content:
            return None
        if 'json' in response.headers.get('Content-Type', '').lower():
            return response.json()
        return response.text


    async def get_process_definition(self, definition_id: str) -> Any:
        return await self._request('GET', f'service/repository/process-definitions/{definition_id}')

    async def get_process_definition_start_form(self, definition_id: str) -> Any:
        return await self._request(
            'GET',
            'service/form/form-data',
            params={'processDefinitionId': definition_id},
        )

    async def terminate_process(
        self,
        instance_id: str,
        *,
        reason: Optional[str] = None,
        cascade: bool = False,
    ) -> None:
        params: Dict[str, Any] = {}
        if reason:
            params['deleteReason'] = reason
        if cascade:
            params['cascade'] = 'true'
        await self._request(
            'DELETE',
            f'service/runtime/process-instances/{instance_id}',
            params=params or None,
        )

    async def get_task(self, task_id: str) -> Any:
        return await self._request('GET', f'service/runtime/tasks/{task_id}')

    async def get_task_form(self, task_id: str) -> Any:
        return await self._request(
            'GET',
            'service/form/form-data',
            params={'taskId': task_id},
        )

    async def get_historic_process_instance(self, instance_id: str) -> Any:
        return await self._request(
            'GET',
            f'service/history/historic-process-instances/{instance_id}',
        )

    async def get_deployment_resource_data(self, deployment_id: str, resource_name: str) -> Any:
        result = await self._request(
            'GET',
            f'service/repository/deployments/{deployment_id}/resourcedata/{resource_name}',
        )
        # Resource data may be returned as text even for JSON content
        if isinstance(result, str):
            return json.loads(result)
        return result

    async def list_process_definitions(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return await self._request('GET', 'service/repository/process-definitions', params=params)

    async def list_process_instances(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return await self._request('GET', 'service/runtime/process-instances', params=params)

    async def get_process_instance(self, instance_id: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return await self._request('GET', f'service/runtime/process-instances/{instance_id}', params=params)

    async def start_process(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self._request('POST', 'service/runtime/process-instances', json=payload)

    async def list_tasks(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return await self._request('GET', 'service/runtime/tasks', params=params)

    async def list_historic_process_instances(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return await self._request('GET', 'service/history/historic-process-instances', params=params)

    async def list_historic_tasks(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return await self._request('GET', 'service/history/historic-task-instances', params=params)

    async def update_task(self, task_id: str, payload: Dict[str, Any]) -> None:
        await self._request('POST', f'service/runtime/tasks/{task_id}', json=payload)

    async def deploy_workflow(
        self,
        *,
        files: list[tuple[str, tuple[str, bytes, str]]],
        deployment_name: str,
        category: Optional[str] = None,
        enable_duplicate_filtering: bool = True,
    ) -> Dict[str, Any]:
        """Deploy BPMN and form files to Flowable.

        Args:
            files: List of (field_name, (filename, content, content_type)) tuples
            deployment_name: Name for the deployment
            category: Optional category label
            enable_duplicate_filtering: Whether to enable duplicate filtering

        Returns:
            Deployment response from Flowable
        """
        url = urljoin(self._base_url, 'service/repository/deployments')
        data: Dict[str, str] = {'deploymentName': deployment_name}
        if category:
            data['category'] = category
        if enable_duplicate_filtering:
            data['enableDuplicateFiltering'] = 'true'

        try:
            async with httpx.AsyncClient(
                auth=(self._username, self._password),
                timeout=self._timeout,
            ) as client:
                response = await client.post(url, data=data, files=files)
                response.raise_for_status()
        except httpx.HTTPStatusError as error:
            detail: Any
            try:
                detail = error.response.json()
            except ValueError:
                detail = error.response.text
            raise FlowableError(error.response.status_code, detail) from error
        except httpx.RequestError as error:
            raise FlowableError(
                status.HTTP_502_BAD_GATEWAY,
                f"Failed to contact Flowable: {error}"
            ) from error

        if 'json' in response.headers.get('Content-Type', '').lower():
            return response.json()
        raise FlowableError(
            status.HTTP_502_BAD_GATEWAY,
            'Flowable deployment response missing JSON content'
        )


@lru_cache(maxsize=1)
def get_flowable_client() -> FlowableClient:
    settings = get_settings()
    return FlowableClient(
        base_url=settings.flowable_rest_base_url,
        username=settings.flowable_rest_username,
        password=settings.flowable_rest_password,
    )


def translate_flowable_error(error: FlowableError) -> HTTPException:
    if isinstance(error.detail, (dict, list)):
        detail = error.detail
    else:
        detail = {'message': str(error.detail)}
    return HTTPException(status_code=error.status_code, detail=detail)
