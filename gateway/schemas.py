from __future__ import annotations

from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class RestVariable(BaseModel):
    name: str
    value: Any
    type: Optional[str] = None

    def to_flowable(self) -> dict:
        data = {'name': self.name, 'value': self.value}
        if self.type is not None:
            data['type'] = self.type
        return data


class DelegationTokenData(BaseModel):
    token_value: str = Field(alias='tokenValue')
    token_owner: str = Field(alias='tokenOwner')
    mode: str

    model_config = ConfigDict(populate_by_name=True)


class StartProcessRequest(BaseModel):
    process_definition_id: str = Field(alias='processDefinitionId')
    name: Optional[str] = None
    business_key: Optional[str] = Field(default=None, alias='businessKey')
    variables: List[RestVariable] = Field(default_factory=list)
    delegation_tokens: Optional[dict[str, DelegationTokenData]] = Field(default=None, alias='delegationTokens')

    model_config = ConfigDict(populate_by_name=True)

    def to_flowable_payload(self) -> dict:
        payload: dict = {
            'processDefinitionId': self.process_definition_id,
        }
        if self.name:
            payload['name'] = self.name
        if self.business_key:
            payload['businessKey'] = self.business_key
        if self.variables:
            payload['variables'] = [variable.to_flowable() for variable in self.variables]
        return payload


class TaskActionRequest(BaseModel):
    action: str = 'complete'
    variables: List[RestVariable] = Field(default_factory=list)

    def to_flowable_payload(self) -> dict:
        payload = {'action': self.action}
        if self.variables:
            payload['variables'] = [variable.to_flowable() for variable in self.variables]
        return payload


class WaterButlerPathResponse(BaseModel):
    provider: str
    node_id: str = Field(alias='nodeId')
    materialized_path: str = Field(alias='materializedPath')
    path: str
    is_folder: bool = Field(alias='isFolder')
    name: Optional[str] = None
    waterbutler_url: str = Field(alias='waterbutlerUrl')
    asice_url: Optional[str] = Field(default=None, alias='asiceUrl')

    model_config = ConfigDict(populate_by_name=True)
