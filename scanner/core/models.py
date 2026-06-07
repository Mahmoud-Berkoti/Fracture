"""Pydantic v2 models for Fracture.

Two model families live here:
  - `Finding` and `ScanResult` describe scanner *output*.
  - `TargetConfig` and its children describe scanner *input* (YAML config).

Section 5.2 of the spec sketches Finding as a @dataclass; section 10
overrides that with "All data models use pydantic v2". This file follows
section 10.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


Severity = Literal["critical", "high", "medium", "low", "info"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --- scanner output ----------------------------------------------------------


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    module: str
    severity: Severity
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    cwe_id: Optional[str] = None
    reproduction_steps: list[str] = Field(default_factory=list)
    remediation: str
    target: Optional[str] = None
    endpoint: Optional[str] = None
    discovered_at: datetime = Field(default_factory=_utcnow)


class ScanResult(BaseModel):
    """Everything the reporter needs to render the HTML + JSONL."""

    target: str
    base_url: str
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    modules_run: list[str]
    findings: list[Finding]


# --- target config (parsed from YAML) ----------------------------------------


class Credential(BaseModel):
    username: str
    password: str


class AuthConfig(BaseModel):
    type: str = "jwt"
    login_endpoint: str
    credentials: list[Credential]


class BolaEndpoint(BaseModel):
    path: str
    method: str = "GET"
    id_param: str = "id"
    create_path: Optional[str] = None
    create_body: dict[str, Any] = Field(default_factory=dict)
    # Alternative probe mode: the victim's user_id is itself the path id
    # (e.g. `/v1/customers/{id}/subscriptions` where {id} is a customer id).
    # When true, the create step is skipped and the owner's user_id from
    # the session context is substituted directly. Requires >=2 logins.
    use_victim_user_id: bool = False


class BolaModuleConfig(BaseModel):
    enabled: bool = True
    endpoints: list[BolaEndpoint] = Field(default_factory=list)


class BootstrapRequest(BaseModel):
    """One-shot setup request issued before a race salvo.

    Use it when the salvo body references a `{placeholder}` that must be
    minted fresh per scan (e.g. a brand-new charge_id to refund). The
    `capture` map pulls dotted JSON paths out of the bootstrap response
    and exposes them as template variables for the salvo body.
    """

    method: str = "POST"
    path: str
    body: dict[str, Any] = Field(default_factory=dict)
    capture: dict[str, str] = Field(default_factory=dict)


class RaceEndpoint(BaseModel):
    path: str
    method: str = "POST"
    body: dict[str, Any] = Field(default_factory=dict)
    bootstrap: Optional[BootstrapRequest] = None


class RaceModuleConfig(BaseModel):
    enabled: bool = True
    concurrency: int = 20
    endpoints: list[RaceEndpoint] = Field(default_factory=list)


class AuthEndpoint(BaseModel):
    path: str
    method: str = "GET"


class AuthModuleConfig(BaseModel):
    enabled: bool = True
    endpoints: list[AuthEndpoint] = Field(default_factory=list)


class BusinessLogicEndpoint(BaseModel):
    path: str
    method: str = "POST"


class BusinessLogicModuleConfig(BaseModel):
    enabled: bool = True
    endpoints: list[BusinessLogicEndpoint] = Field(default_factory=list)


class WebhookModuleConfig(BaseModel):
    enabled: bool = True
    endpoint: str
    secret: str


class ModulesConfig(BaseModel):
    bola: Optional[BolaModuleConfig] = None
    race: Optional[RaceModuleConfig] = None
    auth: Optional[AuthModuleConfig] = None
    business_logic: Optional[BusinessLogicModuleConfig] = None
    webhook: Optional[WebhookModuleConfig] = None


class TargetConfig(BaseModel):
    name: str
    base_url: str
    auth: AuthConfig
    modules: ModulesConfig
