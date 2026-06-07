"""BOLA / IDOR attack module - section 5.4 of the spec.

Per-endpoint pattern:
  1. User A POSTs to `create_path` with `create_body` and captures the
     `id` field from the response.
  2. User B issues the configured request against `path` with that id
     substituted in for `{id_param}`.
  3. HTTP 200 + non-empty body = the endpoint failed to enforce
     per-request ownership. Reported as CWE-639, severity critical.

The two users are taken from the first two credentials in the target
config - *not* hardcoded "alice" / "bob" - so the same module works
against any target that supplies at least two logins.

Endpoints without `create_path` are skipped with a warning: without a way
to mint a victim resource we can't tell the difference between "404 for
missing resource" and "404 because ownership is enforced".
"""
from __future__ import annotations

from typing import Any

import httpx
import structlog

from core.models import BolaEndpoint, BolaModuleConfig, Finding
from core.session import ScanContext

log = structlog.get_logger(__name__)


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return resp.text[:500]


def _substitute_id(path: str, id_param: str, resource_id: str) -> str:
    placeholder = "{" + id_param + "}"
    if placeholder in path:
        return path.replace(placeholder, resource_id)
    # Fallback for paths declared without an explicit placeholder.
    return path.rstrip("/") + "/" + resource_id


async def _probe_endpoint(
    endpoint: BolaEndpoint,
    ctx: ScanContext,
    owner_name: str,
    attacker_name: str,
) -> list[Finding]:
    attacker_session = ctx.sessions[attacker_name]
    owner_id = ctx.user_ids.get(owner_name, "<unknown>")
    attacker_id = ctx.user_ids.get(attacker_name, "<unknown>")
    resource_id: str | None = None

    if endpoint.use_victim_user_id:
        # No create step - the owner's user_id IS the path id.
        if not owner_id or owner_id == "<unknown>":
            log.warning(
                "bola_skip_no_owner_id",
                endpoint=endpoint.path,
                reason="use_victim_user_id requires the owner's user_id to be known",
            )
            return []
        resource_id = owner_id
    elif endpoint.create_path:
        owner_session = ctx.sessions[owner_name]
        try:
            create_resp = await owner_session.post(
                endpoint.create_path, json=endpoint.create_body
            )
        except httpx.HTTPError as exc:
            log.warning(
                "bola_create_request_failed",
                endpoint=endpoint.create_path,
                owner=owner_name,
                error=str(exc),
            )
            return []
        if create_resp.status_code >= 400:
            log.warning(
                "bola_create_non_2xx",
                endpoint=endpoint.create_path,
                status=create_resp.status_code,
                body=_safe_json(create_resp),
            )
            return []
        create_data = create_resp.json() if create_resp.content else {}
        resource_id = create_data.get("id") if isinstance(create_data, dict) else None
        if not resource_id:
            log.warning(
                "bola_no_id_in_create_response",
                endpoint=endpoint.create_path,
                response=create_data,
            )
            return []
    else:
        log.warning(
            "bola_skip_no_strategy",
            endpoint=endpoint.path,
            reason="needs either create_path or use_victim_user_id to probe cross-user access",
        )
        return []

    # 2. Attacker requests the resource by id.
    access_path = _substitute_id(endpoint.path, endpoint.id_param, str(resource_id))
    try:
        access_resp = await attacker_session.request(endpoint.method, access_path)
    except httpx.HTTPError as exc:
        log.warning(
            "bola_access_request_failed",
            endpoint=access_path,
            attacker=attacker_name,
            error=str(exc),
        )
        return []

    if access_resp.status_code != 200:
        log.info(
            "bola_not_vulnerable",
            endpoint=endpoint.path,
            status=access_resp.status_code,
        )
        return []

    body = _safe_json(access_resp)
    # Guard against "200 OK + empty body" false positives.
    if not body or (isinstance(body, dict) and not body):
        log.info("bola_200_but_empty", endpoint=endpoint.path)
        return []

    return [
        Finding(
            module="bola",
            severity="critical",
            title=f"BOLA: cross-user read on {endpoint.path}",
            description=(
                f"User {attacker_name!r} (id={attacker_id}) retrieved a resource "
                f"owned by user {owner_name!r} (id={owner_id}) via "
                f"{endpoint.method} {access_path}. The endpoint accepts the "
                f"resource id alone and performs no ownership check against the "
                f"authenticated user."
            ),
            evidence={
                "resource_owner": owner_name,
                "resource_owner_id": owner_id,
                "attacker": attacker_name,
                "attacker_id": attacker_id,
                "resource_id": resource_id,
                "request": {"method": endpoint.method, "path": access_path},
                "response_status": access_resp.status_code,
                "response_body": body,
            },
            cwe_id="CWE-639",
            reproduction_steps=(
                [
                    f"Authenticate as user A ({owner_name})",
                    f"Note user A's id ({resource_id!r}) - used directly as the path parameter",
                    f"Authenticate as user B ({attacker_name})",
                    f"Issue {endpoint.method} {access_path} with user B's bearer token",
                    "Observe HTTP 200 returning user A's data (see evidence.response_body)",
                ]
                if endpoint.use_victim_user_id
                else [
                    f"Authenticate as user A ({owner_name})",
                    f"POST {endpoint.create_path} with body {endpoint.create_body}",
                    f"Capture the `id` from the response (observed: {resource_id!r})",
                    f"Authenticate as user B ({attacker_name})",
                    f"Issue {endpoint.method} {access_path} with user B's bearer token",
                    "Observe HTTP 200 returning user A's resource (see evidence.response_body)",
                ]
            ),
            remediation=(
                "Enforce object ownership at the query layer. The lookup must "
                "include both the resource id and the authenticated user's id "
                "(`WHERE id = ? AND user_id = ?`). Return HTTP 404 - not 403 - "
                "for both missing and unauthorized resources so existence is not "
                "leaked through status-code differences."
            ),
            endpoint=endpoint.path,
        )
    ]


async def run_bola(ctx: ScanContext, config: BolaModuleConfig) -> list[Finding]:
    if len(ctx.sessions) < 2:
        log.warning(
            "bola_skipped",
            reason="BOLA testing requires at least two authenticated credentials",
            available=list(ctx.sessions.keys()),
        )
        return []

    owner_name, attacker_name = ctx.user_pair()
    findings: list[Finding] = []
    for endpoint in config.endpoints:
        findings.extend(await _probe_endpoint(endpoint, ctx, owner_name, attacker_name))
    return findings
