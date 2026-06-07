"""HTTP session + authentication management for Fracture.

`build_context` logs in every credential pair from the target config and
returns a `ScanContext` containing one authenticated httpx.AsyncClient per
user, plus an unauthenticated `raw_client` (used by the webhook module
since webhooks are intentionally cross-trust-boundary).

All clients are entered into an external AsyncExitStack owned by the
runner so they close cleanly at scan teardown.
"""
from __future__ import annotations

from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Optional

import httpx
import structlog

from .models import TargetConfig

log = structlog.get_logger(__name__)

USER_AGENT = "Fracture/1.0"


@dataclass
class ScanContext:
    base_url: str
    sessions: dict[str, httpx.AsyncClient] = field(default_factory=dict)
    user_ids: dict[str, str] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)
    raw_client: Optional[httpx.AsyncClient] = None
    login_endpoint: Optional[str] = None

    def first_user(self) -> str:
        if not self.sessions:
            raise RuntimeError("No authenticated sessions available")
        return next(iter(self.sessions))

    def user_pair(self) -> tuple[str, str]:
        """Return (alice, bob) - first two authenticated users."""
        if len(self.sessions) < 2:
            raise RuntimeError(
                "BOLA testing requires at least two authenticated credentials"
            )
        names = list(self.sessions.keys())
        return names[0], names[1]


async def _login(
    client: httpx.AsyncClient,
    base_url: str,
    login_endpoint: str,
    username: str,
    password: str,
) -> tuple[str, str]:
    url = f"{base_url.rstrip('/')}{login_endpoint}"
    resp = await client.post(url, json={"username": username, "password": password})
    resp.raise_for_status()
    data = resp.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError(f"Login for {username} returned no access_token: {data!r}")
    return token, data.get("user_id", "")


async def build_context(
    config: TargetConfig,
    stack: AsyncExitStack,
) -> ScanContext:
    raw_client = await stack.enter_async_context(
        httpx.AsyncClient(
            timeout=30.0,
            headers={"User-Agent": USER_AGENT},
        )
    )
    ctx = ScanContext(
        base_url=config.base_url,
        raw_client=raw_client,
        login_endpoint=config.auth.login_endpoint,
    )

    for cred in config.auth.credentials:
        try:
            token, user_id = await _login(
                raw_client,
                config.base_url,
                config.auth.login_endpoint,
                cred.username,
                cred.password,
            )
        except Exception as exc:
            log.error("login_failed", username=cred.username, error=str(exc))
            continue

        client = await stack.enter_async_context(
            httpx.AsyncClient(
                base_url=config.base_url,
                timeout=30.0,
                headers={
                    "Authorization": f"Bearer {token}",
                    "User-Agent": USER_AGENT,
                    "Content-Type": "application/json",
                },
            )
        )
        ctx.sessions[cred.username] = client
        ctx.user_ids[cred.username] = user_id
        ctx.tokens[cred.username] = token
        log.info("authenticated", username=cred.username, user_id=user_id)

    if not ctx.sessions:
        raise RuntimeError("No credentials authenticated successfully; aborting scan")

    return ctx
