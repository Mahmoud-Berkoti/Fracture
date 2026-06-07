"""Webhook security attack module — section 5.5 of the spec.

Two probes against the configured webhook endpoint:

  1. Missing signature header (CWE-345, critical): POST a valid JSON
     event with no signature header at all. A correct webhook handler
     must reject unauthenticated requests outright — accepting them lets
     any internet host inject arbitrary payment-state events into the
     application's bookkeeping.

  2. Replay outside tolerance window (CWE-294, high): POST a payload
     with a valid HMAC signature but a `t=` timestamp 400 seconds in the
     past (industry-standard tolerance is 300s). Accepting it means a
     captured webhook can be replayed indefinitely, so a single observed
     event becomes a perpetual trigger.

Out of scope (could extend the threat model):
  - Future-dated timestamp manipulation.
  - Event-id deduplication probes (need to capture a real event id first).
  - Signature algorithm downgrade.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import httpx
import structlog

from core.models import Finding, WebhookModuleConfig
from core.session import ScanContext

log = structlog.get_logger(__name__)

USER_AGENT = "Fracture/1.0"
REPLAY_AGE_SECONDS = 400  # outside the standard 300s tolerance window
TEST_EVENT = {"type": "payment_intent.succeeded", "data": {"amount": 10000}}


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return resp.text[:500]


async def _probe_missing_signature(
    client: httpx.AsyncClient,
    url: str,
    endpoint_path: str,
    payload_str: str,
) -> list[Finding]:
    resp = await client.post(
        url,
        content=payload_str,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    if resp.status_code != 200:
        log.info(
            "webhook_unsigned_rejected",
            endpoint=endpoint_path,
            status=resp.status_code,
        )
        return []

    return [
        Finding(
            module="webhook",
            severity="critical",
            title=f"Webhook signature validation missing on {endpoint_path}",
            description=(
                f"The webhook endpoint {endpoint_path} processed a POST request "
                f"that carried no signature header. An attacker can inject "
                f"arbitrary payment-state events (here: {TEST_EVENT['type']!r}) "
                f"directly into the system without possessing any shared secret. "
                f"This is the highest-impact webhook flaw because it requires no "
                f"prior access to a legitimate event."
            ),
            evidence={
                "request": {
                    "method": "POST",
                    "url": url,
                    "headers": {"Content-Type": "application/json"},
                    "body": TEST_EVENT,
                },
                "response_status": resp.status_code,
                "response_body": _safe_json(resp),
            },
            cwe_id="CWE-345",
            reproduction_steps=[
                f"Send POST {endpoint_path} with header `Content-Type: application/json`",
                f"Body: {payload_str}",
                "Omit every signature header (no `Fracture-Signature`, no "
                "`Stripe-Signature`, no `X-Hub-Signature-256`)",
                "Observe HTTP 200 — the event was accepted and processed",
            ],
            remediation=(
                "Reject any webhook request whose signature header is missing, "
                "empty, or malformed *before* the body is parsed. Require the "
                "header on the route handler itself rather than in optional "
                "middleware. Use a constant-time HMAC comparison against a "
                "per-tenant secret. Return HTTP 400 so misconfigured callers "
                "get a clear failure signal."
            ),
            endpoint=endpoint_path,
        )
    ]


async def _probe_replay_outside_window(
    client: httpx.AsyncClient,
    url: str,
    endpoint_path: str,
    payload_str: str,
    secret: str,
) -> list[Finding]:
    timestamp = int(time.time()) - REPLAY_AGE_SECONDS
    signing_input = f"{timestamp}.{payload_str}".encode()
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).hexdigest()
    signature_header = f"t={timestamp},v1={signature}"

    resp = await client.post(
        url,
        content=payload_str,
        headers={
            "Content-Type": "application/json",
            "Fracture-Signature": signature_header,
            "User-Agent": USER_AGENT,
        },
    )
    if resp.status_code != 200:
        log.info(
            "webhook_replay_rejected",
            endpoint=endpoint_path,
            status=resp.status_code,
        )
        return []

    return [
        Finding(
            module="webhook",
            severity="high",
            title=f"Webhook replay window not enforced on {endpoint_path}",
            description=(
                f"The webhook endpoint accepted an event with a cryptographically "
                f"valid HMAC signature but a timestamp {REPLAY_AGE_SECONDS} seconds "
                f"in the past — well outside the industry-standard 300s tolerance "
                f"window. A captured webhook can be re-sent indefinitely, so a "
                f"single observed event becomes a perpetual trigger."
            ),
            evidence={
                "request": {
                    "method": "POST",
                    "url": url,
                    "headers": {
                        "Content-Type": "application/json",
                        "Fracture-Signature": signature_header,
                    },
                    "body": TEST_EVENT,
                },
                "timestamp_age_seconds": REPLAY_AGE_SECONDS,
                "signature_valid": True,
                "response_status": resp.status_code,
                "response_body": _safe_json(resp),
            },
            cwe_id="CWE-294",
            reproduction_steps=[
                "Capture a legitimate webhook event with its signature, or compute "
                "one if you have the secret",
                f"Build a signature header `t={timestamp},v1=<hex-hmac>` where the "
                f"timestamp is {REPLAY_AGE_SECONDS}s in the past",
                f"Send POST {endpoint_path} with that header and the original payload",
                "Observe HTTP 200 — the replayed event is processed again",
            ],
            remediation=(
                "After verifying the signature, reject the request when "
                "`abs(now - t) > tolerance` (300s is the industry standard). "
                "Additionally, persist processed event ids in a TTL'd store and "
                "reject duplicates, so even an in-window replay only takes effect "
                "once. Both checks together prevent the full replay attack class."
            ),
            endpoint=endpoint_path,
        )
    ]


async def run_webhook(ctx: ScanContext, config: WebhookModuleConfig) -> list[Finding]:
    if ctx.raw_client is None:
        log.warning("webhook_skipped", reason="raw client not initialized")
        return []

    client = ctx.raw_client
    url = ctx.base_url.rstrip("/") + config.endpoint
    payload_str = json.dumps(TEST_EVENT, separators=(",", ":"))

    findings: list[Finding] = []
    findings.extend(
        await _probe_missing_signature(client, url, config.endpoint, payload_str)
    )
    findings.extend(
        await _probe_replay_outside_window(
            client, url, config.endpoint, payload_str, config.secret
        )
    )
    return findings
