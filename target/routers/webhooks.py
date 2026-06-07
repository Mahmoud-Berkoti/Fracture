"""Webhook handler for BrokenCheckout.

INTENTIONAL VULNERABILITIES:

  - CWE-345 (Insufficient Verification of Data Authenticity):
    The Fracture-Signature header is OPTIONAL. If absent, the payload is
    processed without authentication. Real handlers (Stripe et al.) must
    reject any request without a valid signature.

  - CWE-294 (Authentication Bypass by Capture-Replay):
    Even when the signature is provided, the timestamp component is parsed
    only for signing — it is NOT compared against now() to enforce a replay
    tolerance window. A captured event remains processable forever.

  - No event_id de-duplication: even a properly-signed-within-window event
    can be replayed many times.

Signature scheme matches Stripe's: `t=<unix>,v1=<hex-hmac-sha256>` where the
HMAC is computed over `f"{t}.{raw_body}"`.
"""
from __future__ import annotations

import hashlib
import hmac

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import WebhookEvent

router = APIRouter(prefix="/v1", tags=["webhooks"])

# INTENTIONAL: shared secret hardcoded; matches scanner YAML config.
WEBHOOK_SECRET = "whsec_test_secret"


def _verify_signature(payload: bytes, signature_header: str) -> bool:
    parts: dict[str, str] = {}
    for chunk in signature_header.split(","):
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            parts[k.strip()] = v.strip()
    timestamp = parts.get("t")
    sig = parts.get("v1")
    if not timestamp or not sig:
        return False
    signed_payload = f"{timestamp}.{payload.decode('utf-8', errors='replace')}".encode()
    expected = hmac.new(WEBHOOK_SECRET.encode(), signed_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


@router.post("/webhooks")
async def handle_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    body = await request.body()
    signature = request.headers.get("Fracture-Signature")

    # INTENTIONAL CWE-345: signature is optional. Missing header = "trust me".
    if signature:
        if not _verify_signature(body, signature):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid signature")
        # INTENTIONAL CWE-294: timestamp tolerance window is never enforced.

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid JSON")

    event = WebhookEvent(
        event_type=str(payload.get("type", "unknown")),
        payload=body.decode("utf-8", errors="replace"),
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return {"received": True, "event_id": event.id, "type": event.event_type}
