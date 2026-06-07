"""Business-logic flaw detection — section 2.4 of the spec.

Probes the configured charge endpoints with payloads that a generic
schema validator would let through, but which a domain-aware handler
should reject:

  - `negative_amount` (critical, CWE-20): submits `amount: -1000`. Most
    payment systems treat a negative charge as a credit, so accepting
    one lets the caller drain the platform's treasury.
  - `zero_amount` (medium, CWE-20): submits `amount: 0`. Pollutes
    transaction records and can be used as an existence oracle.
  - `int64_overflow_attempt` (high, CWE-190): submits INT64_MAX. Either
    persisted as-is (breaks aggregation) or wraps to a negative value
    (compounds with the negative-amount flaw).
  - `invalid_currency` (medium, CWE-20): submits `currency: "XYZ"`. A
    missing whitelist enables `amount: 100, currency: "JPY"` against a
    USD-priced endpoint to pay ~1/150th the intended price.

Each probe is a single authenticated request; 2xx = finding.

Out of scope (would extend the threat model):
  - Free-tier abuse: needs trial/subscription endpoints + a reset path.
  - Discount stacking: needs multiple-coupon support on the same charge.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from core.models import BusinessLogicEndpoint, BusinessLogicModuleConfig, Finding
from core.session import ScanContext

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class _LogicTest:
    name: str
    body: dict[str, Any]
    severity: str
    title_template: str
    description_template: str
    cwe_id: str
    remediation: str


_TESTS: tuple[_LogicTest, ...] = (
    _LogicTest(
        name="negative_amount",
        body={"amount": -1000, "currency": "usd"},
        severity="critical",
        title_template="Negative amount accepted on {path}",
        description_template=(
            "Endpoint {path} accepted `amount: -1000`. The handler treats a "
            "negative charge as a valid transaction; in most payment systems this "
            "translates to a credit posted to the caller's balance. An attacker "
            "issuing arbitrary negative values can drain the platform's treasury."
        ),
        cwe_id="CWE-20",
        remediation=(
            "Reject any request with `amount <= 0` at the route handler. Prefer "
            "enforcing the constraint at the Pydantic schema layer "
            "(`amount: int = Field(gt=0)`) so the rule is part of the contract, "
            "not buried in business logic."
        ),
    ),
    _LogicTest(
        name="zero_amount",
        body={"amount": 0, "currency": "usd"},
        severity="medium",
        title_template="Zero-amount transaction accepted on {path}",
        description_template=(
            "Endpoint {path} accepted `amount: 0` and persisted a transaction "
            "record. Zero-amount charges pollute audit logs, complicate reporting, "
            "and can be abused as an existence oracle for customer or product ids."
        ),
        cwe_id="CWE-20",
        remediation=(
            "Enforce a strictly-positive minimum at the schema layer "
            "(`amount: int = Field(gt=0)`). Route any genuine zero-amount flows "
            "(card-on-file verification, $0 auth) through a dedicated endpoint with "
            "its own validation and audit trail."
        ),
    ),
    _LogicTest(
        name="int64_overflow_attempt",
        body={"amount": 9_223_372_036_854_775_807, "currency": "usd"},
        severity="high",
        title_template="Extremely large amount accepted on {path}",
        description_template=(
            "Endpoint {path} accepted `amount: 9223372036854775807` (INT64_MAX). "
            "Either the value is stored as-is — corrupting any downstream "
            "aggregation query — or it wraps to a negative integer in some "
            "language/database boundary, compounding with the negative-amount "
            "vulnerability."
        ),
        cwe_id="CWE-190",
        remediation=(
            "Cap `amount` at a realistic per-transaction ceiling for your platform "
            "(`amount: int = Field(gt=0, le=99_999_99)` for a $99,999.99 limit). "
            "Use a decimal money type end-to-end rather than int64; validate "
            "against the platform's per-transaction policy at the schema layer."
        ),
    ),
    _LogicTest(
        name="invalid_currency",
        body={"amount": 100, "currency": "XYZ"},
        severity="medium",
        title_template="Arbitrary currency code accepted on {path}",
        description_template=(
            "Endpoint {path} accepted `currency: \"XYZ\"`, a non-existent ISO-4217 "
            "code. A missing currency whitelist combined with client-side FX "
            "conversion enables submitting `amount: 100, currency: \"JPY\"` against "
            "a USD-priced endpoint to pay roughly 1/150th of the intended amount."
        ),
        cwe_id="CWE-20",
        remediation=(
            "Validate `currency` against an allowlist of ISO-4217 codes your "
            "platform actually supports. Perform all FX conversion server-side "
            "from a single authoritative rate table; never trust client-supplied "
            "amount-currency pairs as final."
        ),
    ),
)


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return resp.text[:500]


async def _run_test(
    session: httpx.AsyncClient,
    endpoint: BusinessLogicEndpoint,
    test: _LogicTest,
) -> list[Finding]:
    try:
        resp = await session.request(endpoint.method, endpoint.path, json=test.body)
    except httpx.HTTPError as exc:
        log.warning(
            "business_logic_request_failed",
            test=test.name,
            endpoint=endpoint.path,
            error=str(exc),
        )
        return []

    if not (200 <= resp.status_code < 300):
        log.info(
            "business_logic_rejected",
            test=test.name,
            endpoint=endpoint.path,
            status=resp.status_code,
        )
        return []

    return [
        Finding(
            module="business_logic",
            severity=test.severity,
            title=test.title_template.format(path=endpoint.path),
            description=test.description_template.format(path=endpoint.path),
            evidence={
                "test": test.name,
                "request": {
                    "method": endpoint.method,
                    "path": endpoint.path,
                    "body": test.body,
                },
                "response_status": resp.status_code,
                "response_body": _safe_json(resp),
            },
            cwe_id=test.cwe_id,
            reproduction_steps=[
                "Authenticate as any valid user",
                f"Send {endpoint.method} {endpoint.path} with body {test.body}",
                f"Observe HTTP {resp.status_code} — the malformed payload was accepted",
            ],
            remediation=test.remediation,
            endpoint=endpoint.path,
        )
    ]


async def run_business_logic(
    ctx: ScanContext, config: BusinessLogicModuleConfig
) -> list[Finding]:
    if not ctx.sessions:
        log.warning("business_logic_skipped", reason="no authenticated sessions")
        return []
    user = ctx.first_user()
    session = ctx.sessions[user]

    findings: list[Finding] = []
    for endpoint in config.endpoints:
        for test in _TESTS:
            findings.extend(await _run_test(session, endpoint, test))
    return findings
