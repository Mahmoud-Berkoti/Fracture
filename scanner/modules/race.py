"""Race-condition attack module — section 5.3 of the spec.

Per endpoint:
  1. (optional) Run the `bootstrap` request once, capture response fields
     into template variables. This lets the salvo target fresh resources
     (e.g. a brand-new charge_id) so the test is reproducible across runs.
  2. Render the salvo body by substituting `{var}` placeholders from the
     captured template vars.
  3. Build N coroutines that issue the same request and dispatch them all
     via `asyncio.gather`. gather schedules them into the event loop in a
     single tick, so all N HTTP requests are in-flight before any of them
     receives a response — which is what's required to trigger TOCTOU
     races inside the handler (see section 2.2: "Sequential requests or
     thread-pool-based concurrency will not reliably trigger these
     conditions").
  4. Count 2xx responses. >1 = race vulnerability (CWE-362, critical).

Coupon-style endpoints consume their test artifact on first run (e.g.
SAVE10 with max_uses=1 is exhausted after the first scan succeeds). To
re-run, restart the target container so seed data resets.
"""
from __future__ import annotations

import asyncio
import re
from collections import Counter
from typing import Any

import httpx
import structlog

from core.models import BootstrapRequest, Finding, RaceEndpoint, RaceModuleConfig
from core.session import ScanContext

log = structlog.get_logger(__name__)

_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}")
_WHOLE_PLACEHOLDER_RE = re.compile(r"^\{(\w+)\}$")


# --- template substitution ---------------------------------------------------


def _substitute_value(value: Any, template_vars: dict[str, Any]) -> Any:
    if isinstance(value, str):
        # If the entire string is a single placeholder, preserve the captured type.
        m = _WHOLE_PLACEHOLDER_RE.match(value)
        if m and m.group(1) in template_vars:
            return template_vars[m.group(1)]
        # Otherwise interpolate as string.
        return _PLACEHOLDER_RE.sub(
            lambda match: str(template_vars.get(match.group(1), match.group(0))),
            value,
        )
    if isinstance(value, dict):
        return {k: _substitute_value(v, template_vars) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute_value(v, template_vars) for v in value]
    return value


def _find_unresolved(value: Any) -> set[str]:
    if isinstance(value, str):
        return set(_PLACEHOLDER_RE.findall(value))
    if isinstance(value, dict):
        out: set[str] = set()
        for v in value.values():
            out.update(_find_unresolved(v))
        return out
    if isinstance(value, list):
        out = set()
        for v in value:
            out.update(_find_unresolved(v))
        return out
    return set()


def _jsonpath(data: Any, path: str) -> Any:
    for part in path.split("."):
        if isinstance(data, dict):
            data = data.get(part)
        elif isinstance(data, list):
            try:
                data = data[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return data


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return resp.text[:500]


# --- bootstrap ---------------------------------------------------------------


async def _run_bootstrap(
    session: httpx.AsyncClient, bootstrap: BootstrapRequest
) -> dict[str, Any]:
    resp = await session.request(bootstrap.method, bootstrap.path, json=bootstrap.body)
    resp.raise_for_status()
    data = resp.json() if resp.content else {}
    captured = {var: _jsonpath(data, path) for var, path in bootstrap.capture.items()}
    missing = [var for var, val in captured.items() if val is None]
    if missing:
        raise RuntimeError(
            f"Bootstrap {bootstrap.method} {bootstrap.path} did not produce "
            f"required capture vars {missing!r}; response was {data!r}"
        )
    return captured


# --- attack ------------------------------------------------------------------


async def _attack_endpoint(
    ctx: ScanContext,
    endpoint: RaceEndpoint,
    concurrency: int,
    user_name: str,
) -> list[Finding]:
    session = ctx.sessions[user_name]

    template_vars: dict[str, Any] = {}
    if endpoint.bootstrap:
        try:
            template_vars = await _run_bootstrap(session, endpoint.bootstrap)
        except Exception as exc:
            log.error(
                "race_bootstrap_failed",
                endpoint=endpoint.path,
                bootstrap_path=endpoint.bootstrap.path,
                error=str(exc),
            )
            return []
        log.info(
            "race_bootstrap_complete",
            endpoint=endpoint.path,
            captured=template_vars,
        )

    resolved_body = _substitute_value(endpoint.body, template_vars)
    unresolved = _find_unresolved(resolved_body)
    if unresolved:
        log.warning(
            "race_unresolved_placeholders",
            endpoint=endpoint.path,
            unresolved=sorted(unresolved),
        )
        return []

    log.info(
        "race_salvo_dispatch",
        endpoint=endpoint.path,
        concurrency=concurrency,
        user=user_name,
    )

    # All N requests built before any awaited — asyncio.gather schedules
    # them in the same event-loop tick.
    coros = [
        session.request(endpoint.method, endpoint.path, json=resolved_body)
        for _ in range(concurrency)
    ]
    responses = await asyncio.gather(*coros, return_exceptions=True)

    successes: list[httpx.Response] = [
        r
        for r in responses
        if isinstance(r, httpx.Response) and 200 <= r.status_code < 300
    ]
    exceptions = [r for r in responses if isinstance(r, BaseException)]
    status_breakdown: Counter[int] = Counter(
        r.status_code for r in responses if isinstance(r, httpx.Response)
    )

    log.info(
        "race_salvo_complete",
        endpoint=endpoint.path,
        successes=len(successes),
        status_breakdown=dict(status_breakdown),
        exceptions=len(exceptions),
    )

    if len(successes) <= 1:
        return []

    bootstrap_step: list[str] = []
    if endpoint.bootstrap:
        bootstrap_step = [
            f"As a setup step, send {endpoint.bootstrap.method} "
            f"{endpoint.bootstrap.path} with body {endpoint.bootstrap.body} "
            f"and capture {list(endpoint.bootstrap.capture.keys())} from the "
            f"response (observed: {template_vars})",
        ]

    return [
        Finding(
            module="race",
            severity="critical",
            title=f"Race condition in {endpoint.method} {endpoint.path}",
            description=(
                f"{len(successes)} of {concurrency} concurrent {endpoint.method} "
                f"requests to {endpoint.path} returned 2xx for an operation that "
                f"should succeed at most once. The handler performs a check-then-act "
                f"sequence without row-level locking or idempotency-key enforcement, "
                f"so concurrent callers all pass the precondition check before any "
                f"of them commits the state change."
            ),
            evidence={
                "concurrency": concurrency,
                "successful_responses": len(successes),
                "status_breakdown": dict(status_breakdown),
                "exception_count": len(exceptions),
                "exception_samples": [str(e) for e in exceptions[:3]],
                "request_body_resolved": resolved_body,
                "template_vars": template_vars,
                "sample_success_response": _safe_json(successes[0]),
            },
            cwe_id="CWE-362",
            reproduction_steps=[
                f"Authenticate as a valid user ({user_name})",
                *bootstrap_step,
                f"Build {concurrency} coroutines, each issuing {endpoint.method} "
                f"{endpoint.path} with body {resolved_body}",
                "Dispatch them concurrently with `asyncio.gather(*coros)` so they "
                "enter the event loop in the same tick",
                f"Observe {len(successes)} of {concurrency} responses return 2xx, "
                "proving the handler processed the operation more than once",
            ],
            remediation=(
                "Eliminate the check-then-act window. Three viable approaches: "
                "(1) acquire a row-level lock before the precondition check "
                "(`SELECT ... FOR UPDATE`); "
                "(2) make the state change atomic with a guarded UPDATE "
                "(`UPDATE charges SET refunded = true WHERE id = ? AND refunded = false` "
                "— a zero-row result means another request already won); "
                "(3) require an `Idempotency-Key` request header and dedupe by that key "
                "in a unique index. Production payment APIs combine (2) and (3)."
            ),
            endpoint=endpoint.path,
        )
    ]


# --- entry point -------------------------------------------------------------


async def run_race(ctx: ScanContext, config: RaceModuleConfig) -> list[Finding]:
    if not ctx.sessions:
        log.warning("race_skipped", reason="no authenticated sessions")
        return []
    user_name = ctx.first_user()
    findings: list[Finding] = []
    for endpoint in config.endpoints:
        findings.extend(
            await _attack_endpoint(ctx, endpoint, config.concurrency, user_name)
        )
    return findings
