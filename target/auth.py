"""JWT authentication for BrokenCheckout - with intentional flaws.

INTENTIONAL VULNERABILITIES (each is detected by scanner/modules/auth.py):

  1. CWE-347 (Improper Verification of Cryptographic Signature):
     Tokens with header `alg: none` are accepted as authentic. The signature
     segment is ignored entirely when alg=none. This is the canonical
     JWT-library alg-confusion flaw (CVE-2015-9235 family).

  2. CWE-613 (Insufficient Session Expiration):
     The `exp` claim is parsed but never compared against current time.
     Tokens issued years ago remain valid indefinitely.

  3. CWE-798 (Use of Hard-coded Credentials):
     JWT_SECRET = "secret" - trivially brute-forceable. Attacker with knowledge
     of the secret can forge tokens for any user.

Correct remediation is documented in docs/vulnerability-index.md.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import User

# INTENTIONAL: hardcoded shared secret. CWE-798.
JWT_SECRET = "secret"

# Intentionally weak password hashing: single sha256 with a static prefix.
# Real systems should use bcrypt/argon2 with per-user salt + work factor.
_PWD_PREFIX = "brokencheckout-static-salt:"


def hash_password(password: str) -> str:
    return hashlib.sha256((_PWD_PREFIX + password).encode()).hexdigest()


def verify_password(password: str, hashed: str) -> bool:
    return hmac.compare_digest(hash_password(password), hashed)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def issue_token(user: User, expires_in: int = 3600) -> str:
    """Issue a normal HS256 JWT. Scanner uses this as the baseline good token."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user.id,
        "email": user.email,
        "iat": int(time.time()),
        "exp": int(time.time()) + expires_in,
    }
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_token(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Malformed token")

    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Malformed token")

    alg = str(header.get("alg", "")).lower()

    # CWE-347: accept alg:none with no verification.
    if alg == "none":
        return payload

    if alg in ("hs256", "hmac-sha256"):
        signing_input = f"{header_b64}.{payload_b64}".encode()
        expected = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
        try:
            provided = _b64url_decode(sig_b64)
        except Exception:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid signature")
        if not hmac.compare_digest(expected, provided):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid signature")
        # CWE-613: `exp` claim is not enforced.
        return payload

    raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Unsupported algorithm: {alg}")


async def get_current_user(
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    payload = decode_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token missing sub claim")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    return user


# ---- login route ---------------------------------------------------------

router = APIRouter(prefix="/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str


@router.post("/login", response_model=LoginResponse)
async def login(
    req: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    result = await db.execute(select(User).where(User.email == req.username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    return LoginResponse(access_token=issue_token(user), user_id=user.id)
