"""Payment + payment-method routes for BrokenCheckout.

INTENTIONAL VULNERABILITIES:

  /v1/charges (POST):
    - CWE-20: no amount validation. Negative, zero, and INT64-near values all
      pass through to the database and produce "successful" charges.
    - CWE-20: no currency whitelist. Any string accepted; no FX conversion.
    - CWE-362: coupon application performs a check-then-act sequence with an
      explicit asyncio.sleep window between read and write, so N concurrent
      requests all see uses < max_uses and all increment past the limit.

  /v1/payment-methods/{id} (GET):
    - CWE-639: no ownership check. Any authenticated user can fetch any
      payment method by guessing/knowing its ID.

  /v1/payment-methods (GET):
    - Used by scanner/modules/auth.py as the target for expired-token,
      alg:none, and tampered-claim probes. Endpoint itself is "correct" —
      the bypass is in auth.py's token validation.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import get_current_user
from database import get_db
from models import Charge, Coupon, PaymentMethod, User

router = APIRouter(prefix="/v1", tags=["payments"])


class ChargeRequest(BaseModel):
    amount: int
    currency: str = "usd"
    coupon: str | None = None


class PaymentMethodCreate(BaseModel):
    brand: str = "visa"
    last4: str = "4242"
    exp_month: int = 12
    exp_year: int = 2030


@router.post("/charges")
async def create_charge(
    charge: ChargeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    # INTENTIONAL: missing `if charge.amount <= 0: raise ...`
    # INTENTIONAL: missing currency whitelist
    if charge.coupon:
        result = await db.execute(select(Coupon).where(Coupon.code == charge.coupon))
        coupon = result.scalar_one_or_none()
        if not coupon or not coupon.active or coupon.uses >= coupon.max_uses:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Coupon invalid")
        # INTENTIONAL CWE-362: race window between check and increment.
        await asyncio.sleep(0.05)
        coupon.uses += 1

    new_charge = Charge(
        user_id=current_user.id,
        amount=charge.amount,
        currency=charge.currency,
        coupon_code=charge.coupon,
    )
    db.add(new_charge)
    await db.commit()
    await db.refresh(new_charge)
    return {
        "id": new_charge.id,
        "amount": new_charge.amount,
        "currency": new_charge.currency,
        "status": new_charge.status,
        "coupon": new_charge.coupon_code,
    }


@router.get("/payment-methods")
async def list_payment_methods(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    result = await db.execute(
        select(PaymentMethod).where(PaymentMethod.user_id == current_user.id)
    )
    methods = result.scalars().all()
    return [
        {
            "id": m.id,
            "brand": m.brand,
            "last4": m.last4,
            "exp_month": m.exp_month,
            "exp_year": m.exp_year,
        }
        for m in methods
    ]


@router.post("/payment-methods")
async def create_payment_method(
    body: PaymentMethodCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    method = PaymentMethod(
        user_id=current_user.id,
        brand=body.brand,
        last4=body.last4,
        exp_month=body.exp_month,
        exp_year=body.exp_year,
    )
    db.add(method)
    await db.commit()
    await db.refresh(method)
    return {"id": method.id, "brand": method.brand, "last4": method.last4}


@router.get("/payment-methods/{payment_method_id}")
async def get_payment_method(
    payment_method_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    # INTENTIONAL CWE-639: filter is `id == ?` only, no `user_id` predicate.
    result = await db.execute(
        select(PaymentMethod).where(PaymentMethod.id == payment_method_id)
    )
    method = result.scalar_one_or_none()
    if not method:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    return {
        "id": method.id,
        "user_id": method.user_id,
        "brand": method.brand,
        "last4": method.last4,
        "exp_month": method.exp_month,
        "exp_year": method.exp_year,
    }
