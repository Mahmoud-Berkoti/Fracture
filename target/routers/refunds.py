"""Refund routes for BrokenCheckout.

INTENTIONAL VULNERABILITIES (both fire from /v1/refunds):

  - CWE-639 (BOLA): the handler looks up the charge by `charge_id` alone with
    no `user_id` predicate, so any authenticated user can refund any other
    user's charge.

  - CWE-362 (race condition): the "is this already refunded?" check happens
    before an asyncio.sleep, and the `refunded = True` write happens after.
    N concurrent requests all observe refunded == False, all sleep, all
    write True, all return 200 with a new refund row. This is the canonical
    check-then-act TOCTOU pattern.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import get_current_user
from database import get_db
from models import Charge, Refund, User

router = APIRouter(prefix="/v1", tags=["refunds"])


class RefundRequest(BaseModel):
    charge_id: str
    amount: int | None = None


@router.post("/refunds")
async def create_refund(
    refund: RefundRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    # INTENTIONAL CWE-639: missing `Charge.user_id == current_user.id` predicate.
    result = await db.execute(select(Charge).where(Charge.id == refund.charge_id))
    charge = result.scalar_one_or_none()
    if not charge:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Charge not found")
    if charge.refunded:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Already refunded")

    # INTENTIONAL CWE-362: simulated processing latency creates the race window.
    await asyncio.sleep(0.05)

    charge.refunded = True
    new_refund = Refund(
        charge_id=charge.id,
        amount=refund.amount if refund.amount is not None else charge.amount,
    )
    db.add(new_refund)
    await db.commit()
    await db.refresh(new_refund)
    return {
        "refund_id": new_refund.id,
        "charge_id": charge.id,
        "amount": new_refund.amount,
    }
