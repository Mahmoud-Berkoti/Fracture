"""Customer + invoice routes for BrokenCheckout.

INTENTIONAL VULNERABILITIES:

  /v1/customers/{customer_id}/subscriptions (GET):
    - CWE-639 (BOLA): no check that `customer_id == current_user.id`. Any
      authenticated user can list any other user's subscriptions.

  /v1/invoices/{invoice_id} (GET):
    - CWE-639 (BOLA): the lookup filters by invoice_id only; no ownership
      predicate. Authenticated user A can fetch user B's invoice.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import get_current_user
from database import get_db
from models import Invoice, Subscription, User

router = APIRouter(prefix="/v1", tags=["customers"])


class InvoiceCreate(BaseModel):
    amount: int = 1000
    currency: str = "usd"


@router.get("/customers/{customer_id}/subscriptions")
async def list_customer_subscriptions(
    customer_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    # INTENTIONAL CWE-639: no `customer_id == current_user.id` enforcement.
    result = await db.execute(
        select(Subscription).where(Subscription.user_id == customer_id)
    )
    subs = result.scalars().all()
    return [
        {"id": s.id, "user_id": s.user_id, "plan": s.plan, "status": s.status}
        for s in subs
    ]


@router.post("/invoices")
async def create_invoice(
    body: InvoiceCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    invoice = Invoice(
        user_id=current_user.id,
        amount=body.amount,
        currency=body.currency,
    )
    db.add(invoice)
    await db.commit()
    await db.refresh(invoice)
    return {
        "id": invoice.id,
        "amount": invoice.amount,
        "currency": invoice.currency,
        "paid": invoice.paid,
    }


@router.get("/invoices/{invoice_id}")
async def get_invoice(
    invoice_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    # INTENTIONAL CWE-639: filter is invoice_id only; no ownership predicate.
    result = await db.execute(select(Invoice).where(Invoice.id == invoice_id))
    invoice = result.scalar_one_or_none()
    if not invoice:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    return {
        "id": invoice.id,
        "user_id": invoice.user_id,
        "amount": invoice.amount,
        "currency": invoice.currency,
        "paid": invoice.paid,
    }
