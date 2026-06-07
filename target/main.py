"""BrokenCheckout - deliberately vulnerable payment API for Fracture's tests.

Every router contains documented intentional flaws. See docs/vulnerability-index.md
for the CWE breakdown and the correct remediation for each one. This is the
canonical target the scanner is validated against (section 7 of the spec).
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import select

import auth
from auth import hash_password
from database import async_session_factory, init_db
from models import (
    Charge,
    Coupon,
    Invoice,
    PaymentMethod,
    Subscription,
    User,
)
from routers import customers, payments, refunds, webhooks


async def seed_data() -> None:
    """Seed alice + bob and their owned resources.

    Idempotent - re-runs on container restart are a no-op once users exist.
    Stable IDs (`usr_alice`, `pm_alice_001`, ...) make BOLA reproduction
    steps deterministic across runs.
    """
    async with async_session_factory() as db:
        existing = await db.execute(select(User))
        if existing.scalars().first():
            return

        alice = User(
            id="usr_alice",
            email="alice@example.com",
            password_hash=hash_password("password123"),
        )
        bob = User(
            id="usr_bob",
            email="bob@example.com",
            password_hash=hash_password("password123"),
        )
        db.add_all([alice, bob])

        db.add_all(
            [
                PaymentMethod(id="pm_alice_001", user_id=alice.id, brand="visa", last4="4242"),
                PaymentMethod(id="pm_bob_001", user_id=bob.id, brand="mastercard", last4="5555"),
                Charge(id="ch_alice_001", user_id=alice.id, amount=5000, currency="usd"),
                Charge(id="ch_bob_001", user_id=bob.id, amount=3000, currency="usd"),
                Invoice(id="in_alice_001", user_id=alice.id, amount=12000, currency="usd"),
                Invoice(id="in_bob_001", user_id=bob.id, amount=8000, currency="usd"),
                Subscription(id="sub_alice_001", user_id=alice.id, plan="pro"),
                Subscription(id="sub_bob_001", user_id=bob.id, plan="starter"),
                Coupon(code="SAVE10", discount_percent=10, max_uses=1, uses=0, active=True),
            ]
        )
        await db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await seed_data()
    yield


app = FastAPI(title="BrokenCheckout", version="1.0", lifespan=lifespan)
app.include_router(auth.router)
app.include_router(payments.router)
app.include_router(refunds.router)
app.include_router(webhooks.router)
app.include_router(customers.router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
async def root() -> dict[str, str]:
    return {
        "name": "BrokenCheckout",
        "version": "1.0",
        "warning": "Deliberately vulnerable. Do not deploy.",
    }
