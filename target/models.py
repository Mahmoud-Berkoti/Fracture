"""SQLAlchemy models for BrokenCheckout.

Tables match the spec (section 4.2): users, payment_methods, charges, refunds,
webhook_events, coupons, subscriptions. An invoices table is added to back the
BOLA test on /v1/invoices/{id} (section 2.1).
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    payment_methods: Mapped[list["PaymentMethod"]] = relationship(back_populates="user")
    charges: Mapped[list["Charge"]] = relationship(back_populates="user")
    invoices: Mapped[list["Invoice"]] = relationship(back_populates="user")
    subscriptions: Mapped[list["Subscription"]] = relationship(back_populates="user")


class PaymentMethod(Base):
    __tablename__ = "payment_methods"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    brand: Mapped[str] = mapped_column(String, default="visa")
    last4: Mapped[str] = mapped_column(String, default="4242")
    exp_month: Mapped[int] = mapped_column(Integer, default=12)
    exp_year: Mapped[int] = mapped_column(Integer, default=2030)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped[User] = relationship(back_populates="payment_methods")


class Charge(Base):
    __tablename__ = "charges"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    amount: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String, default="usd")
    status: Mapped[str] = mapped_column(String, default="succeeded")
    refunded: Mapped[bool] = mapped_column(Boolean, default=False)
    coupon_code: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped[User] = relationship(back_populates="charges")


class Refund(Base):
    __tablename__ = "refunds"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    charge_id: Mapped[str] = mapped_column(ForeignKey("charges.id"), nullable=False, index=True)
    amount: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Invoice(Base):
    __tablename__ = "invoices"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    amount: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String, default="usd")
    paid: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped[User] = relationship(back_populates="invoices")


class WebhookEvent(Base):
    __tablename__ = "webhook_events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    processed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Coupon(Base):
    __tablename__ = "coupons"

    code: Mapped[str] = mapped_column(String, primary_key=True)
    discount_percent: Mapped[int] = mapped_column(Integer, default=10)
    max_uses: Mapped[int] = mapped_column(Integer, default=1)
    uses: Mapped[int] = mapped_column(Integer, default=0)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    plan: Mapped[str] = mapped_column(String, default="starter")
    status: Mapped[str] = mapped_column(String, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped[User] = relationship(back_populates="subscriptions")
