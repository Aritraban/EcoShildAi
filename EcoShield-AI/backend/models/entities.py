"""ORM entities for EcoShield AI (SQLAlchemy 2.x typed style).

16 tables covering authentication, carbon accounting, AI outputs, and the
cybersecurity monitoring/audit layer.
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class Role(str, enum.Enum):
    USER = "USER"
    ADMIN = "ADMIN"
    SECURITY_ADMIN = "SECURITY_ADMIN"


class Severity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Period(str, enum.Enum):
    DAILY = "DAILY"
    MONTHLY = "MONTHLY"
    ANNUAL = "ANNUAL"


# --------------------------------------------------------------------------- #
# Identity & authentication
# --------------------------------------------------------------------------- #
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.USER, nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    email_verify_token: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    password_reset_token: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    password_reset_expires: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    profile: Mapped["UserProfile"] = relationship(
        back_populates="user", uselist=False, cascade="all, delete-orphan"
    )
    sessions: Mapped[List["UserSession"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    carbon_records: Mapped[List["CarbonRecord"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    notifications: Mapped[List["Notification"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def is_locked(self) -> bool:
        if self.locked_until is None:
            return False
        lu = self.locked_until if self.locked_until.tzinfo else self.locked_until.replace(tzinfo=timezone.utc)
        return lu > utcnow()


class UserProfile(Base):
    __tablename__ = "user_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)

    full_name: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC", nullable=False)
    phone: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    # Privacy-by-design toggles
    analytics_opt_in: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    data_sharing_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    user: Mapped["User"] = relationship(back_populates="profile")


class UserSession(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    sid: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)

    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    device_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    is_mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    user: Mapped["User"] = relationship(back_populates="sessions")

    __table_args__ = (Index("ix_sessions_user_active", "user_id", "revoked"),)


# --------------------------------------------------------------------------- #
# Emission factors (admin-editable configuration, not hard-coded)
# --------------------------------------------------------------------------- #
class EmissionFactor(Base):
    __tablename__ = "emission_factors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    category: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    key: Mapped[str] = mapped_column(String(80), nullable=False)
    value: Mapped[float] = mapped_column(Float, nullable=False)
    unit: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    updated_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    __table_args__ = (UniqueConstraint("category", "key", name="uq_factor_category_key"),)


# --------------------------------------------------------------------------- #
# Carbon accounting
# --------------------------------------------------------------------------- #
class CarbonRecord(Base):
    """One calculator submission plus its computed CO2e breakdown."""

    __tablename__ = "carbon_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    period: Mapped[Period] = mapped_column(Enum(Period), default=Period.MONTHLY, nullable=False)
    reference_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    transport_co2e: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    energy_co2e: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    food_co2e: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    shopping_co2e: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    waste_co2e: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    total_co2e: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    user: Mapped["User"] = relationship(back_populates="carbon_records")
    transportation: Mapped[Optional["Transportation"]] = relationship(
        back_populates="record", uselist=False, cascade="all, delete-orphan"
    )
    energy: Mapped[Optional["EnergyUsage"]] = relationship(
        back_populates="record", uselist=False, cascade="all, delete-orphan"
    )
    food: Mapped[Optional["FoodUsage"]] = relationship(
        back_populates="record", uselist=False, cascade="all, delete-orphan"
    )
    shopping: Mapped[Optional["ShoppingUsage"]] = relationship(
        back_populates="record", uselist=False, cascade="all, delete-orphan"
    )
    waste: Mapped[Optional["WasteUsage"]] = relationship(
        back_populates="record", uselist=False, cascade="all, delete-orphan"
    )


class Transportation(Base):
    __tablename__ = "transportation"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    record_id: Mapped[int] = mapped_column(
        ForeignKey("carbon_records.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    vehicle_type: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    fuel_type: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    distance_km: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    distance_period: Mapped[Period] = mapped_column(Enum(Period), default=Period.MONTHLY, nullable=False)
    fuel_liters: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    public_transport_km: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    flight_km: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    record: Mapped["CarbonRecord"] = relationship(back_populates="transportation")


class EnergyUsage(Base):
    __tablename__ = "energy_usage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    record_id: Mapped[int] = mapped_column(
        ForeignKey("carbon_records.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    electricity_kwh: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    lpg_kg: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    natural_gas_m3: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    ac_hours_per_day: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    heating_kwh: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    renewable_kwh: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    record: Mapped["CarbonRecord"] = relationship(back_populates="energy")


class FoodUsage(Base):
    __tablename__ = "food_usage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    record_id: Mapped[int] = mapped_column(
        ForeignKey("carbon_records.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    diet_type: Mapped[str] = mapped_column(String(20), default="mixed", nullable=False)
    meat_meals_per_week: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    dairy_meals_per_week: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    food_waste_kg: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    record: Mapped["CarbonRecord"] = relationship(back_populates="food")


class ShoppingUsage(Base):
    __tablename__ = "shopping_usage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    record_id: Mapped[int] = mapped_column(
        ForeignKey("carbon_records.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    clothing_spend: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    electronics_spend: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    plastic_items: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    online_orders: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    record: Mapped["CarbonRecord"] = relationship(back_populates="shopping")


class WasteUsage(Base):
    __tablename__ = "waste_usage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    record_id: Mapped[int] = mapped_column(
        ForeignKey("carbon_records.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    household_waste_kg: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    recycling_percent: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    plastic_waste_kg: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    paper_waste_kg: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    organic_waste_kg: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    record: Mapped["CarbonRecord"] = relationship(back_populates="waste")


# --------------------------------------------------------------------------- #
# AI outputs
# --------------------------------------------------------------------------- #
class CarbonPrediction(Base):
    __tablename__ = "carbon_predictions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    predicted_next_month: Mapped[float] = mapped_column(Float, nullable=False)
    predicted_annual: Mapped[float] = mapped_column(Float, nullable=False)
    confidence_low: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    confidence_high: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    potential_reduction_pct: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    model_version: Mapped[str] = mapped_column(String(32), default="v1", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Recommendation(Base):
    __tablename__ = "recommendations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    estimated_reduction_kg: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    rank: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


# --------------------------------------------------------------------------- #
# Cybersecurity layer
# --------------------------------------------------------------------------- #
class LoginEvent(Base):
    __tablename__ = "login_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True
    )
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    device_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    browser: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    failure_reason: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True, nullable=False)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True
    )
    event_type: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.LOW, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    metadata_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True, nullable=False)


class AuditLog(Base):
    """Append-only audit trail protected by a hash chain (tamper-evident)."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True
    )
    event: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    device_info: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    result: Mapped[str] = mapped_column(String(20), default="SUCCESS", nullable=False)
    risk_level: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.LOW, nullable=False)
    details_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    prev_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    integrity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True, nullable=False)


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    type: Mapped[str] = mapped_column(String(40), default="INFO", nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.LOW, nullable=False)
    read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    user: Mapped["User"] = relationship(back_populates="notifications")


__all__ = [
    "Role",
    "Severity",
    "Period",
    "User",
    "UserProfile",
    "UserSession",
    "EmissionFactor",
    "CarbonRecord",
    "Transportation",
    "EnergyUsage",
    "FoodUsage",
    "ShoppingUsage",
    "WasteUsage",
    "CarbonPrediction",
    "Recommendation",
    "LoginEvent",
    "SecurityEvent",
    "AuditLog",
    "Notification",
]
